import asyncio,json,re,socket,time,subprocess,os,ipaddress,secrets
from contextlib import asynccontextmanager
from datetime import datetime,timezone
from pathlib import Path
from typing import Optional
import httpx
from fastapi import FastAPI,Query,Request,HTTPException,Depends,Header,Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse,FileResponse

# ── Security ─────────────────────────────────────────────────
ADMIN_TOKEN = os.environ.get("NYM_CHECKER_TOKEN", "")
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost"}
MAX_TARGET_LEN = 253  # max DNS hostname length

# Env-driven config (P3.2)
def _env_bool(name, default=False):
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")

def _env_set(name, default=None):
    v = os.environ.get(name, "").strip()
    if not v:
        return set(default or [])
    return {x.strip() for x in v.split(",") if x.strip()}

TRUSTED_PROXIES = _env_set("NYM_TRUSTED_PROXIES")
TRUST_XFF = _env_bool("NYM_TRUST_XFF", False)
IPV6_AGENT_URL = (os.environ.get("IPV6_AGENT_URL") or "").strip() or None
ALLOW_INSECURE_IPV6_AGENT = _env_bool("ALLOW_INSECURE_IPV6_AGENT", False)
SMTP_RESULTS_FILE_PATH = os.environ.get("SMTP_RESULTS_FILE", "/opt/nym-probe/latest_smtp.json")
SMTP_STALE_SECONDS = int(os.environ.get("SMTP_STALE_SECONDS", str(3600 * 36)))

# Resolved at startup (validated below)
_ipv6_agent_enabled = False  # set by _validate_security_config
_ipv6_agent_secure = False

def _validate_security_config():
    """Validate env config at startup. Logs warnings, disables features safely."""
    global TRUST_XFF, _ipv6_agent_enabled, _ipv6_agent_secure
    msgs = []
    # XFF needs trusted proxies
    if TRUST_XFF and not TRUSTED_PROXIES:
        msgs.append("[!] NYM_TRUST_XFF=1 but NYM_TRUSTED_PROXIES is empty - forcing TRUST_XFF=False")
        TRUST_XFF = False
    # IPv6 agent: require https unless explicitly opted in
    if IPV6_AGENT_URL:
        if IPV6_AGENT_URL.startswith("https://"):
            _ipv6_agent_enabled = True
            _ipv6_agent_secure = True
        elif IPV6_AGENT_URL.startswith("http://"):
            if ALLOW_INSECURE_IPV6_AGENT:
                _ipv6_agent_enabled = True
                _ipv6_agent_secure = False
                msgs.append(f"[!] IPV6_AGENT_URL is plain HTTP and ALLOW_INSECURE_IPV6_AGENT=1; "
                            f"using insecure transport (degraded source)")
            else:
                _ipv6_agent_enabled = False
                msgs.append(f"[!] IPV6_AGENT_URL is plain HTTP without ALLOW_INSECURE_IPV6_AGENT=1; "
                            f"agent disabled. Returning 'unknown' for IPv6 status.")
                try:
                    sec_log("insecure_agent_blocked", "self", {"url_scheme": "http"})
                except Exception:
                    pass
        else:
            msgs.append(f"[!] IPV6_AGENT_URL has unsupported scheme; agent disabled")
            _ipv6_agent_enabled = False
    else:
        _ipv6_agent_enabled = False
    for m in msgs:
        print(m)

def _host_for_url(ip):
    """Wrap IPv6 addresses in brackets for use in URLs."""
    return f"[{ip}]" if ":" in ip else ip

def _is_private_ip(ip_str):
    """Block SSRF: reject loopback, link-local, private, reserved IPs."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return True  # invalid IP -> reject

def require_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    """Admin access requires a valid token. No localhost bypass (behind reverse proxy all requests look local)."""
    if ADMIN_TOKEN and x_admin_token and secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        return True
    sec_log("auth_denied", _real_ip(request), {"path": str(request.url.path)})
    raise HTTPException(status_code=403, detail="Forbidden: admin token required")

# ── Rate limiter (in-memory token bucket per IP) ─────────────
RATE_LIMIT_FILE = Path("nym_checker_security.log")
RL_WINDOW = 60         # seconds
RL_MAX_CHEAP = 120     # cheap endpoints: /api/nodes, /api/health, /api/hit, /api/network-stats
RL_MAX_EXPENSIVE = 20  # expensive endpoints: /api/check, /api/check-batch
_rl_buckets_cheap = {}
_rl_buckets_expensive = {}

def _rl_check(buckets, max_req, client_ip):
    now = time.time()
    bucket = buckets.setdefault(client_ip, [])
    cutoff = now - RL_WINDOW
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(buckets) > 10000:
        for k in list(buckets.keys()):
            if not buckets[k] or buckets[k][-1] < cutoff:
                buckets.pop(k, None)
    if len(bucket) >= max_req:
        return False
    bucket.append(now)
    return True

def _is_valid_ip(s):
    """True if string parses as a valid IP (v4 or v6)."""
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False

def _real_ip(request: Request):
    """
    Extract real client IP with hardened proxy-header trust.
    - Only trust forwarding headers from peers in TRUSTED_PROXIES (env-driven).
    - In iter1: only X-Real-IP. X-Forwarded-For ignored unless TRUST_XFF=1 + trusted peer.
    - Any invalid header value → fallback to request.client.host. Never fail the request.
    """
    direct = request.client.host if request.client else "unknown"
    if direct not in TRUSTED_PROXIES:
        # Direct request, ignore proxy headers
        if request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For"):
            try:
                sec_log("proxy_header_untrusted", direct, {
                    "real_ip_present": bool(request.headers.get("X-Real-IP")),
                    "xff_present": bool(request.headers.get("X-Forwarded-For")),
                })
            except Exception:
                pass
        return direct
    # Trusted peer: read X-Real-IP first
    real_ip = (request.headers.get("X-Real-IP") or "").strip()
    if real_ip:
        if _is_valid_ip(real_ip):
            return real_ip
        try:
            sec_log("proxy_header_invalid", direct, {"header": "X-Real-IP", "value": real_ip[:64]})
        except Exception:
            pass
    # Optional XFF (off by default in iter1)
    if TRUST_XFF:
        xff = (request.headers.get("X-Forwarded-For") or "").strip()
        if xff:
            # Right-to-left: drop trusted proxies, take first untrusted
            hops = [h.strip() for h in xff.split(",") if h.strip()]
            for hop in reversed(hops):
                if hop in TRUSTED_PROXIES:
                    continue
                if _is_valid_ip(hop):
                    return hop
                try:
                    sec_log("proxy_header_invalid", direct, {"header": "X-Forwarded-For", "value": hop[:64]})
                except Exception:
                    pass
                break
    return direct

def rate_limit_check(request: Request, expensive=False):
    """Returns True if allowed, False if rate-limited."""
    client_ip = _real_ip(request)
    if expensive:
        ok = _rl_check(_rl_buckets_expensive, RL_MAX_EXPENSIVE, client_ip)
    else:
        ok = _rl_check(_rl_buckets_cheap, RL_MAX_CHEAP, client_ip)
    if not ok:
        sec_log("rate_limited", client_ip, {"type": "expensive" if expensive else "cheap"})
    return ok

def sec_log(event, ip, details=None):
    """Append a security event to the log file."""
    try:
        line = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "ip": ip,
            "details": details or {}
        }, ensure_ascii=False)
        with open(RATE_LIMIT_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass



STATIC_DIR=Path(os.environ.get("STATIC_DIR","/opt/nym-checker/static"))
app=FastAPI(title="Nym Node Checker",version="2.4")
PORT_CHANGES_FILE=Path("nym_port_changes.json")
AUTO_SYNC_INTERVAL=10800  # 3 hours
ALLOWED_ORIGINS=os.environ.get("CORS_ORIGINS","").split(",") if os.environ.get("CORS_ORIGINS") else []
app.add_middleware(CORSMiddleware,allow_origins=ALLOWED_ORIGINS,allow_methods=["GET","POST"],allow_headers=["X-Admin-Token"])

REF_FILE=Path("nym_reference.json")
CACHE_FILE=Path("nym_nodes_cache.json")
CACHE_AGE=1800  # 30 min
_cache_lock=asyncio.Lock()

def _atomic_write_sync(path: Path, data: str):
    """Write to temp file then rename - prevents partial reads on crash."""
    tmp=path.with_suffix(".tmp")
    tmp.write_text(data,encoding="utf-8")
    tmp.replace(path)

async def _atomic_write(path: Path, data: str):
    """Async wrapper for atomic write - doesn't block event loop."""
    loop=asyncio.get_event_loop()
    await loop.run_in_executor(None, _atomic_write_sync, path, data)

async def _async_read(path: Path):
    """Async file read - doesn't block event loop."""
    loop=asyncio.get_event_loop()
    return await loop.run_in_executor(None, path.read_text)

DEF_REF={
    "updated_at":None,"latest_version":"1.28.0",
    "ports":{"base":[
        {"port":1789,"proto":"tcp","desc":"Mixnet"},
        {"port":1790,"proto":"tcp","desc":"Verloc"},{"port":8080,"proto":"tcp","desc":"Node API"}],
      "gateway_extra":[{"port":9000,"proto":"tcp","desc":"Clients WS"}],
      "gateway_infra":[{"port":80,"proto":"tcp","desc":"HTTP (nginx)"},{"port":443,"proto":"tcp","desc":"HTTPS (nginx)"},{"port":9001,"proto":"tcp","desc":"WSS (nginx)"}],
      "wireguard_extra":[{"port":51822,"proto":"udp","desc":"WireGuard"}],"ntm_extra":[{"port":41264,"proto":"tcp","desc":"Lewes Protocol"},{"port":51264,"proto":"udp","desc":"Lewes Protocol"}]},
    "min_hardware":{"cpu_cores":2,"ram_mb":4096},"min_hardware_gateway":{"cpu_cores":4,"ram_mb":8192},
    "github_ntm_url":"https://raw.githubusercontent.com/nymtech/nym/refs/heads/develop/scripts/nym-node-setup/network-tunnel-manager.sh",
    "nodes_api":"https://validator.nymtech.net/api/v1/nym-nodes/described"
}

def load_ref():
    if REF_FILE.exists():return json.loads(REF_FILE.read_text())
    import copy;return copy.deepcopy(DEF_REF)
def save_ref(r):REF_FILE.write_text(json.dumps(r,indent=2,ensure_ascii=False))

def load_port_changes():
    if PORT_CHANGES_FILE.exists():
        try:return json.loads(PORT_CHANGES_FILE.read_text())
        except:pass
    return []

def log_port_change(event_type,details):
    changes=load_port_changes()
    changes.insert(0,{"ts":datetime.now(timezone.utc).isoformat(),"type":event_type,"details":details})
    PORT_CHANGES_FILE.write_text(json.dumps(changes[:200],ensure_ascii=False))

def _flatten_ports(ref):
    """Return sorted set of 'port/proto' strings from all port groups."""
    result=set()
    for group in ref.get("ports",{}).values():
        for p in group:
            result.add(str(p["port"])+"/"+p["proto"])
    return result

@app.get("/",include_in_schema=False)
async def frontend():return FileResponse(STATIC_DIR/"index.html")

# ── Lightweight visit analytics ─────────────────────────────
HITS_FILE=Path("nym_hits.jsonl")
HITS_MAX_BYTES=10*1024*1024  # 10 MB rotation cap

_SALT_FILE=Path("nym_vid_salt.txt")
def _get_vid_salt():
    if _SALT_FILE.exists():
        return _SALT_FILE.read_text().strip()
    s=secrets.token_hex(16)
    _SALT_FILE.write_text(s)
    return s
_VID_SALT=_get_vid_salt()

def _hash_ip(ip:str)->str:
    """Hash IP for privacy. Persistent salt so same IP = same vid across days."""
    import hashlib
    return hashlib.sha256((_VID_SALT+"|"+(ip or "")).encode()).hexdigest()[:12]

def _rotate_hits():
    try:
        if HITS_FILE.exists() and HITS_FILE.stat().st_size>HITS_MAX_BYTES:
            HITS_FILE.rename(HITS_FILE.with_suffix(".jsonl.1"))
    except Exception:pass

@app.post("/api/hit",include_in_schema=False)
async def record_hit(request:Request,payload:dict=Body(default={})):
    """Record a single visit. Lightweight, fire-and-forget."""
    if not rate_limit_check(request):
        return JSONResponse({"ok":False},status_code=429)
    try:
        client_ip=_real_ip(request)
        ua=(request.headers.get("user-agent") or "")[:200]
        ref=(request.headers.get("referer") or "")[:200]
        path=str(payload.get("path") or "/")[:120]
        lang=str(payload.get("lang") or "")[:6]
        rec={
            "ts":datetime.now(timezone.utc).isoformat(),
            "vid":_hash_ip(client_ip),
            "path":path,
            "lang":lang,
            "ua":ua[:120],
            "ref":ref[:160],
        }
        _rotate_hits()
        with open(HITS_FILE,"a",encoding="utf-8") as f:
            f.write(json.dumps(rec,ensure_ascii=False)+"\n")
    except Exception:pass
    return {"ok":True}

@app.get("/api/stats",include_in_schema=False)
async def get_stats(request:Request,_:bool=Depends(require_admin)):
    """Return aggregated visit stats from hits log."""
    from collections import Counter
    if not HITS_FILE.exists():
        return {"total":0,"unique":0,"today":0,"by_day":[],"by_path":[],"by_lang":[],"by_ref":[],"by_ua":[]}
    now=datetime.now(timezone.utc)
    today_str=now.strftime("%Y-%m-%d")
    total=0;unique=set();today=0
    by_day=Counter();by_path=Counter();by_lang=Counter();by_ref=Counter();by_ua=Counter()
    daily_unique={}
    try:
        with open(HITS_FILE,"r",encoding="utf-8") as f:
            for line in f:
                try:r=json.loads(line)
                except:continue
                total+=1
                vid=r.get("vid","")
                unique.add(vid)
                day=(r.get("ts") or "")[:10]
                if day:
                    by_day[day]+=1
                    daily_unique.setdefault(day,set()).add(vid)
                if day==today_str:today+=1
                if r.get("path"):by_path[r["path"]]+=1
                if r.get("lang"):by_lang[r["lang"]]+=1
                ref=r.get("ref","")
                if ref:
                    try:
                        from urllib.parse import urlparse
                        host=urlparse(ref).netloc or "(direct)"
                    except:host="(direct)"
                    by_ref[host]+=1
                ua=r.get("ua","")
                # Crude UA family
                fam="other"
                ual=ua.lower()
                if "bot" in ual or "crawl" in ual or "spider" in ual:fam="bot"
                elif "firefox" in ual:fam="firefox"
                elif "edg/" in ual:fam="edge"
                elif "chrome" in ual:fam="chrome"
                elif "safari" in ual:fam="safari"
                by_ua[fam]+=1
    except Exception as e:
        return {"error":str(e)}
    days_sorted=sorted(by_day.keys())[-30:]
    return {
        "total":total,
        "unique":len(unique),
        "today":today,
        "today_unique":len(daily_unique.get(today_str,set())),
        "by_day":[{"day":d,"hits":by_day[d],"unique":len(daily_unique.get(d,set()))} for d in days_sorted],
        "by_path":by_path.most_common(15),
        "by_lang":by_lang.most_common(),
        "by_ref":by_ref.most_common(15),
        "by_ua":by_ua.most_common(),
    }

@app.get("/stats",include_in_schema=False)
async def stats_page():
    return FileResponse(STATIC_DIR/"stats.html")

# ── Sync Reference ──────────────────────────────────────────
@app.post("/api/sync-reference")
async def sync_ref(_:bool=Depends(require_admin)):
    ref=load_ref();errors=[]
    async with httpx.AsyncClient(timeout=30) as c:
        try:
            r=await c.get(ref.get("github_ntm_url",DEF_REF["github_ntm_url"]))
            r.raise_for_status()
            ufw=re.findall(r'ufw\s+allow\s+(\d+)/(tcp|udp)',r.text)
            pd={22:"SSH",80:"HTTP",443:"HTTPS",1789:"Mixnet",1790:"Verloc",8080:"Node API",9000:"Clients",9001:"WSS",51822:"WireGuard"}
            def build(nums,fp="tcp"):
                found=[(int(p),pr) for p,pr in ufw if int(p) in nums]
                res=[{"port":p,"proto":pr,"desc":pd.get(p,"Port "+str(p))} for p,pr in sorted(found)]
                for p in sorted(nums):
                    if not any(x["port"]==p for x in res):res.append({"port":p,"proto":fp,"desc":pd.get(p,"Port "+str(p))})
                return res
            ref["ports"]["base"]=build({1789,1790,8080})
            ref["ports"]["gateway_extra"]=build({9000})
            ref["ports"]["gateway_infra"]=build({80,443,9001})
            ref["ports"]["wireguard_extra"]=build({51822},"udp")
            # Parse NTM bash arrays for gateway-specific ports
            ntm_tcp=set(int(p) for p in re.findall(r'local tcp_ports=\(([^)]+)\)',r.text)[0].split()) if re.findall(r'local tcp_ports=\(([^)]+)\)',r.text) else set()
            ntm_udp=set(int(p) for p in re.findall(r'local udp_ports=\(([^)]+)\)',r.text)[0].split()) if re.findall(r'local udp_ports=\(([^)]+)\)',r.text) else set()
            known={22,80,443,1789,1790,8080,9000,9001,51822,4443}
            ntm_extra_tcp=ntm_tcp-known;ntm_extra_udp=ntm_udp-known
            ntm_ports=[]
            for p in sorted(ntm_extra_tcp):ntm_ports.append({"port":p,"proto":"tcp","desc":pd.get(p,"Lewes Protocol") if p==41264 else pd.get(p,"NTM TCP ")+str(p)})
            for p in sorted(ntm_extra_udp):ntm_ports.append({"port":p,"proto":"udp","desc":pd.get(p,"Lewes Protocol") if p==51264 else pd.get(p,"NTM UDP ")+str(p)})
            ref["ports"]["ntm_extra"]=ntm_ports  # always set, even if empty (clears stale ports)
        except Exception as e:errors.append("NTM: "+str(e))
        try:
            # Fetch all recent releases to detect both stable and pre-release
            r=await c.get("https://api.github.com/repos/nymtech/nym/releases?per_page=20",
                          headers={"Accept":"application/vnd.github.v3+json"},timeout=15)
            r.raise_for_status();all_rels=r.json()
            # Most recent stable (not draft, not prerelease) and most recent prerelease
            stable_rel=next((rl for rl in all_rels if not rl.get("draft") and not rl.get("prerelease")),None)
            prerel_rel=next((rl for rl in all_rels if not rl.get("draft") and rl.get("prerelease")),None)
            # Only keep prerelease if published AFTER the stable (otherwise stale)
            if stable_rel and prerel_rel:
                if prerel_rel.get("published_at","")<=stable_rel.get("published_at",""):
                    prerel_rel=None
            async def _bv_from_rel(rel):
                if not rel:return ""
                hashes_url=next((a["browser_download_url"] for a in rel.get("assets",[]) if a.get("name")=="hashes.json"),None)
                if not hashes_url:return ""
                try:
                    r2=await c.get(hashes_url,timeout=15,follow_redirects=True);r2.raise_for_status()
                    bv=r2.json().get("assets",{}).get("nym-node",{}).get("details",{}).get("build_version","")
                    return bv if re.match(r"^\d+\.\d+\.\d+$",bv) else ""
                except:return ""
            stable_bv=await _bv_from_rel(stable_rel)
            prerel_bv=await _bv_from_rel(prerel_rel)
            if stable_bv:
                ref["latest_version"]=stable_bv
                print("[*] Stable version: "+stable_bv)
            else:
                errors.append("No stable version detected from releases")
            if prerel_bv and prerel_bv!=stable_bv:
                ref["prerelease_version"]=prerel_bv
                print("[*] Pre-release version: "+prerel_bv)
            else:
                # Clear stale prerelease_version if no current prerelease exists
                ref.pop("prerelease_version",None)
        except Exception as e:errors.append("Version: "+str(e))
    # 3) Save release download URLs
        try:
            r2=await c.get("https://api.github.com/repos/nymtech/nym/releases?per_page=20",headers={"Accept":"application/vnd.github.v3+json"},timeout=15)
            if r2.status_code==200:
                releases=[]
                for rel in r2.json():
                    tag=rel.get("tag_name","")
                    for a in rel.get("assets",[]):
                        if a.get("name")=="nym-node":
                            releases.append({"tag":tag,"url":a.get("browser_download_url","")})
                            break
                ref["releases"]=releases
        except Exception as e:
            errors.append("Releases list: "+str(e))

        ref["updated_at"]=datetime.now(timezone.utc).isoformat()
    # ── Detect port changes ──────────────────────────────────
    old_ports=_flatten_ports(load_ref())
    new_ports=_flatten_ports(ref)
    added=new_ports-old_ports;removed=old_ports-new_ports
    if added:log_port_change("ports_added",{"ports":sorted(added)})
    if removed:log_port_change("ports_removed",{"ports":sorted(removed)})

    # ── Scan recent changelogs for port mentions ─────────────
    try:
        async with httpx.AsyncClient(timeout=15) as cc:
            rr=await cc.get("https://api.github.com/repos/nymtech/nym/releases?per_page=10",
                            headers={"Accept":"application/vnd.github.v3+json"})
            if rr.status_code==200:
                known_ports={str(p["port"]) for grp in ref.get("ports",{}).values() for p in grp}
                for rel in rr.json():
                    body=(rel.get("body") or "").lower()
                    tag=rel.get("tag_name","")
                    # Find port numbers mentioned near firewall keywords
                    candidates=set()
                    for m in re.finditer(r'(?:port|ufw allow|open|firewall)[^\n]{0,40}?(\d{4,5})',body):
                        candidates.add(m.group(1))
                    for m in re.finditer(r'(\d{4,5})[^\n]{0,30}(?:port|tcp|udp)',body):
                        candidates.add(m.group(1))
                    new_in_notes=candidates-known_ports
                    if new_in_notes:
                        log_port_change("changelog_mention",{"release":tag,"possible_new_ports":sorted(new_in_notes)})
    except Exception as e:
        errors.append("Changelog scan: "+str(e))

    save_ref(ref)
    return{"status":"ok" if not errors else "partial","errors":errors,"reference":ref}

@app.get("/api/reference")
async def get_ref():return load_ref()

@app.get("/api/port-changes")
async def get_port_changes():return load_port_changes()

_price_cache={"data":None,"ts":0}
@app.get("/api/price")
async def get_price():
    now=time.time()
    if _price_cache["data"] and now-_price_cache["ts"]<300:
        return _price_cache["data"]
    async with httpx.AsyncClient(timeout=10) as cl:
        r=await cl.get("https://api.coingecko.com/api/v3/simple/price?ids=nym&vs_currencies=usd&include_24hr_change=true")
        r.raise_for_status()
        d=r.json().get("nym",{})
        _price_cache["data"]=d
        _price_cache["ts"]=now
        return d

@app.get("/api/network-stats")
async def network_stats():
    nodes=await _cnodes();ref=load_ref();latest=ref.get("latest_version","");prerelease=ref.get("prerelease_version")
    total=len(nodes)
    if not total:return{"total":0}
    by_mode={"mixnode":0,"entry-gateway":0,"exit-gateway":0,"unknown":0}
    ver_buckets={0:0,1:0,2:0,3:0,4:0}  # behind-buckets only
    ver_status_counts={"current":0,"prerelease":0,"ahead":0,"behind":0,"unknown":0}
    toc_ok=wg_ok=fully_compliant=0
    ipv6_trusted=ipv6_confirmed=ipv6_absent=ipv6_unknown=0
    # SMTP aggregates (exit gateways only)
    smtp_open=smtp_partial=smtp_blocked=smtp_unknown=0
    for n in nodes:
        by_mode[n.get("mode","unknown")]=by_mode.get(n.get("mode","unknown"),0)+1
        vr=_build_version_response(n.get("version",""),latest,prerelease)
        ver_status_counts[vr["status"]]=ver_status_counts.get(vr["status"],0)+1
        # behind-diff buckets (only for outdated, current/prerelease/ahead go to bucket 0)
        if vr["ok"]:
            ver_buckets[0]+=1
        else:
            ver_buckets[min(_ver_diff(n.get("version",""),latest),4)]+=1
        _toc=n.get("toc")
        if _toc:toc_ok+=1
        st=n.get("ipv6_status","unknown")
        _ipv6=st in ("trusted","confirmed")
        if st=="trusted":ipv6_trusted+=1
        elif st=="confirmed":ipv6_confirmed+=1
        elif st=="absent":ipv6_absent+=1
        else:ipv6_unknown+=1
        if n.get("wg"):wg_ok+=1
        if vr["ok"] and _toc and _ipv6:fully_compliant+=1
        # SMTP status for exit gateways
        if n.get("mode")=="exit-gateway":
            s=_smtp_cache.get(n.get("ip",""),{})
            st_smtp=s.get("status","unknown")
            if st_smtp=="open":smtp_open+=1
            elif st_smtp=="partial":smtp_partial+=1
            elif st_smtp=="blocked":smtp_blocked+=1
            else:smtp_unknown+=1
    ipv6_ok=ipv6_trusted+ipv6_confirmed
    issues=sorted([
        {"key":"outdated","label":"Outdated version","count":total-ver_buckets[0]},
        {"key":"noToc","label":"T&C not accepted","count":total-toc_ok},
        {"key":"noIpv6","label":"No IPv6","count":total-ipv6_ok},
    ],key=lambda x:-x["count"])
    return{
        "total":total,
        "fully_compliant":fully_compliant,
        "by_mode":by_mode,
        "version":{"current":ver_buckets[0],"behind_1":ver_buckets[1],"behind_2":ver_buckets[2],"behind_3":ver_buckets[3],"behind_4plus":ver_buckets[4],
            "by_status":ver_status_counts},
        "toc":{"accepted":toc_ok,"not_accepted":total-toc_ok},
        "ipv6":{"trusted":ipv6_trusted,"confirmed":ipv6_confirmed,"absent":ipv6_absent,"unknown":ipv6_unknown,"enabled":ipv6_ok,"disabled":total-ipv6_ok},
        "wg":{"enabled":wg_ok,"disabled":total-wg_ok},
        "smtp":{"open":smtp_open,"partial":smtp_partial,"blocked":smtp_blocked,"unknown":smtp_unknown,
            "total_exits":smtp_open+smtp_partial+smtp_blocked+smtp_unknown},
        "top_issues":issues,
        "latest_version":latest,
        "prerelease_version":prerelease,
        "cache_note":"Port status not included - requires per-node scan"
    }

# ── Deploy Recommendations ──────────────────────────────────
try:
    from nym_country_data import country_score as _country_score, COUNTRIES as _COUNTRIES
    _DEPLOY_AVAILABLE = True
except Exception as e:
    print(f"[!] nym_country_data not available: {e}")
    _DEPLOY_AVAILABLE = False

try:
    from nym_provider_data import aggregate_providers as _aggregate_providers, PROVIDERS as _PROVIDERS
    _PROVIDERS_AVAILABLE = True
except Exception as e:
    print(f"[!] nym_provider_data not available: {e}")
    _PROVIDERS_AVAILABLE = False

ASN_DATA_FILE = Path("/opt/nym-probe/asn_data.json")
_asn_cache = {"ip_to_asn": {}, "asn_names": {}}
def _load_asn_cache():
    global _asn_cache
    if ASN_DATA_FILE.exists():
        try:
            _asn_cache = json.loads(ASN_DATA_FILE.read_text())
            print(f"[*] ASN cache loaded: {len(_asn_cache.get('ip_to_asn',{}))} IPs, {len(_asn_cache.get('asn_names',{}))} ASNs")
        except Exception as e:
            print(f"[!] ASN cache load error: {e}")

@app.get("/api/deploy-providers")
async def deploy_providers():
    """Hosting provider analysis - aggregate nodes by ASN, score each provider."""
    if not _PROVIDERS_AVAILABLE:
        return JSONResponse({"error":"providers module not loaded"},status_code=500)
    nodes = await _cnodes()
    total = len(nodes)
    if not total:
        return {"error":"no nodes","total":0}
    ip_to_asn = _asn_cache.get("ip_to_asn",{})
    asn_names = _asn_cache.get("asn_names",{})
    results = _aggregate_providers(nodes, ip_to_asn, asn_names, total, smtp_cache=_smtp_cache)
    # Group by classification, sort each group by score desc within group
    grouped = {}
    for r in results:
        grouped.setdefault(r["classification"], []).append(r)
    for k in grouped:
        grouped[k].sort(key=lambda x: -x.get("score", 0))
    return {
        "total_nodes": total,
        "providers": results[:50],
        "by_classification": grouped,
        "asn_coverage": len(ip_to_asn),
    }

@app.get("/api/deploy-provider/{asn}")
async def deploy_provider_detail(asn: str):
    """Detail view for one provider/ASN: score + list of nodes there."""
    if not _PROVIDERS_AVAILABLE:
        return JSONResponse({"error":"providers module not loaded"},status_code=500)
    asn = str(asn).strip().lstrip("AS").lstrip("as")[:10]
    if not asn.isdigit():
        return JSONResponse({"error":"invalid asn"},status_code=400)
    nodes = await _cnodes()
    total = len(nodes)
    ip_to_asn = _asn_cache.get("ip_to_asn",{})
    asn_names = _asn_cache.get("asn_names",{})
    in_provider = [n for n in nodes if (ip_to_asn.get(n.get("ip","")) or {}).get("asn") == asn]
    if not in_provider:
        return JSONResponse({"error":"no nodes in this ASN"},status_code=404)
    # Compute score for this provider
    from nym_provider_data import provider_score as _provider_score
    smtp_stats = {"open":0,"partial":0,"blocked":0,"unknown":0}
    if _smtp_cache:
        for n in in_provider:
            if n.get("mode") != "exit-gateway":
                continue
            s = _smtp_cache.get(n.get("ip",""))
            if s:
                st = s.get("status","unknown")
                if st in smtp_stats:
                    smtp_stats[st] += 1
    score = _provider_score(asn, len(in_provider), total,
                             smtp_stats=smtp_stats if any(smtp_stats.values()) else None,
                             fallback_name=asn_names.get(asn,""))
    score["smtp_stats"] = smtp_stats if any(smtp_stats.values()) else None
    # Country breakdown for this provider
    from collections import Counter
    by_country = Counter()
    for n in in_provider:
        cc = (n.get("location") or "").upper()
        if cc:
            by_country[cc] += 1
    score["by_country"] = [{"cc": cc, "count": cnt} for cc, cnt in by_country.most_common()]
    # Slim node list
    node_list = []
    for n in sorted(in_provider, key=lambda x: x.get("moniker","").lower()):
        node_list.append({
            "node_id": n.get("node_id"),
            "ip": n.get("ip"),
            "moniker": n.get("moniker"),
            "hostname": n.get("hostname"),
            "mode": n.get("mode"),
            "location": n.get("location"),
            "version": n.get("version"),
            "wg": n.get("wg"),
        })
    score["nodes"] = node_list
    return score

@app.get("/api/deploy-country/{cc}")
async def deploy_country_detail(cc: str):
    """Detailed view for one country: score + list of nodes there."""
    if not _DEPLOY_AVAILABLE:
        return JSONResponse({"error":"deploy data not loaded"},status_code=500)
    cc = cc.upper()[:2]
    if cc not in _COUNTRIES:
        return JSONResponse({"error":"country not in database"},status_code=404)
    nodes = await _cnodes()
    total = len(nodes)
    in_country = [n for n in nodes if (n.get("location") or "").upper() == cc]
    score = _country_score(cc, len(in_country), total)
    score["cc"] = cc
    # Slim node info
    node_list = []
    for n in sorted(in_country, key=lambda x: x.get("moniker","").lower()):
        node_list.append({
            "node_id": n.get("node_id"),
            "ip": n.get("ip"),
            "moniker": n.get("moniker"),
            "hostname": n.get("hostname"),
            "mode": n.get("mode"),
            "version": n.get("version"),
            "wg": n.get("wg"),
        })
    return {**score, "nodes": node_list}

@app.get("/api/deploy-recommendations")
async def deploy_recommendations():
    """Where-to-deploy recommendations based on country demand/saturation/operator risk."""
    if not _DEPLOY_AVAILABLE:
        return JSONResponse({"error":"deploy data not loaded"},status_code=500)
    nodes = await _cnodes()
    total = len(nodes)
    if not total:
        return {"error":"no nodes data","total":0}
    # Count nodes per country
    by_country = {}
    for n in nodes:
        cc = (n.get("location") or "").upper()
        if cc:
            by_country[cc] = by_country.get(cc, 0) + 1
    # Score every known country
    results = []
    for cc in _COUNTRIES:
        s = _country_score(cc, by_country.get(cc, 0), total)
        s["cc"] = cc
        results.append(s)
    # Group by classification
    grouped = {}
    for r in results:
        grouped.setdefault(r["classification"], []).append(r)
    # Sort each group by score descending
    for g in grouped.values():
        g.sort(key=lambda x: -x.get("score", 0))
    # Top recommendations (combining highly_recommended + top good)
    top = sorted(
        [r for r in results if r["classification"] in ("highly_recommended","good") and r.get("nodes_here",0) < 20],
        key=lambda x: -x.get("score", 0)
    )[:15]
    return {
        "total_nodes": total,
        "top_recommended": top,
        "by_classification": grouped,
        "classifications": {
            "highly_recommended": "High demand, low saturation, operator-safe - deploy here",
            "good": "Good deployment target, reasonable demand and safety",
            "saturated": "Already many nodes here, diminishing returns",
            "caution": "Restricted VPN laws for users but operators generally safe - verify locally",
            "not_recommended": "Local environment is hostile to privacy infrastructure operators - not recommended",
            "low_demand": "Safe but low user demand (small population or low internet/income)",
        },
    }

# ── Port Check ──────────────────────────────────────────────
async def ck_tcp(host,port,to=3.0):
    """Native asyncio TCP check. Does NOT use the thread pool, so batch checks
    with hundreds of parallel port probes don't starve the executor."""
    writer=None
    try:
        _,writer=await asyncio.wait_for(asyncio.open_connection(host,port),timeout=to)
        return True
    except:
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except:pass

class _QUICProbeProto(asyncio.DatagramProtocol):
    """Receives any UDP data back from the target. Presence of ANY reply to our
    QUIC Version Negotiation trigger is proof that a QUIC server is listening."""
    def __init__(self):
        self.got_reply=False
        self.done=asyncio.Event()
    def datagram_received(self,data,addr):
        if data and len(data)>=5:
            self.got_reply=True
            self.done.set()
    def error_received(self,exc):
        # ICMP port unreachable etc. — leave got_reply False
        self.done.set()
    def connection_lost(self,exc):
        self.done.set()

def _build_quic_vn_trigger():
    """Build a QUIC long-header packet with an unsupported version. Per
    RFC 9000 section 6, a QUIC server MUST respond with a Version Negotiation
    packet listing its supported versions. This requires no cryptography and
    no knowledge of the server's keys — it is a pure protocol-level handshake
    trigger. Pad to 1200 bytes to avoid amplification-limit drops."""
    import os as _os
    # Long header: 0xc0 (header form=1, fixed=1, type=Initial, reserved/pn=0)
    # Any value with top two bits '11' and unknown version will trigger VN.
    header=bytes([0xc0])
    version=bytes([0x1a,0x2a,0x3a,0x4a])  # unassigned version
    dcid=_os.urandom(8)
    dcid_len=bytes([len(dcid)])
    scid=_os.urandom(8)
    scid_len=bytes([len(scid)])
    # Token length (varint) + token (empty)
    token_len=bytes([0x00])
    # Length field (varint, 2 bytes) — we set a dummy length
    length=bytes([0x40,0x00])
    payload=header+version+dcid_len+dcid+scid_len+scid+token_len+length
    # Pad to 1200 bytes total so servers don't drop us for amplification rules
    if len(payload)<1200:
        payload+=b'\x00'*(1200-len(payload))
    return payload

async def ck_quic(host,port,to=2.5):
    """Application-level UDP probe for QUIC ports. Sends a QUIC Version
    Negotiation trigger and waits for ANY UDP reply. Any reply proves the port
    is open and a QUIC server is listening. No reply within timeout = treated
    as closed/unreachable.

    This is deterministic, unlike ICMP-based UDP probing which depends on
    whether the host bothers to send ICMP port-unreachable (rate-limited,
    often dropped)."""
    loop=asyncio.get_event_loop()
    transport=None
    proto=None
    try:
        transport,proto=await asyncio.wait_for(
            loop.create_datagram_endpoint(lambda:_QUICProbeProto(),remote_addr=(host,port)),
            timeout=to)
        try:transport.sendto(_build_quic_vn_trigger())
        except:return False
        try:
            await asyncio.wait_for(proto.done.wait(),timeout=to)
        except asyncio.TimeoutError:
            pass
        return proto.got_reply
    except:
        return False
    finally:
        if transport is not None:
            try:transport.close()
            except:pass

class _UDPProbeProto(asyncio.DatagramProtocol):
    """Generic UDP probe. Sends a small packet and listens for ICMP unreachable.
    ICMP unreachable = port closed. Timeout (no ICMP) = port open (service is listening)."""
    def __init__(self):
        self.got_icmp_error=False
        self.done=asyncio.Event()
    def datagram_received(self,data,addr):
        # Any response = definitely open
        self.done.set()
    def error_received(self,exc):
        # ICMP port unreachable / host unreachable
        self.got_icmp_error=True
        self.done.set()
    def connection_lost(self,exc):
        self.done.set()

async def ck_udp_probe(host,port,to=2.0):
    """Send a small UDP packet, wait for ICMP error. No error = open."""
    loop=asyncio.get_event_loop()
    transport=None
    try:
        transport,proto=await asyncio.wait_for(
            loop.create_datagram_endpoint(lambda:_UDPProbeProto(),remote_addr=(host,port)),
            timeout=to)
        try:transport.sendto(b'\x00'*8)
        except:return False
        try:
            await asyncio.wait_for(proto.done.wait(),timeout=to)
        except asyncio.TimeoutError:
            pass
        # No ICMP error and no response = port open (service silently dropped our garbage)
        return not proto.got_icmp_error
    except:
        return False
    finally:
        if transport is not None:
            try:transport.close()
            except:pass

async def ck_udp(host,port,to=3.0):
    """UDP port check. QUIC ports get a proper VN probe, others get ICMP-based probe."""
    if port==4443:
        return await ck_quic(host,port,to)
    return await ck_udp_probe(host,port,to)

def _udp_verifiable(port):
    """QUIC 4443 is deterministically verified. Other UDP uses ICMP heuristic (likely_open)."""
    return port==4443


# ── Exit Policy (fetched from official Nym source) ──
EXIT_POLICY_URL = "https://nymtech.net/.wellknown/network-requester/exit-policy.txt"
_exit_policy_cache = {"ports": [], "version": None, "fetched_at": None}

import re as _re

def _parse_exit_policy(text):
    """Parse official Nym exit-policy.txt, extract accepted ports with descriptions."""
    ports = []
    seen = set()
    version = None
    # Extract version from first comment line
    for line in text.splitlines():
        if line.startswith("# Nym Node exit policy"):
            vm = _re.search(r"v([\d.]+)", line)
            if vm:
                version = vm.group(1)
            break
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ExitPolicy accept"):
            continue
        # Format: ExitPolicy accept *:<port_or_range> # Description
        m = _re.match(r"ExitPolicy accept \*:(\d+)(?:-(\d+))?\s*(?:#\s*(.*))?", line)
        if not m:
            continue
        p_start = int(m.group(1))
        p_end = int(m.group(2)) if m.group(2) else p_start
        desc = (m.group(3) or "").strip()
        # Clean desc: remove parenthetical abuse warnings
        desc = _re.sub(r"\s*\(.*?\)", "", desc).strip(" -,")
        if not desc:
            desc = str(p_start)
        if p_end - p_start > 5:
            # Range with more than 5 ports — store as range
            key = f"{p_start}-{p_end}"
            if key not in seen:
                seen.add(key)
                ports.append({"port": key, "proto": "tcp", "desc": desc})
        else:
            for p in range(p_start, p_end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append({"port": p, "proto": "tcp", "desc": desc})
    ports.sort(key=lambda x: int(str(x["port"]).split("-")[0]))
    return ports, version

async def _fetch_exit_policy():
    """Fetch and cache exit policy from official Nym source."""
    import httpx
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    # Return cache if fresh (1 hour)
    if (_exit_policy_cache["fetched_at"] and
        (now - _exit_policy_cache["fetched_at"]).total_seconds() < 3600 and
        _exit_policy_cache["ports"]):
        return _exit_policy_cache
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(EXIT_POLICY_URL, timeout=10)
            if r.status_code == 200:
                ports, version = _parse_exit_policy(r.text)
                _exit_policy_cache["ports"] = ports
                _exit_policy_cache["version"] = version
                _exit_policy_cache["fetched_at"] = now
                print(f"[*] Exit policy fetched: v{version}, {len(ports)} ports")
    except Exception as e:
        print(f"[!] Exit policy fetch failed: {e}")
    return _exit_policy_cache

def get_exit_policy():
    """Return cached exit policy synchronously (cache is filled by background tasks)."""
    if not _exit_policy_cache["ports"]:
        return None
    return {
        "declared": True,
        "ports": _exit_policy_cache["ports"],
        "total": len(_exit_policy_cache["ports"]),
        "status": "standard",
        "policy_version": _exit_policy_cache["version"]
    }

# ── Node API Query ──────────────────────────────────────────
MAX_NODE_RESPONSE_BYTES = 1_000_000  # 1 MB cap on any response from arbitrary node

async def _safe_json(client, url, timeout=5):
    """GET url and parse JSON, but refuse responses larger than MAX_NODE_RESPONSE_BYTES."""
    try:
        async with client.stream("GET", url, timeout=timeout) as r:
            if r.status_code != 200:
                return None
            cl = r.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > MAX_NODE_RESPONSE_BYTES:
                return None
            total = 0
            chunks = []
            async for chunk in r.aiter_bytes():
                total += len(chunk)
                if total > MAX_NODE_RESPONSE_BYTES:
                    return None
                chunks.append(chunk)
            try:
                return json.loads(b"".join(chunks))
            except Exception:
                return None
    except Exception:
        return None

async def qnode(client,host,port=8080):
    """Query node API on port 8080 only. No fallback to port 80."""
    res={"reachable":False,"roles":None,"description":None,"build_info":None,"auxiliary":None,"host_info":None,"gateway":None,"lp":None}
    base=f"http://{_host_for_url(host)}:{port}/api/v1"
    roles=await _safe_json(client,base+"/roles",timeout=5)
    if roles is not None:
        res["reachable"]=True;res["roles"]=roles
        endpoints={"description":"/description","build_info":"/build-information","auxiliary":"/auxiliary-details","host_info":"/host-information","gateway":"/gateway","lp":"/lewes-protocol"}
        async def _fetch(k,p):
            v=await _safe_json(client,base+p,timeout=5)
            return k,v
        pairs=await asyncio.gather(*[_fetch(k,p) for k,p in endpoints.items()])
        for k,v in pairs:
            if v is not None:res[k]=v
    return res

# IPV6_AGENT_URL set via env (see top). IPV6_AGENT here for legacy code paths only;
# always check _ipv6_agent_enabled before using.
IPV6_AGENT = IPV6_AGENT_URL or ""

# In-memory cache of IPv6 results to prevent flip-flop on agent timeouts.
# Key: ip, Value: {"status": "trusted"|"confirmed"|"absent"|"unknown", "ts": float}
# trusted  = api/dns said yes (self-declared, not probe-verified)
# confirmed = Stockholm agent actually connected over IPv6
# absent   = Stockholm explicitly said no (short TTL, needs re-check)
# unknown  = timeout/error, no data yet
_ipv6_cache = {}
_IPV6_ABSENT_TTL = 3600 * 6  # 6h - absent is re-checkable, not permanent

# ── SMTP egress cache ───────────────────────────────────────
# Loaded from SMTP_RESULTS_FILE_PATH (env-configurable, produced by daily probe)
# Keyed by IP string -> {"status": "open"|"partial"|"blocked", "open_on": [...], "blocked_on": [...]}
SMTP_RESULTS_FILE = Path(SMTP_RESULTS_FILE_PATH)
_smtp_cache = {}   # ip_str -> dict
_smtp_meta = {}    # "when", "total", etc.

def _load_smtp_cache():
    """Load SMTP probe results from disk into memory, keyed by IP."""
    global _smtp_cache, _smtp_meta
    if not SMTP_RESULTS_FILE.exists():
        print("[*] SMTP cache file not found, skipping")
        return
    try:
        raw = json.loads(SMTP_RESULTS_FILE.read_text())
        file_mtime = SMTP_RESULTS_FILE.stat().st_mtime
        cache = {}
        for _key, entry in raw.items():
            ip = entry.get("ip")
            if not ip:
                continue
            overall = entry.get("overall", "").upper()
            if overall == "FULLY_OPEN":
                status = "open"
            elif overall == "PARTIAL":
                status = "partial"
            elif overall == "HOSTER_BLOCKED":
                status = "blocked"
            else:
                status = "unknown"
            cache[ip] = {
                "status": status,
                "ok": status == "open",
                "open_on": entry.get("open_on", []),
                "blocked_on": entry.get("blocked_on", []),
            }
        _smtp_cache = cache
        _smtp_meta = {
            "loaded": datetime.now(timezone.utc).isoformat(),
            "file_mtime": file_mtime,
            "checked_at": datetime.fromtimestamp(file_mtime, tz=timezone.utc).isoformat(),
            "total": len(cache),
        }
        print(f"[*] SMTP cache loaded: {len(cache)} exits (probed {_smtp_meta['checked_at']})")
    except Exception as e:
        print(f"[!] SMTP cache load error: {e}")

async def _ask_stockholm_single(client, url, timeout=5):
    """Single attempt to query Stockholm agent. Returns True/False/None (None=timeout)."""
    try:
        r = await client.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json().get("supported", False)
    except:
        pass
    return None

async def ck_ipv6(client, host, ipv6_hint=None, hostname=None):
    """Check IPv6 with retry. Timeout never flips trusted/confirmed->false."""
    # 1) Self-declared IPv6 in host_info (ipv6_hint comes from there)
    if ipv6_hint:
        if _is_private_ip(ipv6_hint):
            ipv6_hint = None
        else:
            _ipv6_cache[host] = {"status": "trusted", "ts": time.time()}
            return True

    # 2) DNS AAAA lookup
    if hostname:
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, 8080, socket.AF_INET6)
            )
            if infos:
                _ipv6_cache[host] = {"status": "trusted", "ts": time.time()}
                return True
        except Exception:
            pass

    # 3) Stockholm agent (2 attempts, 5s each) - only if enabled by env config
    result = None
    if _ipv6_agent_enabled:
        url = f"{IPV6_AGENT}/check_ipv6?host={host}&port=8080"
        for _ in range(2):
            result = await _ask_stockholm_single(client, url, timeout=5)
            if result is not None:
                break

    if result is True:
        _ipv6_cache[host] = {"status": "confirmed", "ts": time.time()}
        return True
    if result is False:
        # Don't let one negative override existing trusted/confirmed
        cached = _ipv6_cache.get(host)
        if cached and cached["status"] in ("trusted", "confirmed") and time.time() - cached["ts"] < 86400:
            return True
        # Also check file cache
        if CACHE_FILE.exists():
            try:
                for n in json.loads(CACHE_FILE.read_text()).get("nodes", []):
                    if n.get("ip") == host and n.get("ipv6_status") in ("trusted", "confirmed"):
                        _ipv6_cache[host] = {"status": n["ipv6_status"], "ts": time.time()}
                        return True
            except:
                pass
        _ipv6_cache[host] = {"status": "absent", "ts": time.time()}
        return False

    # Timeout - never flip trusted/confirmed to false
    cached = _ipv6_cache.get(host)
    if cached and cached["status"] in ("trusted", "confirmed") and time.time() - cached["ts"] < 86400:
        return True
    # Also check file cache (from daily scan)
    if CACHE_FILE.exists():
        try:
            for n in json.loads(CACHE_FILE.read_text()).get("nodes", []):
                if n.get("ip") == host and n.get("ipv6_status") in ("trusted", "confirmed"):
                    _ipv6_cache[host] = {"status": n["ipv6_status"], "ts": time.time()}
                    return True
        except:
            pass
    # No positive signal at all - return unknown (shown as false in UI but not cached as absent)
    _ipv6_cache[host] = {"status": "unknown", "ts": time.time()}
    return False

def _build_ipv6_response(ip, supported):
    """Build rich IPv6 response with status, source, checked_at, transport_security."""
    cache_entry=_ipv6_cache.get(ip,{})
    status=cache_entry.get("status","unknown")
    if not supported and status not in ("absent",):status="unknown"
    resp={"supported":supported,"ok":supported,"status":status}
    # Try to get source/checked_at from node cache file
    try:
        for n in json.loads(CACHE_FILE.read_text()).get("nodes",[]):
            if n.get("ip")==ip:
                if n.get("ipv6_source"):resp["source"]=n["ipv6_source"]
                if n.get("ipv6_checked_at"):resp["checked_at"]=n["ipv6_checked_at"]
                if n.get("ipv6_status"):resp["status"]=n["ipv6_status"]
                break
    except:pass
    # Additive optional field: transport_security for stockholm-sourced status
    if resp.get("source") == "stockholm" or resp.get("status") == "confirmed":
        resp["transport_security"] = "secure" if _ipv6_agent_secure else "insecure"
    return resp

# ── Main Check ──────────────────────────────────────────────
# Batch check limits
MAX_BATCH = 35             # max nodes per /api/check-batch request
BATCH_CONCURRENCY = 10     # max parallel qnode() checks inside a batch
_probe_sem = asyncio.Semaphore(50)  # global limit on concurrent probes (TCP/UDP/QUIC)

async def _check_ip(client,ip,hostname,ref):
    """Run full check for an already-resolved IP. Shared by /api/check and /api/check-batch."""
    nd=await qnode(client,ip)
    if not nd["reachable"]:return _fail(ip,ref,"API on port 8080 not responding",hostname)
    roles=nd["roles"] or {};build=nd["build_info"] or {};desc=nd["description"] or {}
    is_mix=roles.get("mixnode_enabled",False)
    is_entry=roles.get("gateway_enabled",False)
    is_exit=roles.get("network_requester_enabled",False) or roles.get("ip_packet_router_enabled",False)
    mode="exit-gateway" if is_exit else("entry-gateway" if is_entry else("mixnode" if is_mix else "unknown"))
    cur=build.get("build_version","unknown");lat=ref.get("latest_version","unknown")
    wg=roles.get("authenticator_enabled",False)
    if nd["host_info"] and isinstance(nd["host_info"],dict):wg=wg or bool(nd["host_info"].get("wireguard",{}).get("enabled"))
    # Build port lists using announced ports where available, falling back to defaults
    aux=nd["auxiliary"] or {}
    _ann=aux.get("announce_ports",{}) if isinstance(aux,dict) else {}
    _host_info=nd["host_info"] or {}
    _hi_data=_host_info.get("data",_host_info) if isinstance(_host_info,dict) else {}
    _node_hostname=_hi_data.get("hostname")
    # Gateway endpoint returns WG + WS/WSS ports in one response
    _gw=nd.get("gateway") or {}
    _gw_data=_gw.get("client_interfaces",_gw) if isinstance(_gw,dict) else {}
    _ws_iface=(_gw_data.get("mixnet_websockets") or {}) if isinstance(_gw_data,dict) else {}
    _wg_iface=(_gw_data.get("wireguard") or {}) if isinstance(_gw_data,dict) else {}
    # LP endpoint: control_port (TCP) + data_port (UDP)
    _lp=nd.get("lp") or {}
    _lp_data=(_lp.get("data") or _lp) if isinstance(_lp,dict) else {}
    # Announced ports (use announced if set, otherwise defaults). Treat 0 as "not set".
    _mix_port=_ann.get("mix_port") or 1789
    _verloc_port=_ann.get("verloc_port") or 1790
    _ws_port=_ws_iface.get("ws_port") or 9000
    _wss_port=_ws_iface.get("wss_port") or 9001
    _wg_tunnel_port=_wg_iface.get("tunnel_port") or _wg_iface.get("port") or 51822
    _lp_control_port=_lp_data.get("control_port") or 41264
    _lp_data_port=_lp_data.get("data_port") or 51264
    # Required ports (affect score)
    rp=[{"port":_mix_port,"proto":"tcp","desc":"Mixnet"}]
    if is_mix:
        rp.append({"port":_verloc_port,"proto":"tcp","desc":"Verloc"})
    if mode in("entry-gateway","exit-gateway"):
        rp.append({"port":_ws_port,"proto":"tcp","desc":"Clients WS"})
    if wg:
        rp.append({"port":_wg_tunnel_port,"proto":"udp","desc":"WireGuard"})
    # Note: 8080 API reachability is already verified by qnode() above - no need to re-probe
    # Infrastructure ports: checked but don't affect score
    infra_ports=[]
    if mode in("entry-gateway","exit-gateway") and _node_hostname:
        # Only check nginx/TLS ports if node announces a hostname
        infra_ports.append({"port":80,"proto":"tcp","desc":"HTTP (nginx)"})
        infra_ports.append({"port":443,"proto":"tcp","desc":"HTTPS (nginx)"})
        infra_ports.append({"port":_wss_port,"proto":"tcp","desc":"WSS (nginx)"})
    if mode=="exit-gateway":
        # Use announced LP ports if available, fallback to defaults
        infra_ports.append({"port":_lp_control_port,"proto":"tcp","desc":"Lewes Protocol"})
        infra_ports.append({"port":_lp_data_port,"proto":"udp","desc":"Lewes Protocol"})
    # Extract IPv6 hint from host-info before parallel block
    _ipv6_hint=None
    if nd["host_info"] and isinstance(nd["host_info"],dict):
        _ips=nd["host_info"].get("data",nd["host_info"]).get("ip_address",[])
        _ipv6_hint=next((str(a) for a in _ips if ":" in str(a)),None)
    _hn=hostname or (nd["host_info"] or {}).get("data",nd["host_info"] or {}).get("hostname")
    # Run ports, hardware, ipv6 all in parallel (with global probe semaphore)
    async def _guarded_probe(coro):
        async with _probe_sem:
            return await coro
    all_ports=rp+infra_ports
    port_coros=[_guarded_probe(ck_tcp(ip,p["port"]) if p["proto"]=="tcp" else ck_udp(ip,p["port"])) for p in all_ports]
    all_results=await asyncio.gather(*port_coros,_phw(client,ip),ck_ipv6(client,ip,_ipv6_hint,hostname=_hn))
    port_results=all_results[:len(all_ports)];hw=all_results[-2];ipv6=all_results[-1]
    n_required=len(rp)
    op,mp,likely_open=[],[],[]
    infra_open,infra_closed=[],[]
    for idx,(pi,ok) in enumerate(zip(all_ports,port_results)):
        label=str(pi["port"])+"/"+pi["proto"]
        is_infra=idx>=n_required
        if pi["proto"]=="udp" and not _udp_verifiable(pi["port"]):
            if ok:
                likely_open.append(label)
                if is_infra: infra_open.append(label)
                else: op.append(label)
            else:
                if is_infra: infra_closed.append(label)
                else: mp.append(label)
        elif ok:
            if is_infra: infra_open.append(label)
            else: op.append(label)
        else:
            if is_infra: infra_closed.append(label)
            else: mp.append(label)
    exit_policy_results=None
    has_exit_policy=False
    if is_exit:
        # Per-node exit policy check via node API
        ep_data=await _safe_json(client,f"http://{_host_for_url(ip)}:8080/api/v1/network-requester/exit-policy",timeout=5)
        if ep_data is None:
            # Fetch failed (timeout/error) — unknown, not a hard no
            exit_policy_results={"declared":None,"status":"unknown","ports":[],"total":0,"node_enabled":None,"upstream_source":""}
            has_exit_policy=False  # conservative: don't award points on unknown
        elif ep_data.get("enabled") and ep_data.get("upstream_source"):
            has_exit_policy=True
            std=get_exit_policy()
            exit_policy_results={"declared":True,"status":"confirmed","ports":std.get("ports",[]) if std else [],"total":std.get("total",0) if std else 0,"node_enabled":True,"upstream_source":ep_data.get("upstream_source","")}
        else:
            exit_policy_results={"declared":False,"status":"absent","ports":[],"total":0,"node_enabled":False,"upstream_source":""}
    toc=aux.get("accepted_operator_terms_and_conditions",False)
    mh=ref.get("min_hardware_gateway",{}) if (is_entry or is_exit) else ref.get("min_hardware",{})
    score=_score(cur,lat,len(mp),len(rp),ipv6,hw,mh,toc,is_exit,has_exit_policy)
    # SMTP egress status (exit gateways only, informational, no score impact)
    smtp_result = None
    if is_exit:
        smtp_data = _smtp_cache.get(ip)
        file_mtime = _smtp_meta.get("file_mtime")
        age = int(time.time() - file_mtime) if file_mtime else None
        stale = age is not None and age > SMTP_STALE_SECONDS
        checked_at = _smtp_meta.get("checked_at")
        if smtp_data:
            smtp_result = dict(smtp_data)
            smtp_result["checked_at"] = checked_at
            smtp_result["age_seconds"] = age
            smtp_result["stale"] = stale
            if stale:
                # Show as unknown if data is too old
                smtp_result["status"] = "unknown"
                smtp_result["ok"] = False
        else:
            smtp_result = {"status":"unknown","ok":False,"open_on":[],"blocked_on":[],
                "checked_at":checked_at,"age_seconds":age,"stale":stale}
    return {"node_ip":ip,"hostname":hostname,"check_timestamp":datetime.now(timezone.utc).isoformat(),
        "score":score,"mode":mode,"wireguard_enabled":wg,
        "version":_build_version_response(cur,lat,ref.get("prerelease_version")),
        "ports":{"total":len(rp),"open":len(op),"missing":mp,"likely_open":likely_open,"ok":len(mp)==0,
            "infra":{"total":len(infra_ports),"open":infra_open,"closed":infra_closed,"ok":len(infra_closed)==0} if infra_ports else None},
        "ipv6":_build_ipv6_response(ip,ipv6),"hardware":hw,"toc":{"accepted":toc,"ok":toc},
        "description":{"moniker":desc.get("moniker",""),"website":desc.get("website",""),"security_contact":desc.get("security_contact","")},
        "auxiliary":{"location":aux.get("location","")},
        "roles":{"mixnode":is_mix,"entry_gateway":is_entry,"exit_gateway":is_exit},
        "exit_policy":exit_policy_results,
        "smtp":smtp_result,
        "reference_version":lat,"reference_updated":ref.get("updated_at"),"min_hardware":mh}

@app.get("/api/check")
async def check_node(request:Request,target:str=Query(...,max_length=MAX_TARGET_LEN)):
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limit_check(request,expensive=True):
        return JSONResponse({"error":"Rate limit exceeded. Try again later."},status_code=429)
    target=target.strip();ref=load_ref()
    if not target or len(target)>MAX_TARGET_LEN:
        return JSONResponse(_fail(target,ref,"Invalid target"))
    # Reject obvious attempts to hit local services by name
    if target.lower() in {"localhost","localhost.localdomain","ip6-localhost","ip6-loopback"}:
        sec_log("ssrf_blocked", client_ip, {"target": target, "reason": "local_name"})
        return JSONResponse(_fail(target,ref,"Target not allowed"))
    try:
        loop=asyncio.get_event_loop()
        infos=await loop.run_in_executor(None,lambda:socket.getaddrinfo(target,None,socket.AF_UNSPEC,socket.SOCK_STREAM))
        if not infos:raise ValueError("No address")
    except:return JSONResponse(_fail(target,ref,"DNS resolution failed"))
    # Deduplicate IPs, preserve order, filter private
    seen=set();candidates=[]
    for info in infos:
        addr=info[4][0]
        if addr not in seen:
            seen.add(addr)
            if not _is_private_ip(addr):
                candidates.append(addr)
    if not candidates:
        sec_log("ssrf_blocked", client_ip, {"target": target, "resolved": list(seen)})
        return JSONResponse(_fail(target,ref,"Target IP not allowed (private/reserved range)"))
    hostname=target if target!=candidates[0] else None
    # Try each resolved address until one responds
    async with httpx.AsyncClient() as client:
        for ip in candidates:
            result=await _check_ip(client,ip,hostname,ref)
            if not result.get("error") or "not responding" not in str(result.get("error","")):
                return JSONResponse(result)
        return JSONResponse(result)  # return last failure

@app.post("/api/check-batch")
async def check_batch(request:Request,body:dict=Body(...)):
    """Batch check multiple nodes by node_id. Max MAX_BATCH nodes per request."""
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limit_check(request,expensive=True):
        return JSONResponse({"error":"Rate limit exceeded. Try again later."},status_code=429)
    ids=body.get("ids",[]) if isinstance(body,dict) else []
    if not isinstance(ids,list):
        return JSONResponse({"error":"'ids' must be a list"},status_code=400)
    if len(ids)==0:
        return JSONResponse({"error":"'ids' is empty"},status_code=400)
    if len(ids)>MAX_BATCH:
        return JSONResponse({"error":f"Too many nodes (max {MAX_BATCH})"},status_code=400)
    # Normalize + dedupe
    seen=set();clean=[]
    for x in ids:
        try:k=int(x)
        except:continue
        if k not in seen:
            seen.add(k);clean.append(k)
    if not clean:
        return JSONResponse({"error":"No valid node ids"},status_code=400)
    # Look up IPs from the cached node list
    all_nodes=await _cnodes()
    by_id={}
    for n in all_nodes:
        try:by_id[int(n.get("node_id"))]=n
        except:pass
    ref=load_ref()
    sem=asyncio.Semaphore(BATCH_CONCURRENCY)
    async def _one(client,nid):
        n=by_id.get(nid)
        if not n:
            return {"node_id":nid,"error":"Node not found in cache","score":{"total":0}}
        ip=(n.get("ip") or "").strip()
        hostname=n.get("hostname") or None
        if not ip or _is_private_ip(ip):
            sec_log("ssrf_blocked_batch", client_ip, {"node_id": nid, "ip": ip})
            return {"node_id":nid,"node_ip":ip,"error":"Invalid or private IP","score":{"total":0}}
        async with sem:
            try:
                res=await _check_ip(client,ip,hostname,ref)
            except Exception as e:
                return {"node_id":nid,"node_ip":ip,"error":f"check failed: {type(e).__name__}","score":{"total":0}}
            res["node_id"]=nid
            return res
    async with httpx.AsyncClient() as client:
        results=await asyncio.gather(*[_one(client,i) for i in clean])
    return JSONResponse({"count":len(results),"results":results})

def _fail(ip,ref,msg,hostname=None):
    return{"node_ip":ip,"hostname":hostname,"check_timestamp":datetime.now(timezone.utc).isoformat(),
        "score":{"total":0},"mode":None,"wireguard_enabled":None,"version":None,"ports":None,
        "ipv6":None,"hardware":None,"toc":None,"description":None,"auxiliary":None,"roles":None,
        "error":msg,"reference_version":ref.get("latest_version"),"reference_updated":ref.get("updated_at"),"min_hardware":ref.get("min_hardware",{})}

async def _phw(client, host):
    """Fetch hardware from node system-info endpoint."""
    d = await _safe_json(client, f"http://{_host_for_url(host)}:8080/api/v1/system-info", timeout=5)
    if isinstance(d, dict):
        try:
            cpu_list = d.get("hardware", {}).get("cpu", [])
            cores = len(cpu_list) if isinstance(cpu_list, list) else 0
            total_mem = d.get("hardware", {}).get("total_memory", 0)
            ram = int(total_mem / (1024 * 1024)) if total_mem else 0
            os_name = d.get("system_name", "")
            os_ver = d.get("os_version", "")
            os_full = (os_name + " " + os_ver).strip()
            return {"available": True, "cpu_cores": cores, "ram_mb": ram, "os": os_full}
        except Exception:
            pass
    return {"available": False, "cpu_cores": 0, "ram_mb": 0, "os": ""}

def _ver_tuple(v):
    """Parse version string into tuple, or None if invalid."""
    try:return tuple(int(x) for x in v.split('.'))
    except:return None

def _build_version_response(cur,stable,prerelease):
    """
    Build version response with status awareness:
    - current: running version
    - stable: latest stable from GitHub (releases/latest)
    - prerelease: most recent prerelease, or None if none or older than stable
    - status: 'current'|'prerelease'|'ahead'|'behind'|'unknown'
    - ok: True if status is current/prerelease/ahead
    """
    cv=_ver_tuple(cur);sv=_ver_tuple(stable);pv=_ver_tuple(prerelease) if prerelease else None
    if cv is None or sv is None:
        return {"current":cur,"latest":stable,"prerelease":prerelease,"status":"unknown","ok":False}
    if cv==sv:
        status="current"
    elif pv and cv==pv:
        status="prerelease"
    elif cv>sv:
        status="ahead"
    else:
        status="behind"
    return {"current":cur,"latest":stable,"prerelease":prerelease,"status":status,
            "ok":status in ("current","prerelease","ahead")}

def _ver_diff(cur,lat):
    """How many minor versions behind cur is vs lat. Returns 0 if up to date."""
    try:
        cv=tuple(int(x) for x in cur.split('.'))
        lv=tuple(int(x) for x in lat.split('.'))
        if cv>=lv:return 0
        if cv[0]!=lv[0]:return 999  # major version gap
        return lv[1]-cv[1]  # minor version difference
    except:return 999

def _score(cur,lat,miss,total,ipv6,hw,mh,toc,is_exit=False,has_exit_policy=False):
    # Exit:     version(30) + ports(30) + ipv6(10) + hw(15) + exit_policy(15) = 100
    # Non-exit: version(30) + ports(30) + ipv6(20) + hw(20) = 100
    # T&C is a multiplier: not accepted = total score 0
    s={"version":0,"ports":0,"ipv6":0,"hardware":0,"toc":0,"exit_policy":0}
    diff=_ver_diff(cur,lat)
    s["version"]=max(0,30-diff*10)
    s["ports"]=round(30*((total-miss)/total)) if total>0 else 0
    s["toc"]=1 if toc else 0
    if is_exit:
        s["ipv6"]=10 if ipv6 else 0
        if hw.get("available"):
            mc=mh.get("cpu_cores",2);mr=mh.get("ram_mb",4096)
            s["hardware"]+=(8 if hw["cpu_cores"]>=mc else(round(8*hw["cpu_cores"]/mc) if mc else 0))
            s["hardware"]+=(7 if hw["ram_mb"]>=mr else(round(7*hw["ram_mb"]/mr) if mr else 0))
        s["exit_policy"]=15 if has_exit_policy else 0
    else:
        s["ipv6"]=20 if ipv6 else 0
        if hw.get("available"):
            mc=mh.get("cpu_cores",2);mr=mh.get("ram_mb",4096)
            s["hardware"]+=(10 if hw["cpu_cores"]>=mc else(round(10*hw["cpu_cores"]/mc) if mc else 0))
            s["hardware"]+=(10 if hw["ram_mb"]>=mr else(round(10*hw["ram_mb"]/mr) if mr else 0))
    raw=s["version"]+s["ports"]+s["ipv6"]+s["hardware"]+s["exit_policy"]
    s["total"]=raw if toc else 0
    return s

# ── Node Directory with Moniker fetching ────────────────────
MONIKER_FILE=Path("nym_monikers.json")

async def _fetch_moniker(client,ip):
    try:
        r=await client.get(f"http://{_host_for_url(ip)}:8080/api/v1/description",timeout=3)
        if r.status_code==200:
            return r.json().get("moniker","")
    except:pass
    return ""

async def _fetch_monikers_batch(nodes,batch_size=50):
    """Fetch monikers for all nodes in parallel batches."""
    monikers={}
    # Load existing
    if MONIKER_FILE.exists():
        try:monikers=json.loads(MONIKER_FILE.read_text())
        except:pass

    # Fetch: missing + empty (retry failures) + all if file older than 24h (stale refresh)
    file_age=time.time()-(MONIKER_FILE.stat().st_mtime if MONIKER_FILE.exists() else 0)
    stale=file_age>86400
    ips_to_fetch=[n["ip"] for n in nodes if n["ip"] not in monikers or not monikers[n["ip"]] or stale]
    if not ips_to_fetch:
        return monikers

    print(f"[*] Fetching monikers for {len(ips_to_fetch)} nodes...")
    async with httpx.AsyncClient() as client:
        for i in range(0,len(ips_to_fetch),batch_size):
            batch=ips_to_fetch[i:i+batch_size]
            results=await asyncio.gather(*[_fetch_moniker(client,ip) for ip in batch])
            for ip,m in zip(batch,results):
                monikers[ip]=m
            print(f"[*] Monikers: {i+len(batch)}/{len(ips_to_fetch)}")

    try:MONIKER_FILE.write_text(json.dumps(monikers,ensure_ascii=False))
    except:pass
    print(f"[*] Monikers saved: {sum(1 for v in monikers.values() if v)} with names")
    return monikers

@app.get("/api/nodes")
async def list_nodes(mode:Optional[str]=Query(None,max_length=32),country:Optional[str]=Query(None,max_length=8),q:Optional[str]=Query(None,max_length=200)):
    nodes=await _cnodes()
    if mode:nodes=[n for n in nodes if n.get("mode")==mode]
    if country:nodes=[n for n in nodes if n.get("location","").upper()==country.upper()]
    if q:
        qs=q.strip()
        if len(qs)<3:
            return JSONResponse({"error":"q must be at least 3 characters"},status_code=400)
        ql=qs.lower()
        nodes=[n for n in nodes if ql in n.get("ip","").lower() or ql in n.get("moniker","").lower() or ql in(n.get("hostname") or "").lower() or ql in n.get("identity_key","").lower() or ql in str(n.get("node_id","")).lower()]
    _LIST_KEYS=("node_id","ip","hostname","moniker","mode","location","version","wg","identity_key")
    ref=load_ref();latest=ref.get("latest_version","");prerelease=ref.get("prerelease_version")
    slim=[]
    for n in nodes:
        item={k:n.get(k) for k in _LIST_KEYS}
        item["version_status"]=_build_version_response(n.get("version",""),latest,prerelease).get("status","unknown")
        slim.append(item)
    return{"count":len(slim),"nodes":slim,"latest_version":latest,"prerelease_version":prerelease}

_nodes_mem={"nodes":[],"ts":0,"file_ts":0}
async def _cnodes():
    """Load nodes from in-memory cache, refresh from disk only if file changed."""
    if not CACHE_FILE.exists():return []
    try:
        fts=CACHE_FILE.stat().st_mtime
        if fts!=_nodes_mem["file_ts"]:
            data=json.loads(CACHE_FILE.read_text())
            _nodes_mem["nodes"]=data.get("nodes",[])
            _nodes_mem["file_ts"]=fts
        return _nodes_mem["nodes"]
    except:
        return []

async def _fnodes():
    """Fetch fresh node list from Nym described API."""
    nodes = []
    async with httpx.AsyncClient(timeout=30) as c:
        try:
            r = await c.get(DEF_REF["nodes_api"], timeout=20)
            r.raise_for_status()
            for it in r.json().get("data", []):
                try:
                    d = it.get("description", {})
                    if not isinstance(d, dict): continue
                    hi = d.get("host_information", {})
                    bi = d.get("build_information", {})
                    aux = d.get("auxiliary_details", {})
                    dr = d.get("declared_role", {})
                    ips = hi.get("ip_address", []) if isinstance(hi, dict) else []
                    ip = ips[0] if ips else ""
                    if not ip: continue
                    if dr.get("exit_ipr") or dr.get("exit_nr"): mode = "exit-gateway"
                    elif dr.get("entry"): mode = "entry-gateway"
                    elif dr.get("mixnode"): mode = "mixnode"
                    else: mode = "mixnode"
                    _ipv6 = any(":" in str(a) for a in ips)
                    _ipv6_addr = next((str(a) for a in ips if ":" in str(a)), None)
                    _toc = bool(aux.get("accepted_operator_terms_and_conditions", False)) if isinstance(aux, dict) else False
                    nodes.append({
                        "node_id": it.get("node_id", ""),
                        "identity_key": hi.get("keys", {}).get("ed25519", "") if isinstance(hi.get("keys"), dict) else "",
                        "ip": ip,
                        "hostname": hi.get("hostname") if isinstance(hi, dict) else None,
                        "moniker": "Node " + str(it.get("node_id", "")),
                        "mode": mode,
                        "location": aux.get("location", "") if isinstance(aux, dict) else "",
                        "version": bi.get("build_version", "") if isinstance(bi, dict) else "",
                        "wg": bool(d.get("wireguard")),
                        "toc": _toc,
                        "ipv6": _ipv6,
                        "ipv6_addr": _ipv6_addr,
                    })
                except: continue
        except Exception as e:
            print("[!] Fetch nodes: " + str(e))
    print(f"[*] Fetched {len(nodes)} nodes")
    return nodes


@app.post("/api/nodes/refresh")
async def refresh_nodes(_:bool=Depends(require_admin)):
    async with _cache_lock:
        # Save IPv6 data from previous cache before overwriting
        prev_ipv6={}
        if CACHE_FILE.exists():
            try:
                old=json.loads(CACHE_FILE.read_text())
                for n in old.get("nodes",[]):
                    if n.get("ipv6") or n.get("ipv6_addr") or n.get("ipv6_status") in ("confirmed","trusted"):
                        prev_ipv6[n["ip"]]={k:n.get(k) for k in ("ipv6","ipv6_addr","ipv6_source","ipv6_status","ipv6_checked_at") if n.get(k) is not None}
            except:pass
        if MONIKER_FILE.exists():MONIKER_FILE.unlink()
        nodes=await _fnodes()
        if not nodes:
            return{"status":"error","message":"fetch returned 0 nodes, keeping old cache"}
        monikers=await _fetch_monikers_batch(nodes)
        for n in nodes:
            m=monikers.get(n["ip"],"")
            if m:n["moniker"]=re.sub(r"[\x00-\x1F\x7F]","",m).strip() or n["moniker"]
            if not n.get("ipv6") and n["ip"] in prev_ipv6:
                n.update(prev_ipv6[n["ip"]])
        await _atomic_write(CACHE_FILE,json.dumps({"ts":time.time(),"nodes":nodes},ensure_ascii=False))
        return{"status":"ok","count":len(nodes)}

@app.post("/api/nodes/refresh-ipv6")
async def refresh_ipv6_endpoint(_:bool=Depends(require_admin)):
    return await _do_refresh_ipv6()

async def _do_refresh_ipv6():
    """
    IPv6 discovery for all cached nodes.
    Sources: self-declared API, DNS AAAA, Stockholm agent.
    Status semantics:
      trusted   = api/dns said yes (not probe-verified)
      confirmed = Stockholm actually connected over IPv6
      absent    = Stockholm explicitly said no (short TTL, will be re-checked)
      unknown   = timeout/error or never checked
    Rules:
      - timeout never flips trusted/confirmed -> false
      - absent has short TTL (6h) and gets re-checked next scan
    """
    async with _cache_lock:
        return await _do_refresh_ipv6_inner()

async def _do_refresh_ipv6_inner():
    if not CACHE_FILE.exists():
        return {"status": "error", "message": "no cache"}
    data = json.loads(CACHE_FILE.read_text())
    nodes = data.get("nodes", [])
    total = len(nodes)
    now = datetime.now(timezone.utc).isoformat()
    now_ts = time.time()

    sem = asyncio.Semaphore(40)
    stk_sem = asyncio.Semaphore(10)

    async def resolve_aaaa(hostname):
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, 8080, socket.AF_INET6)
            )
            if infos:
                return infos[0][4][0]
        except Exception:
            pass
        return None

    async def ask_stockholm(ip):
        """Returns (True, addr), (False, None), or (None, None) on timeout/disabled."""
        if not _ipv6_agent_enabled:
            return None, None
        url = f"{IPV6_AGENT}/check_ipv6?host={ip}&port=8080"
        async with httpx.AsyncClient() as client:
            for _ in range(2):
                try:
                    r = await client.get(url, timeout=5)
                    if r.status_code == 200:
                        j = r.json()
                        if j.get("supported"):
                            return True, j.get("ipv6_addr", "")
                        return False, None
                except Exception:
                    pass
        return None, None

    async def discover_ipv6(node):
        async with sem:
            ip = node.get("ip", "")
            if not ip:
                return
            prev_status = node.get("ipv6_status", "unknown")
            # Expire stale absent - treat as unknown so Stockholm re-checks
            if prev_status == "absent" and node.get("ipv6_checked_at"):
                try:
                    checked = datetime.fromisoformat(node["ipv6_checked_at"])
                    if (datetime.now(timezone.utc) - checked).total_seconds() > _IPV6_ABSENT_TTL:
                        prev_status = "unknown"
                except:
                    prev_status = "unknown"

            # 1) Self-declared in API (ip_address list contains IPv6)
            if node.get("ipv6") and node.get("ipv6_addr"):
                node["ipv6_source"] = "api"
                node["ipv6_status"] = "trusted"
                node["ipv6_checked_at"] = now
                return

            # 2) DNS AAAA on hostname
            hostname = node.get("hostname") or ""
            if hostname:
                aaaa = await resolve_aaaa(hostname)
                if aaaa:
                    node["ipv6"] = True
                    node["ipv6_addr"] = aaaa
                    node["ipv6_source"] = "dns"
                    node["ipv6_status"] = "trusted"
                    node["ipv6_checked_at"] = now
                    return

            # 3) Stockholm agent
            async with stk_sem:
                supported, addr = await ask_stockholm(ip)

            if supported is True:
                node["ipv6"] = True
                node["ipv6_addr"] = addr or ""
                node["ipv6_source"] = "stockholm"
                node["ipv6_status"] = "confirmed"
                node["ipv6_checked_at"] = now
            elif supported is False:
                # Explicit negative - but don't override trusted/confirmed
                if prev_status in ("trusted", "confirmed"):
                    pass  # keep positive - one negative doesn't override
                else:
                    node["ipv6"] = False
                    node.pop("ipv6_addr", None)
                    node["ipv6_source"] = "stockholm"
                    node["ipv6_status"] = "absent"
                    node["ipv6_checked_at"] = now
            else:
                # Timeout - never change trusted/confirmed
                if prev_status in ("trusted", "confirmed"):
                    pass
                else:
                    node["ipv6_status"] = "unknown"
                    node["ipv6_checked_at"] = now

    await asyncio.gather(*[discover_ipv6(n) for n in nodes])

    await _atomic_write(CACHE_FILE,json.dumps(data, ensure_ascii=False))
    trusted = sum(1 for n in nodes if n.get("ipv6_status") == "trusted")
    confirmed = sum(1 for n in nodes if n.get("ipv6_status") == "confirmed")
    absent = sum(1 for n in nodes if n.get("ipv6_status") == "absent")
    unknown = sum(1 for n in nodes if n.get("ipv6_status") == "unknown")
    print(f"[*] IPv6 scan done: {trusted} trusted, {confirmed} confirmed, {absent} absent, {unknown} unknown (of {total})")
    return {"status": "ok", "total": total, "trusted": trusted, "confirmed": confirmed, "absent": absent, "unknown": unknown}


_bg_tasks = []

@asynccontextmanager
async def lifespan(app):
    _validate_security_config()  # P3.2: validate env-driven security config + warnings
    _load_smtp_cache()  # load existing results immediately on startup
    _load_asn_cache()
    _bg_tasks.append(asyncio.create_task(_fetch_exit_policy()))
    _bg_tasks.append(asyncio.create_task(_bg_moniker_refresh()))
    _bg_tasks.append(asyncio.create_task(_bg_auto_sync()))
    _bg_tasks.append(asyncio.create_task(_bg_daily_ipv6()))
    _bg_tasks.append(asyncio.create_task(_bg_daily_smtp()))
    yield
    for t in _bg_tasks:
        t.cancel()

app.router.lifespan_context = lifespan

async def _bg_daily_ipv6():
    """Run DNS AAAA IPv6 scan once a day to keep data fresh."""
    await asyncio.sleep(300)  # 5 min after startup
    while True:
        try:
            print("[*] Daily IPv6 scan starting...")
            await _do_refresh_ipv6()
        except Exception as e:
            print(f"[!] Daily IPv6 scan error: {e}")
        await asyncio.sleep(86400)  # 24 hours

async def _bg_daily_smtp():
    """Run SMTP egress probe once a day. Offset from IPv6 scan by ~6h."""
    await asyncio.sleep(21600)  # 6 hours after startup
    while True:
        try:
            print("[*] Daily SMTP probe starting...")
            proc = await asyncio.create_subprocess_exec(
                "python3", "/opt/nym-probe/run_all.py",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd="/opt/nym-probe"
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=7200)  # 2h max
            print(f"[*] SMTP probe finished (exit={proc.returncode})")
            if proc.returncode == 0:
                # Copy results to the standard location
                src = Path("/opt/nym-probe/all_results_multitarget.json")
                if src.exists():
                    import shutil
                    shutil.copy2(str(src), str(SMTP_RESULTS_FILE))
                _load_smtp_cache()
            else:
                print(f"[!] SMTP probe stderr: {stderr.decode()[:500]}")
        except asyncio.TimeoutError:
            print("[!] SMTP probe timed out (>2h)")
            if proc:
                proc.kill()
        except Exception as e:
            print(f"[!] Daily SMTP probe error: {e}")
        await asyncio.sleep(86400)  # 24 hours

async def _bg_auto_sync():
    await asyncio.sleep(60)  # Wait 1 min after startup
    while True:
        try:
            print("[*] Auto-sync: checking for updates...")
            old_ports=_flatten_ports(load_ref())
            await sync_ref()
            new_ports=_flatten_ports(load_ref())
            added=new_ports-old_ports
            if added:print("[*] Auto-sync: new ports detected: "+str(added))
            else:print("[*] Auto-sync: no port changes")
        except Exception as e:
            print("[!] Auto-sync error: "+str(e))
        await asyncio.sleep(AUTO_SYNC_INTERVAL)

NODE_STALE_SECONDS = 2 * 3600  # Keep node in cache for 2h if validator API stops returning it

async def _bg_moniker_refresh():
    await asyncio.sleep(5)  # Let the server start first
    while True:
        try:
            async with _cache_lock:
                # Load previous cache (by node_id so we can merge and preserve ipv6)
                prev_by_nid = {}
                prev_ipv6 = {}
                if CACHE_FILE.exists():
                    try:
                        old_data = json.loads(CACHE_FILE.read_text())
                        for n in old_data.get("nodes", []):
                            nid = n.get("node_id")
                            if nid is not None:
                                prev_by_nid[nid] = n
                            if n.get("ipv6") or n.get("ipv6_addr") or n.get("ipv6_status") in ("confirmed","trusted"):
                                prev_ipv6[n["ip"]] = {k:n.get(k) for k in ("ipv6","ipv6_addr","ipv6_source","ipv6_status","ipv6_checked_at") if n.get(k) is not None}
                    except: pass
                nodes = await _fnodes()
                if not nodes:
                    print("[!] Background refresh: 0 nodes, keeping old cache")
                    continue
                now = time.time()
                fetched_nids = set()
                # Stamp fresh nodes with last_seen=now, keep monikers/ipv6
                for n in nodes:
                    n["last_seen"] = now
                    if n.get("node_id") is not None:
                        fetched_nids.add(n["node_id"])
                monikers = await _fetch_monikers_batch(nodes)
                for n in nodes:
                    m = monikers.get(n["ip"], "")
                    if m: n["moniker"] = re.sub(r"[\x00-\x1F\x7F]", "", m).strip() or n["moniker"]
                    if not n.get("ipv6") and n["ip"] in prev_ipv6:
                        n.update(prev_ipv6[n["ip"]])
                # Re-add nodes from previous cache that are missing this round but still fresh
                # (handles validator API transient drops - node stays in cache for up to NODE_STALE_SECONDS)
                kept = 0
                for nid, old in prev_by_nid.items():
                    if nid in fetched_nids:
                        continue
                    last_seen = old.get("last_seen") or old_data.get("ts", 0)
                    if now - last_seen < NODE_STALE_SECONDS:
                        # Keep it without updating last_seen
                        nodes.append(old)
                        kept += 1
                await _atomic_write(CACHE_FILE,json.dumps({"ts": now, "nodes": nodes}, ensure_ascii=False))
                print(f"[*] Background refresh done: {len(nodes)} nodes (fresh={len(fetched_nids)}, kept_stale={kept}, ipv6_kept={len(prev_ipv6)})")
        except Exception as e:
            print(f"[!] Background refresh error: {e}")
        await asyncio.sleep(1800)  # Every 30 min

@app.get("/api/health")
async def health():
    now=time.time()
    cache_age=None
    cache_nodes=0
    if CACHE_FILE.exists():
        try:
            data=json.loads(CACHE_FILE.read_text())
            cache_age=round(now-data.get("ts",0))
            cache_nodes=len(data.get("nodes",[]))
        except:pass
    ref=load_ref()
    return{
        "status":"ok","ts":datetime.now(timezone.utc).isoformat(),
        "cache":{"age_seconds":cache_age,"nodes":cache_nodes,"stale":cache_age is not None and cache_age>7200},
        "reference":{"version":ref.get("latest_version"),"updated":ref.get("updated_at")},
        "exit_policy_loaded":bool(_exit_policy_cache.get("ports")),
    }

if __name__=="__main__":
    import uvicorn
    if not REF_FILE.exists():save_ref(DEF_REF);print("[*] Created "+str(REF_FILE))
    print("[*] Nym Checker -> http://0.0.0.0:8000")
    uvicorn.run(app,host="0.0.0.0",port=8000)
