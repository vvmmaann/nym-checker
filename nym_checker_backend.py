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
# gzip compression for responses >= 1KB (knocks /api/nodes 220KB -> ~30KB)
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1024)

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
    # Hardware requirements: hardcoded baseline, since the official docs render the
    # NymNodeSpecs values via a React component (JS) that raw markdown / WebFetch
    # cannot read. Community consensus (multiple operator guides, 2024-2026) and the
    # values shipped in the official setup script agree on these numbers. Auto-sync
    # would require a headless browser; for now they are manually verified and the
    # frontend points operators at the live docs URL for the authoritative table.
    "min_hardware":{"cpu_cores":2,"ram_mb":4096},
    "min_hardware_gateway":{"cpu_cores":4,"ram_mb":8192},
    "min_hardware_meta":{
        "verified_at":"2026-05-12",
        "source":"https://nym.com/docs/operators/nodes/preliminary-steps/vps-setup",
        "method":"manual",
        "note":"NymNodeSpecs component on Nym docs is JS-rendered. Check the source URL for authoritative current values."
    },
    "github_ntm_url":"https://raw.githubusercontent.com/nymtech/nym/refs/heads/develop/scripts/nym-node-setup/network-tunnel-manager.sh",
    "nodes_api":"https://validator.nymtech.net/api/v1/nym-nodes/described",
    "bonded_api":"https://validator.nymtech.net/api/v1/nym-nodes/bonded"
}

def load_ref():
    """Load reference data from disk, merged on top of DEF_REF so that newly added
    default fields appear automatically even when the on-disk file predates them."""
    import copy
    base = copy.deepcopy(DEF_REF)
    if REF_FILE.exists():
        try:
            persisted = json.loads(REF_FILE.read_text())
            if isinstance(persisted, dict):
                base.update(persisted)
                # Fill in any new default-only keys that the persisted file is missing
                for k, v in DEF_REF.items():
                    if k not in persisted:
                        base[k] = copy.deepcopy(v)
        except Exception:
            pass
    return base
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

@app.get("/country/{cc}",include_in_schema=False)
async def country_page(cc:str):
    """Per-country deep-dive page. Same index.html, JS bootstrap resolves the route."""
    return FileResponse(STATIC_DIR/"index.html")

@app.get("/provider/{asn}",include_in_schema=False)
async def provider_page(asn:str):
    """Per-provider deep-dive page. Same index.html, JS bootstrap resolves the route."""
    return FileResponse(STATIC_DIR/"index.html")

_OPERATOR_GENERIC_TOKENS = {"node","nym","gateway","mixnode","exit","entry","mix","gw","mainnet","testnet"}
_op_keys_cache = {"file_ts": None, "by_ip": {}}  # ip -> canonical key

def _operator_key_raw(moniker:str):
    """Stage 1: extract a normalized key from a single moniker.

    Splits on non-alphanumeric AND on camelCase boundaries so 'BwNymGama'
    becomes ['bw','nym','gama'] - matching the same handling as 'bwnym-pr-quwi'
    which becomes ['bwnym','pr','quwi']. Generic words and trailing digits stripped.
    Returns None if no usable token survives.
    """
    if not moniker: return None
    import re
    # Insert space at camelCase boundaries: BwNymGama -> Bw Nym Gama
    cased = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(moniker))
    norm = re.sub(r"[^a-zA-Z0-9]+", " ", cased).strip().lower()
    if not norm: return None
    tokens = [t for t in norm.split() if t not in _OPERATOR_GENERIC_TOKENS and len(t) >= 3]
    if not tokens: return None
    first = re.sub(r"\d+$", "", tokens[0])  # strip trailing digits
    out = first if len(first) >= 3 else tokens[0]
    return out or None


def _compute_operator_keys(nodes):
    """Stage 2: merge brand variants. We compute a raw key per node via tokenization,
    plus the FULL lowercased alphanumeric moniker (no separators). Then for each
    node we check if any canonical raw-key (>=2 nodes) is a prefix of the full
    lowercased moniker. If so, that canonical key becomes the operator key.

    This catches:
      'bwnym-mote-DE' -> raw 'bwnym', full 'bwnymmoteDE'
      'BwNymGama'     -> raw 'gama' (bw too short, nym generic), full 'bwnymgama'
                       -> matches canonical 'bwnym' as prefix -> merged to 'bwnym'
      'NYMLEM STOCKHOLM GW' -> raw 'nymlem'
      '✅🌐✅NYMLEM✅🌐✅' -> raw 'nymlem'
    Returns dict {ip: canonical_key}.
    """
    import re
    initial = {}
    full_alphanum = {}
    for n in nodes:
        m = n.get("moniker","") or ""
        ip = n.get("ip","") or ""
        if not ip: continue
        k = _operator_key_raw(m)
        if k: initial[ip] = k
        full_alphanum[ip] = re.sub(r"[^a-z0-9]", "", m.lower())
    counts = {}
    for k in initial.values():
        counts[k] = counts.get(k, 0) + 1
    # Canonical: keys with >=2 nodes. Sort longest-first so we prefer specific brands.
    canonical = sorted([k for k, c in counts.items() if c >= 2 and len(k) >= 3], key=lambda x: -len(x))
    final = {}
    for ip in full_alphanum:
        full = full_alphanum.get(ip, "")
        raw = initial.get(ip)
        merged = raw
        # Look for any canonical key that is a prefix of the full lowercased moniker
        for c in canonical:
            if full.startswith(c):
                merged = c
                break
        if merged:
            final[ip] = merged
    return final


def _refresh_op_keys_cache(force=False):
    """Recompute operator_keys cache when node cache file changes."""
    try:
        if not CACHE_FILE.exists():
            _op_keys_cache["by_ip"] = {}
            _op_keys_cache["file_ts"] = None
            return
        fts = CACHE_FILE.stat().st_mtime
        if not force and fts == _op_keys_cache["file_ts"]:
            return
        nodes = _nodes_mem.get("nodes") or []
        if not nodes and CACHE_FILE.exists():
            nodes = json.loads(CACHE_FILE.read_text()).get("nodes", [])
        _op_keys_cache["by_ip"] = _compute_operator_keys(nodes)
        _op_keys_cache["file_ts"] = fts
    except Exception:
        pass


def _operator_key(moniker:str):
    """Public entry retained for callers that only have moniker. Stage 1 only.
    For accurate brand-merged grouping use _operator_key_for_ip(ip)."""
    return _operator_key_raw(moniker)


def _operator_key_for_ip(ip:str):
    """Return the canonical brand-merged operator key for a given node IP, or None."""
    _refresh_op_keys_cache()
    return _op_keys_cache["by_ip"].get(ip)


@app.get("/operator/{key}",include_in_schema=False)
async def operator_page(key:str):
    """Per-operator profile page. Same index.html, JS bootstrap resolves the route."""
    return FileResponse(STATIC_DIR/"index.html")

@app.get("/wallet/{address}",include_in_schema=False)
async def wallet_page(address:str):
    """Per-wallet explorer page (deep-link / new tab). Same index.html, JS bootstrap resolves it."""
    return FileResponse(STATIC_DIR/"index.html")

@app.get("/plan",include_in_schema=False)
async def plan_page():
    """Plan-your-node wizard page. Same index.html, JS handles state."""
    return FileResponse(STATIC_DIR/"index.html")

@app.get("/api/operator/{key}")
async def operator_profile(key:str):
    """Group all nodes whose moniker shares the given operator key (brand-prefix, merged)."""
    nodes_all = await _cnodes()
    _refresh_op_keys_cache()
    key_norm = (key or "").lower()
    if not key_norm:
        return JSONResponse({"error":"empty key"}, status_code=400)
    op_nodes = [n for n in nodes_all if _op_keys_cache["by_ip"].get(n.get("ip","")) == key_norm]
    if not op_nodes:
        return JSONResponse({"error":"no nodes found for this operator key","key":key_norm}, status_code=404)
    by_mode = {}
    by_country = {}
    by_provider = {}
    versions = {}
    wallets = set()
    for n in op_nodes:
        m = n.get("mode","unknown") or "unknown"
        cc = (n.get("location") or "??").upper() or "??"
        v = n.get("version","") or ""
        by_mode[m] = by_mode.get(m, 0) + 1
        by_country[cc] = by_country.get(cc, 0) + 1
        if v: versions[v] = versions.get(v, 0) + 1
        if n.get("owner"): wallets.add(n["owner"])
    try:
        ip_asn = _ip_to_asn_cache if isinstance(_ip_to_asn_cache, dict) else {}
    except Exception:
        ip_asn = {}
    for n in op_nodes:
        info = ip_asn.get(n.get("ip","")) if ip_asn else None
        if info:
            asn = str(info.get("asn",""))
            if asn: by_provider[asn] = by_provider.get(asn, 0) + 1
    # Display name: longest common prefix across actual monikers, fallback to first moniker
    monikers = [n.get("moniker","") for n in op_nodes if n.get("moniker")]
    moniker_sample = monikers[0] if monikers else key_norm
    return {
        "key": key_norm,
        "node_count": len(op_nodes),
        "wallet_count": len(wallets),
        "moniker_sample": moniker_sample,
        "by_mode": by_mode,
        "by_country": by_country,
        "by_provider": by_provider,
        "by_version": versions,
        "nodes": op_nodes,
    }


@app.get("/api/operator-key-of/{ip}")
async def operator_key_of(ip:str):
    """Return the canonical (brand-merged) operator key for a node by IP, plus shared-node count."""
    await _cnodes()  # ensure cache loaded
    _refresh_op_keys_cache()
    key = _op_keys_cache["by_ip"].get(ip)
    if not key:
        return {"key": None, "count": 0}
    count = sum(1 for k in _op_keys_cache["by_ip"].values() if k == key)
    node = next((n for n in (_nodes_mem.get("nodes") or []) if n.get("ip")==ip), None)
    return {"key": key, "count": count, "moniker": (node or {}).get("moniker","")}

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

@app.get("/guide",include_in_schema=False)
async def guide_page():
    return FileResponse(STATIC_DIR/"guide.html")

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

# Region groupings for plan recommendations - kept here so frontend and backend agree
_PLAN_REGIONS = {
    "eu": {"DE","FI","FR","GB","NL","PL","RO","BG","GR","CZ","AT","CH","IT","ES","PT","IE","BE","DK","SE","NO","HU","SK","EE","LV","LT","LU","MD","UA","RS","HR","SI","IS","CY","MT","AL","MK","ME","BA","XK"},
    "asia": {"JP","SG","HK","TW","KR","AU","NZ","IN","ID","TH","MY","PH","VN","KG","KZ"},
    "americas": {"US","CA","BR","MX","AR","CL","CO","PE","UY","PA","CR","EC","DO"},
    "africa": {"ZA","EG","MA","KE","NG","SC","IL","TR","AE"},
}

@app.get("/api/plan")
async def plan_recommendation(node_type:str=Query("any"), exp:str=Query("some"), region:str=Query("any")):
    """Generate a coherent deployment plan that cross-references country and providers.

    Outputs top countries that BOTH match the user's filter AND have at least one
    quality hosting provider currently used by other Nym operators there. Each
    country in the result includes the actual providers present in it.
    """
    if not _DEPLOY_AVAILABLE:
        return JSONResponse({"error":"deploy data not loaded"}, status_code=503)
    nodes_all = await _cnodes()
    total = len(nodes_all)
    if not total:
        return JSONResponse({"error":"no nodes data"}, status_code=503)
    ref = load_ref()
    ip_to_asn = _asn_cache.get("ip_to_asn",{})
    asn_names = _asn_cache.get("asn_names",{})

    # Determine actual node type to recommend
    pt = node_type
    if pt == "any":
        pt = "mixnode" if exp == "novice" else "entry-gateway"

    # Build country -> nodes count + per-ASN nodes count (used as "battle-tested" evidence)
    by_country_count = {}
    nodes_per_asn_global = {}  # asn -> total nodes globally on this ASN
    nodes_in_cc_asn = {}  # (cc, asn) -> nodes count there on this asn
    for n in nodes_all:
        cc = (n.get("location","") or "").upper()
        ip = n.get("ip","") or ""
        if cc:
            by_country_count[cc] = by_country_count.get(cc, 0) + 1
        info = ip_to_asn.get(ip) or {}
        asn = info.get("asn")
        if asn:
            nodes_per_asn_global[asn] = nodes_per_asn_global.get(asn, 0) + 1
            if cc:
                nodes_in_cc_asn[(cc, asn)] = nodes_in_cc_asn.get((cc, asn), 0) + 1

    region_filter = _PLAN_REGIONS.get(region) if region != "any" else None
    try:
        from nym_provider_data import provider_score as _ps, PROVIDERS as _PROVIDERS_DICT
    except Exception:
        _ps = None
        _PROVIDERS_DICT = {}

    # Build country -> [asn] mapping from PROVIDERS official countries field (verified from each provider site)
    country_to_official_asns = {}
    for asn, pinfo in (_PROVIDERS_DICT or {}).items():
        ccs = pinfo.get("countries") or []
        for cc in ccs:
            country_to_official_asns.setdefault(cc.upper(), []).append(asn)

    candidate_countries = []
    for cc in _COUNTRIES:
        if region_filter and cc not in region_filter:
            continue
        s = _country_score(cc, by_country_count.get(cc, 0), total)
        s["cc"] = cc
        # Drop hostile classifications regardless of inputs
        if s.get("classification") in ("not_recommended","saturated"):
            continue
        # For exit-gateway recommendations, require safe operator_risk
        if pt == "exit-gateway" and s.get("operator_risk") != "safe":
            continue
        # Find providers that OFFICIALLY serve this country (verified from provider websites)
        official_asns = country_to_official_asns.get(cc, [])
        if not official_asns:
            continue
        # Score each provider, attach battle-tested evidence (existing Nym nodes in this country on this ASN)
        scored_provs = []
        if _ps:
            for asn in official_asns:
                here_count = nodes_in_cc_asn.get((cc, asn), 0)
                global_count = nodes_per_asn_global.get(asn, 0)
                ps_smtp = None
                try:
                    if _smtp_cache:
                        ss = {"open":0,"partial":0,"blocked":0,"unknown":0}
                        for nd in nodes_all:
                            info2 = ip_to_asn.get(nd.get("ip","")) or {}
                            if info2.get("asn") != asn: continue
                            if nd.get("mode") != "exit-gateway": continue
                            sc = _smtp_cache.get(nd.get("ip",""))
                            if sc:
                                st = sc.get("status","unknown")
                                if st in ss: ss[st] += 1
                        if any(ss.values()): ps_smtp = ss
                except Exception:
                    pass
                pscore = _ps(asn, global_count, total, smtp_stats=ps_smtp, fallback_name=asn_names.get(asn,""))
                pscore["nodes_in_country"] = here_count
                pscore["battle_tested_here"] = here_count > 0
                pinfo = _PROVIDERS_DICT.get(asn) or {}
                pscore["countries_source"] = pinfo.get("countries_source")
                pscore["countries_verified_at"] = pinfo.get("countries_verified_at")
                scored_provs.append(pscore)
        # Filter quality + bias by experience/type
        good = [p for p in scored_provs if p.get("classification") in ("great","good","ok")]
        if pt == "exit-gateway":
            tor_or_crypto = [p for p in good if (p.get("metadata") or {}).get("crypto_payments") or (p.get("metadata") or {}).get("tor_friendly") is True]
            if tor_or_crypto: good = tor_or_crypto
        if exp == "pro":
            with_crypto = [p for p in good if (p.get("metadata") or {}).get("crypto_payments")]
            if len(with_crypto) >= 1: good = with_crypto
        if not good:
            continue
        # Sort: battle-tested first, then classification, then score
        good.sort(key=lambda x: (0 if x.get("battle_tested_here") else 1,
                                  {"great":0,"good":1,"ok":2}.get(x.get("classification","ok"),3),
                                  -x.get("score",0)))
        s["available_providers"] = good[:3]
        s["all_provider_count"] = len(scored_provs)
        candidate_countries.append(s)

    # Rank countries: needed_nodes desc, then score desc
    candidate_countries.sort(key=lambda x: (-x.get("needed_nodes",0), -x.get("score",0)))
    top_countries = candidate_countries[:3]

    hardware_key = "min_hardware_gateway" if pt != "mixnode" else "min_hardware"
    return {
        "node_type": pt,
        "experience": exp,
        "region": region,
        "top_countries": top_countries,
        "hardware": {
            "min": ref.get(hardware_key),
            "meta": ref.get("min_hardware_meta"),
        },
        "links": {
            "docs_root": "https://nym.com/docs/operators/nodes",
            "vps_setup": (ref.get("min_hardware_meta") or {}).get("source", "https://nym.com/docs/operators/nodes/preliminary-steps/vps-setup"),
            "init_run": "https://nym.com/docs/operators/binaries/init-and-run",
        },
    }


@app.post("/api/admin/update-hardware")
async def admin_update_hardware(_:bool=Depends(require_admin),body:dict=Body(...)):
    """Admin override for hardware minimum requirements.
    Body: {"min_hardware":{...}, "min_hardware_gateway":{...}, "verified_at":"YYYY-MM-DD"}
    """
    ref = load_ref()
    if "min_hardware" in body and isinstance(body["min_hardware"], dict):
        ref["min_hardware"] = body["min_hardware"]
    if "min_hardware_gateway" in body and isinstance(body["min_hardware_gateway"], dict):
        ref["min_hardware_gateway"] = body["min_hardware_gateway"]
    meta = ref.get("min_hardware_meta") or {}
    if "verified_at" in body:
        meta["verified_at"] = body["verified_at"]
    if "source" in body:
        meta["source"] = body["source"]
    meta["method"] = "manual-admin-update"
    ref["min_hardware_meta"] = meta
    save_ref(ref)
    return {"ok": True, "ref": {"min_hardware": ref.get("min_hardware"), "min_hardware_gateway": ref.get("min_hardware_gateway"), "min_hardware_meta": ref.get("min_hardware_meta")}}


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
            _fm=_smtp_meta.get("file_mtime")
            _age=int(time.time()-_fm) if _fm else None
            _stale=_age is not None and _age>SMTP_STALE_SECONDS
            st_smtp="unknown" if _stale else s.get("status","unknown")
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
    # Attach per-metric source attribution (World Bank, Freedom House, RSF) where available
    try:
        from nym_country_data import COUNTRY_DATA_SOURCES as _CDS
        score["data_sources"] = _CDS.get(cc, {})
    except Exception:
        pass
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
    # Sort each group: countries that STILL NEED nodes first (the actionable "deploy here"
    # entries), then by score. A country that has already met its own target
    # (needed_nodes == 0, e.g. Norway at 9/8) must not headline a "deploy here" group just
    # because its composite score is high - it sorts to the tail of its group instead.
    for g in grouped.values():
        g.sort(key=lambda x: (x.get("needed_nodes", 0) == 0, -x.get("score", 0)))
    # Top recommendations: high-score, operator-safe, room to grow (nodes_here < 20), and
    # STILL NEEDS nodes. Excludes countries already at/over their target so a covered country
    # never appears in the "where to deploy" hero.
    top = sorted(
        [r for r in results if r["classification"] in ("highly_recommended","good")
         and r.get("nodes_here",0) < 20 and r.get("needed_nodes",0) > 0],
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
# Multi-vantage probe agents - HTTP endpoints on remote Nym nodes that perform TCP probes
# from their network vantage point. Lets us detect "blocked from this IP range" vs
# "really closed" by comparing results from multiple geographic locations.
#
# Env format: comma-separated pairs of "LABEL=URL" so frontend can show regional names
# (EU/AF/AM/AS) instead of advertising the vantage IPs. Plain "URL" (no label) falls back
# to the host portion as the label.
def _parse_probe_agents(raw: str):
    pairs = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            label, _, url = chunk.partition("=")
            label, url = label.strip(), url.strip()
        else:
            url = chunk
            label = url.split("//")[-1].split("/")[0].split(":")[0]  # fallback to host
        if url:
            pairs.append((label or "?", url))
    return pairs

PROBE_AGENTS = _parse_probe_agents(os.environ.get("PROBE_AGENTS", ""))
# Back-compat alias for any older callers (now unused internally)
PROBE_AGENT_URLS = [u for _, u in PROBE_AGENTS]


_PROBE_AGENT_HEALTH = {}  # url -> {"alive": bool, "last_check": ts, "consecutive_failures": int}
_PROBE_AGENT_TIMEOUT = 2.0  # tight timeout so dead vantages do not block checks
_PROBE_DEACTIVATE_AFTER = 3  # mark dead after N consecutive failures
_PROBE_RECHECK_INTERVAL = 60  # retry dead agents after this many seconds


def _agent_is_alive(url):
    """Skip agents that recently failed several times in a row, with periodic recheck."""
    import time
    h = _PROBE_AGENT_HEALTH.get(url)
    if not h:
        return True
    if h.get("alive", True):
        return True
    if time.time() - h.get("last_check", 0) > _PROBE_RECHECK_INTERVAL:
        return True  # recheck window: give it another chance
    return False


def _agent_record_result(url, success):
    """Update agent health based on probe result."""
    import time
    h = _PROBE_AGENT_HEALTH.setdefault(url, {"alive": True, "last_check": 0, "consecutive_failures": 0})
    h["last_check"] = time.time()
    if success:
        h["alive"] = True
        h["consecutive_failures"] = 0
    else:
        h["consecutive_failures"] = h.get("consecutive_failures", 0) + 1
        if h["consecutive_failures"] >= _PROBE_DEACTIVATE_AFTER:
            h["alive"] = False


async def _probe_from_agent(client, agent_url, ip, port, proto="tcp", timeout=None):
    """Hit a remote probe agent with tight timeout + circuit breaker.

    Skips agents that recently failed N consecutive times; retries after RECHECK_INTERVAL.
    Returns dict or None on failure.
    """
    if not _agent_is_alive(agent_url):
        return None
    t = timeout if timeout is not None else _PROBE_AGENT_TIMEOUT
    try:
        r = await client.get(
            f"{agent_url.rstrip('/')}/probe",
            params={"ip": ip, "port": port, "proto": proto},
            timeout=t,
        )
        if r.status_code == 200:
            _agent_record_result(agent_url, True)
            return r.json()
        _agent_record_result(agent_url, False)
    except Exception:
        _agent_record_result(agent_url, False)
        return None
    return None


async def _smtp_probe_from_agent(client, agent_url, timeout=30.0):
    """Ask agent to probe all configured mail providers from its vantage point."""
    try:
        r = await client.get(f"{agent_url.rstrip('/')}/smtp-probe", timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


@app.get("/api/smtp-vantages")
async def smtp_vantages():
    """Aggregate SMTP reachability from all configured probe agents.

    Returns per-provider matrix keyed by region label (EU/AF/AM/AS), not by IP -
    keeps the actual vantage node IPs unadvertised.
    """
    if not PROBE_AGENTS:
        return {"error": "no probe agents configured", "vantages": {}}
    async with httpx.AsyncClient(timeout=35) as client:
        coros = [_smtp_probe_from_agent(client, url) for _, url in PROBE_AGENTS]
        responses = await asyncio.gather(*coros, return_exceptions=True)
    vantages = {}
    matrix = {}  # provider -> port -> {label: bool}
    for (label, _url), resp in zip(PROBE_AGENTS, responses):
        if isinstance(resp, Exception) or resp is None:
            vantages[label] = {"error": str(resp)[:80] if resp else "unreachable"}
            continue
        smtp = (resp.get("smtp") if isinstance(resp, dict) else {}) or {}
        vantages[label] = {"providers": {}}
        for prov, info in smtp.items():
            ports = (info or {}).get("ports") or {}
            simplified = {}
            for p, pinfo in ports.items():
                opened = bool((pinfo or {}).get("open"))
                simplified[p] = opened
                matrix.setdefault(prov, {}).setdefault(p, {})[label] = opened
            vantages[label]["providers"][prov] = simplified
    return {
        "agents": list(vantages.keys()),
        "vantages": vantages,
        "matrix": matrix,
        "providers": list({p for v in vantages.values() if "providers" in v for p in v["providers"]}),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def _multi_vantage_probe_ports(client, ip, ports_list):
    """For each TCP port in ports_list, probe from all configured remote agents in parallel.

    Returns dict keyed by "port/proto" -> {agent_label: {open, latency_ms, errno}}.
    Labels are region tags (EU/AF/AM/AS) configured in PROBE_AGENTS env, NOT IPs.
    Returns empty dict if no agents are configured (single-vantage fallback).
    """
    if not PROBE_AGENTS:
        return {}
    results = {}
    for port_spec in ports_list:
        port = port_spec.get("port")
        proto = port_spec.get("proto", "tcp")
        if not port or proto != "tcp":
            continue
        coros = [_probe_from_agent(client, url, ip, port, proto) for _, url in PROBE_AGENTS]
        agent_responses = await asyncio.gather(*coros, return_exceptions=True)
        port_results = {}
        for (label, _url), resp in zip(PROBE_AGENTS, agent_responses):
            if isinstance(resp, Exception) or resp is None:
                continue
            port_results[label] = {
                "open": bool(resp.get("open")),
                "latency_ms": resp.get("latency_ms"),
                "errno": resp.get("errno"),
            }
        if port_results:
            results[f"{port}/{proto}"] = port_results
    return results


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
    """Query the node's self-describe API. Tries the node's declared custom_http_port first
    (passed as `port` from the on-chain bond data), then common fallbacks — ~11% of nodes serve
    their API on a non-8080 port (8000, 8081, 7999, ...) and hardcoding 8080 made them look dead."""
    res={"reachable":False,"roles":None,"description":None,"build_info":None,"auxiliary":None,"host_info":None,"gateway":None,"lp":None,"http_port":None}
    candidates=[]
    for p in (port,8080,8000,9000):
        if p and p not in candidates:
            candidates.append(p)
    for p in candidates:
        base=f"http://{_host_for_url(host)}:{p}/api/v1"
        # 3s: a healthy node API answers in <1s; anything slower is effectively down, and the
        # check cache makes a later retry instant — so fail fast instead of blocking the open.
        roles=await _safe_json(client,base+"/roles",timeout=3)
        if roles is None:
            continue
        res["reachable"]=True;res["roles"]=roles;res["http_port"]=p
        endpoints={"description":"/description","build_info":"/build-information","auxiliary":"/auxiliary-details","host_info":"/host-information","gateway":"/gateway","lp":"/lewes-protocol"}
        async def _fetch(k,pp):
            v=await _safe_json(client,base+pp,timeout=5)
            return k,v
        pairs=await asyncio.gather(*[_fetch(k,pp) for k,pp in endpoints.items()])
        for k,v in pairs:
            if v is not None:res[k]=v
        return res
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
# Nym official functional probe cache (from the production node-status API that backs
# Harbour Master: mainnet-node-status-api.nymtech.cc).
# Their probe goes THROUGH the gateway to test actual routing/exit/WG/SOCKS5 functionality,
# which is complementary to our INBOUND multi-vantage port probing.
# NOTE: must use the FULL /v2/gateways endpoint, NOT /v2/gateways/skinny - skinny omits
# last_probe_result / last_testrun_utc entirely. The full endpoint also does NOT expose
# ports_check, and routing_score/config_score are deprecated (0 network-wide), so we keep
# none of those. Gateways only (mixnodes get no functional probe by design), so mixnode
# keys simply miss the cache and render no section.
_nym_probe_cache = {}    # identity_key -> {last_probe_result, last_testrun_utc, last_updated_utc, performance}
_nym_probe_meta = {"last_refresh": None, "total_gateways": 0, "error": None}
NYM_PROBE_URL = os.environ.get("NYM_PROBE_URL", "https://mainnet-node-status-api.nymtech.cc/v2/gateways")
NYM_PROBE_REFRESH_SEC = int(os.environ.get("NYM_PROBE_REFRESH_SEC", "900"))  # 15 min default

# --- Nym validator annotation scores (stress / routing / config / performance) ---
# The gateways functional-probe API above does NOT carry these; only the per-node validator
# annotation endpoint does. stress_testing_score is the mixnode-only signal that drives
# rewarded-set selection (gateways report stress 0 / was_reachable=false by design).
_stress_cache = {}   # node_id -> {stress, stress_reachable, routing, config, performance, last_updated}
_stress_meta = {"last_refresh": None, "total": 0, "error": None}
STRESS_ANNOTATION_URL = os.environ.get("NYM_STRESS_URL", "https://validator.nymtech.net/api/v2/nym-nodes/annotation")
STRESS_REFRESH_SEC = int(os.environ.get("NYM_STRESS_REFRESH_SEC", "900"))  # 15 min default
STRESS_CONCURRENCY = int(os.environ.get("NYM_STRESS_CONCURRENCY", "24"))
# Bulk economics for the Nymesis-style explorer table (opcost/margin/delegations/pledge), harvested
# from the bonded API in a single call (side effect of _fetch_owners). node_id -> {opcost,margin,delegations,pledge}
_bonded_econ = {}
# Rewarded (active) set node ids, refreshed on a short TTL for the "ACTIVE" column.
_rewarded_set = {"ids": set(), "epoch": None, "ts": 0}
RSET_TTL = int(os.environ.get("NYM_RSET_TTL", "300"))
REWARDED_SET_URL = os.environ.get("NYM_REWARDED_SET_URL", "https://validator.nymtech.net/api/v1/nym-nodes/rewarded-set")
# Bulk saturation + total-stake for the explorer table (SAT / STAKE columns). Background sweep of the
# cheap per-node get_node_stake_saturation contract query (mirrors the annotation sweep pattern).
_econ_bulk = {}   # node_id -> {"saturation": float|None, "total_stake": float|None}
_econ_bulk_meta = {"last_refresh": None, "total": 0, "error": None}
ECON_BULK_REFRESH_SEC = int(os.environ.get("NYM_ECON_BULK_REFRESH_SEC", "1200"))  # 20 min
ECON_BULK_CONCURRENCY = int(os.environ.get("NYM_ECON_BULK_CONCURRENCY", "10"))

# --- Economics / delegation graph (on-chain via Nyx LCD) ----------------------
# Node economics (saturation, per-epoch reward, claimable operator reward, owner
# wallet balance, cost params) and the full delegation graph come from the mixnet
# contract's smart queries + the bank module. Per-node queries are cached with a TTL
# and only run on demand (detail view / own nodes), never across all ~800 nodes.
NYM_LCD = os.environ.get("NYM_LCD", "https://lcd-nyx.keplr.app")
MIXNET_CONTRACT = os.environ.get("NYM_MIXNET_CONTRACT",
    "n17srjznxl9dvzdkpwpw24gg668wc73val88a6m5ajg6ankwvz9wtst0cznr")
# Nym Delegation Program / team wallet: delegates to ~500+ nodes; flags DP-backed nodes.
NYM_DP_WALLET = os.environ.get("NYM_DP_WALLET", "n1rnxpdpx3kldygsklfft0gech7fhfcux4zst5lw")
UNYM = 1_000_000  # NYM has 6 decimals
_econ_cache = {}   # node_id -> {..economics.., "ts": epoch}
ECON_TTL = int(os.environ.get("NYM_ECON_TTL", "600"))    # 10 min
_deleg_cache = {}  # node_id -> {"delegations":[...], "ts": epoch}
DELEG_TTL = int(os.environ.get("NYM_DELEG_TTL", "600"))
_bal_cache = {}    # addr -> {"balance": nym, "ts": epoch}
BAL_TTL = int(os.environ.get("NYM_BAL_TTL", "600"))
_dp_backed = {}    # node_id -> delegated NYM by the DP wallet
_dp_meta = {"last_refresh": None, "nodes": 0, "total_nym": 0.0, "wallet": NYM_DP_WALLET}
DP_REFRESH_SEC = int(os.environ.get("NYM_DP_REFRESH_SEC", "3600"))    # hourly
ECON_CONCURRENCY = int(os.environ.get("NYM_ECON_CONCURRENCY", "8"))
_reward_params = {"saturation_point": None, "ts": 0}   # cached stake_saturation_point (NYM)
RP_TTL = int(os.environ.get("NYM_RP_TTL", "3600"))
# Last non-zero per-epoch operator reward per node — the current-epoch estimate is 0 when a node
# is out of the active set, so we show this "typical when in the set" figure instead of 0.
REWARD_TYPICAL_FILE = Path("nym_reward_typical.json")
def _load_reward_typical():
    try:
        return {int(k): v for k, v in json.loads(REWARD_TYPICAL_FILE.read_text()).items()}
    except Exception:
        return {}
_reward_typical = _load_reward_typical()
def _save_reward_typical():
    try:
        REWARD_TYPICAL_FILE.write_text(json.dumps({str(k): v for k, v in _reward_typical.items()}))
    except Exception:
        pass
_wallet_cache = {}   # address -> {..wallet.., "ts": epoch}
_wallet_tx_cache = {}  # address -> {"v": {...}, "ts": epoch}
WALLET_TTL = int(os.environ.get("NYM_WALLET_TTL", "180"))
WALLET_TX_LIMIT = int(os.environ.get("NYM_WALLET_TX_LIMIT", "40"))
WALLET_REWARD_MAX = int(os.environ.get("NYM_WALLET_REWARD_MAX", "80"))  # cap per-delegation reward lookups
# --- Full tx-history indexer -------------------------------------------------
# The public LCD tx-service returns only the most recent ~100 matching txs and ignores
# pagination offset, so full wallet history needs an archive node. rpc.nyx.nodes.guru is a
# full archive (earliest_block=1); its Tendermint /tx_search paginates properly. We index
# each viewed wallet into SQLite once, then serve instantly and tail for new txs.
NYM_RPC_ARCHIVE = os.environ.get("NYM_RPC_ARCHIVE", "https://rpc.nyx.nodes.guru")
TXDB = Path("nym_txs.db")
TX_INDEX_TTL = int(os.environ.get("NYM_TX_INDEX_TTL", "300"))            # re-tail a wallet after 5min
TX_INDEX_MAX_PAGES = int(os.environ.get("NYM_TX_INDEX_MAX_PAGES", "40"))  # backfill cap (4000 tx/query)
TX_SERVE_LIMIT = int(os.environ.get("NYM_TX_SERVE_LIMIT", "250"))         # rows returned to the UI
# Nyx block time is ~5.69s and extremely stable across the whole chain, so a tx timestamp is
# recovered from its height by piecewise-linear interpolation over these measured (height, UTC)
# anchors instead of one /block query per tx.
_HEIGHT_ANCHORS_ISO = [
    (2000000, "2022-06-13T22:26:42Z"), (8000000, "2023-07-17T19:09:02Z"),
    (14000000, "2024-08-18T20:11:05Z"), (20000000, "2025-09-09T02:03:34Z"),
    (24000000, "2026-05-30T16:38:52Z"), (24893877, "2026-07-28T12:49:34Z"),
]
def _anchor_epochs():
    from datetime import datetime
    out = []
    for h, iso in _HEIGHT_ANCHORS_ISO:
        try:
            out.append((h, datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()))
        except Exception:
            pass
    return sorted(out)
_HEIGHT_ANCHORS = _anchor_epochs()
_check_cache = {}    # ip -> {"r": response, "ts": epoch}; makes re-opening a node instant
CHECK_TTL = int(os.environ.get("NYM_CHECK_TTL", "90"))

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

def _build_provider_advisory(asn):
    """Top-level advisory for the node's hosting provider.

    Returns the risk_advisory dict from PROVIDERS[asn] if present, enriched
    with the provider name + aliases so the frontend can render a banner.
    Returns None if no advisory active.
    """
    if not asn:
        return None
    try:
        from nym_provider_data import PROVIDERS as _PROV
    except Exception:
        return None
    p = (_PROV or {}).get(str(asn)) or {}
    adv = p.get("risk_advisory")
    if not adv:
        return None
    return {
        "asn": str(asn),
        "provider_name": p.get("name"),
        "aliases": p.get("aliases") or [],
        **adv,
    }


def _build_grid_energy_response(country_code, asn=None):
    """Build grid energy response: country grid intensity (Ember) + provider renewable tier.

    Returns None if no country code or country has no grid intensity data.
    The frontend renders a compact row + expand panel with both layers.
    """
    if not country_code:
        return None
    try:
        from nym_country_data import COUNTRIES as _COUNTRIES, COUNTRY_DATA_SOURCES as _CDS, GRID_INTENSITY_WORLD_AVG as _WORLD
    except Exception:
        return None
    c = (_COUNTRIES or {}).get(country_code)
    if not c or "grid_intensity_g_per_kwh" not in c:
        return None
    intensity = c.get("grid_intensity_g_per_kwh")
    band = "unknown"
    if isinstance(intensity, (int, float)):
        if intensity < 100:    band = "very_low"
        elif intensity < 300:  band = "low"
        elif intensity < 500:  band = "medium"
        elif intensity < 700:  band = "high"
        else:                  band = "very_high"
    src = (_CDS or {}).get(country_code, {}).get("grid_intensity_g_per_kwh", {})

    # Provider renewable layer (looked up by ASN)
    provider_block = None
    if asn:
        try:
            from nym_provider_data import PROVIDERS as _PROV
            p = (_PROV or {}).get(str(asn)) or {}
            r = p.get("renewable")
            if r:
                provider_block = {
                    "name": p.get("name"),
                    "asn": str(asn),
                    "tier": r.get("tier"),
                    "tier_label": r.get("tier_label"),
                    "verification_confidence": r.get("verification_confidence"),
                    "claim_summary": r.get("claim_summary"),
                    "source_url": r.get("source_url"),
                    "verified_at": r.get("verified_at"),
                    "datacenters_count": len(r.get("datacenters") or []),
                }
        except Exception:
            pass

    return {
        "intensity_g_per_kwh": intensity,
        "intensity_band": band,
        "data_year": c.get("grid_intensity_year"),
        "freshness": c.get("grid_intensity_freshness"),
        "trend_5y": c.get("grid_intensity_trend_5y"),
        "trend_5y_delta_pct": c.get("grid_intensity_trend_pct"),
        "trend_5y_reference_year": c.get("grid_intensity_trend_ref_year"),
        "trend_5y_reference_value": c.get("grid_intensity_trend_ref_value"),
        "country_code": country_code,
        "country_name": c.get("name"),
        "world_avg_g_per_kwh": (_WORLD or {}).get("value") if _WORLD else None,
        "world_avg_year": (_WORLD or {}).get("year") if _WORLD else None,
        "source": {
            "provider": src.get("provider"),
            "url": src.get("source"),
            "indicator": src.get("indicator"),
            "license": src.get("license"),
            "verified_at": src.get("verified_at"),
        } if src else None,
        "provider": provider_block,
    }


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
    # Use the node's declared custom_http_port (from the cache, sourced from on-chain bond data)
    # so nodes serving their API on a non-8080 port are reached instead of shown as unreachable.
    _cport=None
    try:
        _cn=next((cn for cn in (_nodes_mem.get("nodes") or []) if cn.get("ip")==ip),None)
        _cport=(_cn or {}).get("http_port")
    except Exception:
        _cport=None
    nd=await qnode(client,ip,port=_cport or 8080)
    if not nd["reachable"]:return _fail(ip,ref,"node API not responding (tried declared port + 8080/8000/9000)",hostname)
    _apiport=nd.get("http_port") or _cport or 8080  # the API port qnode actually reached, reused below
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
    # multi-vantage re-probes the same ports independently of the local result, so run it
    # concurrently with the local probes instead of as a separate sequential await.
    async def _mv_safe():
        try:
            return await _multi_vantage_probe_ports(client, ip, all_ports)
        except Exception:
            return {}
    all_results=await asyncio.gather(*port_coros,_phw(client,ip,_apiport),ck_ipv6(client,ip,_ipv6_hint,hostname=_hn),_mv_safe())
    _np=len(all_ports)
    port_results=all_results[:_np];hw=all_results[_np];ipv6=all_results[_np+1];_multi_vantage=all_results[_np+2]
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
    # Attach local result for each port so frontend can compare (multi-vantage ran above, in parallel)
    if _multi_vantage:
        for idx,(pi,ok) in enumerate(zip(all_ports,port_results)):
            if pi["proto"] != "tcp":
                continue
            key = f"{pi['port']}/{pi['proto']}"
            if key in _multi_vantage:
                _multi_vantage[key]["local"] = {"open": bool(ok)}
    exit_policy_results=None
    has_exit_policy=False
    if is_exit:
        # Per-node exit policy check via node API
        ep_data=await _safe_json(client,f"http://{_host_for_url(ip)}:{_apiport}/api/v1/network-requester/exit-policy",timeout=5)
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
    # Try to enrich with operator wallet (owner) and brand-prefix grouping from the cache.
    try:
        _cached = _nodes_mem.get("nodes") or []
        _own_node = next((cn for cn in _cached if cn.get("ip")==ip), None)
        _owner = (_own_node or {}).get("owner","") if _own_node else ""
        _refresh_op_keys_cache()
        _op_key = _op_keys_cache["by_ip"].get(ip)
        _op_count = sum(1 for k in _op_keys_cache["by_ip"].values() if k == _op_key) if _op_key else 0
    except Exception:
        _owner = ""; _op_key = None; _op_count = 0

    # Comparison stats - peer placement in the network for the user
    try:
        _comp = {}
        # Ensure node cache is populated (lazy-load on first request after restart)
        await _cnodes()
        _all = _nodes_mem.get("nodes") or []
        if _all:
            _comp["network_total"] = len(_all)
            _same_mode = [n for n in _all if n.get("mode") == mode]
            _comp["mode"] = mode
            _comp["mode_peers"] = len(_same_mode)
            _own_cc = (aux.get("location","") or "").upper()
            if _own_cc:
                _same_country = [n for n in _all if (n.get("location","") or "").upper() == _own_cc]
                _comp["country"] = _own_cc
                _comp["country_count"] = len(_same_country)
                _comp["country_pct"] = round(len(_same_country)/len(_all)*100, 1)
            # ASN comparison via ip_to_asn cache
            _asn_cache_local = _asn_cache.get("ip_to_asn", {}) if isinstance(_asn_cache.get("ip_to_asn"), dict) else {}
            _own_asn_info = _asn_cache_local.get(ip) or {}
            _own_asn = _own_asn_info.get("asn")
            if _own_asn:
                _same_asn = [n for n in _all if (_asn_cache_local.get(n.get("ip","")) or {}).get("asn") == _own_asn]
                _comp["asn"] = _own_asn
                _comp["asn_name"] = _asn_cache.get("asn_names",{}).get(_own_asn,"")
                _comp["asn_count"] = len(_same_asn)
                _comp["asn_pct"] = round(len(_same_asn)/len(_all)*100, 1)
            # Version distribution among same-mode peers - compute version_status on the fly for each peer
            _own_vs_raw = _build_version_response(cur, lat, ref.get("prerelease_version")) or {}
            _own_vs = _own_vs_raw.get("status") if isinstance(_own_vs_raw, dict) else None
            if _own_vs:
                _prerel = ref.get("prerelease_version")
                _peer_status = {}
                for n in _same_mode:
                    nip = n.get("ip","")
                    pv = n.get("version","")
                    if not pv:
                        _peer_status[nip] = "unknown"; continue
                    pvs = _build_version_response(pv, lat, _prerel) or {}
                    _peer_status[nip] = pvs.get("status","unknown") if isinstance(pvs, dict) else "unknown"
                _vd = {"current":0, "prerelease":0, "behind":0, "unknown":0}
                for s in _peer_status.values():
                    if s not in _vd: s = "unknown"
                    _vd[s] += 1
                _comp["version_status"] = _own_vs
                _comp["version_distribution_same_mode"] = _vd
                # "Ahead of" rank: count of nodes you outrank by version (behind worst, current/prerelease better)
                _order = {"behind":0, "unknown":1, "current":2, "prerelease":3}
                _own_rank = _order.get(_own_vs, 1)
                _ahead = sum(1 for s in _peer_status.values() if _order.get(s, 1) < _own_rank)
                _comp["version_better_than_pct"] = round(_ahead/max(len(_same_mode),1)*100, 1)
            # WireGuard share for same-mode peers (relevant for entry/exit)
            # Use cached wg (derived from nym-api described listing) as source of truth -
            # live _check_ip wg flag is taken from authenticator_enabled which lags behind
            # actual deployment for nodes that have wireguard config but not yet polled.
            if mode in ("entry-gateway","exit-gateway"):
                _wg_share = sum(1 for n in _same_mode if n.get("wg"))
                _comp["wg_pct_same_mode"] = round(_wg_share/max(len(_same_mode),1)*100, 1)
                _own_wg_cached = bool((_own_node or {}).get("wg")) if _own_node else None
                _comp["has_wg"] = _own_wg_cached if _own_wg_cached is not None else wg
    except Exception as _comp_err:
        _comp = {"error": str(_comp_err)}
    # node_id lets the frontend lazy-load on-chain economics + delegations (never blocks the check)
    _eid = (_own_node or {}).get("node_id") if _own_node else None
    return {"node_ip":ip,"hostname":hostname,"check_timestamp":datetime.now(timezone.utc).isoformat(),
        "score":score,"mode":mode,"wireguard_enabled":wg,
        "version":_build_version_response(cur,lat,ref.get("prerelease_version")),
        "ports":{"total":len(rp),"open":len(op),"missing":mp,"likely_open":likely_open,"ok":len(mp)==0,
            "infra":{"total":len(infra_ports),"open":infra_open,"closed":infra_closed,"ok":len(infra_closed)==0} if infra_ports else None,
            "multi_vantage":_multi_vantage if _multi_vantage else None},
        "ipv6":_build_ipv6_response(ip,ipv6),"hardware":hw,"toc":{"accepted":toc,"ok":toc},
        "description":{"moniker":desc.get("moniker",""),"website":desc.get("website",""),"security_contact":desc.get("security_contact","")},
        "auxiliary":{"location":aux.get("location","")},
        "roles":{"mixnode":is_mix,"entry_gateway":is_entry,"exit_gateway":is_exit},
        "exit_policy":exit_policy_results,
        "smtp":smtp_result,
        "grid_energy":_build_grid_energy_response(aux.get("location",""), _comp.get("asn") if isinstance(_comp, dict) else None),
        "provider_advisory":_build_provider_advisory(_comp.get("asn") if isinstance(_comp, dict) else None),
        "functional_probe":_build_functional_probe_response((_own_node or {}).get("identity_key") if _own_node else None, _multi_vantage),
        "stress":_build_stress_response((_own_node or {}).get("node_id") if _own_node else None),
        "node_id":_eid,
        "owner":_owner,
        "identity_key":(_own_node or {}).get("identity_key","") if _own_node else "",
        "operator_key":_op_key,
        "operator_count":_op_count,
        "comparison":_comp,
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
            _ce=_check_cache.get(ip)
            if _ce and (time.time()-_ce["ts"])<CHECK_TTL:
                result=_ce["r"]
            else:
                result=await _check_ip(client,ip,hostname,ref)
                _check_cache[ip]={"r":result,"ts":time.time()}
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

async def _phw(client, host, port=8080):
    """Fetch hardware from node system-info endpoint (on the node's real API port)."""
    d = await _safe_json(client, f"http://{_host_for_url(host)}:{port}/api/v1/system-info", timeout=5)
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

async def _fetch_moniker(client,ip,port=8080):
    # try the node's declared custom_http_port first, then common fallbacks — ~11% of nodes
    # serve their API off :8080, which otherwise left them with a blank (default) moniker.
    tried=[]
    for p in (port,8080,8000):
        if not p or p in tried:continue
        tried.append(p)
        try:
            r=await client.get(f"http://{_host_for_url(ip)}:{p}/api/v1/description",timeout=3)
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

    # Fetch: missing + empty (retry failures) + ALL if the last FULL refresh was >24h ago.
    # The 24h clock lives in a marker key INSIDE the file, NOT the file mtime: the file is
    # rewritten every cycle to retry empty/new nodes, and an mtime-based check reset itself
    # each rewrite, so it never went stale and a renamed node's cached name never updated.
    _FULL_KEY="__full_refresh_ts__"
    _last_full=monikers.get(_FULL_KEY) if isinstance(monikers.get(_FULL_KEY),(int,float)) else 0
    stale=(time.time()-_last_full)>86400
    _port_by_ip={n["ip"]:n.get("http_port") for n in nodes}
    ips_to_fetch=[n["ip"] for n in nodes if n["ip"] not in monikers or not monikers[n["ip"]] or stale]
    if not ips_to_fetch:
        return monikers

    print(f"[*] Fetching monikers for {len(ips_to_fetch)} nodes...")
    async with httpx.AsyncClient() as client:
        for i in range(0,len(ips_to_fetch),batch_size):
            batch=ips_to_fetch[i:i+batch_size]
            results=await asyncio.gather(*[_fetch_moniker(client,ip,_port_by_ip.get(ip) or 8080) for ip in batch])
            for ip,m in zip(batch,results):
                monikers[ip]=m
            print(f"[*] Monikers: {i+len(batch)}/{len(ips_to_fetch)}")

    if stale:                       # stamp the full-refresh clock only when we did a full pass
        monikers[_FULL_KEY]=time.time()
    try:MONIKER_FILE.write_text(json.dumps(monikers,ensure_ascii=False))
    except:pass
    print(f"[*] Monikers saved: {sum(1 for k,v in monikers.items() if k!=_FULL_KEY and v)} with names")
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
    _LIST_KEYS=("node_id","ip","hostname","moniker","mode","location","version","wg","owner","identity_key")
    ref=load_ref();latest=ref.get("latest_version","");prerelease=ref.get("prerelease_version")
    slim=[]
    for n in nodes:
        # Drop nulls/empty strings to shrink payload (gzip still helps, but smaller JSON parses faster)
        item={k:v for k in _LIST_KEYS if (v:=n.get(k)) not in (None,"",False)}
        # wg=false is meaningful (not just missing), restore it explicitly
        item["wg"]=bool(n.get("wg"))
        # toc=false (operator T&C not accepted) is meaningful too - Nymi watches it for alerts
        item["toc"]=bool(n.get("toc"))
        vs=_build_version_response(n.get("version",""),latest,prerelease).get("status","unknown")
        if vs!="unknown":item["version_status"]=vs
        _se=_stress_cache.get(n.get("node_id"))
        # only surface stress for stress-tested nodes (mixnodes reachable by the monitor);
        # gateways/untested report 0/was_reachable=false and would read as false failures
        if _se and _se.get("stress") is not None and _se.get("stress_reachable"):item["stress"]=_se["stress"]
        _db=_dp_backed.get(n.get("node_id"))
        if _db:item["dp_backed"]=_db
        slim.append(item)
    return{"count":len(slim),"nodes":slim,"latest_version":latest,"prerelease_version":prerelease}

async def _get_rewarded_set():
    """Active/rewarded set node ids (for the ACTIVE column), cached RSET_TTL."""
    import time
    if _rewarded_set["ids"] and (time.time() - _rewarded_set["ts"]) < RSET_TTL:
        return _rewarded_set["ids"]
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(REWARDED_SET_URL, headers={"User-Agent": "nym-checker/1.0"})
            j = r.json()
        ids = set()
        for k in ("entry_gateways", "exit_gateways", "standby", "layer1", "layer2", "layer3"):
            for x in (j.get(k) or []):
                try: ids.add(int(x))
                except Exception: pass
        mx = j.get("mixnodes")
        if isinstance(mx, dict):
            for layer in mx.values():
                for x in (layer or []):
                    try: ids.add(int(x))
                    except Exception: pass
        elif isinstance(mx, list):
            for x in mx:
                try: ids.add(int(x))
                except Exception: pass
        if ids:
            _rewarded_set["ids"] = ids
            _rewarded_set["epoch"] = j.get("epoch_id")
            _rewarded_set["ts"] = time.time()
    except Exception as e:
        print("[!] rewarded-set: " + str(e))
    return _rewarded_set["ids"]

@app.get("/api/nymesis")
async def nymesis_table():
    """Bulk explorer table (Nymesis-style): one row per node from already-cached sources
    (node cache + annotation/stress cache + bonded econ + rewarded-set + DP map). Cheap — no
    per-node LCD. Saturation / total-stake / owner-reward are intentionally omitted (they need
    per-node contract queries) and load lazily in the node detail view instead."""
    nodes = await _cnodes()
    if not _bonded_econ:
        try:
            async with httpx.AsyncClient() as c:
                await _fetch_owners(c)
        except Exception:
            pass
    active = await _get_rewarded_set()
    ref = load_ref(); latest = ref.get("latest_version", ""); prerelease = ref.get("prerelease_version")
    rows = []
    for n in nodes:
        nid = n.get("node_id")
        if nid is None:
            continue
        se = _stress_cache.get(nid) or {}
        be = _bonded_econ.get(nid) or {}
        eb = _econ_bulk.get(nid) or {}
        vs = _build_version_response(n.get("version", ""), latest, prerelease).get("status", "unknown")
        rows.append({
            "node_id": nid,
            "moniker": n.get("moniker", ""),
            "ip": n.get("ip", ""),
            "identity_key": n.get("identity_key", ""),
            "country": n.get("location", ""),
            "version": n.get("version", ""),
            "version_status": vs,
            "mode": n.get("mode", ""),
            "perf": se.get("performance"),
            "config": se.get("config"),
            "routing": se.get("routing"),
            "stress": se.get("stress") if se.get("stress_reachable") else None,
            "delegations": be.get("delegations"),
            "opcost": be.get("opcost"),
            "margin": be.get("margin"),
            "pledge": be.get("pledge"),
            "saturation": eb.get("saturation"),
            "total_stake": eb.get("total_stake"),
            "owner_reward": eb.get("owner_reward"),
            "active": nid in active,
            "dp": bool(_dp_backed.get(nid)),
        })
    return {"count": len(rows), "rows": rows, "epoch": _rewarded_set.get("epoch"), "latest_version": latest}

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

async def _fetch_owners(client):
    """Fetch node_id -> owner wallet and node_id -> custom_http_port from the bonded endpoint.
    bonded carries the owner wallet AND the node's declared API port; described carries neither."""
    owners = {}
    ports = {}
    econ = {}
    try:
        r = await client.get(DEF_REF["bonded_api"] + "?limit=3000", timeout=25)
        r.raise_for_status()
        for item in r.json().get("data", []):
            bi = item.get("bond_information", {}) or {}
            nid = bi.get("node_id")
            if nid is None:
                continue
            owner = bi.get("owner")
            if owner:
                owners[nid] = owner
            hp = (bi.get("node") or {}).get("custom_http_port")
            if hp:
                ports[nid] = hp
            # Bulk economics for the explorer table (one bonded call covers every node).
            rd = item.get("rewarding_details") or {}
            cp = rd.get("cost_params") or {}
            e = {}
            try: e["margin"] = round(float(cp.get("profit_margin_percent")), 4)
            except Exception: e["margin"] = None
            e["opcost"] = _unym((cp.get("interval_operating_cost") or {}).get("amount"))
            e["delegations"] = rd.get("unique_delegations")
            e["pledge"] = _unym((bi.get("original_pledge") or {}).get("amount"))
            econ[nid] = e
    except Exception as e:
        print("[!] Fetch owners: " + str(e))
    if econ:
        _bonded_econ.clear()
        _bonded_econ.update(econ)
    return owners, ports


async def _fnodes():
    """Fetch fresh node list from Nym described API, enriched with owner from bonded API."""
    nodes = []
    async with httpx.AsyncClient(timeout=30) as c:
        owners, ports = await _fetch_owners(c)
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
                    _node_id_val = it.get("node_id", "")
                    nodes.append({
                        "node_id": _node_id_val,
                        "identity_key": hi.get("keys", {}).get("ed25519", "") if isinstance(hi.get("keys"), dict) else "",
                        "ip": ip,
                        "hostname": hi.get("hostname") if isinstance(hi, dict) else None,
                        "moniker": "Node " + str(_node_id_val),
                        "mode": mode,
                        "location": aux.get("location", "") if isinstance(aux, dict) else "",
                        "version": bi.get("build_version", "") if isinstance(bi, dict) else "",
                        "wg": bool(d.get("wireguard")),
                        "toc": _toc,
                        "ipv6": _ipv6,
                        "ipv6_addr": _ipv6_addr,
                        "owner": owners.get(_node_id_val, ""),
                        "http_port": ports.get(_node_id_val),
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

            # 2.5) Official Nym probe (Nym monitors test v6 directly). Robust to the PTR->AAAA gap
            #      that makes the Stockholm agent return no_ipv6_address_found for v6-capable nodes
            #      whose reverse-DNS hostname has no AAAA (i.e. most of them).
            idk = node.get("identity_key") or ""
            if idk:
                _pe = _nym_probe_cache.get(idk)
                if _pe:
                    _o  = (_pe.get("last_probe_result") or {}).get("outcome") or {}
                    _wg = _o.get("wg") or {}
                    _ex = _o.get("as_exit") or {}
                    _ph6 = _wg.get("ping_hosts_performance_v6")
                    # REAL working v6 only: external-v6 routing OR actual v6 ping traffic.
                    # can_handshake_v6 alone is NOT enough - it is often True while v6 is dead
                    # (ping 0.0, no external route). Keying on it is exactly what made us show
                    # "confirmed" where Harbourmaster (same Nym data) correctly shows no IPv6.
                    _v6ok = (_ex.get("can_route_ip_external_v6") is True
                             or (isinstance(_ph6, (int, float)) and _ph6 > 0))
                    # The probe is Nym's own, fresh (~15 min) and authoritative, so let it decide
                    # BOTH ways - a stale "confirmed" gets corrected to absent instead of sticking.
                    node["ipv6"] = bool(_v6ok)
                    node["ipv6_source"] = "nym-probe"
                    node["ipv6_status"] = "confirmed" if _v6ok else "absent"
                    node["ipv6_checked_at"] = now
                    if not _v6ok:
                        node.pop("ipv6_addr", None)
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
    _bg_tasks.append(asyncio.create_task(_bg_daily_history_snapshot()))
    _bg_tasks.append(asyncio.create_task(_bg_monthly_country_metrics_refresh()))
    _bg_tasks.append(asyncio.create_task(_bg_refresh_nym_probe()))
    _bg_tasks.append(asyncio.create_task(_bg_refresh_stress()))
    _bg_tasks.append(asyncio.create_task(_bg_refresh_econ_bulk()))
    _bg_tasks.append(asyncio.create_task(_bg_analytics_backfill()))
    _bg_tasks.append(asyncio.create_task(_bg_refresh_dp()))
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

# ── History snapshots ────────────────────────────────────────
# Daily snapshots of per-node state for trend analysis (uptime, version drift, SMTP, IPv6).
# Reuses already-cached data (no extra probes) so it is cheap to run.
HISTORY_DB = Path("nym_history.db")

def _init_history_db():
    import sqlite3
    conn = sqlite3.connect(str(HISTORY_DB))
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS node_snapshots (
            snapshot_date TEXT NOT NULL,
            node_id INTEGER,
            ip TEXT NOT NULL,
            mode TEXT,
            location TEXT,
            version TEXT,
            version_status TEXT,
            wg INTEGER,
            online INTEGER,
            smtp_status TEXT,
            ipv6_supported INTEGER,
            PRIMARY KEY (snapshot_date, ip)
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_date ON node_snapshots(ip, snapshot_date DESC)")
        conn.commit()
    finally:
        conn.close()


def _take_history_snapshot():
    """Insert one row per known node for today's date (overwrite if already exists)."""
    import sqlite3
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    nodes = _nodes_mem.get("nodes") or []
    if not nodes:
        return {"inserted": 0, "date": today, "skipped_reason": "no nodes in cache"}
    ref = load_ref()
    latest = ref.get("latest_version")
    prerel = ref.get("prerelease_version")
    rows = []
    for n in nodes:
        ip = n.get("ip", "") or ""
        if not ip:
            continue
        v = n.get("version", "") or ""
        vs = "unknown"
        if v:
            vsr = _build_version_response(v, latest, prerel) or {}
            vs = vsr.get("status", "unknown") if isinstance(vsr, dict) else "unknown"
        smtp_entry = _smtp_cache.get(ip) if _smtp_cache else None
        smtp_status = (smtp_entry or {}).get("status") if smtp_entry else None
        # IPv6: prefer verified cache, fall back to nym-api ip_addresses presence in node cache
        ipv6_entry = _ipv6_cache.get(ip) if _ipv6_cache else None
        ipv6_ok = 1 if (ipv6_entry or {}).get("status") in ("trusted", "confirmed") else (1 if n.get("ipv6") else 0)
        rows.append((
            today,
            n.get("node_id"),
            ip,
            n.get("mode") or "",
            (n.get("location") or "").upper(),
            v,
            vs,
            1 if n.get("wg") else 0,
            1,  # online: present in nym-api described list = alive
            smtp_status,
            ipv6_ok,
        ))
    if not rows:
        return {"inserted": 0, "date": today, "skipped_reason": "no rows"}
    conn = sqlite3.connect(str(HISTORY_DB))
    try:
        conn.executemany("""INSERT OR REPLACE INTO node_snapshots
            (snapshot_date, node_id, ip, mode, location, version, version_status, wg, online, smtp_status, ipv6_supported)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows)
        conn.commit()
    finally:
        conn.close()
    return {"inserted": len(rows), "date": today}


@app.get("/api/history/{ip}")
async def node_history(ip: str, days: int = Query(30, ge=1, le=365)):
    """Return per-day snapshot history for a node (up to N days back)."""
    import sqlite3
    from datetime import datetime, timezone, timedelta
    if not HISTORY_DB.exists():
        return {"ip": ip, "days": days, "snapshots": []}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = sqlite3.connect(str(HISTORY_DB))
    try:
        cur = conn.execute("""SELECT snapshot_date, mode, location, version, version_status, wg, online, smtp_status, ipv6_supported
            FROM node_snapshots WHERE ip = ? AND snapshot_date >= ?
            ORDER BY snapshot_date ASC""", (ip, cutoff))
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"ip": ip, "days": days, "snapshots": rows, "count": len(rows)}


@app.get("/api/economics/{node_id}")
async def node_economics(node_id: int):
    """On-chain economics for a node: saturation, per-epoch + claimable operator reward,
    owner wallet balance, cost params (margin/operating cost), delegated stake, DP backing."""
    nodes = await _cnodes()
    n = next((x for x in nodes if x.get("node_id") == node_id), None)
    owner = (n or {}).get("owner") or None
    se = _stress_cache.get(node_id) or {}
    econ = await _fetch_node_economics(node_id, owner=owner, perf=se.get("performance"))
    return econ or {"node_id": node_id, "available": False}


@app.get("/api/delegations/{node_id}")
async def node_delegations(node_id: int):
    """Delegation graph for a node: who delegated, how much, when, their wallet balance,
    how many nodes they back, and DP/vesting flags."""
    d = await _fetch_node_delegations(node_id)
    return d or {"node_id": node_id, "delegations": [], "count": 0}


CTX_DB = os.environ.get("NYM_CTX_DB", str(Path(__file__).parent / "nym_contract_txs.db"))


@app.get("/api/node-history/{node_id}")
async def node_history(node_id: int, limit: int = Query(60, ge=1, le=500)):
    """Delegations/undelegations and bond changes for ONE node, newest first.

    Filled by contract_index.py, which tails new blocks every 2 min and decodes the tx bodies:
    the chain does NOT index node_id (it lives in the message body, not in an event), so a node's
    history cannot be tx_searched the way a wallet's can - it has to be parsed and stored.
    """
    import sqlite3
    rows = []
    try:
        conn = sqlite3.connect(CTX_DB)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT height, iso, kind, owner, amount, success FROM ctx "
            "WHERE node_id=? ORDER BY height DESC LIMIT ?", (node_id, limit))
        rows = [dict(r) for r in cur]
        conn.close()
    except Exception:
        pass
    return {"node_id": node_id, "events": rows, "count": len(rows)}


@app.get("/api/dp")
async def dp_info():
    """Nym Delegation Program / team wallet backing summary (nodes + total NYM)."""
    return {**_dp_meta, "backed_count": len(_dp_backed)}


@app.get("/api/wallet/{address}")
async def wallet_info(address: str):
    """Explorer view of any Nyx wallet: balance, delegations (with node names), operated
    nodes, pending operator reward, and categorized tx history (delegate/undelegate/
    withdraw/send/receive)."""
    address = (address or "").strip()
    if not (address.startswith("n1") and 38 <= len(address) <= 70 and address.isalnum()):
        return JSONResponse({"error": "invalid Nyx address"}, status_code=400)
    try:
        return await _fetch_wallet(address)
    except Exception as e:
        return {"address": address, "available": False, "error": str(e)[:200]}


@app.get("/api/wallet/{address}/txs")
async def wallet_txs(address: str):
    """Full tx history for a wallet, indexed from the archive RPC into SQLite (delegate,
    undelegate, withdraw-reward, send, receive, ...). First view backfills from genesis;
    later views serve from SQLite instantly and tail for new txs."""
    address = (address or "").strip()
    if not (address.startswith("n1") and 38 <= len(address) <= 70 and address.isalnum()):
        return JSONResponse({"error": "invalid Nyx address"}, status_code=400)
    try:
        _txdb_init()
        st = _tx_index_state(address)
        if st is None:
            await _index_wallet(address, full=True)       # first view: full backfill
        elif (time.time() - st["ts"]) > TX_INDEX_TTL:
            await _index_wallet(address, full=False)       # stale: quick tail for new txs
        txs = _read_wallet_txs(address, TX_SERVE_LIMIT)
        if not txs:
            # archive unreachable / nothing indexed -> live LCD recent as a safety net
            async with httpx.AsyncClient(timeout=20.0) as client:
                txs = await _fetch_wallet_txs(client, address, WALLET_TX_LIMIT)
        st = _tx_index_state(address) or {}
        return {"address": address, "txs": txs, "tx_count": len(txs), "total_indexed": st.get("total")}
    except Exception as e:
        return {"address": address, "txs": [], "tx_count": 0, "error": str(e)[:200]}


@app.get("/api/pending/{address}")
async def wallet_pending(address: str):
    """Pending epoch events (delegations/undelegations queued for the NEXT epoch) for an address.
    In Nym, a delegation is not active until the epoch boundary — this surfaces it in the meantime."""
    address = (address or "").strip()
    if not (address.startswith("n1") and 38 <= len(address) <= 70 and address.isalnum()):
        return JSONResponse({"error": "invalid Nyx address"}, status_code=400)
    out = {"seconds_until_executable": None, "pending": []}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            start = None
            for _ in range(12):  # cap pages (500 each)
                q = {"get_pending_epoch_events": {"limit": 500}}
                if start is not None:
                    q["get_pending_epoch_events"]["start_after"] = start
                data = await _lcd_smart(client, q)
                if not isinstance(data, dict):
                    break
                if out["seconds_until_executable"] is None:
                    out["seconds_until_executable"] = data.get("seconds_until_executable")
                evs = data.get("events") or []
                for it in evs:
                    kind = ((it.get("event") or {}).get("kind")) or {}
                    for k in ("delegate", "undelegate"):
                        d = kind.get(k)
                        if isinstance(d, dict) and d.get("owner") == address:
                            out["pending"].append({
                                "type": k,
                                "node_id": d.get("node_id") if d.get("node_id") is not None else d.get("mix_id"),
                                "amount": _unym((d.get("amount") or {}).get("amount")) if d.get("amount") else None,
                            })
                nxt = data.get("start_next_after")
                if not evs or nxt is None or nxt == start:
                    break
                start = nxt
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


# ── Nymesis analytics: fetch once from their public API, PERSIST into our own SQLite, serve from
# ── ours (their API is only a "top-up"). Owns the history so it survives their paused serverless. ──
NYMESIS_ANALYTICS = os.environ.get("NYMESIS_ANALYTICS_API", "").rstrip("/")
ANALYTICS_DB = Path("nym_analytics.db")
ANALYTICS_REFRESH = int(os.environ.get("NYM_ANALYTICS_REFRESH", "43200"))  # top-up a node from their API at most every 12h
_an_inited = False

def _analytics_db_init():
    global _an_inited
    if _an_inited:
        return
    import sqlite3
    conn = sqlite3.connect(str(ANALYTICS_DB), timeout=30)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS an_series(node_id INTEGER,metric TEXT,date TEXT,a REAL,b REAL,PRIMARY KEY(node_id,metric,date))")
        conn.execute("CREATE TABLE IF NOT EXISTS an_events(node_id INTEGER,kind TEXT,date TEXT,info TEXT,PRIMARY KEY(node_id,kind,date))")
        conn.execute("CREATE TABLE IF NOT EXISTS an_meta(node_id INTEGER PRIMARY KEY,uptime INTEGER,ts REAL)")
        conn.commit()
    finally:
        conn.close()
    _an_inited = True

async def _analytics_fetch(node_id, days=30):
    """Pull raw history from the Nymesis public API. Returns None if it gives us nothing."""
    async def g(client, path):
        try:
            r = await client.get(f"{NYMESIS_ANALYTICS}/api/v3/nodes/{node_id}/{path}")
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None
    async with httpx.AsyncClient(timeout=14.0) as client:
        profit, perf, rewarded, packets, updates, reboots, uptime = await asyncio.gather(
            g(client, f"history/profit?days={days}"), g(client, f"history/performance?days={days}"),
            g(client, f"history/rewarded?days={days}"), g(client, f"history/packets?days={days}"),
            g(client, "history/updates?days=60"), g(client, "history/reboots?days=30"), g(client, "uptime"))
    out = {"profit": (profit or {}).get("elements"), "performance": (perf or {}).get("elements"),
           "rewarded": (rewarded or {}).get("elements"), "packets": (packets or {}).get("elements"),
           "updates": (updates or {}).get("elements"), "reboots": (reboots or {}).get("elements"),
           "uptime": (uptime or {}).get("uptime") if isinstance(uptime, dict) else None}
    return out if (out.get("profit") or out.get("performance")) else None

def _analytics_store(node_id, raw):
    import sqlite3, time
    _analytics_db_init()
    conn = sqlite3.connect(str(ANALYTICS_DB), timeout=30)
    try:
        def ups(metric, elements, ka, kb=None):
            for e in (elements or []):
                d = e.get("date")
                if d:
                    conn.execute("INSERT OR REPLACE INTO an_series(node_id,metric,date,a,b) VALUES(?,?,?,?,?)",
                                 (node_id, metric, d, e.get(ka), (e.get(kb) if kb else None)))
        ups("profit", raw.get("profit"), "owner_profit", "node_profit")
        ups("performance", raw.get("performance"), "performance")
        ups("rewarded", raw.get("rewarded"), "count", "rate")
        ups("packets", raw.get("packets"), "ingress", "egress")
        for u in (raw.get("updates") or []):
            if u.get("date"):
                conn.execute("INSERT OR REPLACE INTO an_events(node_id,kind,date,info) VALUES(?,?,?,?)", (node_id, "update", u.get("date"), u.get("build_version")))
        for rb in (raw.get("reboots") or []):
            if rb.get("date"):
                conn.execute("INSERT OR REPLACE INTO an_events(node_id,kind,date,info) VALUES(?,?,?,?)", (node_id, "reboot", rb.get("date"), None))
        conn.execute("INSERT OR REPLACE INTO an_meta(node_id,uptime,ts) VALUES(?,?,?)", (node_id, raw.get("uptime"), time.time()))
        conn.commit()
    finally:
        conn.close()

def _analytics_read(node_id):
    import sqlite3
    _analytics_db_init()
    conn = sqlite3.connect(str(ANALYTICS_DB), timeout=30)
    try:
        def ser(metric, ka, kb=None):
            rows = conn.execute("SELECT date,a,b FROM an_series WHERE node_id=? AND metric=? ORDER BY date", (node_id, metric)).fetchall()
            res = []
            for d, a, b in rows:
                o = {"date": d, ka: a}
                if kb: o[kb] = b
                res.append(o)
            return res or None
        out = {"available": False, "source": "stored"}
        out["profit"] = ser("profit", "owner_profit", "node_profit")
        out["performance"] = ser("performance", "performance")
        out["rewarded"] = ser("rewarded", "count", "rate")
        out["packets"] = ser("packets", "ingress", "egress")
        ev = conn.execute("SELECT kind,date,info FROM an_events WHERE node_id=? ORDER BY date", (node_id,)).fetchall()
        out["updates"] = [{"date": d, "build_version": info} for (k, d, info) in ev if k == "update"] or None
        out["reboots"] = [{"date": d} for (k, d, info) in ev if k == "reboot"] or None
        m = conn.execute("SELECT uptime,ts FROM an_meta WHERE node_id=?", (node_id,)).fetchone()
        out["uptime"] = m[0] if m else None
        out["stored_ts"] = m[1] if m else None
        if out["profit"] or out["performance"]:
            out["available"] = True
        return out
    finally:
        conn.close()

def _analytics_ts(node_id):
    import sqlite3
    _analytics_db_init()
    conn = sqlite3.connect(str(ANALYTICS_DB), timeout=30)
    try:
        r = conn.execute("SELECT ts FROM an_meta WHERE node_id=?", (node_id,)).fetchone()
        return r[0] if r else None
    finally:
        conn.close()

@app.get("/api/analytics/{node_id}")
async def node_analytics(node_id: int, days: int = 30):
    """Serve a node's history from OUR store; top up from the Nymesis public API when stale."""
    import time
    ts = _analytics_ts(node_id)
    if ts is None or (time.time() - ts) > ANALYTICS_REFRESH:
        try:
            raw = await _analytics_fetch(node_id, days)
            if raw:
                _analytics_store(node_id, raw)
        except Exception:
            pass
    return _analytics_read(node_id)

async def _bg_analytics_backfill():
    """One-time backfill: pull every bonded node's Nymesis history into our store, so we own it."""
    await asyncio.sleep(90)
    try:
        nodes = await _cnodes()
        ids = []
        seen = set()
        for n in nodes:
            nid = n.get("node_id")
            if nid is not None and nid not in seen:
                seen.add(nid); ids.append(nid)
        sem = asyncio.Semaphore(int(os.environ.get("NYM_ANALYTICS_BACKFILL_CONC", "6")))
        done = [0]
        async def one(nid):
            async with sem:
                if _analytics_ts(nid) is not None:
                    return
                try:
                    raw = await _analytics_fetch(nid, 30)
                    if raw:
                        _analytics_store(nid, raw); done[0] += 1
                except Exception:
                    pass
        await asyncio.gather(*(one(nid) for nid in ids))
        print(f"[*] Analytics backfill stored {done[0]} nodes into {ANALYTICS_DB}")
    except Exception as e:
        print("[!] analytics backfill: " + str(e))


async def _bg_monthly_country_metrics_refresh():
    """Regenerate country_metrics.json from World Bank API once a month, then hot-reload.
    Freedom House and RSF data is embedded as snapshot in build_country_data.py, so this
    refresh only pulls the World Bank fields (population, GDP, internet penetration).
    """
    # Initial wait: 5 minutes after startup so other tasks settle
    await asyncio.sleep(300)
    while True:
        try:
            print("[*] Monthly country metrics refresh starting...")
            script_path = Path(__file__).parent / "build_country_data.py"
            out_path = Path(__file__).parent / "country_metrics.json"
            if not script_path.exists():
                print(f"[!] build_country_data.py not found at {script_path}")
            else:
                proc = await asyncio.create_subprocess_exec(
                    "python3", str(script_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                if proc.returncode == 0 and stdout:
                    out_path.write_bytes(stdout)
                    # Hot-reload the overlay in nym_country_data
                    try:
                        import importlib, nym_country_data as ncd
                        importlib.reload(ncd)
                        print(f"[*] Country metrics refreshed: {len(stdout)} bytes, overlay reloaded")
                    except Exception as e:
                        print(f"[!] Country metrics refresh: written but overlay reload failed: {e}")
                else:
                    print(f"[!] build_country_data.py failed (rc={proc.returncode}): {stderr.decode()[:300]}")
        except asyncio.TimeoutError:
            print("[!] Monthly country metrics refresh timed out")
        except Exception as e:
            print(f"[!] Monthly country metrics refresh error: {e}")
        # Sleep 30 days
        await asyncio.sleep(86400 * 30)


async def _bg_daily_history_snapshot():
    """Take a daily history snapshot of all known nodes. Reuses cached data, no extra probes."""
    _init_history_db()
    await asyncio.sleep(90)  # Let other startup tasks settle, give cache time to populate
    # Take an initial snapshot once on startup if today's hasn't been taken yet
    try:
        await _cnodes()  # ensure cache loaded
        result = _take_history_snapshot()
        print(f"[*] History snapshot (startup): {result}")
    except Exception as e:
        print(f"[!] History snapshot (startup) error: {e}")
    while True:
        # Sleep until just after midnight UTC, then take snapshot
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        next_run = (now + timedelta(days=1)).replace(hour=0, minute=15, second=0, microsecond=0)
        sleep_sec = max(60, (next_run - now).total_seconds())
        await asyncio.sleep(sleep_sec)
        try:
            await _cnodes()
            result = _take_history_snapshot()
            print(f"[*] Daily history snapshot: {result}")
        except Exception as e:
            print(f"[!] Daily history snapshot error: {e}")


async def _fetch_nym_probe():
    """Fetch all pages of Nym's gateway functional probe API and update _nym_probe_cache.

    Source: mainnet-node-status-api.nymtech.cc/v2/gateways (the production API behind
    Harbour Master). Probe runs THROUGH the gateway (handshake, route, download), not just
    a port check. ~748 gateways, server caps pages at 200, so this pulls ~4 pages.
    Keyed by gateway identity_key (ed25519). Mixnodes are not in this dataset.
    """
    import time
    new_cache: dict = {}
    total = 0
    page = 0
    page_size = 200  # match the server's hard page cap; requesting more just gets clamped,
                     # and out-of-range pages repeat the last page rather than returning empty
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            try:
                url = f"{NYM_PROBE_URL}?size={page_size}&page={page}"
                r = await client.get(url, headers={"User-Agent": "nym-checker/1.0"})
                r.raise_for_status()
                data = r.json()
                items = data.get("items", []) or []
                total = data.get("total", total) or 0
                srv_size = data.get("size") or page_size  # server's actual page size, not a magic constant
                if not items:
                    break
                for it in items:
                    key = it.get("gateway_identity_key")
                    if not key:
                        continue
                    # Store only the operationally meaningful subset. NOTE: the full /v2/gateways
                    # endpoint does NOT expose ports_check, and routing_score/config_score are
                    # deprecated (0 across the whole network), so none of those are kept.
                    new_cache[key] = {
                        "last_probe_result": it.get("last_probe_result"),
                        "last_testrun_utc": it.get("last_testrun_utc"),
                        "last_updated_utc": it.get("last_updated_utc"),
                        "performance": it.get("performance"),
                    }
                # Authoritative stop: we have everything the server reports. Keys dedupe, so a
                # repeated out-of-range page can never inflate the count past total.
                if total and len(new_cache) >= total:
                    break
                # Short page (fewer than the server's OWN page size) = last page. Uses the echoed
                # size, so it stays correct even if Nym later changes the page cap.
                if len(items) < srv_size:
                    break
                page += 1
                # Page ceiling derived from total, not a hardcoded magic number.
                max_pages = (total // max(srv_size, 1)) + 3 if total else 50
                if page > max_pages:
                    print(f"[!] Nym probe: page {page} exceeds ceiling {max_pages}, stopping")
                    break
            except Exception as e:
                _nym_probe_meta["error"] = f"page {page}: {str(e)[:200]}"
                raise
    _nym_probe_cache.clear()
    _nym_probe_cache.update(new_cache)
    _nym_probe_meta["last_refresh"] = time.time()
    _nym_probe_meta["total_gateways"] = len(new_cache)
    _nym_probe_meta["error"] = None
    return len(new_cache)


async def _bg_refresh_nym_probe():
    """Background task: refresh Nym functional probe cache every NYM_PROBE_REFRESH_SEC."""
    # Initial delay so startup is fast
    await asyncio.sleep(20)
    while True:
        try:
            count = await _fetch_nym_probe()
            print(f"[*] Nym probe cache refreshed: {count} gateways")
        except Exception as e:
            print(f"[!] Nym probe refresh error: {e}")
        await asyncio.sleep(NYM_PROBE_REFRESH_SEC)


def _build_functional_probe_response(identity_key, our_multi_vantage=None):
    """Return the gateway's last functional probe result from Nym's official API,
    with cross-validation flags against our own multi-vantage results.

    Returns None if not in cache (mixnodes, or fresh nodes not yet probed).
    """
    if not identity_key:
        return None
    entry = _nym_probe_cache.get(identity_key)
    if not entry:
        return None

    out = (entry.get("last_probe_result") or {}).get("outcome") or {}

    # Compact, frontend-friendly shape.
    # NOTE: routing_score/config_score are intentionally omitted - the official API reports
    # them as 0 for the ENTIRE network (deprecated), so surfacing them would falsely imply
    # every gateway is broken. Use `performance` + the boolean probe dimensions instead.
    resp = {
        "available": True,
        "performance": entry.get("performance"),
        "last_probed_utc": entry.get("last_testrun_utc"),
        "as_entry": {
            "can_connect": (out.get("as_entry") or {}).get("can_connect"),
            "can_route":   (out.get("as_entry") or {}).get("can_route"),
        } if out.get("as_entry") else None,
        "as_exit": {
            "can_connect":           (out.get("as_exit") or {}).get("can_connect"),
            "can_route_ip_v4":       (out.get("as_exit") or {}).get("can_route_ip_v4"),
            "can_route_ip_v6":       (out.get("as_exit") or {}).get("can_route_ip_v6"),
            "can_route_external_v4": (out.get("as_exit") or {}).get("can_route_ip_external_v4"),
            "can_route_external_v6": (out.get("as_exit") or {}).get("can_route_ip_external_v6"),
        } if out.get("as_exit") else None,
        "lewes_protocol": {
            "can_connect":   (out.get("lp") or {}).get("can_connect"),
            "can_handshake": (out.get("lp") or {}).get("can_handshake"),
            "can_register":  (out.get("lp") or {}).get("can_register"),
            "error":         (out.get("lp") or {}).get("error"),
        } if out.get("lp") else None,
        "socks5": (lambda s: {
            "can_connect": s.get("can_connect_socks5"),
            "https_latency_ms": (s.get("https_connectivity") or {}).get("https_latency_ms"),
            "https_success":    (s.get("https_connectivity") or {}).get("https_success"),
            "https_endpoint":   (s.get("https_connectivity") or {}).get("endpoint_used"),
        } if s else None)(out.get("socks5")),
        "wireguard": (lambda w: {
            "handshake_v4": w.get("can_handshake_v4"),
            "handshake_v6": w.get("can_handshake_v6"),
            "dns_v4":       w.get("can_resolve_dns_v4"),
            "dns_v6":       w.get("can_resolve_dns_v6"),
            "register":     w.get("can_register"),
            "download_v4_bytes": w.get("downloaded_file_size_bytes_v4"),
            "download_v4_ms":    w.get("download_duration_milliseconds_v4"),
            "download_v6_bytes": w.get("downloaded_file_size_bytes_v6"),
            "download_v6_ms":    w.get("download_duration_milliseconds_v6"),
            "ping_hosts_v4":     w.get("ping_hosts_performance_v4"),
            "ping_hosts_v6":     w.get("ping_hosts_performance_v6"),
        } if w else None)(out.get("wg")),
        "source": {
            "provider": "Nym Node Status API (official, production)",
            "url": NYM_PROBE_URL,
        },
    }

    # Cross-validation hints: where our inbound multi-vantage and their functional probe disagree
    if our_multi_vantage:
        hints = []
        # If our vantages all see ports as closed but their probe says routing works,
        # the provider likely whitelists their probe IP but blocks our vantage IPs.
        all_closed_inbound = all(
            all(v.get("open") is False for v in port_data.values() if isinstance(v, dict))
            for port_data in our_multi_vantage.values()
        ) if our_multi_vantage else False
        their_routes = (resp.get("as_exit") or {}).get("can_route_external_v4")
        if all_closed_inbound and their_routes:
            hints.append({
                "code": "vantage_blacklist_likely",
                "message": "Our inbound vantages see ports as closed, but the official probe routes traffic. Provider may whitelist Nym probe IPs.",
            })
        if hints:
            resp["cross_validation"] = hints

    return resp


async def _fetch_stress():
    """Fetch per-node validator annotation scores (stress/routing/config/performance) and
    update _stress_cache. No bulk endpoint exists, so this iterates node_ids with bounded
    concurrency (like the IPv6 scan). stress_testing_score is meaningful only for mixnodes;
    gateways report stress 0 / was_reachable=false by design (still keep routing/config/perf)."""
    import time
    nodes = await _cnodes()
    ids = []
    seen = set()
    for n in nodes:
        nid = n.get("node_id")
        if nid is None or nid in seen:
            continue
        seen.add(nid)
        ids.append(nid)

    new_cache = {}
    sem = asyncio.Semaphore(STRESS_CONCURRENCY)
    now_ts = time.time()

    async def one(nid, client):
        async with sem:
            try:
                r = await client.get(f"{STRESS_ANNOTATION_URL}/{nid}",
                                     headers={"User-Agent": "nym-checker/1.0"})
                if r.status_code != 200:
                    return
                _ann = (r.json() or {}).get("annotation") or {}
                dp = _ann.get("detailed_performance") or {}
            except Exception:
                return
            st = dp.get("stress_testing_score") or {}
            new_cache[nid] = {
                "stress": st.get("score"),
                "stress_reachable": st.get("was_reachable"),
                "routing": (dp.get("routing_score") or {}).get("score"),
                "config": (dp.get("config_score") or {}).get("score"),
                "performance": dp.get("performance_score"),
                "role": _ann.get("current_role"),
                "last_updated": now_ts,
            }

    async with httpx.AsyncClient(timeout=15.0) as client:
        await asyncio.gather(*(one(nid, client) for nid in ids))

    if new_cache:
        _stress_cache.clear()
        _stress_cache.update(new_cache)
        _stress_meta["last_refresh"] = now_ts
        _stress_meta["total"] = len(new_cache)
        _stress_meta["error"] = None
    else:
        _stress_meta["error"] = "no annotations fetched"
    return len(new_cache)


# ── Hourly stress/performance history (upstream only exposes the current 24h-avg) ─────────────
STRESS_HIST_DB = Path("nym_stress_history.db")
STRESS_HIST_RETAIN_DAYS = int(os.environ.get("NYM_STRESS_HIST_RETAIN_DAYS", "8"))

def _stress_hist_init():
    import sqlite3
    conn = sqlite3.connect(str(STRESS_HIST_DB))
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS stress_hist(
            node_id INTEGER, hour TEXT, ts REAL,
            stress REAL, performance REAL, routing REAL, config REAL, role TEXT,
            PRIMARY KEY(node_id, hour))""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sh ON stress_hist(node_id, hour DESC)")
        conn.commit()
    finally:
        conn.close()

def _snapshot_stress_history():
    """Write one row per node for the current UTC hour from the live stress cache."""
    import sqlite3
    from datetime import datetime, timezone
    if not _stress_cache:
        return 0
    now = datetime.now(timezone.utc)
    hour = now.strftime("%Y-%m-%dT%H:00Z")
    ts = now.timestamp()
    rows = [(nid, hour, ts, e.get("stress"), e.get("performance"), e.get("routing"),
             e.get("config"), e.get("role")) for nid, e in _stress_cache.items()]
    conn = sqlite3.connect(str(STRESS_HIST_DB))
    try:
        conn.executemany("""INSERT OR REPLACE INTO stress_hist
            (node_id, hour, ts, stress, performance, routing, config, role)
            VALUES(?,?,?,?,?,?,?,?)""", rows)
        conn.execute("DELETE FROM stress_hist WHERE ts < ?", (ts - STRESS_HIST_RETAIN_DAYS * 86400,))
        conn.commit()
    finally:
        conn.close()
    return len(rows)

def _read_stress_history(node_id, hours=24):
    import sqlite3
    from datetime import datetime, timezone, timedelta
    if not STRESS_HIST_DB.exists():
        return []
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp()
    conn = sqlite3.connect(str(STRESS_HIST_DB))
    try:
        cur = conn.execute("""SELECT hour, stress, performance, routing, config, role
            FROM stress_hist WHERE node_id=? AND ts>=? ORDER BY hour ASC""", (node_id, cutoff))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


@app.get("/api/stress-history/{node_id}")
async def stress_history(node_id: int, hours: int = Query(24, ge=1, le=168)):
    """Hourly stress/performance history for a node (last N hours) — powers the 24-bar view."""
    pts = _read_stress_history(node_id, hours)
    return {"node_id": node_id, "hours": hours, "points": pts, "count": len(pts)}


async def _bg_refresh_stress():
    """Background task: refresh the Nym annotation-score cache every STRESS_REFRESH_SEC,
    and snapshot the scores into the hourly history once per UTC hour."""
    from datetime import datetime, timezone
    await asyncio.sleep(25)  # let the node cache warm first
    _stress_hist_init()
    _last_hist_hour = None
    while True:
        try:
            count = await _fetch_stress()
            print(f"[*] Stress/score cache refreshed: {count} nodes")
            _h = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00Z")
            if _h != _last_hist_hour:
                n = _snapshot_stress_history()
                _last_hist_hour = _h
                print(f"[*] Stress history snapshot: {n} nodes @ {_h}")
        except Exception as e:
            _stress_meta["error"] = str(e)[:200]
            print(f"[!] Stress refresh error: {e}")
        await asyncio.sleep(STRESS_REFRESH_SEC)


async def _fetch_econ_bulk():
    """Background sweep: per-node saturation + total_stake (the SAT/STAKE table columns) via the
    cheap get_node_stake_saturation contract query. Bounded concurrency, like the annotation sweep."""
    import time
    nodes = await _cnodes()
    ids = []
    seen = set()
    for n in nodes:
        nid = n.get("node_id")
        if nid is None or nid in seen:
            continue
        seen.add(nid); ids.append(nid)
    new = {}
    sem = asyncio.Semaphore(ECON_BULK_CONCURRENCY)
    async with httpx.AsyncClient(timeout=20) as client:
        sp = await _saturation_point(client)
        async def one(nid):
            async with sem:
                try:
                    sat, pend = await asyncio.gather(
                        _lcd_smart(client, {"get_node_stake_saturation": {"node_id": nid}}),
                        _lcd_smart(client, {"get_pending_node_operator_reward": {"node_id": nid}}),
                    )
                except Exception:
                    return
                e = {}
                if isinstance(sat, dict):
                    try: e["saturation"] = round(float(sat.get("current_saturation")), 4)
                    except Exception: e["saturation"] = None
                    try: e["total_stake"] = round(float(sat.get("uncapped_saturation")) * sp, 2) if sp else None
                    except Exception: e["total_stake"] = None
                if isinstance(pend, dict):
                    e["owner_reward"] = _unym((pend.get("amount_earned") or {}).get("amount"))
                if e.get("saturation") is not None or e.get("total_stake") is not None or e.get("owner_reward") is not None:
                    new[nid] = e
        await asyncio.gather(*(one(nid) for nid in ids))
    if new:
        _econ_bulk.clear(); _econ_bulk.update(new)
        _econ_bulk_meta["last_refresh"] = time.time(); _econ_bulk_meta["total"] = len(new); _econ_bulk_meta["error"] = None
    return len(new)


async def _bg_refresh_econ_bulk():
    await asyncio.sleep(40)  # let the node cache + saturation point warm first
    while True:
        try:
            count = await _fetch_econ_bulk()
            print(f"[*] Econ-bulk (saturation/stake) refreshed: {count} nodes")
        except Exception as e:
            _econ_bulk_meta["error"] = str(e)[:200]
            print(f"[!] Econ-bulk refresh error: {e}")
        await asyncio.sleep(ECON_BULK_REFRESH_SEC)


def _build_stress_response(node_id):
    """Return a node's Nym-measured scores (stress/routing/config/performance) from the
    validator annotation API. Returns None if not cached (fresh nodes render nothing).
    stress_testing_score is a mixnode metric; for gateways stress_was_reachable is false."""
    if node_id is None:
        return None
    entry = _stress_cache.get(node_id)
    if not entry:
        return None
    return {
        "available": True,
        "node_id": node_id,
        "stress_testing_score": entry.get("stress"),
        "stress_was_reachable": entry.get("stress_reachable"),
        "routing_score": entry.get("routing"),
        "config_score": entry.get("config"),
        "performance_score": entry.get("performance"),
        "source": {
            "provider": "Nym validator annotation API",
            "url": STRESS_ANNOTATION_URL,
        },
    }


# ── Economics / delegation graph (on-chain via Nyx LCD) ───────────────────────
async def _lcd_smart(client, query):
    """Base64 smart-query the mixnet contract; returns the `data` payload or None."""
    import base64
    b = base64.b64encode(json.dumps(query).encode()).decode()
    url = f"{NYM_LCD}/cosmwasm/wasm/v1/contract/{MIXNET_CONTRACT}/smart/{b}"
    try:
        r = await client.get(url, headers={"User-Agent": "nym-checker/1.0"})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    return (r.json() or {}).get("data")


def _unym(v):
    """unym string (may carry a fractional tail) -> NYM float, or None."""
    try:
        return round(int(str(v).split(".")[0]) / UNYM, 6)
    except Exception:
        return None


async def _lcd_balance(client, addr):
    """Liquid unym balance of any address, in NYM, with a short shared cache."""
    if not addr:
        return None
    ent = _bal_cache.get(addr)
    if ent and (time.time() - ent["ts"]) < BAL_TTL:
        return ent["balance"]
    try:
        r = await client.get(f"{NYM_LCD}/cosmos/bank/v1beta1/balances/{addr}")
        bal = 0.0
        if r.status_code == 200:
            for b in (r.json() or {}).get("balances", []):
                if b.get("denom") == "unym":
                    bal = int(b.get("amount", 0)) / UNYM
        _bal_cache[addr] = {"balance": bal, "ts": time.time()}
        return bal
    except Exception:
        return ent["balance"] if ent else None


async def _saturation_point(client):
    """Network stake-saturation point (NYM), cached RP_TTL. Turns a node's saturation
    ratio into an absolute total-stake figure."""
    if _reward_params["saturation_point"] is not None and (time.time() - _reward_params["ts"]) < RP_TTL:
        return _reward_params["saturation_point"]
    rp = await _lcd_smart(client, {"get_rewarding_params": {}})
    if isinstance(rp, dict):
        iv = rp.get("interval") if isinstance(rp.get("interval"), dict) else rp
        sp = _unym(iv.get("stake_saturation_point"))
        if sp:
            _reward_params["saturation_point"] = sp
            _reward_params["ts"] = time.time()
    return _reward_params["saturation_point"]


async def _fetch_node_economics(node_id, owner=None, perf=None):
    """On-chain economics for one node: saturation, this-epoch operator reward,
    accumulated claimable operator reward, owner wallet balance, cost params, DP
    backing. The independent contract queries run concurrently. Cached ECON_TTL."""
    if node_id is None:
        return None
    ent = _econ_cache.get(node_id)
    if ent and (time.time() - ent["ts"]) < ECON_TTL:
        return ent
    try:
        perf_s = f"{float(perf):.4f}" if perf else "1.0"
    except Exception:
        perf_s = "1.0"
    out = {"node_id": node_id, "available": True, "ts": time.time()}
    async with httpx.AsyncClient(timeout=15.0) as client:
        sat, pend, est, rd, bal, sp = await asyncio.gather(
            _lcd_smart(client, {"get_node_stake_saturation": {"node_id": node_id}}),
            _lcd_smart(client, {"get_pending_node_operator_reward": {"node_id": node_id}}),
            _lcd_smart(client, {"get_estimated_current_epoch_operator_reward":
                                {"node_id": node_id, "estimated_performance": perf_s}}),
            _lcd_smart(client, {"get_node_rewarding_details": {"node_id": node_id}}),
            _lcd_balance(client, owner),
            _saturation_point(client),
        )
    if isinstance(sat, dict):
        try: out["saturation"] = round(float(sat.get("current_saturation")), 4)
        except Exception: out["saturation"] = None
        try: out["saturation_uncapped"] = round(float(sat.get("uncapped_saturation")), 4)
        except Exception: pass
    if isinstance(pend, dict):
        out["operator_reward_claimable"] = _unym((pend.get("amount_earned") or {}).get("amount"))
        out["pledge"] = _unym((pend.get("amount_staked") or {}).get("amount"))
        out["fully_bonded"] = pend.get("node_still_fully_bonded")
    if isinstance(est, dict):
        out["reward_per_epoch"] = _unym((est.get("estimation") or {}).get("amount"))
        out["stake_value"] = _unym((est.get("current_stake_value") or {}).get("amount"))
    if isinstance(rd, dict):
        rw = rd.get("rewarding_details") or rd
        cp = rw.get("cost_params") or {}
        try: out["profit_margin"] = round(float(cp.get("profit_margin_percent")), 4)
        except Exception: pass
        out["operating_cost"] = _unym((cp.get("interval_operating_cost") or {}).get("amount"))
        out["unique_delegations"] = rw.get("unique_delegations")
    if owner:
        out["owner"] = owner
        out["owner_balance"] = bal
    if out.get("saturation_uncapped") is not None and sp:
        out["total_stake"] = round(out["saturation_uncapped"] * sp, 6)
    out["dp_backed"] = _dp_backed.get(node_id)
    # typical per-epoch reward: remember the last non-zero estimate (when the node was in the set)
    _rpe = out.get("reward_per_epoch")
    if _rpe and _rpe > 0 and _reward_typical.get(node_id) != _rpe:
        _reward_typical[node_id] = _rpe
        _save_reward_typical()
    out["reward_per_epoch_typical"] = _reward_typical.get(node_id)
    _econ_cache[node_id] = out
    return out


async def _fetch_node_delegations(node_id):
    """Full delegator list for one node, each enriched with wallet balance, portfolio
    size (how many nodes they back) and flags (dp / vesting). Cached DELEG_TTL.
    Per-delegator lookups run under a bounded semaphore (ECON_CONCURRENCY)."""
    if node_id is None:
        return None
    ent = _deleg_cache.get(node_id)
    if ent and (time.time() - ent["ts"]) < DELEG_TTL:
        return ent
    out = {"node_id": node_id, "ts": time.time(), "delegations": [], "count": 0}
    async with httpx.AsyncClient(timeout=15.0) as client:
        d = await _lcd_smart(client, {"get_node_delegations": {"node_id": node_id}})
        rows = (d or {}).get("delegations", []) if isinstance(d, dict) else (d or [])
        sem = asyncio.Semaphore(ECON_CONCURRENCY)

        async def enrich(x):
            addr = x.get("owner")
            rec = {"address": addr,
                   "amount": _unym((x.get("amount") or {}).get("amount")),
                   "height": x.get("height"),
                   "vesting": bool(x.get("proxy")),
                   "is_dp": addr == NYM_DP_WALLET}
            async with sem:
                bal, port = await asyncio.gather(
                    _lcd_balance(client, addr),
                    _lcd_smart(client, {"get_delegator_delegations": {"delegator": addr, "limit": 200}}),
                )
            rec["balance"] = bal
            pl = (port or {}).get("delegations", []) if isinstance(port, dict) else (port or [])
            rec["portfolio_nodes"] = len(pl)
            rec["portfolio_capped"] = len(pl) >= 200
            if rec["is_dp"] and _dp_meta.get("nodes"):
                rec["portfolio_nodes"] = _dp_meta["nodes"]
                rec["portfolio_capped"] = False
            return rec

        recs = list(await asyncio.gather(*(enrich(x) for x in rows)))
    recs.sort(key=lambda r: (r.get("amount") or 0), reverse=True)
    out["delegations"] = recs
    out["count"] = len(recs)
    out["total_delegated"] = round(sum(r.get("amount") or 0 for r in recs), 6)
    _deleg_cache[node_id] = out
    return out


async def _fetch_dp_backed():
    """Paginate the Nym DP/team wallet's delegation portfolio -> {node_id: NYM} so every
    node can be flagged DP-backed. One wallet, cheap; refreshed hourly."""
    backed = {}
    total = 0.0
    async with httpx.AsyncClient(timeout=20.0) as client:
        after = None
        for _ in range(30):
            q = {"get_delegator_delegations": {"delegator": NYM_DP_WALLET, "limit": 200}}
            if after:
                q["get_delegator_delegations"]["start_after"] = after
            d = await _lcd_smart(client, q)
            if not isinstance(d, dict):
                break
            rows = d.get("delegations", [])
            for x in rows:
                nid = x.get("node_id")
                if nid is not None:
                    amt = _unym((x.get("amount") or {}).get("amount")) or 0
                    backed[nid] = amt
                    total += amt
            after = d.get("start_next_after")
            if not after or not rows:
                break
    if backed:
        _dp_backed.clear()
        _dp_backed.update(backed)
        _dp_meta["last_refresh"] = time.time()
        _dp_meta["nodes"] = len(backed)
        _dp_meta["total_nym"] = round(total, 6)
    return len(backed)


async def _bg_refresh_dp():
    """Background task: refresh the DP-backing map every DP_REFRESH_SEC."""
    await asyncio.sleep(35)  # let the node cache warm first
    while True:
        try:
            n = await _fetch_dp_backed()
            print(f"[*] DP-backing map refreshed: {n} nodes, {_dp_meta['total_nym']:.0f} NYM")
        except Exception as e:
            print(f"[!] DP refresh error: {e}")
        await asyncio.sleep(DP_REFRESH_SEC)


# ── Wallet explorer (balance + delegations + rewards + categorized tx history) ─
def _sum_coins(coins):
    """Sum the unym amount across a coins array -> NYM float, or None."""
    t = 0
    for c in coins or []:
        if isinstance(c, dict) and c.get("denom") == "unym":
            try: t += int(c.get("amount", 0))
            except Exception: pass
    return round(t / UNYM, 6) if t else None


def _tx_received_unym(tr, address):
    """Sum unym transferred TO `address` in a tx (undelegate/withdraw payouts) from events."""
    total = 0
    def scan(events):
        nonlocal total
        for ev in events or []:
            if ev.get("type") != "transfer":
                continue
            cur = None
            for a in ev.get("attributes") or []:
                k, v = a.get("key"), a.get("value")
                if k == "recipient":
                    cur = v
                elif k == "amount" and cur == address and v:
                    for part in str(v).split(","):
                        part = part.strip()
                        if part.endswith("unym"):
                            try: total += int(part[:-4])
                            except Exception: pass
    scan(tr.get("events"))
    for lg in tr.get("logs") or []:
        scan(lg.get("events"))
    return round(total / UNYM, 6) if total else None


def _parse_tx(tr, address):
    """Classify one tx_response for `address` into delegate/undelegate/withdraw/send/…"""
    msgs = ((tr.get("tx") or {}).get("body") or {}).get("messages", []) or []
    m = msgs[0] if msgs else {}
    ty = m.get("@type", "")
    typ, node_id, amount, cp = "other", None, None, None
    if "MsgExecuteContract" in ty:
        mm = m.get("msg") if isinstance(m.get("msg"), dict) else {}
        key = next(iter(mm.keys()), "") if mm else ""
        inner = mm.get(key) if isinstance(mm.get(key), dict) else {}
        node_id = inner.get("node_id") or inner.get("mix_id")
        funds = m.get("funds") or []
        if key == "delegate":
            typ, amount = "delegate", _sum_coins(funds)
        elif key == "undelegate":
            typ, amount = "undelegate", _tx_received_unym(tr, address)
        elif "withdraw" in key:
            typ, amount = "withdraw_reward", _tx_received_unym(tr, address)
        elif key.startswith("bond"):
            typ, amount = "bond", _sum_coins(funds)
        elif key.startswith("unbond"):
            typ, amount = "unbond", _tx_received_unym(tr, address)
        elif key.startswith("update_"):
            typ = "config"
        elif key.startswith("migrate"):
            typ = "migrate"
        else:
            typ = key or "exec"
    elif ty.endswith("MsgSend"):
        amount = _sum_coins(m.get("amount") or [])
        if m.get("from_address") == address:
            typ, cp = "send", m.get("to_address")
        else:
            typ, cp = "receive", m.get("from_address")
    elif "MsgWithdrawDelegatorReward" in ty or "MsgWithdrawValidatorCommission" in ty:
        typ, amount = "staking_reward", _tx_received_unym(tr, address)
    elif "MsgDelegate" in ty:
        typ, amount = "stake_delegate", _sum_coins([m.get("amount")] if m.get("amount") else [])
    else:
        typ = ty.split(".")[-1] or "other"
    return {"hash": tr.get("txhash"), "height": int(tr.get("height", 0) or 0),
            "time": tr.get("timestamp"), "type": typ, "node_id": node_id,
            "amount": amount, "counterparty": cp, "success": (int(tr.get("code", 0) or 0) == 0)}


async def _fetch_wallet_txs(client, address, limit):
    """Recent txs where `address` is sender OR recipient, de-duped and classified."""
    seen, rows = set(), []
    async def q(query):
        try:
            r = await client.get(f"{NYM_LCD}/cosmos/tx/v1beta1/txs",
                                 params={"query": query, "order_by": "ORDER_BY_DESC",
                                         "pagination.limit": str(limit)})
            if r.status_code != 200:
                return []
            return (r.json() or {}).get("tx_responses", []) or []
        except Exception:
            return []
    out_tx, in_tx = await asyncio.gather(
        q(f"message.sender='{address}'"),
        q(f"transfer.recipient='{address}'"),
    )
    for tr in list(out_tx) + list(in_tx):
        h = tr.get("txhash")
        if not h or h in seen:
            continue
        seen.add(h)
        try:
            rows.append(_parse_tx(tr, address))
        except Exception:
            continue
    rows.sort(key=lambda t: t.get("height", 0), reverse=True)
    return rows[:limit]


# ── Full tx-history indexer (archive RPC → SQLite) ────────────────────────────
def _height_to_time(height):
    """Approx UTC ISO timestamp for a block height via piecewise-linear interpolation
    over the measured anchors (archive RPC tx_search carries height but no block time)."""
    from datetime import datetime, timezone
    a = _HEIGHT_ANCHORS
    if not a or not height:
        return None
    if height <= a[0][0]:
        (h0, t0), (h1, t1) = a[0], a[1]
    elif height >= a[-1][0]:
        (h0, t0), (h1, t1) = a[-2], a[-1]
    else:
        h0 = None
        for i in range(1, len(a)):
            if height <= a[i][0]:
                (h0, t0), (h1, t1) = a[i - 1], a[i]
                break
        if h0 is None:
            return None
    if h1 == h0:
        return None
    ep = t0 + (height - h0) * (t1 - t0) / (h1 - h0)
    return datetime.fromtimestamp(ep, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _amt_unym(s):
    """Leading-integer part of a '123unym' coin string -> NYM float, or None."""
    try:
        num = ""
        for ch in str(s):
            if ch.isdigit():
                num += ch
            else:
                break
        return round(int(num) / UNYM, 6) if num else None
    except Exception:
        return None


async def _rpc_tx_search(client, query, page, per_page=100):
    """Tendermint /tx_search on the archive node (paginates properly, unlike the LCD)."""
    import urllib.parse
    url = (NYM_RPC_ARCHIVE + "/tx_search?query=" + urllib.parse.quote('"' + query + '"')
           + f"&per_page={per_page}&page={page}&order_by=" + urllib.parse.quote('"desc"'))
    try:
        r = await client.get(url, timeout=25)
        if r.status_code != 200:
            return None
        return (r.json() or {}).get("result") or {}
    except Exception:
        return None


def _parse_rpc_tx(t, address):
    """Classify an archive-RPC tx from its events: the wasm-* event names the action, the
    transfer event carrying a msg_index gives the amount/direction."""
    tr = t.get("tx_result") or {}
    success = 1 if tr.get("code", 0) in (0, None) else 0
    action = None; wasm = []; nid = None; amt = None; to = None; frm = None
    for e in (tr.get("events") or []):
        ty = e.get("type", "")
        attrs = {a.get("key"): a.get("value") for a in (e.get("attributes") or [])}
        if ty == "message" and attrs.get("action"):
            action = attrs["action"].split(".")[-1]
        if ty.startswith("wasm"):
            wasm.append(ty)
            for k, v in attrs.items():
                if "node_id" in k and nid is None:
                    try: nid = int(v)
                    except Exception: pass
        if ty == "transfer" and attrs.get("msg_index") is not None:
            amt = _amt_unym(attrs.get("amount")); to = attrs.get("recipient"); frm = attrs.get("sender")
    wj = " ".join(wasm)
    typ = "other"; direction = None; amount = None; cp = None
    if "pending_delegation" in wj:
        typ, direction, amount, cp = "delegate", "out", amt, "contract"
    elif "pending_undelegation" in wj:
        typ, direction, amount = "undelegate", "in", amt
    elif "withdraw_operator_reward" in wj or "withdraw_delegator_reward" in wj:
        typ, direction, amount = "withdraw_reward", "in", amt
    elif "cost_params_update" in wj:
        typ = "cost_update"
    elif "family" in wj:
        typ = "family"
    elif "bond" in wj:
        typ, amount = "bond", amt
    elif action == "MsgSend":
        if to == address:
            typ, direction, amount, cp = "receive", "in", amt, frm
        else:
            typ, direction, amount, cp = "send", "out", amt, to
    elif action == "MsgWithdrawDelegatorReward":
        typ, direction, amount = "staking_reward", "in", amt
    try: h = int(t.get("height"))
    except Exception: h = 0
    return {"hash": t.get("hash"), "height": h, "type": typ, "node_id": nid,
            "amount": amount, "counterparty": cp, "direction": direction, "success": success}


def _txdb_init():
    import sqlite3
    conn = sqlite3.connect(str(TXDB))
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS wallet_txs(
            address TEXT, hash TEXT, height INTEGER, time TEXT, type TEXT, node_id INTEGER,
            amount REAL, counterparty TEXT, direction TEXT, success INTEGER,
            PRIMARY KEY(address, hash))""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wtx ON wallet_txs(address, height DESC)")
        conn.execute("CREATE TABLE IF NOT EXISTS tx_index_state(address TEXT PRIMARY KEY, ts REAL, total INTEGER)")
        conn.commit()
    finally:
        conn.close()


async def _index_wallet(address, full=True):
    """Backfill (full) or tail (page 1 only) a wallet's tx history from the archive RPC into
    SQLite. Indexes both directions (message.sender + transfer.recipient), deduped by hash."""
    rows = {}
    async with httpx.AsyncClient(timeout=25.0) as client:
        for q in (f"message.sender='{address}'", f"transfer.recipient='{address}'"):
            page = 1
            while page <= TX_INDEX_MAX_PAGES:
                res = await _rpc_tx_search(client, q, page)
                if not res:
                    break
                txs = res.get("txs") or []
                for t in txs:
                    r = _parse_rpc_tx(t, address)
                    if r.get("hash"):
                        rows[r["hash"]] = r
                total = int(res.get("total_count") or 0)
                if not full or not txs or page * 100 >= total:
                    break
                page += 1
    for r in rows.values():
        r["time"] = _height_to_time(r["height"])
    import sqlite3
    conn = sqlite3.connect(str(TXDB))
    try:
        conn.executemany("""INSERT OR REPLACE INTO wallet_txs
            (address, hash, height, time, type, node_id, amount, counterparty, direction, success)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(address, r["hash"], r["height"], r.get("time"), r["type"], r["node_id"],
              r["amount"], r["counterparty"], r["direction"], r["success"]) for r in rows.values()])
        tot = conn.execute("SELECT COUNT(*) FROM wallet_txs WHERE address=?", (address,)).fetchone()[0]
        conn.execute("INSERT OR REPLACE INTO tx_index_state(address, ts, total) VALUES(?,?,?)",
                     (address, time.time(), tot))
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def _read_wallet_txs(address, limit):
    import sqlite3
    conn = sqlite3.connect(str(TXDB))
    try:
        cur = conn.execute("""SELECT hash, height, time, type, node_id, amount, counterparty, direction, success
            FROM wallet_txs WHERE address=? ORDER BY height DESC LIMIT ?""", (address, limit))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def _tx_index_state(address):
    import sqlite3
    if not TXDB.exists():
        return None
    conn = sqlite3.connect(str(TXDB))
    try:
        r = conn.execute("SELECT ts, total FROM tx_index_state WHERE address=?", (address,)).fetchone()
        return {"ts": r[0], "total": r[1]} if r else None
    finally:
        conn.close()


async def _fetch_wallet(address):
    """Full wallet view: balance, delegations (with node monikers), operated nodes,
    pending operator reward, and categorized tx history. Cached WALLET_TTL."""
    ent = _wallet_cache.get(address)
    if ent and (time.time() - ent["ts"]) < WALLET_TTL:
        return ent
    out = {"address": address, "available": True, "ts": time.time(),
           "is_dp": address == NYM_DP_WALLET}
    nodes = await _cnodes()
    by_id = {n.get("node_id"): n for n in nodes}
    async with httpx.AsyncClient(timeout=20.0) as client:
        bal_task = _lcd_balance(client, address)
        # delegations by this wallet (paged)
        dels, after = [], None
        for _ in range(10):
            qd = {"get_delegator_delegations": {"delegator": address, "limit": 200}}
            if after:
                qd["get_delegator_delegations"]["start_after"] = after
            d = await _lcd_smart(client, qd)
            if not isinstance(d, dict):
                break
            page = d.get("delegations", [])
            dels.extend(page)
            after = d.get("start_next_after")
            if not after or not page:
                break
        out["balance"] = await bal_task
        out["txs"] = None  # tx history is loaded lazily via /api/wallet/{addr}/txs
        # enrich delegations with node moniker/ip
        deleg, tot = [], 0.0
        for x in dels:
            nid = x.get("node_id")
            amt = _unym((x.get("amount") or {}).get("amount")) or 0
            tot += amt
            n = by_id.get(nid) or {}
            deleg.append({"node_id": nid, "amount": amt, "moniker": n.get("moniker"),
                          "ip": n.get("ip"), "vesting": bool(x.get("proxy"))})
        deleg.sort(key=lambda r: r["amount"], reverse=True)
        out["delegations"] = deleg
        out["delegations_count"] = len(deleg)
        out["delegations_total"] = round(tot, 6)
        # per-delegation pending delegator reward (capped so big wallets stay cheap)
        if deleg and len(deleg) <= WALLET_REWARD_MAX:
            _sem = asyncio.Semaphore(ECON_CONCURRENCY)
            async def _drew(nid):
                async with _sem:
                    pr = await _lcd_smart(client, {"get_pending_delegator_reward": {"address": address, "node_id": nid}})
                return _unym((pr.get("amount_earned") or {}).get("amount")) if isinstance(pr, dict) else None
            drews = await asyncio.gather(*[_drew(d["node_id"]) for d in deleg])
            dg_pend = 0.0
            for d, r in zip(deleg, drews):
                d["reward"] = r
                dg_pend += r or 0
            out["pending_delegator_reward"] = round(dg_pend, 6)
        else:
            out["pending_delegator_reward"] = None  # too many delegations to price each row
        # nodes this wallet OWNS (operator), each with its pending operator reward
        owned = [{"node_id": n.get("node_id"), "moniker": n.get("moniker"), "ip": n.get("ip"),
                  "mode": n.get("mode")} for n in nodes if n.get("owner") == address]
        out["operator_of"] = owned
        op_pend = 0.0
        if owned:
            prs = await asyncio.gather(*[
                _lcd_smart(client, {"get_pending_node_operator_reward": {"node_id": o["node_id"]}})
                for o in owned])
            for o, pr in zip(owned, prs):
                r = _unym((pr.get("amount_earned") or {}).get("amount")) if isinstance(pr, dict) else None
                o["reward"] = r
                op_pend += r or 0
        out["pending_operator_reward"] = round(op_pend, 6)
        # combined pending reward across both roles — the top-line figure
        if out.get("pending_delegator_reward") is None:
            out["pending_reward_total"] = None
            out["rewards_partial"] = True
        else:
            out["pending_reward_total"] = round((out.get("pending_operator_reward") or 0) + (out.get("pending_delegator_reward") or 0), 6)
    _wallet_cache[address] = out
    return out


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
    uvicorn.run(app,host="127.0.0.1",port=8000)
