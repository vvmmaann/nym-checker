#!/usr/bin/env python3
"""Tail the chain for mixnet-contract actions, keyed by node_id AND owner.

node_id lives in the tx BODY, not in an indexed event, so you cannot tx_search by node - which is
why a node's delegation history was invisible while a wallet's was not. But `tx.height` IS always
indexed and Nyx is quiet (~5.5k txs/day), so we read new blocks since the last run, pick the txs
that touch the mixnet contract, and decode them through the LCD.

One row per MESSAGE (a tx may delegate to several nodes at once), with the real block time and
the amount from that message itself (funds, or decrease_by). v1 stored one row per tx with the
first action, the first node_id and the largest transfer, and the indexing time as the tx time.
"""
import base64, json, os, re, sqlite3, time, urllib.parse, urllib.request

RPC = os.environ.get("NYM_RPC_ARCHIVE", "https://rpc.nyx.nodes.guru")
LCD = os.environ.get("NYM_LCD_DECODE", "https://api.nyx.nodes.guru")
MIXNET = os.environ.get("NYM_MIXNET_CONTRACT", "n17srjznxl9dvzdkpwpw24gg668wc73val88a6m5ajg6ankwvz9wtst0cznr")
DB = os.environ.get("NYM_CTX_DB", "/opt/nym-checker/nym_contract_txs.db")
UA = {"User-Agent": "curl/8"}
KINDS = ("delegate", "undelegate", "bond_nym_node", "unbond_nym_node", "pledge_more",
         "decrease_pledge", "update_node_config", "update_cost_params")
# cheap pre-filter on the raw tx bytes before paying for an LCD decode
ACT = re.compile(r'\{"(' + "|".join(KINDS) + r')"')


def _j(url, timeout=45):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout))


def _retry(fn, *a):
    for i in range(3):
        try:
            return fn(*a)
        except Exception:
            time.sleep(2 * (i + 1))
    return None


def search(query, page, per=100):
    u = (RPC + "/tx_search?query=" + urllib.parse.quote('"' + query + '"')
         + "&per_page=%d&page=%d&order_by=%s" % (per, page, urllib.parse.quote('"asc"')))
    r = _retry(_j, u)
    return (r or {}).get("result") if r else None


def latest_height():
    return int(_j(RPC + "/status", 20)["result"]["sync_info"]["latest_block_height"])


_times = {}


def block_time(h):
    if h not in _times:
        r = _retry(_j, RPC + "/header?height=%d" % h, 20)
        ts = (((r or {}).get("result") or {}).get("header") or {}).get("time")
        _times[h] = ts[:19] + "Z" if ts else None
    return _times[h]


def _unym(coins):
    return sum(int(c.get("amount") or 0) for c in (coins or []) if c.get("denom") == "unym") or None


def _walk(msgs):
    """Yield (msg_index, sender, action, body, funds) for every mixnet-contract execute,
    including ones wrapped in authz MsgExec (they share the outer message's index)."""
    for i, m in enumerate(msgs or []):
        ty = (m.get("@type") or "").split(".")[-1]
        if ty == "MsgExec":
            for _, snd, act, body, funds in _walk(m.get("msgs")):
                yield i, snd, act, body, funds
            continue
        if ty != "MsgExecuteContract" or m.get("contract") != MIXNET:
            continue
        body = m.get("msg")
        if isinstance(body, str):
            try:
                body = json.loads(base64.b64decode(body))
            except Exception:
                body = {}
        if not isinstance(body, dict) or len(body) != 1:
            continue
        act = next(iter(body))
        if act in KINDS:
            yield i, m.get("sender"), act, body.get(act) or {}, m.get("funds")


def parse(t):
    """Rows for one candidate tx, or [] if it does not touch the mixnet contract."""
    try:
        blob = base64.b64decode(t.get("tx") or "").decode("utf-8", "ignore")
    except Exception:
        return []
    if not ACT.search(blob):
        return []
    d = _retry(_j, LCD + "/cosmos/tx/v1beta1/txs/" + t["hash"])
    if not d:
        return None                       # decode failed: caller must not advance past this height
    tx, tr = d.get("tx") or {}, d.get("tx_response") or {}
    h = int(t.get("height") or 0)
    iso = block_time(h)
    ok = 1 if (tr.get("code") or 0) == 0 else 0
    rows = []
    for i, snd, act, body, funds in _walk((tx.get("body") or {}).get("messages")):
        nid = body.get("node_id", body.get("mix_id")) if isinstance(body, dict) else None
        if act == "decrease_pledge":
            amount = _unym([body.get("decrease_by") or {}])
        elif act in ("delegate", "pledge_more", "bond_nym_node"):
            amount = _unym(funds)
        else:
            amount = None                 # undelegate/unbond pay out at the epoch boundary
        rows.append(dict(hash=t["hash"], msg_index=i, height=h, iso=iso, kind=act,
                         node_id=int(nid) if nid is not None else None, owner=snd, amount=amount, success=ok))
    return rows


def init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS ctx2(
        hash TEXT, msg_index INTEGER, height INTEGER, ts REAL, iso TEXT, kind TEXT,
        node_id INTEGER, owner TEXT, amount INTEGER, success INTEGER,
        PRIMARY KEY(hash, msg_index))""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ctx2_node ON ctx2(node_id, height DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ctx2_owner ON ctx2(owner, height DESC)")
    c.execute("CREATE TABLE IF NOT EXISTS ctx_meta(k TEXT PRIMARY KEY, v TEXT)")


def meta(c, k, v=None):
    if v is None:
        r = c.execute("SELECT v FROM ctx_meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None
    c.execute("INSERT OR REPLACE INTO ctx_meta(k,v) VALUES(?,?)", (k, str(v)))


def _epoch(iso):
    try:
        return time.mktime(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except Exception:
        return None


def main():
    conn = sqlite3.connect(DB); init(conn)
    top = latest_height()
    last = meta(conn, "last_height_v2")
    if last is None:
        # first v2 run: rebuild from where v1 history starts
        r = conn.execute("SELECT MIN(height) FROM ctx").fetchone() if conn.execute(
            "SELECT name FROM sqlite_master WHERE name='ctx'").fetchone() else None
        start = (r[0] if r and r[0] else top - 2000)
    else:
        start = int(last) + 1
    if start > top:
        print("nothing new (height %d)" % top); return
    end = min(top, start + 20000)        # bounded chunk per run; the timer catches up
    q = "tx.height>=%d AND tx.height<=%d" % (start, end)
    page, stored, scanned = 1, 0, 0
    while True:
        res = search(q, page)
        if res is None:
            print("search failed; not advancing"); conn.close(); return
        txs = res.get("txs") or []
        tot = int(res.get("total_count") or 0)
        if not txs:
            break
        rows = []
        for t in txs:
            scanned += 1
            r = parse(t)
            if r is None:
                print("decode failed for %s; not advancing" % t.get("hash")); conn.commit(); conn.close(); return
            rows.extend(r)
        if rows:
            conn.executemany("INSERT OR REPLACE INTO ctx2 VALUES(?,?,?,?,?,?,?,?,?,?)",
                             [(r["hash"], r["msg_index"], r["height"], _epoch(r["iso"]) if r["iso"] else None, r["iso"],
                               r["kind"], r["node_id"], r["owner"], r["amount"], r["success"]) for r in rows])
            stored += len(rows)
        if page * 100 >= tot:
            break
        page += 1
    meta(conn, "last_height_v2", end)
    conn.commit()
    print("heights %d..%d  scanned=%d  stored=%d" % (start, end, scanned, stored))
    for k, n in conn.execute("SELECT kind,COUNT(*) FROM ctx2 GROUP BY kind ORDER BY 2 DESC"):
        print("   %-22s %d" % (k, n))
    conn.close()


if __name__ == "__main__":
    main()
