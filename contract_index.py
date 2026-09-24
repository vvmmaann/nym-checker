#!/usr/bin/env python3
"""Tail the chain for mixnet-contract actions, keyed by node_id AND owner.

node_id lives in the tx BODY, not in an indexed event, so you cannot tx_search by node - which is
why a node's delegation history was invisible while a wallet's was not. But `tx.height` IS always
indexed and Nyx is quiet (~5.5k txs/day), so we simply read new blocks since the last run and
decode the bodies. One table serves both the node view and the wallet view. No backfill: history
starts the day this runs.
"""
import base64, json, os, re, sqlite3, time, urllib.parse, urllib.request

RPC = os.environ.get("NYM_RPC_ARCHIVE", "https://rpc.nyx.nodes.guru")
DB = os.environ.get("NYM_CTX_DB", "/opt/nym-checker/nym_contract_txs.db")
UA = {"User-Agent": "curl/8"}
# whole-word actions we care about, as they appear in the JSON msg inside the tx body
ACT = re.compile(r'\{"(delegate|undelegate|bond_nym_node|unbond_nym_node|pledge_more|'
                 r'decrease_pledge|update_node_config|update_cost_params)"')
NID = re.compile(r'"(?:node_id|mix_id)":\s*(\d+)')


def _j(url, timeout=45):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout))


def search(query, page, per=100):
    u = (RPC + "/tx_search?query=" + urllib.parse.quote('"' + query + '"')
         + "&per_page=%d&page=%d&order_by=%s" % (per, page, urllib.parse.quote('"asc"')))
    for i in range(3):
        try:
            return _j(u).get("result") or {}
        except Exception:
            time.sleep(2 * (i + 1))
    return None


def latest_height():
    return int(_j(RPC + "/status", 20)["result"]["sync_info"]["latest_block_height"])


def parse(t):
    try:
        blob = base64.b64decode(t.get("tx") or "").decode("utf-8", "ignore")
    except Exception:
        return None
    a = ACT.search(blob)
    if not a:
        return None
    kind = a.group(1)
    m = NID.search(blob)
    nid = int(m.group(1)) if m else None
    tr = t.get("tx_result") or {}
    owner = None
    amount = None
    for e in (tr.get("events") or []):
        at = {x.get("key"): x.get("value") for x in (e.get("attributes") or [])}
        if e.get("type") == "message" and at.get("sender") and not owner:
            owner = at["sender"]
        if e.get("type") == "transfer" and (at.get("amount") or "").endswith("unym"):
            v = int(at["amount"].replace("unym", "") or 0)
            amount = v if amount is None else max(amount, v)
    return dict(hash=t.get("hash"), height=int(t.get("height") or 0), kind=kind,
                node_id=nid, owner=owner, amount=amount,
                success=1 if (tr.get("code") or 0) == 0 else 0)


def init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS ctx(
        hash TEXT PRIMARY KEY, height INTEGER, ts REAL, iso TEXT, kind TEXT,
        node_id INTEGER, owner TEXT, amount INTEGER, success INTEGER)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ctx_node ON ctx(node_id, height DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ctx_owner ON ctx(owner, height DESC)")
    c.execute("CREATE TABLE IF NOT EXISTS ctx_meta(k TEXT PRIMARY KEY, v TEXT)")


def meta(c, k, v=None):
    if v is None:
        r = c.execute("SELECT v FROM ctx_meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None
    c.execute("INSERT OR REPLACE INTO ctx_meta(k,v) VALUES(?,?)", (k, str(v)))


def main():
    conn = sqlite3.connect(DB); init(conn)
    top = latest_height()
    last = meta(conn, "last_height")
    start = int(last) + 1 if last else top - 2000      # first run: just the last ~3 hours
    if start > top:
        print("nothing new (height %d)" % top); return
    q = "tx.height>=%d AND tx.height<=%d" % (start, top)
    page, stored, scanned = 1, 0, 0
    now = time.time()
    while True:
        res = search(q, page)
        if not res:
            break
        txs = res.get("txs") or []
        tot = int(res.get("total_count") or 0)
        if not txs:
            break
        rows = []
        for t in txs:
            scanned += 1
            r = parse(t)
            if r:
                rows.append((r["hash"], r["height"], now,
                             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                             r["kind"], r["node_id"], r["owner"], r["amount"], r["success"]))
        if rows:
            conn.executemany("INSERT OR IGNORE INTO ctx VALUES(?,?,?,?,?,?,?,?,?)", rows)
            stored += len(rows)
        if page * 100 >= tot:
            break
        page += 1
    meta(conn, "last_height", top)
    conn.commit()
    print("heights %d..%d  scanned=%d  stored=%d" % (start, top, scanned, stored))
    for k, n in conn.execute("SELECT kind,COUNT(*) FROM ctx GROUP BY kind ORDER BY 2 DESC"):
        print("   %-22s %d" % (k, n))
    conn.close()


if __name__ == "__main__":
    main()
