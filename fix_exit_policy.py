path = "/opt/nym-checker/nym_checker_backend.py"
with open(path, "r") as f:
    content = f.read()

# 1. Replace the EXIT_POLICY_PORTS and ck_exit_policy with a simpler declared approach
old_block = """# ── Exit Policy Ports (key outbound ports to verify on exit gateways) ──
EXIT_POLICY_PORTS = [
    {"port": 53, "proto": "tcp", "desc": "DNS"},
    {"port": 80, "proto": "tcp", "desc": "HTTP"},
    {"port": 443, "proto": "tcp", "desc": "HTTPS"},
    {"port": 22, "proto": "tcp", "desc": "SSH"},
    {"port": 587, "proto": "tcp", "desc": "SMTP"},
    {"port": 143, "proto": "tcp", "desc": "IMAP"},
    {"port": 8332, "proto": "tcp", "desc": "Bitcoin"},
    {"port": 9001, "proto": "tcp", "desc": "Tor"},
]"""

new_block = """# ── Exit Policy (standard Nym exit policy ports) ──
EXIT_POLICY_PORTS = [
    {"port": 20, "proto": "tcp", "desc": "FTP Data"},
    {"port": 21, "proto": "tcp", "desc": "FTP"},
    {"port": 22, "proto": "tcp", "desc": "SSH"},
    {"port": 43, "proto": "tcp", "desc": "WHOIS"},
    {"port": 53, "proto": "tcp", "desc": "DNS"},
    {"port": 79, "proto": "tcp", "desc": "Finger"},
    {"port": 80, "proto": "tcp", "desc": "HTTP"},
    {"port": 81, "proto": "tcp", "desc": "HTTP Alt"},
    {"port": 88, "proto": "tcp", "desc": "Kerberos"},
    {"port": 110, "proto": "tcp", "desc": "POP3"},
    {"port": 119, "proto": "tcp", "desc": "NNTP"},
    {"port": 123, "proto": "tcp", "desc": "NTP"},
    {"port": 143, "proto": "tcp", "desc": "IMAP"},
    {"port": 220, "proto": "tcp", "desc": "IMAP3"},
    {"port": 389, "proto": "tcp", "desc": "LDAP"},
    {"port": 443, "proto": "tcp", "desc": "HTTPS"},
    {"port": 465, "proto": "tcp", "desc": "SMTP/SSL"},
    {"port": 587, "proto": "tcp", "desc": "SMTP"},
    {"port": 636, "proto": "tcp", "desc": "LDAPS"},
    {"port": 853, "proto": "tcp", "desc": "DNS/TLS"},
    {"port": 873, "proto": "tcp", "desc": "rsync"},
    {"port": 993, "proto": "tcp", "desc": "IMAPS"},
    {"port": 995, "proto": "tcp", "desc": "POP3S"},
    {"port": 1119, "proto": "tcp", "desc": "Battle.net"},
    {"port": 1120, "proto": "tcp", "desc": "Battle.net"},
    {"port": 1194, "proto": "tcp", "desc": "OpenVPN"},
    {"port": 3074, "proto": "tcp", "desc": "Xbox Live"},
    {"port": 3333, "proto": "tcp", "desc": "Mining"},
    {"port": 3478, "proto": "tcp", "desc": "STUN"},
    {"port": 3479, "proto": "tcp", "desc": "STUN"},
    {"port": 3480, "proto": "tcp", "desc": "STUN"},
    {"port": 3481, "proto": "tcp", "desc": "STUN"},
    {"port": 3482, "proto": "tcp", "desc": "STUN"},
    {"port": 3483, "proto": "tcp", "desc": "STUN"},
    {"port": 3484, "proto": "tcp", "desc": "STUN"},
    {"port": 3690, "proto": "tcp", "desc": "SVN"},
    {"port": 3724, "proto": "tcp", "desc": "WoW"},
    {"port": 4000, "proto": "tcp", "desc": "Diablo"},
    {"port": 4444, "proto": "tcp", "desc": "Monero"},
    {"port": 5190, "proto": "tcp", "desc": "ICQ/AIM"},
    {"port": 5222, "proto": "tcp", "desc": "XMPP"},
    {"port": 5223, "proto": "tcp", "desc": "XMPP/SSL"},
    {"port": 6012, "proto": "tcp", "desc": "Gaming"},
    {"port": 6112, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6113, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6114, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6115, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6116, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6117, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6118, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6119, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6120, "proto": "tcp", "desc": "Battle.net"},
    {"port": 6250, "proto": "tcp", "desc": "Gaming"},
    {"port": 8008, "proto": "tcp", "desc": "HTTP Alt"},
    {"port": 8080, "proto": "tcp", "desc": "HTTP Proxy"},
    {"port": 8085, "proto": "tcp", "desc": "Gaming"},
    {"port": 8087, "proto": "tcp", "desc": "HTTP Alt"},
    {"port": 8088, "proto": "tcp", "desc": "HTTP Alt"},
    {"port": 8232, "proto": "tcp", "desc": "Zcash"},
    {"port": 8233, "proto": "tcp", "desc": "Zcash"},
    {"port": 8332, "proto": "tcp", "desc": "Bitcoin"},
    {"port": 8333, "proto": "tcp", "desc": "Bitcoin"},
    {"port": 8443, "proto": "tcp", "desc": "HTTPS Alt"},
    {"port": 8767, "proto": "tcp", "desc": "TeamSpeak"},
    {"port": 9001, "proto": "tcp", "desc": "Tor"},
    {"port": 9030, "proto": "tcp", "desc": "Tor Dir"},
    {"port": 9418, "proto": "tcp", "desc": "Git"},
    {"port": 9443, "proto": "tcp", "desc": "HTTPS Alt"},
    {"port": 9735, "proto": "tcp", "desc": "Lightning"},
    {"port": 18080, "proto": "tcp", "desc": "Monero"},
    {"port": 18081, "proto": "tcp", "desc": "Monero RPC"},
    {"port": 18082, "proto": "tcp", "desc": "Monero"},
    {"port": 18083, "proto": "tcp", "desc": "Monero"},
    {"port": 18084, "proto": "tcp", "desc": "Monero"},
    {"port": 18085, "proto": "tcp", "desc": "Monero"},
    {"port": 18086, "proto": "tcp", "desc": "Monero"},
    {"port": 18087, "proto": "tcp", "desc": "Monero"},
    {"port": 18088, "proto": "tcp", "desc": "Monero"},
    {"port": 18089, "proto": "tcp", "desc": "Monero"},
    {"port": 50002, "proto": "tcp", "desc": "Electrum"},
    {"port": 64738, "proto": "tcp", "desc": "Mumble"},
]"""

content = content.replace(old_block, new_block, 1)
print("1. Replaced EXIT_POLICY_PORTS with full list")

# 2. Remove the ck_exit_policy function entirely and replace with simple declared check
old_func = '''async def ck_exit_policy(host, ports, timeout=4.0):
    \"\"\"Check if exit gateway can reach external services on key ports.
    We connect to the node and ask it to proxy/resolve outbound.
    Simplest approach: try connecting FROM the node perspective by
    checking if common external services are reachable through it.
    Since we can't route through mixnet here, we test if the node's
    network allows outbound on these ports by probing well-known
    endpoints from our checker (as a proxy indicator).
    For a true test, we'd need to send traffic through the mixnet.
    Instead, we do a lightweight check: verify the node's firewall
    allows outbound by testing if the node responds to connections
    on these ports (exit nodes must have them open outbound).
    \"\"\"
    results = []
    async def _check_one(p):
        # We test by asking the Stockholm agent to connect to the exit node
        # and then through it to an external target on that port.
        # Fallback: just verify the port is not blocked inbound on the node
        # (if the node blocks a port inbound, it likely blocks it outbound too)
        port_num = p["port"]
        # Test: can we reach a known external service through the node?
        # Simple heuristic: check if the port is open on the node itself
        # This catches firewall misconfigs where entire port ranges are blocked
        try:
            loop = asyncio.get_event_loop()
            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _tcp, host, port_num, timeout),
                timeout + 1
            )
            return {"port": port_num, "proto": p["proto"], "desc": p["desc"], "open": ok}
        except:
            return {"port": port_num, "proto": p["proto"], "desc": p["desc"], "open": False}

    tasks = [_check_one(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return list(results)

'''

new_func = '''def get_exit_policy(nd):
    """Return declared exit policy info from node API data."""
    desc = nd.get("description") or {}
    nr = desc.get("network_requester") or {}
    uses_policy = nr.get("uses_exit_policy", False)
    return {
        "declared": uses_policy,
        "ports": EXIT_POLICY_PORTS if uses_policy else [],
        "total": len(EXIT_POLICY_PORTS) if uses_policy else 0,
        "status": "standard" if uses_policy else "none"
    }

'''

content = content.replace(old_func, new_func, 1)
print("2. Replaced ck_exit_policy with get_exit_policy")

# 3. Fix the check_node call - replace the old ck_exit_policy call
old_call = """exit_policy_results=None
        if is_exit:
            exit_policy_results=await ck_exit_policy(ip, EXIT_POLICY_PORTS)"""

new_call = """exit_policy_results=None
        if is_exit:
            exit_policy_results=get_exit_policy(nd)"""

content = content.replace(old_call, new_call, 1)
print("3. Fixed check_node call")

with open(path, "w") as f:
    f.write(content)
print("\nDone!")
