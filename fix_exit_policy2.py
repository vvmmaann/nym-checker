path = "/opt/nym-checker/nym_checker_backend.py"
with open(path, "r") as f:
    content = f.read()

# Replace get_exit_policy to use is_exit flag directly
# All exit nodes use the standard exit policy by default
old = '''def get_exit_policy(nd):
    """Return declared exit policy info from node API data."""
    desc = nd.get("description") or {}
    nr = desc.get("network_requester") or {}
    uses_policy = nr.get("uses_exit_policy", False)
    return {
        "declared": uses_policy,
        "ports": EXIT_POLICY_PORTS if uses_policy else [],
        "total": len(EXIT_POLICY_PORTS) if uses_policy else 0,
        "status": "standard" if uses_policy else "none"
    }'''

new = '''def get_exit_policy():
    """Return the standard Nym exit policy port list.
    All exit gateways use the standard exit policy by default."""
    return {
        "declared": True,
        "ports": EXIT_POLICY_PORTS,
        "total": len(EXIT_POLICY_PORTS),
        "status": "standard"
    }'''

content = content.replace(old, new, 1)
print("1. Simplified get_exit_policy")

# Fix the call
content = content.replace(
    "exit_policy_results=get_exit_policy(nd)",
    "exit_policy_results=get_exit_policy()",
    1
)
print("2. Fixed call")

with open(path, "w") as f:
    f.write(content)
print("\nDone!")
