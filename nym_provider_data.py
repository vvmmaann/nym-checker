"""
Datacenter / hosting provider scoring for 'where to deploy' recommendations.

Maps ASN -> quality/reputation/policy metadata, then scores each provider
based on concentration in the Nym network, SMTP egress behavior, IPv6,
crypto payments, Tor policy, documented abuse, and more.

Data enrichment pipeline:
1. /opt/nym-probe/asn_data.json - IP -> ASN mapping (from Team Cymru DNS)
2. isp-sheet.csv data (manually curated)
3. /opt/nym-probe/latest_smtp.json - SMTP egress results per exit IP

Scoring is deliberately conservative:
- "recommended" requires multiple positive signals
- any "avoid" reputation signal (confirmed abuse, termination patterns) demotes
"""

# ASN -> curated metadata. Keys: name, crypto_payments, ipv6, tor_friendly,
# abuse_tolerance, notes, countries, tags
# All fields optional. Auto-fallback uses Team Cymru name.
PROVIDERS = {
    # --- Privacy-friendly tier ---
    "200651": {"name": "FlokiNET", "ipv6": "on_request", "crypto_payments": True,
               "crypto_xmr": True, "tor_friendly": True, "abuse_tolerance": "high",
               "note_code": "note_flokinet", "tags": ["privacy_focused", "xmr_accepted"]},
    "209847": {"name": "WorkTitans", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "high",
               "note_code": "note_worktitans", "tags": ["reseller", "privacy_reseller"]},
    "197540": {"name": "netcup", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_netcup", "tags": ["eu_based"]},
    "207143": {"name": "hosttech", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_hosttech", "tags": ["swiss"]},
    "63473": {"name": "HostHatch", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "high",
              "note_code": "note_hosthatch", "tags": ["global", "privacy_friendly"]},

    # --- Mainstream but workable ---
    "24940": {"name": "Hetzner", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_hetzner", "tags": ["strict_abuse"]},
    "16276": {"name": "OVH", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_ovh", "tags": ["vps_exit_forbidden"]},
    "47583": {"name": "Hostinger", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "medium",
              "note_code": "note_hostinger", "tags": []},
    "51167": {"name": "Contabo", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_contabo", "tags": ["strict_abuse"]},
    "141995": {"name": "Contabo Asia", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": False, "abuse_tolerance": "low",
               "note_code": "note_contabo_asia", "tags": ["strict_abuse"]},

    # --- Cloud giants (concentration concerns) ---
    "14061": {"name": "DigitalOcean", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_digitalocean", "tags": ["cloud_giant"]},
    "20473": {"name": "Vultr", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_vultr", "tags": ["cloud_giant"]},
    "63949": {"name": "Akamai Connected Cloud (Linode)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_linode", "tags": ["cloud_giant"]},

    # --- Regional ---
    "136258": {"name": "OneProvider", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_oneprovider", "tags": ["dedicated_servers"]},
    "9009": {"name": "M247", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": True, "abuse_tolerance": "medium",
             "note_code": "note_m247", "tags": []},
    "212317": {"name": "Hetzner Cloud", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": False, "abuse_tolerance": "low",
               "note_code": "note_hetzner_cloud", "tags": ["strict_abuse"]},
    "59711": {"name": "HZ-EU (Hetzner-related)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_hetzner_related", "tags": ["strict_abuse"]},
    "56322": {"name": "ServerAstra", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "medium",
              "note_code": "note_serverastra", "tags": []},
    "212477": {"name": "Royale Hosting", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_royale", "tags": ["privacy_friendly"]},

    # --- Higher risk ---
    "210644": {"name": "AEZA", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "high",
               "note_code": "note_aeza", "tags": ["russian", "sanctioned"], "country_risk": "high"},

    # --- Other regional ---
    "8100": {"name": "QuadraNet Enterprises", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": "partial", "abuse_tolerance": "medium", "tags": []},
    "6939": {"name": "Hurricane Electric", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": True, "abuse_tolerance": "medium", "tags": []},
    "49505": {"name": "Selectel", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_selectel", "tags": ["russian"]},
    "60068": {"name": "Datacamp (CDN77)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low", "tags": []},
}


def provider_score(asn, nodes_count, total_network_nodes, smtp_stats=None, fallback_name=""):
    """
    Score a provider (ASN) for Nym deployment recommendation.

    smtp_stats: {"open": N, "partial": N, "blocked": N} for exit gateways on this ASN
    """
    p = PROVIDERS.get(asn, {})
    name = p.get("name") or fallback_name or f"AS{asn}"
    share = nodes_count / max(total_network_nodes, 1)
    reasons = []  # list of {code, params}

    # --- Concentration penalty (exponential past 5%) ---
    concentration_penalty = 0
    if share > 0.15:
        concentration_penalty = (share - 0.05) * 400
        reasons.append({"code": "provider_very_oversaturated", "params": {"pct": round(share*100, 1)}})
    elif share > 0.10:
        concentration_penalty = (share - 0.05) * 300
        reasons.append({"code": "provider_oversaturated", "params": {"pct": round(share*100, 1)}})
    elif share > 0.05:
        concentration_penalty = (share - 0.05) * 200
        reasons.append({"code": "provider_approaching_limit", "params": {"pct": round(share*100, 1)}})

    # --- Quality bonuses ---
    quality = 0
    if p.get("ipv6") == "default":
        quality += 10
        reasons.append({"code": "provider_ipv6_default"})
    elif p.get("ipv6") == "on_request":
        quality += 5

    if p.get("crypto_payments"):
        quality += 10
        reasons.append({"code": "provider_crypto"})

    if p.get("crypto_xmr"):
        quality += 5
        reasons.append({"code": "provider_xmr"})

    if p.get("tor_friendly") is True:
        quality += 15
        reasons.append({"code": "provider_tor_friendly"})
    elif p.get("tor_friendly") == "partial":
        quality += 5
    elif p.get("tor_friendly") is False:
        quality -= 10
        reasons.append({"code": "provider_tor_unfriendly"})

    # SMTP bonus (only for exits)
    if smtp_stats:
        total_exits = sum(smtp_stats.values())
        if total_exits > 0:
            open_ratio = smtp_stats.get("open", 0) / total_exits
            if open_ratio > 0.8:
                quality += 10
                reasons.append({"code": "provider_smtp_clean", "params": {"pct": int(open_ratio*100)}})
            elif open_ratio < 0.2 and total_exits >= 3:
                quality -= 15
                reasons.append({"code": "provider_smtp_blocked", "params": {"pct": int(open_ratio*100)}})

    # --- Abuse tolerance ---
    abuse = p.get("abuse_tolerance", "unknown")
    if abuse == "high":
        quality += 10
        reasons.append({"code": "provider_abuse_tolerant"})
    elif abuse == "low":
        quality -= 15
        reasons.append({"code": "provider_abuse_strict"})

    # --- Country risk ---
    if p.get("country_risk") == "high":
        quality -= 20
        reasons.append({"code": "provider_country_risk"})

    # --- Special tags ---
    for tag in p.get("tags", []):
        if tag == "vps_exit_forbidden":
            quality -= 15
            reasons.append({"code": "provider_exit_forbidden"})
        elif tag == "sanctioned":
            quality -= 10
            reasons.append({"code": "provider_sanctioned"})

    # --- Compute raw score ---
    raw = 50 + quality - concentration_penalty
    raw = max(0, min(100, raw))

    # --- Classification ---
    if concentration_penalty >= 15 and quality < 10:
        classification = "oversaturated_avoid"
    elif concentration_penalty >= 15:
        classification = "oversaturated"
    elif raw >= 70:
        classification = "great"
    elif raw >= 50:
        classification = "good"
    elif raw >= 30:
        classification = "ok"
    else:
        classification = "avoid"

    return {
        "asn": asn,
        "name": name,
        "nodes": nodes_count,
        "share_pct": round(share * 100, 2),
        "score": round(raw, 1),
        "classification": classification,
        "reasoning": reasons,
        "metadata": {
            "ipv6": p.get("ipv6"),
            "crypto_payments": p.get("crypto_payments"),
            "tor_friendly": p.get("tor_friendly"),
            "abuse_tolerance": p.get("abuse_tolerance"),
            "note_code": p.get("note_code"),
        },
    }


def aggregate_providers(nodes, ip_to_asn, asn_names, total_nodes, smtp_cache=None):
    """
    Group nodes by ASN, compute provider scores.
    Returns sorted list by score desc.
    """
    from collections import defaultdict
    by_asn = defaultdict(list)
    for n in nodes:
        ip = n.get("ip", "")
        info = ip_to_asn.get(ip)
        if info:
            by_asn[info["asn"]].append(n)

    results = []
    for asn, asn_nodes in by_asn.items():
        # Build SMTP stats for exits on this ASN
        smtp_stats = {"open": 0, "partial": 0, "blocked": 0, "unknown": 0}
        if smtp_cache:
            for n in asn_nodes:
                if n.get("mode") != "exit-gateway":
                    continue
                s = smtp_cache.get(n.get("ip", ""))
                if s:
                    st = s.get("status", "unknown")
                    if st in smtp_stats:
                        smtp_stats[st] += 1
        fallback = asn_names.get(asn, "")
        score = provider_score(asn, len(asn_nodes), total_nodes,
                               smtp_stats=smtp_stats if any(smtp_stats.values()) else None,
                               fallback_name=fallback)
        score["smtp_stats"] = smtp_stats if any(smtp_stats.values()) else None
        results.append(score)

    results.sort(key=lambda x: (-x["share_pct"], -x["score"]))
    return results
