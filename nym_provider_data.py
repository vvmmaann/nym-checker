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
               "note_code": "note_flokinet", "tags": ["privacy_focused", "xmr_accepted"],
               "countries": ["RO","IS","NL","FI"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://flokinet.is",
               "evidence": {
                   "crypto_payments": {"value": True, "source": "https://flokinet.is/index.php?rp=/store/payment-methods", "verified_at": "2026-05-12", "notes": "BTC, XMR, LTC, ETH and other altcoins accepted. Cash by mail also supported."},
                   "crypto_xmr": {"value": True, "source": "https://flokinet.is", "verified_at": "2026-05-12", "notes": "Monero explicitly supported - one of few hosters that accept XMR."},
                   "tor_friendly": {"value": True, "source": "https://flokinet.is/tor.php", "verified_at": "2026-05-12", "notes": "Tor exit relays explicitly allowed. Dedicated Tor-friendly hosting tier offered."},
                   "abuse_tolerance": {"value": "high", "source": "https://flokinet.is", "verified_at": "2026-05-12", "notes": "Privacy-first hoster headquartered in Iceland, designed for high abuse-tolerance operations. RO/IS/NL/FI jurisdictions chosen for legal protections."}
               }},
    "209847": {"name": "WorkTitans", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "high",
               "note_code": "note_worktitans", "tags": ["reseller", "privacy_reseller", "advisory_critical"],
               "aliases": ["the.hosting", "PQ-Hosting", "Stark Industries"],
               "risk_advisory": {
                   "severity": "critical",
                   "status": "infrastructure_seized",
                   "issued_at": "2026-05-22",
                   "issued_by": "Dutch FIOD operation; covered by Krebs on Security",
                   "headline_code": "advisory_seized_headline",
                   "message_code": "advisory_seized_message",
                   "affected_locations": ["US", "DE", "NL", "AT"],
                   "action_required": "migrate_asap",
                   "sgp_deadline_days": 30,
                   "source_url": "https://krebsonsecurity.com/2026/05/netherlands-seizes-800-servers-arrests-2-for-aiding-cyberattacks/",
                   "source_provider": "Krebs on Security",
                   "details": "Dutch Fiscal Intelligence and Investigation Service (FIOD) seized ~800 servers and arrested two operators on 2026-05-18 (raids in Enschede, Almere, Dronten, Schiphol-Rijk). FIOD alleges the company indirectly provided economic resources to sanctioned Russian/Belarusian entities. WorkTitans was a Dutch front-company for sanctioned Stark Industries / PQ-Hosting / the.hosting.",
                   "verified_at": "2026-05-27"
               }},
    "197540": {"name": "netcup", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_netcup", "tags": ["eu_based"],
               "countries": ["AT","DE","NL","US","SG"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://www.netcup.com/en/server/vps"},
    "207143": {"name": "hosttech", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_hosttech", "tags": ["swiss"],
               "countries": ["CH","AT","DE"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://www.datacentermap.com/c/hosttech-gmbh/"},
    "63473": {"name": "HostHatch", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "high",
              "note_code": "note_hosthatch", "tags": ["global", "privacy_friendly"],
              "countries": ["US","NL","GB","ES","IT","NO","SE","AT","PL","CH","JP","SG","HK","AU"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://hosthatch.com/"},

    # --- Mainstream but workable ---
    # 'countries' field: ISO 3166-1 alpha-2 codes where the provider officially operates datacenters
    # (verified via provider's own website). Falls back to "unknown" if not researched yet.
    "24940": {"name": "Hetzner", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_hetzner", "tags": ["strict_abuse"],
              "countries": ["DE","FI","SG","US"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.hetzner.com/cloud",
              "evidence": {
                  "tor_friendly": {"value": False, "source": "https://docs.hetzner.com/cloud/general/tos/", "verified_at": "2026-05-12", "notes": "Hetzner Cloud ToS section 8 disallows anonymizing services and exit relays. Multiple operator reports confirm exit nodes get terminated on first abuse complaint."},
                  "abuse_tolerance": {"value": "low", "source": "https://docs.hetzner.com/cloud/general/abuse/", "verified_at": "2026-05-12", "notes": "Documented 'one strike' approach: any abuse complaint requires response within 24h or instance is suspended. Repeated complaints terminate account."},
                  "crypto_payments": {"value": False, "source": "https://www.hetzner.com/payment-method", "verified_at": "2026-05-12", "notes": "Only credit card, SEPA, PayPal accepted. No crypto."}
              }},
    "16276": {"name": "OVH", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_ovh", "tags": ["vps_exit_forbidden"],
              "countries": ["FR","CA","US","DE","PL","IT","GB","SG","AU"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.ovhcloud.com/en/datacenter/",
              "evidence": {
                  "tor_friendly": {"value": "partial", "source": "https://us.ovhcloud.com/legal/general-terms-of-service/", "verified_at": "2026-05-12", "notes": "OVH ToS prohibits Tor exit nodes on VPS plans specifically. Dedicated server plans allow Tor with restrictions per documented community experience."},
                  "abuse_tolerance": {"value": "medium", "source": "https://us.ovhcloud.com/legal/anti-spam/", "verified_at": "2026-05-12", "notes": "Standard abuse handling: 7-day window to respond before service suspension. Less aggressive than Hetzner."},
                  "vps_exit_forbidden": {"source": "https://us.ovhcloud.com/legal/general-terms-of-service/", "verified_at": "2026-05-12", "notes": "Explicit clause in VPS ToS forbidding open-proxy and Tor exit operation."}
              }},
    "47583": {"name": "Hostinger", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "medium",
              "note_code": "note_hostinger", "tags": [],
              "countries": ["US","BR","NL","ID","KE","LT","SG","GB","AU"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.hostinger.com/support/1583267-where-are-hostinger-servers-located/"},
    "51167": {"name": "Contabo", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_contabo", "tags": ["strict_abuse"],
              "countries": ["DE","US","GB","SG","JP","AU","IN"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://contabo.com/en/locations/"},
    "141995": {"name": "Contabo Asia", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": False, "abuse_tolerance": "low",
               "note_code": "note_contabo_asia", "tags": ["strict_abuse"],
               "countries": ["SG","JP","AU","IN"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://contabo.com/en/locations/"},

    # --- Cloud giants (concentration concerns) ---
    "14061": {"name": "DigitalOcean", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_digitalocean", "tags": ["cloud_giant"],
              "countries": ["US","NL","SG","GB","DE","CA","IN","AU"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://docs.digitalocean.com/platform/regional-availability/",
              "evidence": {
                  "tor_friendly": {"value": False, "source": "https://www.digitalocean.com/legal/acceptable-use-policy", "verified_at": "2026-05-12", "notes": "DO AUP prohibits 'anonymizing services' including Tor exit relays. Multiple community reports of droplet termination for Tor exit operation."},
                  "abuse_tolerance": {"value": "low", "source": "https://www.digitalocean.com/legal/terms-of-service-agreement", "verified_at": "2026-05-12", "notes": "ToS allows DO to suspend instances for any abuse complaint without prior notice. Generally strict response."},
                  "crypto_payments": {"value": False, "source": "https://www.digitalocean.com/community/questions/can-i-pay-with-bitcoin", "verified_at": "2026-05-12", "notes": "No crypto. Credit card, PayPal, Google Pay only."}
              }},
    "20473": {"name": "Vultr", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_vultr", "tags": ["cloud_giant"],
              "countries": ["CA","MX","BR","PL","US","NL","GB","DE","FR","ES","SE","JP","KR","SG","IN","AU","CL","IL","ZA","IT"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.vultr.com/locations/",
              "evidence": {
                  "crypto_payments": {"value": True, "source": "https://www.vultr.com/about/payments/", "verified_at": "2026-05-12", "notes": "BitPay integration: BTC, ETH, LTC, BCH, USDC accepted. Min $10 deposit."},
                  "tor_friendly": {"value": "partial", "source": "https://www.vultr.com/legal/aup/", "verified_at": "2026-05-12", "notes": "Vultr AUP allows Tor relays/middle nodes. Exit nodes require manual approval via support ticket - some operators report success, others rejection."},
                  "abuse_tolerance": {"value": "medium", "source": "https://www.vultr.com/legal/aup/", "verified_at": "2026-05-12", "notes": "Standard abuse handling with response window. Less aggressive than Hetzner but stricter than M247."}
              }},
    "63949": {"name": "Akamai Connected Cloud (Linode)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_linode", "tags": ["cloud_giant"],
              "countries": ["US","CA","DE","GB","IN","SG","AU","JP","FR"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.linode.com/global-infrastructure/"},

    # --- Regional ---
    "136258": {"name": "OneProvider", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_oneprovider", "tags": ["dedicated_servers"]},
    "9009": {"name": "M247", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": True, "abuse_tolerance": "medium",
             "note_code": "note_m247", "tags": [],
             "countries": ["GB","RO","NL","ES","AT","FI","US","SE","BG","GR","MD","IE","IL","PL","AL","NO","CZ","DK","BR","SG","ZA","JP","HK","MY","AU","TR","UA","AE","AR","MX","CA","EE","LT","LV"],
             "countries_verified_at": "2026-05-12", "countries_source": "https://m247.com/why-m247/about-us/our-network/"},
    "212317": {"name": "Hetzner Cloud", "ipv6": "default", "crypto_payments": False,
               "tor_friendly": False, "abuse_tolerance": "low",
               "note_code": "note_hetzner_cloud", "tags": ["strict_abuse"],
               "countries": ["DE","FI","SG","US"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://www.hetzner.com/cloud"},
    "59711": {"name": "HZ-EU (Hetzner-related)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low",
              "note_code": "note_hetzner_related", "tags": ["strict_abuse"],
              "countries": ["DE","FI"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://www.hetzner.com/cloud"},
    "56322": {"name": "ServerAstra", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": True, "abuse_tolerance": "medium",
              "note_code": "note_serverastra", "tags": [],
              "countries": ["HU","US"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://serverastra.com/"},
    "212477": {"name": "Royale Hosting", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "medium",
               "note_code": "note_royale", "tags": ["privacy_friendly"]},

    # --- Higher risk ---
    "210644": {"name": "AEZA", "ipv6": "default", "crypto_payments": True,
               "tor_friendly": True, "abuse_tolerance": "high",
               "note_code": "note_aeza", "tags": ["russian", "sanctioned"], "country_risk": "high",
               "countries": ["DE","AT","NL","SE","RU"],
               "countries_verified_at": "2026-05-12", "countries_source": "https://aeza.net/en"},

    # --- Other regional ---
    "8100": {"name": "QuadraNet Enterprises", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": "partial", "abuse_tolerance": "medium", "tags": []},
    "6939": {"name": "Hurricane Electric", "ipv6": "default", "crypto_payments": False,
             "tor_friendly": True, "abuse_tolerance": "medium", "tags": []},
    "49505": {"name": "Selectel", "ipv6": "default", "crypto_payments": True,
              "tor_friendly": "partial", "abuse_tolerance": "medium",
              "note_code": "note_selectel", "tags": ["russian"],
              "countries": ["RU"],
              "countries_verified_at": "2026-05-12", "countries_source": "https://selectel.ru/en/"},
    "60068": {"name": "Datacamp (CDN77)", "ipv6": "default", "crypto_payments": False,
              "tor_friendly": False, "abuse_tolerance": "low", "tags": []},
    "37105": {"name": "xneelo", "ipv6": "on_request", "crypto_payments": False,
              "tor_friendly": "partial", "abuse_tolerance": "medium", "tags": [],
              "countries": ["ZA"],
              "countries_verified_at": "2026-05-14",
              "countries_source": "https://xneelo.co.za/data-centre/"},
}


# Renewable evidence overlay: maps provider name in renewable JSON to ASN keys above.
# JSON keys come from provider_renewable_evidence.json; PROVIDERS dict above is ASN-keyed.
_RENEWABLE_JSON_TO_ASN = {
    "Hetzner":              "24940",
    "Hetzner Cloud":        "212317",
    "HZ-EU":                "59711",
    "Akamai (Linode)":      "63949",
    "hosttech":             "207143",
    "Contabo":              "51167",
    "Contabo Asia":         "141995",
    "netcup":               "197540",
    "Hostinger":            "47583",
    "OVH":                  "16276",
    "Vultr":                "20473",
    "DigitalOcean":         "14061",
    "M247":                 "9009",
    "Royale Hosting":       "212477",
    "FlokiNET":             "200651",
    "OneProvider":          "136258",
    "xneelo":               "37105",
    "Hurricane Electric":   "6939",
    "QuadraNet":            "8100",
    "Selectel":             "49505",
    "AEZA":                 "210644",
    "HostHatch":            "63473",
    "WorkTitans":           "209847",
    "ServerAstra":          "56322",
    "Datacamp (CDN77)":     "60068",
}


def _load_renewable_overlay():
    """Overlay renewable energy evidence onto PROVIDERS from provider_renewable_evidence.json.

    Adds top-level 'renewable' block to each matched provider. Evidence built by
    manual verification of provider sustainability pages (see grid_energy_verification_report.md).
    """
    import json
    from pathlib import Path
    path = Path(__file__).parent / "provider_renewable_evidence.json"
    if not path.exists():
        return
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    providers = bundle.get("providers", {}) or {}
    matched = 0
    for json_name, entry in providers.items():
        asn = _RENEWABLE_JSON_TO_ASN.get(json_name)
        if not asn or asn not in PROVIDERS:
            continue
        PROVIDERS[asn]["renewable"] = {
            "tier": entry.get("tier"),
            "tier_label": entry.get("tier_label"),
            "verification_confidence": entry.get("verification_confidence"),
            "verification_method": entry.get("verification_method"),
            "claim_summary": entry.get("claim_summary"),
            "source_url": entry.get("source_url"),
            "verified_at": entry.get("verified_at"),
            "datacenters": entry.get("datacenters") or [],
            "specifics": entry.get("specifics") or {},
            "caveats": entry.get("caveats") or [],
        }
        matched += 1
    return matched


_load_renewable_overlay()


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

    # --- Risk advisory override (provider under critical advisory = do_not_use) ---
    advisory = p.get("risk_advisory") or None
    advisory_penalty = 0
    if advisory and advisory.get("severity") in ("critical", "high"):
        sev = advisory.get("severity")
        advisory_penalty = 100 if sev == "critical" else 50
        reasons.append({
            "code": "provider_risk_advisory",
            "params": {"severity": sev, "status": advisory.get("status"), "headline_code": advisory.get("headline_code")},
        })

    # --- Compute raw score ---
    raw = 50 + quality - concentration_penalty - advisory_penalty
    raw = max(0, min(100, raw))

    # --- Classification ---
    if advisory and advisory.get("severity") == "critical":
        classification = "do_not_use"
    elif advisory and advisory.get("severity") == "high":
        classification = "avoid"
    elif concentration_penalty >= 15 and quality < 10:
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
        "evidence": p.get("evidence") or {},
        "countries": p.get("countries") or [],
        "countries_source": p.get("countries_source"),
        "countries_verified_at": p.get("countries_verified_at"),
        "renewable": p.get("renewable"),
        "risk_advisory": advisory,
        "aliases": p.get("aliases") or [],
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
