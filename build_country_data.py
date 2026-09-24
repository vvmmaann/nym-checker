#!/usr/bin/env python3
"""Fetch country metrics from primary sources and produce country_metrics.json.

Sources:
- World Bank Open Data API (no auth required)
  - SP.POP.TOTL: population
  - NY.GDP.PCAP.CD: GDP per capita (current US$)
  - IT.NET.USER.ZS: individuals using the Internet (% of population)
- Freedom House: freedom_total - manually maintained snapshot below
  (Freedom House releases annually as xlsx; embedded snapshot for now)
- Reporters Without Borders: press_freedom - similar annual snapshot

Run: python3 build_country_data.py > country_metrics.json
"""
import json
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone

WORLD_BANK_BASE = "https://api.worldbank.org/v2"
WB_INDICATORS = {
    "population_thousands": "SP.POP.TOTL",
    "gdp_per_capita": "NY.GDP.PCAP.CD",
    "internet_penetration_pct": "IT.NET.USER.ZS",
}


def fetch_wb_indicator(indicator: str, year: str = "2023"):
    """Pull one indicator for all countries from World Bank API."""
    url = f"{WORLD_BANK_BASE}/country/all/indicator/{indicator}?date={year}&format=json&per_page=400"
    sys.stderr.write(f"Fetching {indicator}...\n")
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.loads(r.read())
    # Response is [metadata_obj, [data_rows]]
    if not isinstance(data, list) or len(data) < 2:
        sys.stderr.write(f"  unexpected response\n")
        return {}
    rows = data[1] or []
    result = {}
    for row in rows:
        if not row:
            continue
        iso2 = (row.get("country") or {}).get("id", "")
        iso3 = row.get("countryiso3code", "")  # this is a TOP-LEVEL field, not nested
        val = row.get("value")
        # Skip aggregates (regions). Real countries have ISO2 in standard ISO 3166-1 ranges -
        # World Bank uses XK/XC/XD/XE/XF/etc for World/region groupings. Filter by iso3
        # being 3 chars AND not in known aggregate set.
        if not (iso2 and len(iso2) == 2 and iso3 and len(iso3) == 3):
            continue
        # Known WB aggregate ISO3 prefixes (regions, income groups, etc.)
        if iso3 in {"AFE","AFW","ARB","CEB","CSS","EAP","EAR","EAS","ECA","ECS","EMU","EUU",
                    "FCS","HIC","HPC","IBD","IBT","IDA","IDB","IDX","INX","LAC","LCN","LDC",
                    "LIC","LMC","LMY","LTE","MEA","MIC","MNA","NAC","OED","OSS","PRE","PSS",
                    "PST","SAS","SSA","SSF","SST","TEA","TEC","TLA","TMN","TSA","TSS","UMC","WLD"}:
            continue
        result[iso2] = val
    sys.stderr.write(f"  got {len(result)} country values\n")
    return result


# Freedom House Freedom in the World 2024 - Total Score (out of 100)
# Snapshot from https://freedomhouse.org/sites/default/files/2024-02/All_data_FIW_2013-2024.xlsx
# Released Feb 2024, scores reflect 2023 calendar year
# Higher = more free
FH_FREEDOM_TOTAL_2024 = {
    "US": 83, "CA": 97, "GB": 91, "DE": 94, "FR": 89, "IT": 90, "ES": 90, "NL": 97,
    "BE": 96, "CH": 96, "AT": 92, "SE": 100, "NO": 100, "FI": 100, "DK": 97, "IE": 96,
    "PL": 80, "CZ": 91, "SK": 90, "HU": 65, "GR": 86, "PT": 94, "EE": 94, "LV": 89,
    "LT": 89, "LU": 97, "MT": 89, "CY": 84, "BG": 78, "RO": 83, "SI": 95, "HR": 86,
    "RS": 57, "ME": 67, "BA": 53, "MK": 65, "AL": 67, "XK": 56, "MD": 62, "UA": 50,
    "BY": 8, "RU": 13, "KZ": 23, "KG": 26, "UZ": 12, "TJ": 5, "TM": 2, "AZ": 7, "AM": 54, "GE": 58,
    "IS": 94, "CN": 9, "JP": 96, "KR": 83, "TW": 94, "HK": 41, "MN": 84, "VN": 19, "MM": 9,
    "TH": 36, "MY": 53, "SG": 48, "PH": 55, "ID": 57, "IN": 66, "PK": 35, "BD": 40, "LK": 53,
    "NP": 64, "BT": 61, "AU": 95, "NZ": 99, "PG": 60, "FJ": 64,
    "BR": 72, "AR": 84, "CL": 94, "UY": 96, "CO": 70, "PE": 71, "EC": 68, "VE": 17, "BO": 64,
    "PY": 64, "MX": 60, "GT": 50, "HN": 47, "NI": 23, "SV": 50, "CR": 91, "PA": 83, "DO": 67,
    "JM": 78, "TT": 81, "BS": 91, "CU": 11,
    "ZA": 79, "EG": 18, "MA": 37, "TN": 56, "DZ": 32, "LY": 9, "NG": 43, "KE": 51, "TZ": 36,
    "UG": 33, "ET": 19, "ZW": 28, "ZM": 53, "BW": 72, "NA": 77, "MZ": 39, "AO": 28, "RW": 21,
    "SN": 67, "CI": 49, "GH": 75, "ML": 27, "BF": 27, "MG": 60, "MU": 86, "SC": 78, "CD": 19,
    "IL": 74, "PS": 28, "JO": 33, "LB": 41, "SY": 1, "IQ": 31, "TR": 33, "IR": 12, "SA": 8,
    "AE": 18, "QA": 25, "KW": 37, "OM": 23, "BH": 14, "YE": 9, "AF": 6,
    "AD": 93, "MC": 84, "LI": 95, "SM": 96, "VA": 0,
}
FH_SOURCE = "https://freedomhouse.org/explore-the-map/freedom-on-the-net"
FH_AS_OF = "2024-02"

# Reporters Without Borders Press Freedom Index 2024 - Score (out of 100)
# Higher = more press freedom
# Snapshot from https://rsf.org/en/index?year=2024
RSF_PRESS_FREEDOM_2024 = {
    "US": 66.6, "CA": 80.0, "GB": 76.8, "DE": 81.9, "FR": 78.7, "IT": 69.8, "ES": 75.2,
    "NL": 84.0, "BE": 81.7, "CH": 81.2, "AT": 75.5, "SE": 88.3, "NO": 91.9, "FI": 86.5,
    "DK": 89.6, "IE": 84.3, "PL": 67.7, "CZ": 81.0, "SK": 71.7, "HU": 67.0, "GR": 57.2,
    "PT": 81.5, "EE": 83.5, "LV": 79.0, "LT": 81.4, "LU": 84.0, "MT": 79.5, "CY": 70.6,
    "BG": 53.2, "RO": 67.1, "SI": 76.0, "HR": 67.2, "RS": 51.9, "ME": 58.1, "BA": 60.8,
    "MK": 64.2, "AL": 55.7, "XK": 64.6, "MD": 65.0, "UA": 65.0, "BY": 25.5, "RU": 29.9,
    "KZ": 41.1, "KG": 51.0, "UZ": 30.2, "TJ": 28.4, "TM": 17.6, "AZ": 33.5, "AM": 60.8, "GE": 58.9,
    "IS": 84.0, "CN": 23.1, "JP": 65.5, "KR": 67.0, "TW": 75.0, "HK": 41.3, "MN": 67.5,
    "VN": 25.3, "MM": 24.4, "TH": 39.2, "MY": 53.9, "SG": 42.8, "PH": 43.4, "ID": 51.1,
    "IN": 31.3, "PK": 33.9, "BD": 33.7, "LK": 55.6, "NP": 65.8, "BT": 60.3, "AU": 72.1,
    "NZ": 80.3, "BR": 64.3, "AR": 66.5, "CL": 75.6, "UY": 79.0, "CO": 56.5, "PE": 56.1,
    "EC": 58.4, "VE": 28.3, "BO": 60.7, "PY": 60.7, "MX": 50.6, "GT": 50.4, "HN": 48.8,
    "NI": 34.2, "SV": 49.5, "CR": 81.0, "PA": 67.0, "DO": 64.2, "JM": 79.6, "TT": 75.2,
    "BS": 79.0, "CU": 25.7, "ZA": 73.0, "EG": 25.1, "MA": 41.5, "TN": 51.2, "DZ": 32.4,
    "LY": 28.7, "NG": 49.0, "KE": 65.0, "TZ": 49.3, "UG": 41.5, "ET": 36.7, "ZW": 47.6,
    "ZM": 60.3, "BW": 69.4, "NA": 79.1, "MZ": 49.8, "AO": 50.2, "RW": 39.6, "SN": 60.1,
    "CI": 56.4, "GH": 67.4, "ML": 40.2, "BF": 50.6, "MG": 53.0, "MU": 69.5, "SC": 69.0,
    "CD": 41.9, "IL": 59.4, "PS": 30.0, "JO": 47.5, "LB": 53.7, "SY": 17.4, "IQ": 47.0,
    "TR": 31.6, "IR": 21.3, "SA": 32.4, "AE": 33.9, "QA": 42.5, "KW": 48.7, "OM": 45.6,
    "BH": 35.0, "YE": 30.5, "AF": 19.9, "AD": 80.0, "MC": 76.9, "LI": 80.0, "SM": 87.9,
}
RSF_SOURCE = "https://rsf.org/en/index"
RSF_AS_OF = "2024-05"


def build():
    # Pull all 3 indicators from World Bank
    pop = fetch_wb_indicator(WB_INDICATORS["population_thousands"])
    gdp = fetch_wb_indicator(WB_INDICATORS["gdp_per_capita"])
    inet = fetch_wb_indicator(WB_INDICATORS["internet_penetration_pct"])

    # Union of all known ISO codes
    all_iso = set(pop.keys()) | set(gdp.keys()) | set(inet.keys()) | set(FH_FREEDOM_TOTAL_2024.keys()) | set(RSF_PRESS_FREEDOM_2024.keys())

    out = {}
    for iso in sorted(all_iso):
        entry = {}
        if iso in pop and pop[iso] is not None:
            entry["population_millions"] = round(pop[iso] / 1_000_000, 2)
        if iso in gdp and gdp[iso] is not None:
            entry["gdp_per_capita_kusd"] = round(gdp[iso] / 1000, 1)
        if iso in inet and inet[iso] is not None:
            entry["internet_penetration"] = round(inet[iso] / 100, 3)
        if iso in FH_FREEDOM_TOTAL_2024:
            entry["freedom_total"] = FH_FREEDOM_TOTAL_2024[iso]
        if iso in RSF_PRESS_FREEDOM_2024:
            entry["press_freedom"] = RSF_PRESS_FREEDOM_2024[iso]
        if entry:
            out[iso] = entry

    bundle = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sources": {
                "population_millions": {
                    "indicator": "SP.POP.TOTL",
                    "url": "https://api.worldbank.org/v2/country/all/indicator/SP.POP.TOTL",
                    "provider": "World Bank Open Data",
                    "data_year": "2023",
                },
                "gdp_per_capita_kusd": {
                    "indicator": "NY.GDP.PCAP.CD",
                    "url": "https://api.worldbank.org/v2/country/all/indicator/NY.GDP.PCAP.CD",
                    "provider": "World Bank Open Data",
                    "data_year": "2023",
                },
                "internet_penetration": {
                    "indicator": "IT.NET.USER.ZS",
                    "url": "https://api.worldbank.org/v2/country/all/indicator/IT.NET.USER.ZS",
                    "provider": "World Bank Open Data",
                    "data_year": "2023",
                },
                "freedom_total": {
                    "url": FH_SOURCE,
                    "provider": "Freedom House - Freedom in the World",
                    "as_of": FH_AS_OF,
                    "note": "Manually transcribed snapshot - refresh annually each February when FH publishes new edition",
                },
                "press_freedom": {
                    "url": RSF_SOURCE,
                    "provider": "Reporters Without Borders (RSF) - World Press Freedom Index",
                    "as_of": RSF_AS_OF,
                    "note": "Manually transcribed snapshot - refresh annually each May when RSF publishes new edition",
                },
            },
        },
        "data": out,
    }
    json.dump(bundle, sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    build()
