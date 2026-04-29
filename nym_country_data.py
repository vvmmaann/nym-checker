"""
Country data for 'where to deploy' recommendations.

Data sources:
- population: World Bank 2024 estimates (millions)
- internet_penetration: ITU 2024 (0-1)
- gdp_per_capita: World Bank 2024 (USD thousands)
- freedom_total: Freedom House Freedom in the World 2024 (0-100, higher = more free)
- freedom_on_net: Freedom on the Net 2024 (0-100, higher = more free)
- press_freedom: RSF Press Freedom Index 2024 (0-100, higher = more free)
- vpn_legal: "legal" | "restricted" | "forbidden" (for VPN USERS)
- operator_risk: "safe" | "caution" | "dangerous" | "extreme" (risk to NODE OPERATOR specifically)
  - safe: no known enforcement against privacy infrastructure operators
  - caution: content blocking exists, possible server seizure for abuse complaints, but no systemic targeting
  - dangerous: VPN/privacy operators face real legal consequences (fines, detention)
  - extreme: running privacy infra could lead to prosecution, server seizure, imprisonment
- tor_friendly: does Tor Project's "Good ISPs" list include this country
- five_eyes: member of Five/Nine/Fourteen Eyes (intelligence sharing)
- data_retention: "none" | "minimal" | "moderate" | "aggressive"
- crypto_friendly: legal framework for crypto (0-10 scale)
- neighbors: list of country codes (for entry-gateway demand calc)

All numbers are best-effort approximations. Sources can be updated via /admin/country-data API.
"""

COUNTRIES = {
    # --- North America ---
    "US": {"name": "United States", "population": 335.0, "internet_penetration": 0.91, "gdp_per_capita": 76.3,
           "freedom_total": 83, "freedom_on_net": 76, "press_freedom": 71, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "five", "data_retention": "aggressive", "crypto_friendly": 6,
           "neighbors": ["CA", "MX"]},
    "CA": {"name": "Canada", "population": 39.0, "internet_penetration": 0.93, "gdp_per_capita": 54.9,
           "freedom_total": 97, "freedom_on_net": 87, "press_freedom": 82, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "five", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["US"]},
    "MX": {"name": "Mexico", "population": 129.0, "internet_penetration": 0.81, "gdp_per_capita": 11.1,
           "freedom_total": 60, "freedom_on_net": 60, "press_freedom": 49, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["US", "GT"]},
    "GT": {"name": "Guatemala", "population": 18.0, "internet_penetration": 0.70, "gdp_per_capita": 5.8,
           "freedom_total": 51, "freedom_on_net": None, "press_freedom": 50, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 4,
           "neighbors": ["MX"]},

    # --- Europe / EU ---
    "DE": {"name": "Germany", "population": 84.5, "internet_penetration": 0.93, "gdp_per_capita": 52.7,
           "freedom_total": 93, "freedom_on_net": 77, "press_freedom": 82, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["FR", "NL", "BE", "LU", "AT", "CH", "CZ", "PL", "DK"]},
    "FR": {"name": "France", "population": 68.0, "internet_penetration": 0.92, "gdp_per_capita": 44.4,
           "freedom_total": 89, "freedom_on_net": 75, "press_freedom": 79, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "nine", "data_retention": "aggressive", "crypto_friendly": 7,
           "neighbors": ["DE", "BE", "LU", "CH", "IT", "ES"]},
    "GB": {"name": "United Kingdom", "population": 67.7, "internet_penetration": 0.96, "gdp_per_capita": 46.1,
           "freedom_total": 91, "freedom_on_net": 78, "press_freedom": 73, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "five", "data_retention": "aggressive", "crypto_friendly": 6,
           "neighbors": ["IE"]},
    "IE": {"name": "Ireland", "population": 5.2, "internet_penetration": 0.95, "gdp_per_capita": 103.5,
           "freedom_total": 97, "freedom_on_net": None, "press_freedom": 86, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["GB"]},
    "NL": {"name": "Netherlands", "population": 17.9, "internet_penetration": 0.97, "gdp_per_capita": 57.4,
           "freedom_total": 97, "freedom_on_net": None, "press_freedom": 88, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["DE", "BE"]},
    "BE": {"name": "Belgium", "population": 11.8, "internet_penetration": 0.94, "gdp_per_capita": 53.1,
           "freedom_total": 96, "freedom_on_net": None, "press_freedom": 86, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["DE", "FR", "NL", "LU"]},
    "LU": {"name": "Luxembourg", "population": 0.66, "internet_penetration": 0.99, "gdp_per_capita": 128.3,
           "freedom_total": 97, "freedom_on_net": None, "press_freedom": 89, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 8,
           "neighbors": ["DE", "FR", "BE"]},
    "CH": {"name": "Switzerland", "population": 8.9, "internet_penetration": 0.97, "gdp_per_capita": 98.8,
           "freedom_total": 96, "freedom_on_net": None, "press_freedom": 85, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 9,
           "neighbors": ["DE", "FR", "IT", "AT"]},
    "AT": {"name": "Austria", "population": 9.1, "internet_penetration": 0.94, "gdp_per_capita": 52.0,
           "freedom_total": 93, "freedom_on_net": None, "press_freedom": 82, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["DE", "CH", "IT", "SI", "HU", "SK", "CZ"]},
    "IT": {"name": "Italy", "population": 58.9, "internet_penetration": 0.86, "gdp_per_capita": 38.2,
           "freedom_total": 90, "freedom_on_net": None, "press_freedom": 68, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "aggressive", "crypto_friendly": 6,
           "neighbors": ["FR", "CH", "AT", "SI"]},
    "ES": {"name": "Spain", "population": 48.0, "internet_penetration": 0.96, "gdp_per_capita": 33.9,
           "freedom_total": 90, "freedom_on_net": None, "press_freedom": 77, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "fourteen", "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["FR", "PT"]},
    "PT": {"name": "Portugal", "population": 10.5, "internet_penetration": 0.88, "gdp_per_capita": 25.0,
           "freedom_total": 96, "freedom_on_net": None, "press_freedom": 87, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["ES"]},
    "SE": {"name": "Sweden", "population": 10.5, "internet_penetration": 0.96, "gdp_per_capita": 55.4,
           "freedom_total": 100, "freedom_on_net": None, "press_freedom": 88, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["NO", "FI", "DK"]},
    "NO": {"name": "Norway", "population": 5.5, "internet_penetration": 0.99, "gdp_per_capita": 87.9,
           "freedom_total": 100, "freedom_on_net": None, "press_freedom": 91, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 7,
           "neighbors": ["SE", "FI", "RU"]},
    "FI": {"name": "Finland", "population": 5.6, "internet_penetration": 0.96, "gdp_per_capita": 50.8,
           "freedom_total": 100, "freedom_on_net": 95, "press_freedom": 88, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 8,
           "neighbors": ["SE", "NO", "RU", "EE"]},
    "DK": {"name": "Denmark", "population": 5.9, "internet_penetration": 0.99, "gdp_per_capita": 68.0,
           "freedom_total": 97, "freedom_on_net": None, "press_freedom": 89, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "nine", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["DE", "SE"]},
    "IS": {"name": "Iceland", "population": 0.38, "internet_penetration": 0.99, "gdp_per_capita": 74.6,
           "freedom_total": 94, "freedom_on_net": 93, "press_freedom": 89, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 8,
           "neighbors": []},
    "EE": {"name": "Estonia", "population": 1.37, "internet_penetration": 0.92, "gdp_per_capita": 29.7,
           "freedom_total": 93, "freedom_on_net": 93, "press_freedom": 88, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 8,
           "neighbors": ["FI", "LV", "RU"]},
    "LV": {"name": "Latvia", "population": 1.87, "internet_penetration": 0.90, "gdp_per_capita": 22.0,
           "freedom_total": 89, "freedom_on_net": None, "press_freedom": 84, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["EE", "LT", "RU", "BY"]},
    "LT": {"name": "Lithuania", "population": 2.83, "internet_penetration": 0.85, "gdp_per_capita": 25.0,
           "freedom_total": 90, "freedom_on_net": None, "press_freedom": 85, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["LV", "PL", "BY", "RU"]},
    "PL": {"name": "Poland", "population": 36.8, "internet_penetration": 0.88, "gdp_per_capita": 18.7,
           "freedom_total": 81, "freedom_on_net": None, "press_freedom": 67, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["DE", "CZ", "SK", "UA", "BY", "LT"]},
    "CZ": {"name": "Czechia", "population": 10.9, "internet_penetration": 0.82, "gdp_per_capita": 27.2,
           "freedom_total": 91, "freedom_on_net": None, "press_freedom": 82, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["DE", "AT", "PL", "SK"]},
    "SK": {"name": "Slovakia", "population": 5.4, "internet_penetration": 0.86, "gdp_per_capita": 21.4,
           "freedom_total": 90, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["CZ", "PL", "UA", "HU", "AT"]},
    "HU": {"name": "Hungary", "population": 9.7, "internet_penetration": 0.89, "gdp_per_capita": 19.0,
           "freedom_total": 65, "freedom_on_net": 70, "press_freedom": 54, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": ["AT", "SK", "UA", "RO", "RS", "HR", "SI"]},
    "SI": {"name": "Slovenia", "population": 2.1, "internet_penetration": 0.88, "gdp_per_capita": 29.0,
           "freedom_total": 95, "freedom_on_net": None, "press_freedom": 79, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["AT", "HU", "HR", "IT"]},
    "HR": {"name": "Croatia", "population": 3.9, "internet_penetration": 0.81, "gdp_per_capita": 17.4,
           "freedom_total": 85, "freedom_on_net": None, "press_freedom": 75, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["SI", "HU", "RS", "BA"]},
    "RO": {"name": "Romania", "population": 19.0, "internet_penetration": 0.81, "gdp_per_capita": 15.9,
           "freedom_total": 83, "freedom_on_net": None, "press_freedom": 72, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["HU", "UA", "MD", "BG", "RS"]},
    "BG": {"name": "Bulgaria", "population": 6.8, "internet_penetration": 0.79, "gdp_per_capita": 14.0,
           "freedom_total": 78, "freedom_on_net": None, "press_freedom": 59, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["RO", "RS", "MK", "GR", "TR"]},
    "GR": {"name": "Greece", "population": 10.4, "internet_penetration": 0.85, "gdp_per_capita": 22.0,
           "freedom_total": 85, "freedom_on_net": None, "press_freedom": 51, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["BG", "MK", "AL", "TR"]},
    "AL": {"name": "Albania", "population": 2.8, "internet_penetration": 0.83, "gdp_per_capita": 6.7,
           "freedom_total": 67, "freedom_on_net": None, "press_freedom": 62, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 5,
           "neighbors": ["GR", "MK", "RS", "ME"]},
    "MK": {"name": "North Macedonia", "population": 2.1, "internet_penetration": 0.86, "gdp_per_capita": 7.7,
           "freedom_total": 66, "freedom_on_net": None, "press_freedom": 65, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 5,
           "neighbors": ["GR", "BG", "RS", "AL"]},
    "RS": {"name": "Serbia", "population": 6.7, "internet_penetration": 0.84, "gdp_per_capita": 11.0,
           "freedom_total": 57, "freedom_on_net": None, "press_freedom": 54, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["HU", "RO", "BG", "MK", "AL", "BA", "HR"]},
    "MD": {"name": "Moldova", "population": 2.5, "internet_penetration": 0.82, "gdp_per_capita": 6.1,
           "freedom_total": 62, "freedom_on_net": None, "press_freedom": 68, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["RO", "UA"]},
    "UA": {"name": "Ukraine", "population": 37.0, "internet_penetration": 0.80, "gdp_per_capita": 5.7,
           "freedom_total": 49, "freedom_on_net": 58, "press_freedom": 63, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["PL", "SK", "HU", "RO", "MD", "RU", "BY"]},
    "CY": {"name": "Cyprus", "population": 1.25, "internet_penetration": 0.92, "gdp_per_capita": 32.0,
           "freedom_total": 93, "freedom_on_net": None, "press_freedom": 73, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": []},
    "MT": {"name": "Malta", "population": 0.55, "internet_penetration": 0.88, "gdp_per_capita": 37.0,
           "freedom_total": 89, "freedom_on_net": None, "press_freedom": 74, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 8,
           "neighbors": []},
    "XK": {"name": "Kosovo", "population": 1.7, "internet_penetration": 0.93, "gdp_per_capita": 6.0,
           "freedom_total": 60, "freedom_on_net": None, "press_freedom": 57, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 5,
           "neighbors": ["AL", "MK", "RS"]},

    # --- Eastern Europe / CIS ---
    "RU": {"name": "Russia", "population": 143.0, "internet_penetration": 0.88, "gdp_per_capita": 14.4,
           "freedom_total": 13, "freedom_on_net": 22, "press_freedom": 30, "vpn_legal": "restricted",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 3,
           "neighbors": ["FI", "NO", "EE", "LV", "LT", "BY", "UA", "GE", "AZ", "KZ"]},
    "BY": {"name": "Belarus", "population": 9.2, "internet_penetration": 0.87, "gdp_per_capita": 7.9,
           "freedom_total": 8, "freedom_on_net": 25, "press_freedom": 24, "vpn_legal": "restricted",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["LV", "LT", "PL", "UA", "RU"]},
    "GE": {"name": "Georgia", "population": 3.7, "internet_penetration": 0.79, "gdp_per_capita": 7.2,
           "freedom_total": 58, "freedom_on_net": None, "press_freedom": 60, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["RU", "AZ", "AM", "TR"]},
    "AZ": {"name": "Azerbaijan", "population": 10.1, "internet_penetration": 0.86, "gdp_per_capita": 7.8,
           "freedom_total": 7, "freedom_on_net": 33, "press_freedom": 25, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["GE", "AM", "RU", "TR"]},
    "KZ": {"name": "Kazakhstan", "population": 19.6, "internet_penetration": 0.89, "gdp_per_capita": 11.2,
           "freedom_total": 23, "freedom_on_net": 32, "press_freedom": 35, "vpn_legal": "restricted",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["RU", "CN", "KG", "UZ"]},

    # --- High-risk countries (no hosting - but relevant as neighbors) ---
    "CN": {"name": "China", "population": 1410.0, "internet_penetration": 0.76, "gdp_per_capita": 13.1,
           "freedom_total": 9, "freedom_on_net": 9, "press_freedom": 25, "vpn_legal": "forbidden",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 1,
           "neighbors": ["RU", "KZ", "KG", "MN", "VN", "HK", "TW"]},  # reachable privacy-friendly neighbors
    "IR": {"name": "Iran", "population": 89.0, "internet_penetration": 0.84, "gdp_per_capita": 4.5,
           "freedom_total": 12, "freedom_on_net": 11, "press_freedom": 21, "vpn_legal": "forbidden",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 2,
           "neighbors": ["TR", "AM", "AZ", "IQ", "PK", "AE", "OM"]},
    # --- Asia ---
    "TR": {"name": "Turkey", "population": 85.8, "internet_penetration": 0.83, "gdp_per_capita": 13.1,
           "freedom_total": 32, "freedom_on_net": 32, "press_freedom": 32, "vpn_legal": "restricted",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": ["GR", "BG", "GE", "AM", "AZ", "IR", "IQ", "SY"]},

    # --- Strategic gateways near authoritarian neighbors ---
    "MN": {"name": "Mongolia", "population": 3.4, "internet_penetration": 0.84, "gdp_per_capita": 5.4,
           "freedom_total": 85, "freedom_on_net": None, "press_freedom": 65, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 6,
           "neighbors": ["RU", "CN"]},  # Direct gateway for Chinese + Russian users
    "KG": {"name": "Kyrgyzstan", "population": 6.8, "internet_penetration": 0.78, "gdp_per_capita": 2.0,
           "freedom_total": 27, "freedom_on_net": 56, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "caution",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["KZ", "CN", "UZ", "TJ"]},
    "UZ": {"name": "Uzbekistan", "population": 36.0, "internet_penetration": 0.81, "gdp_per_capita": 2.5,
           "freedom_total": 12, "freedom_on_net": 27, "press_freedom": 30, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 3,
           "neighbors": ["KZ", "KG", "TJ", "AF"]},
    "TJ": {"name": "Tajikistan", "population": 10.1, "internet_penetration": 0.51, "gdp_per_capita": 1.2,
           "freedom_total": 5, "freedom_on_net": 23, "press_freedom": 27, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 2,
           "neighbors": ["UZ", "KG", "AF", "CN"]},
    "AF": {"name": "Afghanistan", "population": 42.2, "internet_penetration": 0.18, "gdp_per_capita": 0.4,
           "freedom_total": 6, "freedom_on_net": None, "press_freedom": 25, "vpn_legal": "restricted",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 1,
           "neighbors": ["PK", "IR", "TJ", "UZ"]},
    "PK": {"name": "Pakistan", "population": 240.0, "internet_penetration": 0.36, "gdp_per_capita": 1.6,
           "freedom_total": 35, "freedom_on_net": 26, "press_freedom": 33, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 2,
           "neighbors": ["IN", "AF", "IR"]},
    "AM": {"name": "Armenia", "population": 2.97, "internet_penetration": 0.80, "gdp_per_capita": 6.6,
           "freedom_total": 54, "freedom_on_net": None, "press_freedom": 65, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["GE", "AZ", "TR", "IR"]},  # Iran neighbor, Christian, pro-Western - good entry for Iranians
    "JO": {"name": "Jordan", "population": 11.2, "internet_penetration": 0.88, "gdp_per_capita": 4.4,
           "freedom_total": 33, "freedom_on_net": 45, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 4,
           "neighbors": ["SA", "IQ", "SY", "IL"]},
    "OM": {"name": "Oman", "population": 4.6, "internet_penetration": 0.95, "gdp_per_capita": 21.0,
           "freedom_total": 24, "freedom_on_net": None, "press_freedom": 40, "vpn_legal": "restricted",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["SA", "AE", "IR"]},
    "IL": {"name": "Israel", "population": 9.5, "internet_penetration": 0.88, "gdp_per_capita": 52.0,
           "freedom_total": 74, "freedom_on_net": 71, "press_freedom": 54, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 7,
           "neighbors": ["JO"]},
    "PH": {"name": "Philippines", "population": 115.0, "internet_penetration": 0.73, "gdp_per_capita": 3.9,
           "freedom_total": 55, "freedom_on_net": 63, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": []},  # SE Asia gateway
    "MM": {"name": "Myanmar", "population": 54.0, "internet_penetration": 0.45, "gdp_per_capita": 1.3,
           "freedom_total": 8, "freedom_on_net": 10, "press_freedom": 24, "vpn_legal": "forbidden",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 2,
           "neighbors": ["TH", "IN", "CN"]},

    # --- Caribbean / Americas (for Cuba, Venezuela gateway) ---
    "CU": {"name": "Cuba", "population": 11.2, "internet_penetration": 0.71, "gdp_per_capita": 9.1,
           "freedom_total": 12, "freedom_on_net": 21, "press_freedom": 20, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 2,
           "neighbors": []},
    "VE": {"name": "Venezuela", "population": 28.7, "internet_penetration": 0.72, "gdp_per_capita": 3.5,
           "freedom_total": 15, "freedom_on_net": 30, "press_freedom": 32, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["CO", "BR"]},
    "DO": {"name": "Dominican Republic", "population": 11.3, "internet_penetration": 0.85, "gdp_per_capita": 10.7,
           "freedom_total": 69, "freedom_on_net": None, "press_freedom": 69, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": []},
    "BS": {"name": "Bahamas", "population": 0.41, "internet_penetration": 0.95, "gdp_per_capita": 35.0,
           "freedom_total": 91, "freedom_on_net": None, "press_freedom": 82, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 8,
           "neighbors": []},
    "CR": {"name": "Costa Rica", "population": 5.2, "internet_penetration": 0.84, "gdp_per_capita": 13.4,
           "freedom_total": 91, "freedom_on_net": None, "press_freedom": 85, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": []},

    # --- Africa: gateways near censorship ---
    "KE": {"name": "Kenya", "population": 55.0, "internet_penetration": 0.42, "gdp_per_capita": 2.1,
           "freedom_total": 48, "freedom_on_net": 66, "press_freedom": 55, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": []},
    "TN": {"name": "Tunisia", "population": 12.4, "internet_penetration": 0.79, "gdp_per_capita": 4.0,
           "freedom_total": 64, "freedom_on_net": 60, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "caution",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": []},
    "JP": {"name": "Japan", "population": 125.0, "internet_penetration": 0.83, "gdp_per_capita": 34.0,
           "freedom_total": 96, "freedom_on_net": 78, "press_freedom": 58, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["KR"]},
    "KR": {"name": "South Korea", "population": 51.7, "internet_penetration": 0.97, "gdp_per_capita": 33.0,
           "freedom_total": 83, "freedom_on_net": 66, "press_freedom": 64, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["JP"]},
    "TW": {"name": "Taiwan", "population": 23.5, "internet_penetration": 0.92, "gdp_per_capita": 32.0,
           "freedom_total": 94, "freedom_on_net": 78, "press_freedom": 75, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": []},
    "HK": {"name": "Hong Kong", "population": 7.4, "internet_penetration": 0.94, "gdp_per_capita": 52.0,
           "freedom_total": 41, "freedom_on_net": 50, "press_freedom": 58, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": []},
    "SG": {"name": "Singapore", "population": 5.9, "internet_penetration": 0.92, "gdp_per_capita": 82.8,
           "freedom_total": 48, "freedom_on_net": 55, "press_freedom": 45, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 7,
           "neighbors": ["MY"]},
    "MY": {"name": "Malaysia", "population": 33.4, "internet_penetration": 0.97, "gdp_per_capita": 11.7,
           "freedom_total": 53, "freedom_on_net": 58, "press_freedom": 52, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": ["SG", "TH", "ID"]},
    "TH": {"name": "Thailand", "population": 71.6, "internet_penetration": 0.85, "gdp_per_capita": 7.2,
           "freedom_total": 30, "freedom_on_net": 39, "press_freedom": 45, "vpn_legal": "restricted",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": ["MY", "KH", "VN", "MM"]},
    "VN": {"name": "Vietnam", "population": 98.9, "internet_penetration": 0.78, "gdp_per_capita": 4.3,
           "freedom_total": 19, "freedom_on_net": 22, "press_freedom": 22, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": ["TH", "KH", "CN"]},
    "KH": {"name": "Cambodia", "population": 16.9, "internet_penetration": 0.79, "gdp_per_capita": 1.8,
           "freedom_total": 23, "freedom_on_net": None, "press_freedom": 26, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["TH", "VN"]},
    "ID": {"name": "Indonesia", "population": 279.0, "internet_penetration": 0.77, "gdp_per_capita": 4.8,
           "freedom_total": 58, "freedom_on_net": 48, "press_freedom": 52, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["MY"]},
    "IN": {"name": "India", "population": 1428.0, "internet_penetration": 0.52, "gdp_per_capita": 2.5,
           "freedom_total": 63, "freedom_on_net": 50, "press_freedom": 31, "vpn_legal": "restricted",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["PK"]},
    "AE": {"name": "UAE", "population": 9.5, "internet_penetration": 0.99, "gdp_per_capita": 51.9,
           "freedom_total": 18, "freedom_on_net": 28, "press_freedom": 30, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 7,
           "neighbors": ["SA", "OM"]},
    "SA": {"name": "Saudi Arabia", "population": 36.9, "internet_penetration": 0.99, "gdp_per_capita": 27.9,
           "freedom_total": 8, "freedom_on_net": 24, "press_freedom": 25, "vpn_legal": "restricted",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": ["AE", "OM", "JO"]},
    "BH": {"name": "Bahrain", "population": 1.5, "internet_penetration": 0.99, "gdp_per_capita": 29.0,
           "freedom_total": 12, "freedom_on_net": 26, "press_freedom": 29, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 5,
           "neighbors": []},
    "EG": {"name": "Egypt", "population": 113.0, "internet_penetration": 0.72, "gdp_per_capita": 3.9,
           "freedom_total": 18, "freedom_on_net": 28, "press_freedom": 32, "vpn_legal": "restricted",
           "operator_risk": "dangerous",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 3,
           "neighbors": []},

    # --- Africa ---
    "ZA": {"name": "South Africa", "population": 60.4, "internet_penetration": 0.75, "gdp_per_capita": 7.1,
           "freedom_total": 79, "freedom_on_net": 73, "press_freedom": 73, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": []},
    "NG": {"name": "Nigeria", "population": 223.0, "internet_penetration": 0.55, "gdp_per_capita": 2.1,
           "freedom_total": 43, "freedom_on_net": 54, "press_freedom": 48, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["NE"]},
    "NE": {"name": "Niger", "population": 27.2, "internet_penetration": 0.22, "gdp_per_capita": 0.6,
           "freedom_total": 39, "freedom_on_net": None, "press_freedom": 52, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 3,
           "neighbors": ["NG", "ML"]},
    "ML": {"name": "Mali", "population": 23.3, "internet_penetration": 0.37, "gdp_per_capita": 0.9,
           "freedom_total": 28, "freedom_on_net": None, "press_freedom": 41, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 3,
           "neighbors": ["NE"]},
    "MA": {"name": "Morocco", "population": 37.8, "internet_penetration": 0.90, "gdp_per_capita": 3.8,
           "freedom_total": 37, "freedom_on_net": 53, "press_freedom": 42, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 4,
           "neighbors": []},

    # --- South America / Latam ---
    "BR": {"name": "Brazil", "population": 216.0, "internet_penetration": 0.82, "gdp_per_capita": 9.3,
           "freedom_total": 72, "freedom_on_net": 65, "press_freedom": 58, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["AR", "BO", "PE", "CO"]},
    "AR": {"name": "Argentina", "population": 46.2, "internet_penetration": 0.87, "gdp_per_capita": 13.6,
           "freedom_total": 85, "freedom_on_net": 72, "press_freedom": 63, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["BR", "CL", "BO"]},
    "CL": {"name": "Chile", "population": 19.6, "internet_penetration": 0.90, "gdp_per_capita": 15.3,
           "freedom_total": 94, "freedom_on_net": None, "press_freedom": 82, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["AR", "BO", "PE"]},
    "BO": {"name": "Bolivia", "population": 12.4, "internet_penetration": 0.64, "gdp_per_capita": 3.5,
           "freedom_total": 65, "freedom_on_net": None, "press_freedom": 58, "vpn_legal": "legal",
           "tor_friendly": False, "five_eyes": None, "data_retention": "minimal", "crypto_friendly": 4,
           "neighbors": ["BR", "AR", "CL", "PE"]},
    "PE": {"name": "Peru", "population": 34.4, "internet_penetration": 0.74, "gdp_per_capita": 7.1,
           "freedom_total": 71, "freedom_on_net": None, "press_freedom": 57, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["BR", "CL", "BO", "EC", "CO"]},
    "EC": {"name": "Ecuador", "population": 18.2, "internet_penetration": 0.74, "gdp_per_capita": 6.4,
           "freedom_total": 67, "freedom_on_net": None, "press_freedom": 53, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["PE", "CO"]},
    "CO": {"name": "Colombia", "population": 52.3, "internet_penetration": 0.73, "gdp_per_capita": 6.7,
           "freedom_total": 71, "freedom_on_net": None, "press_freedom": 57, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["BR", "PE", "EC"]},

    # --- Oceania ---
    "AU": {"name": "Australia", "population": 26.6, "internet_penetration": 0.95, "gdp_per_capita": 63.5,
           "freedom_total": 95, "freedom_on_net": 75, "press_freedom": 77, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "five", "data_retention": "aggressive", "crypto_friendly": 7,
           "neighbors": ["NZ"]},
    "NZ": {"name": "New Zealand", "population": 5.2, "internet_penetration": 0.95, "gdp_per_capita": 47.8,
           "freedom_total": 99, "freedom_on_net": 87, "press_freedom": 84, "vpn_legal": "legal",
           "tor_friendly": True, "five_eyes": "five", "data_retention": "moderate", "crypto_friendly": 7,
           "neighbors": ["AU"]},

    # --- Missing Balkan/Middle East neighbors (referenced above but were undefined) ---
    "BA": {"name": "Bosnia and Herzegovina", "population": 3.2, "internet_penetration": 0.78, "gdp_per_capita": 7.7,
           "freedom_total": 51, "freedom_on_net": None, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 5,
           "neighbors": ["HR", "RS", "ME"]},
    "ME": {"name": "Montenegro", "population": 0.62, "internet_penetration": 0.83, "gdp_per_capita": 11.5,
           "freedom_total": 60, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "operator_risk": "safe",
           "tor_friendly": True, "five_eyes": None, "data_retention": "moderate", "crypto_friendly": 6,
           "neighbors": ["AL", "RS", "BA", "HR"]},
    "IQ": {"name": "Iraq", "population": 44.5, "internet_penetration": 0.79, "gdp_per_capita": 5.6,
           "freedom_total": 29, "freedom_on_net": 32, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "caution",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 3,
           "neighbors": ["TR", "IR", "JO", "SA", "SY"]},
    "SY": {"name": "Syria", "population": 23.0, "internet_penetration": 0.42, "gdp_per_capita": 1.2,
           "freedom_total": 1, "freedom_on_net": 8, "press_freedom": 15, "vpn_legal": "forbidden",
           "operator_risk": "extreme",
           "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive", "crypto_friendly": 1,
           "neighbors": ["TR", "IQ", "JO", "IL"]},

    # --- Europe (fill-ins) ---
    "AD": {"name": "Andorra", "population": 0.08, "internet_penetration": 0.95, "gdp_per_capita": 42.0,
           "freedom_total": 92, "freedom_on_net": None, "press_freedom": 78, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "minimal",
           "crypto_friendly": 6, "neighbors": ["ES", "FR"]},
    "LI": {"name": "Liechtenstein", "population": 0.04, "internet_penetration": 0.97, "gdp_per_capita": 184.0,
           "freedom_total": 96, "freedom_on_net": None, "press_freedom": 84, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "minimal",
           "crypto_friendly": 8, "neighbors": ["CH", "AT"]},
    "MC": {"name": "Monaco", "population": 0.04, "internet_penetration": 0.97, "gdp_per_capita": 234.0,
           "freedom_total": 84, "freedom_on_net": None, "press_freedom": 75, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 6, "neighbors": ["FR"]},
    "SM": {"name": "San Marino", "population": 0.034, "internet_penetration": 0.65, "gdp_per_capita": 60.0,
           "freedom_total": 97, "freedom_on_net": None, "press_freedom": 88, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "minimal",
           "crypto_friendly": 6, "neighbors": ["IT"]},

    # --- Asia (fill-ins) ---
    "BD": {"name": "Bangladesh", "population": 173.0, "internet_penetration": 0.39, "gdp_per_capita": 2.5,
           "freedom_total": 40, "freedom_on_net": 40, "press_freedom": 35, "vpn_legal": "restricted",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": ["IN"]},
    "LK": {"name": "Sri Lanka", "population": 22.0, "internet_penetration": 0.57, "gdp_per_capita": 3.4,
           "freedom_total": 56, "freedom_on_net": 50, "press_freedom": 53, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": []},
    "NP": {"name": "Nepal", "population": 30.5, "internet_penetration": 0.51, "gdp_per_capita": 1.4,
           "freedom_total": 64, "freedom_on_net": None, "press_freedom": 65, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": ["IN", "CN"]},
    "BT": {"name": "Bhutan", "population": 0.78, "internet_penetration": 0.85, "gdp_per_capita": 3.7,
           "freedom_total": 66, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": ["IN", "CN"]},
    "MV": {"name": "Maldives", "population": 0.52, "internet_penetration": 0.75, "gdp_per_capita": 12.5,
           "freedom_total": 53, "freedom_on_net": None, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": []},
    "LA": {"name": "Laos", "population": 7.6, "internet_penetration": 0.62, "gdp_per_capita": 2.0,
           "freedom_total": 13, "freedom_on_net": None, "press_freedom": 25, "vpn_legal": "restricted",
           "operator_risk": "dangerous", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 2, "neighbors": ["TH", "VN", "CN", "MM", "KH"]},
    "BN": {"name": "Brunei", "population": 0.45, "internet_penetration": 0.97, "gdp_per_capita": 33.0,
           "freedom_total": 28, "freedom_on_net": None, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 4, "neighbors": ["MY"]},
    "TL": {"name": "Timor-Leste", "population": 1.36, "internet_penetration": 0.40, "gdp_per_capita": 2.6,
           "freedom_total": 71, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 3, "neighbors": ["ID"]},
    "PG": {"name": "Papua New Guinea", "population": 10.4, "internet_penetration": 0.32, "gdp_per_capita": 2.9,
           "freedom_total": 60, "freedom_on_net": None, "press_freedom": 50, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 3, "neighbors": ["ID"]},

    # --- Middle East (fill-ins) ---
    "LB": {"name": "Lebanon", "population": 5.5, "internet_penetration": 0.86, "gdp_per_capita": 4.4,
           "freedom_total": 43, "freedom_on_net": 51, "press_freedom": 50, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": ["SY", "IL"]},
    "PS": {"name": "Palestine", "population": 5.4, "internet_penetration": 0.76, "gdp_per_capita": 3.5,
           "freedom_total": 23, "freedom_on_net": 35, "press_freedom": 33, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": ["IL", "JO", "EG"]},
    "YE": {"name": "Yemen", "population": 33.7, "internet_penetration": 0.27, "gdp_per_capita": 0.9,
           "freedom_total": 9, "freedom_on_net": 14, "press_freedom": 18, "vpn_legal": "restricted",
           "operator_risk": "extreme", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 1, "neighbors": ["SA", "OM"]},
    "QA": {"name": "Qatar", "population": 2.9, "internet_penetration": 0.99, "gdp_per_capita": 87.5,
           "freedom_total": 25, "freedom_on_net": 37, "press_freedom": 45, "vpn_legal": "restricted",
           "operator_risk": "dangerous", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 5, "neighbors": ["SA"]},
    "KW": {"name": "Kuwait", "population": 4.3, "internet_penetration": 0.99, "gdp_per_capita": 32.0,
           "freedom_total": 37, "freedom_on_net": None, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 4, "neighbors": ["SA", "IQ"]},

    # --- Africa (significant) ---
    "DZ": {"name": "Algeria", "population": 45.0, "internet_penetration": 0.71, "gdp_per_capita": 4.5,
           "freedom_total": 32, "freedom_on_net": 35, "press_freedom": 36, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": ["TN", "MA"]},
    "LY": {"name": "Libya", "population": 6.9, "internet_penetration": 0.46, "gdp_per_capita": 6.0,
           "freedom_total": 9, "freedom_on_net": None, "press_freedom": 27, "vpn_legal": "restricted",
           "operator_risk": "extreme", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 2, "neighbors": ["EG", "TN", "DZ", "NE"]},
    "SD": {"name": "Sudan", "population": 47.0, "internet_penetration": 0.31, "gdp_per_capita": 0.8,
           "freedom_total": 8, "freedom_on_net": None, "press_freedom": 24, "vpn_legal": "restricted",
           "operator_risk": "extreme", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 2, "neighbors": ["EG", "LY"]},
    "ET": {"name": "Ethiopia", "population": 126.0, "internet_penetration": 0.25, "gdp_per_capita": 1.1,
           "freedom_total": 21, "freedom_on_net": 27, "press_freedom": 32, "vpn_legal": "restricted",
           "operator_risk": "dangerous", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 2, "neighbors": []},
    "TZ": {"name": "Tanzania", "population": 65.0, "internet_penetration": 0.31, "gdp_per_capita": 1.2,
           "freedom_total": 32, "freedom_on_net": None, "press_freedom": 42, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 3, "neighbors": ["KE"]},
    "UG": {"name": "Uganda", "population": 47.0, "internet_penetration": 0.27, "gdp_per_capita": 1.0,
           "freedom_total": 34, "freedom_on_net": 51, "press_freedom": 45, "vpn_legal": "restricted",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": ["KE", "TZ"]},
    "RW": {"name": "Rwanda", "population": 13.5, "internet_penetration": 0.30, "gdp_per_capita": 1.0,
           "freedom_total": 23, "freedom_on_net": None, "press_freedom": 30, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": ["UG", "TZ"]},
    "GH": {"name": "Ghana", "population": 33.5, "internet_penetration": 0.69, "gdp_per_capita": 2.3,
           "freedom_total": 80, "freedom_on_net": None, "press_freedom": 72, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": []},
    "SN": {"name": "Senegal", "population": 17.7, "internet_penetration": 0.65, "gdp_per_capita": 1.7,
           "freedom_total": 67, "freedom_on_net": None, "press_freedom": 58, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": []},
    "CI": {"name": "Côte d'Ivoire", "population": 28.0, "internet_penetration": 0.45, "gdp_per_capita": 2.6,
           "freedom_total": 49, "freedom_on_net": None, "press_freedom": 55, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": []},
    "AO": {"name": "Angola", "population": 35.6, "internet_penetration": 0.36, "gdp_per_capita": 2.2,
           "freedom_total": 30, "freedom_on_net": None, "press_freedom": 35, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": []},
    "ZW": {"name": "Zimbabwe", "population": 16.3, "internet_penetration": 0.35, "gdp_per_capita": 1.8,
           "freedom_total": 28, "freedom_on_net": None, "press_freedom": 35, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": ["ZA"]},
    "BW": {"name": "Botswana", "population": 2.6, "internet_penetration": 0.65, "gdp_per_capita": 7.5,
           "freedom_total": 72, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": ["ZA", "ZW"]},
    "NA": {"name": "Namibia", "population": 2.6, "internet_penetration": 0.55, "gdp_per_capita": 4.9,
           "freedom_total": 77, "freedom_on_net": None, "press_freedom": 78, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": ["ZA", "BW", "AO"]},
    "MZ": {"name": "Mozambique", "population": 33.0, "internet_penetration": 0.21, "gdp_per_capita": 0.6,
           "freedom_total": 38, "freedom_on_net": None, "press_freedom": 45, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 3, "neighbors": ["ZA", "TZ", "ZW"]},
    "MG": {"name": "Madagascar", "population": 30.0, "internet_penetration": 0.20, "gdp_per_capita": 0.5,
           "freedom_total": 60, "freedom_on_net": None, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 3, "neighbors": []},
    "MU": {"name": "Mauritius", "population": 1.27, "internet_penetration": 0.66, "gdp_per_capita": 11.4,
           "freedom_total": 86, "freedom_on_net": None, "press_freedom": 73, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 6, "neighbors": []},
    "SC": {"name": "Seychelles", "population": 0.10, "internet_penetration": 0.81, "gdp_per_capita": 17.5,
           "freedom_total": 78, "freedom_on_net": None, "press_freedom": 75, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "minimal",
           "crypto_friendly": 7, "neighbors": []},

    # --- Latin America (fill-ins) ---
    "PA": {"name": "Panama", "population": 4.5, "internet_penetration": 0.69, "gdp_per_capita": 17.6,
           "freedom_total": 83, "freedom_on_net": None, "press_freedom": 70, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 7, "neighbors": ["CO"]},
    "PY": {"name": "Paraguay", "population": 6.9, "internet_penetration": 0.78, "gdp_per_capita": 6.2,
           "freedom_total": 65, "freedom_on_net": None, "press_freedom": 60, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": ["AR", "BR", "BO"]},
    "UY": {"name": "Uruguay", "population": 3.4, "internet_penetration": 0.91, "gdp_per_capita": 21.5,
           "freedom_total": 96, "freedom_on_net": None, "press_freedom": 80, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 7, "neighbors": ["AR", "BR"]},
    "HN": {"name": "Honduras", "population": 10.5, "internet_penetration": 0.59, "gdp_per_capita": 2.8,
           "freedom_total": 47, "freedom_on_net": None, "press_freedom": 50, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": False, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 4, "neighbors": []},
    "NI": {"name": "Nicaragua", "population": 6.9, "internet_penetration": 0.55, "gdp_per_capita": 2.3,
           "freedom_total": 23, "freedom_on_net": 30, "press_freedom": 30, "vpn_legal": "restricted",
           "operator_risk": "dangerous", "tor_friendly": False, "five_eyes": None, "data_retention": "aggressive",
           "crypto_friendly": 3, "neighbors": []},
    "SV": {"name": "El Salvador", "population": 6.4, "internet_penetration": 0.58, "gdp_per_capita": 4.5,
           "freedom_total": 53, "freedom_on_net": None, "press_freedom": 50, "vpn_legal": "legal",
           "operator_risk": "caution", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 8, "neighbors": []},
    "JM": {"name": "Jamaica", "population": 2.8, "internet_penetration": 0.68, "gdp_per_capita": 5.7,
           "freedom_total": 79, "freedom_on_net": None, "press_freedom": 73, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": []},
    "TT": {"name": "Trinidad and Tobago", "population": 1.4, "internet_penetration": 0.79, "gdp_per_capita": 18.0,
           "freedom_total": 81, "freedom_on_net": None, "press_freedom": 76, "vpn_legal": "legal",
           "operator_risk": "safe", "tor_friendly": True, "five_eyes": None, "data_retention": "moderate",
           "crypto_friendly": 5, "neighbors": []},

    # --- Eurasian fill-ins ---
    "CN_NE": {"name": "Mongolia North", "population": 0, "internet_penetration": 0, "gdp_per_capita": 0,
              "freedom_total": 0, "freedom_on_net": None, "press_freedom": 0, "vpn_legal": "legal",
              "operator_risk": "safe", "tor_friendly": False, "five_eyes": None, "data_retention": "moderate",
              "crypto_friendly": 0, "neighbors": []},  # placeholder, removed below
}
# Cleanup placeholder
COUNTRIES.pop("CN_NE", None)


def country_score(cc, nodes_count, total_network_nodes):
    """
    Compute a 'where to deploy' score for a country.

    Returns dict with:
    - score: 0-100 composite
    - classification: "highly_recommended" | "good" | "saturated" | "legal_grey" | "avoid"
    - reasoning: list of human-readable reasons
    """
    c = COUNTRIES.get(cc)
    if not c:
        return {"score": 0, "classification": "unknown", "reasoning": ["no data for this country"]}

    reasons = []  # List of {"code": "...", "params": {...}} for i18n on frontend

    # --- Hard operator risk blockers ---
    op_risk = c.get("operator_risk", "safe")
    if op_risk in ("extreme", "dangerous") or c.get("vpn_legal") == "forbidden":
        # Still compute demand so we can show "ideal target if risk didn't exist"
        share = nodes_count / max(total_network_nodes, 1)
        internal_d = c["population"] * c["internet_penetration"] * _privacy_awareness(c) * _income_factor(c["gdp_per_capita"])
        # For not_recommended countries, show "users who need VPN" as demand signal
        import math
        demand_score = min(60, math.log10(max(internal_d, 1)) * 20) if internal_d > 0 else 0
        # "Ideal target" = what it would be if not for operator risk
        ideal_target = max(0, int(round(demand_score / 8)))
        cap = int(total_network_nodes * 0.05)
        ideal_target = min(ideal_target, cap) if cap > 0 else ideal_target
        if op_risk == "extreme":
            code = "risk_extreme"
        elif op_risk == "dangerous":
            code = "risk_dangerous"
        else:
            code = "vpn_forbidden"
        return {"score": 0, "classification": "not_recommended",
                "country": c["name"], "nodes_here": nodes_count,
                "target_nodes": ideal_target,
                "needed_nodes": 0,  # Not recommended to deploy, so needed stays 0
                "ideal_target": ideal_target,  # What it would be if safe
                "network_share": round(share * 100, 2),
                "operator_risk": op_risk,
                "reasoning": [{"code": code}]}

    # --- 1. Internal demand ---
    internal = (c["population"]
                * c["internet_penetration"]
                * _privacy_awareness(c)
                * _income_factor(c["gdp_per_capita"]))

    # --- 2. Neighbor entry-gateway demand ---
    neighbor_demand = 0
    for nc in c.get("neighbors", []):
        n = COUNTRIES.get(nc)
        if not n:
            continue
        gradient = max(0, c["freedom_total"] - n["freedom_total"]) / 100
        if gradient <= 0:
            continue  # Neighbor is equally or more free, won't route through X
        neighbor_pool = (n["population"]
                         * n["internet_penetration"]
                         * _privacy_awareness(n))
        neighbor_demand += neighbor_pool * gradient
        if n["freedom_total"] < 40 and n["population"] > 20:
            reasons.append({"code": "neighbor_restricted", "params": {"cc": nc, "name": n["name"], "population_m": int(n["population"])}})

    # --- 3. Strategic value ---
    strategic = 0
    if c.get("five_eyes") is None:
        strategic += 15
        reasons.append({"code": "not_in_eyes"})
    elif c.get("five_eyes") == "fourteen":
        strategic -= 5
    elif c.get("five_eyes") in ("five", "nine"):
        strategic -= 15
        reasons.append({"code": "in_eyes", "params": {"tier": c["five_eyes"]}})

    if c.get("data_retention") == "minimal":
        strategic += 10
        reasons.append({"code": "minimal_retention"})
    elif c.get("data_retention") == "aggressive":
        strategic -= 10

    if c.get("crypto_friendly", 0) >= 8:
        strategic += 8

    if c.get("vpn_legal") == "restricted":
        strategic -= 25
        reasons.append({"code": "vpn_restricted"})

    # --- 4. Saturation penalty ---
    share = nodes_count / max(total_network_nodes, 1)
    saturation_penalty = max(0, share - 0.05) * 300
    if share > 0.10:
        reasons.append({"code": "oversaturated", "params": {"pct": round(share*100, 1)}})
    elif share > 0.05:
        reasons.append({"code": "approaching_saturation", "params": {"pct": round(share*100, 1)}})

    # --- Composite ---
    # Normalize demand: log-scale since populations vary 1000x (0.4M to 1.4B)
    import math
    demand_raw = internal + neighbor_demand
    # log10(1) = 0, log10(1000) = 3. Scale to 0-60 range for reasonable countries.
    demand_score = min(60, math.log10(max(demand_raw, 1)) * 20) if demand_raw > 0 else 0
    # Base score from demand (0-60) + strategic (-40 to +40) - saturation (0+)
    raw = demand_score + strategic - saturation_penalty
    # Floor at 0, cap at 100
    raw = max(0, min(100, raw))

    # --- Classification (order matters - most specific first) ---
    if op_risk == "caution":
        classification = "caution"
        reasons.insert(0, {"code": "caution"})
    elif saturation_penalty >= 15:
        classification = "saturated"
    elif raw >= 55:
        classification = "highly_recommended"
    elif raw >= 30:
        classification = "good"
    elif c.get("internet_penetration", 0) < 0.5 or c.get("gdp_per_capita", 0) < 2:
        classification = "low_demand"
    elif raw < 20:
        # Genuinely low demand even with high income - small countries with no censored neighbors
        classification = "low_demand"
    else:
        classification = "good"

    # Target node count: scaled by score, capped at 5% of network
    target_nodes = max(0, int(round(raw / 8)))  # score 80 -> 10 nodes
    cap_at_5pct = int(total_network_nodes * 0.05)
    target_nodes = min(target_nodes, cap_at_5pct) if cap_at_5pct > 0 else target_nodes
    needed = max(0, target_nodes - nodes_count)
    if classification == "saturated":
        needed = 0
        target_nodes = nodes_count  # already saturated, no target growth
    return {
        "score": round(max(0, min(100, raw)), 1),
        "classification": classification,
        "internal_demand": round(internal, 1),
        "neighbor_demand": round(neighbor_demand, 1),
        "strategic_value": strategic,
        "saturation_penalty": round(saturation_penalty, 1),
        "nodes_here": nodes_count,
        "target_nodes": target_nodes,
        "needed_nodes": needed,
        "network_share": round(share * 100, 2),
        "reasoning": reasons,
        "country": c["name"],
        "operator_risk": op_risk,
    }


def _privacy_awareness(c):
    """Proxy for how likely residents are to use mixnet (0-1).
    Higher when: censorship is high (need), income is high (ability), tech adoption high."""
    # Use inverse of press_freedom as proxy for "censorship pressure"
    # and crypto_friendly as proxy for tech/privacy culture
    press = c.get("press_freedom") or 50
    # More censorship = more demand for VPN/mixnet
    censorship_demand = (100 - press) / 100  # 0 (free) - 1 (heavy censorship)
    crypto = (c.get("crypto_friendly") or 5) / 10
    # 50/50 blend: need (censorship) + ability (crypto adoption)
    return 0.3 + 0.4 * censorship_demand + 0.3 * crypto


def _income_factor(gdp_per_capita):
    """Lower factor in low-income countries where paying for mixnet is rare."""
    if gdp_per_capita < 3:
        return 0.3
    if gdp_per_capita < 10:
        return 0.6
    if gdp_per_capita < 30:
        return 0.9
    return 1.0
