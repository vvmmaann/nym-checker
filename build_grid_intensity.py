#!/usr/bin/env python3
"""Build grid_intensity.json from verified Ember Yearly Electricity Data CSV.

Reads Ember CSV (Power sector emissions / CO2 intensity), maps from ISO-3 to our
ISO-2 country codes via direct import of nym_country_data.COUNTRIES, computes 5y
trend, classifies data freshness, and writes a JSON suitable for overlay into the
nym checker country dataset.

Source: https://files.ember-energy.org/public-downloads/yearly_full_release_long_format.csv
License: CC-BY-4.0

Data freshness classification (vs current year):
  fresh   - data <= 1 year old (e.g. 2025 data in 2026)
  recent  - data 2 years old
  aged    - data 3-5 years old
  stale   - data > 5 years old
"""
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

# Allow direct import of nym_country_data for canonical country list
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import nym_country_data as _ncd  # noqa: E402

ISO2_TO_3 = {
    'AD':'AND','AE':'ARE','AF':'AFG','AG':'ATG','AI':'AIA','AL':'ALB','AM':'ARM','AO':'AGO','AR':'ARG','AT':'AUT',
    'AU':'AUS','AW':'ABW','AZ':'AZE','BA':'BIH','BB':'BRB','BD':'BGD','BE':'BEL','BF':'BFA','BG':'BGR','BH':'BHR',
    'BI':'BDI','BJ':'BEN','BM':'BMU','BN':'BRN','BO':'BOL','BR':'BRA','BS':'BHS','BT':'BTN','BW':'BWA','BY':'BLR',
    'BZ':'BLZ','CA':'CAN','CD':'COD','CF':'CAF','CG':'COG','CH':'CHE','CI':'CIV','CK':'COK','CL':'CHL','CM':'CMR',
    'CN':'CHN','CO':'COL','CR':'CRI','CU':'CUB','CV':'CPV','CY':'CYP','CZ':'CZE','DE':'DEU','DJ':'DJI','DK':'DNK',
    'DM':'DMA','DO':'DOM','DZ':'DZA','EC':'ECU','EE':'EST','EG':'EGY','ER':'ERI','ES':'ESP','ET':'ETH','FI':'FIN',
    'FJ':'FJI','FM':'FSM','FO':'FRO','FR':'FRA','GA':'GAB','GB':'GBR','GD':'GRD','GE':'GEO','GH':'GHA','GI':'GIB',
    'GL':'GRL','GM':'GMB','GN':'GIN','GQ':'GNQ','GR':'GRC','GT':'GTM','GW':'GNB','GY':'GUY','HK':'HKG','HN':'HND',
    'HR':'HRV','HT':'HTI','HU':'HUN','ID':'IDN','IE':'IRL','IL':'ISR','IM':'IMN','IN':'IND','IQ':'IRQ','IR':'IRN',
    'IS':'ISL','IT':'ITA','JM':'JAM','JO':'JOR','JP':'JPN','KE':'KEN','KG':'KGZ','KH':'KHM','KI':'KIR','KM':'COM',
    'KP':'PRK','KR':'KOR','KW':'KWT','KY':'CYM','KZ':'KAZ','LA':'LAO','LB':'LBN','LC':'LCA','LI':'LIE','LK':'LKA',
    'LR':'LBR','LS':'LSO','LT':'LTU','LU':'LUX','LV':'LVA','LY':'LBY','MA':'MAR','MC':'MCO','MD':'MDA','ME':'MNE',
    'MG':'MDG','MH':'MHL','MK':'MKD','ML':'MLI','MM':'MMR','MN':'MNG','MO':'MAC','MR':'MRT','MT':'MLT','MU':'MUS',
    'MV':'MDV','MW':'MWI','MX':'MEX','MY':'MYS','MZ':'MOZ','NA':'NAM','NE':'NER','NG':'NGA','NI':'NIC','NL':'NLD',
    'NO':'NOR','NP':'NPL','NR':'NRU','NZ':'NZL','OM':'OMN','PA':'PAN','PE':'PER','PG':'PNG','PH':'PHL','PK':'PAK',
    'PL':'POL','PR':'PRI','PS':'PSE','PT':'PRT','PW':'PLW','PY':'PRY','QA':'QAT','RO':'ROU','RS':'SRB','RU':'RUS',
    'RW':'RWA','SA':'SAU','SB':'SLB','SC':'SYC','SD':'SDN','SE':'SWE','SG':'SGP','SI':'SVN','SK':'SVK','SL':'SLE',
    'SM':'SMR','SN':'SEN','SO':'SOM','SR':'SUR','SS':'SSD','ST':'STP','SV':'SLV','SY':'SYR','SZ':'SWZ','TD':'TCD',
    'TG':'TGO','TH':'THA','TJ':'TJK','TL':'TLS','TM':'TKM','TN':'TUN','TO':'TON','TR':'TUR','TT':'TTO','TV':'TUV',
    'TW':'TWN','TZ':'TZA','UA':'UKR','UG':'UGA','US':'USA','UY':'URY','UZ':'UZB','VC':'VCT','VE':'VEN','VG':'VGB',
    'VN':'VNM','VU':'VUT','WS':'WSM','XK':'XKX','YE':'YEM','ZA':'ZAF','ZM':'ZMB','ZW':'ZWE',
}


def classify_freshness(data_year: int, current_year: int) -> str:
    lag = current_year - data_year
    if lag <= 1:
        return 'fresh'
    if lag == 2:
        return 'recent'
    if lag <= 5:
        return 'aged'
    return 'stale'


def build(ember_csv_path: str, output_path: str) -> None:
    our_codes = set(_ncd.COUNTRIES.keys())
    current_year = datetime.now(timezone.utc).year

    ember_data: dict[str, dict] = {}
    world_values: dict[int, float] = {}
    with open(ember_csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Subcategory'] != 'CO2 intensity':
                continue
            area_type = row['Area type']
            area_name = row['Area']
            year = int(row['Year'])
            try:
                val = float(row['Value'])
            except ValueError:
                continue
            if area_type == 'Region' and area_name == 'World':
                world_values[year] = val
                continue
            if area_type != 'Country or economy':
                continue
            iso = row['ISO 3 code']
            if not iso:
                continue
            if iso not in ember_data:
                ember_data[iso] = {'name': area_name, 'values': {}}
            ember_data[iso]['values'][year] = val

    world_avg = None
    if world_values:
        latest_world = max(world_values.keys())
        world_avg = {'value': round(world_values[latest_world], 1), 'year': latest_world}

    out: dict = {
        '_meta': {
            'schema_version': '1.1',
            'source_name': 'Ember Yearly Electricity Data',
            'source_indicator': 'Power sector emissions - CO2 intensity',
            'source_url': 'https://files.ember-energy.org/public-downloads/yearly_full_release_long_format.csv',
            'source_landing': 'https://ember-energy.org/data/yearly-electricity-data/',
            'license': 'CC-BY-4.0',
            'unit': 'gCO2/kWh',
            'verified_at': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            'fetched_current_year': current_year,
            'world_average': world_avg,
            'our_countries_total': len(our_codes),
            'coverage_summary': None,
            'freshness_summary': None,
            'country_source_lookup_method': 'direct import of backend.nym_country_data.COUNTRIES (145 keys verified)',
        },
        'countries': {},
    }

    covered = 0
    not_covered: list[str] = []
    freshness_dist: Counter = Counter()
    year_dist: Counter = Counter()
    for code in sorted(our_codes):
        iso3 = ISO2_TO_3.get(code)
        if not iso3 or iso3 not in ember_data:
            not_covered.append(code)
            out['countries'][code] = {
                'iso3': iso3,
                'covered': False,
                'note': 'no Ember data available for this ISO3',
            }
            continue
        entry = ember_data[iso3]
        years = sorted(entry['values'].keys())
        latest = years[-1]
        current = entry['values'][latest]
        five_back = latest - 5
        candidates = [y for y in years if abs(y - five_back) <= 1]
        trend = None
        if candidates:
            ref_year = min(candidates, key=lambda y: abs(y - five_back))
            ref_val = entry['values'][ref_year]
            delta = current - ref_val
            classification = 'flat'
            if delta < -20:
                classification = 'down'
            elif delta > 20:
                classification = 'up'
            trend = {
                'reference_year': ref_year,
                'reference_value': round(ref_val, 1),
                'delta': round(delta, 1),
                'delta_pct': round((delta / ref_val) * 100, 1) if ref_val else None,
                'classification': classification,
            }

        freshness = classify_freshness(latest, current_year)
        freshness_dist[freshness] += 1
        year_dist[latest] += 1

        out['countries'][code] = {
            'iso3': iso3,
            'name': entry['name'],
            'covered': True,
            'intensity_g_per_kwh': round(current, 1),
            'data_year': latest,
            'data_year_lag': current_year - latest,
            'freshness': freshness,
            'trend_5y': trend,
            'world_avg_g_per_kwh': world_avg['value'] if world_avg else None,
        }
        covered += 1

    out['_meta']['coverage_summary'] = {
        'covered': covered,
        'not_covered': len(not_covered),
        'not_covered_codes': not_covered,
        'coverage_pct': round(covered / len(our_codes) * 100, 1),
    }
    out['_meta']['freshness_summary'] = {
        'by_class': dict(freshness_dist),
        'by_year': dict(sorted(year_dist.items())),
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f'Wrote {output_path}: {covered}/{len(our_codes)} covered ({covered/len(our_codes)*100:.1f}%)')
    print(f'Not covered: {not_covered}')
    if world_avg:
        print(f"World avg: {world_avg['value']} g/kWh ({world_avg['year']})")
    print()
    print('Freshness:')
    for cls, n in freshness_dist.most_common():
        print(f'  {cls}: {n}')
    print()
    print('Data-year distribution:')
    for yr in sorted(year_dist):
        print(f'  {yr}: {year_dist[yr]}')


if __name__ == '__main__':
    base = r'C:\Users\uncle\Claude\03_nym_checker'
    ember = sys.argv[1] if len(sys.argv) > 1 else f'{base}\\data\\ember\\yearly_full_release.csv'
    out = sys.argv[2] if len(sys.argv) > 2 else f'{base}\\data\\grid_intensity.json'
    build(ember, out)
