"""Build the temporal CWE dataset from CVE List (cvelistV5) records with CVE IDs from 2021-2026.
Split by publication date: train <= 2023-06-30, dev 2023-07-01..2023-12-31, test-2024, test-2025, test-2026."""
import json, glob, re, sys, os, collections
CV = sys.argv[1]
rows = []; stats = collections.Counter()
for y in range(2021, 2027):
    for p in glob.glob(f'{CV}/cves/{y}/*/CVE-*.json'):
        try: d = json.load(open(p))
        except Exception: stats['bad_json'] += 1; continue
        m = d.get('cveMetadata', {})
        if m.get('state') != 'PUBLISHED': stats['not_published'] += 1; continue
        cna = d['containers'].get('cna', {})
        desc = next((x['value'] for x in cna.get('descriptions', []) if x.get('lang', '').lower().startswith('en')), '').strip()
        if not desc: stats['no_desc'] += 1; continue
        def cw(pts):
            s = []
            for pt in pts or []:
                for x in pt.get('descriptions', []):
                    for c in re.findall(r'CWE-(\d+)', (x.get('cweId') or '') + ' ' + (x.get('description') or '')):
                        if c not in s: s.append(c)
            return s
        cna_c = cw(cna.get('problemTypes')); adp_c = []
        for a in d['containers'].get('adp', []):
            adp_c += [c for c in cw(a.get('problemTypes')) if c not in adp_c]
        labels = sorted(set(cna_c) | set(adp_c))
        if not labels: stats['no_cwe'] += 1; continue
        pub = (m.get('datePublished') or '')[:10]
        if not pub: stats['no_date'] += 1; continue
        rows.append({'id': m['cveId'], 'pub': pub, 'desc': desc, 'cwe': labels, 'cna_cwe': sorted(cna_c), 'adp_cwe': sorted(adp_c),
                     'assigner': m.get('assignerShortName', '')})
def split(r):
    if r['pub'] <= '2023-06-30': return 'train'
    if r['pub'] <= '2023-12-31': return 'dev'
    if r['pub'].startswith('2024'): return 'test2024'
    if r['pub'].startswith('2025'): return 'test2025'
    if r['pub'].startswith('2026'): return 'test2026'
    return 'other'
for r in rows: r['split'] = split(r)
# remove exact-duplicate descriptions across splits (keep earliest) to avoid leakage
seen = {}; dup = 0; keep = []
for r in sorted(rows, key=lambda r: (r['pub'], r['id'])):
    k = re.sub(r'\s+', ' ', r['desc'].lower())
    if k in seen: dup += 1; continue
    seen[k] = r['id']; keep.append(r)
stats['duplicates_removed'] = dup
keep = [r for r in keep if r['split'] != 'other']; stats['kept'] = len(keep)
json.dump(keep, open('dataset.json', 'w')); json.dump(dict(stats), open('dataset_stats.json', 'w'))
c = collections.Counter(r['split'] for r in keep)
print(dict(stats)); print(dict(c))
for s in ['train', 'dev', 'test2024', 'test2025', 'test2026']:
    sub = [r for r in keep if r['split'] == s]
    print(s, 'labels/CVE', round(sum(len(r['cwe']) for r in sub) / len(sub), 3), 'ADP-only share', round(sum(1 for r in sub if not r['cna_cwe']) / len(sub), 3))
