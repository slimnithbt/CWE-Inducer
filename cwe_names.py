import json, glob, re, collections
names = collections.defaultdict(collections.Counter)
CV = __import__('os').environ.get('CVELIST', 'cvelistV5')
# files are read in sorted order so that ties between equally frequent names are broken the same way on every OS
for p in sorted(glob.glob(f'{CV}/cves/2023/*/CVE-*.json') + glob.glob(f'{CV}/cves/2024/*/CVE-*.json')):
    try: d = json.load(open(p, encoding='utf-8'))
    except Exception: continue
    for c in [d['containers'].get('cna', {})] + d['containers'].get('adp', []):
        for pt in c.get('problemTypes', []) or []:
            for x in pt.get('descriptions', []):
                t = x.get('description') or ''; m = re.match(r'\s*CWE-(\d+)[:\s]+(.+)', t)
                if m and len(m.group(2)) > 3: names[m.group(1)][m.group(2).strip()] += 1
out = {k: v.most_common(1)[0][0] for k, v in names.items()}
json.dump(out, open('cwe_names.json', 'w'), indent=0); print(len(out), out.get('79'), out.get('89'), out.get('787'))
