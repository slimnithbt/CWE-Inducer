"""Cross-platform check: compare predicted LABELS (not probabilities) in the regenerated prediction files and knowledge
base with the released ones, and report the largest classifier-probability difference.
Usage: python check_labels.py <released results folder>"""
import json, gzip, os, sys
REF = sys.argv[1]
def recs(path): return [json.loads(l) for l in gzip.open(path, 'rt', encoding='utf-8')]
for sp in ['dev', 'test2024', 'test2025', 'test2026']:
    a = recs(os.path.join('predictions', f'{sp}.jsonl.gz')); b = recs(os.path.join(REF, 'predictions', f'{sp}.jsonl.gz'))
    diff = {}; maxp = 0.0
    for x, y in zip(a, b):
        assert x['id'] == y['id'] and x['gold'] == y['gold']
        for s in y['pred']:
            if x['pred'].get(s) != y['pred'][s]: diff.setdefault(s, []).append(x['id'])
        px, py = dict(map(tuple, x['lr_top'])), dict(map(tuple, y['lr_top']))
        maxp = max([maxp] + [abs(px[k] - py[k]) for k in px.keys() & py.keys()])
    print(f"{sp}: {len(a)} CVEs; largest classifier-probability difference {maxp:.1e}; CVEs whose predicted labels differ:",
          {s: (len(v), v[:3]) for s, v in diff.items()} or 'none')
a = recs('cve_cwe_evidence_kb.jsonl.gz'); b = recs(os.path.join(REF, 'cve_cwe_evidence_kb.jsonl.gz'))
lab = lambda r: sorted((x['cwe'], x['tier'], tuple(sorted(e['text'] for e in x['evidence']))) for x in r['assertions'])
d = [x['cve'] for x, y in zip(a, b) if lab(x) != lab(y)]
print(f'knowledge base: {len(d)} of {len(b)} CVEs differ in their assertions (CWE, tier or evidence):', d[:5])
