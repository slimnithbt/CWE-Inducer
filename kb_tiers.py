"""Precision of knowledge-base assertions by evidence tier (against the reference CWE labels)."""
import json, gzip, collections
from ev import load
D, S = load()
gold = {r['id']: set(r['cwe']) for sp in ['test2024', 'test2025', 'test2026'] for r in S[sp]}
t = collections.defaultdict(lambda: [0, 0])
for line in gzip.open('cve_cwe_evidence_kb.jsonl.gz', 'rt'):
    rec = json.loads(line)
    for a in rec['assertions']:
        ok = a['cwe'] in gold[rec['cve']]
        for k in (a['tier'], 'all'): t[k][0] += 1; t[k][1] += ok
out = {k: {'n': n, 'correct': c, 'precision': c / max(1, n)} for k, (n, c) in t.items()}
out['all']['gold_total'] = sum(len(v) for v in gold.values())
json.dump(out, open('kb_tiers.json', 'w'), indent=1); print(out)
