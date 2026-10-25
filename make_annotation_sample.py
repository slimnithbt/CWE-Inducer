"""Draw a stratified sample of knowledge-base assertions for independent human validation of the evidence tiers.
100 assertions per tier (aligned / unaligned / none), test2026, seed 2026. Two files: the annotation sheet (no tier,
no gold label, rows shuffled) and a key file used only after annotation."""
import json, gzip, csv, random
from ev import load
D, S = load(); desc = {r['id']: r['desc'] for r in S['test2026']}; gold = {r['id']: r['cwe'] for r in S['test2026']}
N = json.load(open('cwe_names.json'))
pool = {'aligned': [], 'unaligned': [], 'none': []}
for l in gzip.open('cve_cwe_evidence_kb.jsonl.gz', 'rt'):
    r = json.loads(l)
    if r['cve'] not in desc: continue
    for a in r['assertions']: pool[a['tier']].append((r['cve'], a))
rng = random.Random(2026); rows = []
for t in ['aligned', 'unaligned', 'none']:
    for c, a in rng.sample(pool[t], 100): rows.append((c, a, t))
rng.shuffle(rows)
with open('annotation/annotation_sheet.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['item', 'cve', 'description', 'assigned_cwe', 'cwe_name', 'evidence_spans',
                                   'Q1_cwe_correct (yes/partly/no)', 'Q2_span_supports_cwe (yes/partly/no/no span)', 'notes'])
    for i, (c, a, t) in enumerate(rows, 1):
        w.writerow([i, c, desc[c], 'CWE-' + a['cwe'], N.get(a['cwe'], ''), ' | '.join(sorted({e['text'] for e in a['evidence']})), '', '', ''])
with open('annotation/annotation_key.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['item', 'cve', 'assigned_cwe', 'tier', 'gold_cwes'])
    for i, (c, a, t) in enumerate(rows, 1): w.writerow([i, c, 'CWE-' + a['cwe'], t, ' '.join('CWE-' + x for x in gold[c])])
print({t: len(v) for t, v in pool.items()})
