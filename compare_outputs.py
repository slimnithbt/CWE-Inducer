"""Compare regenerated outputs in the working folder with the released ones in results/ (or another folder).
Timing fields (keys containing 'seconds', and 'timing') are ignored; floats are compared with an absolute tolerance of 1e-9."""
import json, sys, os, gzip
REF = sys.argv[1] if len(sys.argv) > 1 else 'results'
FILES = ['dataset_stats.json', 'shift_stats.json', 'tune_rules.json', 'induced_rules.json', 'cwe_names.json', 'results_p2.json', 'tiers.json',
         'clf2_results.json', 'ablate_ir.json', 'learning_curve.json', 'expand.json', 'kb_meta.json', 'kb_tiers.json',
         'evaluation_report.json', 'multilabel.json', 'cna_only.json']
def walk(a, b, path, out):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in set(a) | set(b):
            if 'seconds' in k or k == 'timing': continue
            if k not in a or k not in b: out.append(f'{path}/{k}: missing'); continue
            walk(a[k], b[k], f'{path}/{k}', out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b): out.append(f'{path}: length {len(a)} vs {len(b)}'); return
        for i, (x, y) in enumerate(zip(a, b)): walk(x, y, f'{path}[{i}]', out)
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        if abs(a - b) > 1e-9: out.append((abs(a - b), f'{path}: {a} vs {b}'))
    elif a != b: out.append((float('inf'), f'{path}: {str(a)[:60]} vs {str(b)[:60]}'))
bad = 0
for f in FILES:
    if not os.path.exists(f) or not os.path.exists(os.path.join(REF, f)): print(f'{f}: not found'); bad += 1; continue
    out = []; walk(json.load(open(f, encoding='utf-8')), json.load(open(os.path.join(REF, f), encoding='utf-8')), '', out)
    if not out: print(f'{f}: identical'); continue
    mx = max(d for d, _ in out); bad += 1
    print(f'{f}: {len(out)} differences, largest absolute difference {mx:.2g}')
    for _, o in sorted(out, key=lambda x: -x[0])[:5]: print('   ', o)
for f in ['cve_cwe_evidence_kb.jsonl.gz'] + [os.path.join('predictions', f'{s}.jsonl.gz') for s in ['dev', 'test2024', 'test2025', 'test2026']]:
    if not os.path.exists(f) or not os.path.exists(os.path.join(REF, f)): print(f'{f}: not found'); bad += 1; continue
    a = gzip.open(f, 'rt', encoding='utf-8').read().splitlines(); b = gzip.open(os.path.join(REF, f), 'rt', encoding='utf-8').read().splitlines()
    nd = sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))
    print(f'{f}: {"identical" if not nd else f"{nd} of {len(b)} records differ"}'); bad += bool(nd)
print('SUMMARY:', 'all regenerated outputs match the released ones' if not bad else f'{bad} files differ')
