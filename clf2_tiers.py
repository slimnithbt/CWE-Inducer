"""Do evidence tiers and grounding generalise to a second classifier?"""
import json, re
from ev import load, micro
D, S = load(); R = json.load(open('rule_outputs.json')); C = json.load(open('clf2_probs.json')); N = json.load(open('cwe_names.json'))
TH = C['threshold']; STOPW = set('of the a an to in on for and or with by from into used during improper incorrect missing'.split())
def aligned(ph, c):
    nt = {w[:5] for w in re.findall(r'[a-z]+', N.get(c, '').lower()) if w not in STOPW and len(w) > 2}
    return bool(nt & {w[:5] for w in re.findall(r'[a-z]+', ph.lower()) if w not in STOPW and len(w) > 2})
out = {'threshold': TH, 'fit_seconds': C['fit_seconds']}
for sp in ['test2024', 'test2025', 'test2026']:
    g = {r['id']: r['cwe'] for r in S[sp]}; ids = list(g)
    ev = {c: {} for c in ids}
    for src in ['Induced rules', 'CyberRule']:
        for c in ids:
            for e in R['evidence'][src].get(c, []): ev[c].setdefault(e[0], []).append(e[1])
    pred = {c: [l for l, p in C['probs'][c] if p >= TH] for c in ids}
    prob = {c: dict((l, p) for l, p in C['probs'][c]) for c in ids}
    ver = {c: sorted(set(pred[c]) | {l for l in ev[c] if prob[c].get(l, 0) >= 0.1}) for c in ids}
    grd = {c: [l for l in pred[c] if l in ev[c]] for c in ids}
    t = {'aligned': [0, 0], 'unaligned': [0, 0], 'none': [0, 0]}
    for c in ids:
        for l in pred[c]:
            k = 'none' if l not in ev[c] else ('aligned' if any(aligned(ph, l) for ph in ev[c][l]) else 'unaligned')
            t[k][0] += 1; t[k][1] += l in g[c]
    tot = sum(v[0] for v in t.values())
    out[sp] = {'clf2': micro(pred, g, ids), 'verify': micro(ver, g, ids), 'grounded': micro(grd, g, ids),
               'tiers': {k: {'share': v[0] / tot, 'precision': v[1] / max(1, v[0])} for k, v in t.items()}}
    print(sp, {k: (round(v['p'], 3), round(v['r'], 3), round(v['f1'], 3)) for k, v in out[sp].items() if k != 'tiers'}, {k: (round(v['share'], 3), round(v['precision'], 3)) for k, v in out[sp]['tiers'].items()})
json.dump(out, open('clf2_results.json', 'w'), indent=1)
