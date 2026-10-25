"""Evidence tiers for classifier labels: aligned rule evidence / unaligned rule evidence / no evidence."""
import json, re
from ev import load, micro
D, S = load(); R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); N = json.load(open('cwe_names.json'))
A = json.load(open('results_p2.json')); TH = A['lr_threshold']
STOPW = set('of the a an to in on for and or with by from into used during improper incorrect missing'.split())
def aligned(ph, c):
    nt = {w[:5] for w in re.findall(r'[a-z]+', N.get(c, '').lower()) if w not in STOPW and len(w) > 2}
    return bool(nt & {w[:5] for w in re.findall(r'[a-z]+', ph.lower()) if w not in STOPW and len(w) > 2})
out = {}
for sp in ['test2024', 'test2025', 'test2026']:
    g = {r['id']: r['cwe'] for r in S[sp]}; ids = list(g); tiers = {'aligned': [0, 0], 'unaligned': [0, 0], 'none': [0, 0]}
    al_pred = {}
    for c in ids:
        ev = {}
        for e in R['evidence']['Induced rules'].get(c, []) + R['evidence']['CyberRule'].get(c, []):
            ev.setdefault(e[0], []).append(e[1])
        al_pred[c] = [e[0] for e in R['evidence']['Induced rules'].get(c, []) if aligned(e[1], e[0])]
        for l, p in L['probs'][c]:
            if p < TH: continue
            t = 'none' if l not in ev else ('aligned' if any(aligned(ph, l) for ph in ev[l]) else 'unaligned')
            tiers[t][0] += 1; tiers[t][1] += l in g[c]
    tot = sum(v[0] for v in tiers.values())
    out[sp] = {'tiers': {k: {'share': v[0] / tot, 'precision': v[1] / v[0]} for k, v in tiers.items()},
               'induced_aligned_only': micro(al_pred, g, ids)}
    print(sp, out[sp])
json.dump(out, open('tiers.json', 'w'), indent=1)
