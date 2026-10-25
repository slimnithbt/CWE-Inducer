"""All results for the temporal study: systems, hybrids, statistics, evidence analysis, risk-coverage."""
import json, random, re, collections
import numpy as np
from scipy.stats import binomtest
from ev import load, micro, macro, prf
from cwe_eval import fam
D, S = load()
R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); NAMES = json.load(open('cwe_names.json'))
STOPW = set('of the a an to in on for and or with by from into used during improper incorrect missing'.split())
def prob(c, l):
    for x, p in L['probs'][c]:
        if x == l: return p
    return 0.0
def lr_pred(c, th): return [x for x, p in L['probs'][c] if p >= th]
G = {sp: {r['id']: r['cwe'] for r in S[sp]} for sp in S}
GCNA = {sp: {r['id']: r['cna_cwe'] for r in S[sp] if r['cna_cwe']} for sp in S}
# ---------- tune LR threshold and hybrid parameter on dev ----------
dev = list(G['dev'])
best_th = max([x / 100 for x in range(10, 80, 5)], key=lambda th: micro({c: lr_pred(c, th) for c in dev}, G['dev'], dev)['f1'])
EVI = lambda c: {e[0] for e in R['evidence']['Induced rules'].get(c, [])} | {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
EVH = lambda c: {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
def verify(c, t): return sorted(set(lr_pred(c, best_th)) | {l for l in EVI(c) if prob(c, l) >= t})
best_t = max([0.0, 0.01, 0.02, 0.05, 0.1, 0.15, 0.2], key=lambda t: micro({c: verify(c, t) for c in dev}, G['dev'], dev)['f1'])
print('dev-selected LR threshold', best_th, 'verify t', best_t)
def systems(ids):
    P = {n: {c: R['pred'][n][c] for c in ids} for n in ['Keyword baseline', 'Regex baseline', 'CyberRule', 'Induced rules']}
    P['Induced + hand rules'] = {c: sorted(set(R['pred']['Induced rules'][c]) | set(R['pred']['CyberRule'][c])) for c in ids}
    P['TF-IDF + LR'] = {c: lr_pred(c, best_th) for c in ids}
    P['Hybrid: rules propose, classifier verifies'] = {c: verify(c, best_t) for c in ids}
    P['Hybrid: classifier grounded by rules'] = {c: [l for l in lr_pred(c, best_th) if l in EVI(c)] for c in ids}
    P['Hybrid: classifier grounded by hand rules'] = {c: [l for l in lr_pred(c, best_th) if l in EVH(c)] for c in ids}
    return P
ORDER = ['Keyword baseline', 'Regex baseline', 'CyberRule', 'Induced rules', 'Induced + hand rules', 'TF-IDF + LR',
         'Hybrid: rules propose, classifier verifies', 'Hybrid: classifier grounded by rules', 'Hybrid: classifier grounded by hand rules']
TRACE = {'Keyword baseline': 'matched keyword', 'Regex baseline': 'matched pattern', 'CyberRule': 'span', 'Induced rules': 'span', 'Induced + hand rules': 'span',
         'TF-IDF + LR': None, 'Hybrid: rules propose, classifier verifies': 'partial', 'Hybrid: classifier grounded by rules': 'span', 'Hybrid: classifier grounded by hand rules': 'span'}
def aligned(phrase, cwe):
    nm = NAMES.get(cwe, '').lower()
    nt = {w[:5] for w in re.findall(r'[a-z]+', nm) if w not in STOPW and len(w) > 2}
    pt = {w[:5] for w in re.findall(r'[a-z]+', phrase.lower()) if w not in STOPW and len(w) > 2}
    return bool(nt & pt)
out = {'lr_threshold': best_th, 'verify_t': best_t, 'n': {sp: len(G[sp]) for sp in G}, 'n_classes': len(L['classes']), 'splits': {}}
rng = random.Random(2026)
for sp in ['dev', 'test2024', 'test2025', 'test2026']:
    ids = list(G[sp]); P = systems(ids); g = G[sp]
    freq = collections.Counter(l for c in ids for l in g[c]); mlabels = sorted(l for l, n in freq.items() if n >= 50)
    res = {}
    B = 1000; boots = sp != 'dev'
    if boots:
        nprng = np.random.default_rng(2026)
        BIDX = np.zeros((B, len(ids)), dtype=np.int32)
        for b in range(B): BIDX[b] = np.bincount(nprng.integers(0, len(ids), len(ids)), minlength=len(ids))
    BF = {}
    for n in ORDER:
        p = P[n]; m = micro(p, g, ids); m['lenient_f1'] = micro(p, g, ids, True)['f1']
        m['macro_f1'], per = macro(p, g, ids, mlabels); m['coverage'] = sum(1 for c in ids if p[c]) / len(ids)
        m['n_pred'] = sum(len(p[c]) for c in ids)
        cg = GCNA[sp]; cids = list(cg); m['cna_only_f1'] = micro(p, cg, cids)['f1']
        if boots:
            arr = np.array([[len(set(p[c]) & set(g[c])), len(set(p[c]) - set(g[c])), len(set(g[c]) - set(p[c]))] for c in ids], dtype=np.int64)
            sums = BIDX @ arr
            tp, fp, fn = sums[:, 0], sums[:, 1], sums[:, 2]
            f1 = np.where(2 * tp + fp + fn > 0, 2 * tp / np.maximum(1, 2 * tp + fp + fn), 0.0)
            BF[n] = list(f1); v = sorted(BF[n]); m['f1_ci'] = (float(v[int(.025 * B)]), float(v[int(.975 * B) - 1]))
        m['per_cwe'] = {l: per[l] for l in freq.most_common(10) and [x for x, _ in freq.most_common(10)]}
        res[n] = m
    # paired comparisons
    pairs = []
    if boots:
        items = [(c, l) for c in ids for l in g[c]]
        for a, b in [('Induced rules', 'CyberRule'), ('Induced rules', 'Regex baseline'), ('TF-IDF + LR', 'Induced rules'),
                     ('Hybrid: rules propose, classifier verifies', 'TF-IDF + LR'), ('CyberRule', 'Regex baseline')]:
            ha = [l in P[a][c] for c, l in items]; hb = [l in P[b][c] for c, l in items]
            x = sum(i and not j for i, j in zip(ha, hb)); y = sum(j and not i for i, j in zip(ha, hb))
            d = sorted(i - j for i, j in zip(BF[a], BF[b]))
            pairs.append({'a': a, 'b': b, 'a_only': x, 'b_only': y, 'p': binomtest(x, x + y, .5).pvalue if x + y else 1.0,
                          'dF1': res[a]['f1'] - res[b]['f1'], 'ci': (float(d[int(.025 * B)]), float(d[int(.975 * B) - 1]))})
    # evidence analysis
    evid = {}
    for n, key in [('Induced rules', 'Induced rules'), ('CyberRule', 'CyberRule')]:
        E = [e for c in ids for e in R['evidence'][key].get(c, [])]
        al = [aligned(e[1], e[0]) for e in E]
        correct = [e[0] in g[c] for c in ids for e in R['evidence'][key].get(c, [])]
        evid[n] = {'n': len(E), 'aligned_share': sum(al) / len(E) if E else 0,
                   'precision_aligned': sum(1 for a, k in zip(al, correct) if a and k) / max(1, sum(al)),
                   'precision_unaligned': sum(1 for a, k in zip(al, correct) if not a and k) / max(1, len(al) - sum(al))}
    lrp = P['TF-IDF + LR']; tot = sum(len(lrp[c]) for c in ids); sup = sum(1 for c in ids for l in lrp[c] if l in EVI(c)); suph = sum(1 for c in ids for l in lrp[c] if l in EVH(c))
    evid['LR labels with rule evidence'] = sup / tot; evid['LR labels with hand-rule evidence'] = suph / tot
    # risk-coverage on top-1 LR label
    top = [(c, L['probs'][c][0][0], L['probs'][c][0][1]) for c in ids]
    def curve(order):
        pts = []; hit = 0
        for i, (c, l, p) in enumerate(order, 1):
            hit += l in g[c]
            if i % max(1, len(order) // 50) == 0 or i == len(order): pts.append((i / len(order), hit / i))
        return pts
    conf = sorted(top, key=lambda t: (-t[2], t[0]))
    grounded_first = sorted(top, key=lambda t: (t[1] not in EVI(t[0]), -t[2], t[0]))
    ng = sum(1 for c, l, p in top if l in EVI(c)); pg = sum(1 for c, l, p in top if l in EVI(c) and l in g[c]) / max(1, ng)
    def prec_at(order, cov): k = int(cov * len(order)); return sum(1 for c, l, p in order[:k] if l in g[c]) / k
    rc = {'confidence': curve(conf), 'grounded_first': curve(grounded_first), 'grounded_share': ng / len(ids), 'grounded_precision': pg,
          'prec_at': {str(cv): {'confidence': prec_at(conf, cv), 'grounded_first': prec_at(grounded_first, cv)} for cv in [0.3, 0.5, 0.6, 0.7, 0.8]}}
    # label vocabulary gap
    gold_lab = [l for c in ids for l in g[c]]
    gap = {'outside_classifier_classes': sum(1 for l in gold_lab if l not in set(L['classes'])) / len(gold_lab)}
    out['splits'][sp] = {'systems': res, 'pairs': pairs, 'evidence': evid, 'risk_coverage': rc, 'label_gap': gap, 'macro_labels': len(mlabels)}
    print('==', sp, len(ids), 'macro labels', len(mlabels), gap)
    for n in ORDER:
        m = res[n]; ci = m.get('f1_ci', (0, 0))
        print(f"{n:44s} P={m['p']:.3f} R={m['r']:.3f} F1={m['f1']:.3f} [{ci[0]:.3f},{ci[1]:.3f}] len={m['lenient_f1']:.3f} macro={m['macro_f1']:.3f} cov={m['coverage']:.3f} cna={m['cna_only_f1']:.3f}")
    for p in pairs: print(f"   {p['a']} vs {p['b']}: {p['a_only']}/{p['b_only']} p={p['p']:.2g} dF1={p['dF1']:+.3f} [{p['ci'][0]:+.3f},{p['ci'][1]:+.3f}]")
    print('   evidence', {k: (v if isinstance(v, float) else {kk: round(vv, 3) for kk, vv in v.items()}) for k, v in evid.items()})
    print('   risk-coverage', rc['prec_at'], 'grounded share', round(rc['grounded_share'], 3), 'grounded prec', round(pg, 3))
out['timing'] = R['timing']; out['lr_fit_seconds'] = L['fit_seconds']; out['lr_pred_seconds'] = {k: v for k, v in L.items() if k.startswith('pred_seconds')}
out['n_rules'] = R['n_rules']; out['rule_hashes_equal'] = len(set(R['rule_hashes'])) == 1; out['induce_fit_seconds'] = R['induce_fit_seconds']
json.dump(out, open('results_p2.json', 'w'), indent=1)
