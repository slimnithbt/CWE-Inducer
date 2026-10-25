"""Additional analyses for the extended paper (all fast; classifier refresh and second classifier run separately)."""
import json, re, collections, statistics
from sklearn.metrics import cohen_kappa_score
from ev import load, micro, prf
from induce import RuleInducer, ngrams, tokens
from cwe_eval import fam
D, S = load(); R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); N = json.load(open('cwe_names.json'))
A = json.load(open('results_p2.json')); TH, VT = A['lr_threshold'], A['verify_t']; CLS = set(L['classes'])
STOPW = set('of the a an to in on for and or with by from into used during improper incorrect missing'.split())
def aligned(ph, c, k=5, stop=True):
    sw = STOPW if stop else set()
    cut = (lambda w: w) if k is None else (lambda w: w[:k])
    nt = {cut(w) for w in re.findall(r'[a-z]+', N.get(c, '').lower()) if w not in sw and len(w) > 2}
    return bool(nt & {cut(w) for w in re.findall(r'[a-z]+', ph.lower()) if w not in sw and len(w) > 2})
def ev_of(c):
    e = {}
    for src in ['Induced rules', 'CyberRule']:
        for x in R['evidence'][src].get(c, []): e.setdefault(x[0], []).append(x[1])
    return e
def lr(c): return [l for l, p in L['probs'][c] if p >= TH]
def prob(c, l): return dict((a, b) for a, b in L['probs'][c]).get(l, 0.0)
def verify(c): return sorted(set(lr(c)) | {l for l in ev_of(c) if prob(c, l) >= VT})
out = {}
# 1. per-CNA
per = {}
for sp in ['test2024', 'test2025', 'test2026']:
    rows = S[sp]; byA = collections.defaultdict(list)
    for r in rows: byA[r['assigner']].append(r)
    top = sorted(byA, key=lambda a: -len(byA[a]))[:8]; per[sp] = []
    for a in top:
        ids = [r['id'] for r in byA[a]]; g = {r['id']: r['cwe'] for r in byA[a]}
        row = {'assigner': a, 'n': len(ids), 'share': len(ids) / len(rows)}
        for name, P in [('hand', R['pred']['CyberRule']), ('induced', R['pred']['Induced rules']), ('lr', {c: lr(c) for c in ids}), ('verify', {c: verify(c) for c in ids})]:
            row[name] = micro(P, g, ids)['f1']
        per[sp].append(row)
out['per_cna'] = per
# 2. refresh: rules and the SGD classifier retrained on progressively newer data, tested on 2026
import numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
ref = {}
te = S['test2026']; g26 = {r['id']: r['cwe'] for r in te}; ids26 = list(g26)
for name, tr in [('train (original)', S['train']), ('+ dev (to Dec 2023)', S['train'] + S['dev']), ('+ 2024', S['train'] + S['dev'] + S['test2024']),
                 ('+ 2025', S['train'] + S['dev'] + S['test2024'] + S['test2025'])]:
    ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in tr], [r['cwe'] for r in tr])
    pr = {r['id']: ri.predict(r['desc'], 0.55, 1) for r in te}
    cnt = Counter(l for r in tr for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
    Y = MultiLabelBinarizer(classes=classes).fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in tr])
    w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True); X = w.fit_transform([r['desc'] for r in tr])
    clf = OneVsRestClassifier(SGDClassifier(loss='log_loss', alpha=2e-6, max_iter=30, tol=None, random_state=0), n_jobs=1).fit(X, Y)
    P = clf.predict_proba(w.transform([r['desc'] for r in te]))
    pc = {r['id']: [classes[j] for j in np.where(P[i] >= 0.25)[0]] for i, r in enumerate(te)}
    ref[name] = {'n_train': len(tr), 'rules': ri.n_rules(0.55), 'induced': micro(pr, g26, ids26), 'sgd': micro(pc, g26, ids26), 'sgd_classes': len(classes)}
    print('refresh', name, round(ref[name]['induced']['f1'], 3), round(ref[name]['sgd']['f1'], 3), flush=True)
out['refresh_2026'] = ref
# rolling protocol: tune tau/K (rules) and threshold (SGD) on 2025 with models trained up to 2024, then retrain up to 2025 and test 2026
tr24 = S['train'] + S['dev'] + S['test2024']; v25 = S['test2025']; gv = {r['id']: r['cwe'] for r in v25}; idv = list(gv)
ri24 = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in tr24], [r['cwe'] for r in tr24])
ex = {r['id']: ri24.explain(r['desc'], 0.3, 5) for r in v25}
grid = []
for tau in [x / 100 for x in range(30, 96, 5)]:
    for K in [1, 2, 3]:
        grid.append((micro({c: [e[0] for e in v if e[1] >= tau][:K] for c, v in ex.items()}, gv, idv)['f1'], tau, K))
_, tau_b, K_b = max(grid)
cnt = Counter(l for r in tr24 for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
Y = MultiLabelBinarizer(classes=classes).fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in tr24])
w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True); X = w.fit_transform([r['desc'] for r in tr24])
clf = OneVsRestClassifier(SGDClassifier(loss='log_loss', alpha=2e-6, max_iter=30, tol=None, random_state=0), n_jobs=1).fit(X, Y)
Pv = clf.predict_proba(w.transform([r['desc'] for r in v25]))
th_b = max([x / 100 for x in range(10, 80, 5)], key=lambda th: micro({r['id']: [classes[j] for j in np.where(Pv[i] >= th)[0]] for i, r in enumerate(v25)}, gv, idv)['f1'])
tr25 = tr24 + v25
ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in tr25], [r['cwe'] for r in tr25])
pr = {r['id']: ri.predict(r['desc'], tau_b, K_b) for r in te}
cnt = Counter(l for r in tr25 for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
Y = MultiLabelBinarizer(classes=classes).fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in tr25])
w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True); X = w.fit_transform([r['desc'] for r in tr25])
clf = OneVsRestClassifier(SGDClassifier(loss='log_loss', alpha=2e-6, max_iter=30, tol=None, random_state=0), n_jobs=1).fit(X, Y)
P = clf.predict_proba(w.transform([r['desc'] for r in te]))
pc = {r['id']: [classes[j] for j in np.where(P[i] >= th_b)[0]] for i, r in enumerate(te)}
out['rolling_2026'] = {'tau': tau_b, 'K': K_b, 'sgd_threshold': th_b, 'induced': micro(pr, g26, ids26), 'sgd': micro(pc, g26, ids26), 'rules': ri.n_rules(tau_b)}
print('rolling', tau_b, K_b, th_b, round(out['rolling_2026']['induced']['f1'], 3), round(out['rolling_2026']['sgd']['f1'], 3), flush=True)
# 3. calibration (newest year, top-1)
LAT = S['test2026']; g25 = {r['id']: r['cwe'] for r in LAT}; ids25 = list(g25)
bins = [0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.01]
def calib(items):
    res = []; ece = 0; n = len(items)
    for lo, hi in zip(bins[:-1], bins[1:]):
        b = [(s, ok) for s, ok in items if lo <= s < hi]
        if b:
            ms = sum(s for s, _ in b) / len(b); acc = sum(ok for _, ok in b) / len(b); ece += len(b) / n * abs(ms - acc)
            res.append({'lo': lo, 'hi': min(hi, 1.0), 'n': len(b), 'mean_score': ms, 'precision': acc})
    return res, ece
ir_items = [(e[4], e[0] in g25[c]) for c in ids25 for e in R['evidence']['Induced rules'].get(c, [])]
lr_items = [(L['probs'][c][0][1], L['probs'][c][0][0] in g25[c]) for c in ids25 if L['probs'][c][0][1] >= 0.55]
cal_ir, ece_ir = calib(ir_items); cal_lr, ece_lr = calib(lr_items)
out['calibration'] = {'induced': cal_ir, 'induced_ece': ece_ir, 'lr': cal_lr, 'lr_ece': ece_lr}
# 4. error taxonomy for the verify hybrid on the newest year
te = LAT
fn = collections.Counter(); fp = collections.Counter()
vul = {r['id'] for r in te if r['assigner'] == 'VulDB'}
for r in te:
    c = r['id']; p = set(verify(c)); gset = set(r['cwe'])
    for x in gset - p:
        if x not in CLS: k = 'gold CWE unseen in training classes'
        elif fam(x) in {fam(y) for y in p}: k = 'related CWE predicted (granularity)'
        elif x == '74' and c in vul: k = 'VulDB CWE-74 convention change'
        elif not p: k = 'no label predicted'
        else: k = 'different, unrelated CWE predicted'
        fn[k] += 1
    for y in p - gset:
        if fam(y) in {fam(x) for x in gset}: k = 'related CWE in gold (granularity)'
        elif '74' in gset and c in vul: k = 'VulDB CWE-74 convention change'
        else: k = 'unrelated CWE'
        fp[k] += 1
out['errors_verify_2026'] = {'fn': fn, 'fp': fp}
# 5. CNA vs ADP agreement where both provide CWEs
agr = {}
for sp in ['test2024', 'test2025', 'test2026']:
    both = [r for r in S[sp] if r['cna_cwe'] and r['adp_cwe']]
    ex = sum(1 for r in both if set(r['cna_cwe']) == set(r['adp_cwe'])); ov = sum(1 for r in both if set(r['cna_cwe']) & set(r['adp_cwe']))
    k = cohen_kappa_score([r['cna_cwe'][0] for r in both], [r['adp_cwe'][0] for r in both]) if both else None
    agr[sp] = {'n_both': len(both), 'exact': ex / max(1, len(both)), 'overlap': ov / max(1, len(both)), 'kappa_first': k}
out['cna_adp_agreement'] = agr
# 6. alignment sensitivity (classifier label tiers, newest year)
sens = {}
for name, kw in [('prefix 4', dict(k=4)), ('prefix 5 (default)', dict(k=5)), ('prefix 6', dict(k=6)), ('whole words', dict(k=None)), ('no stop list', dict(k=5, stop=False))]:
    t = {'aligned': [0, 0], 'unaligned': [0, 0], 'none': [0, 0]}
    for c in ids25:
        e = ev_of(c)
        for l in lr(c):
            tier = 'none' if l not in e else ('aligned' if any(aligned(ph, l, **kw) for ph in e[l]) else 'unaligned')
            t[tier][0] += 1; t[tier][1] += l in g25[c]
    tot = sum(v[0] for v in t.values())
    sens[name] = {k2: {'share': v[0] / tot, 'precision': v[1] / max(1, v[0])} for k2, v in t.items()}
out['alignment_sensitivity'] = sens
# 7. rule-table statistics incl. CNA concentration of rule support
rules = json.load(open('induced_rules.json'))
phr = {r['phrase'] for r in rules}
asg = collections.defaultdict(collections.Counter)
for r in S['train']:
    for gk in set(ngrams(tokens(r['desc']))) & phr: asg[gk][r['assigner']] += 1
conc = [max(asg[r['phrase']].values()) / sum(asg[r['phrase']].values()) for r in rules]
al = [aligned(r['phrase'], r['cwe']) for r in rules]
by_cwe = collections.Counter(r['cwe'] for r in rules)
out['rule_stats'] = {'n_rules': len(rules), 'n_phrases': len(phr), 'n_cwes': len(by_cwe), 'rules_per_cwe_median': statistics.median(by_cwe.values()),
    'rules_per_cwe_max': max(by_cwe.values()), 'length_dist': collections.Counter(len(r['phrase'].split()) for r in rules),
    'aligned_share_rules': sum(al) / len(al), 'single_cna_share_90': sum(1 for x in conc if x >= 0.9) / len(conc),
    'single_cna_share_90_unaligned': sum(1 for x, a in zip(conc, al) if x >= 0.9 and not a) / max(1, sum(1 for a in al if not a)),
    'single_cna_share_90_aligned': sum(1 for x, a in zip(conc, al) if x >= 0.9 and a) / max(1, sum(al))}
json.dump(out, open('expand.json', 'w'), indent=1, default=lambda o: dict(o))
print(json.dumps(out, indent=1, default=lambda o: dict(o))[:6000])
