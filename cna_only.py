"""Temporal label availability check. CISA ADP CWE labels were added from 2024 onwards, after the training cutoff
(June 2023). Here rules and the classifier are trained with CNA labels only (training CVEs without a CNA CWE are
dropped), thresholds are re-selected on dev with CNA labels, and the test years are scored against (a) all labels
and (b) CNA labels only."""
import json, time, numpy as np
from collections import Counter
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from ev import load, micro
from induce import RuleInducer
D, S = load()
tr = [r for r in S['train'] if r['cna_cwe']]
print('training CVEs with CNA labels', len(tr), 'of', len(S['train']), flush=True)
t0 = time.time(); ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in tr], [r['cna_cwe'] for r in tr]); ind_s = time.time() - t0
cnt = Counter(l for r in tr for l in r['cna_cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20); cs = set(classes)
Y = MultiLabelBinarizer(classes=classes).fit_transform([[l for l in r['cna_cwe'] if l in cs] for r in tr])
w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True, dtype=np.float64)
ch = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=3, max_features=300000, sublinear_tf=True, dtype=np.float64)
t0 = time.time()
X = hstack([w.fit_transform([r['desc'] for r in tr]), ch.fit_transform([r['desc'] for r in tr])]).tocsr(); X.sort_indices()
clf = OneVsRestClassifier(LogisticRegression(C=8.0, max_iter=2000, solver='liblinear', random_state=0), n_jobs=1).fit(X, Y)
lr_s = time.time() - t0; print('classes', len(classes), 'LR fit s', round(lr_s), flush=True)
R = json.load(open('rule_outputs.json'))
def probs(rows):
    P = clf.predict_proba(hstack([w.transform([r['desc'] for r in rows]), ch.transform([r['desc'] for r in rows])]).tocsr())
    return [{classes[j]: float(P[i, j]) for j in np.argsort(-P[i])[:10]} for i in range(len(rows))]
def systems(rows, pr, th, tau, k, t):
    out = {'Induced rules': {}, 'TF-IDF + LR': {}, 'Hybrid: rules propose, classifier verifies': {}}
    for r, p in zip(rows, pr):
        c = r['id']; ex = ri.explain(r['desc'], tau, k)
        lp = [l for l, v in p.items() if v >= th]; ev = {e[0] for e in ex} | {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
        out['Induced rules'][c] = [e[0] for e in ex]; out['TF-IDF + LR'][c] = lp
        out['Hybrid: rules propose, classifier verifies'][c] = sorted(set(lp) | {l for l in ev if p.get(l, 0) >= t})
    return out
dev = S['dev']; pdev = probs(dev); gdev = {r['id']: r['cna_cwe'] for r in dev if r['cna_cwe']}; idev = list(gdev)
th = max([x / 100 for x in range(10, 80, 5)], key=lambda th: micro({r['id']: [l for l, v in p.items() if v >= th] for r, p in zip(dev, pdev)}, gdev, idev)['f1'])
tau = max([x / 100 for x in range(30, 100, 5)], key=lambda ta: micro({r['id']: ri.predict(r['desc'], ta, 1) for r in dev}, gdev, idev)['f1'])
t = max([0.0, 0.01, 0.02, 0.05, 0.1, 0.15, 0.2], key=lambda t: micro(systems(dev, pdev, th, tau, 1, t)['Hybrid: rules propose, classifier verifies'], gdev, idev)['f1'])
print('dev-selected: LR threshold', th, 'tau', tau, 'verify t', t, flush=True)
res = {'n_train': len(tr), 'n_classes': len(classes), 'n_rules': ri.n_rules(tau), 'lr_threshold': th, 'tau': tau, 'verify_t': t,
       'lr_fit_seconds': lr_s, 'induce_seconds': ind_s, 'splits': {}}
for sp in ['test2024', 'test2025', 'test2026']:
    rows = S[sp]; P = systems(rows, probs(rows), th, tau, 1, t)
    gall = {r['id']: r['cwe'] for r in rows}; gcna = {r['id']: r['cna_cwe'] for r in rows if r['cna_cwe']}
    res['splits'][sp] = {n: {'all_labels': micro(p, gall, list(gall)), 'cna_labels': micro(p, gcna, list(gcna))} for n, p in P.items()}
    print(sp, {n: (round(v['all_labels']['f1'], 3), round(v['cna_labels']['f1'], 3)) for n, v in res['splits'][sp].items()}, flush=True)
json.dump(res, open('cna_only.json', 'w'), indent=1)
