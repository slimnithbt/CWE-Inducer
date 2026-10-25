"""Second classifier for robustness: linear model trained with SGD (log loss) on word 1-2-gram TF-IDF only."""
import json, time, numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from ev import load, micro
D, S = load(); tr = S['train']
cnt = Counter(l for r in tr for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
Y = MultiLabelBinarizer(classes=classes).fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in tr])
w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True)
t0 = time.time(); X = w.fit_transform([r['desc'] for r in tr])
clf = OneVsRestClassifier(SGDClassifier(loss='log_loss', alpha=2e-6, max_iter=30, tol=None, random_state=0), n_jobs=1).fit(X, Y)
fit = time.time() - t0
out = {'classes': classes, 'fit_seconds': fit, 'probs': {}}
dv = S['dev']; Pd = clf.predict_proba(w.transform([r['desc'] for r in dv])); gd = {r['id']: r['cwe'] for r in dv}
best = max([x / 100 for x in range(10, 80, 5)], key=lambda th: micro({r['id']: [classes[j] for j in np.where(Pd[i] >= th)[0]] for i, r in enumerate(dv)}, gd, list(gd))['f1'])
out['threshold'] = best
for sp in ['test2024', 'test2025', 'test2026']:
    rows = S[sp]; P = clf.predict_proba(w.transform([r['desc'] for r in rows])); top = np.argsort(-P, axis=1)[:, :10]
    out['probs'].update({r['id']: [[classes[j], round(float(P[i, j]), 5)] for j in top[i]] for i, r in enumerate(rows)})
json.dump(out, open('clf2_probs.json', 'w')); print('fit', round(fit), 'threshold', best)
