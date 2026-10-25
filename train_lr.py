"""Supervised baseline: TF-IDF (word 1-2 + char_wb 3-5) + one-vs-rest logistic regression, trained on the
train split only; threshold chosen on dev. Stores the top-10 class probabilities per CVE for dev/test."""
import json, time, hashlib, numpy as np
from collections import Counter
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from ev import load
D, S = load()
tr = S['train']
cnt = Counter(l for r in tr for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
mlb = MultiLabelBinarizer(classes=classes); Y = mlb.fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in tr])
w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True, dtype=np.float64)
ch = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=3, max_features=300000, sublinear_tf=True, dtype=np.float64)
t0 = time.time()
X = hstack([w.fit_transform([r['desc'] for r in tr]), ch.fit_transform([r['desc'] for r in tr])]).tocsr(); X.sort_indices()
clf = OneVsRestClassifier(LogisticRegression(C=8.0, max_iter=2000, solver='liblinear', random_state=0), n_jobs=1).fit(X, Y)
fit_s = time.time() - t0; print('classes', len(classes), 'fit seconds', round(fit_s), flush=True)
out = {'classes': classes, 'fit_seconds': fit_s, 'n_train': len(tr), 'probs': {}}
for split in ['dev', 'test2024', 'test2025', 'test2026']:
    rows = S[split]; t0 = time.time()
    Xs = hstack([w.transform([r['desc'] for r in rows]), ch.transform([r['desc'] for r in rows])]).tocsr()
    P = clf.predict_proba(Xs); out[f'pred_seconds_{split}'] = time.time() - t0
    top = np.argsort(-P, axis=1)[:, :10]
    out['probs'].update({r['id']: [[classes[j], round(float(P[i, j]), 5)] for j in top[i]] for i, r in enumerate(rows)})
    out[f'sha_{split}'] = hashlib.sha256(np.round(P, 8).tobytes()).hexdigest()
    print(split, 'done', flush=True)
json.dump(out, open('lr_probs.json', 'w'))
