"""Learning curve: induced rules vs TF-IDF+LR trained on nested random subsets of the train split; scored on test2025.
Hyper-parameters are those selected on dev for the full training set."""
import json, random, time, numpy as np
from collections import Counter
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from induce import RuleInducer
from ev import load, micro
D, S = load(); tr = S['train'][:]; random.Random(7).shuffle(tr)
te = S['test2025']; g = {r['id']: r['cwe'] for r in te}; ids = list(g)
out = []
for frac in [0.05, 0.1, 0.25, 0.5]:
    sub = tr[:int(frac * len(tr))]
    t0 = time.time(); ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in sub], [r['cwe'] for r in sub]); ti = time.time() - t0
    pr = {r['id']: ri.predict(r['desc'], 0.55, 1) for r in te}; mi = micro(pr, g, ids)
    cnt = Counter(l for r in sub for l in r['cwe']); classes = sorted(l for l, n in cnt.items() if n >= 20)
    mlb = MultiLabelBinarizer(classes=classes); Y = mlb.fit_transform([[l for l in r['cwe'] if l in set(classes)] for r in sub])
    w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300000, sublinear_tf=True)
    ch = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=3, max_features=300000, sublinear_tf=True)
    t0 = time.time(); X = hstack([w.fit_transform([r['desc'] for r in sub]), ch.fit_transform([r['desc'] for r in sub])]).tocsr(); X.sort_indices()
    clf = OneVsRestClassifier(LogisticRegression(C=8.0, max_iter=2000, solver='liblinear', random_state=0), n_jobs=1).fit(X, Y); tl = time.time() - t0
    Xt = hstack([w.transform([r['desc'] for r in te]), ch.transform([r['desc'] for r in te])]).tocsr(); P = clf.predict_proba(Xt)
    pl = {r['id']: [classes[j] for j in np.where(P[i] >= 0.25)[0]] for i, r in enumerate(te)}; ml = micro(pl, g, ids)
    out.append({'frac': frac, 'n_train': len(sub), 'induced_f1': mi['f1'], 'induced_p': mi['p'], 'induced_r': mi['r'], 'induced_seconds': ti,
                'lr_f1': ml['f1'], 'lr_p': ml['p'], 'lr_r': ml['r'], 'lr_seconds': tl, 'lr_classes': len(classes)})
    print(out[-1], flush=True)
    json.dump(out, open('learning_curve.json', 'w'), indent=1)
