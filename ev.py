import json
from cwe_eval import fam
def prf(tp, fp, fn):
    p = tp/(tp+fp) if tp+fp else 0.0; r = tp/(tp+fn) if tp+fn else 0.0
    return p, r, (2*p*r/(p+r) if p+r else 0.0)
def micro(pred, gold, ids, lenient=False):
    tp = fp = fn = 0
    for c in ids:
        g = set(gold[c]); p = set(pred.get(c, []))
        if lenient: g = {fam(x) for x in g}; p = {fam(x) for x in p}
        tp += len(p & g); fp += len(p - g); fn += len(g - p)
    P, R, F = prf(tp, fp, fn); return {'tp': tp, 'fp': fp, 'fn': fn, 'p': P, 'r': R, 'f1': F}
def macro(pred, gold, ids, labels):
    out = {}
    for l in labels:
        tp = sum(1 for c in ids if l in pred.get(c, []) and l in gold[c]); fp = sum(1 for c in ids if l in pred.get(c, []) and l not in gold[c])
        fn = sum(1 for c in ids if l not in pred.get(c, []) and l in gold[c]); out[l] = prf(tp, fp, fn)[2]
    return sum(out.values())/len(out), out
def load():
    D = json.load(open('dataset.json')); S = {}
    for r in D: S.setdefault(r['split'], []).append(r)
    return D, S
