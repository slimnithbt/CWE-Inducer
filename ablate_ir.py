"""Ablation of the rule-induction design on dev (train on train split)."""
import json, re, induce
from induce import RuleInducer, wilson_lb
from ev import load, micro
D, S = load(); tr, dv = S['train'], S['dev']; g = {r['id']: r['cwe'] for r in dv}; ids = list(g)
def run(name, nmax=4, stop=True, digits=True, score='wilson', tau=0.55, k=1, s=5):
    STOP0 = induce.STOP
    if not stop: induce.STOP = set()
    orig_ng = induce.ngrams
    if not digits:
        def ng(toks, nmax=4):
            out = {}
            for n in range(1, nmax + 1):
                for i in range(len(toks) - n + 1):
                    gr = toks[i:i + n]; words = [w for w, _, _ in gr]
                    if words[0] in induce.STOP or words[-1] in induce.STOP: continue
                    key = ' '.join(words); out.setdefault(key, (gr[0][1], gr[-1][2]))
            return out
        induce.ngrams = ng
    orig_lb = induce.wilson_lb
    if score == 'raw': induce.wilson_lb = lambda kk, n, z=1.96: kk / n
    ri = RuleInducer(min_support=s, min_lb=0.3, nmax=nmax).fit([r['desc'] for r in tr], [r['cwe'] for r in tr])
    pred = {r['id']: ri.predict(r['desc'], tau, k) for r in dv}; m = micro(pred, g, ids)
    induce.STOP = STOP0; induce.ngrams = orig_ng; induce.wilson_lb = orig_lb
    print(f"{name:40s} rules={ri.n_rules(tau):6d} P={m['p']:.3f} R={m['r']:.3f} F1={m['f1']:.3f}", flush=True)
    return {'name': name, 'rules': ri.n_rules(tau), **m}
res = [run('full (n<=4, stop-word trimming, no digits, Wilson LB)'),
       run('unigrams only', nmax=1), run('n<=2', nmax=2),
       run('without stop-word trimming', stop=False), run('allow digits (versions, IDs)', digits=False),
       run('raw precision instead of Wilson bound', score='raw'),
       run('top-2 CWEs per CVE', k=2)]
json.dump(res, open('ablate_ir.json', 'w'), indent=1)
