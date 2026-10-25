import json, time
from induce import RuleInducer
from ev import micro, load
D, S = load()
tr, dv = S['train'], S['dev']
gold = {r['id']: r['cwe'] for r in dv}; ids = [r['id'] for r in dv]
res = []
for s in [3, 5, 10]:
    t0 = time.time(); ri = RuleInducer(min_support=s, min_lb=0.3).fit([r['desc'] for r in tr], [r['cwe'] for r in tr])
    print('support', s, 'rules', ri.n_rules(), 'fit s', round(time.time()-t0, 1), flush=True)
    expl = {r['id']: ri.explain(r['desc'], 0.3, 5) for r in dv}
    for tau in [x/100 for x in range(30, 96, 5)]:
        for k in [1, 2, 3]:
            pred = {c: [e[0] for e in v if e[1] >= tau][:k] for c, v in expl.items()}
            m = micro(pred, gold, ids); res.append({'s': s, 'tau': tau, 'k': k, **m})
best = max(res, key=lambda x: x['f1']); print('BEST', best)
for s in [3, 5, 10]:
    b = max([x for x in res if x['s'] == s], key=lambda x: x['f1']); print(s, b)
json.dump({'grid': res, 'best': best}, open('tune_rules.json', 'w'))
