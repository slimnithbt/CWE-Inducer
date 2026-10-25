"""Single- versus multi-label behaviour.
(1) Induced rules with K = 1, 2, 3 labels per description: tau fixed at 0.55 and tau re-selected on dev for each K.
(2) Verify hybrid fed with K = 1 or K = 3 rule candidates (t re-selected on dev).
(3) For the main systems: mean labels per CVE and F1 on CVEs with one gold CWE vs CVEs with two or more."""
import json, gzip
from ev import load, micro
from induce import RuleInducer
D, S = load()
R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); A = json.load(open('results_p2.json')); TR = json.load(open('tune_rules.json'))
TH = A['lr_threshold']
ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in S['train']], [r['cwe'] for r in S['train']])
dev_tau = {k: max((x for x in TR['grid'] if x['s'] == 5 and x['k'] == k), key=lambda x: x['f1'])['tau'] for k in (1, 2, 3)}
def prob(c, l): return dict(L['probs'][c]).get(l, 0.0)
def lr(c): return [x for x, p in L['probs'][c] if p >= TH]
def subset_scores(pred, rows):
    g = {r['id']: r['cwe'] for r in rows}; one = [c for c in g if len(g[c]) == 1]; many = [c for c in g if len(g[c]) > 1]
    m = micro(pred, g, list(g)); return {'all': m, 'single_gold': micro(pred, g, one), 'multi_gold': micro(pred, g, many),
            'labels_per_cve': sum(len(pred[c]) for c in g) / len(g), 'n_single': len(one), 'n_multi': len(many)}
# cache rule explanations at the loosest setting, then filter
EX = {sp: {r['id']: ri.explain(r['desc'], 0.3, 3) for r in S[sp]} for sp in ['dev', 'test2024', 'test2025', 'test2026']}
def rules(sp, tau, k): return {c: [e[0] for e in ex if e[1] >= tau][:k] for c, ex in EX[sp].items()}
def verify(sp, tau, k, t):
    out = {}
    for c, ex in EX[sp].items():
        cand = [e[0] for e in ex if e[1] >= tau][:k]
        ev = set(cand) | {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
        out[c] = sorted(set(lr(c)) | {l for l in ev if prob(c, l) >= t})
    return out
gdev = {r['id']: r['cwe'] for r in S['dev']}; idev = list(gdev)
vt = {k: max([0.0, 0.01, 0.02, 0.05, 0.1, 0.15, 0.2], key=lambda t: micro(verify('dev', dev_tau[k], k, t), gdev, idev)['f1']) for k in (1, 3)}
out = {'dev_tau': dev_tau, 'verify_t': vt, 'rules': {}, 'verify': {}, 'subsets': {}}
for sp in ['test2024', 'test2025', 'test2026']:
    rows = S[sp]
    out['rules'][sp] = {f'K={k}, tau={tau}': subset_scores(rules(sp, tau, k), rows) for k in (1, 2, 3) for tau in sorted({0.55, dev_tau[k]})}
    out['verify'][sp] = {f'rule candidates K={k}': subset_scores(verify(sp, dev_tau[k], k, vt[k]), rows) for k in (1, 3)}
    recs = [json.loads(l) for l in gzip.open(f'predictions/{sp}.jsonl.gz', 'rt')]
    out['subsets'][sp] = {s: subset_scores({r['id']: r['pred'][s] for r in recs}, rows) for s in
                          ['CyberRule', 'Induced rules', 'TF-IDF + LR', 'Hybrid: rules propose, classifier verifies', 'Hybrid: classifier grounded by rules']}
    print('==', sp)
    for grp in ['rules', 'verify', 'subsets']:
        for n, v in out[grp][sp].items():
            print(f"  {n:46s} F1={v['all']['f1']:.3f} P={v['all']['p']:.3f} R={v['all']['r']:.3f} single={v['single_gold']['f1']:.3f} multi={v['multi_gold']['f1']:.3f} lab/CVE={v['labels_per_cve']:.2f}")
json.dump(out, open('multilabel.json', 'w'), indent=1)
