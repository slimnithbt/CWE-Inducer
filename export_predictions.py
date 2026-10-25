"""Write the per-CVE predictions of every system to predictions/<split>.jsonl.gz.

Each line: {"id", "published", "assigner", "gold", "gold_cna", "pred": {system: [CWE ids]}, "lr_top": [[cwe, p], ...]}.
Thresholds are the dev-selected values stored in results_p2.json, so the files contain exactly the outputs scored
in the paper. evaluate.py recomputes Tables 4-5 from these files alone."""
import json, gzip, os
from ev import load
D, S = load()
R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); A = json.load(open('results_p2.json'))
TH, VT = A['lr_threshold'], A['verify_t']
C2 = json.load(open('clf2_probs.json')); C2R = json.load(open('clf2_results.json')); TH2 = C2R['threshold']
def lr_pred(c, th=TH): return [x for x, p in L['probs'][c] if p >= th]
def prob(c, l): return dict(L['probs'][c]).get(l, 0.0)
def clf2_pred(c): return [x for x, p in C2['probs'][c] if p >= TH2]
def ev_i(c): return {e[0] for e in R['evidence']['Induced rules'].get(c, [])} | {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
def ev_h(c): return {e[0] for e in R['evidence']['CyberRule'].get(c, [])}
os.makedirs('predictions', exist_ok=True)
meta = {'lr_threshold': TH, 'verify_t': VT, 'sgd_threshold': TH2, 'systems': []}
for sp in ['dev', 'test2024', 'test2025', 'test2026']:
    with gzip.open(f'predictions/{sp}.jsonl.gz', 'wt') as f:
        for r in S[sp]:
            c = r['id']; lp = lr_pred(c); E = ev_i(c); EH = ev_h(c)
            pred = {n: sorted(R['pred'][n][c]) for n in ['Keyword baseline', 'Regex baseline', 'CyberRule', 'Induced rules']}
            pred['Induced + hand rules'] = sorted(set(R['pred']['Induced rules'][c]) | set(R['pred']['CyberRule'][c]))
            pred['TF-IDF + LR'] = sorted(lp)
            pred['Hybrid: rules propose, classifier verifies'] = sorted(set(lp) | {l for l in E if prob(c, l) >= VT})
            pred['Hybrid: classifier grounded by rules'] = sorted(l for l in lp if l in E)
            pred['Hybrid: classifier grounded by hand rules'] = sorted(l for l in lp if l in EH)
            if c in C2['probs']: pred['SGD classifier'] = sorted(clf2_pred(c))
            f.write(json.dumps({'id': c, 'published': r['pub'], 'assigner': r['assigner'], 'gold': r['cwe'], 'gold_cna': r['cna_cwe'],
                                'pred': pred, 'lr_top': L['probs'][c][:3],
                                'evidence': {'induced': R['evidence']['Induced rules'].get(c, []), 'hand': R['evidence']['CyberRule'].get(c, [])}}) + '\n')
    meta['systems'] = list(pred)
json.dump(meta, open('predictions/meta.json', 'w'), indent=1); print(meta)
