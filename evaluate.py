"""Recompute the main results (Tables 4-5 of the paper) from the released prediction files only.

Usage: python evaluate.py [predictions_dir] [--check results_p2.json]
Needs numpy and scipy. Unit of analysis: the CVE. Every CVE has a gold set of CWE ids and a predicted set per system.

Reported per system and split: micro P/R/F1 over labels, macro-F1 over CWEs with >= 50 gold occurrences in the split,
coverage, exact-set accuracy, and a 95% percentile bootstrap interval of micro-F1 (1,000 resamples of CVEs).

Paired comparisons (A vs B) on the same CVEs:
  * label-level discordance: gold labels recovered by A only / by B only (descriptive; labels within a CVE are not
    independent, so no test is run on these counts);
  * CVE-level McNemar exact test on exact-set correctness (pred == gold), with the discordant CVE counts;
  * paired approximate-randomisation test of the micro-F1 difference (10,000 CVE-level swaps);
  * paired bootstrap 95% interval of the micro-F1 difference (same 1,000 CVE resamples as above).
For the verify hybrid vs the classifier the labels added by the hybrid are split into correct and incorrect additions,
and the hybrid's TP/FP/FN are reconciled with the classifier's."""
import json, gzip, sys, os
import numpy as np
from scipy.stats import binomtest

PD = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else 'predictions'
CHECK = sys.argv[sys.argv.index('--check') + 1] if '--check' in sys.argv else None
SPLITS = ['test2024', 'test2025', 'test2026']
MAIN = ['Keyword baseline', 'Regex baseline', 'CyberRule', 'Induced rules', 'Induced + hand rules', 'TF-IDF + LR',
        'Hybrid: rules propose, classifier verifies', 'Hybrid: classifier grounded by rules', 'Hybrid: classifier grounded by hand rules']
PAIRS = [('Induced rules', 'CyberRule'), ('Induced rules', 'Regex baseline'), ('TF-IDF + LR', 'Induced rules'),
         ('Hybrid: rules propose, classifier verifies', 'TF-IDF + LR'), ('CyberRule', 'Regex baseline')]
B, NPERM = 1000, 10000

def f1(tp, fp, fn):
    tp, fp, fn = (np.asarray(x, dtype=float) for x in (tp, fp, fn))
    d = 2 * tp + fp + fn
    return np.where(d > 0, 2 * tp / np.maximum(d, 1), 0.0)

def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0; r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)

def counts(pred, gold):
    """Per-CVE (tp, fp, fn) array for one system."""
    return np.array([[len(p & g), len(p - g), len(g - p)] for p, g in zip(pred, gold)], dtype=np.int64)

out = {}
for sp in SPLITS:
    recs = [json.loads(l) for l in gzip.open(os.path.join(PD, f'{sp}.jsonl.gz'), 'rt')]
    gold = [set(r['gold']) for r in recs]; n = len(recs)
    systems = [s for s in MAIN if s in recs[0]['pred']] + [s for s in recs[0]['pred'] if s not in MAIN]
    P = {s: [set(r['pred'].get(s, [])) for r in recs] for s in systems}
    freq = {}
    for g in gold:
        for l in g: freq[l] = freq.get(l, 0) + 1
    mlabels = sorted(l for l, k in freq.items() if k >= 50)
    rng = np.random.default_rng(2026)
    BIDX = np.zeros((B, n), dtype=np.int32)
    for b in range(B): BIDX[b] = np.bincount(rng.integers(0, n, n), minlength=n)
    res, BF, CNT = {}, {}, {}
    for s in systems:
        arr = counts(P[s], gold); CNT[s] = arr; tp, fp, fn = arr.sum(0)
        p, r, f = prf(tp, fp, fn)
        mac = []
        for l in mlabels:
            ltp = sum(1 for x, g in zip(P[s], gold) if l in x and l in g); lfp = sum(1 for x, g in zip(P[s], gold) if l in x and l not in g)
            lfn = sum(1 for x, g in zip(P[s], gold) if l not in x and l in g); mac.append(prf(ltp, lfp, lfn)[2])
        sums = BIDX @ arr; BF[s] = f1(sums[:, 0], sums[:, 1], sums[:, 2]); v = np.sort(BF[s])
        res[s] = {'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'p': p, 'r': r, 'f1': f, 'macro_f1': float(np.mean(mac)),
                  'coverage': sum(1 for x in P[s] if x) / n, 'exact_set_accuracy': sum(1 for x, g in zip(P[s], gold) if x == g) / n,
                  'f1_ci': [float(v[int(.025 * B)]), float(v[int(.975 * B) - 1])]}
    pairs = []
    prng = np.random.default_rng(7)
    for a, b in PAIRS:
        if a not in P or b not in P: continue
        la = sum(len((x & g) - y) for x, y, g in zip(P[a], P[b], gold)); lb = sum(len((y & g) - x) for x, y, g in zip(P[a], P[b], gold))
        ea = np.array([x == g for x, g in zip(P[a], gold)]); eb = np.array([y == g for y, g in zip(P[b], gold)])
        n10, n01 = int((ea & ~eb).sum()), int((~ea & eb).sum())
        mc = binomtest(n10, n10 + n01, 0.5).pvalue if n10 + n01 else 1.0
        A_, B_ = CNT[a], CNT[b]; obs = res[a]['f1'] - res[b]['f1']
        diffs = np.empty(NPERM); done = 0
        while done < NPERM:   # approximate randomisation: swap the two systems' outputs on random CVEs
            m = min(200, NPERM - done); sw = (prng.random((m, n)) < 0.5).astype(np.float64)
            shift = sw @ (B_ - A_).astype(np.float64); sa = A_.sum(0) + shift; sb = B_.sum(0) - shift
            diffs[done:done + m] = f1(sa[:, 0], sa[:, 1], sa[:, 2]) - f1(sb[:, 0], sb[:, 1], sb[:, 2]); done += m
        p_ar = (1 + int((np.abs(diffs) >= abs(obs) - 1e-12).sum())) / (NPERM + 1)
        d = np.sort(BF[a] - BF[b])
        pairs.append({'a': a, 'b': b, 'label_a_only': la, 'label_b_only': lb, 'cve_exact_a_only': n10, 'cve_exact_b_only': n01,
                      'mcnemar_cve_p': mc, 'dF1': obs, 'ar_p': p_ar, 'ar_min_p': 1 / (NPERM + 1),
                      'ci': [float(d[int(.025 * B)]), float(d[int(.975 * B) - 1])]})
    # verify hybrid vs classifier: what the hybrid adds
    V, Lr = 'Hybrid: rules propose, classifier verifies', 'TF-IDF + LR'
    add = [x - y for x, y in zip(P[V], P[Lr])]; rem = sum(len(y - x) for x, y in zip(P[V], P[Lr]))
    add_ok = sum(len(a_ & g) for a_, g in zip(add, gold)); add_bad = sum(len(a_ - g) for a_, g in zip(add, gold))
    rv, rl = res[V], res[Lr]
    recon = {'added_labels': add_ok + add_bad, 'added_correct': add_ok, 'added_incorrect': add_bad, 'removed_labels': rem,
             'cves_with_additions': sum(1 for a_ in add if a_),
             'tp_reconciles': rv['tp'] == rl['tp'] + add_ok, 'fp_reconciles': rv['fp'] == rl['fp'] + add_bad, 'fn_reconciles': rv['fn'] == rl['fn'] - add_ok,
             'precision_of_additions': add_ok / max(1, add_ok + add_bad)}
    out[sp] = {'n': n, 'macro_labels': len(mlabels), 'systems': res, 'pairs': pairs, 'verify_vs_lr': recon}
    print(f'\n== {sp}  ({n} CVEs, {len(mlabels)} CWEs in macro-F1)')
    for s in systems:
        m = res[s]; print(f"{s:44s} P={m['p']:.3f} R={m['r']:.3f} F1={m['f1']:.3f} [{m['f1_ci'][0]:.3f},{m['f1_ci'][1]:.3f}] macro={m['macro_f1']:.3f} exact={m['exact_set_accuracy']:.3f}")
    for q in pairs:
        print(f"  {q['a']} vs {q['b']}: labels {q['label_a_only']}/{q['label_b_only']}; CVEs {q['cve_exact_a_only']}/{q['cve_exact_b_only']} McNemar p={q['mcnemar_cve_p']:.2g}; "
              f"dF1={q['dF1']:+.3f} [{q['ci'][0]:+.3f},{q['ci'][1]:+.3f}] AR p={q['ar_p']:.2g}")
    print('  verify vs LR:', recon)
json.dump(out, open('evaluation_report.json', 'w'), indent=1)
if CHECK:
    ref = json.load(open(CHECK)); bad = 0
    for sp in SPLITS:
        for s in MAIN:
            for k in ['tp', 'fp', 'fn', 'p', 'r', 'f1', 'macro_f1', 'coverage']:
                a, b = out[sp]['systems'][s][k], ref['splits'][sp]['systems'][s][k]
                if abs(a - b) > 1e-12: bad += 1; print('MISMATCH', sp, s, k, a, b)
            a, b = out[sp]['systems'][s]['f1_ci'], ref['splits'][sp]['systems'][s]['f1_ci']
            if max(abs(x - y) for x, y in zip(a, b)) > 1e-12: bad += 1; print('MISMATCH CI', sp, s, a, b)
        for q in out[sp]['pairs']:
            r = next(x for x in ref['splits'][sp]['pairs'] if x['a'] == q['a'] and x['b'] == q['b'])
            if (q['label_a_only'], q['label_b_only']) != (r['a_only'], r['b_only']) or max(abs(x - y) for x, y in zip(q['ci'], r['ci'])) > 1e-12:
                bad += 1; print('MISMATCH pair', sp, q['a'], q['b'])
    print('CHECK against', CHECK, ':', 'all values identical' if not bad else f'{bad} mismatches')
