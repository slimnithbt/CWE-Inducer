"""Characteristics of each temporal split (Table 3 of the paper)."""
import json, collections
from ev import load
D, S = load()
train_cnas = {r['assigner'] for r in S['train']}
out = {}
for sp in ['train', 'dev', 'test2024', 'test2025', 'test2026']:
    R = S[sp]; n = len(R); vul = [r for r in R if r['assigner'] == 'VulDB']
    out[sp] = {'n': n, 'multi_label_share': sum(len(r['cwe']) > 1 for r in R) / n,
               'vuldb_share': len(vul) / n, 'vuldb_multi_share': sum(len(r['cwe']) > 1 for r in vul) / max(1, len(vul)),
               'cves_from_cnas_absent_in_training': sum(r['assigner'] not in train_cnas for r in R) / n,
               'mean_desc_words': sum(len(r['desc'].split()) for r in R) / n,
               'top_cnas': collections.Counter(r['assigner'] for r in R).most_common(5)}
json.dump(out, open('shift_stats_check.json' if __import__('sys').argv[1:] == ['--check'] else 'shift_stats.json', 'w'), indent=1)
