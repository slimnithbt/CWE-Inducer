"""Run all rule-based systems on dev/test splits; keep evidence spans for CyberRule and induced rules."""
import json, os, sys, time, hashlib
os.environ.setdefault('CYBERRULE_REPO', '..')
sys.path.insert(0, os.environ['CYBERRULE_REPO'] + '/evaluation')
from cyberrule11 import CyberRule
from evaluate_regex_baseline import RegexBaselineExtractor
from induce import RuleInducer
from cwe_eval import to_cwe
from ev import load
D, S = load()
KW = {'sql': 'SQLInjection', 'injection': 'Injection', 'xss': 'CrossSiteScripting', 'scripting': 'Scripting', 'buffer': 'BufferOverflow',
      'overflow': 'Overflow', 'remote': 'RemoteCodeExecution', 'execution': 'CodeExecution', 'traversal': 'PathTraversal', 'denial': 'DenialOfService',
      'service': 'DenialOfService', 'information': 'InformationDisclosure', 'disclosure': 'InformationDisclosure', 'privilege': 'PrivilegeEscalation',
      'escalation': 'PrivilegeEscalation', 'authentication': 'AuthenticationBypass', 'bypass': 'Bypass'}
def keyword(t):  # keyword baseline from the original repository (product keywords omitted: they never map to a CWE)
    t = t.lower(); return sorted({v for k, v in KW.items() if k in t})
cr = CyberRule(boundaries=True, overlap=True, map_conf=0.0, threshold=0.0)
rx = RegexBaselineExtractor()
t0 = time.time(); ri = RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in S['train']], [r['cwe'] for r in S['train']]); fit_s = time.time() - t0
TAU, K = 0.55, 1
json.dump(ri.to_json(TAU), open('induced_rules.json', 'w'), indent=0)
def cr_explain(t):
    out = []
    for e in cr.entities(t):
        lab = cr.labels(t[e['start']:e['end']]) if e['label'] not in ('ProgrammingLanguage', 'FileType', 'Protocol', 'Hardware', 'CryptoIssue') else []
        for l in lab:
            c = to_cwe(l)
            if c: out.append([c, e['text'], e['start'], e['end'], e['label']])
    return out
P = {'Keyword baseline': {}, 'Regex baseline': {}, 'CyberRule': {}, 'Induced rules': {}}
EVID = {'CyberRule': {}, 'Induced rules': {}}
timing = {}
for split in ['dev', 'test2024', 'test2025', 'test2026']:
    for name in P:
        t0 = time.time()
        for r in S[split]:
            t = r['desc']
            if name == 'Keyword baseline': P[name][r['id']] = sorted({c for c in (to_cwe(l) for l in keyword(t)) if c})
            elif name == 'Regex baseline': P[name][r['id']] = sorted({c for c in (to_cwe(l) for l in rx.extract(t)) if c})
            elif name == 'CyberRule':
                ev = cr_explain(t); EVID[name][r['id']] = ev; P[name][r['id']] = sorted({e[0] for e in ev})
            else:
                ex = ri.explain(t, TAU, K); EVID[name][r['id']] = [[c, g, sp[0], sp[1], s] for c, s, g, sp in ex]; P[name][r['id']] = [e[0] for e in ex]
        timing[f'{name}|{split}'] = time.time() - t0
    print(split, 'done', flush=True)
# determinism check: induce rules twice more and compare rule tables
h = [hashlib.sha256(json.dumps(RuleInducer(min_support=5, min_lb=0.3).fit([r['desc'] for r in S['train']], [r['cwe'] for r in S['train']]).to_json(TAU), sort_keys=True).encode()).hexdigest() for _ in range(2)]
h0 = hashlib.sha256(json.dumps(ri.to_json(TAU), sort_keys=True).encode()).hexdigest()
json.dump({'pred': P, 'evidence': EVID, 'timing': timing, 'induce_fit_seconds': fit_s, 'n_rules': ri.n_rules(TAU), 'rule_hashes': [h0] + h,
           'tau': TAU, 'k': K, 'min_support': 5}, open('rule_outputs.json', 'w'))
print('rules', ri.n_rules(TAU), 'hashes equal', len({h0, *h}) == 1, {k: round(v, 1) for k, v in timing.items()})
