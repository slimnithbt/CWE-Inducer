"""Export the evidence-grounded CVE->CWE knowledge base (test 2024, 2025 and 2026) as JSONL and RDF Turtle (PROV-O),
then check it parses and answer three competency questions with SPARQL."""
import json, re, time, gzip
from rdflib import Graph, Namespace, Literal, URIRef, RDF, XSD
from rdflib.namespace import PROV, RDFS
from ev import load
D, S = load(); R = json.load(open('rule_outputs.json')); L = json.load(open('lr_probs.json')); N = json.load(open('cwe_names.json'))
A = json.load(open('results_p2.json')); TH, VT = A['lr_threshold'], A['verify_t']
STOPW = set('of the a an to in on for and or with by from into used during improper incorrect missing'.split())
def aligned(ph, c):
    nt = {w[:5] for w in re.findall(r'[a-z]+', N.get(c, '').lower()) if w not in STOPW and len(w) > 2}
    return bool(nt & {w[:5] for w in re.findall(r'[a-z]+', ph.lower()) if w not in STOPW and len(w) > 2})
V = Namespace('https://github.com/slimnithbt135/cyberRule/ns#'); CVE = Namespace('https://www.cve.org/CVERecord?id=')
CWE = Namespace('https://cwe.mitre.org/data/definitions/')
g = Graph(); g.bind('v', V); g.bind('prov', PROV); g.bind('cwe', CWE)
act = V['run-hybrid-verify-1.0']; g.add((act, RDF.type, PROV.Activity)); g.add((act, RDFS.label, Literal('Rules propose, classifier verifies (deterministic)')))
n_ass = n_ev = 0; rows = []
for sp in ['test2024', 'test2025', 'test2026']:
    for r in S[sp]:
        c = r['id']; probs = dict((l, p) for l, p in L['probs'][c])
        ev = {}
        for src in ['Induced rules', 'CyberRule']:
            for e in R['evidence'][src].get(c, []): ev.setdefault(e[0], []).append((src, e[1], e[2], e[3]))
        labels = sorted({l for l, p in probs.items() if p >= TH} | {l for l in ev if probs.get(l, 0) >= VT})
        rec = {'cve': c, 'published': r['pub'], 'assertions': []}
        cu = URIRef(CVE[c]); g.add((cu, RDF.type, V.Vulnerability))
        for i, l in enumerate(labels):
            tier = 'none' if l not in ev else ('aligned' if any(aligned(x[1], l) for x in ev[l]) else 'unaligned')
            au = V[f'{c}-a{i}']; n_ass += 1
            g.add((cu, V.hasWeaknessAssertion, au)); g.add((au, RDF.type, V.WeaknessAssertion))
            g.add((au, V.cwe, URIRef(CWE[f'{l}.html']))); g.add((au, V.cweId, Literal(f'CWE-{l}')))
            g.add((au, V.classifierProbability, Literal(round(probs.get(l, 0.0), 4), datatype=XSD.decimal)))
            g.add((au, V.evidenceTier, Literal(tier))); g.add((au, PROV.wasGeneratedBy, act))
            evs = []
            for j, (src, txt, s0, s1) in enumerate(ev.get(l, [])):
                eu = V[f'{c}-a{i}-e{j}']; n_ev += 1
                g.add((au, PROV.wasDerivedFrom, eu)); g.add((eu, RDF.type, V.EvidenceSpan)); g.add((eu, V.text, Literal(txt)))
                g.add((eu, V.start, Literal(s0, datatype=XSD.integer))); g.add((eu, V.end, Literal(s1, datatype=XSD.integer)))
                g.add((eu, V.ruleSource, Literal('induced' if src == 'Induced rules' else 'hand-written')))
                evs.append({'source': src, 'text': txt, 'start': s0, 'end': s1})
            rec['assertions'].append({'cwe': l, 'probability': probs.get(l, 0.0), 'tier': tier, 'evidence': evs})
        rows.append(rec)
with gzip.open('cve_cwe_evidence_kb.jsonl.gz', 'wt') as f:
    for x in rows: f.write(json.dumps(x) + '\n')
t0 = time.time(); g.serialize('cve_cwe_evidence_kb.ttl', format='turtle'); ser = time.time() - t0
g2 = Graph(); t0 = time.time(); g2.parse('cve_cwe_evidence_kb.ttl', format='turtle'); parse_s = time.time() - t0
Q = {'CQ1: assertions per evidence tier': 'PREFIX v: <%s> SELECT ?t (COUNT(?a) AS ?n) WHERE { ?a a v:WeaknessAssertion ; v:evidenceTier ?t } GROUP BY ?t ORDER BY ?t' % V,
     'CQ2: CVEs with an aligned CWE-79 assertion': 'PREFIX v: <%s> SELECT (COUNT(DISTINCT ?c) AS ?n) WHERE { ?c v:hasWeaknessAssertion ?a . ?a v:cweId "CWE-79" ; v:evidenceTier "aligned" }' % V,
     'CQ3: assertions without any evidence span (review queue)': 'PREFIX v: <%s> PREFIX prov: <http://www.w3.org/ns/prov#> SELECT (COUNT(?a) AS ?n) WHERE { ?a a v:WeaknessAssertion . FILTER NOT EXISTS { ?a prov:wasDerivedFrom ?e } }' % V}
qres = {}
for k, q in Q.items():
    t0 = time.time(); res = [[str(x) for x in row] for row in g2.query(q)]; qres[k] = {'rows': res, 'seconds': round(time.time() - t0, 2)}
    print(k, res, qres[k]['seconds'])
meta = {'cves': len(rows), 'assertions': n_ass, 'evidence_spans': n_ev, 'triples': len(g2), 'serialize_seconds': ser, 'parse_seconds': parse_s, 'queries': qres}
json.dump(meta, open('kb_meta.json', 'w'), indent=1); print({k: v for k, v in meta.items() if k != 'queries'})
