"""Consolidated CyberRule pipeline used for every experiment in the revision.
Stages: (1) 16-category pattern library, (2) confidence scoring with context boosters,
(3) priority-tier overlap resolution, (4) strict mapping to canonical weakness/product labels.
Flags allow each stage to be switched off for the ablation study."""
import re, sys, os
REPO = os.environ.get('CYBERRULE_REPO', '..')
sys.path.insert(0, f'{REPO}/src/cyberrule'); sys.path.insert(0, f'{REPO}/evaluation')
from CyberRule_Priority_Tier_Engine import CYBERRULE_PATTERNS as TIERED
import evaluate_cyberrule_improved_v2 as M   # strict mapping tables + map_entity_strict

BOOSTERS = ['vulnerability', 'exploit', 'attack', 'security', 'bypass', 'malicious', 'arbitrary',
            'unauthorized', 'sensitive', 'crafted', 'allows', 'enables', 'leads to', 'results in']

def n_alternatives():
    return {k: len(v['pattern'].split('|')) for k, v in TIERED.items()}

class CyberRule:
    def __init__(self, boundaries=True, overlap=True, threshold=0.6, map_conf=0.7, exclude=True):
        self.overlap, self.threshold = overlap, threshold
        self.map_conf, self.exclude = map_conf, exclude
        self.compiled = {}
        for cat, cfg in TIERED.items():
            alts = cfg['pattern'].split('|')
            if boundaries:  # longest alternative first, whole-word matching
                alts = sorted(alts, key=len, reverse=True)
                pat = r'(?<![A-Za-z0-9])(?:' + '|'.join(alts) + r')(?![A-Za-z0-9])'
            else:
                pat = cfg['pattern']
            self.compiled[cat] = (int(cfg['tier']), re.compile(pat, re.IGNORECASE))

    def _conf(self, s, text, m):
        c = 0.6 + (0.1 if len(s) > 10 else 0) + (0.05 if len(s) > 20 else 0)
        w = text[max(0, m.start() - 50): m.end() + 50].lower()
        if any(b in w for b in BOOSTERS): c += 0.05
        return min(c, 1.0)

    def entities(self, text):
        cands = []
        for cat, (tier, rx) in self.compiled.items():
            for m in rx.finditer(text):
                s = m.group(0); c = self._conf(s, text, m)
                if c >= self.threshold:
                    cands.append({'text': s, 'label': cat, 'tier': tier, 'start': m.start(), 'end': m.end(), 'confidence': round(c, 3)})
        if not self.overlap:
            return sorted(cands, key=lambda e: (e['start'], -e['tier'], e['label']))
        # within-tier: keep longest; across tiers: higher tier wins; ties broken by position then label
        def greedy(items):
            sel, occ = [], []
            for e in items:
                if all(e['end'] <= a or e['start'] >= b for a, b in occ):
                    sel.append(e); occ.append((e['start'], e['end']))
            return sel
        by_tier = {}
        for e in cands: by_tier.setdefault(e['tier'], []).append(e)
        kept = []
        for t, items in by_tier.items():
            kept += greedy(sorted(items, key=lambda e: (-(e['end'] - e['start']), e['start'], e['label'])))
        final = greedy(sorted(kept, key=lambda e: (-e['tier'], -(e['end'] - e['start']), e['start'], e['label'])))
        return sorted(final, key=lambda e: e['start'])

    def labels(self, text):
        out = set()
        for e in self.entities(text):
            if e['confidence'] < self.map_conf: continue
            if self.exclude and e['label'] in M.EXCLUDED_CATEGORIES: continue
            lab = M.map_entity_strict(e['text'], e['label'], 1.0)
            if lab: out.add(lab)
        return sorted(out)
