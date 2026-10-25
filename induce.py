"""Deterministic induction of phrase -> CWE rules from labelled CVE descriptions.

A rule is an n-gram (1-4 tokens, no digits, not starting/ending with a stop word) together with a CWE.
Its score is the Wilson 95% lower bound of P(CWE | phrase) estimated on the training set. At prediction
time every rule whose phrase occurs in the description fires; for each CWE the strongest firing rule is
kept, and the top-k CWEs whose best score reaches tau are output, each with the matched span as evidence.
Everything is integer counting and sorting, so training and prediction are deterministic."""
import re, math, json
from collections import Counter, defaultdict

STOP = set('''a an the of in on at to for from by with and or but is are was were be been being this that these those it its as
which who whom whose when where while than then there their they them via into onto over under up down out not no nor so such
can could may might will would shall should must do does did has have had having also any all some each other more most only own
same too very just after before during through about against between because if else both either neither per upon within without
version versions prior affected affects allow allows allowed user users attacker attackers remote remotely vulnerability vulnerable
issue issues component components product products'''.split())
TOK = re.compile(r"[a-z][a-z0-9]*(?:[-'][a-z0-9]+)*")

def tokens(text):
    return [(m.group(0), m.start(), m.end()) for m in TOK.finditer(text.lower())]

def ngrams(toks, nmax=4):
    out = {}
    for n in range(1, nmax + 1):
        for i in range(len(toks) - n + 1):
            g = toks[i:i + n]; words = [w for w, _, _ in g]
            if words[0] in STOP or words[-1] in STOP: continue
            if any(any(ch.isdigit() for ch in w) for w in words): continue
            key = ' '.join(words)
            if key not in out: out[key] = (g[0][1], g[-1][2])   # first occurrence span
    return out

def wilson_lb(k, n, z=1.96):
    if n == 0: return 0.0
    p = k / n; d = 1 + z * z / n
    return (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d

class RuleInducer:
    def __init__(self, min_support=5, min_lb=0.5, nmax=4):
        self.min_support, self.min_lb, self.nmax = min_support, min_lb, nmax
        self.rules = {}   # phrase -> list of (cwe, lb, k, n) sorted by lb desc

    def fit(self, texts, labels):
        df = Counter(); grams = []
        for t in texts:
            g = set(ngrams(tokens(t), self.nmax)); grams.append(g); df.update(g)
        keep = {g for g, c in df.items() if c >= self.min_support}
        joint = Counter()
        for g, ls in zip(grams, labels):
            for x in g & keep:
                for l in ls: joint[(x, l)] += 1
        rules = defaultdict(list)
        for (x, l), k in joint.items():
            if k < self.min_support: continue
            lb = wilson_lb(k, df[x])
            if lb >= self.min_lb: rules[x].append((l, round(lb, 6), k, df[x]))
        self.rules = {x: sorted(v, key=lambda r: (-r[1], r[0])) for x, v in sorted(rules.items())}
        return self

    def explain(self, text, tau, k):
        """Return [(cwe, score, phrase, (start, end))] for the top-k CWEs reaching tau."""
        best = {}
        for g, span in ngrams(tokens(text), self.nmax).items():
            for (l, lb, kk, n) in self.rules.get(g, ()):
                if lb < tau: break
                cur = best.get(l)
                if cur is None or (lb, len(g)) > (cur[1], len(cur[2])): best[l] = (l, lb, g, span)
        out = sorted(best.values(), key=lambda r: (-r[1], r[0]))[:k]
        return out

    def predict(self, text, tau, k):
        return [r[0] for r in self.explain(text, tau, k)]

    def n_rules(self, tau=None):
        return sum(1 for v in self.rules.values() for r in v if tau is None or r[1] >= tau)

    def to_json(self, tau):
        return [{'phrase': x, 'cwe': l, 'score': lb, 'support': k, 'df': n} for x, v in self.rules.items() for (l, lb, k, n) in v if lb >= tau]
