# CWE-Inducer: evidence-grounded CWE assignment under temporal drift

Code, rules, predictions and knowledge base for the paper *Evidence-Grounded CWE Assignment from Vulnerability
Descriptions under Temporal Drift*. The repository reproduces every table and figure of the paper.
Requirements: Python 3.11+, scikit-learn 1.9, numpy, scipy, matplotlib, rdflib.

The hand-written baseline (CyberRule) is imported from its own repository. Clone it into this folder before a full
reproduction (the quick check below does not need it):
```
git clone https://github.com/slimnithbt135/cyberRule.git
```
and set `CYBERRULE_REPO=cyberRule` (`run_all.bat` does this automatically; for `run_all.sh` use
`CYBERRULE_REPO=cyberRule CVELIST=cvelistV5 sh run_all.sh`).

## Data
```
git clone --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git cvelistV5
cd cvelistV5
git sparse-checkout set cves/2021 cves/2022 cves/2023 cves/2024 cves/2025 cves/2026
git checkout 040abf6e17da47ddefd22517c40540fc79753917
cd ..
```
`results/dataset_splits.json.gz` holds the exact 182,733 records and splits used in the paper (snapshot of 17 Oct 2026).
To skip step 1, gunzip it to `dataset.json`. Splits: train (to 30 Jun 2023, 29,931), dev (Jul–Dec 2023, 9,497),
test2024 (33,337), test2025 (41,135), test2026 (1 Jan–17 Oct 2026, 68,833).

## Quick check: recompute the main results from the released predictions (3 minutes)
```
python evaluate.py results/predictions --check results/results_p2.json
```
`results/predictions/<split>.jsonl.gz` holds, for every CVE, the gold CWEs (all and CNA-only) and the predicted CWEs of
every system, plus rule evidence. `evaluate.py` needs only numpy and scipy. It recomputes Table 4 (P, R, F1, macro-F1,
bootstrap intervals) and Table 5: label-level discordance (descriptive), CVE-level McNemar exact tests on exact-set
correctness, paired approximate-randomisation tests and paired bootstrap intervals of the F1 difference. It also
reconciles the verify hybrid's additions with the classifier's counts, and checks every value against
`results_p2.json`.

## Full reproduction (about 3 hours on 2 CPU cores)
```
python -m venv venv && . venv/bin/activate
pip install numpy scipy scikit-learn==1.9.1 matplotlib rdflib
CYBERRULE_REPO=cyberRule CVELIST=cvelistV5 sh run_all.sh
```
`run_all.sh` runs every step below in order and finishes with `compare_outputs.py`, which compares each regenerated
output with the released copy in `results/` (timing fields ignored).

| Step | Command | Output (paper element) |
|---|---|---|
| 1 | `python build_dataset.py $CVELIST` | `dataset.json`, `dataset_stats.json` (Table 2) |
| 2 | `python shift_stats.py` | `shift_stats.json` (Table 3) |
| 3 | `python tune_rules.py` | rule hyper-parameters on dev |
| 4 | `python run_rules.py` | `rule_outputs.json`, `induced_rules.json` |
| 5 | `python train_lr.py` (15–25 min) | `lr_probs.json` |
| 6 | `python train_clf2.py` | `clf2_probs.json` |
| 7 | `python cwe_names.py` | `cwe_names.json` |
| 8 | `python analyze.py` | `results_p2.json` (Table 4, Figs 2, 7, 9) |
| 9 | `python tiers.py` | `tiers.json` (Fig. 6) |
| 10 | `python clf2_tiers.py` | `clf2_results.json` (Table 8) |
| 11 | `python ablate_ir.py` | `ablate_ir.json` (Table 7) |
| 12 | `python learning_curve.py` (about 30 min) | `learning_curve.json` (Fig. 5) |
| 13 | `python expand.py` (about 1 h) | `expand.json`: per-CNA results, retraining, calibration, error types, CNA–ADP agreement, alignment sensitivity, rule statistics (Figs 3, 4, 8; Tables 9–11) |
| 14 | `python export_kb.py`, `python kb_tiers.py` | knowledge base (TTL + JSONL), `kb_meta.json`, `kb_tiers.json` (Table 13) |
| 15 | `python export_predictions.py` | `predictions/` |
| 16 | `python evaluate.py predictions --check results_p2.json` | `evaluation_report.json` (Table 5, verify-hybrid reconciliation) |
| 17 | `python multilabel.py` | `multilabel.json` (Table 6) |
| 18 | `python cna_only.py` (about 20 min) | `cna_only.json` (training on CNA labels only, Section 4.3) |
| 19 | `python figs_p2.py` | all figures |

## Human-annotation sample
`annotation/` holds a stratified sample of 300 assertions (100 per evidence tier) for independent human validation,
and the protocol (`PROTOCOL.md`). The key (tier and reference labels per item) is withheld so that the sample can still
be annotated blind; it can be regenerated with `make_annotation_sample.py`. No annotation results are reported in the paper yet.

`results/` holds the outputs used in the paper, including the induced rule table (`induced_rules.json`) and the
evidence-annotated knowledge base (`cve_cwe_evidence_kb.ttl.gz`, `cve_cwe_evidence_kb.jsonl.gz`; 143,305 CVEs,
114,471 assertions, 1,924,086 triples).

## Determinism
The snapshot is cvelistV5 commit `040abf6e17da47ddefd22517c40540fc79753917` (17 Oct 2026).
Rule induction and both rule extractors are deterministic (the three SHA-256 digests of the rule table in
`rule_outputs.json` are identical). The logistic-regression classifier uses `random_state=0` and `liblinear`;
retraining it reproduced the stored probabilities exactly (digests in `lr_probs.json`).

## Licence
Code: MIT. CVE records: CVE Program terms of use.

## Windows and other platforms
On Windows use `run_all.bat` (Command Prompt) instead of `run_all.sh`. Quote paths that contain spaces, e.g.
`python compare_outputs.py "C:\path with spaces\evidence_grounded_cwe\results"`.
The rule components are platform-independent. The classifiers' probabilities can differ in the last digits across
operating systems and Python/numpy builds, so `compare_outputs.py` may report small differences; `check_labels.py`
shows how many CVEs actually receive different labels. On Windows with Python 3.14 all reported metrics matched to
three decimals; one or two labels per test year whose probability lies at a decision threshold changed, and the SGD
results of the retraining experiment moved by about 0.001 F1.
