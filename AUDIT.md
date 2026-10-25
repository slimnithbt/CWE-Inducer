# Pre-submission audit (18 October 2026)

## Clean-room reproduction
- Fresh clone of https://github.com/slimnithbt135/cyberRule (commit c2b8a936, 26 Mar 2026), this folder copied in,
  new virtual environment (numpy 2.5.4, scipy 1.18.1, scikit-learn 1.9.1, rdflib 7.6.0), cvelistV5 commit 040abf6e.
- `run_all.sh` ran all 19 steps in 2 h 25 min on 2 CPU cores. `compare_outputs.py`: every regenerated JSON output, the
  JSONL knowledge base and all four prediction files are identical to the released ones (log: `clean_reproduction.log`).

## Statistics
- Unit of analysis changed to the CVE. McNemar's exact test is now applied to CVE-level exact-set correctness
  (discordant CVE counts reported); a paired approximate-randomisation test (10,000 CVE-level swaps) and the paired CVE
  bootstrap give the F1-difference inference. Label-level counts are kept, descriptively.
- Finding: TF-IDF + LR has higher micro-F1 than the induced rules, but not more exactly correct CVEs
  (tie in 2024; rules ahead in 2025 and 2026). Reported in the paper.
- Verify hybrid: added labels split into correct and incorrect (precision of additions 47–56%); TP/FP/FN reconcile
  exactly with the classifier's counts in all three years.
- `evaluate.py` recomputes Tables 4–5 from `results/predictions/` alone; all values identical to `results_p2.json`.

## Knowledge base
- JSONL: 143,305 CVEs, 114,471 assertions, 163,247 evidence spans (aligned 80,329 / unaligned 11,601 / none 22,541).
- Turtle re-parsed: 1,924,086 triples; CQ1–CQ3 give the reported counts (CQ2 19,344; CQ3 22,541).

## Labels and design
- Every ADP CWE label is a CISA Vulnrichment label added in 2024 or later; 24.9% of training CVEs have only ADP labels.
  Retraining on CNA labels only (`cna_only.py`) leaves the system ordering unchanged in every year.
- Multi-label: K = 2 or 3 rule labels lowers overall F1 in every test year; the classifier predicts < 1 label per CVE on
  average (`multilabel.py`).

## References
- All cited references were checked against publisher or indexing records. Corrections: unverifiable page ranges removed
  (ThreatZoom, Aota et al., SecureBERT, CyberGraph, Geifman & El-Yaniv); DOIs added (ThreatZoom, Aota, CVSS-BERT, CASIE,
  RelExt, SEPSES, V2W-BERT, Ouyang et al.); citation contexts tightened (Aota, Mirtaheri, Sun, Anwar, Liu).
- Added four recent CVE-to-CWE papers (Simonetto et al. 2025 and 2026, Turtiainen & Costin 2024, Schwengber Kelm et al. 2026).

## Still open (author)
- Publish release v2.0.0 at the URL cited in the paper; it does not exist yet (only cyberRule1.0.0 is public).
- Carry out the human annotation in `annotation/` before claiming human validation.
- Confirm the AI-assistance statement in Section 4.5 and in the declaration reflects your own review.
