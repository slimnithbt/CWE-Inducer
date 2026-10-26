# Human validation of the evidence tiers: annotation protocol

**Purpose.** The paper's evidence tiers rest on lexical overlap between an evidence span and the CWE name. This sample
lets independent analysts check (a) whether each assigned CWE is correct and (b) whether the evidence span actually
supports it, so that the automated tiers can be compared with human judgement.

**Sample.** `annotation_sheet.csv`: 300 knowledge-base assertions for CVEs published in 2026, 100 drawn at random from
each tier (aligned, unaligned, no evidence; seed 2026; `make_annotation_sample.py`). Rows are shuffled. The tier and the
reference CWE labels are withheld in `annotation_key.csv`, which annotators must not open.

**Annotators.** Two people with vulnerability-analysis experience, working independently. They may consult the CWE
website for definitions but not the CVE record's official CWE.

**Questions per row.**
- Q1, CWE correct: *yes* (the CWE fits the described weakness), *partly* (a parent, child or sibling CWE would fit better),
  or *no*.
- Q2, span supports CWE: *yes* (the span names or clearly describes the weakness), *partly* (the span is related but not
  sufficient on its own), *no* (the span does not support the CWE), or *no span* (the evidence column is empty).
- Notes: free text, e.g. a better CWE.

**Analysis.**
1. Agreement between annotators: Cohen's κ for Q1 and Q2 (with *yes* / *partly* / *no* as categories), plus the raw
   agreement rate. Settle disagreements by discussion and record the adjudicated label.
2. Per tier, after joining with the key: share of Q1 = *yes* (human precision) and share of Q2 = *yes*.
3. Agreement of the automated tier with Q2: does *aligned* coincide with *yes*, and *unaligned* with *partly* / *no*?
   Report a confusion table and κ.
4. Compare human precision per tier with the reference-label precision reported in the paper.

Report the results in the paper (Section 5.5 and Section 7) only once the annotation has actually been done.
