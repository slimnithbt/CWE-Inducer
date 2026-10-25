#!/bin/sh
# Full reproduction, in paper order. Usage: CVELIST=/path/to/cvelistV5 sh run_all.sh
# (set CYBERRULE_REPO if this folder is not inside the CyberRule repository). About 3 h on 2 CPU cores.
set -e
: "${CVELIST:=cvelistV5}"; export CVELIST
run() { echo "== $(date +%H:%M:%S) $*"; "$@"; }
run python build_dataset.py "$CVELIST"
run python shift_stats.py
run python tune_rules.py
run python run_rules.py
run python train_lr.py
run python train_clf2.py
run python cwe_names.py
run python analyze.py
run python tiers.py
run python clf2_tiers.py
run python ablate_ir.py
run python learning_curve.py
run python expand.py
run python export_kb.py
run python kb_tiers.py
run python export_predictions.py
run python evaluate.py predictions --check results_p2.json
run python multilabel.py
run python cna_only.py
mkdir -p figs && run python figs_p2.py
run python compare_outputs.py results
