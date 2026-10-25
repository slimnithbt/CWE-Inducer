@echo off
rem Full reproduction on Windows (cmd). Run from the CWE-Inducer folder:  run_all.bat
rem Expects the CyberRule repository in .\cyberRule and the CVE records in .\cvelistV5
rem (change the two lines below if they are elsewhere). Takes about 2.5-3 hours.
set CYBERRULE_REPO=cyberRule
set CVELIST=cvelistV5
set PYTHONUTF8=1

for %%S in (
  "build_dataset.py %CVELIST%"
  "shift_stats.py"
  "tune_rules.py"
  "run_rules.py"
  "train_lr.py"
  "train_clf2.py"
  "cwe_names.py"
  "analyze.py"
  "tiers.py"
  "clf2_tiers.py"
  "ablate_ir.py"
  "learning_curve.py"
  "expand.py"
  "export_kb.py"
  "kb_tiers.py"
  "export_predictions.py"
  "evaluate.py predictions --check results_p2.json"
  "multilabel.py"
  "cna_only.py"
) do (
  echo == %TIME% python %%~S
  python %%~S
  if errorlevel 1 (echo STOPPED: python %%~S failed & exit /b 1)
)
if not exist figs mkdir figs
echo == %TIME% python figs_p2.py
python figs_p2.py || (echo STOPPED: figs_p2.py failed & exit /b 1)
echo == %TIME% python compare_outputs.py results
python compare_outputs.py results
