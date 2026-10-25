import json, numpy as np, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9, 'axes.edgecolor': '#8a8984', 'axes.linewidth': 0.6, 'xtick.color': '#52514e',
                     'ytick.color': '#52514e', 'axes.spines.top': False, 'axes.spines.right': False})
BLUE, ORANGE, AQUA, GREY, INK, MUTED = '#2a78d6', '#eb6834', '#1baf7a', '#9b9a96', '#0b0b0b', '#52514e'
A = json.load(open('results_p2.json')); T = json.load(open('tiers.json'))
# Fig 1: architecture
fig, ax = plt.subplots(figsize=(7.2, 3.0)); ax.axis('off'); ax.set_xlim(0, 100); ax.set_ylim(0, 40)
def box(x, y, w, h, t, sub, fc='#eef3fb', ec=BLUE):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.3,rounding_size=1.0', fc=fc, ec=ec, lw=0.8))
    ax.text(x + w / 2, y + h * 0.66, t, ha='center', va='center', fontsize=7.6, fontweight='bold', color=INK)
    ax.text(x + w / 2, y + h * 0.28, sub, ha='center', va='center', fontsize=6.3, color=MUTED, linespacing=1.15)
def arrow(x0, y0, x1, y1): ax.annotate('', xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle='-|>', color=MUTED, lw=0.8))
box(1, 15, 14, 10, 'CVE\ndescription', '', fc='#f4f4f2', ec=GREY)
box(22, 28, 20, 10, 'Hand-written rules', 'CyberRule: 509 forms')
box(22, 15, 20, 10, 'Induced rules', 'n-gram → CWE,\nWilson-bounded')
box(22, 2, 20, 10, 'Supervised\nclassifier', 'TF-IDF + LR', fc='#f4f4f2', ec=GREY)
box(50, 21, 20, 12, 'Evidence spans', 'phrase, offsets,\nrule source')
box(50, 3, 20, 10, 'Candidate labels', 'CWE + probability', fc='#f4f4f2', ec=GREY)
box(77, 13, 22, 16, 'Combination', 'verify: rules propose,\nclassifier filters\n\ngrounded: keep labels\nwith evidence', fc='#e8f6f0', ec=AQUA)
for y in (33, 20, 7): arrow(15.5, 20, 21.5, y)
arrow(42.5, 33, 49.5, 29); arrow(42.5, 20, 49.5, 25); arrow(42.5, 7, 49.5, 8)
arrow(70.5, 27, 76.5, 23); arrow(70.5, 8, 76.5, 17)
ax.text(88, 9.5, 'evidence tier:\naligned / unaligned / none', ha='center', fontsize=6.3, color=MUTED, va='top')
plt.savefig('figs/f1_architecture.png', dpi=300, bbox_inches='tight'); plt.close()
# Fig 2: F1 by system and year
names = ['Keyword baseline', 'Regex baseline', 'CyberRule', 'Induced rules', 'TF-IDF + LR', 'Hybrid: classifier grounded by rules', 'Hybrid: rules propose, classifier verifies']
lab = {'CyberRule': 'Hand-written rules (CyberRule)', 'Hybrid: classifier grounded by rules': 'Hybrid: grounded', 'Hybrid: rules propose, classifier verifies': 'Hybrid: verify'}
fig, ax = plt.subplots(figsize=(6.4, 4.0)); y = np.arange(len(names))
for k, (sp, col, mk) in enumerate([('test2024', BLUE, 'o'), ('test2025', ORANGE, 's'), ('test2026', AQUA, 'D')]):
    v = [A['splits'][sp]['systems'][n]['f1'] for n in names]
    ax.plot(v, y + (k - 1) * 0.27, mk, color=col, ms=6.5, mec='white', mew=1.2, label=f"Published in {sp[-4:]}")
    for yy, vv in zip(y, v): ax.text(vv + 0.012, yy + (k - 1) * 0.27, f'{vv:.3f}', va='center', fontsize=6.0, color=INK)
ax.set_yticks(y); ax.set_yticklabels([lab.get(n, n) for n in names], fontsize=7.8); ax.set_xlim(0.1, 0.8); ax.tick_params(axis='y', length=0)
ax.set_xlabel('Micro-averaged F1 (CVE List CWE labels)'); ax.grid(axis='x', color='#e6e5e0', lw=0.6); ax.set_axisbelow(True)
ax.legend(frameon=False, fontsize=7.5, loc='lower right')
plt.savefig('figs/f2_f1.png', dpi=300, bbox_inches='tight'); plt.close()
# Fig 3: risk-coverage 2025
rc = A['splits']['test2026']['risk_coverage']
fig, ax = plt.subplots(figsize=(4.8, 3.2))
for key, col, lb in [('confidence', GREY, 'Ranked by classifier confidence'), ('grounded_first', AQUA, 'Grounded labels first, then confidence')]:
    xs, ys = zip(*rc[key]); ax.plot(xs, ys, color=col, lw=2, label=lb)
ax.set_xlabel('Coverage (share of CVEs labelled automatically)'); ax.set_ylabel('Precision of top-1 label'); ax.set_ylim(0.6, 1.0); ax.set_xlim(0, 1)
ax.axvline(rc['grounded_share'], color='#c3c2b7', lw=0.8, ls='--'); ax.text(rc['grounded_share'] + 0.01, 0.985, 'all grounded labels used', ha='left', va='top', fontsize=6.5, color=MUTED)
ax.grid(color='#f0efec', lw=0.5); ax.legend(frameon=False, fontsize=7.2, loc='lower left')
plt.savefig('figs/f3_risk_coverage.png', dpi=300, bbox_inches='tight'); plt.close()
# Fig 4: evidence tiers
fig, ax = plt.subplots(figsize=(5.6, 2.8)); tiers = ['aligned', 'unaligned', 'none']; tl = ['Aligned rule evidence', 'Unaligned rule evidence', 'No rule evidence']
x = np.arange(3)
for k, (sp, col) in enumerate([('test2024', BLUE), ('test2025', ORANGE), ('test2026', AQUA)]):
    v = [T[sp]['tiers'][t]['precision'] for t in tiers]; s = [T[sp]['tiers'][t]['share'] for t in tiers]
    bars = ax.bar(x + (k - 1) * 0.27, v, 0.25, color=col, label=sp[-4:], edgecolor='white', linewidth=1)
    for xx, vv, ss in zip(x, v, s): ax.text(xx + (k - 1) * 0.27, vv + 0.02, f'{vv:.2f}\n({100*ss:.0f}%)', ha='center', fontsize=5.6, color=INK)
ax.set_xticks(x); ax.set_xticklabels(tl, fontsize=7.6); ax.set_ylim(0, 1.15); ax.set_ylabel('Precision of classifier labels'); ax.legend(frameon=False, fontsize=7.5, ncol=3, loc='upper right')
ax.grid(axis='y', color='#eeede9', lw=0.5); ax.set_axisbelow(True)
plt.savefig('figs/f4_tiers.png', dpi=300, bbox_inches='tight'); plt.close()
# Fig 5: learning curve
try:
    LC = json.load(open('learning_curve.json'))
    full = {'n_train': A['n']['train'], 'induced_f1': A['splits']['test2025']['systems']['Induced rules']['f1'], 'lr_f1': A['splits']['test2025']['systems']['TF-IDF + LR']['f1']}
    pts = LC + [full]
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    ax.plot([p['n_train'] for p in pts], [p['induced_f1'] for p in pts], '-o', color=BLUE, lw=2, ms=5, mec='white', label='Induced rules')
    ax.plot([p['n_train'] for p in pts], [p['lr_f1'] for p in pts], '-s', color=GREY, lw=2, ms=5, mec='white', label='TF-IDF + LR')
    ax.set_xscale('log'); ax.minorticks_off(); xt=[p['n_train'] for p in pts]; ax.set_xticks(xt); ax.set_xticklabels([f'{x:,}' for x in xt], fontsize=7); ax.set_xlabel('Training CVEs (log scale)'); ax.set_ylabel('F1 on CVEs published in 2025'); ax.grid(color='#f0efec', lw=0.5)
    ax.legend(frameon=False, fontsize=7.5, loc='lower right')
    plt.savefig('figs/f5_learning_curve.png', dpi=300, bbox_inches='tight'); plt.close()
except FileNotFoundError: pass
# Fig 6: per-CWE F1 heatmap (2025, ten most frequent CWEs)
S25 = A['splits']['test2026']['systems']; cw = list(S25['TF-IDF + LR']['per_cwe'].keys())
rows = ['CyberRule', 'Induced rules', 'TF-IDF + LR', 'Hybrid: rules propose, classifier verifies']
M = np.array([[S25[r]['per_cwe'].get(c, 0) for c in cw] for r in rows])
fig, ax = plt.subplots(figsize=(6.6, 2.4)); im = ax.imshow(M, cmap='Blues', vmin=0, vmax=1, aspect='auto')
for i in range(M.shape[0]):
    for j in range(M.shape[1]): ax.text(j, i, f'{M[i,j]:.2f}', ha='center', va='center', fontsize=6.6, color='white' if M[i, j] > 0.6 else INK)
ax.set_xticks(range(len(cw))); ax.set_xticklabels([f'CWE-{c}' for c in cw], fontsize=7, rotation=35, ha='right')
ax.set_yticks(range(len(rows))); ax.set_yticklabels(['Hand-written rules', 'Induced rules', 'TF-IDF + LR', 'Hybrid: verify'], fontsize=7.5)
for s in ax.spines.values(): s.set_visible(False)
cb = plt.colorbar(im, ax=ax, fraction=0.025, pad=0.02); cb.ax.tick_params(labelsize=6.5); cb.set_label('F1', fontsize=7)
plt.savefig('figs/f6_per_cwe.png', dpi=300, bbox_inches='tight'); plt.close()
print('figs ok')
# ---------- extension figures ----------
E = json.load(open('expand.json'))
# Fig 7: reliability diagram
fig, ax = plt.subplots(figsize=(4.4, 3.4))
ax.plot([0.5, 1], [0.5, 1], color='#c3c2b7', lw=0.8, ls='--')
for key, col, mk, lb in [('induced', BLUE, 'o', 'Induced rules (Wilson score)'), ('lr', GREY, 's', 'TF-IDF + LR (probability)')]:
    pts = E['calibration'][key]
    ax.plot([p['mean_score'] for p in pts], [p['precision'] for p in pts], '-' + mk, color=col, lw=1.6, ms=5, mec='white', label=lb)
ax.set_xlim(0.5, 1.0); ax.set_ylim(0.2, 1.0); ax.set_xlabel('Mean score in bin'); ax.set_ylabel('Observed precision (2026)')
ax.grid(color='#f0efec', lw=0.5); ax.legend(frameon=False, fontsize=7.2, loc='upper left')
plt.savefig('figs/f7_calibration.png', dpi=300, bbox_inches='tight'); plt.close()
# Fig 8: per-CNA F1 heatmap (2025)
rows = E['per_cna']['test2026']; cols = [('hand', 'Hand-written'), ('induced', 'Induced'), ('lr', 'TF-IDF + LR'), ('verify', 'Hybrid: verify')]
M = np.array([[r[k] for k, _ in cols] for r in rows])
fig, ax = plt.subplots(figsize=(5.0, 3.2)); im = ax.imshow(M, cmap='Blues', vmin=0, vmax=1, aspect='auto')
for i in range(M.shape[0]):
    for j in range(M.shape[1]): ax.text(j, i, f'{M[i,j]:.2f}', ha='center', va='center', fontsize=7, color='white' if M[i, j] > 0.6 else INK)
ax.set_xticks(range(len(cols))); ax.set_xticklabels([c for _, c in cols], fontsize=7.5)
ax.set_yticks(range(len(rows))); ax.set_yticklabels([f"{r['assigner']} ({r['n']:,})" for r in rows], fontsize=7.5)
for s in ax.spines.values(): s.set_visible(False)
cb = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02); cb.ax.tick_params(labelsize=6.5); cb.set_label('F1', fontsize=7)
plt.savefig('figs/f8_per_cna.png', dpi=300, bbox_inches='tight'); plt.close()
print('ext figs ok')

RF = E['refresh_2026']; RO = E['rolling_2026']
names9 = list(RF.keys()); xs = np.arange(len(names9) + 1)
fig, ax = plt.subplots(figsize=(5.4, 2.9))
iv = [RF[n]['induced']['f1'] for n in names9] + [RO['induced']['f1']]; sv = [RF[n]['sgd']['f1'] for n in names9] + [RO['sgd']['f1']]
ax.bar(xs - 0.19, iv, 0.36, color=BLUE, label='Induced rules', edgecolor='white'); ax.bar(xs + 0.19, sv, 0.36, color=GREY, label='SGD classifier', edgecolor='white')
for x0, a, b in zip(xs, iv, sv):
    ax.text(x0 - 0.19, a + 0.008, f'{a:.3f}', ha='center', fontsize=6, color=INK); ax.text(x0 + 0.19, b + 0.008, f'{b:.3f}', ha='center', fontsize=6, color=INK)
ax.set_xticks(xs); ax.set_xticklabels(['Original\ntraining', '+ Jul–Dec\n2023', '+ 2024', '+ 2025', '+ 2025 and\nre-tuned'], fontsize=7)
ax.set_ylim(0.3, 0.7); ax.set_ylabel('F1 on CVEs published in 2026'); ax.legend(frameon=False, fontsize=7.2, loc='upper left', ncol=2)
ax.grid(axis='y', color='#eeede9', lw=0.5); ax.set_axisbelow(True)
plt.savefig('figs/f9_refresh.png', dpi=300, bbox_inches='tight'); plt.close()
print('refresh fig ok')
