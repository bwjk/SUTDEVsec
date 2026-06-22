# -*- coding: utf-8 -*-
"""
===========================================================================
EVSecSim — Attack 10: Coordinated Fleet Overload (ramp-to-failure analysis)
===========================================================================

WHAT THIS IS
------------
The realistic, scaled-up grid-impact study requested in review: instead of a
single EVSE (Attack 7) or a 5-charger botnet (Attack 8), it ramps a coordinated
attacker-controlled fleet's aggregate load and finds the point at which the
PGTwin grid actually fails — at TWO injection points:

  Bus 44 — 0.4 kV "small industry" (Load4, 0.1 MW base)  -> small-site worst case
  Bus 21 — 6.6 kV industrial hub   (Load1, 1.0 MW base)  -> realistic MV charging hub
                                                             (HEADLINE)

KEY FINDING (measured below)
----------------------------
At a realistic MV connection the binding failure mode is NOT voltage collapse
but THERMAL LINE OVERLOAD: the feeder hits 100% loading at multi-MW scale while
voltage barely moves.  In reality that trips overcurrent protection -> the feeder
is disconnected.  Voltage collapse only appears when a hub-scale load is
(unrealistically) concentrated on the tiny 0.4 kV bus.

HONESTY
-------
This is a static power flow.  "Shutdown" = voltage collapse (non-convergence)
+ protection thresholds crossed; the model does not trip/cascade on its own.
Transformer thermal does not bind on this grid (loads are small vs 25 MVA
trafos) — the constraints are line ampacity (MV) and bus voltage (LV).

OUTPUT
------
  captures/grid_csv/attack10_ramp_sweep.csv            full sweep data
  captures/grid_csv/figures/figureE_ramp_to_failure.png   the paper figure
===========================================================================
"""
import os, sys, csv, warnings
sys.path.insert(0, 'grid')
warnings.filterwarnings('ignore')
import pandapower as pp
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from ZSGplussync_docker import PGT

OUTCSV = 'captures/grid_csv/attack10_ramp_sweep.csv'
OUTFIG = 'captures/grid_csv/figures/figureE_ramp_to_failure.png'
os.makedirs('captures/grid_csv/figures', exist_ok=True)

# label, load index, bus index, baseline MW, sweep ceiling kW, step kW, colour
SCENARIOS = [
    ("Bus 44 — 0.4 kV small-industry feeder (worst case)", 3, 44, 0.1,  700.0,  5.0, '#b00020'),
    ("Bus 21 — 6.6 kV MV charging hub (realistic)",        0, 21, 1.0, 8000.0, 50.0, '#1565c0'),
]


def ramp(load_idx, bus_idx, baseline_mw, ceil_kw, step_kw):
    pgt = PGT(); net = pgt.create_pgtv2()
    rows = []
    marks = {"v95": None, "v90": None, "line100": None, "trafo100": None, "collapse": None}
    kw = 0.0
    while kw <= ceil_kw:
        net.load.at[load_idx, 'p_mw'] = baseline_mw + kw / 1000.0
        try:
            pp.runpp(net, numba=False)
        except Exception:
            marks["collapse"] = kw
            break
        vm = float(net.res_bus.vm_pu[bus_idx])
        line_max = float(net.res_line.loading_percent.max())
        trafo_max = float(net.res_trafo.loading_percent.max())
        rows.append((kw, vm, line_max, trafo_max))
        if marks["v95"] is None and vm < 0.95:       marks["v95"] = kw
        if marks["v90"] is None and vm < 0.90:       marks["v90"] = kw
        if marks["line100"] is None and line_max >= 100.0:  marks["line100"] = kw
        if marks["trafo100"] is None and trafo_max >= 100.0: marks["trafo100"] = kw
        kw += step_kw
    return rows, marks


def fk(kw):
    if kw is None:
        return "not reached"
    return f"{kw/1000:.2f} MW" if kw >= 1000 else f"{kw:.0f} kW"


results = []
with open(OUTCSV, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(["scenario", "added_kw", "vm_pu_bus", "max_line_loading_pct", "max_trafo_loading_pct"])
    for label, lidx, bidx, base, ceil, step, col in SCENARIOS:
        rows, marks = ramp(lidx, bidx, base, ceil, step)
        results.append((label, bidx, col, rows, marks))
        for (kw, vm, lm, tm) in rows:
            w.writerow([label.split(" —")[0], f"{kw:.0f}", f"{vm:.4f}", f"{lm:.2f}", f"{tm:.2f}"])

# ---- threshold table to stdout ----
print("\n" + "=" * 78)
print("ATTACK 10 — Coordinated fleet overload: ramp-to-failure thresholds")
print("=" * 78)
print(f"{'Threshold':<34}{'Bus 44 (0.4 kV)':<22}{'Bus 21 (6.6 kV MV hub)':<22}")
print("-" * 78)
m44, m21 = results[0][4], results[1][4]
for key, name in [("v95", "vm_pu < 0.95 (IEC limit)"),
                  ("line100", "line loading >= 100%"),
                  ("v90", "vm_pu < 0.90 (relay risk)"),
                  ("trafo100", "trafo loading >= 100%"),
                  ("collapse", "power-flow COLLAPSE")]:
    print(f"{name:<34}{fk(m44[key]):<22}{fk(m21[key]):<22}")
print("=" * 78)

# ---- figure: 2 rows (vm_pu, line loading) x 2 cols (Bus 44, Bus 21) ----
fig, axes = plt.subplots(2, 2, figsize=(11, 7))
for col_i, (label, bidx, col, rows, marks) in enumerate(results):
    mw = [r[0] / 1000 for r in rows]
    vm = [r[1] for r in rows]
    lm = [r[2] for r in rows]

    ax_v = axes[0][col_i]
    ax_v.plot(mw, vm, color=col, lw=1.8)
    ax_v.axhline(0.95, color='#888', ls=':', lw=1, label='IEC 0.95')
    ax_v.axhline(0.90, color='#444', ls='--', lw=1, label='relay 0.90')
    if marks["collapse"]:
        ax_v.axvline(marks["collapse"] / 1000, color='k', ls='-.', lw=1.2)
        ax_v.annotate('collapse', (marks["collapse"] / 1000, 0.75), fontsize=8,
                      ha='right', rotation=90, va='center')
    ax_v.set_title(label, fontsize=9)
    ax_v.set_ylabel('Bus voltage (pu)'); ax_v.grid(alpha=0.25)
    ax_v.legend(fontsize=7, loc='lower left')

    ax_l = axes[1][col_i]
    ax_l.plot(mw, lm, color=col, lw=1.8)
    ax_l.axhline(100, color='#d35400', ls='--', lw=1.2, label='100% — thermal overload / trip')
    if marks["line100"]:
        ax_l.axvline(marks["line100"] / 1000, color='#d35400', ls=':', lw=1)
        ax_l.annotate(f'  overload @ {fk(marks["line100"])}',
                      (marks["line100"] / 1000, 105), fontsize=7, color='#d35400')
    ax_l.set_xlabel('Coordinated fleet load injected (MW)')
    ax_l.set_ylabel('Worst line loading (%)'); ax_l.grid(alpha=0.25)
    ax_l.legend(fontsize=7, loc='upper left')

fig.suptitle('Attack 10 — Coordinated fleet overload: LV worst-case (left) vs. realistic MV hub (right)',
             fontsize=11)
fig.tight_layout(rect=[0, 0, 1, 0.97])
fig.savefig(OUTFIG, dpi=160)
plt.close(fig)
print(f"\nfigure -> {OUTFIG}\ncsv    -> {OUTCSV}")
