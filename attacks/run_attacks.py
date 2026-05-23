#!/usr/bin/env python3
"""
OCPP Attack Orchestrator
Run: python run_attacks.py
Each step opens new terminal window(s). Type 'next' (or just Enter) to advance.
"""
import subprocess, sys, os, time, atexit, tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
PY   = sys.executable
TEE  = os.path.join(BASE, "_tee.py")  # kept for future use
LOGS = os.path.join(BASE, "logs")
os.makedirs(LOGS, exist_ok=True)

# Temp .bat files — cleaned up on exit
_bats = []
@atexit.register
def _cleanup():
    for f in _bats:
        try: os.unlink(f)
        except: pass

# ── helpers ───────────────────────────────────────────────────────────────────

def terminal(title, script_args, delay_after=0):
    """Open a new cmd window running script_args.
    Uses a .bat file so spaced paths are never double-quoted inside cmd /k.
    chcp 65001 switches the console to UTF-8 so Unicode chars in scripts work.
    """
    cmd_line = f'"{PY}" {script_args}'

    fd, bat = tempfile.mkstemp(suffix=".bat", prefix="_run_", dir=BASE)
    _bats.append(bat)
    with os.fdopen(fd, "w") as f:
        f.write(
            f"@echo off\n"
            f"chcp 65001 >nul\n"          # UTF-8 console — fixes arrow/unicode chars
            f"title {title}\n"
            f"{cmd_line}\n"
        )

    p = subprocess.Popen(
        ["cmd", "/k", bat],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        cwd=BASE,
    )
    if delay_after:
        time.sleep(delay_after)
    return p

def kill(*procs):
    for p in procs:
        if p and p.poll() is None:
            p.terminate()
            try:    p.wait(timeout=3)
            except: p.kill()

def pause(msg=""):
    sep = "-" * 60
    if msg:
        print(f"\n  {msg}")
    print(f"  {sep}")
    print("  Press Enter (or type 'next') to continue, Ctrl+C to quit.")
    print(f"  {sep}")
    try:
        while True:
            if input("  > ").strip().lower() in ("", "next", "n"):
                return
    except KeyboardInterrupt:
        print("\n\nAborted.")
        sys.exit(0)

def header(step, title, desc):
    w = 62
    print("\n" + "=" * w)
    print(f"  STEP {step}  -  {title}")
    print("=" * w)
    print(f"  {desc}")

# ── steps ─────────────────────────────────────────────────────────────────────

def step0_csms():
    header(0, "CSMS Server", "Central Management System - stays open for all attacks.")
    print("  Opens:  csms_server4.py  (ws://127.0.0.1:9000)")
    pause("Starting CSMS server...")
    p = terminal("CSMS  ws://127.0.0.1:9000", "csms_server4.py", delay_after=1.5)
    print("  [OK] CSMS running.")
    return p

def step0b_grid_diagram():
    header("0b", "Grid Topology Diagram",
           "Builds the pandapower grid twin and opens an interactive\n"
           "  Plotly diagram in your browser showing the full 220kV->66kV->22kV\n"
           "  network with 500 EV chargers and 7 town loads.")
    print("  Opens:  a6breakers.py  (grid_visualization.html in browser)")
    pause()
    p = terminal("Grid Topology - a6breakers", "a6breakers.py", delay_after=3)
    print("  [OK] Grid diagram generating — browser should open automatically.")
    print("       (the terminal will close once the HTML is written)")
    pause("When ready to start the attacks...")
    kill(p)

def step1_saiflow(csms):
    header(1, "SaiFlow DoS",
           "Rogue charger connects with the same CP ID (CP_1).\n"
           "  OCPP 1.6 has no duplicate-connection detection, so the\n"
           "  real EVSE is shadowed and its messages are discarded.\n"
           "  Attacker floods ~1000 Heartbeats/sec for 60 seconds.")
    print("  Opens:  evse_client4_fixed.py          (legitimate EVSE - the victim)")
    print("          attack_saiflow_dos.py           (rogue CP_1 - the attacker)")
    pause()
    p_evse = terminal("Attack 1 - Legitimate EVSE (victim)",
                      "evse_client4_fixed.py", delay_after=2)
    p_atk  = terminal("Attack 1 - SaiFlow DoS (rogue CP_1)",
                      "attack_saiflow_dos.py --duration 60")
    print("  [OK] Both running. Watch the CSMS window - once the rogue connects,")
    print("       the legitimate EVSE's MeterValues stop appearing.")
    pause("When ready to move to the next attack...")
    kill(p_atk, p_evse)

def step2_fdi(csms):
    header(2, "False Data Injection",
           "Compromised EVSE sends fabricated MeterValues.\n"
           "  Phase 1  (0-15 s)  : normal readings\n"
           "  Phase 2  (15-30 s) : under-report  - draws 60 kW, reports 0 kW\n"
           "  Phase 3  (30-45 s) : over-report   - idle, reports 999 kW")
    print("  Opens:  attack_fdi.py")
    pause()
    p = terminal("Attack 2 - False Data Injection", "attack_fdi.py")
    print("  [OK] FDI running. Watch the CSMS window for spoofed meter values.")
    pause("When ready to move to the next attack...")
    kill(p)

def step3_mitm(csms):
    header(3, "MITM Session Hijack",
           "Transparent WebSocket proxy on port 9001.\n"
           "  Phase 1  (0-10 s)  : log only (relay unchanged)\n"
           "  Phase 2  (10-20 s) : tamper MeterValues -> 999 kW\n"
           "  Phase 3  (20 s+)   : inject forged StopTransaction")
    print("  Opens:  attack_mitm_session.py  (proxy on port 9001)")
    print("          evse_client4_fixed.py --url ws://127.0.0.1:9001  (EVSE via proxy)")
    pause()
    p_proxy = terminal("Attack 3 - MITM Proxy :9001",
                       "attack_mitm_session.py", delay_after=2)
    p_evse  = terminal("Attack 3 - EVSE via Proxy",
                       "evse_client4_fixed.py --url ws://127.0.0.1:9001")
    print("  [OK] Proxy and EVSE running. Watch the proxy window for tampered messages.")
    pause("When ready to move to the next attack...")
    kill(p_evse, p_proxy)

def step4_load(csms):
    header(4, "Coordinated Load Altering",
           "Botnet of 10 compromised EVSEs - synchronized phases:\n"
           "  Phase 1  (0-20 s)  : baseline  - all bots at 220 kW\n"
           "  Phase 2  (20-40 s) : surge     - simultaneous max load\n"
           "  Phase 3  (40-60 s) : drop      - simultaneous zero load\n"
           "  Phase 4  (60-80 s) : oscillate - 22 MW swings every 5 s\n"
           "  Grid twin reports voltage and frequency deviation per phase.")
    print("  Opens:  attack_load_altering.py --bots 10")
    pause()
    p = terminal("Attack 4 - Load Altering (10 bots)",
                 "attack_load_altering.py --bots 10")
    print("  [OK] Load altering running. Watch grid impact in the attack window.")
    pause("When ready to finish...")
    kill(p)

def done(csms):
    header("Done", "All attacks complete", "Shutting down CSMS.")
    kill(csms)
    print("\n  Done. All terminal windows can be closed.\n")

# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 62)
    print("  OCPP 1.6 Attack Orchestrator - SUTD Thesis")
    print("  Each attack opens in its own terminal window.")
    print("  Type 'next' or press Enter to advance each step.")
    print("=" * 62)

    csms = step0_csms()
    step0b_grid_diagram()
    step1_saiflow(csms)
    step2_fdi(csms)
    step3_mitm(csms)
    step4_load(csms)
    done(csms)
