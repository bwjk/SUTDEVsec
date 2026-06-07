"""
===========================================================================
EVSecSim — OCPP 2.0.1 legitimate EVSE (baseline)
===========================================================================

The 2.0.1 counterpart of core/evse_client4_fixed.py used for the
`v201-normal` baseline.  Connects to the 2.0.1 CSMS, boots, opens a
transaction (TransactionEvent[Started]), and reports honest power via
TransactionEvent[Updated] every few seconds, then ends cleanly.

This is the "truthful charger" the FDI attack later impersonates — its
honest reporting is the baseline the operator expects to see.
===========================================================================
"""

import asyncio
import os
import argparse
import websockets
from datetime import datetime, timezone

from ocpp.v201 import ChargePoint as cp, call
from ocpp.v201.enums import RegistrationStatusEnumType

CSMS_URL = os.environ.get("CSMS_URL", "ws://127.0.0.1:9100")
CP_ID    = os.environ.get("CP_ID", "CP-201-1")


def now():
    return datetime.now(timezone.utc).isoformat()


class EVSEv201(cp):

    async def boot(self) -> bool:
        resp = await self.call(call.BootNotification(
            charging_station={"model": "EVSE-201", "vendor_name": "LegitVendor"},
            reason="PowerUp",
        ))
        print(f"[EVSE-201] Boot status: {resp.status}")
        return resp.status == RegistrationStatusEnumType.accepted

    async def tx(self, event_type: str, seq: int, power_kw: float, tx_id: str):
        await self.call(call.TransactionEvent(
            event_type=event_type,
            timestamp=now(),
            trigger_reason="ChargingStateChanged",
            seq_no=seq,
            transaction_info={"transaction_id": tx_id},
            meter_value=[{
                "timestamp": now(),
                "sampledValue": [{
                    "value": round(power_kw, 2),
                    "measurand": "Power.Active.Import",
                    "unitOfMeasure": {"unit": "kW"},
                }],
            }],
        ))


async def run(duration_s: int):
    print(f"[EVSE-201] Connecting to {CSMS_URL} as {CP_ID} ...")
    async with websockets.connect(CSMS_URL, ping_interval=None) as ws:
        await ws.send(CP_ID)
        evse = EVSEv201(CP_ID, ws)
        start_task = asyncio.create_task(evse.start())
        await asyncio.sleep(0.1)

        if not await evse.boot():
            print("[EVSE-201] Boot rejected — exiting")
            start_task.cancel()
            return

        tx_id = "TX-201-1"
        await evse.tx("Started", 0, 11.0, tx_id)
        print("[EVSE-201] Transaction started — reporting honest 11 kW")

        seq, elapsed = 1, 0
        while elapsed < duration_s:
            await asyncio.sleep(5)
            elapsed += 5
            await evse.tx("Updated", seq, 11.0, tx_id)
            print(f"[EVSE-201] TransactionEvent[Updated] seq={seq} | 11.0 kW (honest)")
            seq += 1

        await evse.tx("Ended", seq, 0.0, tx_id)
        print("[EVSE-201] Transaction ended cleanly")

        start_task.cancel()
        try:
            await start_task
        except (asyncio.CancelledError, websockets.exceptions.ConnectionClosedOK):
            pass


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="OCPP 2.0.1 legitimate EVSE")
    p.add_argument("--url", default=CSMS_URL)
    p.add_argument("--duration", type=int, default=30)
    args = p.parse_args()
    CSMS_URL = args.url
    try:
        asyncio.run(run(args.duration))
    except ConnectionRefusedError:
        print(f"[EVSE-201] Cannot reach CSMS at {CSMS_URL}")
