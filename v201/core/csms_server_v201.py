"""
===========================================================================
EVSecSim — OCPP 2.0.1 CSMS (plaintext / insecure-profile equivalent)
===========================================================================

WHAT THIS IS
------------
A minimal OCPP 2.0.1 Central System, the 2.0.1 counterpart of the 1.6
CSMS in core/csms_server4.py.  It exists so the data-integrity attacks
(False Data Injection, load overload) can be re-run against 2.0.1's
*message model* — TransactionEvent / MeterValues — instead of 1.6's
StartTransaction / MeterValues / StopTransaction.

IMPORTANT — SECURITY PROFILE
----------------------------
This CSMS runs on plaintext ws:// with the same first-frame handshake as
the 1.6 testbed.  That is the OCPP 2.0.1 *insecure-profile equivalent*
(Security Profile 1: no TLS, no mutual-TLS client certificate).  It is
deliberately NOT Profile 2/3.  The point of this track is to isolate ONE
variable — the message model — and show that the data-integrity attack
class survives the migration from 1.6 to 2.0.1 message formats.

It does NOT add TLS, mutual-TLS, signed firmware, or signed MeterValues.
Those are the controls that *prevent* the MITM (3a/3b/6) and firmware (5)
attacks — they belong to the security profile, not the protocol version,
and are out of scope for this survival demo (a TLS track is deferred).

KEY OCPP 2.0.1 DIFFERENCES vs 1.6
--------------------------------
  - BootNotification payload is nested: chargingStation{model,vendorName}
    + reason, instead of flat chargePointVendor/chargePointModel.
  - StartTransaction / StopTransaction / MeterValues are unified into a
    single TransactionEvent message (Started / Updated / Ended).
  - Power readings ride in meterValue[].sampledValue[].value, same as 1.6,
    and are STILL accepted with no plausibility check — the vulnerability
    the FDI / overload attacks exploit.

HOW TO RUN
----------
  docker compose --profile v201-normal up        # CSMS + legit 2.0.1 EVSE
  docker compose --profile v201-fdi up            # FDI attack (survives 2.0.1)
  docker compose --profile v201-overload-grid up  # overload + PGTwin grid
===========================================================================
"""

import asyncio
import logging
import os
import websockets
from datetime import datetime, timezone

# Docker Desktop host-port proxy sends plain HTTP probes; silence the noise.
logging.getLogger("websockets.server").setLevel(logging.CRITICAL)

from ocpp.routing import on
from ocpp.v201 import ChargePoint as cp
from ocpp.v201 import call_result
from ocpp.v201.enums import RegistrationStatusEnumType, AuthorizationStatusEnumType


def extract_power(meter_value) -> str:
    """
    Pull a Power.Active.Import value out of an OCPP 2.0.1 meterValue array.
    The ocpp library converts incoming camelCase to snake_case, so keys are
    sampled_value / value here — but we probe both to be safe.
    """
    try:
        for mv in meter_value or []:
            samples = mv.get("sampled_value") or mv.get("sampledValue") or []
            # Prefer an explicit Power.Active.Import sample; else first sample.
            chosen = None
            for s in samples:
                measurand = s.get("measurand", "")
                if measurand == "Power.Active.Import":
                    chosen = s
                    break
            if chosen is None and samples:
                chosen = samples[0]
            if chosen is not None:
                return str(chosen.get("value", "N/A"))
    except Exception:
        pass
    return "N/A"


class CSMSv201(cp):

    @on("BootNotification")
    async def on_boot(self, charging_station, reason, **kwargs):
        model = charging_station.get("model", "?")
        vendor = charging_station.get("vendor_name") or charging_station.get("vendorName", "?")
        print(f"[CSMS-v201] BootNotification from: {self.id} "
              f"({vendor} / {model}) reason={reason}")
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=10,
            status=RegistrationStatusEnumType.accepted,
        )

    @on("Heartbeat")
    async def on_heartbeat(self, **kwargs):
        return call_result.Heartbeat(
            current_time=datetime.now(timezone.utc).isoformat()
        )

    @on("StatusNotification")
    async def on_status(self, timestamp, connector_status, evse_id, connector_id, **kwargs):
        print(f"[CSMS-v201] {self.id} | StatusNotification: "
              f"evse={evse_id} conn={connector_id} status={connector_status}")
        return call_result.StatusNotification()

    @on("Authorize")
    async def on_authorize(self, id_token, **kwargs):
        return call_result.Authorize(
            id_token_info={"status": AuthorizationStatusEnumType.accepted}
        )

    @on("TransactionEvent")
    async def on_transaction_event(self, event_type, timestamp, trigger_reason,
                                   seq_no, transaction_info, **kwargs):
        tx_id = transaction_info.get("transaction_id") or transaction_info.get("transactionId", "?")
        meter_value = kwargs.get("meter_value")
        power = extract_power(meter_value)
        # NO plausibility check — value logged verbatim, exactly as 1.6 did.
        print(f"[CSMS-v201] {self.id} | TransactionEvent[{event_type}] "
              f"txId={tx_id} seq={seq_no} | Power = {power} kW")
        return call_result.TransactionEvent()

    @on("MeterValues")
    async def on_meter_values(self, evse_id, meter_value, **kwargs):
        power = extract_power(meter_value)
        print(f"[CSMS-v201] {self.id} | evse={evse_id} | Power = {power} kW")
        return call_result.MeterValues()


async def handler(websocket):
    charge_point_id = "unknown"
    try:
        # Mirror the 1.6 testbed handshake: CP id arrives as the first raw frame.
        charge_point_id = await websocket.recv()
        print(f"[CSMS-v201] Connected: {charge_point_id}")
        cp_instance = CSMSv201(charge_point_id, websocket)
        await cp_instance.start()
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[CSMS-v201] {charge_point_id} disconnected cleanly.")
    except websockets.exceptions.ConnectionClosedError as exc:
        print(f"[CSMS-v201] {charge_point_id} disconnected with error: {exc}")


async def main():
    bind_host = os.environ.get("BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("CSMS_PORT", "9100"))
    server = await websockets.serve(handler, bind_host, port)
    print(f"[CSMS-v201] Running on ws://{bind_host}:{port}  (OCPP 2.0.1, plaintext / Profile-1 equivalent)")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
