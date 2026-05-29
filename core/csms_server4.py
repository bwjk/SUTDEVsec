import asyncio
import logging
import os
import websockets
from datetime import datetime, timezone

# Docker Desktop's host-port proxy sends plain HTTP probes at startup;
# websockets logs those as ERROR-level "opening handshake failed" noise.
logging.getLogger("websockets.server").setLevel(logging.CRITICAL)

from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp
from ocpp.v16.enums import RegistrationStatus, FirmwareStatus
from ocpp.v16 import call_result

_tx_counter = 0


# -----------------------------
# CSMS (Central System)
# -----------------------------
class CSMS(cp):

    @on('BootNotification')
    async def on_boot(self, charge_point_vendor, charge_point_model, **kwargs):
        print(f"[CSMS] BootNotification from: {self.id} "
              f"({charge_point_vendor} / {charge_point_model})")
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=10,
            status=RegistrationStatus.accepted
        )

    @on('Heartbeat')
    async def on_heartbeat(self):
        return call_result.Heartbeat(
            current_time=datetime.now(timezone.utc).isoformat()
        )

    @on('StartTransaction')
    async def on_start_transaction(self, connector_id, id_tag, meter_start, timestamp, **kwargs):
        global _tx_counter
        _tx_counter += 1
        print(f"[CSMS] {self.id} | StartTransaction: connectorId={connector_id} "
              f"idTag={id_tag} meterStart={meter_start} Wh → txId={_tx_counter}")
        return call_result.StartTransaction(
            transaction_id=_tx_counter,
            id_tag_info={"status": "Accepted"},
        )

    @on('MeterValues')
    async def on_meter_values(self, connector_id, meter_value, **kwargs):
        try:
            power = meter_value[0]["sampled_value"][0]["value"]
        except Exception:
            power = "N/A"
        print(f"[CSMS] {self.id} | Power = {power} kW")
        return call_result.MeterValues()

    # ------------------------------------------------------------------
    # BUG FIX: StopTransaction handler added.
    # Without this the CSMS returns NotImplemented to any StopTransaction
    # frame — including injected ones — so Phase 3 of the MITM attack
    # produced no visible output on this terminal.
    # ------------------------------------------------------------------
    @on('FirmwareStatusNotification')
    async def on_firmware_status(self, status, **kwargs):
        print(f"[CSMS] {self.id} | FirmwareStatusNotification: {status}")
        return call_result.FirmwareStatusNotification()

    @on('StopTransaction')
    async def on_stop_transaction(self, transaction_id, meter_stop,
                                   timestamp, **kwargs):
        print()
        print(f"[CSMS] {'!' * 52}")
        print(f"[CSMS]  STOPTRANSACTION received from : {self.id}")
        print(f"[CSMS]  transaction_id : {transaction_id}")
        print(f"[CSMS]  meter_stop     : {meter_stop} Wh")
        print(f"[CSMS]  timestamp      : {timestamp}")
        print(f"[CSMS]  --> SESSION TERMINATED — billing closed at {meter_stop} Wh")
        print(f"[CSMS] {'!' * 52}")
        print()
        return call_result.StopTransaction()


# -----------------------------
# CONNECTION HANDLER
# -----------------------------
async def handler(websocket):
    charge_point_id = "unknown"
    try:
        charge_point_id = await websocket.recv()
        print(f"[CSMS] Connected: {charge_point_id}")
        cp_instance = CSMS(charge_point_id, websocket)
        await cp_instance.start()

    except websockets.exceptions.ConnectionClosedOK:
        # Clean disconnect (code 1000) — normal end of any PoC attack script.
        # Suppress the traceback; this is expected behaviour, not a crash.
        print(f"[CSMS] {charge_point_id} disconnected cleanly.")

    except websockets.exceptions.ConnectionClosedError as exc:
        # Abnormal disconnect — log but keep the server alive.
        print(f"[CSMS] {charge_point_id} disconnected with error: {exc}")


# -----------------------------
# MAIN SERVER
# -----------------------------
async def main():
    bind_host = os.environ.get("BIND_HOST", "0.0.0.0")
    server = await websockets.serve(handler, bind_host, 9000)
    print(f"[CSMS] Running on ws://{bind_host}:9000")
    await server.wait_closed()


asyncio.run(main())
