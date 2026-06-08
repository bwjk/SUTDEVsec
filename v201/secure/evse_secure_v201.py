"""
===========================================================================
EVSecSim — OCPP 2.0.1 SECURE EVSE  (Security Profile 3 + signed firmware)
===========================================================================

The TLS-secured EVSE used by the prevention demos.  Two defences:

  1. TRANSPORT (Profile 3, mutual TLS)
     Connects over wss:// and VALIDATES the server certificate against the
     trust anchor (ca.pem).  Any man-in-the-middle proxy that cannot present
     a CA-signed certificate is rejected at the TLS handshake — the EVSE
     never sends a single OCPP frame through it.  It also presents its own
     client certificate (mutual TLS).

  2. APPLICATION (signed firmware)
     On UpdateFirmware, it downloads the payload and VERIFIES the firmware
     signature against the PINNED manufacturer public key (fw_pub.pem).  A
     malicious payload signed by anything other than the manufacturer key
     fails verification → the EVSE emits FirmwareStatusNotification(
     InvalidSignature) and refuses to install.  This is the OCPP 2.0.1
     application-layer control doing the work — not just transport TLS.

CERTS (baked into image by gen_certs.py, read from /certs)
  ca.pem                  verify the CSMS server certificate
  client.pem / client.key present for mutual TLS
  fw_pub.pem              pinned manufacturer key — verify firmware signatures

USAGE
  --url wss://csms-secure-v201:9101   normal (legit CSMS)
  --url wss://atk-mitm-secure:9101    via MITM proxy (rejected at handshake)
===========================================================================
"""

import asyncio
import os
import ssl
import argparse
import urllib.request
import websockets
from datetime import datetime, timezone

from ocpp.routing import on
from ocpp.v201 import ChargePoint as cp, call, call_result
from ocpp.v201.enums import RegistrationStatusEnumType

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

CERT_DIR = os.environ.get("CERT_DIR", "/certs")
CP_ID    = os.environ.get("CP_ID", "EVSE-Secure-201")

RED, GREEN, YELLOW, CYAN, BOLD, RESET = (
    "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m")


def now():
    return datetime.now(timezone.utc).isoformat()


def load_manufacturer_key():
    with open(os.path.join(CERT_DIR, "fw_pub.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


class SecureEVSEv201(cp):

    async def boot(self) -> bool:
        resp = await self.call(call.BootNotification(
            charging_station={"model": "EVSE-SEC-201", "vendor_name": "LegitVendor"},
            reason="PowerUp"))
        print(f"[EVSE-SEC] Boot status: {resp.status}")
        return resp.status == RegistrationStatusEnumType.accepted

    async def report(self, seq, power_kw):
        await self.call(call.TransactionEvent(
            event_type="Updated", timestamp=now(),
            trigger_reason="MeterValuePeriodic", seq_no=seq,
            transaction_info={"transaction_id": "TX-SEC-201"},
            meter_value=[{"timestamp": now(), "sampledValue": [
                {"value": round(power_kw, 2), "measurand": "Power.Active.Import",
                 "unitOfMeasure": {"unit": "kW"}}]}]))

    # ── Signed-firmware verification (the application-layer control) ──────────
    @on("UpdateFirmware")
    async def on_update_firmware(self, request_id, firmware, **kwargs):
        location = firmware.get("location")
        print(f"\n[EVSE-SEC] UpdateFirmware received -> location={location}")
        asyncio.create_task(self._verify_firmware(location))
        return call_result.UpdateFirmware(status="Accepted")

    async def _status(self, status):
        try:
            await self.call(call.FirmwareStatusNotification(status=status, request_id=1))
        except Exception:
            pass

    async def _verify_firmware(self, location):
        await self._status("Downloading")
        try:
            payload = urllib.request.urlopen(location, timeout=10).read()
            sig = urllib.request.urlopen(location + ".sig", timeout=10).read()
        except Exception as exc:
            print(f"[EVSE-SEC] firmware download failed: {exc}")
            await self._status("DownloadFailed")
            return
        await self._status("Downloaded")
        print(f"[EVSE-SEC] Downloaded {len(payload)} bytes + {len(sig)} byte signature")
        print(f"[EVSE-SEC] Verifying signature against pinned manufacturer key ...")

        try:
            self.mfr_key.verify(
                sig, payload, padding.PKCS1v15(), hashes.SHA256())
            verified = True
        except InvalidSignature:
            verified = False

        if verified:
            await self._status("SignatureVerified")
            print(f"[EVSE-SEC] {GREEN}signature VALID — would install (legit firmware){RESET}")
            await self._status("Installing")
            await self._status("Installed")
        else:
            await self._status("InvalidSignature")
            print()
            print(f"[EVSE-SEC] {BOLD}{GREEN}{'='*56}{RESET}")
            print(f"[EVSE-SEC] {BOLD}{GREEN}  BLOCKED — firmware signature INVALID{RESET}")
            print(f"[EVSE-SEC] {BOLD}{GREEN}  payload not signed by the manufacturer key{RESET}")
            print(f"[EVSE-SEC] {BOLD}{GREEN}  EVSE REFUSES TO INSTALL — attack prevented{RESET}")
            print(f"[EVSE-SEC] {BOLD}{GREEN}  (OCPP 2.0.1 signed-firmware application control){RESET}")
            print(f"[EVSE-SEC] {BOLD}{GREEN}{'='*56}{RESET}\n")


def client_ssl_context() -> ssl.SSLContext:
    # Verify the server against our CA (defeats MITM); present our client cert.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                     cafile=os.path.join(CERT_DIR, "ca.pem"))
    ctx.load_cert_chain(os.path.join(CERT_DIR, "client.pem"),
                        os.path.join(CERT_DIR, "client.key"))
    return ctx


async def run(url: str, duration: int):
    print(f"[EVSE-SEC] Connecting to {url} (verifying server cert against CA) ...")
    ctx = client_ssl_context()
    try:
        async with websockets.connect(url, ssl=ctx, ping_interval=None) as ws:
            await ws.send(CP_ID)
            evse = SecureEVSEv201(CP_ID, ws)
            evse.mfr_key = load_manufacturer_key()
            start_task = asyncio.create_task(evse.start())
            await asyncio.sleep(0.1)
            if not await evse.boot():
                start_task.cancel(); return
            print(f"[EVSE-SEC] {GREEN}TLS + mutual-TLS handshake OK — connected to verified CSMS{RESET}")

            seq, elapsed = 1, 0
            while elapsed < duration:
                await asyncio.sleep(5); elapsed += 5
                await evse.report(seq, 11.0)
                print(f"[EVSE-SEC] TransactionEvent[Updated] seq={seq} | 11.0 kW")
                seq += 1

            start_task.cancel()
            try:
                await start_task
            except (asyncio.CancelledError, websockets.exceptions.ConnectionClosedOK):
                pass

    except ssl.SSLCertVerificationError as exc:
        print()
        print(f"{BOLD}{GREEN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN}  BLOCKED — server certificate verification FAILED{RESET}")
        print(f"{BOLD}{GREEN}  {exc.verify_message}{RESET}")
        print(f"{BOLD}{GREEN}  The EVSE refused the connection — no OCPP frame sent.{RESET}")
        print(f"{BOLD}{GREEN}  MITM / rogue endpoint cannot present a CA-signed cert.{RESET}")
        print(f"{BOLD}{GREEN}  Attack prevented (OCPP 2.0.1 Security Profile 2/3, TLS).{RESET}")
        print(f"{BOLD}{GREEN}{'='*60}{RESET}")
    except ssl.SSLError as exc:
        print(f"\n{BOLD}{GREEN}BLOCKED — TLS error: {exc.reason} — attack prevented{RESET}")
    except ConnectionRefusedError:
        print(f"[EVSE-SEC] Cannot reach {url}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="OCPP 2.0.1 secure EVSE (Profile 3 + signed firmware)")
    p.add_argument("--url", default=os.environ.get("CSMS_URL", "wss://csms-secure-v201:9101"))
    p.add_argument("--duration", type=int, default=20)
    args = p.parse_args()
    asyncio.run(run(args.url, args.duration))
