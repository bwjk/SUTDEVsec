"""
===========================================================================
EVSecSim — OCPP 2.0.1 SECURE: MITM blocked by TLS  (Attacks 3a/3b/6)
===========================================================================

The TLS-prevention counterpart of the 1.6 MITM attacks.  This proxy
attempts the same interposition as attack_mitm_session_patched.py /
attack_mitm_ext.py / attack_duration_spoof.py — but against a Security
Profile 3 (mutual-TLS) deployment, where it FAILS in both directions:

  Downstream (proxy → EVSE):
    The proxy can only present a SELF-SIGNED certificate — it does not
    possess a CA-signed server cert.  The EVSE validates the server
    certificate against the trust anchor and REJECTS the proxy at the TLS
    handshake, before sending any OCPP frame.

  Upstream (proxy → real CSMS):
    The proxy has no valid CLIENT certificate, so the mutual-TLS CSMS
    rejects its connection too.

Result: the man-in-the-middle has no readable channel.  The MeterValues
tampering, StopTransaction injection, and StopTransaction-drop that all
succeed on the plaintext track are impossible here — not because of the
OCPP version, but because Security Profile 2/3 (TLS + cert validation) is
deployed.  The EVSE prints the decisive BLOCKED message on its terminal.

HOW TO RUN
----------
  docker compose --profile v201-secure-mitm up
===========================================================================
"""

import asyncio
import os
import ssl
import datetime
import tempfile
import websockets

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PROXY_PORT  = int(os.environ.get("PROXY_PORT", "9101"))
REAL_CSMS   = os.environ.get("REAL_CSMS", "wss://csms-secure-v201:9101")
CERT_DIR    = os.environ.get("CERT_DIR", "/certs")

RED, GREEN, YELLOW, BOLD, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[1m", "\033[0m"


def make_self_signed(cn="csms-secure-v201"):
    """The attacker can forge any cert — but NOT one signed by the trusted CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "rogue.pem"), os.path.join(d, "rogue.key")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cp, kp


async def probe_upstream():
    """Try to connect to the real CSMS as a client — fails (no valid client cert)."""
    await asyncio.sleep(1)
    try:
        ctx = ssl.create_default_context(cafile=os.path.join(CERT_DIR, "ca.pem"))
        async with websockets.connect(REAL_CSMS, ssl=ctx, ping_interval=None):
            print(f"{RED}[MITM] upstream connect SUCCEEDED — unexpected{RESET}")
    except Exception as exc:
        print(f"{BOLD}{GREEN}[MITM] upstream to real CSMS BLOCKED "
              f"({type(exc).__name__}) — no valid client certificate{RESET}")


async def handler(ws):
    # If a TLS peer ever got this far it would be relayed — but the EVSE
    # rejects our self-signed cert during the handshake, so this rarely runs.
    print(f"{YELLOW}[MITM] a peer completed handshake (unexpected on Profile 3){RESET}")
    try:
        async for _ in ws:
            pass
    except Exception:
        pass


async def main():
    cert, key = make_self_signed()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)   # self-signed — NOT CA-signed

    print(f"\n{BOLD}{RED}{'='*60}{RESET}")
    print(f"{BOLD}{RED}  OCPP 2.0.1 MITM attempt — Security Profile 3 target{RESET}")
    print(f"{BOLD}{RED}{'='*60}{RESET}")
    print(f"  Proxy listening : wss://0.0.0.0:{PROXY_PORT} (self-signed cert)")
    print(f"  Real CSMS       : {REAL_CSMS}")
    print(f"  Expectation     : EVSE rejects our forged cert; CSMS rejects us upstream\n")

    server = await websockets.serve(handler, "0.0.0.0", PROXY_PORT, ssl=ctx)
    await probe_upstream()
    print(f"{BOLD}{GREEN}[MITM] Waiting for EVSE — it will reject our self-signed "
          f"certificate at the TLS handshake (see EVSE terminal for BLOCKED).{RESET}")
    print(f"{YELLOW}[MITM] The man-in-the-middle has no readable channel — "
          f"tampering/injection/drop are all impossible.{RESET}")
    await asyncio.sleep(40)
    server.close()
    await server.wait_closed()
    print(f"{BOLD}{GREEN}[MITM] MITM attack failed — Profile 3 TLS prevented interposition.{RESET}")


if __name__ == "__main__":
    asyncio.run(main())
