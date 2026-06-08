"""
===========================================================================
EVSecSim — OCPP 2.0.1 Secure Track: certificate + key generation
===========================================================================

Generates the PKI for the OCPP 2.0.1 Security-Profile-3 (mutual-TLS)
prevention demos:

  ca.pem / ca.key        Root CA — the shared trust anchor
  server.pem / server.key  CSMS server cert (SAN = csms-secure-v201, localhost)
  client.pem / client.key  Legitimate EVSE client cert (mutual-TLS)
  fw_sign.key            Manufacturer firmware-signing private key
  fw_pub.pem             Manufacturer firmware-signing public key (baked into EVSE)

Baked into the shared Docker image at build time (one CA for all
containers).  The attacker containers deliberately do NOT use these
CA-signed materials — a real attacker would not possess them — so the
prevention demos remain faithful: the MITM proxy self-signs, and the
malicious firmware is signed by an attacker key (or unsigned).

Usage:
  python gen_certs.py [output_dir]     # default: /certs
===========================================================================
"""

import os
import sys
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

UTC = datetime.timezone.utc


def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def save_pub(key, path):
    with open(path, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def _valid_window():
    return (datetime.datetime.now(UTC) - datetime.timedelta(days=1),
            datetime.datetime.now(UTC) + datetime.timedelta(days=3650))


def make_ca():
    key = keypair()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EVSecSim-OCPP201-CA")])
    nb, na = _valid_window()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, cn, sans=None, server=True):
    key = keypair()
    nb, na = _valid_window()
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    usage = x509.ExtendedKeyUsage(
        [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH] if server
        else [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    builder = builder.add_extension(usage, critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/certs"
    os.makedirs(out, exist_ok=True)

    ca_key, ca_cert = make_ca()
    save_key(ca_key, os.path.join(out, "ca.key"))
    save_cert(ca_cert, os.path.join(out, "ca.pem"))

    # Server cert — SAN must cover the Docker service hostname the EVSE dials.
    srv_key, srv_cert = make_leaf(
        ca_key, ca_cert, "csms-secure-v201",
        sans=["csms-secure-v201", "localhost"], server=True)
    save_key(srv_key, os.path.join(out, "server.key"))
    save_cert(srv_cert, os.path.join(out, "server.pem"))

    # Client cert — legitimate EVSE identity for mutual TLS (Profile 3).
    cli_key, cli_cert = make_leaf(
        ca_key, ca_cert, "EVSE-Secure-201", server=False)
    save_key(cli_key, os.path.join(out, "client.key"))
    save_cert(cli_cert, os.path.join(out, "client.pem"))

    # Firmware signing keypair — manufacturer key. Private signs legit firmware;
    # public is baked into the EVSE to verify any firmware before installing.
    fw_key = keypair()
    save_key(fw_key, os.path.join(out, "fw_sign.key"))
    save_pub(fw_key, os.path.join(out, "fw_pub.pem"))

    print(f"[gen_certs] PKI written to {out}:")
    for f in sorted(os.listdir(out)):
        print(f"  {f}")


if __name__ == "__main__":
    main()
