# EVSecSim — OCPP 1.6 Security Research Testbed

A proof-of-concept security research framework demonstrating known attack vectors against EV charging infrastructure over OCPP 1.6. Built for the SUTD thesis project on EV charging cybersecurity.

> **For authorized research and educational use only.**

---

## Overview

EVSecSim simulates a minimal EV charging ecosystem consisting of:

- A **CSMS** (Central System / Charge Point Management System) over WebSocket
- An **EVSE client** (EV Supply Equipment) backed by a live pandapower grid twin
- Four **attack scripts** demonstrating published OCPP 1.6 vulnerabilities

The attacks target the same weaknesses documented by SaiFlow (2023) and Idaho National Laboratory (INL/CON-23-72329, 2023): no transport encryption, no message authentication, no connection deduplication, and no charge-point identity verification.

---

## Project Structure

```
SUTDEVsec/
├── Dockerfile                   # Shared image for all services
├── docker-compose.yml           # Full containerised topology
├── .dockerignore
├── requirements.txt
├── core/
│   ├── csms_server4.py          # OCPP 1.6 CSMS (WebSocket server on port 9000)
│   └── evse_client4_fixed.py    # Legitimate EVSE client + pandapower grid simulation
└── attacks/
    ├── run_attacks.py                  # Interactive orchestrator (local use)
    ├── attack_saiflow_dos_patched.py   # Attack 1: SaiFlow duplicate-CP DoS
    ├── attack_fdi.py                   # Attack 2: MeterValues False Data Injection
    ├── attack_mitm_session_patched.py  # Attack 3: MITM WebSocket proxy + session hijack
    ├── attack_load_altering.py         # Attack 4: Coordinated botnet load altering
    └── a6breakers.py                   # Grid topology visualiser (Plotly HTML)
```

---

## Containerised Network Topology

Each component runs in its own container on a logically separate network segment, matching a realistic threat model where an external attacker can only reach the CSMS's exposed port and has no visibility into the internal operator network.

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                      public-net  ·  172.20.0.0/24                         │
  │                                                                            │
  │   ┌─────────────────────┐               ┌─────────────────────┐           │
  │   │     atk-saiflow      │               │      atk-load        │           │
  │   │     172.20.0.30      │               │     172.20.0.40      │           │
  │   │  (Attack 1 — DoS)    │               │ (Attack 4 — Botnet)  │           │
  │   └──────────┬───────────┘               └──────────┬──────────┘           │
  │              │ ws://csms:9000                        │ ws://csms:9000       │
  │              └───────────────────┬───────────────────┘                     │
  │                                  ▼                                          │
  │                       ┌──────────────────┐                                 │
  │                       │       csms        │ ◄── :9000 published to host    │
  │                       │   172.20.0.10     │                                 │
  │                       └────────┬─────────┘                                 │
  └────────────────────────────────│────────────────────────────────────────────┘
                                   │  dual-homed
  ┌────────────────────────────────│────────────────────────────────────────────┐
  │              operator-net  ·  172.19.0.0/24  [internal, isolated]            │
  │                                   │                                           │
  │                       ┌───────────┴──────────┐                               │
  │                       │         csms          │                               │
  │                       │     172.19.0.10       │                               │
  │                       └──┬──────────┬─────────┘                              │
  │          ws://csms:9000  │          │          │                              │
  │         ┌────────────────┘          │          └───────────────┐              │
  │         ▼                           ▼                          ▼              │
  │  ┌─────────────┐          ┌──────────────────┐       ┌──────────────────┐   │
  │  │    evse      │          │     atk-fdi       │       │    atk-mitm      │   │
  │  │ 172.19.0.20  │          │   172.19.0.30     │       │  172.19.0.40     │   │
  │  │ (legit EVSE) │          │ (compromised EVSE)│       │  (proxy :9001)   │   │
  │  └─────────────┘          └──────────────────┘       └────────┬─────────┘   │
  │                                                                │               │
  │                                                   ws://atk-mitm:9001          │
  │                                                                │               │
  │                                                  ┌────────────┴────────┐      │
  │                                                  │    evse-via-mitm    │      │
  │                                                  │    172.19.0.50      │      │
  │                                                  └─────────────────────┘      │
  └───────────────────────────────────────────────────────────────────────────────┘
```

### Threat model per attack

| Attack | Attacker position | Network | Can see operator-net? |
|--------|-------------------|---------|----------------------|
| 1 — SaiFlow DoS | External | public-net | No |
| 2 — FDI | Compromised EVSE (insider) | operator-net | Yes |
| 3 — MITM proxy | Compromised switch / ARP poison | operator-net | Yes |
| 4 — Load altering | External botnet | public-net | No |

---

## Docker Deployment

### Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)

### Build

```bash
docker compose build
```

### Run scenarios

```bash
# Baseline — CSMS + legitimate EVSE only
docker compose --profile normal up

# Attack 1 — SaiFlow DoS  (external attacker + victim EVSE)
docker compose --profile saiflow up

# Attack 2 — False Data Injection  (compromised EVSE, no legit EVSE)
docker compose --profile fdi up

# Attack 3 — MITM proxy  (proxy intercepts EVSE traffic)
docker compose --profile mitm up

# Attack 4 — Coordinated load altering  (external botnet, 10 bots)
docker compose --profile load up
```

### Follow logs

```bash
# All containers in a scenario
docker compose --profile saiflow logs -f

# Single container
docker logs -f csms
docker logs -f atk-saiflow
```

### Tear down

```bash
docker compose --profile <profile> down
```

### Capture traffic (Wireshark)

The CSMS publishes port 9000 to the host. Capture locally:

```bash
# Linux/macOS
tcpdump -i any -w capture.pcap port 9000

# Inside a container (install tcpdump in Dockerfile if needed)
docker exec -it csms tcpdump -i eth0 -w /tmp/capture.pcap
```

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

### Run all attacks interactively

```bash
cd attacks
python run_attacks.py
```

The orchestrator opens each component in its own terminal window and prompts you to advance step-by-step.

### Run components manually

```bash
# Terminal 1 — CSMS
python core/csms_server4.py

# Terminal 2 — Legitimate EVSE
python core/evse_client4_fixed.py

# Terminal 2 (MITM variant) — EVSE via proxy
python core/evse_client4_fixed.py --url ws://127.0.0.1:9001
```

---

## Attacks

### Attack 1 — SaiFlow Denial-of-Service

**Script:** `attacks/attack_saiflow_dos_patched.py`

Exploits OCPP 1.6's lack of duplicate-connection detection. A rogue client connects with the same CP ID (`CP_1`) as a legitimate EVSE. The CSMS accepts the second connection without deduplication, creating session shadowing: operator commands are routed to the attacker's socket, not the real charger.

A Heartbeat flood (~1000 HB/s) saturates the CSMS event loop, increasing latency for all connected charge points.

```bash
python attacks/attack_saiflow_dos_patched.py
python attacks/attack_saiflow_dos_patched.py --cp-id CP_2 --duration 30
python attacks/attack_saiflow_dos_patched.py --interval 0.1   # slower demo rate
```

**Root cause:** No CP authentication; no connection registry in OCPP 1.6.  
**Mitigation:** OCPP 2.0.1 with mutual TLS; CSMS-side duplicate-session rejection.

---

### Attack 2 — False Data Injection (FDI)

**Script:** `attacks/attack_fdi.py`

A compromised EVSE fabricates MeterValues readings. The CSMS trusts all reported values unconditionally — there is no signing or plausibility check.

Three phases run automatically:

| Phase | Real draw | Reported to CSMS | Effect |
|-------|-----------|------------------|--------|
| 1 — Normal | 60 kW | 60 kW | Baseline |
| 2 — Under-report | 60 kW | 0 kW | Grid load hidden; billing zeroed |
| 3 — Over-report | 0 kW | 999 kW | Phantom demand event triggered |

```bash
python attacks/attack_fdi.py
# or override target via env var:
CSMS_URL=ws://127.0.0.1:9000 python attacks/attack_fdi.py
```

**Root cause:** MeterValues are unsigned and unverified in OCPP 1.6.  
**Mitigation:** OCPP 2.0.1 signed MeterValues; CSMS plausibility checks; cross-reference with SCADA.

---

### Attack 3 — MITM WebSocket Proxy + Session Hijack

**Script:** `attacks/attack_mitm_session_patched.py`

A transparent WebSocket proxy intercepts the plaintext OCPP channel. Three phases:

- **Phase 1 (0–10 s):** Transparent relay — all traffic logged, nothing modified.
- **Phase 2 (10–20 s):** MeterValues tampered in transit — EVSE sends real kW, CSMS receives 999 kW.
- **Phase 3 (20 s+):** Forged `StopTransaction` injected into CSMS — session closed on CSMS side while EVSE keeps charging; billing corrupted.

```bash
# Terminal 1
python core/csms_server4.py

# Terminal 2 — proxy
python attacks/attack_mitm_session_patched.py

# Terminal 3 — EVSE via proxy
python core/evse_client4_fixed.py --url ws://127.0.0.1:9001
```

CLI options: `--tamper-delay`, `--inject-delay`, `--tamper-value`, `--proxy-port`, `--csms-url`

**Root cause:** Plaintext WebSocket (ws://); no message integrity protection.  
**Mitigation:** TLS (wss://); mutual certificate authentication; OCPP 2.0.1 per-message signing.

---

### Attack 4 — Coordinated Load Altering

**Script:** `attacks/attack_load_altering.py`

A botnet of compromised EVSEs connects to the CSMS and executes coordinated load commands. The pandapower grid twin (220 kV → 66 kV → 22 kV; 500 EV chargers; 1,510 MW total load) runs a power flow after each phase and reports real grid impact metrics.

| Phase | Action | Grid effect |
|-------|--------|-------------|
| Baseline | All bots at 220 kW | Normal operation |
| Surge | All bots simultaneously max load | Voltage sag; transformer overload |
| Drop | All bots simultaneously drop to zero | Voltage rise; unnecessary generation dispatch |
| Oscillate | Bots toggle 0 ↔ 220 kW every 5 s | Protection relay misoperation risk |

```bash
python attacks/attack_load_altering.py --bots 10
python attacks/attack_load_altering.py --bots 50     # 10% of 500-station fleet
python attacks/attack_load_altering.py --bots 500    # full fleet takeover
```

**Root cause:** No per-CP rate limiting or session limits; no operator-signed charging profiles.  
**Mitigation:** OCPP 2.0.1 `SetChargingProfile` with signed profiles; CSMS anomaly detection; grid-side ROCOL protection relays.

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
