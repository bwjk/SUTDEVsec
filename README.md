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
├── core/
│   ├── csms_server4.py          # OCPP 1.6 CSMS (WebSocket server on port 9000)
│   └── evse_client4_fixed.py    # Legitimate EVSE client + pandapower grid simulation
├── attacks/
│   ├── run_attacks.py           # Interactive orchestrator — runs all attacks in sequence
│   ├── attack_saiflow_dos_patched.py   # Attack 1: SaiFlow duplicate-CP DoS
│   ├── attack_fdi.py                   # Attack 2: MeterValues False Data Injection
│   ├── attack_mitm_session_patched.py  # Attack 3: MITM WebSocket proxy + session hijack
│   ├── attack_load_altering.py         # Attack 4: Coordinated botnet load altering
│   └── a6breakers.py                   # Grid topology visualiser (Plotly HTML)
└── requirements.txt.txt
```

---

## Requirements

```
ocpp==0.26
websockets==10.4
pandapower
matplotlib
plotly
```

Install dependencies:

```bash
pip install ocpp==0.26 websockets==10.4 pandapower matplotlib plotly
```

---

## Quick Start

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

# Terminal 2 — Legitimate EVSE (connects to CSMS)
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

Builds the full grid twin (220 kV → 66 kV → 22 kV, 7 town loads × 200 MW, 500 EV chargers × 220 kW) and exports an interactive Plotly diagram to `grid_visualization.html`.

```bash
python attacks/a6breakers.py
```

---

## Architecture

```
EVSE (evse_client4_fixed.py)
  │  ws://127.0.0.1:9000  (normal)
  │  ws://127.0.0.1:9001  (via MITM proxy)
  ▼
[MITM Proxy: port 9001]  ──────────────────────┐
  │  ws://127.0.0.1:9000                        │ inject / tamper
  ▼                                             │
CSMS (csms_server4.py : port 9000) ◄───────────┘

SaiFlow / FDI / Load attacks connect directly to port 9000
```

---

## References

- Saposnik, L.R. & Porat, D. (2023). *Hijacking EV charge points to cause DoS.* SaiFlow Security Advisory.
- Johnson et al. (2023). *Disrupting EV Charging Sessions.* Idaho National Laboratory, INL/CON-23-72329.
- Open Charge Alliance. *OCPP 1.6 Specification.*
- Open Charge Alliance. *OCPP 2.0.1 Security Whitepaper.*
