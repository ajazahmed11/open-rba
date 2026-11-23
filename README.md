# Open-RBA: Risk-Based Alerting & Incident Prioritization Framework

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/pytest-73%2F73%20passing-brightgreen.svg)](tests/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20Compatible-orange.svg)](https://wazuh.com/)

---

### 🎓 Academic Research Title
* **Academic Title:** *Intelligent Incident Response Framework using Threat Intelligence Enrichment and Risk-Based Incident Prioritization for SIEM Environments*

---

## 📌 Overview
`open-rba` is an open-source, deterministic Python framework designed to resolve SIEM alert fatigue by transforming raw alerts from **Wazuh SIEM** into mathematically prioritized incidents.

Traditional SIEMs rely on static rule levels (1–15). `open-rba` introduces:
1. **Dynamic CTI Weight Renormalization** ensuring internal and non-routable incidents are not penalized when external threat intelligence is not applicable.
2. **Tactical Criticality Progression** scoring intrusion progression based on post-exploitation severity.
3. **Sub-Linear Entity Risk Accumulation** using logarithmic dampening to prevent high-volume routine alerts from masking targeted intrusions.
4. **Resilient Ingestion** querying Wazuh OpenSearch Indexer (`:9200`) or reading `alerts.json`, with SHA-256 deduplication and dead-letter queue routing.

---

## 🏗️ 5-Stage Pipeline Architecture

```text
Raw Wazuh Alerts (alerts.json / OpenSearch Indexer :9200)
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 1: Ingestion & Normalizer                      │ ── SHA-256 Deduplication & Dead-Letter Isolation
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 2: Temporal Correlation Engine                 │ ── Session-Window Burst Compression
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 3: CTI Enrichment & Temporal Decay             │ ── AbuseIPDB, 7-Day TTL Cache & Exp Decay (λ=0.05)
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 4: MITRE ATT&CK Mapper                         │ ── Intrusion Criticality Progression [0.10 to 1.00]
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 5: Dynamic Multi-Factor Risk Scorer            │ ── Dynamic Renormalization & Diminishing Returns Rollup
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
        Prioritized Analyst Incident Queue & Entity Rollup
```

### Module Breakdown

1. **Module 1 — Ingestion & Normalization (`src/ingestion/`):**
   * Ingests alerts from Wazuh OpenSearch Indexer (`:9200`/`wazuh-alerts-*`) or local log files (`alerts.json`).
   * Computes SHA-256 content hashes across `(timestamp, rule_id, agent_name, src_ip, dst_ip, user, log_content)` for idempotent storage.
   * Routes malformed alerts or invalid schemas directly to the `dead_letter` table without stalling transactions.

2. **Module 2 — Temporal Correlation Engine (`src/correlation/`):**
   * Groups high-frequency alert bursts sharing `(src_ip, target_host, technique_family)` within sliding session windows ($\Delta t \le 120\text{s}$).
   * Reduces repetitive noise by $\ge 70\%$ in high-volume attacks (e.g., 99.3% in brute-force floods; 37.5% across heterogeneous sample telemetry).
   * Normalizes timestamps to UTC across mixed log formats.

3. **Module 3 — Threat Intelligence Enrichment (`src/enrichment/`):**
   * Enriches external IP addresses using AbuseIPDB confidence scores.
   * Applies exponential temporal decay with $\lambda = 0.05$ (half-life $t_{1/2} = \frac{\ln(2)}{0.05} \approx 13.86$ days):
     $$CTI_{decay} = CTI_{raw} \cdot e^{-\lambda \Delta t}$$
   * Maintains a local SQLite cache with a 7-day TTL and gracefully flags rate limits (HTTP 429) to trigger weight renormalization rather than scoring indicators as benign.

4. **Module 4 — MITRE ATT&CK Tactical Progression (`src/attck/`):**
   * Maps technique IDs and descriptions to MITRE tactics using regex word boundaries.
   * Intrusion criticality scoring:
     * *Reconnaissance:* 0.10
     * *Discovery / Resource Development:* 0.20
     * *Initial Access:* 0.40
     * *Execution:* 0.50
     * *Persistence:* 0.60
     * *Defense Evasion:* 0.70
     * *Credential Access / Lateral Movement:* 0.80
     * *Privilege Escalation:* 0.90
     * *Exfiltration / Impact:* 1.00

5. **Module 5 — Dynamic Multi-Factor Risk Scorer (`src/scoring/`):**
   * **Dynamic CTI Weight Renormalization:** When an incident has no external IP indicator ($CTI = \text{None}$), intrinsic weights rebalance dynamically:
     $$w'_{sev} = \frac{w_{sev}}{w_{sev} + w_{kc}} = \frac{0.35}{0.35 + 0.25} = 0.5833$$
     $$w'_{kc} = \frac{w_{kc}}{w_{sev} + w_{kc}} = \frac{0.25}{0.35 + 0.25} = 0.4167$$
     $$R_{base} = w'_{sev} \cdot S_{norm} + w'_{kc} \cdot KC_{norm}$$
   * **Base Score (with CTI):**
     $$R_{base} = w_{sev} \cdot S_{norm} + w_{cti} \cdot CTI_{decay} + w_{kc} \cdot KC_{norm} \in [0.0, 1.0]$$
   * **Asset Multiplier:**
     $$R_{incident} = R_{base} \cdot M_{asset}$$
     *(Critical: $3.0\times$, High: $2.0\times$, Medium: $1.5\times$, Low: $1.0\times$)*
   * **Bounded Entity Risk Rollup:**
     $$R_{effective} = R_{(0)} + \sum_{i=1}^{n-1} \frac{R_{(i)}}{1 + \ln(1 + i)}$$
     $$R_{entity} = R_{effective} \cdot \text{Tactics\_Bonus}$$
     *(Tactics bonus: $1.0\times$ for single tactic, $1.3\times$ for two tactics, $1.6\times$ for multi-stage intrusions $\ge 3$ tactics)*

---

## 📁 Repository Structure
```
open-rba/
├── config/             # Configurable weights and operational thresholds (weights.yaml)
├── data/               # Local SQLite database & bundled sample alert dataset
│   ├── sample_alerts.json
│   └── alerts.db
├── docs/               # Architecture diagrams and technical documentation
├── src/                # Modular Python source code (M1 to M5)
│   ├── ingestion/      # Module 1: Ingestion, schema, deduplication & Wazuh client
│   ├── correlation/    # Module 2: Session-window temporal correlation engine
│   ├── enrichment/     # Module 3: Threat intelligence client with exponential decay
│   ├── attck/          # Module 4: MITRE ATT&CK tactical progression mapper
│   ├── scoring/        # Module 5: Dynamic risk scoring & entity aggregation
│   └── pipeline.py     # End-to-end analytical pipeline CLI
└── tests/              # Pytest test suite (73 unit and integration tests)
```

---

## 🚀 Quickstart & Usage

### 1. Installation
```bash
git clone https://github.com/ajazahmed11/open-rba.git
cd open-rba
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Prioritization Pipeline
```bash
# Ingest alerts, correlate bursts, enrich CTI, map MITRE tactics, and prioritize:
python -m src.pipeline --file data/sample_alerts.json

# Or prioritize existing database records directly:
python -m src.pipeline --no-ingest
```

### 3. Run Ingestion Standalone
```bash
# Ingest from local alert JSON/JSONL file:
python -m src.ingestion.wazuh_client --file data/sample_alerts.json

# Ingest live alerts from Wazuh OpenSearch Indexer (:9200):
python -m src.ingestion.wazuh_client --indexer https://localhost:9200 --last 100
```

### 4. Run the Test Suite
```bash
pytest tests/ -v
```
*(All 73 unit and integration tests execute in <0.3s)*

---

## 📜 License
This project is open-source and licensed under the [MIT License](LICENSE).
