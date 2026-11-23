# Open-RBA: Risk-Based Alerting & Incident Prioritization Framework

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/pytest-72%2F72%20passing-brightgreen.svg)](tests/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20Compatible-orange.svg)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/ATT%26CK-v14%20Aligned-red.svg)](https://attack.mitre.org/)

---

### 🎓 Academic Research Title
* **Academic Title:** *Intelligent Incident Response Framework using Threat Intelligence Enrichment and Risk-Based Incident Prioritization for SIEM Environments*

---

## 📌 Overview
`open-rba` is an open-source, deterministic Python framework designed to resolve SIEM alert fatigue by transforming raw, statically-severitized alerts from **Wazuh SIEM** into mathematically prioritized, context-enriched incidents.

Traditional SIEMs rely on static alert rules (1–15) that fail to differentiate high-frequency network noise from multi-stage targeted attacks. `open-rba` introduces:
1. **Dynamic CTI Weight Renormalization** to prevent internal/local events from being penalized when threat intelligence is absent.
2. **Intrusion Stage Criticality Progression** aligning tactical depth with actual breach impact.
3. **Sub-Linear Entity Risk Accumulation** using logarithmic diminishing returns to prevent volume flood attacks from masking critical single-event compromises.
4. **Resilient Ingestion** supporting OpenSearch Indexer (`:9200`), local `alerts.json`, SHA-256 deduplication, and dead-letter queue isolation.

---

## 🏗️ 5-Stage Pipeline Architecture

```text
Raw Wazuh Alerts (alerts.json / OpenSearch Indexer :9200 / API :55000)
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 1: Ingestion & Normalizer                      │ ── SHA-256 Deduplication & Dead-Letter Isolation
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 2: Temporal Correlation Engine                 │ ── Session-Window Burst Compression (≥70% Noise Cut)
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 3: CTI Enrichment & Temporal Decay             │ ── AbuseIPDB, 7-Day TTL Cache & Exp Decay (e^-λΔt)
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 4: MITRE ATT&CK Mapper                         │ ── Intrusion Criticality Progression [0.1 to 1.0]
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
   * Ingests alerts from Wazuh OpenSearch Indexer (`:9200`), local `alerts.json`, or the management daemon (`:55000`).
   * Computes SHA-256 content hashes across `(timestamp, rule_id, agent_id, src_ip, full_log)` for idempotent storage.
   * Isolates malformed records into a dedicated `dead_letter` table rather than silently dropping rows.

2. **Module 2 — Temporal Correlation Engine (`src/correlation/`):**
   * Clusters high-frequency alert bursts sharing `(src_ip, target_host, technique_family)` within sliding session windows ($\Delta t \le 120\text{s}$).
   * Consolidates repetitive telemetry (e.g., SSH brute force, port scans) into single parent incident objects, reducing analyst volume by $\ge 70\%$.
   * Guarantees UTC-aware timestamp parsing across heterogeneous log formats.

3. **Module 3 — Threat Intelligence Enrichment (`src/enrichment/`):**
   * Enriches public IP indicators with AbuseIPDB confidence scores.
   * Applies an exponential temporal decay function with a 14-day half-life:
     $$CTI_{decay} = CTI_{raw} \cdot e^{-\lambda \Delta t}, \quad \lambda = \frac{\ln(2)}{14}$$
   * Implements a local SQLite cache with a 7-day TTL and gracefully flags API rate limits (HTTP 429) to trigger dynamic renormalization rather than misclassifying IPs as clean.

4. **Module 4 — MITRE ATT&CK Tactical Progression (`src/attck/`):**
   * Maps technique IDs and alert descriptions to MITRE ATT&CK tactics using regex word boundaries.
   * Scores intrusion progression based on post-exploitation criticality:
     * *Discovery / Reconnaissance:* 0.20
     * *Initial Access:* 0.40
     * *Execution / Persistence:* 0.50 – 0.60
     * *Privilege Escalation / Defense Evasion:* 0.90
     * *Exfiltration / Impact:* 1.00

5. **Module 5 — Dynamic Multi-Factor Risk Scorer (`src/scoring/`):**
   * **Dynamic CTI Weight Renormalization:** When an incident has no public indicator or threat intelligence is unavailable ($CTI = \text{None}$), the missing CTI weight ($w_{cti} = 0.40$) is not scored as zero. Instead, weights renormalize across available intrinsic factors:
     $$w'_{sev} = \frac{w_{sev}}{w_{sev} + w_{kc}} = \frac{0.35}{0.35 + 0.25} = 0.5833$$
     $$w'_{kc} = \frac{w_{kc}}{w_{sev} + w_{kc}} = \frac{0.25}{0.35 + 0.25} = 0.4167$$
     $$R_{base} = w'_{sev} \cdot S_{norm} + w'_{kc} \cdot KC_{norm}$$
   * **Full Multi-Factor Base Score (with CTI):**
     $$R_{base} = w_{sev} \cdot S_{norm} + w_{cti} \cdot CTI_{decay} + w_{kc} \cdot KC_{norm} \in [0.0, 1.0]$$
   * **Asset Multiplier:**
     $$R_{incident} = R_{base} \cdot M_{asset}$$
     *(Tier 1 / Domain Controller / Critical DB: $1.5\times$, High / API / Auth: $1.25\times$, Standard Workstation: $1.0\times$)*
   * **Bounded Entity Risk Rollup with Diminishing Returns:**
     To prevent high-volume low-severity events from outranking targeted high-impact breaches, entity risk uses rank-decayed diminishing returns:
     $$R_{effective} = R_{(0)} + \sum_{i=1}^{n-1} \frac{R_{(i)}}{1 + \ln(1 + i)}$$
     $$R_{entity} = R_{effective} \cdot \left(1.0 + 0.1 \times \min(N_{tactics}, 5)\right)$$

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
└── tests/              # Pytest test suite (72 unit and integration tests)
    ├── test_ingestion.py
    ├── test_correlation.py
    ├── test_enrichment.py
    ├── test_attck.py
    ├── test_scoring.py
    └── test_pipeline.py
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

### 2. Run the Complete Prioritization Pipeline
```bash
# Ingest alerts, correlate bursts, enrich CTI, map MITRE tactics, and prioritize:
python -m src.pipeline --file data/sample_alerts.json
```

### 3. Run Ingestion Standalone
```bash
# Ingest from local alert JSON/JSONL file:
python -m src.ingestion.wazuh_client --file data/sample_alerts.json

# Ingest live alerts from Wazuh OpenSearch Indexer (:9200):
python -m src.ingestion.wazuh_client --indexer https://wazuh-indexer:9200 --last 100
```

### 4. Run the Test Suite
```bash
pytest tests/ -v
```
*(All 72 unit and integration tests execute in <0.3s)*

---

## 📜 License
This project is open-source and licensed under the [MIT License](LICENSE).
