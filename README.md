# Open-RBA: Risk-Based Alerting & Incident Prioritization Framework

**Academic Title:** *Intelligent Incident Response Framework using Threat Intelligence Enrichment and Risk-Based Incident Prioritization for SIEM Environments*  

---

## 📌 Overview
`open-rba` is an open-source, deterministic Python framework designed to eliminate SIEM alert fatigue by converting raw, statically-severitized alerts from **Wazuh SIEM** into mathematically prioritized, context-enriched incidents.

![System Architecture](docs/framework_architecture.png)

## 🏗️ 5-Stage Pipeline
1. **Module 1 (Ingestion & Normalization):** Ingests raw alerts via Wazuh REST API (:55000) or logs into standardized SQLite schema.
2. **Module 2 (Temporal Correlation):** Clusters high-frequency alert bursts (same source/technique within sliding window) to achieve ≥70% alert reduction.
3. **Module 3 (Threat Intel with Decay):** Queries AbuseIPDB & AlienVault OTX with local caching and exponential decay ($e^{-\lambda \Delta t}$).
4. **Module 4 (MITRE ATT&CK Mapping):** Tracks tactical depth across the intrusion lifecycle (Initial Access → Exfiltration).
5. **Module 5 (Dynamic Risk Scoring):** Weighted mathematical scoring formula ranking the most critical threats at Queue #1.

## 📁 Repository Structure
```
open-rba/
├── config/             # Configurable weights (weights.yaml)
├── data/               # SQLite database & local caches (git-ignored)
├── docs/               # Formal M.Tech proposal, presentation & diagrams
├── src/                # Modular Python source code (M1 to M5)
│   ├── ingestion/
│   ├── correlation/
│   ├── enrichment/
│   ├── attck/
│   └── scoring/
└── tests/              # Pytest test suites
```
