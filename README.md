# Open-RBA: Risk-Based Alerting & Incident Prioritization Framework

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/pytest-109%2F109%20passing-brightgreen.svg)](tests/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20Compatible-orange.svg)](https://wazuh.com/)

---

## 📌 Overview
`open-rba` is an open-source, deterministic, and explainable Python framework that transforms raw **Wazuh SIEM** alerts into prioritized incident queues and bounded entity risk timelines.

Key capabilities:
1. **Confidence × Impact Risk Scoring (`v2` default, `v1` baseline):** Separates detection likelihood (rule severity prior, `(rule_id, host)` IDF rarity, attack outcome distinction, and an upward-only CTI boost) from target impact (asset tier criticality and privileged-account involvement).
2. **No Clean-IP Penalty:** External indicators with `AbuseIPDB = 0` or unavailable CTI do not drag down incident confidence compared to internal alerts (`v2` applies CTI strictly as a bounded upward boost; `v1` preserves legacy weight renormalization).
3. **Target-Aware Correlation (`target_aware` / `source_ip`):** Collapses repetitive bursts and IP-rotating credential sprays targeting the same `(host, technique_family)` within a sliding session window ($\Delta t \le 120\text{s}$).
4. **Bounded Entity Risk Timeline (`[0, 100]`):** Combines time-decayed rolling incident contributions ($\lambda_{\text{entity}} = 0.10/\text{day}$, window $W = 30\text{ days}$) with deterministic time-bounded ordered attack chains from YAML, normalized via $100 \cdot (1 - e^{-R/k})$.
5. **Reproducible Evaluation Harness (`eval/`):** Benchmarks `v1` and `v2` against 7 reference baselines using Precision@5/10/20 (95% bootstrap CIs), Recall@k, factor ablations, and $\pm 20\%$ weight perturbation stability.

---

## 🏗️ 5-Stage Pipeline Architecture

```text
Raw Wazuh Alerts (alerts.json / OpenSearch Indexer :9200)
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 1: Ingestion & Normalizer                      │ ── UTC Canonicalization, SHA-256 Dedup & Dead-Letter
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 2: Temporal Correlation Engine                 │ ── Sliding-Window & Target-Aware Spray Compression
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 3: CTI Enrichment & Temporal Decay             │ ── AbuseIPDB, 7-Day Cache, 429 Circuit-Breaker & Decay
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 4: MITRE ATT&CK Mapper                         │ ── Explicit Techniques, rule.mitre.tactic & Negation Guards
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Module 5: Multi-Factor Risk Scorer (v2 / v1)          │ ── Confidence × Impact, Rarity, Sequences & [0,100] Rollup
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
        Prioritized Incident Queue & Bounded Entity Timeline
```

### Module Breakdown

1. **Module 1 — Ingestion & Normalization (`src/ingestion/`):**
   * Streams local JSONL/JSON-array log files (`alerts.json`) or queries Wazuh OpenSearch Indexer (`:9200`/`wazuh-alerts-*`) with ascending sort, `search_after` pagination, and per-source checkpoints.
   * Canonicalizes timestamps to UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SS.mmmZ`), preserves `rule.mitre.tactic`, and enforces SHA-256 deduplication across `(timestamp, rule_id, agent_name, src_ip, dst_ip, user, log_content)`.
   * Isolates malformed records in SQLite `dead_letter` (WAL mode + `busy_timeout`) with automated v1→v2→v3 schema migrations.

2. **Module 2 — Temporal Correlation Engine (`src/correlation/`):**
   * Supports `target_aware` (default, collapses rotating-IP sprays by `(scope, agent_name, technique_family)`) and `source_ip` (`v1` legacy) within sliding session windows ($\Delta t \le 120\text{s}$).
   * Compresses single-source and 50-IP brute-force floods by **99.3%** (`150 → 1` incident), and heterogeneous 8-alert sample telemetry by **37.5%** (`8 → 5` incidents).

3. **Module 3 — Threat Intelligence Enrichment (`src/enrichment/`):**
   * Queries AbuseIPDB REST API v2 with local SQLite caching (7-day TTL, WAL mode, stale-on-error fallback), per-run memoization, and HTTP 429 circuit-breaking.
   * Applies exponential temporal decay with $\lambda = 0.05$ ($t_{1/2} \approx 13.86$ days):
     $$CTI_{decay} = CTI_{raw} \cdot e^{-\lambda \Delta t}$$

4. **Module 4 — MITRE ATT&CK Mapper (`src/attck/`):**
   * Resolves explicit technique IDs (`TECHNIQUE_MAP`, 24 common techniques), falls back to Wazuh's native `rule.mitre.tactic`, and finally applies word-boundary regex inference with negation guards (preventing clean scans or routine FIM alerts from inflating Defense Evasion).
   * Tactical stage progression: *Reconnaissance* `0.10`, *Discovery / Resource Dev* `0.20`, *Initial Access* `0.40`, *Execution* `0.50`, *Persistence* `0.60`, *Defense Evasion* `0.70`, *Credential Access / Lateral Movement / Collection / C2* `0.80`, *Privilege Escalation* `0.90`, *Exfiltration / Impact* `1.00`.

5. **Module 5 — Risk Scoring & Entity Aggregation (`src/scoring/`):**
   * **Scoring `v2` (Default):**
     * **Confidence** $\in [0, 1]$: Weighted combination of rule severity prior ($S/15$), kill-chain depth, and corpus `(rule_id, host)` IDF rarity, scaled by an outcome factor (damping failed-only probes by $0.65\times$ and boosting confirmed execution/compromise/post-failure auth success by $1.25\times$), plus a capped upward CTI boost ($0.15 \cdot CTI_{decay}$).
     * **Impact** $\in [0, 1]$: Normalized asset tier (`critical: 3.0`, `high: 2.0`, `medium: 1.5`, `low: 1.0`) plus a $+0.15$ boost when privileged accounts are targeted.
     * **Incident Risk:** $R_{incident} = 3.0 \cdot \text{Confidence} \cdot \text{Impact} \in [0.0, 3.0]$.
     * **Bounded Entity Timeline:** Decays incidents over a 30-day rolling window ($\lambda_{\text{entity}} = 0.10/\text{day}$), applies rank diminishing returns and deterministic time-bounded sequence chain rules from `config/weights.yaml` (`sequences:`), and maps strictly to $[0, 100)$:
       $$R_{entity} = 100 \cdot \left(1 - e^{-R_{\text{effective}} / k}\right)$$
   * **Scoring `v1` (Comparison Baseline):** Selectable via `scoring.version: v1` in `config/weights.yaml` or `--scoring-version v1`.

---

## 📊 Evaluation Harness & Benchmark Results

All metrics below are generated directly by `python -m eval.run --synthetic --queues 20 --seed 42 --versions v1 v2 --out eval_out` on 20 seeded synthetic queues (1,000 bootstrap resamples).

> **Note:** Synthetic queues are for CI regression testing only. For real Wazuh/Kali lab evaluation, record attack start/stop timestamps and attacker IPs to label captured alerts and pass `--alerts` / `--labels` to `eval.run`.

| System | P@5 (95% CI) | P@10 (95% CI) | P@20 (95% CI) | Recall@10 | Recall@20 | 1st True Rank |
|---|---|---|---|---|---|---|
| `baseline:random` | 0.220 [0.180, 0.270] | 0.225 [0.185, 0.265] | 0.253 [0.233, 0.273] | 0.190 | 0.426 | 2.80 |
| `baseline:time_newest` | 0.110 [0.040, 0.200] | 0.175 [0.105, 0.250] | 0.203 [0.145, 0.268] | 0.149 | 0.341 | 9.45 |
| `baseline:max_rule_level` | 0.960 [0.920, 0.990] | 0.480 [0.460, 0.495] | 0.333 [0.295, 0.372] | 0.405 | 0.563 | 1.00 |
| `baseline:alert_count` | 0.200 [0.200, 0.200] | 0.230 [0.180, 0.280] | 0.290 [0.280, 0.297] | 0.195 | 0.489 | 1.70 |
| `baseline:level_x_asset` | 0.670 [0.600, 0.740] | 0.675 [0.600, 0.750] | 0.568 [0.555, 0.580] | 0.569 | 0.958 | 1.00 |
| `baseline:additive` | 0.640 [0.550, 0.730] | 0.635 [0.575, 0.695] | 0.525 [0.505, 0.547] | 0.535 | 0.886 | 1.00 |
| `baseline:idf_bm25` | 0.970 [0.940, 1.000] | 0.495 [0.475, 0.515] | 0.282 [0.273, 0.292] | 0.417 | 0.476 | 1.00 |
| `open_rba:v1` | 1.000 [1.000, 1.000] | 0.790 [0.745, 0.835] | 0.565 [0.550, 0.580] | 0.666 | 0.954 | 1.00 |
| **`open_rba:v2`** | **1.000 [1.000, 1.000]** | **1.000 [1.000, 1.000]** | **0.593 [0.583, 0.603]** | **0.845** | **1.000** | **1.00** |

Weight perturbation sensitivity ($\pm 20\%$ on `v2` weights) preserves Spearman rank correlation $\rho \ge 0.9949$.

---

## 📁 Repository Structure
```
open-rba/
├── config/             # Configurable weights, correlation mode, asset tiers & sequence rules
├── data/               # Local SQLite database & bundled sample alert dataset
├── eval/               # Evaluation harness, 7 baselines, bootstrap CIs & synthetic generator
├── src/                # Modular Python source code (M1 to M5)
│   ├── ingestion/      # Module 1: Ingestion, schema v3, deduplication & Wazuh client
│   ├── correlation/    # Module 2: Session-window & target-aware correlation engine
│   ├── enrichment/     # Module 3: Threat intelligence client with exponential decay
│   ├── attck/          # Module 4: MITRE ATT&CK tactical progression mapper
│   ├── scoring/        # Module 5: Dynamic risk scoring (v2/v1) & entity timeline rollup
│   └── pipeline.py     # End-to-end analytical pipeline CLI
└── tests/              # Pytest test suite (109 unit and integration tests)
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
# Run bundled demo alerts with offline mock CTI (v2 default):
python -m src.pipeline --demo

# Compare against legacy v1 scoring:
python -m src.pipeline --demo --scoring-version v1

# Ingest local alerts file with explicit mock CTI or time windowing:
python -m src.pipeline --file data/sample_alerts.json --mock-cti
python -m src.pipeline --no-ingest --since 2026-10-05T10:15:00Z
```

### 3. Run Ingestion Standalone
```bash
# Ingest from local alert JSON/JSONL file:
python -m src.ingestion.wazuh_client --file data/sample_alerts.json

# Ingest live alerts from Wazuh OpenSearch Indexer (:9200):
python -m src.ingestion.wazuh_client --indexer https://localhost:9200 --last 100

# Ingest with TLS verification disabled for local self-signed testing certificates:
python -m src.ingestion.wazuh_client --indexer https://localhost:9200 --insecure
```

### 4. Run the Evaluation Harness & Test Suite
```bash
# Synthetic multi-queue benchmark comparing v1, v2, and all 7 baselines:
python -m eval.run --synthetic --queues 20 --seed 42 --versions v1 v2 --out /tmp/eval_out

# Custom labeled JSONL evaluation:
python -m eval.run --alerts alerts.jsonl --labels labels.jsonl --versions v1 v2 --out /tmp/eval_out

# Run all 109 unit and integration tests:
pytest tests/ -v
```

---

## 📜 License
This project is open-source and licensed under the [MIT License](LICENSE).
