"""
Open-RBA End-to-End Analytical Pipeline & CLI Entry Point.

Executes the complete 5-stage Risk-Based Alerting pipeline:
    1. Ingestion & Normalization (SQLite persistence + deduplication)
    2. Temporal Correlation (Session window burst reduction)
    3. Threat Intelligence Enrichment (AbuseIPDB + exponential decay e^-lambda*t)
    4. MITRE ATT&CK Mapping (Kill-chain depth evaluation)
    5. Dynamic Multi-Factor Risk Scoring (Normalized prioritization & entity ranking)
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.ingestion.wazuh_client import WazuhClient
from src.ingestion.database import AlertDatabase
from src.correlation.engine import correlate_alerts, alert_reduction_ratio, CorrelatedIncident
from src.enrichment.client import ThreatIntelClient
from src.attck.mapper import ATTACKMapper
from src.scoring.engine import RiskScoringEngine, ScoredIncident, EntityIncident


DEFAULT_MOCK_INTEL = {
    "203.0.113.45": {
        "score": 88.0,
        "last_reported_at": "2026-10-01T08:00:00Z"
    },
    "198.51.100.99": {
        "score": 45.0,
        "last_reported_at": "2026-09-20T00:00:00Z"
    }
}


class OpenRBAPipeline:
    """Orchestrates the 5-stage Open-RBA incident prioritization workflow."""

    def __init__(
        self,
        db_path: str = "data/alerts.db",
        weights_config: str = "config/weights.yaml",
        api_key: Optional[str] = None,
        mock_intel: Optional[Dict[str, Any]] = None
    ):
        base_dir = Path(__file__).parent.parent
        resolved_db = db_path if Path(db_path).is_absolute() else str(base_dir / db_path)
        resolved_weights = weights_config if Path(weights_config).is_absolute() else str(base_dir / weights_config)

        self.db_path = resolved_db
        self.wazuh_client = WazuhClient(db_path=resolved_db)
        self.db = AlertDatabase(db_path=resolved_db)
        self.scoring_engine = RiskScoringEngine(config_path=resolved_weights)
        self.attack_mapper = ATTACKMapper()

        # Load lambda decay factor from config
        decay_cfg = self.scoring_engine.config.get("temporal_decay", {})
        lambda_factor = float(decay_cfg.get("lambda_factor", 0.05))
        max_age_days = int(decay_cfg.get("max_indicator_age_days", 90))

        # Configurable mock intelligence for offline testing
        active_mock_intel = mock_intel if mock_intel is not None else DEFAULT_MOCK_INTEL

        self.cti_client = ThreatIntelClient(
            api_key=api_key or os.getenv("ABUSEIPDB_API_KEY"),
            db_path=resolved_db,
            lambda_factor=lambda_factor,
            max_age_days=max_age_days,
            mock_data=active_mock_intel
        )

    def run(
        self,
        file_path: Optional[str] = None,
        use_api: bool = False,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Executes the complete pipeline and returns structured evaluation metrics."""
        # --- Stage 1: Ingestion ---
        ingested_count = 0
        if file_path:
            ingested_count = self.wazuh_client.ingest_from_file(file_path, limit=limit)

        raw_alerts = self.db.fetch_all()
        if not raw_alerts:
            return {
                "status": "empty",
                "raw_alerts_count": 0,
                "incidents_count": 0,
                "reduction_ratio": 0.0,
                "scored_incidents": [],
                "entities": []
            }

        # --- Stage 2: Correlation ---
        window_seconds = int(
            self.scoring_engine.config.get("correlation", {}).get("time_window_seconds", 120)
        )
        correlated = correlate_alerts(raw_alerts, window_seconds=window_seconds)
        reduction = alert_reduction_ratio(len(raw_alerts), len(correlated))

        # --- Stage 3, 4, 5: Enrichment, ATT&CK, Risk Scoring ---
        scored_incidents = self.scoring_engine.score_all(correlated, self.cti_client, self.attack_mapper)
        ranked_entities = self.scoring_engine.aggregate_by_entity(scored_incidents)

        return {
            "status": "success",
            "raw_alerts_count": len(raw_alerts),
            "new_ingested": ingested_count,
            "incidents_count": len(scored_incidents),
            "reduction_ratio": reduction,
            "scored_incidents": scored_incidents,
            "entities": ranked_entities
        }


def format_table(results: Dict[str, Any]) -> str:
    """Formats pipeline output into an executive ASCII summary table."""
    lines = []
    lines.append("=" * 100)
    lines.append("  🛡️  OPEN-RBA: RISK-BASED INCIDENT PRIORITIZATION PIPELINE")
    lines.append("=" * 100)

    raw_count = results["raw_alerts_count"]
    inc_count = results["incidents_count"]
    ratio = results["reduction_ratio"]

    lines.append(f"  • Total Raw Alerts Ingested : {raw_count}")
    lines.append(f"  • Correlated Incident Units : {inc_count}")
    lines.append(f"  • Alert Noise Reduction     : {ratio:.1%} (Target: ≥70.0%)")
    lines.append("-" * 100)

    lines.append("\n🏆 PRIORITIZED INCIDENT QUEUE (Ranked by Dynamic Risk Score):")
    lines.append("-" * 100)
    header = f"{'RANK':<5} {'RISK':<6} {'HOST':<8} {'ASSET':<9} {'TACTIC':<22} {'TECH':<8} {'SRC IP':<15} {'ALERTS':<7}"
    lines.append(header)
    lines.append("-" * 100)

    for rank, s in enumerate(results["scored_incidents"], 1):
        inc = s.incident
        src = inc.src_ip or "LOCAL"
        tactic = s.attack.primary_tactic
        tech = s.attack.primary_technique
        lines.append(
            f"#{rank:<4} {s.incident_risk:<6.2f} {inc.agent_name:<8} {s.asset_tier:<9} "
            f"{tactic:<22} {tech:<8} {src:<15} {inc.alert_count:<7}"
        )
    lines.append("-" * 100)

    lines.append("\n🎯 ENTITY TARGET SUMMARY (Host-Level Multi-Stage Intrusion Rollup):")
    lines.append("-" * 100)
    e_header = f"{'RANK':<5} {'HOST':<8} {'ASSET':<9} {'ENTITY RISK':<12} {'INCIDENTS':<10} {'TACTICS OBSERVED':<35} {'BONUS':<6}"
    lines.append(e_header)
    lines.append("-" * 100)

    for rank, e in enumerate(results["entities"], 1):
        tactics_str = ", ".join(e.distinct_tactics)
        lines.append(
            f"#{rank:<4} {e.agent_name:<8} {e.asset_tier:<9} {e.total_entity_risk:<12.2f} "
            f"{e.incident_count:<10} {tactics_str:<35} {e.tactics_depth_bonus}x"
        )
    lines.append("=" * 100)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Open-RBA Prioritization Pipeline")
    parser.add_argument("--file", type=str, default="data/sample_alerts.json",
                        help="Path to JSON alert file to ingest and prioritize")
    parser.add_argument("--db", type=str, default="data/alerts.db",
                        help="Target SQLite alerts database")
    parser.add_argument("--weights", type=str, default="config/weights.yaml",
                        help="Path to multi-factor weights configuration")
    parser.add_argument("--limit", type=int, default=500,
                        help="Maximum alerts to process")

    args = parser.parse_args()
    pipeline = OpenRBAPipeline(db_path=args.db, weights_config=args.weights)
    results = pipeline.run(file_path=args.file, limit=args.limit)

    print(format_table(results))


if __name__ == "__main__":
    main()
