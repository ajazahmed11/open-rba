"""
End-to-end integration tests for Open-RBA Analytical Pipeline.
Validates the complete 5-stage workflow from raw file ingestion to prioritized entity queues.
"""

import pytest
from pathlib import Path
from src.pipeline import OpenRBAPipeline


def test_full_pipeline_sample_alerts(tmp_path):
    db_file = tmp_path / "pipeline_test.db"
    sample_file = Path(__file__).parent.parent / "data" / "sample_alerts.json"
    weights_file = Path(__file__).parent.parent / "config" / "weights.yaml"

    pipeline = OpenRBAPipeline(
        db_path=str(db_file),
        weights_config=str(weights_file)
    )

    results = pipeline.run(file_path=str(sample_file))

    assert results["status"] == "success"
    assert results["raw_alerts_count"] == 8
    assert results["incidents_count"] == 5
    # 8 alerts compressed into 5 incidents
    assert results["reduction_ratio"] == 0.375

    # Check scored incidents
    scored = results["scored_incidents"]
    assert len(scored) == 5

    # Verify descending risk sort order
    risks = [s.incident_risk for s in scored]
    assert risks == sorted(risks, reverse=True)

    # Check ranked entities
    entities = results["entities"]
    assert len(entities) == 2  # web01 and db01

    # web01 has 3 distinct tactics (Initial Access, Credential Access, Privilege Escalation)
    # so it should receive the 1.6x multi-stage bonus and be ranked #1
    assert entities[0].agent_name == "web01"
    assert entities[0].tactics_depth_bonus == 1.6
    assert len(entities[0].distinct_tactics) == 3


def test_full_pipeline_empty_db(tmp_path):
    db_file = tmp_path / "empty.db"
    pipeline = OpenRBAPipeline(db_path=str(db_file))
    results = pipeline.run(file_path=None)
    assert results["status"] == "empty"
    assert results["raw_alerts_count"] == 0
    assert results["incidents_count"] == 0
