"""
Unit tests for Open-RBA Ingestion & Normalization Module.
Tests schema integrity, edge-case normalization, deduplication, and SQLite persistence.
"""

import json
import pytest
from pathlib import Path

from src.ingestion.database import AlertDatabase, NormalizedAlert
from src.ingestion.wazuh_client import normalize_wazuh_alert, WazuhClient


# ---------------------------------------------------------------------------
# Normalization tests
# ---------------------------------------------------------------------------

def test_normalize_wazuh_alert_standard():
    raw = {
        "timestamp": "2026-10-05T10:14:07.410+0000",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force attempt",
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]}
        },
        "agent": {"name": "web01"},
        "data": {
            "srcip": "203.0.113.45",
            "dstuser": "root"
        }
    }
    alert = normalize_wazuh_alert(raw)
    assert alert is not None
    assert alert.rule_id == "5712"
    assert alert.rule_level == 10
    assert alert.agent_name == "web01"
    assert alert.src_ip == "203.0.113.45"
    assert alert.user == "root"
    assert alert.mitre_tactics == ["T1110.001"]


def test_normalize_wazuh_alert_mitre_string():
    """Wazuh decoders occasionally return mitre.id as a string instead of a list."""
    raw = {
        "timestamp": "2026-10-05T10:14:15.000Z",
        "rule": {
            "id": "100130",
            "level": 10,
            "description": "Directory Traversal",
            "mitre": {"id": "T1190"}
        },
        "agent": {"name": "web01"}
    }
    alert = normalize_wazuh_alert(raw)
    assert alert is not None
    assert alert.mitre_tactics == ["T1190"]


def test_normalize_wazuh_alert_missing_fields():
    """Alerts without network IPs or user identities should normalize gracefully."""
    raw = {
        "timestamp": "2026-10-05T10:14:30.000Z",
        "rule": {"id": "100100", "level": 12, "description": "FIM sudoers modified"},
        "agent": {"name": "web01"}
    }
    alert = normalize_wazuh_alert(raw)
    assert alert is not None
    assert alert.src_ip is None
    assert alert.user is None
    assert alert.mitre_tactics == []


# ---------------------------------------------------------------------------
# Content hash tests
# ---------------------------------------------------------------------------

def test_content_hash_deterministic():
    """Same alert data must always produce the same hash."""
    alert = NormalizedAlert(
        timestamp="2026-10-05T10:00:00Z",
        rule_id="5712", rule_level=10,
        rule_description="SSH brute force",
        agent_name="web01", src_ip="1.2.3.4"
    )
    assert alert.content_hash() == alert.content_hash()


def test_content_hash_differs_on_key_fields():
    """Alerts differing in identity fields must produce different hashes."""
    base = dict(
        timestamp="2026-10-05T10:00:00Z",
        rule_id="5712", rule_level=10,
        rule_description="SSH brute force",
        agent_name="web01", src_ip="1.2.3.4"
    )
    a1 = NormalizedAlert(**base)
    a2 = NormalizedAlert(**{**base, "src_ip": "5.6.7.8"})
    a3 = NormalizedAlert(**{**base, "timestamp": "2026-10-05T10:00:01Z"})
    assert a1.content_hash() != a2.content_hash()
    assert a1.content_hash() != a3.content_hash()


# ---------------------------------------------------------------------------
# Database tests
# ---------------------------------------------------------------------------

def test_database_insert_and_fetch(tmp_path):
    db_file = tmp_path / "test_alerts.db"
    db = AlertDatabase(str(db_file))

    sample = NormalizedAlert(
        timestamp="2026-10-05T10:00:00Z",
        rule_id="5712",
        rule_level=10,
        rule_description="SSH brute force",
        agent_name="web01",
        src_ip="192.168.1.100",
        mitre_tactics=["T1110"]
    )
    alert_id = db.insert_alert(sample)
    assert alert_id >= 1
    assert db.count() == 1

    records = db.fetch_recent(1)
    assert len(records) == 1
    assert records[0]["rule_id"] == "5712"
    assert records[0]["src_ip"] == "192.168.1.100"
    assert records[0]["mitre_tactics"] == ["T1110"]


def test_database_batch_insert(tmp_path):
    db_file = tmp_path / "test_alerts.db"
    db = AlertDatabase(str(db_file))

    batch = [
        NormalizedAlert(
            timestamp=f"2026-10-05T10:00:0{i}Z",
            rule_id="5710",
            rule_level=5,
            rule_description="Failed login",
            agent_name="web01",
            src_ip="203.0.113.5"
        )
        for i in range(5)
    ]
    inserted = db.insert_batch(batch)
    assert inserted == 5
    assert db.count() == 5


def test_database_dedup_single(tmp_path):
    """Inserting the same alert twice via insert_alert should not create a duplicate."""
    db = AlertDatabase(str(tmp_path / "test.db"))
    alert = NormalizedAlert(
        timestamp="2026-10-05T10:00:00Z",
        rule_id="5712", rule_level=10,
        rule_description="SSH brute force",
        agent_name="web01", src_ip="1.2.3.4"
    )
    id1 = db.insert_alert(alert)
    id2 = db.insert_alert(alert)
    assert id1 >= 1
    assert id2 == 0  # duplicate skipped
    assert db.count() == 1


def test_database_dedup_batch(tmp_path):
    """Batch inserting a mix of new and duplicate alerts should only insert new ones."""
    db = AlertDatabase(str(tmp_path / "test.db"))
    alert_a = NormalizedAlert(
        timestamp="2026-10-05T10:00:00Z",
        rule_id="5712", rule_level=10,
        rule_description="SSH brute force",
        agent_name="web01", src_ip="1.2.3.4"
    )
    alert_b = NormalizedAlert(
        timestamp="2026-10-05T10:00:05Z",
        rule_id="5710", rule_level=5,
        rule_description="Failed login",
        agent_name="web01", src_ip="1.2.3.4"
    )
    # First batch: both new
    inserted = db.insert_batch([alert_a, alert_b])
    assert inserted == 2
    assert db.count() == 2

    # Second batch: same alerts again — zero new inserts
    inserted = db.insert_batch([alert_a, alert_b])
    assert inserted == 0
    assert db.count() == 2


def test_database_fetch_time_range(tmp_path):
    """fetch_time_range should return only alerts within the specified window."""
    db = AlertDatabase(str(tmp_path / "test.db"))
    alerts = [
        NormalizedAlert(timestamp="2026-10-05T10:00:00Z", rule_id="5710",
                        rule_level=5, rule_description="A", agent_name="web01"),
        NormalizedAlert(timestamp="2026-10-05T10:05:00Z", rule_id="5710",
                        rule_level=5, rule_description="B", agent_name="web01"),
        NormalizedAlert(timestamp="2026-10-05T10:10:00Z", rule_id="5710",
                        rule_level=5, rule_description="C", agent_name="web01"),
    ]
    db.insert_batch(alerts)
    result = db.fetch_time_range("2026-10-05T10:00:00Z", "2026-10-05T10:05:00Z")
    assert len(result) == 2
    assert result[0]["rule_description"] == "A"
    assert result[1]["rule_description"] == "B"


# ---------------------------------------------------------------------------
# Client integration tests
# ---------------------------------------------------------------------------

def test_wazuh_client_ingest_file(tmp_path):
    db_file = tmp_path / "test_alerts.db"
    sample_file = tmp_path / "alerts.json"

    lines = [
        json.dumps({
            "timestamp": "2026-10-05T10:00:00Z",
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "web01"},
            "data": {"srcip": "1.2.3.4"}
        }),
        json.dumps({
            "timestamp": "2026-10-05T10:01:00Z",
            "rule": {"id": "100130", "level": 10, "description": "Web attack"},
            "agent": {"name": "web01"},
            "data": {"srcip": "1.2.3.4"}
        })
    ]
    sample_file.write_text("\n".join(lines), encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file))
    assert count == 2
    assert client.db.count() == 2


def test_wazuh_client_ingest_file_idempotent(tmp_path):
    """Ingesting the same file twice must not create duplicate rows."""
    db_file = tmp_path / "test_alerts.db"
    sample_file = tmp_path / "alerts.json"

    lines = [
        json.dumps({
            "timestamp": "2026-10-05T10:00:00Z",
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "web01"},
            "data": {"srcip": "1.2.3.4"}
        }),
    ]
    sample_file.write_text("\n".join(lines), encoding="utf-8")

    client = WazuhClient(str(db_file))
    count1 = client.ingest_from_file(str(sample_file))
    count2 = client.ingest_from_file(str(sample_file))
    assert count1 == 1
    assert count2 == 0  # duplicate, nothing new
    assert client.db.count() == 1


def test_wazuh_client_ingest_file_tail_limit(tmp_path):
    """When limit is passed, ingest_from_file must tail the newest N lines."""
    db_file = tmp_path / "test_tail.db"
    sample_file = tmp_path / "alerts_tail.json"

    lines = [
        json.dumps({
            "timestamp": f"2026-10-05T10:0{i}:00Z",
            "rule": {"id": f"571{i}", "level": 5, "description": f"Event {i}"},
            "agent": {"name": "web01"}
        })
        for i in range(5)
    ]
    sample_file.write_text("\n".join(lines), encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file), limit=2)
    assert count == 2
    # The two alerts in the database should be Event 3 and Event 4 (the newest lines)
    recent = client.db.fetch_recent(2)
    rule_ids = {r["rule_id"] for r in recent}
    assert rule_ids == {"5713", "5714"}


def test_dead_letter_recording(tmp_path):
    """Malformed alerts are routed to the dead_letter table without crashing."""
    db_file = tmp_path / "test_dead_letter.db"
    sample_file = tmp_path / "alerts_malformed.json"

    content = "THIS IS NOT JSON\n" + json.dumps({
        "timestamp": "2026-10-05T10:00:00Z",
        "rule": {"id": "5712", "level": 10, "description": "Valid"},
        "agent": {"name": "web01"}
    }) + "\n"
    sample_file.write_text(content, encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file))
    assert count == 1
    # Check that dead_letter table received the bad line
    with client.db._get_connection() as conn:
        rows = conn.cursor().execute("SELECT * FROM dead_letter").fetchall()
        assert len(rows) == 1
        assert "THIS IS NOT JSON" in rows[0]["raw_payload"]


def test_dead_letter_on_non_numeric_rule_level(tmp_path):
    """Alerts with invalid/corrupted rule levels are routed to dead_letter."""
    db_file = tmp_path / "test_level_dead.db"
    sample_file = tmp_path / "alerts_corrupt_level.json"

    content = json.dumps({
        "timestamp": "2026-10-05T10:00:00Z",
        "rule": {"id": "5712", "level": "INVALID_LEVEL", "description": "Corrupt rule"},
        "agent": {"name": "web01"}
    }) + "\n"
    sample_file.write_text(content, encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file))
    assert count == 0
    with client.db._get_connection() as conn:
        rows = conn.cursor().execute("SELECT * FROM dead_letter").fetchall()
        assert len(rows) == 1
        assert "NormalizationError" in rows[0]["error_reason"]

