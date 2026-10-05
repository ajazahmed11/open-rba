"""
Unit tests for Open-RBA Ingestion & Normalization Module.
Tests schema integrity, edge-case normalization, and SQLite persistence.
"""

import json
import pytest
from pathlib import Path

from src.ingestion.database import AlertDatabase, NormalizedAlert
from src.ingestion.wazuh_client import normalize_wazuh_alert, WazuhClient


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
    assert alert_id == 1
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
