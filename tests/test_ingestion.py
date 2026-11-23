"""
Unit tests for Open-RBA Ingestion & Normalization Module.
Tests schema integrity, edge-case normalization, deduplication, and SQLite persistence.
"""

import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

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


def test_normalize_wazuh_alert_missing_timestamp():
    """Alerts without a valid timestamp must be rejected and not silently defaulted."""
    raw = {
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web01"}
    }
    assert normalize_wazuh_alert(raw) is None

    raw_empty = {
        "timestamp": "   ",
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web01"}
    }
    assert normalize_wazuh_alert(raw_empty) is None


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


def test_normalize_wazuh_alert_unparseable_timestamp(tmp_path):
    """Alerts with invalid/unparseable timestamps are rejected and dead-lettered."""
    raw = {
        "timestamp": "not-a-date",
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"name": "web01"}
    }
    assert normalize_wazuh_alert(raw) is None

    db_file = tmp_path / "test_unparseable_ts.db"
    sample_file = tmp_path / "alerts_bad_ts.json"
    sample_file.write_text(json.dumps(raw) + "\n", encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file))
    assert count == 0
    with client.db._get_connection() as conn:
        rows = conn.cursor().execute("SELECT * FROM dead_letter").fetchall()
        assert len(rows) == 1
        assert "NormalizationError" in rows[0]["error_reason"]


def test_dedup_canonical_payload_sort_keys():
    """Identical alerts with scrambled JSON key order produce the exact same content hash."""
    payload_a = {"timestamp": "2026-10-05T10:00:00Z", "rule": {"id": "5712", "level": 10}, "z": 99, "a": 1}
    payload_b = {"a": 1, "z": 99, "rule": {"level": 10, "id": "5712"}, "timestamp": "2026-10-05T10:00:00Z"}

    alert_a = normalize_wazuh_alert(payload_a)
    alert_b = normalize_wazuh_alert(payload_b)
    assert alert_a is not None and alert_b is not None
    assert alert_a.content_hash() == alert_b.content_hash()


def test_database_v1_to_v3_migration(tmp_path):
    """A legacy v1 database (without schema_version table) is migrated to v3 and rehashed."""
    db_file = tmp_path / "legacy_v1.db"

    with sqlite3.connect(db_file) as conn:
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_level INTEGER NOT NULL,
                rule_description TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                user TEXT,
                process TEXT,
                mitre_tactics TEXT,
                raw_payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        legacy_payload = json.dumps({
            "timestamp": "2026-10-05T10:00:00.000Z",
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "web01"},
            "full_log": "sshd: brute force attack"
        })
        conn.execute(
            "INSERT INTO alerts (content_hash, timestamp, rule_id, rule_level, rule_description, agent_name, raw_payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy_old_hash_12345", "2026-10-05T10:00:00.000Z", "5712", 10, "SSH brute force", "web01", legacy_payload)
        )
        conn.commit()

    # Open with AlertDatabase -> must trigger migration to schema version 3
    client = WazuhClient(str(db_file))
    assert client.db.get_schema_version() == 3

    # The row in DB should now have the canonical v3 hash
    with client.db._get_connection() as conn:
        row = conn.cursor().execute("SELECT content_hash FROM alerts WHERE id = 1").fetchone()
        assert row[0] != "legacy_old_hash_12345"

    # Re-ingesting the exact same alert from a file should now be detected as duplicate (0 inserted)
    sample_file = tmp_path / "reingest.json"
    sample_file.write_text(legacy_payload + "\n", encoding="utf-8")
    inserted = client.ingest_from_file(str(sample_file))
    assert inserted == 0
    assert client.db.count() == 1


def test_database_v2_to_v3_migration(tmp_path):
    """An existing v2 database upgrades to v3, canonicalizes timestamps and adds mitre_tactic_names."""
    db_file = tmp_path / "legacy_v2.db"

    with sqlite3.connect(db_file) as conn:
        conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        conn.execute("INSERT INTO schema_version (version) VALUES (2)")
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_level INTEGER NOT NULL,
                rule_description TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                user TEXT,
                process TEXT,
                mitre_tactics TEXT,
                raw_payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        v2_payload = json.dumps({
            "timestamp": "2026-10-05T10:14:01.120+0000",
            "rule": {
                "id": "5710",
                "level": 5,
                "description": "sshd: login attempt",
                "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]}
            },
            "agent": {"name": "web01"}
        })
        conn.execute(
            "INSERT INTO alerts (content_hash, timestamp, rule_id, rule_level, rule_description, agent_name, raw_payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("v2_hash_abcdef", "2026-10-05T10:14:01.120+0000", "5710", 5, "sshd: login attempt", "web01", v2_payload)
        )
        conn.commit()

    client = WazuhClient(str(db_file))
    assert client.db.get_schema_version() == 3

    with client.db._get_connection() as conn:
        row = conn.cursor().execute("SELECT timestamp, mitre_tactic_names, content_hash FROM alerts WHERE id = 1").fetchone()
        assert row[0].endswith("Z")
        assert "2026-10-05T10:14:01" in row[0]
        assert "Credential Access" in row[1]
        assert row[2] != "v2_hash_abcdef"


def test_ingest_from_indexer_ascending_and_checkpoint(tmp_path):
    """Indexer queries must sort ascending, paginate, and advance checkpoint keyed per URL/index."""
    db_file = tmp_path / "indexer_test.db"
    client = WazuhClient(str(db_file))

    hits_data = {
        "hits": {
            "hits": [
                {
                    "_id": "hit1",
                    "_source": {
                        "timestamp": "2026-10-05T10:00:00.000Z",
                        "rule": {"id": "5710", "level": 5, "description": "Login attempt"},
                        "agent": {"name": "web01"}
                    },
                    "sort": ["2026-10-05T10:00:00.000Z", "hit1"]
                },
                {
                    "_id": "hit2",
                    "_source": {
                        "timestamp": "2026-10-05T10:00:05.000Z",
                        "rule": {"id": "5712", "level": 10, "description": "Brute force"},
                        "agent": {"name": "web01"}
                    },
                    "sort": ["2026-10-05T10:00:05.000Z", "hit2"]
                }
            ]
        }
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(hits_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        count = client.ingest_from_indexer(
            indexer_url="https://mock-indexer:9200",
            index_pattern="wazuh-alerts-*",
            user="admin",
            password="secret_password",
            verify_ssl=False,
            limit=10
        )
        assert count == 2
        assert client.db.count() == 2

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["sort"][0]["timestamp"]["order"] == "asc"

        chk = client.db.get_checkpoint("https://mock-indexer:9200/wazuh-alerts-*")
        assert chk == "2026-10-05T10:00:05.000Z"


def test_ingest_from_indexer_pagination_search_after(tmp_path):
    """When hits exceed page_size, search_after cursor is passed in consecutive page queries."""
    db_file = tmp_path / "pagination_test.db"
    client = WazuhClient(str(db_file))

    page1_data = {
        "hits": {
            "hits": [
                {
                    "_id": "hit1",
                    "_source": {
                        "timestamp": "2026-10-05T10:00:01.000Z",
                        "rule": {"id": "5710", "level": 5, "description": "Alert 1"},
                        "agent": {"name": "web01"}
                    },
                    "sort": ["2026-10-05T10:00:01.000Z", "hit1"]
                }
            ]
        }
    }
    page2_data = {
        "hits": {
            "hits": [
                {
                    "_id": "hit2",
                    "_source": {
                        "timestamp": "2026-10-05T10:00:02.000Z",
                        "rule": {"id": "5710", "level": 5, "description": "Alert 2"},
                        "agent": {"name": "web01"}
                    },
                    "sort": ["2026-10-05T10:00:02.000Z", "hit2"]
                }
            ]
        }
    }

    resp1 = MagicMock()
    resp1.read.return_value = json.dumps(page1_data).encode("utf-8")
    resp1.__enter__.return_value = resp1

    resp2 = MagicMock()
    resp2.read.return_value = json.dumps(page2_data).encode("utf-8")
    resp2.__enter__.return_value = resp2

    with patch("urllib.request.urlopen", side_effect=[resp1, resp2]) as mock_urlopen:
        count = client.ingest_from_indexer(
            indexer_url="https://mock-indexer:9200",
            index_pattern="wazuh-alerts-*",
            user="admin",
            password="secret_password",
            verify_ssl=False,
            limit=2,
            page_size=1
        )
        assert count == 2
        assert client.db.count() == 2
        assert mock_urlopen.call_count == 2

        # Verify page 2 payload included search_after from page 1
        req2 = mock_urlopen.call_args_list[1][0][0]
        body2 = json.loads(req2.data.decode("utf-8"))
        assert body2.get("search_after") == ["2026-10-05T10:00:01.000Z", "hit1"]


def test_fetch_agent_inventory_success_and_auth_error(tmp_path):
    """fetch_agent_inventory retrieves agents list via JWT auth or fails cleanly."""
    client = WazuhClient(str(tmp_path / "client.db"))

    with pytest.raises(ValueError, match="WAZUH_API_PASSWORD required"):
        client.fetch_agent_inventory(user="admin", password="")

    token_resp = MagicMock()
    token_resp.read.return_value = json.dumps({"data": {"token": "mock-token-xyz"}}).encode("utf-8")
    token_resp.__enter__.return_value = token_resp

    agents_resp = MagicMock()
    agents_resp.read.return_value = json.dumps({
        "data": {
            "affected_items": [
                {"id": "001", "name": "web01", "ip": "192.168.1.10", "group": ["web-servers"]},
                {"id": "002", "name": "db01", "ip": "192.168.1.20", "group": ["databases"]}
            ]
        }
    }).encode("utf-8")
    agents_resp.__enter__.return_value = agents_resp

    with patch("urllib.request.urlopen", side_effect=[token_resp, agents_resp]):
        agents = client.fetch_agent_inventory(
            api_url="https://localhost:55000",
            user="wazuh-wui",
            password="test_password",
            verify_ssl=False
        )
        assert len(agents) == 2
        assert agents[0]["name"] == "web01"
        assert agents[1]["name"] == "db01"


def test_ingest_from_file_json_array(tmp_path):
    """Ingestion supports standard JSON arrays as well as line-delimited JSONL."""
    db_file = tmp_path / "array_test.db"
    sample_file = tmp_path / "alerts_array.json"

    data = [
        {
            "timestamp": "2026-10-05T10:00:00.000Z",
            "rule": {"id": "5710", "level": 5, "description": "Alert 1"},
            "agent": {"name": "web01"}
        },
        {
            "timestamp": "2026-10-05T10:00:01.000Z",
            "rule": {"id": "5712", "level": 10, "description": "Alert 2"},
            "agent": {"name": "web01"}
        }
    ]
    sample_file.write_text(json.dumps(data), encoding="utf-8")

    client = WazuhClient(str(db_file))
    count = client.ingest_from_file(str(sample_file))
    assert count == 2
    assert client.db.count() == 2


def test_fetch_agent_inventory_missing_token_raises(tmp_path):
    """fetch_agent_inventory raises ConnectionError if auth succeeded without token."""
    client = WazuhClient(str(tmp_path / "client.db"))

    token_resp = MagicMock()
    token_resp.read.return_value = json.dumps({"data": {}}).encode("utf-8")
    token_resp.__enter__.return_value = token_resp

    with patch("urllib.request.urlopen", return_value=token_resp):
        with pytest.raises(ConnectionError, match="no JWT token returned"):
            client.fetch_agent_inventory(
                api_url="https://localhost:55000",
                user="wazuh-wui",
                password="test_password",
                verify_ssl=False
            )

