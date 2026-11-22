"""
Database schema and storage manager for Open-RBA.
Stores normalized SIEM alerts in a local SQLite database for downstream
heuristic correlation, threat enrichment, and risk scoring.
"""

import hashlib
import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class NormalizedAlert:
    """Standardized schema for normalized SIEM alerts across all sources."""
    timestamp: str               # ISO 8601 string: YYYY-MM-DDTHH:MM:SS
    rule_id: str                 # Wazuh rule ID (e.g., "5712", "100100")
    rule_level: int              # Wazuh static rule level (1 to 15)
    rule_description: str        # Human-readable description
    agent_name: str              # Hostname / agent (e.g., "web01", "db01")
    src_ip: Optional[str] = None # Attacker / source IP address
    dst_ip: Optional[str] = None # Destination IP address
    user: Optional[str] = None   # Target username (e.g., "root", "ubuntu")
    process: Optional[str] = None# Process or executable name
    mitre_tactics: Optional[List[str]] = None # MITRE technique IDs (e.g., ["T1110", "T1078"])
    raw_payload: Optional[str] = None         # Original raw JSON for forensic auditing

    def content_hash(self) -> str:
        """Deterministic SHA-256 hash of identity fields for deduplication.

        Two alerts are considered duplicates if they share the same timestamp,
        rule_id, agent_name, src_ip, dst_ip, and user — i.e., the same event
        observed at the same moment on the same host from the same source.
        """
        identity = f"{self.timestamp}|{self.rule_id}|{self.agent_name}|{self.src_ip}|{self.dst_ip}|{self.user}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()


CREATE_ALERTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
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
    mitre_tactics TEXT, -- Stored as JSON array string
    raw_payload TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dead_letter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_payload TEXT,
    error_reason TEXT,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts (agent_name);
"""


class AlertDatabase:
    """Manages SQLite operations for normalized alerts."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        """Initializes tables and indexing schema idempotently."""
        with self._get_connection() as conn:
            conn.executescript(CREATE_ALERTS_TABLE_SQL)

    def _alert_to_row(self, alert: NormalizedAlert) -> tuple:
        """Convert a NormalizedAlert to a tuple for SQL insertion."""
        mitre_json = json.dumps(alert.mitre_tactics) if alert.mitre_tactics else "[]"
        return (
            alert.content_hash(),
            alert.timestamp,
            alert.rule_id,
            alert.rule_level,
            alert.rule_description,
            alert.agent_name,
            alert.src_ip,
            alert.dst_ip,
            alert.user,
            alert.process,
            mitre_json,
            alert.raw_payload,
        )

    def record_dead_letter(self, raw_payload: str, error_reason: str) -> None:
        """Stores a malformed or rejected alert in the dead_letter table for auditing."""
        sql = "INSERT INTO dead_letter (raw_payload, error_reason) VALUES (?, ?)"
        try:
            with self._get_connection() as conn:
                conn.cursor().execute(sql, (raw_payload, error_reason))
        except Exception:
            pass

    def insert_alert(self, alert: NormalizedAlert) -> int:
        """Inserts a single normalized alert, skipping duplicates on content_hash.
        Returns the row ID (0 if skipped as duplicate)."""
        sql = """
        INSERT INTO alerts (
            content_hash, timestamp, rule_id, rule_level, rule_description,
            agent_name, src_ip, dst_ip, user, process,
            mitre_tactics, raw_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(content_hash) DO NOTHING
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, self._alert_to_row(alert))
                return cursor.lastrowid if cursor.rowcount > 0 else 0
        except sqlite3.IntegrityError as e:
            self.record_dead_letter(alert.raw_payload or "", f"IntegrityError: {e}")
            return 0
        except Exception as e:
            self.record_dead_letter(alert.raw_payload or "", f"InsertError: {e}")
            return 0

    def insert_batch(self, alerts: List[NormalizedAlert]) -> int:
        """Batch inserts normalized alerts within a single transaction.
        Skips duplicates on content_hash conflict. Returns count of newly inserted rows."""
        if not alerts:
            return 0
        sql = """
        INSERT INTO alerts (
            content_hash, timestamp, rule_id, rule_level, rule_description,
            agent_name, src_ip, dst_ip, user, process,
            mitre_tactics, raw_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(content_hash) DO NOTHING
        """
        inserted_count = 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for alert in alerts:
                try:
                    cursor.execute(sql, self._alert_to_row(alert))
                    if cursor.rowcount > 0:
                        inserted_count += 1
                except sqlite3.IntegrityError as e:
                    self.record_dead_letter(alert.raw_payload or "", f"IntegrityError: {e}")
                except Exception as e:
                    self.record_dead_letter(alert.raw_payload or "", f"BatchInsertError: {e}")
            conn.commit()
        return inserted_count

    def fetch_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves the most recent alerts ordered by timestamp descending."""
        sql = "SELECT * FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (limit,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d["mitre_tactics"] else []
                results.append(d)
            return results

    def fetch_time_range(self, start: str, end: str) -> List[Dict[str, Any]]:
        """Retrieves alerts within a time range [start, end] inclusive.
        Timestamps are compared lexicographically (ISO 8601 sorts correctly)."""
        sql = """
        SELECT * FROM alerts
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC, id ASC
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (start, end))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d["mitre_tactics"] else []
                results.append(d)
            return results

    def fetch_all(self) -> List[Dict[str, Any]]:
        """Retrieves all alerts ordered by timestamp ascending."""
        sql = "SELECT * FROM alerts ORDER BY timestamp ASC, id ASC"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d["mitre_tactics"] else []
                results.append(d)
            return results

    def count(self) -> int:
        """Returns total alert records currently stored."""
        sql = "SELECT COUNT(*) FROM alerts"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            return cursor.fetchone()[0]
