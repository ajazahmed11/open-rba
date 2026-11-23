"""
Database schema and storage manager for Open-RBA.
Stores normalized SIEM alerts in a local SQLite database for downstream
heuristic correlation, threat enrichment, and risk scoring.
"""

import hashlib
import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NormalizedAlert:
    """Standardized schema for normalized SIEM alerts across all sources."""
    timestamp: str               # Canonical UTC ISO-8601 string: YYYY-MM-DDTHH:MM:SS.mmmZ
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
    full_log: Optional[str] = None            # Full raw log message string
    mitre_tactic_names: Optional[List[str]] = None # MITRE tactic names (e.g., ["Credential Access"])

    def content_hash(self) -> str:
        """Deterministic SHA-256 hash of identity fields for deduplication.

        Incorporates timestamp, rule, agent, network endpoints, user, and
        full_log or canonical raw_payload to ensure uniqueness.
        """
        if self.full_log:
            log_key = self.full_log
        elif self.raw_payload:
            try:
                parsed = json.loads(self.raw_payload)
                log_key = json.dumps(parsed, sort_keys=True)
            except Exception:
                log_key = self.raw_payload
        else:
            log_key = self.rule_description or ""

        identity = f"{self.timestamp}|{self.rule_id}|{self.agent_name}|{self.src_ip}|{self.dst_ip}|{self.user}|{log_key}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()


CREATE_ALERTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkpoints (
    source TEXT PRIMARY KEY,
    last_timestamp TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    mitre_tactic_names TEXT -- Stored as JSON array string
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
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def init_schema(self) -> None:
        """Initializes tables and indexing schema idempotently with automated migrations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
            has_version_table = cursor.fetchone() is not None

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
            has_alerts_table = cursor.fetchone() is not None

            current_version = 0
            if has_version_table:
                cursor.execute("SELECT MAX(version) FROM schema_version")
                row = cursor.fetchone()
                current_version = int(row[0]) if row and row[0] is not None else 0

            conn.executescript(CREATE_ALERTS_TABLE_SQL)

            if not has_version_table and has_alerts_table:
                self._migrate_v1_to_v2(conn)
                self._migrate_v2_to_v3(conn)
            elif current_version == 1:
                self._migrate_v1_to_v2(conn)
                self._migrate_v2_to_v3(conn)
            elif current_version == 2:
                self._migrate_v2_to_v3(conn)
            else:
                conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (3)")

            conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        """Migrates legacy v1 database to v2 by re-indexing canonical hashes."""
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, rule_id, rule_level, rule_description, "
            "agent_name, src_ip, dst_ip, user, process, mitre_tactics, raw_payload FROM alerts"
        )
        rows = cursor.fetchall()
        seen_hashes = set()
        for row in rows:
            row_id = row[0]
            raw_payload_str = row[11]
            full_log = None
            canonical_payload = raw_payload_str
            if raw_payload_str:
                try:
                    payload_dict = json.loads(raw_payload_str)
                    full_log = payload_dict.get("full_log")
                    canonical_payload = json.dumps(payload_dict, sort_keys=True)
                except Exception:
                    pass

            norm = NormalizedAlert(
                timestamp=row[1],
                rule_id=row[2],
                rule_level=row[3],
                rule_description=row[4],
                agent_name=row[5],
                src_ip=row[6],
                dst_ip=row[7],
                user=row[8],
                process=row[9],
                mitre_tactics=json.loads(row[10]) if row[10] else [],
                raw_payload=canonical_payload,
                full_log=full_log
            )
            new_hash = norm.content_hash()
            if new_hash in seen_hashes:
                cursor.execute("DELETE FROM alerts WHERE id = ?", (row_id,))
            else:
                seen_hashes.add(new_hash)
                cursor.execute(
                    "UPDATE alerts SET content_hash = ?, raw_payload = ? WHERE id = ?",
                    (new_hash, canonical_payload, row_id)
                )

        conn.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (2)")

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection) -> None:
        """Migrates v2 database to v3 by canonicalizing timestamps to UTC ISO-8601 and adding mitre_tactic_names."""
        cursor = conn.cursor()

        # 1. Add mitre_tactic_names column if absent
        cursor.execute("PRAGMA table_info(alerts)")
        cols = {row[1] for row in cursor.fetchall()}
        if "mitre_tactic_names" not in cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic_names TEXT")

        # 2. Canonicalize timestamps and recompute v3 content hashes
        from src.correlation.engine import parse_timestamp
        cursor.execute(
            "SELECT id, timestamp, rule_id, rule_level, rule_description, "
            "agent_name, src_ip, dst_ip, user, process, mitre_tactics, raw_payload FROM alerts"
        )
        rows = cursor.fetchall()
        seen_hashes = set()
        for row in rows:
            row_id = row[0]
            raw_ts = row[1]
            try:
                dt = parse_timestamp(raw_ts)
                canonical_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
            except Exception:
                canonical_ts = raw_ts

            raw_payload_str = row[11]
            full_log = None
            tactic_names = []
            canonical_payload = raw_payload_str
            if raw_payload_str:
                try:
                    payload_dict = json.loads(raw_payload_str)
                    full_log = payload_dict.get("full_log")
                    canonical_payload = json.dumps(payload_dict, sort_keys=True)
                    mitre_block = payload_dict.get("rule", {}).get("mitre", {})
                    if isinstance(mitre_block, dict):
                        raw_t = mitre_block.get("tactic", [])
                        if isinstance(raw_t, list):
                            tactic_names = [str(x) for x in raw_t]
                        elif isinstance(raw_t, str):
                            tactic_names = [raw_t]
                except Exception:
                    pass

            norm = NormalizedAlert(
                timestamp=canonical_ts,
                rule_id=row[2],
                rule_level=row[3],
                rule_description=row[4],
                agent_name=row[5],
                src_ip=row[6],
                dst_ip=row[7],
                user=row[8],
                process=row[9],
                mitre_tactics=json.loads(row[10]) if row[10] else [],
                raw_payload=canonical_payload,
                full_log=full_log,
                mitre_tactic_names=tactic_names
            )
            new_hash = norm.content_hash()
            if new_hash in seen_hashes:
                cursor.execute("DELETE FROM alerts WHERE id = ?", (row_id,))
            else:
                seen_hashes.add(new_hash)
                cursor.execute(
                    "UPDATE alerts SET content_hash = ?, timestamp = ?, raw_payload = ?, mitre_tactic_names = ? WHERE id = ?",
                    (new_hash, canonical_ts, canonical_payload, json.dumps(tactic_names), row_id)
                )

        conn.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (3)")

    def get_schema_version(self) -> int:
        """Returns the current database schema version."""
        sql = "SELECT MAX(version) FROM schema_version"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql)
                row = cursor.fetchone()
                return int(row[0]) if row and row[0] is not None else 1
        except Exception:
            return 1

    def get_checkpoint(self, source: str) -> Optional[str]:
        """Retrieves last recorded timestamp for an ingestion source."""
        sql = "SELECT last_timestamp FROM checkpoints WHERE source = ?"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (source,))
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception:
            return None

    def set_checkpoint(self, source: str, last_timestamp: str) -> None:
        """Saves last recorded timestamp for an ingestion source."""
        sql = """
        INSERT OR REPLACE INTO checkpoints (source, last_timestamp, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (source, last_timestamp))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to record checkpoint for {source}: {e}")

    def _alert_to_row(self, alert: NormalizedAlert) -> tuple:
        """Convert a NormalizedAlert to a tuple for SQL insertion."""
        mitre_json = json.dumps(alert.mitre_tactics) if alert.mitre_tactics else "[]"
        tactic_names_json = json.dumps(alert.mitre_tactic_names) if alert.mitre_tactic_names else "[]"
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
            tactic_names_json,
        )

    def record_dead_letter(self, raw_payload: str, error_reason: str, conn: Optional[sqlite3.Connection] = None) -> None:
        """Stores a malformed or rejected alert in the dead_letter table for auditing."""
        sql = "INSERT INTO dead_letter (raw_payload, error_reason) VALUES (?, ?)"
        try:
            if conn is not None:
                conn.cursor().execute(sql, (raw_payload, error_reason))
            else:
                with self._get_connection() as c:
                    c.cursor().execute(sql, (raw_payload, error_reason))
                    c.commit()
        except Exception as e:
            logger.warning(f"Failed to record dead-letter entry: {e}")

    def insert_alert(self, alert: NormalizedAlert) -> int:
        """Inserts a single normalized alert, skipping duplicates on content_hash.
        Returns the row ID (0 if skipped as duplicate)."""
        sql = """
        INSERT INTO alerts (
            content_hash, timestamp, rule_id, rule_level, rule_description,
            agent_name, src_ip, dst_ip, user, process,
            mitre_tactics, raw_payload, mitre_tactic_names
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(content_hash) DO NOTHING
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, self._alert_to_row(alert))
                conn.commit()
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
            mitre_tactics, raw_payload, mitre_tactic_names
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    self.record_dead_letter(alert.raw_payload or "", f"IntegrityError: {e}", conn=conn)
                except Exception as e:
                    self.record_dead_letter(alert.raw_payload or "", f"BatchInsertError: {e}", conn=conn)
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
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d.get("mitre_tactics") else []
                d["mitre_tactic_names"] = json.loads(d["mitre_tactic_names"]) if d.get("mitre_tactic_names") else []
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
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d.get("mitre_tactics") else []
                d["mitre_tactic_names"] = json.loads(d["mitre_tactic_names"]) if d.get("mitre_tactic_names") else []
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
                d["mitre_tactics"] = json.loads(d["mitre_tactics"]) if d.get("mitre_tactics") else []
                d["mitre_tactic_names"] = json.loads(d["mitre_tactic_names"]) if d.get("mitre_tactic_names") else []
                results.append(d)
            return results

    def count(self) -> int:
        """Returns total alert records currently stored."""
        sql = "SELECT COUNT(*) FROM alerts"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            return cursor.fetchone()[0]
