"""
Threat Intelligence Enrichment Client for Open-RBA (Module 3).

Queries threat intelligence sources (AbuseIPDB, AlienVault OTX) with local
SQLite caching, TTL enforcement, and exponential temporal decay:
    CTI_decayed = CTI_normalized * exp(-lambda * delta_t)

Stale indicators decay dynamically, ensuring transient scanner reputation
does not permanently inflate incident risk.
"""

import os
import math
import json
import sqlite3
import logging
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CTIReport:
    """Standardized threat intelligence report for an indicator."""
    ip: str
    raw_score: float             # Abuse confidence score (0 to 100)
    normalized_score: float      # Scale mapped to [0.0, 1.0]
    decayed_score: float         # After applying exp(-lambda * delta_t) in [0.0, 1.0]
    indicator_age_days: float    # Delta t in days between report and alert
    is_private: bool             # RFC 1918 / loopback / local IP flag
    source: str                  # "abuseipdb", "cache", "mock", or "local"


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_or_local_ip(ip_str: Optional[str]) -> bool:
    """Returns True if IP is empty, loopback, or in RFC 1918 private subnets."""
    if not ip_str or ip_str in ("LOCAL", "N/A", "—"):
        return True
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return True


def calculate_temporal_decay(
    normalized_score: float,
    age_days: float,
    lambda_factor: float = 0.05,
    max_age_days: int = 90
) -> float:
    """
    Applies exponential decay: score * exp(-lambda * delta_t).

    Args:
        normalized_score: Base indicator score in [0.0, 1.0].
        age_days: Age of the indicator in days (delta_t >= 0).
        lambda_factor: Half-life decay constant (lambda = 0.05 -> ~13.86 days half-life).
        max_age_days: Beyond this age, indicator weight drops to minimum / zero.

    Returns:
        Decayed score bounded in [0.0, 1.0].
    """
    if normalized_score <= 0.0:
        return 0.0

    delta_t = max(0.0, float(age_days))
    if delta_t > max_age_days:
        return 0.0

    decay_factor = math.exp(-lambda_factor * delta_t)
    decayed = normalized_score * decay_factor
    return max(0.0, min(1.0, round(decayed, 4)))


class CTICache:
    """Local SQLite cache manager for threat intelligence lookups."""

    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS cti_cache (
        ip TEXT PRIMARY KEY,
        raw_score REAL NOT NULL,
        normalized_score REAL NOT NULL,
        last_reported_at TEXT NOT NULL,
        cached_at TEXT NOT NULL,
        source TEXT NOT NULL,
        raw_payload TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_cti_cached_at ON cti_cache(cached_at);
    """

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(self.CREATE_TABLE_SQL)

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM cti_cache WHERE ip = ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (ip,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def put(
        self,
        ip: str,
        raw_score: float,
        normalized_score: float,
        last_reported_at: str,
        source: str = "abuseipdb",
        raw_payload: Optional[str] = None
    ) -> None:
        sql = """
        INSERT OR REPLACE INTO cti_cache (
            ip, raw_score, normalized_score, last_reported_at, cached_at, source, raw_payload
        ) VALUES (?, ?, ?, ?, datetime('now'), ?, ?)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (ip, raw_score, normalized_score, last_reported_at, source, raw_payload))


class ThreatIntelClient:
    """
    Enriches indicators with threat reputation and exponential decay.
    Supports AbuseIPDB API, persistent SQLite caching with TTL, and offline datasets.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        db_path: str = "data/alerts.db",
        lambda_factor: float = 0.05,
        max_age_days: int = 90,
        cache_ttl_days: int = 7,
        mock_data: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.cache = CTICache(db_path)
        self.lambda_factor = lambda_factor
        self.max_age_days = max_age_days
        self.cache_ttl_days = cache_ttl_days
        self.mock_data = mock_data or {}

    def lookup_ip(self, ip: Optional[str], alert_timestamp: Optional[str] = None) -> CTIReport:
        """
        Looks up an IP address, applies temporal decay relative to alert_timestamp,
        and returns a normalized CTIReport.
        """
        if not ip or is_private_or_local_ip(ip):
            return CTIReport(
                ip=ip or "LOCAL",
                raw_score=0.0,
                normalized_score=0.0,
                decayed_score=0.0,
                indicator_age_days=0.0,
                is_private=True,
                source="local"
            )

        ip_clean = ip.strip()

        # Check mock database first (for reproducible testing / offline research)
        if ip_clean in self.mock_data:
            mock_entry = self.mock_data[ip_clean]
            raw_score = float(mock_entry.get("score", 0.0))
            norm_score = max(0.0, min(1.0, raw_score / 100.0))
            last_reported = mock_entry.get("last_reported_at", "2026-10-01T00:00:00Z")
            age_days = self._compute_age_days(last_reported, alert_timestamp)
            decayed = calculate_temporal_decay(norm_score, age_days, self.lambda_factor, self.max_age_days)
            return CTIReport(
                ip=ip_clean,
                raw_score=raw_score,
                normalized_score=norm_score,
                decayed_score=decayed,
                indicator_age_days=age_days,
                is_private=False,
                source="mock"
            )

        # Check local SQLite cache with TTL expiration
        cached = self.cache.get(ip_clean)
        if cached:
            cached_at_str = cached.get("cached_at", "")
            is_valid = True
            if cached_at_str:
                try:
                    cached_dt = datetime.fromisoformat(cached_at_str.replace("Z", "+00:00"))
                    if cached_dt.tzinfo is None:
                        cached_dt = cached_dt.replace(tzinfo=timezone.utc)
                    cache_age_days = (datetime.now(timezone.utc) - cached_dt).total_seconds() / 86400.0
                    if cache_age_days > self.cache_ttl_days:
                        is_valid = False
                except Exception:
                    is_valid = True

            if is_valid:
                norm_score = cached["normalized_score"]
                raw_score = cached["raw_score"]
                age_days = self._compute_age_days(cached["last_reported_at"], alert_timestamp)
                decayed = calculate_temporal_decay(norm_score, age_days, self.lambda_factor, self.max_age_days)
                return CTIReport(
                    ip=ip_clean,
                    raw_score=raw_score,
                    normalized_score=norm_score,
                    decayed_score=decayed,
                    indicator_age_days=age_days,
                    is_private=False,
                    source="cache"
                )

        # Live API query if API key is present
        if self.api_key and self.api_key != "your_abuseipdb_api_key_here":
            api_res, query_status = self._query_abuseipdb(ip_clean)
            if api_res:
                raw_score = float(api_res.get("abuseConfidenceScore", 0.0))
                norm_score = max(0.0, min(1.0, raw_score / 100.0))
                last_reported = api_res.get("lastReportedAt") or datetime.now(timezone.utc).isoformat()
                self.cache.put(ip_clean, raw_score, norm_score, last_reported, "abuseipdb", json.dumps(api_res))
                age_days = self._compute_age_days(last_reported, alert_timestamp)
                decayed = calculate_temporal_decay(norm_score, age_days, self.lambda_factor, self.max_age_days)
                return CTIReport(
                    ip=ip_clean,
                    raw_score=raw_score,
                    normalized_score=norm_score,
                    decayed_score=decayed,
                    indicator_age_days=age_days,
                    is_private=False,
                    source="abuseipdb"
                )
            elif query_status in ("rate_limited", "error"):
                # If cached entry exists (even expired), serve stale entry on live failure
                if cached:
                    norm_score = cached["normalized_score"]
                    raw_score = cached["raw_score"]
                    age_days = self._compute_age_days(cached["last_reported_at"], alert_timestamp)
                    decayed = calculate_temporal_decay(norm_score, age_days, self.lambda_factor, self.max_age_days)
                    return CTIReport(
                        ip=ip_clean,
                        raw_score=raw_score,
                        normalized_score=norm_score,
                        decayed_score=decayed,
                        indicator_age_days=age_days,
                        is_private=False,
                        source="cache-stale"
                    )
                # Differentiate lookup failure from a clean IP so weight renormalization applies
                return CTIReport(
                    ip=ip_clean,
                    raw_score=0.0,
                    normalized_score=0.0,
                    decayed_score=0.0,
                    indicator_age_days=0.0,
                    is_private=False,
                    source="error"
                )

        # If API is not configured or offline, but an expired cache record exists, serve it as stale
        if cached:
            norm_score = cached["normalized_score"]
            raw_score = cached["raw_score"]
            age_days = self._compute_age_days(cached["last_reported_at"], alert_timestamp)
            decayed = calculate_temporal_decay(norm_score, age_days, self.lambda_factor, self.max_age_days)
            return CTIReport(
                ip=ip_clean,
                raw_score=raw_score,
                normalized_score=norm_score,
                decayed_score=decayed,
                indicator_age_days=age_days,
                is_private=False,
                source="cache-stale"
            )

        # Graceful fallback when offline / no key
        return CTIReport(
            ip=ip_clean,
            raw_score=0.0,
            normalized_score=0.0,
            decayed_score=0.0,
            indicator_age_days=0.0,
            is_private=False,
            source="unknown"
        )

    def _query_abuseipdb(self, ip: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Queries AbuseIPDB REST API v2, returning data and status."""
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data"), "ok"
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning(f"AbuseIPDB rate limit exceeded (HTTP 429) for IP {ip}")
                return None, "rate_limited"
            logger.warning(f"AbuseIPDB HTTP error {e.code} for IP {ip}: {e}")
            return None, "error"
        except Exception as e:
            logger.warning(f"AbuseIPDB request failed for IP {ip}: {e}")
            return None, "error"

    def _compute_age_days(self, reported_at_iso: str, alert_ts_iso: Optional[str]) -> float:
        """Calculates delta_t (in days) between indicator report and alert occurrence."""
        try:
            # Parse reported date
            rep_clean = reported_at_iso.replace("Z", "+00:00")
            rep_dt = datetime.fromisoformat(rep_clean)

            if alert_ts_iso:
                import re
                al_clean = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', alert_ts_iso).replace("Z", "+00:00")
                al_dt = datetime.fromisoformat(al_clean)
            else:
                al_dt = datetime.now(timezone.utc)

            # Ensure timezone compatibility
            if rep_dt.tzinfo is None:
                rep_dt = rep_dt.replace(tzinfo=timezone.utc)
            if al_dt.tzinfo is None:
                al_dt = al_dt.replace(tzinfo=timezone.utc)

            delta_sec = (al_dt - rep_dt).total_seconds()
            return max(0.0, round(delta_sec / 86400.0, 2))
        except Exception:
            return 0.0
