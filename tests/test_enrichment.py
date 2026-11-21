"""
Unit tests for Open-RBA Threat Intelligence Enrichment Module (Module 3).
Tests private IP detection, exponential decay calculation, local caching,
and mock lookup mechanisms.
"""

import pytest
import math
from src.enrichment.client import (
    is_private_or_local_ip,
    calculate_temporal_decay,
    CTICache,
    ThreatIntelClient,
    CTIReport,
)


class TestPrivateIPDetection:
    def test_rfc1918_private_ips(self):
        assert is_private_or_local_ip("192.168.1.10") is True
        assert is_private_or_local_ip("10.89.0.8") is True
        assert is_private_or_local_ip("172.16.5.20") is True

    def test_loopback_and_special(self):
        assert is_private_or_local_ip("127.0.0.1") is True
        assert is_private_or_local_ip("::1") is True
        assert is_private_or_local_ip("LOCAL") is True
        assert is_private_or_local_ip("—") is True
        assert is_private_or_local_ip(None) is True

    def test_public_ips(self):
        assert is_private_or_local_ip("203.0.113.45") is False
        assert is_private_or_local_ip("198.51.100.99") is False
        assert is_private_or_local_ip("8.8.8.8") is False


class TestTemporalDecayMath:
    def test_zero_age_no_decay(self):
        score = 0.8
        decayed = calculate_temporal_decay(score, age_days=0.0, lambda_factor=0.05)
        assert decayed == score

    def test_half_life_decay(self):
        # Half life with lambda=0.05 is ln(2)/0.05 = ~13.86 days
        half_life_days = math.log(2) / 0.05
        score = 1.0
        decayed = calculate_temporal_decay(score, age_days=half_life_days, lambda_factor=0.05)
        assert abs(decayed - 0.5) < 0.01

    def test_max_age_cutoff(self):
        # Beyond max_age_days (90), indicator decays to 0.0
        decayed = calculate_temporal_decay(0.9, age_days=95.0, lambda_factor=0.05, max_age_days=90)
        assert decayed == 0.0

    def test_negative_age_handled_gracefully(self):
        # If timestamp clock skew causes negative age, delta_t clamped to 0
        decayed = calculate_temporal_decay(0.7, age_days=-2.0, lambda_factor=0.05)
        assert decayed == 0.7


class TestCTICache:
    def test_cache_put_and_get(self, tmp_path):
        db_file = tmp_path / "test_cti.db"
        cache = CTICache(str(db_file))

        assert cache.get("203.0.113.45") is None

        cache.put(
            ip="203.0.113.45",
            raw_score=85.0,
            normalized_score=0.85,
            last_reported_at="2026-10-01T12:00:00Z",
            source="abuseipdb"
        )

        entry = cache.get("203.0.113.45")
        assert entry is not None
        assert entry["ip"] == "203.0.113.45"
        assert entry["raw_score"] == 85.0
        assert entry["normalized_score"] == 0.85


class TestThreatIntelClient:
    def test_lookup_private_ip_returns_zero(self, tmp_path):
        client = ThreatIntelClient(db_path=str(tmp_path / "cti.db"))
        report = client.lookup_ip("192.168.1.10")
        assert report.is_private is True
        assert report.normalized_score == 0.0
        assert report.decayed_score == 0.0

    def test_lookup_mock_indicator_with_decay(self, tmp_path):
        mock_data = {
            "203.0.113.45": {
                "score": 100.0,
                "last_reported_at": "2026-10-01T00:00:00Z"
            }
        }
        client = ThreatIntelClient(
            db_path=str(tmp_path / "cti.db"),
            mock_data=mock_data,
            lambda_factor=0.05
        )

        # Alert happening ~4 days after indicator report
        report = client.lookup_ip("203.0.113.45", alert_timestamp="2026-10-05T00:00:00Z")
        assert report.raw_score == 100.0
        assert report.normalized_score == 1.0
        assert 0.75 < report.decayed_score < 0.85  # exp(-0.05 * 4) ~= 0.818
        assert report.indicator_age_days == 4.0
        assert report.source == "mock"
