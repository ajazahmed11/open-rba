"""
Unit tests for Open-RBA Temporal Correlation Engine (Module 2).
Tests grouping logic, session windows, deduplication, edge cases,
and the ≥70% alert reduction claim against realistic attack data.
"""

import pytest
from src.correlation.engine import (
    correlate_alerts,
    alert_reduction_ratio,
    extract_technique_family,
    parse_timestamp,
    CorrelatedIncident,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _alert(id, timestamp, rule_id, rule_level, description, agent_name,
           src_ip=None, mitre_tactics=None):
    """Create an alert dict matching the shape returned by AlertDatabase."""
    return {
        "id": id,
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": description,
        "agent_name": agent_name,
        "src_ip": src_ip,
        "dst_ip": None,
        "user": None,
        "process": None,
        "mitre_tactics": mitre_tactics or [],
    }


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_z_suffix(self):
        dt = parse_timestamp("2026-10-05T10:14:15.000Z")
        assert dt.hour == 10 and dt.minute == 14

    def test_offset_without_colon(self):
        dt = parse_timestamp("2026-10-05T10:14:01.120+0000")
        assert dt.hour == 10

    def test_offset_with_colon(self):
        dt = parse_timestamp("2026-10-05T10:14:01.120+00:00")
        assert dt.hour == 10

    def test_positive_offset(self):
        dt = parse_timestamp("2026-10-05T15:44:01.000+0530")
        assert dt.hour == 10 and dt.minute == 14  # Normalized to UTC!

    def test_naive_timestamp_normalized_to_utc(self):
        dt = parse_timestamp("2026-10-05T10:14:01")
        assert dt.tzinfo is not None
        assert dt.hour == 10

    def test_empty_or_none_timestamp_fallback(self):
        with pytest.raises(ValueError):
            parse_timestamp("")
        with pytest.raises(ValueError):
            parse_timestamp(None)

    def test_mixed_naive_and_aware_correlation(self):
        # Alerts with naive and aware timestamps should not crash with TypeError
        a1 = _alert(1, "2026-10-05T10:14:01", "5710", 5, "SSH failed", "web01", "203.0.113.45")
        a2 = _alert(2, "2026-10-05T10:14:10Z", "5710", 5, "SSH failed", "web01", "203.0.113.45")
        incidents = correlate_alerts([a1, a2], window_seconds=120)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 2


class TestExtractTechniqueFamily:
    def test_sub_technique(self):
        assert extract_technique_family(["T1110.001"], "5710") == "T1110"

    def test_top_level(self):
        assert extract_technique_family(["T1190"], "100130") == "T1190"

    def test_no_mitre_falls_back_to_rule(self):
        assert extract_technique_family([], "5710") == "rule:5710"

    def test_multiple_techniques_uses_first(self):
        assert extract_technique_family(["T1078.001", "T1110"], "5712") == "T1078"


# ---------------------------------------------------------------------------
# Core correlation tests
# ---------------------------------------------------------------------------

class TestCorrelateAlerts:
    def test_empty_input(self):
        assert correlate_alerts([]) == []

    def test_single_alert(self):
        alerts = [_alert(1, "2026-10-05T10:00:00Z", "5712", 10, "Brute force", "web01",
                         src_ip="1.2.3.4", mitre_tactics=["T1110.001"])]
        result = correlate_alerts(alerts)
        assert len(result) == 1
        inc = result[0]
        assert inc.alert_count == 1
        assert inc.src_ip == "1.2.3.4"
        assert inc.agent_name == "web01"
        assert inc.technique_family == "T1110"

    def test_brute_force_burst_collapses(self):
        """4 SSH alerts from same src/host/technique within seconds → 1 incident."""
        alerts = [
            _alert(1, "2026-10-05T10:14:01.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:14:03.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(3, "2026-10-05T10:14:05.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(4, "2026-10-05T10:14:07.000Z", "5712", 10, "Brute force", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
        ]
        result = correlate_alerts(alerts)
        assert len(result) == 1
        inc = result[0]
        assert inc.alert_count == 4
        assert inc.max_severity == 10  # escalated to brute-force level
        assert inc.alert_ids == [1, 2, 3, 4]
        assert set(inc.rule_ids) == {"5710", "5712"}
        assert inc.technique_family == "T1110"

    def test_different_techniques_not_merged(self):
        """SSH brute force + web traversal from same IP → 2 separate incidents."""
        alerts = [
            _alert(1, "2026-10-05T10:14:01.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:14:15.000Z", "100130", 10, "Directory traversal", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1190"]),
        ]
        result = correlate_alerts(alerts)
        assert len(result) == 2
        families = {inc.technique_family for inc in result}
        assert families == {"T1110", "T1190"}

    def test_no_src_ip_groups_as_local(self):
        """Host-local events (FIM, etc.) with no source IP form their own group."""
        alerts = [
            _alert(1, "2026-10-05T10:14:30.000Z", "100100", 12, "Sudoers modified", "web01",
                   mitre_tactics=["T1548.003"]),
        ]
        result = correlate_alerts(alerts)
        assert len(result) == 1
        inc = result[0]
        assert inc.src_ip is None
        assert "LOCAL" in inc.group_key

    def test_different_hosts_not_merged(self):
        """Same attacker hitting web01 and db01 → 2 separate incidents."""
        alerts = [
            _alert(1, "2026-10-05T10:14:01.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:14:03.000Z", "5710", 5, "Failed login", "db01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
        ]
        result = correlate_alerts(alerts)
        assert len(result) == 2
        hosts = {inc.agent_name for inc in result}
        assert hosts == {"web01", "db01"}

    def test_window_expiry_splits_clusters(self):
        """Same attacker, same technique, but 5-minute gap → 2 incidents."""
        alerts = [
            _alert(1, "2026-10-05T10:00:00.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:00:02.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            # 5-minute gap
            _alert(3, "2026-10-05T10:05:00.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            _alert(4, "2026-10-05T10:05:02.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
        ]
        result = correlate_alerts(alerts, window_seconds=120)
        assert len(result) == 2
        assert result[0].alert_count == 2
        assert result[1].alert_count == 2

    def test_session_window_extends_continuously(self):
        """Alerts 30s apart spanning 10 minutes → 1 incident (window keeps extending)."""
        alerts = [
            _alert(i, f"2026-10-05T10:{i // 2:02d}:{(i % 2) * 30:02d}.000Z",
                   "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"])
            for i in range(1, 21)  # 20 alerts, 30s apart = 10 minutes total
        ]
        result = correlate_alerts(alerts, window_seconds=120)
        assert len(result) == 1
        assert result[0].alert_count == 20

    def test_sorted_by_severity_descending(self):
        """Output should be ordered with most critical incidents first."""
        alerts = [
            _alert(1, "2026-10-05T10:00:00.000Z", "5710", 5, "Low", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110"]),
            _alert(2, "2026-10-05T10:00:00.000Z", "100100", 12, "High", "web01",
                   mitre_tactics=["T1548.003"]),
            _alert(3, "2026-10-05T10:00:00.000Z", "100131", 6, "Medium", "db01",
                   src_ip="5.6.7.8", mitre_tactics=["T1046"]),
        ]
        result = correlate_alerts(alerts)
        severities = [inc.max_severity for inc in result]
        assert severities == sorted(severities, reverse=True)

    def test_max_severity_propagated_from_escalation(self):
        """When a burst contains a high-severity escalation, the incident gets that level."""
        alerts = [
            _alert(1, "2026-10-05T10:00:00.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:00:01.000Z", "5710", 5, "Failed login", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
            _alert(3, "2026-10-05T10:00:02.000Z", "5712", 10, "Brute force detected", "web01",
                   src_ip="1.2.3.4", mitre_tactics=["T1110.001"]),
        ]
        result = correlate_alerts(alerts)
        assert len(result) == 1
        assert result[0].max_severity == 10
        assert result[0].representative_description == "Brute force detected"


class TestFullSampleData:
    """Test against the actual 8-alert sample dataset structure."""

    @pytest.fixture
    def sample_alerts(self):
        """Reproduce the 8 alerts from data/sample_alerts.json."""
        return [
            _alert(1, "2026-10-05T10:14:01.120+0000", "5710", 5,
                   "sshd: Attempt to login using a non-existent user", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(2, "2026-10-05T10:14:03.240+0000", "5710", 5,
                   "sshd: Attempt to login using a non-existent user", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(3, "2026-10-05T10:14:05.350+0000", "5710", 5,
                   "sshd: Attempt to login using a non-existent user", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(4, "2026-10-05T10:14:07.410+0000", "5712", 10,
                   "sshd: brute force trying to get access to the system.", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1110.001"]),
            _alert(5, "2026-10-05T10:14:15.890+0000", "100130", 10,
                   "Snort IDS: Web Application Attack (Directory Traversal)", "web01",
                   src_ip="203.0.113.45", mitre_tactics=["T1190"]),
            _alert(6, "2026-10-05T10:14:30.500+0000", "100100", 12,
                   "FIM: Sudoers file was modified (T1548.003)", "web01",
                   mitre_tactics=["T1548.003"]),
            _alert(7, "2026-10-05T10:15:10.100+0000", "100131", 6,
                   "Snort IDS: Network Reconnaissance (Nmap SYN scan)", "db01",
                   src_ip="198.51.100.99", mitre_tactics=["T1046"]),
            _alert(8, "2026-10-05T10:15:20.220+0000", "5710", 5,
                   "sshd: Attempt to login using a non-existent user", "db01",
                   src_ip="198.51.100.99", mitre_tactics=["T1110.001"]),
        ]

    def test_produces_correct_incident_count(self, sample_alerts):
        """8 alerts should produce 5 incidents:
        1. SSH brute force burst on web01 (alerts 1-4, same src+technique)
        2. Web traversal on web01 (alert 5, different technique)
        3. FIM sudoers on web01 (alert 6, local event, no src_ip)
        4. Nmap recon on db01 (alert 7)
        5. SSH attempt on db01 (alert 8, different technique from #7)
        """
        result = correlate_alerts(sample_alerts)
        assert len(result) == 5

    def test_brute_force_burst_is_collapsed(self, sample_alerts):
        """The 4 SSH brute-force alerts (1-4) must become 1 incident."""
        result = correlate_alerts(sample_alerts)
        brute_force = [inc for inc in result if inc.technique_family == "T1110"
                       and inc.agent_name == "web01"]
        assert len(brute_force) == 1
        assert brute_force[0].alert_count == 4
        assert brute_force[0].max_severity == 10

    def test_fim_alert_not_merged_with_network_attacks(self, sample_alerts):
        """The FIM/sudoers alert (no src_ip) must be its own incident."""
        result = correlate_alerts(sample_alerts)
        fim = [inc for inc in result if inc.technique_family == "T1548"]
        assert len(fim) == 1
        assert fim[0].src_ip is None
        assert fim[0].max_severity == 12

    def test_most_critical_incident_first(self, sample_alerts):
        """FIM (severity 12) should be ranked #1."""
        result = correlate_alerts(sample_alerts)
        assert result[0].max_severity == 12
        assert result[0].technique_family == "T1548"


class TestRealisticBruteForce:
    """Prove the ≥70% alert reduction claim with realistic attack volumes."""

    def test_hydra_attack_reduction(self):
        """Simulate a realistic Hydra brute-force attack:
        50 failed-login alerts + 1 threshold alert from same attacker,
        plus 2 recon alerts on a second host and 1 FIM alert.
        Total: 54 alerts → expect ~4 incidents = ~93% reduction.
        """
        alerts = []
        # 50 rapid-fire SSH failed logins (1 per second)
        for i in range(50):
            alerts.append(_alert(
                i + 1, f"2026-10-05T10:00:{i:02d}.000Z",
                "5710", 5, "Failed login", "web01",
                src_ip="203.0.113.45", mitre_tactics=["T1110.001"]
            ))
        # Brute-force threshold alert
        alerts.append(_alert(
            51, "2026-10-05T10:00:50.000Z",
            "5712", 10, "Brute force detected", "web01",
            src_ip="203.0.113.45", mitre_tactics=["T1110.001"]
        ))
        # Nmap recon on db01 (different host)
        alerts.append(_alert(
            52, "2026-10-05T10:01:00.000Z",
            "100131", 6, "Nmap SYN scan", "db01",
            src_ip="198.51.100.99", mitre_tactics=["T1046"]
        ))
        alerts.append(_alert(
            53, "2026-10-05T10:01:05.000Z",
            "100131", 6, "Nmap SYN scan", "db01",
            src_ip="198.51.100.99", mitre_tactics=["T1046"]
        ))
        # FIM alert on web01 (local, no src_ip)
        alerts.append(_alert(
            54, "2026-10-05T10:01:10.000Z",
            "100100", 12, "Sudoers modified", "web01",
            mitre_tactics=["T1548.003"]
        ))

        result = correlate_alerts(alerts)
        reduction = alert_reduction_ratio(len(alerts), len(result))

        assert len(result) == 3  # brute force, recon, FIM
        assert reduction >= 0.70, f"Reduction {reduction:.1%} below 70% target"
        assert reduction > 0.90, f"Expected >90% reduction, got {reduction:.1%}"

        # Verify the brute-force burst was properly collapsed
        bf = [inc for inc in result if inc.technique_family == "T1110"]
        assert len(bf) == 1
        assert bf[0].alert_count == 51  # 50 failed + 1 threshold


class TestAlertReductionRatio:
    def test_no_alerts(self):
        assert alert_reduction_ratio(0, 0) == 0.0

    def test_no_reduction(self):
        assert alert_reduction_ratio(5, 5) == 0.0

    def test_full_reduction(self):
        assert alert_reduction_ratio(100, 1) == 0.99

    def test_typical_reduction(self):
        ratio = alert_reduction_ratio(50, 3)
        assert 0.93 < ratio < 0.95
