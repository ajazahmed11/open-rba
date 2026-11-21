"""
Unit tests for Open-RBA MITRE ATT&CK Mapping Module (Module 4).
Tests technique-to-tactic resolution, tactical kill-chain stage depth,
and behavioral heuristic fallbacks.
"""

import pytest
from src.attck.mapper import ATTACKMapper, ATTACKProfile


class TestATTACKMapper:
    @pytest.fixture
    def mapper(self):
        return ATTACKMapper()

    def test_explicit_technique_resolution(self, mapper):
        # T1110 -> Credential Access (Stage 6)
        prof = mapper.evaluate_incident(techniques=["T1110.001"])
        assert prof.primary_technique == "T1110"
        assert prof.primary_tactic == "Credential Access"
        assert prof.tactic_id == "TA0006"
        assert prof.stage_depth == 6
        assert prof.normalized_depth == 0.6
        assert prof.inferred is False

    def test_initial_access_technique(self, mapper):
        # T1190 -> Initial Access (Stage 2)
        prof = mapper.evaluate_incident(techniques=["T1190"])
        assert prof.primary_technique == "T1190"
        assert prof.primary_tactic == "Initial Access"
        assert prof.stage_depth == 2
        assert prof.normalized_depth == 0.2

    def test_privilege_escalation_technique(self, mapper):
        # T1548 -> Privilege Escalation (Stage 5)
        prof = mapper.evaluate_incident(techniques=["T1548.003"])
        assert prof.primary_technique == "T1548"
        assert prof.primary_tactic == "Privilege Escalation"
        assert prof.stage_depth == 5
        assert prof.normalized_depth == 0.5

    def test_heuristic_fallback_brute_force(self, mapper):
        prof = mapper.evaluate_incident(
            techniques=[],
            rule_description="sshd: brute force attack detected",
            rule_id="5712"
        )
        assert prof.primary_technique == "T1110"
        assert prof.primary_tactic == "Credential Access"
        assert prof.inferred is True

    def test_heuristic_fallback_sudoers(self, mapper):
        prof = mapper.evaluate_incident(
            techniques=[],
            rule_description="Integrity check: /etc/sudoers file was modified",
            rule_id="100100"
        )
        assert prof.primary_technique == "T1548"
        assert prof.primary_tactic == "Privilege Escalation"
        assert prof.inferred is True

    def test_multi_technique_selects_deepest(self, mapper):
        # Both Initial Access (Stage 2) and Credential Access (Stage 6) present
        prof = mapper.evaluate_incident(techniques=["T1190", "T1110.001"])
        assert prof.primary_tactic == "Credential Access"
        assert prof.stage_depth == 6
