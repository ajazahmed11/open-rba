"""
Unit tests for Open-RBA Dynamic Multi-Factor Risk Scoring Engine (Module 5).
Tests normalized math, contextual asset multipliers, zero-threat safety,
and entity-centric aggregation with multi-stage attack depth bonuses.
"""

import pytest
from src.correlation.engine import CorrelatedIncident
from src.enrichment.client import CTIReport, ThreatIntelClient
from src.attck.mapper import ATTACKProfile, ATTACKMapper
from src.scoring.engine import RiskScoringEngine, ScoredIncident, EntityIncident


def _make_sample_incident(
    agent_name="web01",
    src_ip="203.0.113.45",
    rule_level=10,
    technique_family="T1110",
    techniques=None
):
    return CorrelatedIncident(
        src_ip=src_ip,
        agent_name=agent_name,
        technique_family=technique_family,
        alert_count=4,
        max_severity=rule_level,
        first_seen="2026-10-05T10:14:01Z",
        last_seen="2026-10-05T10:14:07Z",
        alert_ids=[1, 2, 3, 4],
        mitre_techniques=techniques or ["T1110.001"],
        rule_ids=["5710", "5712"],
        representative_description="sshd: brute force attack"
    )


class TestRiskScoringEngine:
    @pytest.fixture
    def engine(self):
        return RiskScoringEngine(config_path="config/weights.yaml")

    def test_weights_sum_to_one(self, engine):
        total = engine.w_sev + engine.w_cti + engine.w_kc
        assert abs(total - 1.0) < 1e-6

    def test_asset_multiplier_mapping(self, engine):
        tier, mult = engine.get_asset_context("db01")
        assert tier == "critical"
        assert mult == 3.0

        tier, mult = engine.get_asset_context("web01")
        assert tier == "high"
        assert mult == 2.0

        tier, mult = engine.get_asset_context("fedora01")
        assert tier == "medium"
        assert mult == 1.5

        tier, mult = engine.get_asset_context("ephemeral-staging-node")
        assert tier == "low"
        assert mult == 1.0

    def test_score_incident_bounded(self, engine):
        inc = _make_sample_incident(agent_name="web01", rule_level=12)
        cti = CTIReport(
            ip="203.0.113.45", raw_score=90.0, normalized_score=0.9,
            decayed_score=0.8, indicator_age_days=2.0, is_private=False, source="mock"
        )
        attack = ATTACKProfile(
            primary_technique="T1110", primary_tactic="Credential Access",
            tactic_id="TA0006", stage_depth=6, normalized_depth=0.6, inferred=False
        )

        scored = engine.score_incident(inc, cti, attack)
        # Base risk must be bounded in [0.0, 1.0]
        assert 0.0 <= scored.base_risk <= 1.0
        # Incident risk with asset multiplier (2.0 for web01) must be <= 3.0
        assert 0.0 <= scored.incident_risk <= 3.0
        assert scored.asset_tier == "high"
        assert scored.asset_multiplier == 2.0

    def test_zero_threat_on_critical_asset_does_not_inflate(self, engine):
        # Benign or level 0 alert on critical server (db01)
        inc = _make_sample_incident(agent_name="db01", rule_level=0)
        cti = CTIReport(
            ip=None, raw_score=0.0, normalized_score=0.0,
            decayed_score=0.0, indicator_age_days=0.0, is_private=True, source="local"
        )
        # Minimum depth
        attack = ATTACKProfile(
            primary_technique="rule:0", primary_tactic="Initial Access",
            tactic_id="TA0001", stage_depth=1, normalized_depth=0.1, inferred=True
        )

        scored = engine.score_incident(inc, cti, attack)
        # Even with 3.0 asset multiplier, total score remains tiny (below 0.1)
        assert scored.incident_risk < 0.15

    def test_entity_aggregation_multi_stage_bonus(self, engine):
        # web01 targeted by 3 distinct tactics: Initial Access, Credential Access, Privilege Escalation
        inc1 = _make_sample_incident(agent_name="web01", rule_level=10, technique_family="T1110")
        inc2 = _make_sample_incident(agent_name="web01", rule_level=10, technique_family="T1190")
        inc3 = _make_sample_incident(agent_name="web01", rule_level=12, technique_family="T1548")

        mock_cti = CTIReport(ip="203.0.113.45", raw_score=80.0, normalized_score=0.8,
                             decayed_score=0.8, indicator_age_days=1.0, is_private=False, source="mock")

        att1 = ATTACKProfile("T1110", "Credential Access", "TA0006", 6, 0.6, False)
        att2 = ATTACKProfile("T1190", "Initial Access", "TA0001", 2, 0.2, False)
        att3 = ATTACKProfile("T1548", "Privilege Escalation", "TA0004", 5, 0.5, False)

        scored1 = engine.score_incident(inc1, mock_cti, att1)
        scored2 = engine.score_incident(inc2, mock_cti, att2)
        scored3 = engine.score_incident(inc3, mock_cti, att3)

        entities = engine.aggregate_by_entity([scored1, scored2, scored3])
        assert len(entities) == 1
        web_entity = entities[0]
        assert web_entity.agent_name == "web01"
        assert web_entity.incident_count == 3
        assert len(web_entity.distinct_tactics) == 3
        # 3 distinct tactics trigger 1.6x multi-stage bonus
        assert web_entity.tactics_depth_bonus == 1.6

        import math
        sorted_scored = sorted([scored1, scored2, scored3], key=lambda x: x.incident_risk, reverse=True)
        eff_risk = sorted_scored[0].incident_risk + (sorted_scored[1].incident_risk / (1.0 + math.log(2.0))) + (sorted_scored[2].incident_risk / (1.0 + math.log(3.0)))
        assert web_entity.total_entity_risk == round(eff_risk * 1.6, 3)
        raw_sum = round(scored1.incident_risk + scored2.incident_risk + scored3.incident_risk, 3)
        assert web_entity.raw_incident_risk_sum == raw_sum

    def test_dynamic_weight_renormalization_missing_cti(self, engine):
        # Internal host event with no public IP (e.g. /etc/sudoers FIM alert Level 12)
        inc = _make_sample_incident(agent_name="web01", src_ip=None, rule_level=12, technique_family="T1548")
        cti = CTIReport(
            ip="LOCAL", raw_score=0.0, normalized_score=0.0,
            decayed_score=0.0, indicator_age_days=0.0, is_private=True, source="local"
        )
        attack = ATTACKProfile(
            primary_technique="T1548", primary_tactic="Privilege Escalation",
            tactic_id="TA0004", stage_depth=9, normalized_depth=0.9, inferred=False
        )

        scored = engine.score_incident(inc, cti, attack)
        # Should be dynamically renormalized: CTI weight drops to 0, sev and kc re-sum to 1.0
        assert scored.score_breakdown["renormalized"] is True
        assert scored.score_breakdown["effective_weights"]["threat_intel"] == 0.0

        # With renormalization, base risk is (0.5833 * 0.8) + (0.4167 * 0.9) = 0.8417
        # On web01 (high tier, 2.0x), incident risk is ~1.683
        assert scored.base_risk > 0.80
        assert scored.incident_risk > 1.60

    def test_asset_tokenization_prevents_substring_false_positives(self, engine):
        # "capital-kiosk" must not match "api" in "capital" -> low
        tier, mult = engine.get_asset_context("capital-kiosk")
        assert tier == "low"
        assert mult == 1.0

        # "dbadmin-laptop" is an endpoint device, not a database server -> low
        tier, mult = engine.get_asset_context("dbadmin-laptop")
        assert tier == "low"
        assert mult == 1.0

        # "api-gateway-01" has distinct "api" token -> high
        tier, mult = engine.get_asset_context("api-gateway-01")
        assert tier == "high"
        assert mult == 2.0

        # "auth-ldap-server" has distinct "ldap" token -> critical
        tier, mult = engine.get_asset_context("auth-ldap-server")
        assert tier == "critical"
        assert mult == 3.0

    def test_diminishing_returns_bounds_alert_volume_spam(self, engine):
        # Simulate 50 low-level incidents (each risk ~0.5) on a workstation
        mock_cti = CTIReport(ip="203.0.113.45", raw_score=20.0, normalized_score=0.2,
                             decayed_score=0.2, indicator_age_days=1.0, is_private=False, source="mock")
        attack = ATTACKProfile("T1046", "Discovery", "TA0007", 2, 0.2, False)

        scored_list = []
        for i in range(50):
            inc = _make_sample_incident(agent_name="workstation-01", rule_level=5, technique_family="T1046")
            scored_list.append(engine.score_incident(inc, mock_cti, attack))

        entities = engine.aggregate_by_entity(scored_list)
        assert len(entities) == 1
        entity = entities[0]
        assert entity.incident_count == 50

        # Unbounded sum would be 50 * incident_risk (~15.0)
        # Logarithmic diminishing returns curve strictly bounds the volume storm
        assert entity.total_entity_risk < 7.0
        assert entity.total_entity_risk < entity.raw_incident_risk_sum
