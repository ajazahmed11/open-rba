"""
Dynamic Multi-Factor Risk Scoring Engine for Open-RBA (Module 5).

Implements normalized, mathematically bounded multi-factor risk scoring
and entity-centric aggregation.

Formulation:
    R_base = w_sev * S_norm + w_cti * CTI_decayed + w_kc * KC_norm   (in [0.0, 1.0])
    R_incident = R_base * Asset_Multiplier                           (in [0.0, 3.0])
    R_entity = (sum(R_incident)) * Tactics_Depth_Bonus

Ensures that high-value assets amplify confirmed threats without triggering
phantom alerts on benign activity.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from src.correlation.engine import CorrelatedIncident
from src.enrichment.client import CTIReport, ThreatIntelClient
from src.attck.mapper import ATTACKProfile, ATTACKMapper


@dataclass
class ScoredIncident:
    """A prioritized security incident with complete explainability telemetry."""
    incident: CorrelatedIncident
    cti: CTIReport
    attack: ATTACKProfile
    base_risk: float              # Sum of normalized factors in [0.0, 1.0]
    asset_tier: str               # "critical", "high", "medium", or "low"
    asset_multiplier: float       # 1.0 to 3.0
    incident_risk: float          # Final incident score in [0.0, 3.0]
    score_breakdown: Dict[str, float]


@dataclass
class EntityIncident:
    """Entity-centric rollup grouping all incidents targeting a specific host."""
    agent_name: str
    asset_tier: str
    asset_multiplier: float
    incident_count: int
    distinct_tactics: List[str]
    tactics_depth_bonus: float
    total_entity_risk: float
    incidents: List[ScoredIncident]


class RiskScoringEngine:
    """Evaluates multi-factor risk scores from configuration weights."""

    DEFAULT_CONFIG = {
        "weights": {
            "severity": 0.35,
            "threat_intel": 0.40,
            "kill_chain": 0.25,
        },
        "assets": {
            "default_criticality": 1.0,
            "tiers": {
                "critical": 3.0,
                "high": 2.0,
                "medium": 1.5,
                "low": 1.0
            },
            "hosts": {
                "db01": "critical",
                "web01": "high",
                "fedora01": "medium"
            }
        }
    }

    def __init__(self, config_path: Optional[str] = "config/weights.yaml"):
        self.config = self._load_config(config_path)

        # Extract normalized weights (ensure they sum to 1.0)
        raw_w = self.config.get("weights", {})
        w_sev = float(raw_w.get("severity", 0.35))
        w_cti = float(raw_w.get("threat_intel", 0.40))
        w_kc = float(raw_w.get("kill_chain", 0.25))
        total_w = w_sev + w_cti + w_kc

        self.w_sev = w_sev / total_w
        self.w_cti = w_cti / total_w
        self.w_kc = w_kc / total_w

        # Asset mappings
        asset_cfg = self.config.get("assets", {})
        self.asset_tiers = asset_cfg.get("tiers", {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0})
        self.asset_hosts = asset_cfg.get("hosts", {})
        self.default_criticality = float(asset_cfg.get("default_criticality", 1.0))

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        if config_path:
            p = Path(config_path)
            if p.exists():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            return data
                except Exception:
                    pass
        return self.DEFAULT_CONFIG

    def get_asset_context(self, agent_name: str) -> tuple[str, float]:
        """Resolves asset tier name and multiplier for a host."""
        tier = self.asset_hosts.get(agent_name.lower())
        if tier and tier in self.asset_tiers:
            return tier, float(self.asset_tiers[tier])

        # Heuristic role detection if not explicitly mapped
        name_lower = agent_name.lower()
        if any(k in name_lower for k in ["dc", "domain", "db", "database", "ldap"]):
            return "critical", float(self.asset_tiers.get("critical", 3.0))
        if any(k in name_lower for k in ["web", "api", "gateway", "proxy"]):
            return "high", float(self.asset_tiers.get("high", 2.0))
        if any(k in name_lower for k in ["stage", "test", "dev", "ephemeral"]):
            return "low", float(self.asset_tiers.get("low", 1.0))

        return "medium", self.default_criticality

    def score_incident(
        self,
        incident: CorrelatedIncident,
        cti: CTIReport,
        attack: ATTACKProfile
    ) -> ScoredIncident:
        """Calculates normalized multi-factor risk score for an incident."""
        # Factor 1: Normalized static severity [0.0, 1.0]
        s_norm = max(0.0, min(1.0, incident.max_severity / 15.0))

        # Factor 2: Decayed CTI score [0.0, 1.0]
        cti_norm = max(0.0, min(1.0, cti.decayed_score))

        # Factor 3: Normalized kill-chain progression depth [0.1, 1.0]
        kc_norm = max(0.1, min(1.0, attack.normalized_depth))

        # Base Risk sum in [0.0, 1.0]
        base_risk = (self.w_sev * s_norm) + (self.w_cti * cti_norm) + (self.w_kc * kc_norm)
        base_risk = round(base_risk, 4)

        # Contextual Asset Multiplier [1.0, 3.0]
        tier, asset_mult = self.get_asset_context(incident.agent_name)

        # Final Incident Risk
        incident_risk = round(base_risk * asset_mult, 3)

        breakdown = {
            "severity_norm": round(s_norm, 4),
            "severity_weighted": round(self.w_sev * s_norm, 4),
            "cti_decayed": round(cti_norm, 4),
            "cti_weighted": round(self.w_cti * cti_norm, 4),
            "kill_chain_norm": round(kc_norm, 4),
            "kill_chain_weighted": round(self.w_kc * kc_norm, 4),
            "base_risk": base_risk,
            "asset_multiplier": asset_mult
        }

        return ScoredIncident(
            incident=incident,
            cti=cti,
            attack=attack,
            base_risk=base_risk,
            asset_tier=tier,
            asset_multiplier=asset_mult,
            incident_risk=incident_risk,
            score_breakdown=breakdown
        )

    def score_all(
        self,
        incidents: List[CorrelatedIncident],
        cti_client: ThreatIntelClient,
        attack_mapper: ATTACKMapper
    ) -> List[ScoredIncident]:
        """Scores and ranks a list of correlated incidents in descending order."""
        scored = []
        for inc in incidents:
            cti = cti_client.lookup_ip(inc.src_ip, alert_timestamp=inc.last_seen)
            attack = attack_mapper.evaluate_incident(
                techniques=inc.mitre_techniques,
                rule_description=inc.representative_description,
                rule_id=inc.rule_ids[0] if inc.rule_ids else ""
            )
            scored.append(self.score_incident(inc, cti, attack))

        scored.sort(key=lambda x: x.incident_risk, reverse=True)
        return scored

    def aggregate_by_entity(self, scored_incidents: List[ScoredIncident]) -> List[EntityIncident]:
        """
        Groups scored incidents by target entity (host), applying tactical
        depth progression multiplier to multi-stage intrusions.
        """
        by_host: Dict[str, List[ScoredIncident]] = {}
        for s in scored_incidents:
            by_host.setdefault(s.incident.agent_name, []).append(s)

        entities: List[EntityIncident] = []
        for host, host_incidents in by_host.items():
            tier, mult = self.get_asset_context(host)
            all_tactics = {inc.attack.primary_tactic for inc in host_incidents}

            # Tactical depth bonus
            tactic_count = len(all_tactics)
            if tactic_count >= 3:
                depth_bonus = 1.6  # Multi-stage intrusion (e.g. Initial Access + PrivEsc + CredAccess)
            elif tactic_count == 2:
                depth_bonus = 1.3  # Two-stage sequence
            else:
                depth_bonus = 1.0  # Single tactic activity

            incident_risk_sum = sum(inc.incident_risk for inc in host_incidents)
            total_entity_risk = round(incident_risk_sum * depth_bonus, 3)

            entities.append(EntityIncident(
                agent_name=host,
                asset_tier=tier,
                asset_multiplier=mult,
                incident_count=len(host_incidents),
                distinct_tactics=sorted(list(all_tactics)),
                tactics_depth_bonus=depth_bonus,
                total_entity_risk=total_entity_risk,
                incidents=sorted(host_incidents, key=lambda x: x.incident_risk, reverse=True)
            ))

        entities.sort(key=lambda e: e.total_entity_risk, reverse=True)
        return entities
