"""
Dynamic Multi-Factor Risk Scoring Engine for Open-RBA (Module 5).

Implements normalized, mathematically bounded multi-factor risk scoring
and entity-centric aggregation with dynamic weight renormalization and
diminishing-returns volume damping.

Formulation:
    1. Dynamic Weight Renormalization:
       If CTI is applicable (external indicator present):
           w'_sev = w_sev, w'_cti = w_cti, w'_kc = w_kc
       Else (local host alert, private IP, missing/failed CTI):
           w'_cti = 0.0
           w'_sev = w_sev / (w_sev + w_kc)
           w'_kc  = w_kc  / (w_sev + w_kc)

    2. Normalized Incident Risk:
       R_base = w'_sev * S_norm + w'_cti * CTI_decayed + w'_kc * KC_norm   (in [0.0, 1.0])
       R_incident = R_base * Asset_Multiplier                             (in [0.0, 3.0])

    3. Bounded Entity Aggregation (Diminishing Marginal Risk):
       R_effective = R_0 + sum_{i=1..n-1} (R_i / (1 + ln(1 + i)))
       R_entity = R_effective * Tactics_Depth_Bonus
"""

import re
import math
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
    score_breakdown: Dict[str, Any]


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
    raw_incident_risk_sum: float = 0.0


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

        # Extract normalized weights (ensure they are non-negative and sum to > 0)
        raw_w = self.config.get("weights", {})
        w_sev = float(raw_w.get("severity", 0.35))
        w_cti = float(raw_w.get("threat_intel", 0.40))
        w_kc = float(raw_w.get("kill_chain", 0.25))

        if w_sev < 0 or w_cti < 0 or w_kc < 0:
            raise ValueError(f"Weights must be non-negative: severity={w_sev}, threat_intel={w_cti}, kill_chain={w_kc}")

        total_w = w_sev + w_cti + w_kc
        if total_w <= 0:
            raise ValueError(f"Sum of weights must be positive, got {total_w}")

        self.w_sev = w_sev / total_w
        self.w_cti = w_cti / total_w
        self.w_kc = w_kc / total_w

        # Asset mappings: validate tiers and ensure hosts reference valid tiers
        asset_cfg = self.config.get("assets", {})
        self.asset_tiers = asset_cfg.get("tiers", {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0})
        for tier_name, mult in self.asset_tiers.items():
            if float(mult) <= 0:
                raise ValueError(f"Asset tier multiplier for {tier_name!r} must be positive: {mult}")

        self.asset_hosts = {}
        for k, v in asset_cfg.get("hosts", {}).items():
            tier_val = str(v).lower()
            if tier_val not in self.asset_tiers:
                raise ValueError(f"Host {k!r} assigned unknown asset tier {v!r}. Must be one of {list(self.asset_tiers.keys())}")
            self.asset_hosts[str(k).lower()] = tier_val

        self.default_criticality = float(asset_cfg.get("default_criticality", 1.0))
        if self.default_criticality <= 0:
            raise ValueError(f"default_criticality must be positive: {self.default_criticality}")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        if config_path:
            p = Path(config_path)
            if not p.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if not isinstance(data, dict):
                        raise ValueError(f"Configuration in {config_path} must be a YAML mapping")
                    return data
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML in configuration file {config_path}: {e}") from e
        return self.DEFAULT_CONFIG

    def get_asset_context(self, agent_name: str) -> tuple[str, float]:
        """Resolves asset tier name and multiplier for a host using robust tokenization."""
        name_lower = agent_name.lower()

        # Direct explicit host lookup
        tier = self.asset_hosts.get(name_lower)
        if tier and tier in self.asset_tiers:
            return tier, float(self.asset_tiers[tier])

        # Tokenize by non-alphanumeric delimiters to avoid substring false positives
        # (e.g. "capital-kiosk" shouldn't trigger "api", "dbadmin-laptop" shouldn't trigger "db")
        tokens = set(re.split(r'[-_.\s0-9]+', name_lower))
        tokens.discard("")

        # Endpoint / workstation tokens (demote priority)
        endpoint_tokens = {"laptop", "workstation", "pc", "kiosk", "desktop", "client", "endpoint"}
        is_endpoint = bool(tokens & endpoint_tokens)

        # Low value / ephemeral / test assets (strictly take precedence over server role tokens like db, web)
        low_tokens = {"stage", "staging", "test", "dev", "ephemeral", "sandbox", "lab", "kiosk"}
        if (tokens & low_tokens) or is_endpoint:
            return "low", float(self.asset_tiers.get("low", 1.0))

        # Critical infrastructure tokens (only if not test/endpoint)
        critical_tokens = {"dc", "domain", "db", "database", "ldap", "pki", "vault", "auth", "ad"}
        if tokens & critical_tokens:
            return "critical", float(self.asset_tiers.get("critical", 3.0))

        # High value server roles
        high_tokens = {"web", "api", "gateway", "proxy", "nginx", "apache", "prod", "production"}
        if tokens & high_tokens:
            return "high", float(self.asset_tiers.get("high", 2.0))

        return "low", self.default_criticality

    def register_agent_inventory(self, agents: List[Dict[str, Any]]) -> int:
        """Dynamically registers hosts discovered from Wazuh agent inventory into asset classification.
        Inspects agent name and group tags to populate asset tiers for unconfigured hosts.
        Returns count of newly registered hosts.
        """
        registered = 0
        for agent in agents:
            name = agent.get("name")
            if not name:
                continue
            name_lower = str(name).lower()
            if name_lower not in self.asset_hosts:
                tier, _ = self.get_asset_context(name_lower)
                # Preserve explicit low/ephemeral classification over group tags
                tokens = set(re.split(r'[-_.\s0-9]+', name_lower))
                is_explicit_low = bool(tokens & {"stage", "staging", "test", "dev", "ephemeral", "sandbox", "lab", "kiosk", "laptop", "workstation", "pc", "desktop", "client", "endpoint"})
                if not is_explicit_low:
                    groups = agent.get("group", [])
                    if isinstance(groups, str):
                        groups = [groups]
                    for g in groups:
                        g_tokens = set(re.split(r'[-_.\s0-9]+', str(g).lower()))
                        if g_tokens & {"db", "database", "databases", "dc", "domain", "ldap", "pki", "vault"}:
                            tier = "critical"
                            break
                        elif g_tokens & {"web", "api", "prod", "production", "gateway"}:
                            tier = "high"
                self.asset_hosts[name_lower] = tier
                registered += 1
        return registered

    def score_incident(
        self,
        incident: CorrelatedIncident,
        cti: CTIReport,
        attack: ATTACKProfile
    ) -> ScoredIncident:
        """Calculates normalized multi-factor risk score for an incident with dynamic CTI renormalization."""
        # Factor 1: Normalized static severity [0.0, 1.0]
        s_norm = max(0.0, min(1.0, incident.max_severity / 15.0))

        # Factor 2: Decayed CTI score [0.0, 1.0]
        cti_norm = max(0.0, min(1.0, cti.decayed_score))

        # Factor 3: Normalized kill-chain progression depth [0.1, 1.0]
        kc_norm = max(0.1, min(1.0, attack.normalized_depth))

        # Dynamic Weight Renormalization:
        # If CTI is not applicable (internal host, private IP, local event, or lookup unavailable),
        # renormalize remaining weights so missing external intelligence does not penalize local incidents.
        has_applicable_cti = (
            not cti.is_private
            and incident.src_ip is not None
            and cti.source not in ("local", "unknown", "error")
        )

        if has_applicable_cti:
            eff_w_sev = self.w_sev
            eff_w_cti = self.w_cti
            eff_w_kc = self.w_kc
        else:
            eff_w_cti = 0.0
            sum_remaining = self.w_sev + self.w_kc
            if sum_remaining > 0:
                eff_w_sev = self.w_sev / sum_remaining
                eff_w_kc = self.w_kc / sum_remaining
            else:
                eff_w_sev = 0.5
                eff_w_kc = 0.5

        # Base Risk sum in [0.0, 1.0]
        base_risk = (eff_w_sev * s_norm) + (eff_w_cti * cti_norm) + (eff_w_kc * kc_norm)
        base_risk = round(base_risk, 4)

        # Contextual Asset Multiplier [1.0, 3.0]
        tier, asset_mult = self.get_asset_context(incident.agent_name)

        # Final Incident Risk
        incident_risk = round(base_risk * asset_mult, 3)

        breakdown = {
            "severity_norm": round(s_norm, 4),
            "severity_weighted": round(eff_w_sev * s_norm, 4),
            "cti_decayed": round(cti_norm, 4),
            "cti_weighted": round(eff_w_cti * cti_norm, 4),
            "kill_chain_norm": round(kc_norm, 4),
            "kill_chain_weighted": round(eff_w_kc * kc_norm, 4),
            "renormalized": not has_applicable_cti,
            "effective_weights": {
                "severity": round(eff_w_sev, 4),
                "threat_intel": round(eff_w_cti, 4),
                "kill_chain": round(eff_w_kc, 4),
            },
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
            rep_rule = getattr(inc, "representative_rule_id", None) or (inc.rule_ids[0] if inc.rule_ids else "")
            attack = attack_mapper.evaluate_incident(
                techniques=inc.mitre_techniques,
                rule_description=inc.representative_description,
                rule_id=rep_rule,
                tactic_names=getattr(inc, "mitre_tactic_names", None)
            )
            scored.append(self.score_incident(inc, cti, attack))

        scored.sort(key=lambda x: x.incident_risk, reverse=True)
        return scored

    def aggregate_by_entity(self, scored_incidents: List[ScoredIncident]) -> List[EntityIncident]:
        """
        Groups scored incidents by target entity (host), applying logarithmic
        diminishing marginal risk to bound repeated incident storms and applying
        tactical depth bonuses to multi-stage intrusions.
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

            # Sort incidents descending by incident risk
            sorted_incidents = sorted(host_incidents, key=lambda x: x.incident_risk, reverse=True)
            raw_incident_risk_sum = round(sum(inc.incident_risk for inc in sorted_incidents), 3)

            # Diminishing returns curve: primary incident contributes 100%, subsequent incidents
            # contribute with logarithmic dampening to prevent volume spam from overtaking root compromises:
            # R_effective = R_0 + sum_{i=1..n-1} (R_i / (1 + ln(1 + i)))
            if sorted_incidents:
                effective_risk = sorted_incidents[0].incident_risk
                for i, inc in enumerate(sorted_incidents[1:], 1):
                    effective_risk += inc.incident_risk / (1.0 + math.log(1.0 + i))
            else:
                effective_risk = 0.0

            total_entity_risk = round(effective_risk * depth_bonus, 3)

            entities.append(EntityIncident(
                agent_name=host,
                asset_tier=tier,
                asset_multiplier=mult,
                incident_count=len(host_incidents),
                distinct_tactics=sorted(list(all_tactics)),
                tactics_depth_bonus=depth_bonus,
                total_entity_risk=total_entity_risk,
                incidents=sorted_incidents,
                raw_incident_risk_sum=raw_incident_risk_sum
            ))

        entities.sort(key=lambda e: e.total_entity_risk, reverse=True)
        return entities

