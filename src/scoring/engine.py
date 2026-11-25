"""
Dynamic Multi-Factor Risk Scoring Engine for Open-RBA (Module 5).

Supports two explicit scoring versions via config (`scoring.version`):
  - v1 (baseline): Normalized severity + decayed CTI + kill-chain stage with
    dynamic CTI renormalization, asset multiplier, and log-damped entity rollup.
  - v2: Confidence x Impact separation, outcome signals (attempt vs. success),
    corpus (rule_id, host) IDF rarity, upward-only capped CTI boost (no clean-IP
    penalty), timed ordered sequence chain rules, and bounded [0, 100] entity
    timeline rollup: 100 * (1 - exp(-R / k)).
"""

import re
import math
import yaml
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from src.correlation.engine import CorrelatedIncident, parse_timestamp
from src.enrichment.client import CTIReport, ThreatIntelClient
from src.attck.mapper import ATTACKProfile, ATTACKMapper


@dataclass
class ScoredIncident:
    """A prioritized security incident with complete explainability telemetry."""
    incident: CorrelatedIncident
    cti: CTIReport
    attack: ATTACKProfile
    base_risk: float              # Sum of normalized factors (v1) or confidence*impact (v2) in [0.0, 1.0]
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
    total_entity_risk: float      # Unbounded in v1; strictly bounded in [0, 100) in v2
    incidents: List[ScoredIncident]
    raw_incident_risk_sum: float = 0.0


PRIVILEGED_USERS = {
    "root", "admin", "administrator", "postgres", "mysql",
    "sudo", "wheel", "system", "ubuntu", "sysadmin"
}

DEFAULT_SEQUENCES = [
    {
        "name": "brute_force_to_compromise",
        "from_tactics": ["Credential Access"],
        "to_tactics": ["Initial Access", "Execution", "Privilege Escalation"],
        "max_gap_seconds": 900,
        "bonus": 0.50,
    },
    {
        "name": "access_to_privilege_escalation",
        "from_tactics": ["Initial Access", "Credential Access", "Execution"],
        "to_tactics": ["Privilege Escalation", "Defense Evasion", "Impact", "Exfiltration"],
        "max_gap_seconds": 3600,
        "bonus": 0.75,
    },
    {
        "name": "recon_to_exploit",
        "from_tactics": ["Reconnaissance", "Discovery"],
        "to_tactics": ["Initial Access", "Execution", "Privilege Escalation"],
        "max_gap_seconds": 3600,
        "bonus": 0.40,
    },
]


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
        },
        "scoring": {
            "version": "v1",
        },
    }

    def __init__(self, config_path: Optional[str] = "config/weights.yaml", scoring_version: Optional[str] = None):
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

        # Scoring version & v2 configuration
        scoring_cfg = self.config.get("scoring", {}) or {}
        resolved_ver = str(scoring_version or scoring_cfg.get("version", "v1")).lower()
        if resolved_ver not in ("v1", "v2"):
            raise ValueError(f"Unsupported scoring.version {resolved_ver!r}; must be 'v1' or 'v2'")
        self.scoring_version = resolved_ver

        v2_cfg = scoring_cfg.get("v2", {}) or {}
        self.v2_cti_boost_weight = float(v2_cfg.get("cti_boost_weight", 0.15))
        self.v2_rarity_weight = float(v2_cfg.get("rarity_weight", 0.20))
        self.v2_outcome_fail_penalty = float(v2_cfg.get("outcome_fail_penalty", 0.65))
        self.v2_outcome_success_boost = float(v2_cfg.get("outcome_success_boost", 1.25))
        self.v2_privileged_user_boost = float(v2_cfg.get("privileged_user_boost", 0.15))
        self.v2_entity_scale_k = float(v2_cfg.get("entity_scale_k", 2.5))
        self.v2_entity_lambda_days = float(v2_cfg.get("entity_lambda_days", 0.10))
        self.v2_entity_window_days = float(v2_cfg.get("entity_window_days", 30))

        self.sequence_rules = self.config.get("sequences", DEFAULT_SEQUENCES)

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

        tokens = set(re.split(r'[-_.\s0-9]+', name_lower))
        tokens.discard("")

        endpoint_tokens = {"laptop", "workstation", "pc", "kiosk", "desktop", "client", "endpoint"}
        is_endpoint = bool(tokens & endpoint_tokens)

        low_tokens = {"stage", "staging", "test", "dev", "ephemeral", "sandbox", "lab", "kiosk"}
        if (tokens & low_tokens) or is_endpoint:
            return "low", float(self.asset_tiers.get("low", 1.0))

        critical_tokens = {"dc", "domain", "db", "database", "ldap", "pki", "vault", "auth", "ad"}
        if tokens & critical_tokens:
            return "critical", float(self.asset_tiers.get("critical", 3.0))

        high_tokens = {"web", "api", "gateway", "proxy", "nginx", "apache", "prod", "production"}
        if tokens & high_tokens:
            return "high", float(self.asset_tiers.get("high", 2.0))

        return "low", self.default_criticality

    def register_agent_inventory(self, agents: List[Dict[str, Any]]) -> int:
        """Dynamically registers hosts discovered from Wazuh agent inventory into asset classification."""
        registered = 0
        for agent in agents:
            name = agent.get("name")
            if not name:
                continue
            name_lower = str(name).lower()
            if name_lower not in self.asset_hosts:
                tier, _ = self.get_asset_context(name_lower)
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

    # ------------------------------------------------------------------
    # v2 Signal Helpers
    # ------------------------------------------------------------------

    def _evaluate_outcome_v2(
        self,
        incident: CorrelatedIncident,
        attack: ATTACKProfile,
        has_prior_failures: bool = False,
    ) -> Tuple[str, float]:
        """Distinguishes failed attempts/routine noise from confirmed compromises."""
        desc = (incident.representative_description or "").lower()
        rep_rule = str(getattr(incident, "representative_rule_id", "") or "")
        tech = (attack.primary_technique or "").upper()

        # Routine maintenance / benign scans
        if re.search(r'\b(0\s+findings|no\s+malware|scan\s+completed\s+with\s+0|dpkg\s+package|cron|400\s+error|404)\b', desc) or rep_rule in ("2902", "550", "5501", "31101"):
            return "routine_benign", 0.55

        # Confirmed post-exploitation / high-impact compromise
        if tech in ("T1548", "T1068", "T1014", "T1059", "T1003", "T1190", "T1486", "T1485", "T1048"):
            return "confirmed_compromise", self.v2_outcome_success_boost
        if re.search(r'\b(sudoers|rootkit|trojan|backdoor|web\s+shell|command\s+execution|sql\s*injection|sqli|directory\s+traversal|privilege\s+escalation|gained\s+root)\b', desc):
            return "confirmed_compromise", self.v2_outcome_success_boost

        # Auth success: suspicious if preceded by failures, high severity, or external IP with elevated level
        if rep_rule == "5715" or re.search(r'\b(authentication\s+success|accepted\s+password)\b', desc):
            if has_prior_failures or incident.max_severity >= 6:
                return "auth_success_after_failure", self.v2_outcome_success_boost
            return "routine_auth", 0.65

        # Failed-only / brute-force attempts (not yet succeeded)
        if rep_rule in ("5710", "5712") or re.search(r'\b(non-existent\s+user|failed\s+password|auth(entication)?\s+failed|invalid\s+user|attempt\s+to\s+login|brute\s*force)\b', desc):
            return "failed_attempt", self.v2_outcome_fail_penalty

        return "neutral", 1.0

    def _compute_rarity_map_v2(self, incidents: List[CorrelatedIncident]) -> Dict[int, float]:
        """Computes normalized corpus IDF rarity per (rule_id, agent_name) in [0.0, 1.0]."""
        n = len(incidents)
        if n <= 1:
            return {id(inc): 1.0 for inc in incidents}

        pair_df: Counter = Counter()
        for inc in incidents:
            rep_rule = getattr(inc, "representative_rule_id", None) or (inc.rule_ids[0] if inc.rule_ids else "0")
            pair_df[(str(rep_rule), inc.agent_name)] += 1

        max_idf = math.log((n + 1.0) / 1.5)
        rarity_map: Dict[int, float] = {}
        for inc in incidents:
            rep_rule = getattr(inc, "representative_rule_id", None) or (inc.rule_ids[0] if inc.rule_ids else "0")
            df = pair_df[(str(rep_rule), inc.agent_name)]
            idf = math.log((n + 1.0) / (df + 0.5))
            rarity_map[id(inc)] = max(0.0, min(1.0, idf / max_idf)) if max_idf > 0 else 1.0
        return rarity_map

    def _score_incident_v1(
        self,
        incident: CorrelatedIncident,
        cti: CTIReport,
        attack: ATTACKProfile,
    ) -> ScoredIncident:
        s_norm = max(0.0, min(1.0, incident.max_severity / 15.0))
        cti_norm = max(0.0, min(1.0, cti.decayed_score))
        kc_norm = max(0.1, min(1.0, attack.normalized_depth))

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

        base_risk = round((eff_w_sev * s_norm) + (eff_w_cti * cti_norm) + (eff_w_kc * kc_norm), 4)
        tier, asset_mult = self.get_asset_context(incident.agent_name)
        incident_risk = round(base_risk * asset_mult, 3)

        breakdown = {
            "version": "v1",
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
            "asset_multiplier": asset_mult,
        }

        return ScoredIncident(
            incident=incident,
            cti=cti,
            attack=attack,
            base_risk=base_risk,
            asset_tier=tier,
            asset_multiplier=asset_mult,
            incident_risk=incident_risk,
            score_breakdown=breakdown,
        )

    def _score_incident_v2(
        self,
        incident: CorrelatedIncident,
        cti: CTIReport,
        attack: ATTACKProfile,
        rarity_score: float = 0.5,
        has_prior_failures: bool = False,
    ) -> ScoredIncident:
        """Confidence x Impact formulation with rarity, outcome, and capped upward CTI boost."""
        s_norm = max(0.0, min(1.0, incident.max_severity / 15.0))
        kc_norm = max(0.1, min(1.0, attack.normalized_depth))
        cti_norm = max(0.0, min(1.0, cti.decayed_score))

        outcome_label, outcome_factor = self._evaluate_outcome_v2(incident, attack, has_prior_failures=has_prior_failures)

        # Upward-only CTI confidence boost: clean external IPs (score=0) receive 0 boost, never a penalty
        has_applicable_cti = (
            not cti.is_private
            and incident.src_ip is not None
            and cti.source not in ("local", "unknown", "error")
        )
        # Allow evaluation drop-factor ablations (w_cti == 0 -> no CTI boost)
        cti_weight_active = self.v2_cti_boost_weight if self.w_cti > 0 else 0.0
        cti_boost = cti_weight_active * cti_norm if has_applicable_cti else 0.0

        # Respect config weights proportionally while enforcing v2 Confidence semantics
        w_sum = (self.w_sev + self.w_kc + self.v2_rarity_weight) or 1.0
        w_s = self.w_sev / w_sum
        w_k = self.w_kc / w_sum
        w_r = self.v2_rarity_weight / w_sum

        conf_core = (w_s * s_norm) + (w_k * kc_norm) + (w_r * rarity_score)
        confidence = max(0.0, min(1.0, (conf_core * outcome_factor) + cti_boost))

        # Impact in [0, 1] from normalized asset tier + privileged-account flag
        tier, asset_mult = self.get_asset_context(incident.agent_name)
        max_tier_mult = max(float(v) for v in self.asset_tiers.values()) if self.asset_tiers else 3.0
        impact_base = max(0.1, min(1.0, asset_mult / max_tier_mult))

        users_lower = {str(u).lower() for u in getattr(incident, "users", []) if u}
        is_priv_user = bool(users_lower & PRIVILEGED_USERS) and outcome_label != "routine_benign"
        priv_boost = self.v2_privileged_user_boost if is_priv_user else 0.0
        impact = max(0.0, min(1.0, impact_base + priv_boost))

        base_risk = round(confidence * impact, 4)
        incident_risk = round(base_risk * max_tier_mult, 3)

        # Top contributing explainability signals
        signals = [
            ("severity_prior", round(w_s * s_norm, 3)),
            ("kill_chain_depth", round(w_k * kc_norm, 3)),
            ("rarity_idf", round(w_r * rarity_score, 3)),
            (f"outcome:{outcome_label}", round(outcome_factor, 2)),
            ("asset_impact", round(impact, 3)),
        ]
        if cti_boost > 0:
            signals.append(("cti_boost", round(cti_boost, 3)))
        if is_priv_user:
            signals.append(("privileged_user", round(priv_boost, 3)))
        top_signals = [f"{name}={val}" for name, val in sorted(signals, key=lambda x: x[1], reverse=True)[:4]]

        breakdown = {
            "version": "v2",
            "confidence": round(confidence, 4),
            "impact": round(impact, 4),
            "outcome": outcome_label,
            "outcome_factor": round(outcome_factor, 4),
            "rarity": round(rarity_score, 4),
            "severity_norm": round(s_norm, 4),
            "kill_chain_norm": round(kc_norm, 4),
            "cti_decayed": round(cti_norm, 4),
            "cti_boost": round(cti_boost, 4),
            "privileged_user": is_priv_user,
            "renormalized": not has_applicable_cti,
            "base_risk": base_risk,
            "asset_multiplier": asset_mult,
            "top_signals": top_signals,
        }

        return ScoredIncident(
            incident=incident,
            cti=cti,
            attack=attack,
            base_risk=base_risk,
            asset_tier=tier,
            asset_multiplier=asset_mult,
            incident_risk=incident_risk,
            score_breakdown=breakdown,
        )

    def score_incident(
        self,
        incident: CorrelatedIncident,
        cti: CTIReport,
        attack: ATTACKProfile,
        rarity_score: float = 0.5,
        has_prior_failures: bool = False,
    ) -> ScoredIncident:
        """Scores a single incident using the active scoring version (v1 or v2)."""
        if self.scoring_version == "v2":
            return self._score_incident_v2(
                incident, cti, attack,
                rarity_score=rarity_score,
                has_prior_failures=has_prior_failures,
            )
        return self._score_incident_v1(incident, cti, attack)

    def _lookup_best_cti(self, inc: CorrelatedIncident, cti_client: ThreatIntelClient) -> CTIReport:
        """Looks up CTI across source IPs in a cluster, selecting the highest decayed risk."""
        ips = getattr(inc, "src_ips", None) or ([inc.src_ip] if inc.src_ip else [])
        if not ips:
            return cti_client.lookup_ip(None, alert_timestamp=inc.last_seen)
        best: Optional[CTIReport] = None
        for ip in ips[:5]:
            rep = cti_client.lookup_ip(ip, alert_timestamp=inc.last_seen)
            if best is None or rep.decayed_score > best.decayed_score:
                best = rep
        return best  # type: ignore[return-value]

    def score_all(
        self,
        incidents: List[CorrelatedIncident],
        cti_client: ThreatIntelClient,
        attack_mapper: ATTACKMapper
    ) -> List[ScoredIncident]:
        """Scores and ranks a list of correlated incidents in descending order."""
        rarity_map = self._compute_rarity_map_v2(incidents) if self.scoring_version == "v2" else {}

        # Detect preceding credential failures on each (host, src_ip) for auth_success escalation in v2
        failure_times: Dict[Tuple[str, Optional[str]], List[float]] = {}
        if self.scoring_version == "v2":
            for inc in incidents:
                desc = (inc.representative_description or "").lower()
                if inc.technique_family == "T1110" or "failed" in desc or "non-existent user" in desc:
                    try:
                        t_epoch = parse_timestamp(inc.last_seen).timestamp()
                        failure_times.setdefault((inc.agent_name, inc.src_ip), []).append(t_epoch)
                    except Exception:
                        pass

        scored = []
        for inc in incidents:
            cti = self._lookup_best_cti(inc, cti_client)
            rep_rule = getattr(inc, "representative_rule_id", None) or (inc.rule_ids[0] if inc.rule_ids else "")
            attack = attack_mapper.evaluate_incident(
                techniques=inc.mitre_techniques,
                rule_description=inc.representative_description,
                rule_id=rep_rule,
                tactic_names=getattr(inc, "mitre_tactic_names", None)
            )
            has_prior = False
            if self.scoring_version == "v2":
                try:
                    t_inc = parse_timestamp(inc.first_seen).timestamp()
                    prior_list = failure_times.get((inc.agent_name, inc.src_ip), [])
                    has_prior = any(0 <= (t_inc - t_fail) <= 900 for t_fail in prior_list)
                except Exception:
                    has_prior = False

            scored.append(self.score_incident(
                inc, cti, attack,
                rarity_score=rarity_map.get(id(inc), 0.5),
                has_prior_failures=has_prior,
            ))

        scored.sort(key=lambda x: x.incident_risk, reverse=True)
        return scored

    def _evaluate_sequence_rules_v2(self, host_incidents: List[ScoredIncident]) -> Tuple[float, List[str]]:
        """Evaluates deterministic time-bounded ordered attack chains from YAML."""
        if len(host_incidents) < 2 or not self.sequence_rules:
            return 1.0, []

        timed: List[Tuple[float, str]] = []
        for s in host_incidents:
            try:
                t_sec = parse_timestamp(s.incident.first_seen).timestamp()
                timed.append((t_sec, s.attack.primary_tactic))
            except Exception:
                continue
        timed.sort(key=lambda item: item[0])

        matched_names: List[str] = []
        total_bonus = 0.0
        for rule in self.sequence_rules:
            from_tacs = set(rule.get("from_tactics", []))
            to_tacs = set(rule.get("to_tactics", []))
            max_gap = float(rule.get("max_gap_seconds", 3600))
            bonus = float(rule.get("bonus", 0.3))
            rule_name = str(rule.get("name", "sequence"))

            matched = False
            for i in range(len(timed)):
                t_a, tac_a = timed[i]
                if tac_a not in from_tacs:
                    continue
                for j in range(i + 1, len(timed)):
                    t_b, tac_b = timed[j]
                    gap = t_b - t_a
                    if gap > max_gap:
                        break
                    if tac_b in to_tacs:
                        matched = True
                        break
                if matched:
                    break

            if matched:
                matched_names.append(rule_name)
                total_bonus += bonus

        depth_bonus = round(1.0 + min(0.6, total_bonus), 2)
        return depth_bonus, matched_names

    def aggregate_by_entity(self, scored_incidents: List[ScoredIncident]) -> List[EntityIncident]:
        """Groups scored incidents by target host."""
        by_host: Dict[str, List[ScoredIncident]] = {}
        for s in scored_incidents:
            by_host.setdefault(s.incident.agent_name, []).append(s)

        entities: List[EntityIncident] = []
        for host, host_incidents in by_host.items():
            tier, mult = self.get_asset_context(host)
            all_tactics = {inc.attack.primary_tactic for inc in host_incidents}
            sorted_incidents = sorted(host_incidents, key=lambda x: x.incident_risk, reverse=True)
            raw_incident_risk_sum = round(sum(inc.incident_risk for inc in sorted_incidents), 3)

            if self.scoring_version == "v2":
                # v2: Time-decayed rolling window + timed ordered chains + bounded [0, 100) normalization
                ref_dt = None
                for inc in sorted_incidents:
                    try:
                        dt = parse_timestamp(inc.incident.last_seen)
                        if ref_dt is None or dt > ref_dt:
                            ref_dt = dt
                    except Exception:
                        pass

                decayed_risks: List[float] = []
                for inc in sorted_incidents:
                    age_days = 0.0
                    if ref_dt is not None:
                        try:
                            inc_dt = parse_timestamp(inc.incident.last_seen)
                            age_days = max(0.0, (ref_dt - inc_dt).total_seconds() / 86400.0)
                        except Exception:
                            age_days = 0.0
                    if age_days <= self.v2_entity_window_days:
                        decayed_risks.append(inc.incident_risk * math.exp(-self.v2_entity_lambda_days * age_days))

                decayed_risks.sort(reverse=True)
                if decayed_risks:
                    effective_risk = decayed_risks[0]
                    for i, r_val in enumerate(decayed_risks[1:], 1):
                        effective_risk += r_val / (1.0 + math.log(1.0 + i))
                else:
                    effective_risk = 0.0

                depth_bonus, _ = self._evaluate_sequence_rules_v2(sorted_incidents)
                scaled_r = effective_risk * depth_bonus
                k = max(0.1, self.v2_entity_scale_k)
                total_entity_risk = round(100.0 * (1.0 - math.exp(-scaled_r / k)), 2)
            else:
                # v1 baseline rollup
                tactic_count = len(all_tactics)
                if tactic_count >= 3:
                    depth_bonus = 1.6
                elif tactic_count == 2:
                    depth_bonus = 1.3
                else:
                    depth_bonus = 1.0

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
                raw_incident_risk_sum=raw_incident_risk_sum,
            ))

        entities.sort(key=lambda e: e.total_entity_risk, reverse=True)
        return entities
