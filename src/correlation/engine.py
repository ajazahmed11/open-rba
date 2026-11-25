"""
Temporal Correlation Engine for Open-RBA (Module 2).

Groups raw normalized alerts into correlated incidents by collapsing
noisy bursts (e.g., 50 Hydra failed-login alerts) into single events
while preserving distinct attack types.

Grouping key: (src_ip, target_host, technique_family)
Window type:  Session window — extends as long as new alerts for the
              same group keep arriving within `window_seconds` of each
              other. A gap larger than the window finalizes the cluster.

This is pure noise reduction. Scoring happens in Module 5.
"""

import re
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_timestamp(ts: Optional[str]) -> datetime:
    """Parse ISO 8601 timestamp, handling Wazuh format variants safely.

    Handles:
      - 2026-10-05T10:14:01.120+0000   (offset without colon)
      - 2026-10-05T10:14:15.000Z       (UTC Z suffix)
      - 2026-10-05T10:14:30.500+00:00  (standard offset)
      - 2026-10-05T10:14:30            (naive timestamp, normalized to UTC)
      - Empty or malformed strings     (falls back safely to UTC now)

    Guarantees that all returned datetimes are timezone-aware in UTC,
    preventing TypeError on offset-naive and offset-aware comparisons.
    """
    if not ts or not isinstance(ts, str) or not ts.strip():
        raise ValueError(f"Invalid or empty timestamp string: {ts!r}")

    ts_clean = ts.strip()
    # Normalize bare 4-digit timezone offset (+0000 -> +00:00)
    ts_clean = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts_clean)
    # Normalize trailing Z to +00:00
    if ts_clean.endswith("Z"):
        ts_clean = ts_clean[:-1] + "+00:00"

    dt = datetime.fromisoformat(ts_clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def extract_technique_family(mitre_techniques: List[str], rule_id: str) -> str:
    """Extract the top-level MITRE ATT&CK technique for grouping.

    T1110.001 → T1110  (strip sub-technique)
    T1190     → T1190  (already top-level)
    []        → rule:5710  (fallback when no MITRE annotation)
    """
    if mitre_techniques:
        return mitre_techniques[0].split(".")[0]
    return f"rule:{rule_id}"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CorrelatedIncident:
    """A group of temporally-related alerts collapsed into one incident.

    Preserves forensic detail: which alerts contributed, their time span,
    all observed MITRE techniques, and the peak severity.
    """
    src_ip: Optional[str]           # Attacker source (None for host-local events)
    agent_name: str                 # Target host
    technique_family: str           # Top-level MITRE technique or rule:ID
    alert_count: int                # Number of raw alerts compressed into this
    max_severity: int               # Highest rule_level in the group
    first_seen: str                 # ISO timestamp of earliest alert
    last_seen: str                  # ISO timestamp of latest alert
    alert_ids: List[int]            # DB primary keys of contributing alerts
    mitre_techniques: List[str]     # All distinct technique IDs observed
    rule_ids: List[str]             # All distinct rule IDs in the group
    representative_description: str # Description from the highest-severity alert
    representative_rule_id: str = "" # Rule ID from the highest-severity alert
    mitre_tactic_names: List[str] = field(default_factory=list) # All observed tactic names
    src_ips: List[str] = field(default_factory=list) # All distinct source IPs in the cluster
    users: List[str] = field(default_factory=list)   # All distinct target usernames in the cluster

    @property
    def group_key(self) -> str:
        """Human-readable grouping key."""
        src = self.src_ip or "LOCAL"
        return f"{src}|{self.agent_name}|{self.technique_family}"


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def _make_group_key(alert: Dict[str, Any], mode: str = "source_ip") -> tuple:
    """Compute the correlation grouping key for an alert.

    Modes:
      - source_ip (v1): (src_ip_or_LOCAL, agent_name, technique_family)
      - target_aware (v2): collapses external multi-IP sprays/scans targeting the same
        (agent_name, technique_family), while keeping LOCAL host events separate.
    """
    src = alert.get("src_ip") or "LOCAL"
    agent = alert.get("agent_name", "unknown")
    techniques = alert.get("mitre_tactics") or []
    family = extract_technique_family(techniques, str(alert.get("rule_id", "0")))
    if mode == "target_aware":
        src_scope = "LOCAL" if src == "LOCAL" else "EXTERNAL"
        return (src_scope, agent, family)
    return (src, agent, family)


def _new_cluster(alert: Dict[str, Any], ts: datetime, family: str) -> dict:
    """Initialize a new cluster state dict from the first alert."""
    techniques = alert.get("mitre_tactics") or []
    tactic_names = alert.get("mitre_tactic_names") or []
    rule_id = str(alert.get("rule_id", "0"))
    rule_level = int(alert.get("rule_level", 0))
    desc = alert.get("rule_description", "")
    src_ip = alert.get("src_ip")
    user = alert.get("user")
    return {
        "src_ip": src_ip,
        "src_ips": [src_ip] if src_ip else [],
        "users": [user] if user else [],
        "agent_name": alert.get("agent_name", "unknown"),
        "technique_family": family,
        "first_seen": alert.get("timestamp", ""),
        "last_seen": alert.get("timestamp", ""),
        "first_dt": ts,
        "last_dt": ts,
        "alert_ids": [alert.get("id", 0)],
        "alert_count": 1,
        "max_severity": rule_level,
        "representative_description": desc,
        "representative_rule_id": rule_id,
        "mitre_techniques": list(techniques),
        "mitre_tactic_names": list(tactic_names),
        "rule_ids": [rule_id],
    }


def _extend_cluster(cluster: dict, alert: Dict[str, Any], ts: datetime) -> None:
    """Add an alert to an existing cluster, updating all aggregates."""
    cluster["last_dt"] = ts
    cluster["last_seen"] = alert.get("timestamp", cluster["last_seen"])
    cluster["alert_ids"].append(alert.get("id", 0))
    cluster["alert_count"] += 1

    src_ip = alert.get("src_ip")
    if src_ip and src_ip not in cluster["src_ips"]:
        cluster["src_ips"].append(src_ip)
    user = alert.get("user")
    if user and user not in cluster["users"]:
        cluster["users"].append(user)

    rule_level = int(alert.get("rule_level", 0))
    if rule_level > cluster["max_severity"]:
        cluster["max_severity"] = rule_level
        cluster["representative_description"] = alert.get("rule_description", cluster["representative_description"])
        cluster["representative_rule_id"] = str(alert.get("rule_id", cluster["representative_rule_id"]))

    for t in alert.get("mitre_tactics") or []:
        if t not in cluster["mitre_techniques"]:
            cluster["mitre_techniques"].append(t)

    for tac in alert.get("mitre_tactic_names") or []:
        if tac not in cluster["mitre_tactic_names"]:
            cluster["mitre_tactic_names"].append(tac)

    rid = str(alert.get("rule_id", "0"))
    if rid not in cluster["rule_ids"]:
        cluster["rule_ids"].append(rid)


def _finalize_cluster(cluster: dict) -> CorrelatedIncident:
    """Convert internal cluster state dict into a CorrelatedIncident."""
    rep_rule = cluster.get("representative_rule_id") or (cluster["rule_ids"][0] if cluster["rule_ids"] else "")
    src_ips = cluster.get("src_ips", [])
    primary_src = src_ips[0] if src_ips else cluster["src_ip"]
    return CorrelatedIncident(
        src_ip=primary_src,
        agent_name=cluster["agent_name"],
        technique_family=cluster["technique_family"],
        alert_count=cluster["alert_count"],
        max_severity=cluster["max_severity"],
        first_seen=cluster["first_seen"],
        last_seen=cluster["last_seen"],
        alert_ids=cluster["alert_ids"],
        mitre_techniques=cluster["mitre_techniques"],
        rule_ids=cluster["rule_ids"],
        representative_description=cluster["representative_description"],
        representative_rule_id=rep_rule,
        mitre_tactic_names=cluster.get("mitre_tactic_names", []),
        src_ips=src_ips,
        users=cluster.get("users", []),
    )


def correlate_alerts(
    alerts: List[Dict[str, Any]],
    window_seconds: int = 120,
    mode: str = "source_ip",
) -> List[CorrelatedIncident]:
    """
    Temporal correlation engine.

    Groups alerts by (src_ip, target_host, technique_family) using session
    windows. The window extends as long as alerts for the same group keep
    arriving within `window_seconds` of each other. A gap larger than the
    window closes the current cluster and starts a new one.

    Args:
        alerts: Alert dicts from AlertDatabase.fetch_*() methods.
                Each must have: id, timestamp, rule_id, rule_level,
                rule_description, agent_name, src_ip, mitre_tactics.
        window_seconds: Max gap (in seconds) between consecutive alerts
                        in the same cluster before splitting.

    Returns:
        List of CorrelatedIncident objects, sorted by max_severity
        descending (most critical incidents first).
    """
    if not alerts:
        return []

    valid_alerts = []
    for alert in alerts:
        if not isinstance(alert, dict):
            logger.warning(f"Skipping non-dict alert in correlate_alerts: {alert}")
            continue
        ts_str = alert.get("timestamp")
        if not ts_str:
            logger.warning(f"Skipping alert missing timestamp: {alert}")
            continue
        agent_val = alert.get("agent_name")
        rule_val = alert.get("rule_id")
        if not isinstance(agent_val, str) or not agent_val.strip() or rule_val is None or str(rule_val).strip() == "":
            logger.warning(f"Skipping malformed alert missing valid agent_name or rule_id: {alert}")
            continue
        try:
            int(alert.get("rule_level", 0))
        except (ValueError, TypeError):
            logger.warning(f"Skipping alert with non-numeric rule_level (ID: {alert.get('id')}): {alert.get('rule_level')!r}")
            continue
        try:
            ts = parse_timestamp(ts_str)
            valid_alerts.append((ts, alert))
        except Exception as e:
            logger.warning(f"Skipping alert with corrupt or missing timestamp (ID: {alert.get('id')}): {e}")
            continue

    if not valid_alerts:
        return []

    # Sort chronologically by parsed UTC timestamp
    valid_alerts.sort(key=lambda item: item[0])

    # Active clusters keyed by (src_ip, agent, technique_family)
    active: Dict[tuple, dict] = {}
    completed: List[CorrelatedIncident] = []

    for ts, alert in valid_alerts:
        key = _make_group_key(alert, mode=mode)
        family = key[2]  # technique_family from the tuple

        if key in active:
            cluster = active[key]
            gap = (ts - cluster["last_dt"]).total_seconds()

            if gap <= window_seconds:
                _extend_cluster(cluster, alert, ts)
            else:
                # Gap exceeded — finalize old cluster, start fresh
                completed.append(_finalize_cluster(cluster))
                active[key] = _new_cluster(alert, ts, family)
        else:
            active[key] = _new_cluster(alert, ts, family)

    # Finalize all remaining active clusters
    for cluster in active.values():
        completed.append(_finalize_cluster(cluster))

    # Most critical incidents first
    completed.sort(key=lambda inc: inc.max_severity, reverse=True)
    return completed


def alert_reduction_ratio(num_alerts: int, num_incidents: int) -> float:
    """Calculate the alert-to-incident reduction ratio.

    Returns a float in [0.0, 1.0] where higher means more compression.
    Example: 50 alerts → 3 incidents = 1 - 3/50 = 0.94 (94% reduction).
    """
    if num_alerts == 0:
        return 0.0
    return 1.0 - (num_incidents / num_alerts)
