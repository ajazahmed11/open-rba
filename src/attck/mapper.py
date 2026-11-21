"""
MITRE ATT&CK Mapping & Kill-Chain Progression Engine for Open-RBA (Module 4).

Maps security alert indicators and technique IDs into standard MITRE ATT&CK
tactics, evaluating tactical depth across the cyber intrusion lifecycle:
    Reconnaissance (Stage 1) -> Initial Access (Stage 2) -> ... -> Impact (Stage 10).

Provides behavioral heuristic inference for alerts missing explicit MITRE annotations.
"""

import re
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise Tactics & Chronological Stages
# ---------------------------------------------------------------------------

TACTIC_STAGES = {
    "Reconnaissance": 1,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 6,
    "Lateral Movement": 7,
    "Collection": 8,
    "Command and Control": 8,
    "Exfiltration": 9,
    "Impact": 10,
}

TACTIC_IDS = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# Standard mapping of common techniques to primary tactics
TECHNIQUE_MAP: Dict[str, Tuple[str, str]] = {
    "T1595": ("Reconnaissance", "Active Scanning"),
    "T1590": ("Reconnaissance", "Gather Victim Network Information"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1566": ("Initial Access", "Phishing"),
    "T1078": ("Initial Access", "Valid Accounts"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1203": ("Execution", "Exploitation for Client Execution"),
    "T1053": ("Persistence", "Scheduled Task/Job"),
    "T1136": ("Persistence", "Create Account"),
    "T1548": ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
    "T1068": ("Privilege Escalation", "Exploitation for Privilege Escalation"),
    "T1070": ("Defense Evasion", "Indicator Removal"),
    "T1562": ("Defense Evasion", "Impair Defenses"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1003": ("Credential Access", "OS Credential Dumping"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1082": ("Discovery", "System Information Discovery"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1005": ("Collection", "Data from Local System"),
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1485": ("Impact", "Data Destruction"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
}


@dataclass
class ATTACKProfile:
    """Evaluated tactical depth profile for an incident."""
    primary_technique: str
    primary_tactic: str
    tactic_id: str
    stage_depth: int           # Integer score from 1 (Recon) to 10 (Impact)
    normalized_depth: float    # Normalization mapped strictly to [0.1, 1.0]
    inferred: bool             # True if derived via heuristic fallback


class ATTACKMapper:
    """Maps alerts to MITRE ATT&CK taxonomy and computes kill-chain progression."""

    def __init__(self):
        self.technique_map = TECHNIQUE_MAP
        self.tactic_stages = TACTIC_STAGES

    def evaluate_incident(
        self,
        techniques: List[str],
        rule_description: str = "",
        rule_id: str = ""
    ) -> ATTACKProfile:
        """
        Determines the highest tactical depth reached by an incident.
        If explicit techniques are provided, evaluates their tactics.
        Otherwise, infers tactical category from rule description or ID.
        """
        candidates: List[Tuple[str, str, int, bool]] = []

        # 1. Evaluate explicit techniques
        for tech in techniques:
            base_tech = tech.split(".")[0].strip().upper()
            if base_tech in self.technique_map:
                tactic_name, _ = self.technique_map[base_tech]
                stage = self.tactic_stages.get(tactic_name, 1)
                candidates.append((base_tech, tactic_name, stage, False))

        # 2. Heuristic inference fallback if no known technique matched
        if not candidates:
            inferred_tech, inferred_tactic = self._infer_from_rule(rule_description, rule_id)
            stage = self.tactic_stages.get(inferred_tactic, 1)
            candidates.append((inferred_tech, inferred_tactic, stage, True))

        # Pick candidate with deepest kill-chain progression
        best = max(candidates, key=lambda c: c[2])
        tech, tactic, stage, inferred = best
        tactic_id = TACTIC_IDS.get(tactic, "TA0043")
        norm_depth = round(stage / 10.0, 2)

        return ATTACKProfile(
            primary_technique=tech,
            primary_tactic=tactic,
            tactic_id=tactic_id,
            stage_depth=stage,
            normalized_depth=norm_depth,
            inferred=inferred
        )

    def _infer_from_rule(self, description: str, rule_id: str) -> Tuple[str, str]:
        """Heuristic behavioral pattern matching for alerts lacking MITRE tags."""
        desc_lower = description.lower()

        if any(w in desc_lower for w in ["brute force", "failed login", "password", "authentication failed"]):
            return "T1110", "Credential Access"
        if any(w in desc_lower for w in ["sudo", "sudoers", "privilege", "root", "elevation"]):
            return "T1548", "Privilege Escalation"
        if any(w in desc_lower for w in ["traversal", "sql injection", "sqli", "xss", "web attack", "exploit"]):
            return "T1190", "Initial Access"
        if any(w in desc_lower for w in ["scan", "nmap", "reconnaissance", "port scan", "sweep"]):
            return "T1046", "Discovery"
        if any(w in desc_lower for w in ["tamper", "integrity", "log cleared", "audit"]):
            return "T1070", "Defense Evasion"
        if any(w in desc_lower for w in ["powershell", "bash", "command", "shell"]):
            return "T1059", "Execution"

        # Default fallback
        return f"rule:{rule_id}" if rule_id else "UNKNOWN", "Initial Access"
