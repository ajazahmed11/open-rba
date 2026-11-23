"""
MITRE ATT&CK Mapping & Intrusion Criticality Engine for Open-RBA (Module 4).

Maps security alert indicators and technique IDs into standard MITRE ATT&CK
tactics, evaluating tactical criticality across the intrusion lifecycle:
    Reconnaissance (Stage 1) -> Initial Access (Stage 4) -> ... -> Impact (Stage 10).

Provides behavioral heuristic inference using strict word boundaries to avoid
false positive heuristic mappings (e.g., distinguishing password change from brute force).
"""

import re
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise Tactics & Intrusion Criticality Stages (1 to 10)
# ---------------------------------------------------------------------------

TACTIC_STAGES = {
    "Reconnaissance": 1,        # Pre-attack probing (0.10)
    "Discovery": 2,             # Environment / network discovery (0.20)
    "Resource Development": 2,  # Infrastructure preparation (0.20)
    "Initial Access": 4,        # Perimeter breach / exploitation (0.40)
    "Execution": 5,             # Adversary code running on target (0.50)
    "Persistence": 6,           # Maintaining access (0.60)
    "Defense Evasion": 7,       # Evading detection / log tampering (0.70)
    "Credential Access": 8,     # Dumping credentials / brute force (0.80)
    "Lateral Movement": 8,      # Internal network pivoting (0.80)
    "Collection": 8,            # Staging internal target data (0.80)
    "Command and Control": 8,   # C2 channel established (0.80)
    "Privilege Escalation": 9,  # Root / Administrator compromise (0.90)
    "Exfiltration": 10,         # Stealing sensitive organizational data (1.00)
    "Impact": 10,               # Destruction / ransomware encryption (1.00)
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
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1082": ("Discovery", "System Information Discovery"),
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
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1005": ("Collection", "Data from Local System"),
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1485": ("Impact", "Data Destruction"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
}


@dataclass
class ATTACKProfile:
    """Evaluated tactical criticality profile for an incident."""
    primary_technique: str
    primary_tactic: str
    tactic_id: str
    stage_depth: int           # Criticality score from 1 (Recon) to 10 (Impact)
    normalized_depth: float    # Normalization mapped strictly to [0.1, 1.0]
    inferred: bool             # True if derived via heuristic fallback


class ATTACKMapper:
    """Maps alerts to MITRE ATT&CK taxonomy and computes intrusion criticality."""

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
        Determines the highest tactical criticality reached by an incident.
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

        # Pick candidate with deepest intrusion criticality
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
        """Strict word-boundary heuristic pattern matching for alerts lacking MITRE tags."""
        desc = description.lower()

        # Guard against negative findings and clean scan completions
        if re.search(r'\b(no|0|zero|clean)\s+(findings?|malware|rootkits?|threats?)\b|\bscan\s+completed\s+with\s+0\b|\b(0|zero)\s+findings\b', desc):
            return "T1082", "Discovery"

        # Check specific threats like rootkit or trojan before routine scan keywords
        if re.search(r'\b(rootkits?|trojans?|trojaned|backdoors?|malware)\b', desc):
            return "T1014", "Defense Evasion"

        # Guard against routine scan completions
        if re.search(r'\b(rootcheck|syscheck\s+scan)\b', desc):
            return "T1082", "Discovery"

        if re.search(r'\b(password\s+(changed|updated|reset))\b', desc):
            return "T1078", "Initial Access"

        if re.search(r'\b(sudoers?|privilege\s+escalation|elevation\s+of\s+privilege|gained\s+root)\b', desc):
            return "T1548", "Privilege Escalation"

        if re.search(r'\b(brute\s*force|failed\s+login|password\s+guessing|auth(entication)?\s+failed)\b', desc):
            return "T1110", "Credential Access"

        if re.search(r'\b(traversal|sql\s*injection|sqli|cross\s*site|xss|rce|remote\s+code|exploit)\b', desc):
            return "T1190", "Initial Access"

        if re.search(r'\b(nmap|port\s+scan|syn\s+scan|network\s+recon|service\s+scan)\b', desc):
            return "T1046", "Discovery"

        if re.search(r'\b(tamper|integrity|log\s+cleared|audit\s+log|defense\s+evasion)\b', desc):
            return "T1070", "Defense Evasion"

        if re.search(r'\b(powershell|bash|shell|exec(ute)?\s+command)\b', desc):
            return "T1059", "Execution"

        # Default fallback
        return f"rule:{rule_id}" if rule_id else "UNKNOWN", "Initial Access"
