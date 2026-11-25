"""
Deterministic Synthetic Telemetry & Ground-Truth Label Generator for Open-RBA CI.

Generates multi-queue Wazuh-formatted alerts mixing realistic benign operational
noise (routine logins, package updates with benign FIM changes, cron jobs,
internal health probes, noisy low-severity internet scanners) with scripted
multi-stage attacks (SSH brute-force + success, IP-rotating password sprays,
port scans, web SQLi/traversal exploits, sudoers escalation, rootkit detection).

For CI and reproducible evaluation only — real thesis experiments use the Kali
lab recording protocol documented in README.md.
"""

import json
import random
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional


HOSTS = ["web01", "db01", "fedora01", "app01", "worker01", "test-db01", "backup01"]


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _make_wazuh_alert(
    ts: datetime,
    rule_id: str,
    level: int,
    description: str,
    agent_name: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    user: Optional[str] = None,
    process: Optional[str] = None,
    mitre_ids: Optional[List[str]] = None,
    mitre_tactics: Optional[List[str]] = None,
    full_log: Optional[str] = None,
) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
        "id": rule_id,
        "level": level,
        "description": description,
    }
    if mitre_ids or mitre_tactics:
        rule["mitre"] = {}
        if mitre_ids:
            rule["mitre"]["id"] = mitre_ids
        if mitre_tactics:
            rule["mitre"]["tactic"] = mitre_tactics

    data: Dict[str, Any] = {}
    if src_ip:
        data["srcip"] = src_ip
    if dst_ip:
        data["dstip"] = dst_ip
    if user:
        data["dstuser"] = user
    if process:
        data["process"] = process

    alert: Dict[str, Any] = {
        "timestamp": _fmt_ts(ts),
        "rule": rule,
        "agent": {"name": agent_name},
        "data": data,
    }
    if full_log:
        alert["full_log"] = full_log
    return alert


def generate_queue(queue_idx: int, rng: random.Random, base_time: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Generates one synthetic evaluation queue of benign + attack Wazuh alerts."""
    alerts: List[Dict[str, Any]] = []
    labels: List[Dict[str, Any]] = []
    mock_cti: Dict[str, Any] = {}

    queue_id = f"q_{queue_idx:03d}"
    q_start = base_time + timedelta(hours=queue_idx * 4)

    def emit(raw_alert: Dict[str, Any], label: str, attack_id: Optional[str]) -> None:
        alerts.append(raw_alert)
        data = raw_alert.get("data", {})
        labels.append({
            "queue_id": queue_id,
            "timestamp": raw_alert["timestamp"],
            "rule_id": str(raw_alert["rule"]["id"]),
            "agent_name": raw_alert["agent"]["name"],
            "src_ip": data.get("srcip"),
            "label": label,
            "attack_id": attack_id,
        })

    # --- 1. Benign background noise (~25-35 distinct incidents across ~80-110 alerts) ---
    # Routine admin SSH logins from internal subnet
    for i in range(rng.randint(6, 10)):
        host = rng.choice(["web01", "db01", "fedora01", "app01", "worker01"])
        t = q_start + timedelta(minutes=rng.randint(1, 180), seconds=rng.randint(0, 59))
        emit(
            _make_wazuh_alert(
                t, "5715", 3, "sshd: authentication success.",
                host, src_ip=f"10.0.1.{rng.randint(10, 30)}",
                user=rng.choice(["deploy", "ops", "backup"]),
                mitre_ids=["T1078"], mitre_tactics=["Initial Access"],
                full_log=f"Accepted publickey for ops from 10.0.1.15 #{i}"
            ),
            "benign", None
        )

    # Routine cron jobs & systemd maintenance
    for i in range(rng.randint(6, 10)):
        host = rng.choice(HOSTS)
        t = q_start + timedelta(minutes=rng.randint(1, 180), seconds=rng.randint(0, 59))
        emit(
            _make_wazuh_alert(
                t, "5501", 3, "PAM: Login session opened.",
                host, user="root", process="cron",
                full_log=f"pam_unix(cron:session): session opened for user root #{i}"
            ),
            "benign", None
        )

    # Package updates triggering benign FIM checksum changes (often level 7 in Wazuh!)
    for i in range(rng.randint(5, 8)):
        host = rng.choice(["web01", "db01", "app01", "fedora01"])
        t_base = q_start + timedelta(minutes=rng.randint(5, 170))
        emit(
            _make_wazuh_alert(
                t_base, "2902", 7, "New dpkg package installed.",
                host, process="apt",
                full_log=f"status installed libc6:amd64 update #{i}"
            ),
            "benign", None
        )
        emit(
            _make_wazuh_alert(
                t_base + timedelta(seconds=rng.randint(2, 15)), "550", 7,
                "Integrity checksum changed.",
                host, process="syscheck",
                full_log=f"Integrity checksum changed for: '/usr/lib/libssl.so.3' #{i}"
            ),
            "benign", None
        )

    # Routine rootcheck clean scans (benign, level 4)
    for i in range(rng.randint(2, 4)):
        host = rng.choice(["web01", "db01", "fedora01"])
        t = q_start + timedelta(minutes=rng.randint(1, 180))
        emit(
            _make_wazuh_alert(
                t, "510", 4, "Rootcheck: scan completed with 0 findings.",
                host, full_log=f"Starting rootcheck scan, 0 findings #{i}"
            ),
            "benign", None
        )

    # Background Internet scanner noise (known bad IP on AbuseIPDB, high-level IDS/SSH noise on test/low hosts or blocked port probes)
    for i in range(rng.randint(6, 9)):
        scanner_ip = f"198.51.100.{rng.randint(10, 40)}"
        mock_cti[scanner_ip] = {
            "score": float(rng.randint(55, 95)),
            "last_reported_at": _fmt_ts(q_start - timedelta(days=rng.randint(1, 10))),
        }
        host = rng.choice(["test-db01", "worker01", "backup01"])
        t = q_start + timedelta(minutes=rng.randint(1, 180), seconds=rng.randint(0, 59))
        # Repeat a noisy blocked connection burst on low-value hosts
        for j in range(rng.randint(3, 6)):
            emit(
                _make_wazuh_alert(
                    t + timedelta(seconds=j * 2), "5710", 5,
                    "sshd: Attempt to login using a non-existent user",
                    host, src_ip=scanner_ip, user=f"user{j}",
                    mitre_ids=["T1110.001"], mitre_tactics=["Credential Access"],
                    full_log=f"Invalid user user{j} from {scanner_ip} #{i}_{j}"
                ),
                "benign", None
            )

    # Noisy recurring benign application warning on critical/high hosts (tests rarity / volume damping)
    noisy_ip = f"192.0.2.{rng.randint(10, 50)}"
    mock_cti[noisy_ip] = {
        "score": float(rng.randint(25, 45)),
        "last_reported_at": _fmt_ts(q_start - timedelta(days=5)),
    }
    for i in range(rng.randint(4, 7)):
        t = q_start + timedelta(minutes=i * 15, seconds=rng.randint(0, 30))
        emit(
            _make_wazuh_alert(
                t, "31101", 5, "Web server 400 error code (health check / crawler).",
                "web01", src_ip=noisy_ip,
                full_log=f"GET /favicon.ico 404 from {noisy_ip} #{i}"
            ),
            "benign", None
        )

    # --- 2. Scripted Multi-Stage Attacks (3 to 5 attack campaigns per queue) ---
    # Attack A: SSH brute force -> authentication success on high/critical host (from a FRESH unreported external IP!)
    atk_a_ip = f"203.0.113.{rng.randint(10, 99)}"
    # Fresh attacker IP: score=0 on AbuseIPDB (tests clean-IP penalty bug in v1)
    mock_cti[atk_a_ip] = {
        "score": 0.0,
        "last_reported_at": _fmt_ts(q_start - timedelta(days=1)),
    }
    atk_a_host = rng.choice(["web01", "db01"])
    t_a = q_start + timedelta(minutes=rng.randint(5, 175))
    for j in range(rng.randint(5, 10)):
        emit(
            _make_wazuh_alert(
                t_a + timedelta(seconds=j * 3), "5710", 5,
                "sshd: Attempt to login using a non-existent user",
                atk_a_host, src_ip=atk_a_ip, user=rng.choice(["admin", "root", "ubuntu"]),
                mitre_ids=["T1110.001"], mitre_tactics=["Credential Access"],
                full_log=f"Failed password for root from {atk_a_ip} seq={j}"
            ),
            "attack", f"{queue_id}_ssh_compromise"
        )
    # Escalate to successful login within 2 minutes
    emit(
        _make_wazuh_alert(
            t_a + timedelta(seconds=45), "5715", 8,
            "sshd: authentication success.",
            atk_a_host, src_ip=atk_a_ip, user="ubuntu",
            mitre_ids=["T1078"], mitre_tactics=["Initial Access"],
            full_log=f"Accepted password for ubuntu from {atk_a_ip}"
        ),
        "attack", f"{queue_id}_ssh_compromise"
    )
    # Post-compromise sudoers modification within 10 minutes
    emit(
        _make_wazuh_alert(
            t_a + timedelta(minutes=3), "100100", 12,
            "FIM: Sudoers file was modified (T1548.003)",
            atk_a_host, process="visudo", user="ubuntu",
            mitre_ids=["T1548.003"], mitre_tactics=["Privilege Escalation"],
            full_log="Checksum changed on /etc/sudoers by ubuntu"
        ),
        "attack", f"{queue_id}_ssh_compromise"
    )

    # Attack B: Public-facing Web Application SQLi / Path Traversal exploit (T1190, fresh IP)
    atk_b_ip = f"203.0.113.{rng.randint(100, 180)}"
    mock_cti[atk_b_ip] = {
        "score": float(rng.choice([0, 0, 75])),
        "last_reported_at": _fmt_ts(q_start - timedelta(days=2)),
    }
    t_b = q_start + timedelta(minutes=rng.randint(5, 175))
    emit(
        _make_wazuh_alert(
            t_b, "100130", 10,
            "Snort IDS: Web Application Attack (SQL Injection / Directory Traversal)",
            "web01", src_ip=atk_b_ip, dst_ip="192.168.1.10",
            mitre_ids=["T1190"], mitre_tactics=["Initial Access"],
            full_log=f"GET /api/users?id=1' UNION SELECT * FROM users-- from {atk_b_ip}"
        ),
        "attack", f"{queue_id}_web_sqli"
    )
    emit(
        _make_wazuh_alert(
            t_b + timedelta(seconds=20), "100140", 11,
            "Command execution attempted via web shell (bash -c)",
            "web01", src_ip=atk_b_ip, user="www-data", process="bash",
            mitre_ids=["T1059"], mitre_tactics=["Execution"],
            full_log="www-data spawned /bin/bash -c id"
        ),
        "attack", f"{queue_id}_web_sqli"
    )

    # Attack C: Distributed IP-rotating credential spray against db01 (8 different IPs, 1-2 alerts each)
    t_c = q_start + timedelta(minutes=rng.randint(5, 175))
    spray_base = rng.randint(190, 230)
    for j in range(6):
        sip = f"203.0.113.{spray_base + j}"
        mock_cti[sip] = {
            "score": float(rng.randint(10, 40)),
            "last_reported_at": _fmt_ts(q_start - timedelta(days=1)),
        }
        emit(
            _make_wazuh_alert(
                t_c + timedelta(seconds=j * 8), "5710", 6,
                "sshd: Attempt to login using a non-existent user",
                "db01", src_ip=sip, user="postgres",
                mitre_ids=["T1110.001"], mitre_tactics=["Credential Access"],
                full_log=f"Failed password for postgres from {sip} spray={j}"
            ),
            "attack", f"{queue_id}_distributed_spray"
        )

    # Attack D (optional ~70% of queues): Rootkit / defense evasion or port scan -> exploit
    if rng.random() < 0.75:
        t_d = q_start + timedelta(minutes=rng.randint(5, 175))
        d_host = rng.choice(["db01", "app01"])
        emit(
            _make_wazuh_alert(
                t_d, "510", 11,
                "Rootcheck: rootkit detected by presence of hidden file",
                d_host, mitre_ids=["T1014"], mitre_tactics=["Defense Evasion"],
                full_log="Hidden kernel module /dev/.hidden_rk detected"
            ),
            "attack", f"{queue_id}_rootkit"
        )

    # Sort alerts chronologically so queues simulate stream arrival
    paired = sorted(zip(alerts, labels), key=lambda pair: pair[0]["timestamp"])
    sorted_alerts = [p[0] for p in paired]
    sorted_labels = [p[1] for p in paired]
    return sorted_alerts, sorted_labels, mock_cti


def generate_synthetic_dataset(
    num_queues: int = 20,
    seed: int = 42,
    base_time: Optional[datetime] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Generates a deterministic multi-queue benchmark dataset."""
    rng = random.Random(seed)
    start_dt = base_time or datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

    all_alerts: List[Dict[str, Any]] = []
    all_labels: List[Dict[str, Any]] = []
    all_cti: Dict[str, Any] = {}

    for q_idx in range(num_queues):
        q_alerts, q_labels, q_cti = generate_queue(q_idx, rng, start_dt)
        all_alerts.extend(q_alerts)
        all_labels.extend(q_labels)
        all_cti.update(q_cti)

    return all_alerts, all_labels, all_cti


def main():
    parser = argparse.ArgumentParser(description="Generate seeded synthetic Wazuh telemetry + ground-truth labels")
    parser.add_argument("--queues", type=int, default=20, help="Number of evaluation queues")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--out-alerts", type=str, required=True, help="Output alerts JSONL path")
    parser.add_argument("--out-labels", type=str, required=True, help="Output labels JSONL path")
    parser.add_argument("--out-cti", type=str, default=None, help="Optional output mock CTI JSON path")
    args = parser.parse_args()

    alerts, labels, cti = generate_synthetic_dataset(num_queues=args.queues, seed=args.seed)

    Path(args.out_alerts).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_labels).parent.mkdir(parents=True, exist_ok=True)

    with open(args.out_alerts, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

    with open(args.out_labels, "w", encoding="utf-8") as f:
        for lbl in labels:
            f.write(json.dumps(lbl) + "\n")

    if args.out_cti:
        Path(args.out_cti).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_cti, "w", encoding="utf-8") as f:
            json.dump(cti, f, indent=2)

    print(f"Generated {len(alerts)} alerts and {len(labels)} labels across {args.queues} queues (seed={args.seed}).")


if __name__ == "__main__":
    main()
