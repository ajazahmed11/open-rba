"""
Wazuh Ingestion Client & Normalizer for Open-RBA.
Fetches alerts from the Wazuh REST API or local alert log files,
normalizes them into standardized NormalizedAlert records, and persists
them in SQLite for correlation and risk scoring.
"""

import json
import argparse
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.ingestion.database import AlertDatabase, NormalizedAlert


def normalize_wazuh_alert(raw: Dict[str, Any]) -> Optional[NormalizedAlert]:
    """
    Parses a raw Wazuh JSON alert dict into a standardized NormalizedAlert.
    Handles field variance across different rule decoders.
    """
    try:
        rule_block = raw.get("rule", {})
        rule_id = str(rule_block.get("id", "0"))
        rule_level = int(rule_block.get("level", 0))
        rule_desc = rule_block.get("description", "Unknown rule")

        agent_block = raw.get("agent", {})
        agent_name = agent_block.get("name", "manager")

        data_block = raw.get("data", {})
        src_ip = data_block.get("srcip") or data_block.get("src_ip")
        dst_ip = data_block.get("dstip") or data_block.get("dst_ip")
        user = data_block.get("dstuser") or data_block.get("srcuser") or data_block.get("user")
        process = data_block.get("process") or raw.get("program_name")

        # Extract MITRE ATT&CK technique IDs
        mitre_tactics = []
        mitre_block = rule_block.get("mitre", {})
        if isinstance(mitre_block, dict):
            raw_ids = mitre_block.get("id", [])
            if isinstance(raw_ids, list):
                mitre_tactics = [str(t) for t in raw_ids]
            elif isinstance(raw_ids, str):
                mitre_tactics = [raw_ids]

        timestamp = raw.get("timestamp", "")
        raw_json_str = json.dumps(raw)

        return NormalizedAlert(
            timestamp=timestamp,
            rule_id=rule_id,
            rule_level=rule_level,
            rule_description=rule_desc,
            agent_name=agent_name,
            src_ip=src_ip,
            dst_ip=dst_ip,
            user=user,
            process=process,
            mitre_tactics=mitre_tactics,
            raw_payload=raw_json_str
        )
    except Exception as e:
        print(f"[Warning] Failed to normalize alert: {e}", file=sys.stderr)
        return None


class WazuhClient:
    """Ingestion client capable of reading local log files or querying the REST API."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db = AlertDatabase(db_path)

    def ingest_from_file(self, file_path: str, limit: Optional[int] = None) -> int:
        """Reads a JSONL file (such as alerts.json) and inserts normalized rows.
        Duplicates are silently skipped via content_hash deduplication."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Alerts file not found: {file_path}")

        alerts: List[NormalizedAlert] = []
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                if limit and len(alerts) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    norm = normalize_wazuh_alert(data)
                    if norm:
                        alerts.append(norm)
                except json.JSONDecodeError:
                    continue

        count = self.db.insert_batch(alerts)
        return count

    def ingest_from_api(
        self,
        api_url: str,
        user: str,
        password: str,
        verify_ssl: bool = False,
        limit: int = 100
    ) -> int:
        """
        Authenticates against Wazuh REST API (:55000), fetches JWT token,
        and retrieves recent security alerts.
        """
        import urllib.request
        import ssl
        import base64

        # Step 1: Authenticate and get JWT token
        auth_url = f"{api_url.rstrip('/')}/security/user/authenticate"
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        cred_bytes = f"{user}:{password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(cred_bytes).decode('utf-8')}"

        req = urllib.request.Request(
            auth_url,
            method="POST",
            headers={"Authorization": auth_header, "Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                token_data = json.loads(resp.read().decode("utf-8"))
                jwt_token = token_data.get("data", {}).get("token")
        except Exception as e:
            raise ConnectionError(f"Wazuh API authentication failed: {e}")

        if not jwt_token:
            raise ConnectionError("Wazuh API returned empty JWT token")

        # Step 2: Fetch recent security alerts (not manager daemon logs)
        alerts_url = f"{api_url.rstrip('/')}/alerts?limit={limit}&sort=-timestamp"
        req_alerts = urllib.request.Request(
            alerts_url,
            method="GET",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )

        with urllib.request.urlopen(req_alerts, context=ctx, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("data", {}).get("affected_items", [])

        alerts: List[NormalizedAlert] = []
        for item in items:
            norm = normalize_wazuh_alert(item)
            if norm:
                alerts.append(norm)

        return self.db.insert_batch(alerts)


def main():
    parser = argparse.ArgumentParser(description="Open-RBA Wazuh Ingestion Client")
    parser.add_argument("--file", type=str, default="data/sample_alerts.json",
                        help="Path to JSONL alert log file to ingest")
    parser.add_argument("--api", action="store_true",
                        help="Ingest live alerts from Wazuh REST API")
    parser.add_argument("--last", type=int, default=100,
                        help="Maximum number of alerts to ingest/display")
    parser.add_argument("--db", type=str, default="data/alerts.db",
                        help="Target SQLite database path")

    args = parser.parse_args()
    client = WazuhClient(args.db)

    if args.api:
        api_url = os.getenv("WAZUH_API_URL", "https://localhost:55000")
        api_user = os.getenv("WAZUH_API_USER", "wazuh-wui")
        api_pass = os.getenv("WAZUH_API_PASSWORD", "")
        if not api_pass:
            print("[Error] WAZUH_API_PASSWORD environment variable not set.", file=sys.stderr)
            sys.exit(1)
        print(f"Connecting to Wazuh API at {api_url}...")
        count = client.ingest_from_api(api_url, api_user, api_pass, limit=args.last)
    else:
        print(f"Ingesting alerts from file: {args.file} (limit: {args.last})...")
        count = client.ingest_from_file(args.file, limit=args.last)

    total_in_db = client.db.count()
    print(f"✔ Ingested {count} new alert(s) ({total_in_db} total in database)")

    print("\nRecent Normalized Alerts:")
    print("-" * 90)
    print(f"{'TIMESTAMP':<24} {'RULE':<8} {'LVL':<4} {'HOST':<8} {'SRC IP':<16} {'MITRE':<15}")
    print("-" * 90)
    for a in client.db.fetch_recent(limit=min(10, args.last)):
        ts = a["timestamp"][:19] if a["timestamp"] else "N/A"
        mitre_str = ",".join(a["mitre_tactics"]) if a["mitre_tactics"] else "—"
        src = a["src_ip"] or "—"
        print(f"{ts:<24} {a['rule_id']:<8} {a['rule_level']:<4} {a['agent_name']:<8} {src:<16} {mitre_str:<15}")
    print("-" * 90)


if __name__ == "__main__":
    main()
