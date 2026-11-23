"""
Wazuh Ingestion Client & Normalizer for Open-RBA.
Fetches alerts from local alert log files (e.g. /var/ossec/logs/alerts/alerts.json),
the Wazuh OpenSearch Indexer (:9200), or Wazuh API, normalizes them into standardized
NormalizedAlert records, and persists them in SQLite for correlation and risk scoring.
"""

import json
import argparse
import sys
import os
import logging
from collections import deque
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.ingestion.database import AlertDatabase, NormalizedAlert

logger = logging.getLogger(__name__)


def normalize_wazuh_alert(raw: Dict[str, Any]) -> Optional[NormalizedAlert]:
    """
    Parses a raw Wazuh JSON alert dict into a standardized NormalizedAlert.
    Handles field variance across different rule decoders and event sources.
    """
    try:
        rule_block = raw.get("rule", {})
        rule_id = str(rule_block.get("id", "0"))
        rule_level = int(rule_block.get("level", 0))
        rule_desc = rule_block.get("description", "Unknown rule")

        agent_block = raw.get("agent", {})
        agent_name = agent_block.get("name") or "manager"

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
        logger.warning(f"Failed to normalize alert: {e}")
        return None


class WazuhClient:
    """Ingestion client capable of reading local log files or querying OpenSearch/Wazuh."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db = AlertDatabase(db_path)

    def ingest_from_file(self, file_path: str, limit: Optional[int] = None) -> int:
        """Reads a JSONL file (such as alerts.json) and inserts normalized rows.
        When limit is specified, reads the most recent N lines (tailing the file).
        Duplicates are skipped via content_hash deduplication."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Alerts file not found: {file_path}")

        alerts: List[NormalizedAlert] = []
        with open(path, "r", encoding="utf-8") as f:
            if limit:
                # Tail the newest `limit` lines from the log file
                lines = deque(f, maxlen=limit)
            else:
                lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                norm = normalize_wazuh_alert(data)
                if norm:
                    alerts.append(norm)
            except json.JSONDecodeError as e:
                self.db.record_dead_letter(line, f"JSONDecodeError: {e}")
                continue

        count = self.db.insert_batch(alerts)
        return count

    def ingest_from_indexer(
        self,
        indexer_url: str = "https://localhost:9200",
        index_pattern: str = "wazuh-alerts-*",
        user: str = "admin",
        password: str = "admin",
        verify_ssl: Optional[bool] = None,
        limit: int = 100
    ) -> int:
        """
        Queries Wazuh Indexer (OpenSearch / Elasticsearch) on port :9200
        where historical security alerts are actually stored and indexed.
        """
        import urllib.request
        import ssl
        import base64

        if verify_ssl is None:
            verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        search_url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        cred_bytes = f"{user}:{password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(cred_bytes).decode('utf-8')}"

        query_payload = json.dumps({
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}}
        }).encode("utf-8")

        req = urllib.request.Request(
            search_url,
            data=query_payload,
            method="POST",
            headers={"Authorization": auth_header, "Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                hits = data.get("hits", {}).get("hits", [])
        except Exception as e:
            raise ConnectionError(f"Wazuh Indexer query failed: {e}")

        alerts: List[NormalizedAlert] = []
        for hit in hits:
            source = hit.get("_source", {})
            norm = normalize_wazuh_alert(source)
            if norm:
                alerts.append(norm)

        return self.db.insert_batch(alerts)

    def ingest_from_api(
        self,
        api_url: str,
        user: str,
        password: str,
        verify_ssl: Optional[bool] = None,
        limit: int = 100
    ) -> int:
        """
        Connects to Wazuh REST API (:55000).
        Note: Wazuh 4.x+ REST API manages agents and configurations; security alerts
        are indexed directly in the Wazuh Indexer (:9200) or logged to alerts.json.
        """
        import urllib.request
        import ssl
        import base64

        if verify_ssl is None:
            verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

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

        # Step 2: Attempt fetching alerts endpoint (if configured / custom proxy)
        alerts_url = f"{api_url.rstrip('/')}/alerts?limit={limit}&sort=-timestamp"
        req_alerts = urllib.request.Request(
            alerts_url,
            method="GET",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )

        try:
            with urllib.request.urlopen(req_alerts, context=ctx, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                items = data.get("data", {}).get("affected_items", [])
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotImplementedError(
                    "Wazuh REST API on port :55000 does not expose a native /alerts endpoint. "
                    "Use ingest_from_indexer() to query OpenSearch (:9200/wazuh-alerts-*) or "
                    "ingest_from_file() to read /var/ossec/logs/alerts/alerts.json."
                ) from e
            raise

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
    parser.add_argument("--indexer", nargs="?", const="default", default=None,
                        help="Ingest alerts from Wazuh OpenSearch Indexer (:9200), optional custom URL")
    parser.add_argument("--api", nargs="?", const="default", default=None,
                        help="Ingest alerts from Wazuh REST API (:55000), optional custom URL")
    parser.add_argument("--last", type=int, default=100,
                        help="Maximum number of alerts to ingest/display")
    parser.add_argument("--db", type=str, default="data/alerts.db",
                        help="Target SQLite database path")

    args = parser.parse_args()
    client = WazuhClient(args.db)

    verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    if args.indexer is not None:
        idx_url = args.indexer if args.indexer != "default" else os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        idx_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        idx_pass = os.getenv("WAZUH_INDEXER_PASSWORD", "admin")
        print(f"Querying Wazuh Indexer at {idx_url} (limit: {args.last})...")
        try:
            count = client.ingest_from_indexer(idx_url, user=idx_user, password=idx_pass,
                                               verify_ssl=verify_ssl, limit=args.last)
        except Exception as e:
            print(f"[Error] Failed to connect to Wazuh Indexer at {idx_url}: {e}", file=sys.stderr)
            print("        Ensure Wazuh OpenSearch Indexer (:9200) is running or configure WAZUH_INDEXER_URL.", file=sys.stderr)
            sys.exit(1)
    elif args.api is not None:
        api_url = args.api if args.api != "default" else os.getenv("WAZUH_API_URL", "https://localhost:55000")
        api_user = os.getenv("WAZUH_API_USER", "wazuh-wui")
        api_pass = os.getenv("WAZUH_API_PASSWORD", "")
        if not api_pass:
            print("[Error] WAZUH_API_PASSWORD environment variable not set.", file=sys.stderr)
            sys.exit(1)
        print(f"Connecting to Wazuh API at {api_url}...")
        try:
            count = client.ingest_from_api(api_url, api_user, api_pass, verify_ssl=verify_ssl, limit=args.last)
        except Exception as e:
            print(f"[Error] Failed to connect to Wazuh API at {api_url}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Ingesting newest alerts from file: {args.file} (limit: {args.last})...")
        try:
            count = client.ingest_from_file(args.file, limit=args.last)
        except Exception as e:
            print(f"[Error] Failed to ingest alerts from file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

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

