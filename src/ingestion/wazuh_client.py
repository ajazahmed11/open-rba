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
        
        # Rule level must be a valid integer
        raw_level = rule_block.get("level", 0)
        try:
            rule_level = int(raw_level)
        except (ValueError, TypeError):
            logger.warning(f"Invalid non-numeric rule level: {raw_level}")
            return None

        rule_desc = rule_block.get("description", "Unknown rule")

        agent_block = raw.get("agent", {})
        agent_name = agent_block.get("name") or "manager"

        data_block = raw.get("data", {})
        src_ip = data_block.get("srcip") or data_block.get("src_ip")
        dst_ip = data_block.get("dstip") or data_block.get("dst_ip")
        user = data_block.get("dstuser") or data_block.get("srcuser") or data_block.get("user")
        process = data_block.get("process") or raw.get("program_name")
        full_log = raw.get("full_log")

        # Extract MITRE ATT&CK technique IDs and tactic names
        mitre_tactics = []
        mitre_tactic_names = []
        mitre_block = rule_block.get("mitre", {})
        if isinstance(mitre_block, dict):
            raw_ids = mitre_block.get("id", [])
            if isinstance(raw_ids, list):
                mitre_tactics = [str(t) for t in raw_ids]
            elif isinstance(raw_ids, str):
                mitre_tactics = [raw_ids]

            raw_tactics = mitre_block.get("tactic", [])
            if isinstance(raw_tactics, list):
                mitre_tactic_names = [str(t) for t in raw_tactics]
            elif isinstance(raw_tactics, str):
                mitre_tactic_names = [raw_tactics]

        # Validate required timestamp and canonicalize to UTC ISO-8601
        timestamp = raw.get("timestamp")
        if not timestamp or not isinstance(timestamp, str) or not timestamp.strip():
            logger.warning("Alert missing valid ISO-8601 timestamp")
            return None
        try:
            from src.correlation.engine import parse_timestamp
            dt = parse_timestamp(timestamp)
            canonical_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
        except Exception as e:
            logger.warning(f"Alert has unparseable ISO-8601 timestamp {timestamp!r}: {e}")
            return None

        raw_json_str = json.dumps(raw, sort_keys=True)

        return NormalizedAlert(
            timestamp=canonical_ts,
            rule_id=rule_id,
            rule_level=rule_level,
            rule_description=rule_desc,
            agent_name=agent_name,
            src_ip=src_ip,
            dst_ip=dst_ip,
            user=user,
            process=process,
            mitre_tactics=mitre_tactics,
            raw_payload=raw_json_str,
            full_log=full_log,
            mitre_tactic_names=mitre_tactic_names
        )
    except Exception as e:
        logger.warning(f"Failed to normalize alert: {e}")
        return None


class WazuhClient:
    """Ingestion client capable of reading local log files or querying OpenSearch/Wazuh."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db = AlertDatabase(db_path)

    def ingest_from_file(self, file_path: str, limit: Optional[int] = None) -> int:
        """Reads a JSONL or JSON array file (such as alerts.json) and inserts normalized rows.
        When limit is specified, reads the most recent N lines/objects (tailing the file).
        Duplicates are skipped via content_hash deduplication."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Alerts file not found: {file_path}")

        alerts: List[NormalizedAlert] = []
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return 0

        # Handle standard JSON array format: [ {...}, {...} ]
        if content.startswith("[") and content.endswith("]"):
            try:
                data_list = json.loads(content)
                if isinstance(data_list, list):
                    if limit:
                        data_list = data_list[-limit:]
                    for item in data_list:
                        if isinstance(item, dict):
                            norm = normalize_wazuh_alert(item)
                            if norm:
                                alerts.append(norm)
                            else:
                                self.db.record_dead_letter(
                                    json.dumps(item, sort_keys=True),
                                    "NormalizationError: Malformed schema or invalid timestamp/rule level"
                                )
                        else:
                            self.db.record_dead_letter(str(item), "NormalizationError: Non-dict item in JSON array")
                    return self.db.insert_batch(alerts)
            except json.JSONDecodeError:
                pass  # Fall through to line-by-line JSONL parser

        # Handle standard line-by-line JSONL format
        lines = content.splitlines()
        if limit:
            lines = lines[-limit:]

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                norm = normalize_wazuh_alert(data)
                if norm:
                    alerts.append(norm)
                else:
                    self.db.record_dead_letter(line, "NormalizationError: Malformed schema or non-numeric rule level")
            except json.JSONDecodeError as e:
                self.db.record_dead_letter(line, f"JSONDecodeError: {e}")
                continue

        count = self.db.insert_batch(alerts)
        return count

    def ingest_from_indexer(
        self,
        indexer_url: str = "https://localhost:9200",
        index_pattern: str = "wazuh-alerts-*",
        user: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        limit: int = 100,
        page_size: int = 100
    ) -> int:
        """
        Queries Wazuh Indexer (OpenSearch / Elasticsearch) on port :9200
        where historical security alerts are actually stored and indexed.
        Supports time checkpointing and secure credential management.
        """
        import urllib.request
        import ssl
        import base64

        auth_user = user or os.getenv("WAZUH_INDEXER_USER")
        auth_pass = password or os.getenv("WAZUH_INDEXER_PASSWORD")
        if not auth_user or not auth_pass:
            raise ValueError(
                "Wazuh Indexer credentials required. Set WAZUH_INDEXER_USER and "
                "WAZUH_INDEXER_PASSWORD or pass user/password parameters."
            )

        if verify_ssl is None:
            # Default verify_ssl to True for security unless explicitly set to false
            verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "true").lower() in ("true", "1", "yes")

        search_url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        cred_bytes = f"{auth_user}:{auth_pass}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(cred_bytes).decode('utf-8')}"

        # Incremental checkpointing keyed per (url, index_pattern)
        checkpoint_key = f"{indexer_url.rstrip('/')}/{index_pattern}"
        checkpoint = self.db.get_checkpoint(checkpoint_key)

        if checkpoint:
            query_filter = {"range": {"timestamp": {"gte": checkpoint}}}
        else:
            query_filter = {"match_all": {}}

        alerts: List[NormalizedAlert] = []
        max_ts = checkpoint
        total_fetched = 0
        search_after = None

        while total_fetched < limit:
            batch_size = min(page_size, limit - total_fetched)
            query_body: Dict[str, Any] = {
                "size": batch_size,
                "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
                "query": query_filter
            }
            if search_after:
                query_body["search_after"] = search_after

            query_payload = json.dumps(query_body).encode("utf-8")
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

            if not hits:
                break

            for hit in hits:
                source = hit.get("_source", {})
                norm = normalize_wazuh_alert(source)
                if norm:
                    alerts.append(norm)
                    if not max_ts or norm.timestamp > max_ts:
                        max_ts = norm.timestamp
                else:
                    self.db.record_dead_letter(
                        json.dumps(source, sort_keys=True),
                        "NormalizationError: Malformed indexer alert schema or timestamp"
                    )

            total_fetched += len(hits)
            search_after = hits[-1].get("sort")
            if not search_after or len(hits) < batch_size:
                break

        # Advance checkpoint only after batch insert completes successfully
        inserted = self.db.insert_batch(alerts)
        if max_ts and alerts:
            self.db.set_checkpoint(checkpoint_key, max_ts)

        return inserted

    def fetch_agent_inventory(
        self,
        api_url: str = "https://localhost:55000",
        user: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves agent inventory metadata from Wazuh management API (:55000)
        to assist in dynamic asset tier categorization.
        """
        import urllib.request
        import ssl
        import base64

        auth_user = user if user is not None else os.getenv("WAZUH_API_USER", "wazuh-wui")
        auth_pass = password if password is not None else os.getenv("WAZUH_API_PASSWORD")
        if not auth_pass:
            raise ValueError("WAZUH_API_PASSWORD required for management API access")

        if verify_ssl is None:
            verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "true").lower() in ("true", "1", "yes")

        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Authenticate with Wazuh management API
        auth_url = f"{api_url.rstrip('/')}/security/user/authenticate"
        cred_bytes = f"{auth_user}:{auth_pass}".encode("utf-8")
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
            raise ConnectionError("Wazuh API authentication succeeded but no JWT token returned")

        # Fetch agents list
        agents_url = f"{api_url.rstrip('/')}/agents?limit=500"
        req_agents = urllib.request.Request(
            agents_url,
            method="GET",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )

        try:
            with urllib.request.urlopen(req_agents, context=ctx, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            raise ConnectionError(f"Failed to fetch Wazuh agent inventory: {e}")


def main():
    parser = argparse.ArgumentParser(description="Open-RBA Wazuh Ingestion Client")
    parser.add_argument("--file", type=str, default="data/sample_alerts.json",
                        help="Path to JSONL alert log file to ingest")
    parser.add_argument("--indexer", nargs="?", const="default", default=None,
                        help="Ingest alerts from Wazuh OpenSearch Indexer (:9200), optional custom URL")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification for local/testing indexer")
    parser.add_argument("--last", type=int, default=100,
                        help="Maximum number of alerts to ingest/display")
    parser.add_argument("--db", type=str, default="data/alerts.db",
                        help="Target SQLite database path")

    args = parser.parse_args()
    client = WazuhClient(args.db)

    verify_ssl = not args.insecure and (os.getenv("WAZUH_VERIFY_SSL", "true").lower() in ("true", "1", "yes"))

    if args.indexer is not None:
        idx_url = args.indexer if args.indexer != "default" else os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        print(f"Querying Wazuh Indexer at {idx_url} (limit: {args.last})...")
        try:
            count = client.ingest_from_indexer(idx_url, verify_ssl=verify_ssl, limit=args.last)
        except Exception as e:
            print(f"[Error] Failed to connect to Wazuh Indexer at {idx_url}: {e}", file=sys.stderr)
            print("        Ensure WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD are set.", file=sys.stderr)
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

