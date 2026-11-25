"""
Evaluation Harness Runner for Open-RBA (Phase 2 & 3).

Usage:
    python -m eval.run --alerts data/eval_alerts.jsonl --labels data/eval_labels.jsonl --out eval_out
    python -m eval.run --synthetic --queues 20 --seed 42 --out eval_out
"""

import csv
import json
import argparse
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from src.ingestion.wazuh_client import normalize_wazuh_alert
from src.ingestion.database import AlertDatabase
from src.correlation.engine import correlate_alerts, CorrelatedIncident, parse_timestamp
from src.enrichment.client import ThreatIntelClient
from src.attck.mapper import ATTACKMapper
from src.scoring.engine import RiskScoringEngine

from eval.synthetic import generate_synthetic_dataset
from eval.baselines import BASELINES
from eval.metrics import (
    build_attack_key_set,
    canonical_ts,
    is_incident_positive,
    precision_at_k,
    recall_at_k,
    first_true_rank,
    bootstrap_ci,
    spearman_rank_correlation,
)


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _partition_queues(
    alerts: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    window_hours: float = 0.0,
) -> List[Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """Partitions alerts & labels into independent evaluation queues."""
    # Prefer explicit queue_id from labels if present
    has_queue_ids = any("queue_id" in lbl and lbl["queue_id"] for lbl in labels)
    if has_queue_ids:
        lbl_by_key: Dict[Tuple[str, str, str, Optional[str]], str] = {}
        queues_lbl: Dict[str, List[Dict[str, Any]]] = {}
        for lbl in labels:
            qid = str(lbl.get("queue_id", "q_000"))
            queues_lbl.setdefault(qid, []).append(lbl)
            key = (
                canonical_ts(str(lbl["timestamp"])),
                str(lbl["rule_id"]),
                str(lbl["agent_name"]),
                lbl.get("src_ip") or None,
            )
            lbl_by_key[key] = qid

        queues_alerts: Dict[str, List[Dict[str, Any]]] = {qid: [] for qid in queues_lbl}
        for a in alerts:
            data = a.get("data", {}) if isinstance(a.get("data"), dict) else {}
            rule = a.get("rule", {}) if isinstance(a.get("rule"), dict) else {}
            agent = a.get("agent", {}) if isinstance(a.get("agent"), dict) else {}
            key = (
                canonical_ts(str(a.get("timestamp", ""))),
                str(rule.get("id", "0")),
                str(agent.get("name", "manager")),
                data.get("srcip") or data.get("src_ip") or None,
            )
            qid = lbl_by_key.get(key)
            if qid:
                queues_alerts.setdefault(qid, []).append(a)
        return [(qid, queues_alerts[qid], queues_lbl[qid]) for qid in sorted(queues_lbl.keys())]

    if window_hours and window_hours > 0:
        # Time-window partitioning for real lab recordings
        timed_alerts = sorted(alerts, key=lambda x: parse_timestamp(x["timestamp"]))
        if not timed_alerts:
            return []
        t0 = parse_timestamp(timed_alerts[0]["timestamp"])
        win_sec = window_hours * 3600.0
        q_alerts: Dict[int, List[Dict[str, Any]]] = {}
        q_labels: Dict[int, List[Dict[str, Any]]] = {}
        for a in timed_alerts:
            bucket = int((parse_timestamp(a["timestamp"]) - t0).total_seconds() // win_sec)
            q_alerts.setdefault(bucket, []).append(a)
        for lbl in labels:
            bucket = int((parse_timestamp(lbl["timestamp"]) - t0).total_seconds() // win_sec)
            q_labels.setdefault(bucket, []).append(lbl)
        return [(f"win_{b:03d}", q_alerts.get(b, []), q_labels.get(b, [])) for b in sorted(q_alerts.keys())]

    return [("queue_000", alerts, labels)]


def _prepare_queue(
    raw_alerts: List[Dict[str, Any]],
    db_path: str,
    window_seconds: int = 120,
    correlation_mode: str = "source_ip",
) -> Tuple[List[Dict[str, Any]], Dict[int, Dict[str, Any]], List[CorrelatedIncident]]:
    """Normalizes raw alerts via M1 and correlates them via M2."""
    db = AlertDatabase(db_path)
    norm_list = []
    for raw in raw_alerts:
        norm = normalize_wazuh_alert(raw)
        if norm:
            norm_list.append(norm)
    db.insert_batch(norm_list)
    db_alerts = db.fetch_all()
    alert_map = {a["id"]: a for a in db_alerts}
    incidents = correlate_alerts(db_alerts, window_seconds=window_seconds)
    return db_alerts, alert_map, incidents


def _evaluate_ranker(
    ranker_name: str,
    queue_data: List[Dict[str, Any]],
    rank_fn,
    seed: int = 42,
    n_bootstrap: int = 1000,
) -> Dict[str, Any]:
    p5_list: List[float] = []
    p10_list: List[float] = []
    p20_list: List[float] = []
    r10_list: List[float] = []
    r20_list: List[float] = []
    first_ranks: List[float] = []
    inc_counts: List[int] = []

    for q in queue_data:
        ranked_incidents = rank_fn(q)
        inc_counts.append(len(ranked_incidents))
        rels = [is_incident_positive(inc, q["alert_map"], q["attack_keys"]) for inc in ranked_incidents]
        p5_list.append(precision_at_k(rels, 5))
        p10_list.append(precision_at_k(rels, 10))
        p20_list.append(precision_at_k(rels, 20))
        r10 = recall_at_k(rels, 10)
        r20 = recall_at_k(rels, 20)
        if r10 is not None:
            r10_list.append(r10)
        if r20 is not None:
            r20_list.append(r20)
        ftr = first_true_rank(rels)
        if ftr is not None:
            first_ranks.append(float(ftr))

    p5_m, p5_lo, p5_hi = bootstrap_ci(p5_list, n_resamples=n_bootstrap, seed=seed)
    p10_m, p10_lo, p10_hi = bootstrap_ci(p10_list, n_resamples=n_bootstrap, seed=seed)
    p20_m, p20_lo, p20_hi = bootstrap_ci(p20_list, n_resamples=n_bootstrap, seed=seed)
    r10_m, _, _ = bootstrap_ci(r10_list, n_resamples=n_bootstrap, seed=seed)
    r20_m, _, _ = bootstrap_ci(r20_list, n_resamples=n_bootstrap, seed=seed)
    ftr_m, ftr_lo, ftr_hi = bootstrap_ci(first_ranks, n_resamples=n_bootstrap, seed=seed)

    return {
        "system": ranker_name,
        "queues": len(queue_data),
        "avg_incidents": round(sum(inc_counts) / max(1, len(inc_counts)), 1),
        "p5": round(p5_m, 4),
        "p5_ci_low": round(p5_lo, 4),
        "p5_ci_high": round(p5_hi, 4),
        "p10": round(p10_m, 4),
        "p10_ci_low": round(p10_lo, 4),
        "p10_ci_high": round(p10_hi, 4),
        "p20": round(p20_m, 4),
        "p20_ci_low": round(p20_lo, 4),
        "p20_ci_high": round(p20_hi, 4),
        "r10": round(r10_m, 4),
        "r20": round(r20_m, 4),
        "first_true_rank": round(ftr_m, 2),
        "first_true_ci_low": round(ftr_lo, 2),
        "first_true_ci_high": round(ftr_hi, 2),
    }


def _score_with_config(
    q: Dict[str, Any],
    weights_path: str,
    scoring_version: str = "v1",
    drop_factor: Optional[str] = None,
    weight_overrides: Optional[Dict[str, float]] = None,
    disable_asset_mult: bool = False,
) -> List[CorrelatedIncident]:
    eng = RiskScoringEngine(config_path=weights_path)
    if weight_overrides:
        w_sev = weight_overrides.get("severity", eng.w_sev)
        w_cti = weight_overrides.get("threat_intel", eng.w_cti)
        w_kc = weight_overrides.get("kill_chain", eng.w_kc)
        tot = w_sev + w_cti + w_kc
        eng.w_sev, eng.w_cti, eng.w_kc = w_sev / tot, w_cti / tot, w_kc / tot

    if drop_factor == "severity":
        eng.w_sev = 0.0
    elif drop_factor == "threat_intel":
        eng.w_cti = 0.0
    elif drop_factor == "kill_chain":
        eng.w_kc = 0.0
    if drop_factor in ("severity", "threat_intel", "kill_chain"):
        tot = eng.w_sev + eng.w_cti + eng.w_kc
        if tot > 0:
            eng.w_sev /= tot
            eng.w_cti /= tot
            eng.w_kc /= tot

    if disable_asset_mult:
        eng.asset_tiers = {k: 1.0 for k in eng.asset_tiers}
        eng.default_criticality = 1.0

    # Override version if engine supports v2
    if hasattr(eng, "scoring_version"):
        eng.scoring_version = scoring_version

    scored = eng.score_all(q["incidents"], q["cti_client"], q["mapper"])
    return [s.incident for s in scored]


def run_evaluation(
    alerts: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    mock_cti: Optional[Dict[str, Any]] = None,
    weights_path: str = "config/weights.yaml",
    versions: Optional[List[str]] = None,
    seed: int = 42,
    n_bootstrap: int = 1000,
    window_hours: float = 0.0,
) -> Dict[str, Any]:
    """Runs baselines, Open-RBA versions, factor ablations, and weight perturbations."""
    versions = versions or ["v1"]
    queues = _partition_queues(alerts, labels, window_hours=window_hours)
    base_engine = RiskScoringEngine(config_path=weights_path)
    win_sec = int(base_engine.config.get("correlation", {}).get("time_window_seconds", 120))
    mapper = ATTACKMapper()

    queue_data: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for qid, q_alerts, q_labels in queues:
            db_path = str(Path(tmpdir) / f"{qid}.db")
            _, alert_map, incidents = _prepare_queue(q_alerts, db_path, window_seconds=win_sec)
            cti_client = ThreatIntelClient(
                api_key=None,
                db_path=db_path,
                mock_data=mock_cti or {},
            )
            attack_keys = build_attack_key_set(q_labels)
            queue_data.append({
                "queue_id": qid,
                "alert_map": alert_map,
                "incidents": incidents,
                "cti_client": cti_client,
                "mapper": mapper,
                "attack_keys": attack_keys,
            })

    # 1. Evaluate 7 baselines
    main_rows: List[Dict[str, Any]] = []
    for name, fn in BASELINES.items():
        if name == "random":
            row = _evaluate_ranker(
                f"baseline:{name}",
                queue_data,
                lambda q, f=fn: f(q["incidents"], q["alert_map"], base_engine, seed=seed),
                seed=seed,
                n_bootstrap=n_bootstrap,
            )
        else:
            row = _evaluate_ranker(
                f"baseline:{name}",
                queue_data,
                lambda q, f=fn: f(q["incidents"], q["alert_map"], base_engine),
                seed=seed,
                n_bootstrap=n_bootstrap,
            )
        main_rows.append(row)

    # 2. Evaluate Open-RBA version(s)
    for ver in versions:
        row = _evaluate_ranker(
            f"open_rba:{ver}",
            queue_data,
            lambda q, v=ver: _score_with_config(q, weights_path, scoring_version=v),
            seed=seed,
            n_bootstrap=n_bootstrap,
        )
        main_rows.append(row)

    # 3. Ablations & Weight +/-20% Perturbations on the target version (latest requested)
    target_ver = versions[-1]
    ablation_rows: List[Dict[str, Any]] = []

    def _inc_uid(inc: CorrelatedIncident) -> str:
        first_aid = inc.alert_ids[0] if inc.alert_ids else 0
        return f"{inc.group_key}|{inc.first_seen}|{first_aid}"

    baseline_orders = [
        [_inc_uid(inc) for inc in _score_with_config(q, weights_path, scoring_version=target_ver)]
        for q in queue_data
    ]

    def _stability(mod_fn) -> float:
        corrs = []
        for q, ref_order in zip(queue_data, baseline_orders):
            mod_order = [_inc_uid(inc) for inc in mod_fn(q)]
            corrs.append(spearman_rank_correlation(ref_order, mod_order))
        return round(sum(corrs) / max(1, len(corrs)), 4)

    for factor in ("severity", "threat_intel", "kill_chain"):
        r = _evaluate_ranker(
            f"ablation:{target_ver}:drop_{factor}",
            queue_data,
            lambda q, fac=factor: _score_with_config(q, weights_path, scoring_version=target_ver, drop_factor=fac),
            seed=seed,
            n_bootstrap=n_bootstrap,
        )
        r["spearman_vs_full"] = _stability(lambda q, fac=factor: _score_with_config(q, weights_path, scoring_version=target_ver, drop_factor=fac))
        ablation_rows.append(r)

    r_no_asset = _evaluate_ranker(
        f"ablation:{target_ver}:drop_asset_mult",
        queue_data,
        lambda q: _score_with_config(q, weights_path, scoring_version=target_ver, disable_asset_mult=True),
        seed=seed,
        n_bootstrap=n_bootstrap,
    )
    r_no_asset["spearman_vs_full"] = _stability(lambda q: _score_with_config(q, weights_path, scoring_version=target_ver, disable_asset_mult=True))
    ablation_rows.append(r_no_asset)

    # +/-20% weight perturbations
    orig_w = {
        "severity": base_engine.w_sev,
        "threat_intel": base_engine.w_cti,
        "kill_chain": base_engine.w_kc,
    }
    for w_name, base_val in orig_w.items():
        for sign, mult in (("-20pct", 0.8), ("+20pct", 1.2)):
            ov = dict(orig_w)
            ov[w_name] = base_val * mult
            r_p = _evaluate_ranker(
                f"perturb:{target_ver}:{w_name}_{sign}",
                queue_data,
                lambda q, o=ov: _score_with_config(q, weights_path, scoring_version=target_ver, weight_overrides=o),
                seed=seed,
                n_bootstrap=n_bootstrap,
            )
            r_p["spearman_vs_full"] = _stability(lambda q, o=ov: _score_with_config(q, weights_path, scoring_version=target_ver, weight_overrides=o))
            ablation_rows.append(r_p)

    return {
        "main": main_rows,
        "ablations": ablation_rows,
        "queues_count": len(queue_data),
    }


def write_outputs(report: Dict[str, Any], out_dir: str) -> Tuple[Path, Path]:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_path = out_path / "results.csv"
    md_path = out_path / "results.md"

    all_rows = report["main"] + report["ablations"]
    fieldnames = [
        "system", "queues", "avg_incidents",
        "p5", "p5_ci_low", "p5_ci_high",
        "p10", "p10_ci_low", "p10_ci_high",
        "p20", "p20_ci_low", "p20_ci_high",
        "r10", "r20", "first_true_rank", "first_true_ci_low", "first_true_ci_high",
        "spearman_vs_full",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    md_lines = [
        f"# Open-RBA Evaluation Report ({report['queues_count']} queues)",
        "",
        "## Main Comparison (Macro-Averaged with 95% Bootstrap CIs)",
        "",
        "| System | P@5 (95% CI) | P@10 (95% CI) | P@20 (95% CI) | Recall@10 | Recall@20 | 1st True Rank |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in report["main"]:
        md_lines.append(
            f"| {r['system']} "
            f"| {r['p5']:.3f} [{r['p5_ci_low']:.3f}, {r['p5_ci_high']:.3f}] "
            f"| {r['p10']:.3f} [{r['p10_ci_low']:.3f}, {r['p10_ci_high']:.3f}] "
            f"| {r['p20']:.3f} [{r['p20_ci_low']:.3f}, {r['p20_ci_high']:.3f}] "
            f"| {r['r10']:.3f} | {r['r20']:.3f} | {r['first_true_rank']:.2f} |"
        )

    md_lines.extend([
        "",
        "## Ablations & ±20% Weight Perturbations",
        "",
        "| Variant | P@5 | P@10 | P@20 | Recall@10 | 1st True Rank | Spearman ρ |",
        "|---|---|---|---|---|---|---|",
    ])
    for r in report["ablations"]:
        md_lines.append(
            f"| {r['system']} | {r['p5']:.3f} | {r['p10']:.3f} | {r['p20']:.3f} "
            f"| {r['r10']:.3f} | {r['first_true_rank']:.2f} | {r.get('spearman_vs_full', '')} |"
        )

    md_text = "\n".join(md_lines) + "\n"
    md_path.write_text(md_text, encoding="utf-8")
    return md_path, csv_path


def main():
    parser = argparse.ArgumentParser(description="Run Open-RBA Incident Prioritization Evaluation Harness")
    parser.add_argument("--alerts", type=str, default=None, help="Path to alerts JSONL file")
    parser.add_argument("--labels", type=str, default=None, help="Path to ground-truth labels JSONL file")
    parser.add_argument("--cti", type=str, default=None, help="Optional mock CTI JSON file")
    parser.add_argument("--synthetic", action="store_true", help="Run on built-in seeded synthetic generator")
    parser.add_argument("--queues", type=int, default=20, help="Number of synthetic queues")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--bootstrap", type=int, default=1000, help="Bootstrap resamples")
    parser.add_argument("--window-hours", type=float, default=0.0, help="Split unlabeled queues by time window")
    parser.add_argument("--weights", type=str, default="config/weights.yaml", help="Weights YAML config")
    parser.add_argument("--versions", nargs="+", default=["v1"], help="Scoring versions to evaluate (e.g. v1 v2)")
    parser.add_argument("--out", type=str, default="eval_out", help="Output directory for results.md and results.csv")
    args = parser.parse_args()

    if args.synthetic:
        alerts, labels, mock_cti = generate_synthetic_dataset(num_queues=args.queues, seed=args.seed)
    elif args.alerts and args.labels:
        alerts = _load_jsonl(args.alerts)
        labels = _load_jsonl(args.labels)
        mock_cti = json.loads(Path(args.cti).read_text(encoding="utf-8")) if args.cti else {}
    else:
        parser.error("Provide either (--alerts and --labels) or --synthetic")
        return

    report = run_evaluation(
        alerts=alerts,
        labels=labels,
        mock_cti=mock_cti,
        weights_path=args.weights,
        versions=args.versions,
        seed=args.seed,
        n_bootstrap=args.bootstrap,
        window_hours=args.window_hours,
    )
    md_path, csv_path = write_outputs(report, args.out)
    print(md_path.read_text(encoding="utf-8"))
    print(f"Saved results to {md_path} and {csv_path}")


if __name__ == "__main__":
    main()
