"""
Unit and Integration Tests for Open-RBA Evaluation Harness (Phase 2).
"""

import json
import csv
import subprocess
import sys
from pathlib import Path

from eval.synthetic import generate_synthetic_dataset
from eval.metrics import precision_at_k, recall_at_k, first_true_rank, bootstrap_ci, spearman_rank_correlation
from eval.run import run_evaluation, write_outputs


def test_synthetic_generator_deterministic_and_balanced():
    a1, l1, c1 = generate_synthetic_dataset(num_queues=3, seed=123)
    a2, l2, c2 = generate_synthetic_dataset(num_queues=3, seed=123)
    assert a1 == a2
    assert l1 == l2
    assert c1 == c2

    attack_count = sum(1 for lbl in l1 if lbl["label"] == "attack")
    benign_count = sum(1 for lbl in l1 if lbl["label"] == "benign")
    assert attack_count > 10
    assert benign_count > 50


def test_metrics_and_bootstrap_ci():
    rels = [True, False, True, False, False]
    assert precision_at_k(rels, 5) == 0.4
    assert recall_at_k(rels, 5) == 1.0
    assert first_true_rank(rels) == 1
    assert first_true_rank([False, False, True]) == 3

    mean, lo, hi = bootstrap_ci([0.2, 0.4, 0.6, 0.8], n_resamples=200, seed=42)
    assert lo <= mean <= hi
    assert abs(spearman_rank_correlation(["a", "b", "c"], ["a", "b", "c"]) - 1.0) < 1e-9


def test_evaluation_harness_end_to_end_cli(tmp_path):
    alerts, labels, cti = generate_synthetic_dataset(num_queues=5, seed=42)
    alerts_file = tmp_path / "alerts.jsonl"
    labels_file = tmp_path / "labels.jsonl"
    cti_file = tmp_path / "cti.json"
    out_dir = tmp_path / "eval_out"

    alerts_file.write_text("\n".join(json.dumps(a) for a in alerts) + "\n", encoding="utf-8")
    labels_file.write_text("\n".join(json.dumps(l) for l in labels) + "\n", encoding="utf-8")
    cti_file.write_text(json.dumps(cti), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable, "-m", "eval.run",
            "--alerts", str(alerts_file),
            "--labels", str(labels_file),
            "--cti", str(cti_file),
            "--out", str(out_dir),
            "--bootstrap", "100",
        ],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Main Comparison" in proc.stdout

    md_path = out_dir / "results.md"
    csv_path = out_dir / "results.csv"
    assert md_path.exists()
    assert csv_path.exists()

    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    systems = {r["system"] for r in rows}
    # All 7 baselines + open_rba:v1 + ablations must be present
    for b in ("random", "time_newest", "max_rule_level", "alert_count", "level_x_asset", "additive", "idf_bm25"):
        assert f"baseline:{b}" in systems
    assert "open_rba:v1" in systems
    assert "ablation:v1:drop_severity" in systems
    assert "perturb:v1:severity_+20pct" in systems
