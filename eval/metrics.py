"""
Ranking Metrics, Ground-Truth Matching, Bootstrap Confidence Intervals,
and Rank Stability Helpers for Open-RBA Evaluation.
"""

import math
import random
from typing import Dict, List, Tuple, Set, Any, Optional

from src.correlation.engine import CorrelatedIncident, parse_timestamp


def canonical_ts(ts: str) -> str:
    try:
        dt = parse_timestamp(ts)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    except Exception:
        return str(ts)


def build_attack_key_set(labels: List[Dict[str, Any]]) -> Set[Tuple[str, str, str, Optional[str]]]:
    """Builds a lookup set of attack alert identity tuples from JSONL labels."""
    keys: Set[Tuple[str, str, str, Optional[str]]] = set()
    for lbl in labels:
        if str(lbl.get("label", "")).lower() == "attack":
            keys.add((
                canonical_ts(str(lbl.get("timestamp", ""))),
                str(lbl.get("rule_id", "")),
                str(lbl.get("agent_name", "")),
                lbl.get("src_ip") or None,
            ))
    return keys


def is_incident_positive(
    inc: CorrelatedIncident,
    alert_map: Dict[int, Dict[str, Any]],
    attack_keys: Set[Tuple[str, str, str, Optional[str]]],
) -> bool:
    """A ranked incident is positive if ANY of its contributing alerts is labeled 'attack'."""
    for aid in inc.alert_ids:
        a = alert_map.get(aid)
        if not a:
            continue
        key = (
            canonical_ts(str(a.get("timestamp", ""))),
            str(a.get("rule_id", "")),
            str(a.get("agent_name", "")),
            a.get("src_ip") or None,
        )
        if key in attack_keys:
            return True
    return False


def precision_at_k(relevances: List[bool], k: int) -> float:
    if not relevances or k <= 0:
        return 0.0
    top_k = relevances[:k]
    return sum(1 for r in top_k if r) / len(top_k)


def recall_at_k(relevances: List[bool], k: int) -> Optional[float]:
    total_pos = sum(1 for r in relevances if r)
    if total_pos == 0:
        return None
    top_k = relevances[:k]
    return sum(1 for r in top_k if r) / total_pos


def first_true_rank(relevances: List[bool]) -> Optional[int]:
    for idx, rel in enumerate(relevances, 1):
        if rel:
            return idx
    return None


def bootstrap_ci(
    values: List[float],
    n_resamples: int = 1000,
    seed: int = 42,
    alpha: float = 0.05,
) -> Tuple[float, float, float]:
    """Computes (mean, ci_low, ci_high) via seeded non-parametric bootstrap."""
    if not values:
        return (0.0, 0.0, 0.0)
    n = len(values)
    mean_val = sum(values) / n
    if n == 1:
        return (mean_val, mean_val, mean_val)

    rng = random.Random(seed)
    means: List[float] = []
    for _ in range(n_resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()

    low_idx = max(0, int((alpha / 2.0) * n_resamples))
    high_idx = min(n_resamples - 1, int((1.0 - alpha / 2.0) * n_resamples))
    return (mean_val, means[low_idx], means[high_idx])


def spearman_rank_correlation(order_a: List[str], order_b: List[str]) -> float:
    """Computes Spearman rank correlation between two ordered lists of incident keys."""
    if not order_a or not order_b:
        return 0.0
    pos_b = {item: idx for idx, item in enumerate(order_b)}
    common = [item for item in order_a if item in pos_b]
    n = len(common)
    if n < 2:
        return 1.0 if n == 1 else 0.0

    # Handle duplicate keys deterministically by indexing occurrences if any
    ranks_a = list(range(n))
    ranks_b = [pos_b[item] for item in common]
    mean_a = sum(ranks_a) / n
    mean_b = sum(ranks_b) / n

    num = sum((a - mean_a) * (b - mean_b) for a, b in zip(ranks_a, ranks_b))
    den_a = math.sqrt(sum((a - mean_a) ** 2 for a in ranks_a))
    den_b = math.sqrt(sum((b - mean_b) ** 2 for b in ranks_b))
    if den_a == 0 or den_b == 0:
        return 0.0
    return max(-1.0, min(1.0, num / (den_a * den_b)))
