"""
Baseline Incident Rankers for Open-RBA Evaluation Harness.

Implements the 7 reference baselines from the evaluation protocol:
  1. random           (seeded shuffle)
  2. time_newest      (most recent incident last_seen first)
  3. max_rule_level   (peak Wazuh rule_level descending)
  4. alert_count      (compressed alert count descending)
  5. level_x_asset    (normalized max_severity * asset multiplier)
  6. additive         (sum of level/15 across alerts + asset weight)
  7. idf_bm25         (BM25/IDF over rule_id, technique_family, and level bucket)
"""

import math
import random
from collections import Counter
from typing import Dict, List, Any, Callable, Tuple

from src.correlation.engine import CorrelatedIncident
from src.scoring.engine import RiskScoringEngine


def _level_bucket(level: int) -> str:
    if level >= 12:
        return "lvl_crit"
    if level >= 8:
        return "lvl_high"
    if level >= 5:
        return "lvl_med"
    return "lvl_low"


def _incident_tokens(inc: CorrelatedIncident, alert_map: Dict[int, Dict[str, Any]]) -> List[str]:
    """Extracts bag-of-signals tokens for BM25/IDF incident scoring."""
    tokens: List[str] = []
    for aid in inc.alert_ids:
        a = alert_map.get(aid)
        if not a:
            continue
        rid = str(a.get("rule_id", "0"))
        lvl = int(a.get("rule_level", 0))
        tokens.append(f"rule:{rid}")
        tokens.append(_level_bucket(lvl))
        techs = a.get("mitre_tactics") or []
        if techs:
            for t in techs:
                tokens.append(f"tech:{str(t).split('.')[0]}")
        else:
            tokens.append("tech:none")
    if not tokens:
        tokens = [f"rule:{r}" for r in inc.rule_ids] + [f"tech:{inc.technique_family}", _level_bucket(inc.max_severity)]
    return tokens


def rank_random(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
    seed: int = 42,
) -> List[CorrelatedIncident]:
    rng = random.Random(seed)
    items = list(incidents)
    rng.shuffle(items)
    return items


def rank_time_newest(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
) -> List[CorrelatedIncident]:
    return sorted(incidents, key=lambda inc: (inc.last_seen, inc.group_key), reverse=True)


def rank_max_rule_level(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
) -> List[CorrelatedIncident]:
    return sorted(incidents, key=lambda inc: (inc.max_severity, inc.last_seen, inc.group_key), reverse=True)


def rank_alert_count(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
) -> List[CorrelatedIncident]:
    return sorted(incidents, key=lambda inc: (inc.alert_count, inc.max_severity, inc.last_seen), reverse=True)


def rank_level_x_asset(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
) -> List[CorrelatedIncident]:
    def score(inc: CorrelatedIncident) -> Tuple[float, str]:
        _, mult = scoring_engine.get_asset_context(inc.agent_name)
        val = (max(0, min(15, inc.max_severity)) / 15.0) * mult
        return (val, inc.last_seen)

    return sorted(incidents, key=score, reverse=True)


def rank_additive(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
) -> List[CorrelatedIncident]:
    """Sum of (rule_level / 15) across alerts in the incident plus asset weight."""
    def score(inc: CorrelatedIncident) -> Tuple[float, str]:
        _, mult = scoring_engine.get_asset_context(inc.agent_name)
        sev_sum = 0.0
        for aid in inc.alert_ids:
            a = alert_map.get(aid)
            if a is not None:
                sev_sum += max(0, min(15, int(a.get("rule_level", 0)))) / 15.0
        if sev_sum == 0.0:
            sev_sum = (max(0, min(15, inc.max_severity)) / 15.0) * max(1, inc.alert_count)
        return (sev_sum + (mult - 1.0), inc.last_seen)

    return sorted(incidents, key=score, reverse=True)


def rank_idf_bm25(
    incidents: List[CorrelatedIncident],
    alert_map: Dict[int, Dict[str, Any]],
    scoring_engine: RiskScoringEngine,
    k1: float = 1.2,
    b: float = 0.75,
) -> List[CorrelatedIncident]:
    """BM25/IDF-style scoring over rule_id, technique_family, and level bucket."""
    if not incidents:
        return []

    docs = [_incident_tokens(inc, alert_map) for inc in incidents]
    n_docs = len(docs)
    avgdl = sum(len(d) for d in docs) / max(1, n_docs)

    # Document frequency per token
    df: Counter = Counter()
    for d in docs:
        for tok in set(d):
            df[tok] += 1

    # Severity prior multiplier for level buckets so critical detections stay meaningful
    bucket_prior = {
        "lvl_crit": 2.0,
        "lvl_high": 1.5,
        "lvl_med": 1.0,
        "lvl_low": 0.5,
    }

    scored_pairs = []
    for inc, d in zip(incidents, docs):
        tf = Counter(d)
        dl = len(d)
        bm25_score = 0.0
        for tok, freq in tf.items():
            # BM25 IDF with +1 smoothness so unique/half-corpus tokens stay positive
            idf = math.log(((n_docs - df[tok] + 0.5) / (df[tok] + 0.5)) + 1.0)
            norm_tf = (freq * (k1 + 1.0)) / (freq + k1 * (1.0 - b + b * (dl / max(1.0, avgdl))))
            prior = bucket_prior.get(tok, 1.0)
            bm25_score += idf * norm_tf * prior
        scored_pairs.append((bm25_score, inc.last_seen, inc))

    scored_pairs.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in scored_pairs]


BASELINES: Dict[str, Callable[..., List[CorrelatedIncident]]] = {
    "random": rank_random,
    "time_newest": rank_time_newest,
    "max_rule_level": rank_max_rule_level,
    "alert_count": rank_alert_count,
    "level_x_asset": rank_level_x_asset,
    "additive": rank_additive,
    "idf_bm25": rank_idf_bm25,
}
