"""Risk scoring: combine findings and correlations into 0-100 scores per entity and per case.

Each finding contributes ``weight(severity) * confidence * reliability(module)`` and the
contributions are combined with a noisy-OR, so many weak signals add up but never exceed 100.
Module reliability comes from the analyst feedback loop (see v3lum.core.feedback).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Severity

WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.12,
    Severity.MEDIUM: 0.3,
    Severity.HIGH: 0.6,
    Severity.CRITICAL: 0.88,
}

LEVELS: list[tuple[float, str]] = [(80, "critical"), (55, "high"), (30, "medium"), (8, "low"), (0, "clean")]


def level(score: float) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "clean"


def _noisy_or(weights: list[float]) -> float:
    acc = 1.0
    for w in weights:
        acc *= 1.0 - max(0.0, min(0.99, w))
    return round((1.0 - acc) * 100, 1)


def score(graph: Graph, correlations: list[Correlation], reliability: dict[str, float] | None = None) -> dict[str, Any]:
    reliability = reliability or {}
    per_entity: dict[str, dict[str, Any]] = {}
    for key, node in graph.nodes.items():
        if node.noise:
            continue
        weights = [
            WEIGHTS[f.severity] * f.confidence * reliability.get(f.module, 1.0)
            for f in node.findings
            if "known_good" not in f.tags
        ]
        if not weights:
            continue
        s = _noisy_or(weights)
        if s > 0:
            per_entity[key] = {"score": s, "level": level(s)}

    corr_weights = [WEIGHTS[c.severity] * c.confidence for c in correlations]
    seed_scores = [per_entity.get(n.key, {}).get("score", 0.0) for n in graph.seeds()]
    # The case is as risky as its riskiest seed, raised by cross-referenced evidence and by
    # strong signals anywhere in the graph (dampened: a pivot is not the seed itself).
    pivot_weights = [d["score"] / 100 * 0.6 for k, d in per_entity.items() if not graph.nodes[k].seed]
    combined = _noisy_or([s / 100 for s in seed_scores] + corr_weights + pivot_weights)
    top = sorted(per_entity.items(), key=lambda kv: -kv[1]["score"])[:10]
    return {
        "score": combined,
        "level": level(combined),
        "entities": per_entity,
        "top": [{"entity": k, **v} for k, v in top],
    }
