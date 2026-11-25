"""Cross-referencing engine: correlation rules run over the finished investigation graph.

A rule is a function ``(graph, results) -> iterable[Correlation]`` registered with ``@rule``.
Rules live in the ``v3lum.correlations`` package (auto-discovered, like modules).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult

log = logging.getLogger("v3lum.correlate")

RuleFn = Callable[[Graph, list[ModuleResult]], Iterable[Correlation]]


@dataclass
class RuleInfo:
    id: str
    title: str
    description: str
    fn: RuleFn


RULES: dict[str, RuleInfo] = {}
RULE_ERRORS: dict[str, str] = {}
_LOADED = False


def rule(rule_id: str, title: str, description: str = "") -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        RULES[rule_id] = RuleInfo(rule_id, title, description or (fn.__doc__ or "").strip(), fn)
        return fn

    return deco


def load_rules(force: bool = False) -> dict[str, RuleInfo]:
    global _LOADED
    if _LOADED and not force:
        return RULES
    import v3lum.correlations as pkg

    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if info.name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # pragma: no cover - defensive
            RULE_ERRORS[info.name] = f"{type(exc).__name__}: {exc}"
            log.warning("failed to load rules %s: %s", info.name, exc)
    _LOADED = True
    return RULES


def run_rules(graph: Graph, results: list[ModuleResult], only: set[str] | None = None) -> list[Correlation]:
    load_rules()
    out: list[Correlation] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()
    for rid, info in RULES.items():
        if only and rid not in only:
            continue
        try:
            for corr in info.fn(graph, results) or []:
                if not corr.rule:
                    corr.rule = rid
                sig = (corr.rule, tuple(sorted(e.key for e in corr.entities)), corr.title)
                if sig in seen:
                    continue
                seen.add(sig)
                out.append(corr)
        except Exception as exc:  # a broken rule must not break the report
            RULE_ERRORS[rid] = f"{type(exc).__name__}: {exc}"
            log.warning("rule %s failed: %s", rid, exc)
    out.sort(key=lambda c: (-int(c.severity), -c.confidence))
    return out
