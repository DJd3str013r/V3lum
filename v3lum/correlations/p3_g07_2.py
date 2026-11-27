"""Correlation rules of batch p3-G07-2 (structural / fuzzy hash pivots, P351 FC6).

``p3g072_case_fuzzy_similarity``: local ssdeep similarity between the files of one case is a
correlation over case attributes, not a per-entity module (P351 FC6). The rule reads the ssdeep
values the case already holds - attribute ``similarity_hashes`` of file/hash nodes (YARAify,
MalShare, PolySwarm, VirusShare, structural_hash_pivots) and ``ssdeep`` nodes linked from them
(file_hashing ``has_hash``, ``similarity_hash``) - groups the nodes of one file (``same_file`` /
``has_hash`` edges) and compares different files:

* an identical ssdeep on two different files always counts (score 100, no package needed);
* with the optional ``ppdeep`` extra (Apache-2.0, ``v3lum/data/extras/ppdeep.json``) comparable
  digests (equal or doubled block size) are scored and counted from ``MIN_SCORE`` up.

Every hit is a hypothesis (severity info, confidence possible, tag ``hypothesis``): shared code,
packers, installers and templates give similar fuzzy hashes too. TLSH distance is not computed: it
waits for a wheel-providing implementation (P351 FC6, P267 FC2).
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable
from itertools import combinations
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.core.module import package_available

RULE_ID = "p3g072_case_fuzzy_similarity"
FILE_TYPES = frozenset({EntityType.FILE, EntityType.MD5, EntityType.SHA1, EntityType.SHA256, EntityType.SHA512})
SAME_FILE_RELATIONS = frozenset({"same_file", "has_hash"})
SSDEEP_RELATIONS = frozenset({"has_hash", "similarity_hash"})
MIN_SCORE = 60
MAX_FILES = 200
MAX_HITS = 50
PPDEEP = "ppdeep"
_SSDEEP = re.compile(r"^(\d{1,10}):([A-Za-z0-9+/]{1,64}):([A-Za-z0-9+/]{0,64})")


def _block(value: str) -> int | None:
    m = _SSDEEP.match(value or "")
    if not m:
        return None
    bs = int(m.group(1))
    n = bs // 3
    return bs if bs >= 3 and not bs % 3 and not n & (n - 1) else None


def comparable(a: str, b: str) -> bool:
    """ssdeep scores exist only for equal block sizes or a 2x ratio (cheap pre-filter)."""
    x, y = _block(a), _block(b)
    if not x or not y:
        return False
    lo, hi = sorted((x, y))
    return lo == hi or hi == 2 * lo


def _canonical(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    m = _SSDEEP.match(value.strip())
    return f"{m.group(1)}:{m.group(2)}:{m.group(3)}" if m and _block(value.strip()) else None


def _file_groups(graph: Graph) -> dict[str, list[str]]:
    """Union of file/hash nodes that are the same file -> {root key: [member keys]}."""
    parent: dict[str, str] = {}

    def find(k: str) -> str:
        while parent.setdefault(k, k) != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    nodes = {k: n for k, n in graph.nodes.items() if n.entity.type in FILE_TYPES}
    for k in nodes:
        find(k)
    for e in graph.edges:
        if e.relation in SAME_FILE_RELATIONS and e.src in nodes and e.dst in nodes:
            ra, rb = find(e.src), find(e.dst)
            if ra != rb:
                parent[rb] = ra
    groups: dict[str, list[str]] = {}
    for k in nodes:
        groups.setdefault(find(k), []).append(k)
    return groups


def _ssdeeps(graph: Graph, keys: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for k in keys:
        node = graph.nodes[k]
        for value, _src in node.attributes.get("similarity_hashes", []):
            if isinstance(value, dict):
                v = _canonical(value.get("ssdeep"))
                if v:
                    out.add(v)
        for e in graph.out_edges(k):
            dst = graph.nodes.get(e.dst)
            if e.relation in SSDEEP_RELATIONS and dst is not None and dst.entity.type is EntityType.SSDEEP:
                v = _canonical(dst.entity.value)
                if v:
                    out.add(v)
    return out


def _representative(graph: Graph, keys: list[str]) -> Any:
    order = {EntityType.SHA256: 0, EntityType.FILE: 1, EntityType.SHA1: 2, EntityType.MD5: 3, EntityType.SHA512: 4}
    best = min(keys, key=lambda k: (order.get(graph.nodes[k].entity.type, 9), k))
    return graph.nodes[best].entity


def _scorer() -> Any:
    if not package_available(PPDEEP):
        return None
    try:
        return importlib.import_module(PPDEEP)
    except Exception:  # noqa: BLE001 - a broken optional extra only disables scored comparisons
        return None


@rule(
    RULE_ID,
    "Files of this case have similar fuzzy hashes (ssdeep)",
    "Two different files of the case share an identical ssdeep, or score at least 60 with the optional ppdeep "
    "extra: a similarity hypothesis (shared code, packer, installer or template), never proof of a common origin.",
    version="1",
    severity="info",
    criterion="identical ssdeep on two different files of the case, or ppdeep score >= 60 between comparable digests",
    false_positives="Installers, packers, document templates and shared libraries give similar fuzzy hashes to unrelated files.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_identical_ssdeep_attributes.json",
        f"tests/fixtures/rules/{RULE_ID}/positive_shared_ssdeep_node.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_same_file_hashes.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_incomparable_digests.json",
    ),
)
def case_fuzzy_similarity(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    groups = _file_groups(graph)
    files = []
    for root, keys in sorted(groups.items()):
        values = _ssdeeps(graph, keys)
        if values:
            files.append((root, keys, values))
    files = files[:MAX_FILES]
    scorer = None
    hits = 0
    for (_ra, ka, va), (_rb, kb, vb) in combinations(files, 2):
        if hits >= MAX_HITS:
            return
        best = (0, "", "")
        for a in sorted(va):
            for b in sorted(vb):
                if a == b:
                    score = 100
                elif comparable(a, b):
                    scorer = scorer or _scorer()
                    if scorer is None:
                        continue
                    try:
                        score = int(scorer.compare(a, b))
                    except Exception:  # noqa: BLE001 - an odd digest never stops the rule
                        continue
                else:
                    continue
                if score > best[0]:
                    best = (score, a, b)
        if best[0] < MIN_SCORE:
            continue
        hits += 1
        ea, eb = _representative(graph, ka), _representative(graph, kb)
        how = "identical ssdeep" if best[0] == 100 and best[1] == best[2] else f"ssdeep score {best[0]}/100 (ppdeep)"
        yield Correlation(
            rule=RULE_ID,
            title="Files of this case have similar fuzzy hashes (ssdeep)",
            severity=Severity.INFO,
            description=(
                f"{ea.value[:16]}... and {eb.value[:16]}... are different files with {how}. A similarity hypothesis: "
                "shared code, packers, installers or templates give similar fuzzy hashes too. TLSH distance is not computed."
            ),
            entities=[ea, eb],
            confidence="possible",
            evidence=[],
            recommendation="Compare the two files (imports, sections, strings) before treating them as one campaign or toolset.",
            tags=["hypothesis"],
            criterion=f"{how} between two files of the case (P351 FC6: case-level comparison, never a verdict)",
            key="|".join(sorted((ea.key, eb.key))),
        )
