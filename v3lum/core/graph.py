"""The investigation knowledge graph: entities (nodes), relations (edges), facts and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Finding


@dataclass
class Node:
    entity: Entity
    depth: int = 0
    seed: bool = False
    investigated: bool = False
    noise: bool = False
    sources: set[str] = field(default_factory=set)
    attributes: dict[str, list[tuple[Any, str]]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.entity.key

    def attr(self, key: str, default: Any = None) -> Any:
        vals = self.attributes.get(key)
        return vals[0][0] if vals else default

    def attr_values(self, key: str) -> list[Any]:
        """All values recorded for ``key`` by any module, list-valued attributes flattened."""
        out: list[Any] = []
        for value, _src in self.attributes.get(key, []):
            items = value if isinstance(value, (list, tuple, set)) else [value]
            for item in items:
                if item not in out:
                    out.append(item)
        return out

    def attr_sources(self, key: str) -> list[str]:
        return [src for _v, src in self.attributes.get(key, [])]

    def has_tag(self, tag: str) -> bool:
        return any(tag in f.tags for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.entity.type.value,
            "value": self.entity.value,
            "display": self.entity.display,
            "depth": self.depth,
            "seed": self.seed,
            "investigated": self.investigated,
            "noise": self.noise,
            "sources": sorted(self.sources),
            "attributes": {k: [{"value": v, "source": s} for v, s in vals] for k, vals in self.attributes.items()},
            "findings": [f.id for f in self.findings],
        }


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    relation: str
    module: str
    confidence: float = 0.9

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "relation": self.relation, "module": self.module, "confidence": self.confidence}


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------------ mutation
    def add_node(self, entity: Entity, depth: int = 0, *, seed: bool = False, source: str = "") -> tuple[Node, bool]:
        node = self.nodes.get(entity.key)
        created = node is None
        if node is None:
            node = Node(entity, depth=depth, seed=seed)
            self.nodes[entity.key] = node
        else:
            node.depth = min(node.depth, depth)
            node.seed = node.seed or seed
        if source:
            node.sources.add(source)
        return node, created

    def add_edge(self, src: Entity, dst: Entity, relation: str, module: str, confidence: float = 0.9) -> bool:
        k = (src.key, dst.key, relation)
        if k in self._edge_keys:
            return False
        self._edge_keys.add(k)
        self.edges.append(Edge(src.key, dst.key, relation, module, confidence))
        return True

    def add_attributes(self, entity: Entity, attrs: dict[str, Any], module: str) -> None:
        node, _ = self.add_node(entity)
        for key, value in attrs.items():
            bucket = node.attributes.setdefault(key, [])
            if not any(v == value and s == module for v, s in bucket):
                bucket.append((value, module))

    def add_finding(self, finding: Finding) -> None:
        if finding.entity is None:
            return
        node, _ = self.add_node(finding.entity)
        node.findings.append(finding)

    # ------------------------------------------------------------------ queries
    def get(self, entity_or_key: Entity | str) -> Node | None:
        key = entity_or_key.key if isinstance(entity_or_key, Entity) else entity_or_key
        return self.nodes.get(key)

    def of_type(self, *types: EntityType) -> list[Node]:
        return [n for n in self.nodes.values() if n.entity.type in types]

    def out_edges(self, key: str, relation: str | None = None) -> list[Edge]:
        return [e for e in self.edges if e.src == key and (relation is None or e.relation == relation)]

    def in_edges(self, key: str, relation: str | None = None) -> list[Edge]:
        return [e for e in self.edges if e.dst == key and (relation is None or e.relation == relation)]

    def neighbors(self, key: str, relation: str | None = None, direction: str = "out") -> list[Node]:
        keys: list[str] = []
        if direction in ("out", "both"):
            keys += [e.dst for e in self.out_edges(key, relation)]
        if direction in ("in", "both"):
            keys += [e.src for e in self.in_edges(key, relation)]
        seen: set[str] = set()
        out = []
        for k in keys:
            if k not in seen and k in self.nodes:
                seen.add(k)
                out.append(self.nodes[k])
        return out

    def seeds(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.seed]

    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for n in self.nodes.values():
            out.extend(n.findings)
        return out

    def children_tree(self) -> dict[str, list[tuple[str, str]]]:
        """Parent key -> [(child key, relation)] using first-discovery edges (for tree rendering)."""
        tree: dict[str, list[tuple[str, str]]] = {}
        placed: set[str] = {n.key for n in self.seeds()}
        for e in self.edges:
            if e.dst in placed:
                continue
            placed.add(e.dst)
            tree.setdefault(e.src, []).append((e.dst, e.relation))
        return tree

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes.values()], "edges": [e.to_dict() for e in self.edges]}
