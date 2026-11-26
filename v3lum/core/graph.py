"""The investigation knowledge graph: entities (nodes), relations (edges), facts and findings.

Nodes carry entity-level context set by the engine (ownership, criticality, TLP, path
confidence, noise kind, entity tags) next to the facts (attributes) and findings modules
reported. :meth:`Graph.from_dict` rebuilds a graph from a stored case dict or from a
``v3lum.graph_fixture/1`` document (correlation-rule fixtures).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Confidence, Finding

GRAPH_FIXTURE_SCHEMA = "v3lum.graph_fixture/1"


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
    ownership: str = ""  # 'own_asset' | 'third_party' | '' (org profile, engine)
    criticality: str = ""  # org-profile criticality of the asset ('' = unknown)
    tlp: str = ""  # entity TLP value ('' = case TLP)
    path_confidence: float = 1.0  # product of edge confidences from the closest seed (AR07)
    noise_kind: str = ""  # cdn | cloud | resolver | webmail | sinkhole | parked | warninglist ... ('' = not noise)
    tags: set[str] = field(default_factory=set)  # entity-level tags set by the engine (own_asset, sinkhole...)

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
        """Is ``tag`` on one of the node's findings? (see :meth:`tagged` for entity tags too)."""
        return any(tag in f.tags for f in self.findings)

    def add_tag(self, tag: str) -> None:
        """Set an entity-level tag (engine side: own_asset, third_party, sinkhole, parked...)."""
        if tag:
            self.tags.add(tag)

    def tagged(self, *tags: str) -> bool:
        """True when any of ``tags`` is an entity tag of the node or a tag of one of its findings."""
        wanted = set(tags)
        if wanted & self.tags:
            return True
        return any(wanted.intersection(f.tags) for f in self.findings)

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
            "ownership": self.ownership,
            "criticality": self.criticality,
            "tlp": self.tlp,
            "path_confidence": round(float(self.path_confidence), 4),
            "noise_kind": self.noise_kind,
            "tags": sorted(self.tags),
        }


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    relation: str
    module: str
    confidence: float = 0.9

    @property
    def confidence_label(self) -> Confidence:
        return Confidence.from_value(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "relation": self.relation,
            "module": self.module,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label.value,
        }


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
        return self._add_edge_keys(src.key, dst.key, relation, module, confidence)

    def _add_edge_keys(self, src: str, dst: str, relation: str, module: str, confidence: float = 0.9) -> bool:
        k = (src, dst, relation)
        if k in self._edge_keys:
            return False
        self._edge_keys.add(k)
        self.edges.append(Edge(src, dst, relation, module, float(confidence)))
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
        if not finding.id:
            finding.ensure_id()
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
        """Nodes (findings by id), edges and the full findings: :meth:`from_dict` rebuilds it losslessly."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "findings": [f.to_dict() for f in self.findings()],
        }

    # ------------------------------------------------------------------ rebuild
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Graph:
        """Rebuild a graph from a stored case dict, a ``to_dict`` dump or a graph fixture.

        * nodes come from ``nodes`` (fixtures, :meth:`to_dict`) or ``entities`` (case dicts);
        * attributes are ``{name: [{value, source}]}`` (fixtures may also give a bare value);
        * node ``findings`` are full finding dicts (fixtures) or ids resolved against the
          top-level ``findings`` list (case dicts); case findings not listed by a node are
          attached through their ``entity`` key;
        * unknown keys are ignored. In a ``v3lum.graph_fixture/1`` document an invalid node or
          an edge to an unknown node raises ValueError (fixtures must be exact).
        """
        strict = d.get("schema") == GRAPH_FIXTURE_SCHEMA
        graph = cls()
        raw_nodes = d.get("nodes")
        if raw_nodes is None:
            raw_nodes = d.get("entities") or []
        top_findings = {f["id"]: f for f in d.get("findings") or () if isinstance(f, dict) and f.get("id")}
        used: set[str] = set()
        for raw in raw_nodes:
            entity = _node_entity(raw)
            if entity is None:
                if strict:
                    raise ValueError(f"graph fixture: invalid node {raw!r} (needs key 'type:value' or type + value)")
                continue
            node, _ = graph.add_node(entity, int(raw.get("depth", 0) or 0), seed=bool(raw.get("seed", False)))
            node.investigated = bool(raw.get("investigated", False))
            node.noise = bool(raw.get("noise", False))
            node.sources.update(str(s) for s in raw.get("sources") or ())
            node.ownership = str(raw.get("ownership") or "")
            node.criticality = str(raw.get("criticality") or "")
            node.tlp = str(raw.get("tlp") or "")
            node.path_confidence = float(raw.get("path_confidence", 1.0) if raw.get("path_confidence") is not None else 1.0)
            node.noise_kind = str(raw.get("noise_kind") or "")
            node.tags.update(str(t) for t in raw.get("tags") or ())
            for name, values in (raw.get("attributes") or {}).items():
                bucket = node.attributes.setdefault(name, [])
                for value, source in _attr_entries(values):
                    if not any(v == value and s == source for v, s in bucket):
                        bucket.append((value, source))
                    if source:
                        node.sources.add(source)
            for item in raw.get("findings") or ():
                if isinstance(item, dict):
                    f = Finding.from_dict(item, entity=entity)
                elif isinstance(item, str) and item in top_findings:
                    f = Finding.from_dict(top_findings[item], entity=entity)
                    used.add(item)
                else:
                    continue
                node.findings.append(f)
        for fid, fd in top_findings.items():
            if fid in used:
                continue
            node = graph.nodes.get(str(fd.get("entity") or ""))
            if node is not None and not any(f.id == fid for f in node.findings):
                node.findings.append(Finding.from_dict(fd, entity=node.entity))
        for raw in d.get("edges") or ():
            if not isinstance(raw, dict):
                continue
            src, dst = str(raw.get("src") or ""), str(raw.get("dst") or "")
            if strict and (src not in graph.nodes or dst not in graph.nodes):
                raise ValueError(f"graph fixture: edge {src!r} -> {dst!r} references an unknown node")
            if not src or not dst:
                continue
            conf = raw.get("confidence", 0.9)
            if isinstance(conf, str):
                conf = Confidence.from_value(conf).weight
            graph._add_edge_keys(src, dst, str(raw.get("relation") or "related"), str(raw.get("module") or ""), float(conf if conf is not None else 0.9))
        return graph


def _node_entity(raw: Any) -> Entity | None:
    if not isinstance(raw, dict):
        return None
    etype, value = raw.get("type"), raw.get("value")
    if not (etype and isinstance(value, str)):
        key = raw.get("key")
        if not isinstance(key, str) or ":" not in key:
            return None
        etype, value = key.split(":", 1)
    try:
        return Entity(EntityType(str(etype)), value)
    except ValueError:
        return None


def _attr_entries(values: Any) -> list[tuple[Any, str]]:
    """[{value, source}, ...] -> [(value, source)]; anything else is one value from 'fixture'."""
    if isinstance(values, list) and values and all(isinstance(v, dict) and "value" in v for v in values):
        return [(v["value"], str(v.get("source") or "")) for v in values]
    return [(values, "fixture")]
