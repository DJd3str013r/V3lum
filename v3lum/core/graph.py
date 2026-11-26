"""The investigation knowledge graph: entities (nodes), relations (edges), facts and findings.

Nodes carry entity-level context set by the engine (ownership, criticality, TLP, path
confidence, noise kind, entity tags) next to the facts (attributes) and findings modules
reported. :meth:`Graph.from_dict` rebuilds a graph from a stored case dict or from a
``v3lum.graph_fixture/1`` document (correlation-rule fixtures).

Engine v2 semantics (WP08):

* **Noise on add (AR06)**: :meth:`Graph.add_node` evaluates noise for every new node
  (``v3lum.core.noise``): ``Node.noise``/``Node.noise_kind``, entity tags ``sinkhole`` /
  ``parked`` / ``benign_scanner`` and the attributes ``is_sinkhole`` / ``is_parked``. Noise applies to
  domains, IPs and bare-host URLs only: a URL with a path or query on a legitimate platform
  (Google Forms, OneDrive, ``*.github.io``...) is investigated and tagged
  ``hosted_on_legit_platform``. Tenant sites of user-site platforms that are not public suffixes
  (``<blog>.wordpress.com``, ``<site>.squarespace.com``, ``*.googleusercontent.com``: see
  :data:`TENANT_PLATFORMS`) are not noise either - the platform's own name-server, mail and web
  hosts stay noise.
* **Path confidence (AR07)**: ``Node.path_confidence`` is the maximum, over the paths from a seed,
  of the product of the edge confidences. Seeds are 1.0, a new non-seed node 0.0 until an edge
  reaches it; :meth:`Graph.add_edge` updates it incrementally (and propagates a raise downstream).
* **Persistence safety**: :meth:`Node.to_dict` writes SECRET_TYPES values through
  ``entities.redacted_value`` (raw secrets exist only in memory during the run).

Graphs rebuilt by :meth:`Graph.from_dict` keep the stored/fixture values exactly (no noise
evaluation, no path-confidence recomputation).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Confidence, Finding

log = logging.getLogger("v3lum.graph")

GRAPH_FIXTURE_SCHEMA = "v3lum.graph_fixture/1"

#: Source label of the facts the graph records itself (noise attributes).
NOISE_SOURCE = "noise"
#: Noise kinds that become entity tags, with the boolean attribute that goes with them ('' = none).
NOISE_TAGS: dict[str, str] = {"sinkhole": "is_sinkhole", "parked": "is_parked", "benign_scanner": ""}
#: Entity tag of URLs/domains hosted on a legitimate platform (AR06).
LEGIT_PLATFORM_TAG = "hosted_on_legit_platform"

#: User-site platforms whose tenant sites are plain subdomains of the platform's registrable domain
#: (no public-suffix entry), so the noise lists - which walk up to the PSL registrable domain - would
#: count every tenant site as platform infrastructure. A strict subdomain of one of them is a tenant
#: site (not noise, tagged ``hosted_on_legit_platform``) unless its first label is one of the
#: platform's own infrastructure labels (:data:`PLATFORM_INFRA_LABEL`: name servers, mail, web...).
TENANT_PLATFORMS: dict[str, str] = {
    "wordpress.com": "wordpress",
    "squarespace.com": "squarespace",
    "googleusercontent.com": "googleusercontent",
    "wix.com": "wix",
}
#: First labels that name a platform's own infrastructure (they stay noise).
PLATFORM_INFRA_LABEL = re.compile(
    r"^(?:ns\d*|dns\d*|mx\d*|mail\d*|smtp\d*|imap\d*|pop\d*|mta\d*|relay\d*|autodiscover|autoconfig|webmail|"
    r"www\d*|api|cdn\d*|static\d*|media\d*|img\d*|images?\d*|lh\d+|s\d+|i\d+|ssl|login|accounts?|support|help|status|blog)$"
)
#: Noise kinds a tenant site may override (shared platform infrastructure, never sinkholes or parking).
_TENANT_OVERRIDABLE = frozenset({"hosting", "cloud", "saas", "cdn"})

#: Edge confidences are clamped to [0, 1]; path confidences compare with this tolerance.
_EPS = 1e-12


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
    path_confidence: float = 1.0  # max over seed paths of the product of edge confidences (AR07)
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

    def set_fact(self, name: str, value: Any, source: str = NOISE_SOURCE) -> None:
        """Record a fact the core derived itself (e.g. ``is_sinkhole``) once per (value, source)."""
        bucket = self.attributes.setdefault(name, [])
        if not any(v == value and s == source for v, s in bucket):
            bucket.append((value, source))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view. SECRET_TYPES values are written redacted (``entities.redacted_value``)."""
        value = _persisted_value(self.entity)
        return {
            "key": f"{self.entity.type.value}:{value}",
            "type": self.entity.type.value,
            "value": value,
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


def _persisted_value(entity: Entity) -> str:
    """The value written to disk: SECRET_TYPES through ``entities.redacted_value``; others unchanged."""
    if entity.type in _entities.SECRET_TYPES:
        try:
            return _entities.redacted_value(entity.type, entity.value)
        except Exception:  # noqa: BLE001 - never write a raw secret, whatever goes wrong
            return "[redacted]"
    return entity.value


def secret_value_map(entities: Any) -> dict[str, str]:
    """Raw SECRET_TYPES values among ``entities`` -> their persisted form (``redacted_value``).

    Only values that differ from their persisted form and have at least 8 characters are listed
    (short values could collide with unrelated text)."""
    found: dict[str, str] = {}
    for entity in entities:
        if not isinstance(entity, Entity) or entity.type not in _entities.SECRET_TYPES:
            continue
        raw = str(entity.value)
        safe = _persisted_value(entity)
        if raw and safe != raw and len(raw) >= 8:
            found[raw] = safe
    return found


def redact_secret_values(data: Any, secrets_map: dict[str, str]) -> Any:
    """Replace every raw secret of ``secrets_map`` (also inside longer strings and dict keys, e.g.
    entity keys 'jwt:<raw>') by its persisted form, everywhere in ``data`` (a new structure)."""
    if not secrets_map:
        return data
    items = sorted(secrets_map.items(), key=lambda kv: -len(kv[0]))

    def fix(text: str) -> str:
        for raw, safe in items:
            if raw in text:
                text = text.replace(raw, safe)
        return text

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return fix(value)
        if isinstance(value, dict):
            return {(fix(k) if isinstance(k, str) else k): walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, tuple):
            return tuple(walk(v) for v in value)
        return value

    return walk(data)


@dataclass(frozen=True)
class Edge:
    """A relation ``src -> dst`` found by ``module``. ``expand`` is the pivot's expand flag
    (False = listed for the analyst, never auto-investigated: a weak relation for correlations)."""

    src: str
    dst: str
    relation: str
    module: str
    confidence: float = 0.9
    expand: bool = True

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
            "expand": self.expand,
        }


class Graph:
    """Nodes keyed by entity key, edges deduplicated by (src, dst, relation).

    ``Graph(noise_check=True)``: new nodes get their noise evaluated (AR06). Graphs rebuilt from
    stored cases or fixtures (:meth:`from_dict`) keep the recorded values instead.
    """

    def __init__(self, *, noise_check: bool = True) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.noise_check = bool(noise_check)
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._out: dict[str, list[Edge]] = {}

    # ------------------------------------------------------------------ mutation
    def add_node(self, entity: Entity, depth: int = 0, *, seed: bool = False, source: str = "") -> tuple[Node, bool]:
        """Add (or update) the node of ``entity``; returns ``(node, created)``.

        A new node gets its noise evaluated (when ``noise_check``) and a path confidence of 1.0 for
        a seed, 0.0 otherwise (raised by :meth:`add_edge`). An existing node keeps the smallest
        depth; becoming a seed sets its path confidence to 1.0 (propagated downstream).
        """
        node = self.nodes.get(entity.key)
        created = node is None
        if node is None:
            node = Node(entity, depth=depth, seed=seed, path_confidence=1.0 if seed else 0.0)
            self.nodes[entity.key] = node
            if self.noise_check:
                evaluate_noise(node)
        else:
            node.depth = min(node.depth, depth)
            if seed and not node.seed:
                node.seed = True
                self._raise_path_confidence(node.key, 1.0)
        if source:
            node.sources.add(source)
        return node, created

    def add_edge(self, src: Entity, dst: Entity, relation: str, module: str, confidence: float = 0.9, *, expand: bool = True) -> bool:
        """Add the relation ``src -> dst`` (once per (src, dst, relation)); True when it is new.

        Updates the destination's path confidence: ``max(current, src.path_confidence * confidence)``,
        propagated to everything downstream of it (AR07).
        """
        added = self._add_edge_keys(src.key, dst.key, relation, module, confidence, expand=expand)
        conf = _clamp(confidence)
        origin = self.nodes.get(src.key)
        if origin is not None and dst.key in self.nodes:
            self._raise_path_confidence(dst.key, origin.path_confidence * conf)
        return added

    def _add_edge_keys(self, src: str, dst: str, relation: str, module: str, confidence: float = 0.9, *, expand: bool = True) -> bool:
        k = (src, dst, relation)
        if k in self._edge_keys:
            return False
        self._edge_keys.add(k)
        edge = Edge(src, dst, relation, module, float(confidence), bool(expand))
        self.edges.append(edge)
        self._out.setdefault(src, []).append(edge)
        return True

    def _raise_path_confidence(self, key: str, value: float) -> None:
        """Raise ``key``'s path confidence to ``value`` and relax everything downstream (worklist)."""
        work = [(key, value)]
        while work:
            current, val = work.pop()
            node = self.nodes.get(current)
            if node is None or val <= node.path_confidence + _EPS:
                continue
            node.path_confidence = min(1.0, val)
            for edge in self._out.get(current, ()):
                work.append((edge.dst, node.path_confidence * _clamp(edge.confidence)))

    def _node_for(self, entity: Entity) -> Node:
        """The node of ``entity`` as it is (depth, seed and path confidence untouched), or a new one
        at depth 0. Facts and findings never move a node: ``add_node(entity)`` would lower an existing
        node's depth to 0."""
        node = self.nodes.get(entity.key)
        if node is None:
            node, _ = self.add_node(entity)
        return node

    def add_attributes(self, entity: Entity, attrs: dict[str, Any], module: str) -> None:
        node = self._node_for(entity)
        for key, value in attrs.items():
            bucket = node.attributes.setdefault(key, [])
            if not any(v == value and s == module for v, s in bucket):
                bucket.append((value, module))

    def add_finding(self, finding: Finding) -> None:
        if finding.entity is None:
            return
        if not finding.id:
            finding.ensure_id()
        node = self._node_for(finding.entity)
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
        """Nodes (findings by id), edges and the full findings: :meth:`from_dict` rebuilds it losslessly
        (SECRET_TYPES values excepted: they are written redacted everywhere, edges and findings too)."""
        data = {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "findings": [f.to_dict() for f in self.findings()],
        }
        return redact_secret_values(data, secret_value_map(n.entity for n in self.nodes.values()))

    # ------------------------------------------------------------------ rebuild
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Graph:
        """Rebuild a graph from a stored case dict, a ``to_dict`` dump or a graph fixture.

        * nodes come from ``nodes`` (fixtures, :meth:`to_dict`) or ``entities`` (case dicts);
        * attributes are ``{name: [{value, source}]}`` (fixtures may also give a bare value);
        * node ``findings`` are full finding dicts (fixtures) or ids resolved against the
          top-level ``findings`` list (case dicts); case findings not listed by a node are
          attached through their ``entity`` key;
        * the recorded noise, noise kind, tags and path confidence are kept as stored (no
          re-evaluation); edges keep their ``expand`` flag (default True);
        * unknown keys are ignored. In a ``v3lum.graph_fixture/1`` document an invalid node or
          an edge to an unknown node raises ValueError (fixtures must be exact).
        """
        strict = d.get("schema") == GRAPH_FIXTURE_SCHEMA
        graph = cls(noise_check=False)
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
            expand = raw.get("expand", True)
            graph._add_edge_keys(
                src, dst, str(raw.get("relation") or "related"), str(raw.get("module") or ""), float(conf if conf is not None else 0.9),
                expand=True if expand is None else bool(expand),
            )
        return graph


# --------------------------------------------------------------------------------------
# noise semantics (AR06)
# --------------------------------------------------------------------------------------


def tenant_platform(entity: Entity) -> str | None:
    """Platform id when ``entity`` (domain or bare-host URL) is a tenant site of one of
    :data:`TENANT_PLATFORMS`: a strict subdomain whose first label is not platform infrastructure."""
    etype = entity.type
    if etype is EntityType.DOMAIN:
        host = entity.value
    elif etype is EntityType.URL:
        host = _entities.url_host(entity.value)
    else:
        return None
    host = str(host or "").strip().lower().rstrip(".")
    for platform, pid in TENANT_PLATFORMS.items():
        if not host.endswith("." + platform):
            continue
        sub = host[: -len(platform) - 1]
        first = sub.split(".", 1)[0]
        if not first or PLATFORM_INFRA_LABEL.match(first):
            return None
        return pid
    return None


def evaluate_noise(node: Node) -> None:
    """Set ``node.noise``, ``noise_kind``, the noise tags/attributes and the legit-platform tag.

    Never raises: a noise-list problem leaves the node as not noise (it is reported by
    ``noise.errors()``) - a node wrongly marked noise would lose its scoring, which is worse.
    """
    from v3lum.core import noise  # lazy: noise -> datasets -> ... must not load with the graph

    entity = node.entity
    try:
        kinds = set(noise.noise_kinds(entity))
        tenant = tenant_platform(entity) if kinds else None
        if tenant and kinds <= _TENANT_OVERRIDABLE:
            kinds = set()  # a tenant site on shared platform infrastructure is investigated
        kind = next((k for k in noise.PRECEDENCE if k in kinds), "") if kinds else ""
        if kinds and not kind:
            kind = sorted(kinds)[0]
        node.noise = bool(kinds)
        node.noise_kind = kind
        for noise_kind, attribute in NOISE_TAGS.items():
            if noise_kind in kinds:
                node.add_tag(noise_kind)
                if attribute:
                    node.set_fact(attribute, True)
        if not node.noise:
            platform = noise.legit_platform(entity) if entity.type in (EntityType.URL, EntityType.DOMAIN) else None
            if platform or tenant_platform(entity):
                node.add_tag(LEGIT_PLATFORM_TAG)
    except Exception as exc:  # noqa: BLE001 - noise evaluation must never break a scan
        log.warning("noise evaluation failed for %s: %s", entity.type.value, type(exc).__name__)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _clamp(value: Any) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    if num != num:  # NaN
        return 0.0
    return max(0.0, min(1.0, num))


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
