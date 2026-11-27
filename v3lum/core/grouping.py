"""Display grouping of near-duplicate findings (P335): presentation only.

Terminal, HTML and Markdown renderers may show findings that state **the same fact about the same
subject** as one row; the case JSON, STIX/MISP exports and evidence keep every entity, finding,
source and link (these functions never modify their input and every finding id appears in exactly
one group). Distinct IOCs are never merged: URL variants are grouped visually and exported
separately. Score de-duplication is the risk model's job (``v3lum.core.scoring``), not this one.

What groups (union-find over the grouping keys below; a finding may carry several keys and a group
is a connected component):

* **the same breach across sources** - findings tagged ``breach`` on the same entity whose breach
  key matches: ``data['breach_key']`` when the module gives one (already normalised by the breach
  modules), else ``data['name']`` / ``data['breach']`` / ``data['breach_name']`` lower-cased with
  everything but letters and digits removed. Key ``breach|<entity key>|<breach key>``. Withheld
  sensitive names (no key) never group.
* **URL variants of one resource** - findings on URL entities whose :func:`normalize_url_key` is the
  same and which state the same kind of fact (``scoring.tag_family``). Key
  ``url|<normalized url>|<tag family>``. A URL without a path never groups (portals reuse the
  homepage for different records).
* **the same CVE from several sources** - findings naming one CVE (the entity itself, or
  ``data['cve']`` / ``data['cve_id']``, or exactly one CVE id in the title) about the same subject
  and the same kind of fact. Key ``cve|<subject entity key>|<CVE-ID>|<tag family>``.

Identity entities (username, social_account, person_name, email, phone and every other personal
type) are never merged: every key above contains the exact subject entity key, so two different
handles, addresses or names never share a group (homonyms stay apart). A finding matching no rule is
its own group, key ``finding|<finding id>``. The key of a group is the smallest key of its members.

A group (:class:`FindingGroup`) shows the highest severity and the highest confidence label with the
criterion of its principal member (highest confidence, then severity, then id), the count, the
sources and their upstream families ('seen by 3 sources: ...'); every member keeps its own id
(evidence, feedback). :func:`group_correlations` groups correlations by their subject entity (the
first entity they name).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from v3lum.core import entities as _entities
from v3lum.core.models import finding_id

__all__ = [
    "FindingGroup",
    "HOST_PREFIXES",
    "TRACKING_PARAMS",
    "group_correlations",
    "group_findings",
    "normalize_url_key",
]

#: Query parameters dropped from the URL key (plus every ``utm_*``): tracking, not content.
TRACKING_PARAMS: frozenset[str] = frozenset({"fbclid", "gclid", "igshid", "ref", "si", "hl", "trk"})
#: Host prefixes removed from the URL key (repeatedly, while a registrable name remains).
HOST_PREFIXES: tuple[str, ...] = ("www.", "m.")
#: Default ports dropped from the URL key.
_DEFAULT_PORTS = {"http": 80, "https": 443}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONF_RANK = {"confirmed": 2, "probable": 1, "possible": 0}
_SENSITIVE_NAMES = frozenset({"sensitivebreachnamewithheld", "sensitivebreach", "withheld"})


@dataclass(frozen=True)
class FindingGroup:
    """One display row: findings (or correlations) stating the same fact about the same subject."""

    key: str
    member_ids: tuple[str, ...]
    severity: str
    confidence_label: str
    criterion: str
    count: int
    sources: tuple[str, ...] = ()
    upstream_families: tuple[str, ...] = ()
    kind: str = "finding"  # breach | url | cve | finding | correlation
    entities: tuple[str, ...] = ()
    title: str = ""
    principal_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    def label(self) -> str:
        """'seen by 3 sources: a, b, c' (or 'seen by 1 source: a'; '' without a source)."""
        if not self.sources:
            return ""
        n = len(self.sources)
        return f"seen by {n} source{'s' if n != 1 else ''}: {', '.join(self.sources)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "member_ids": list(self.member_ids),
            "principal_id": self.principal_id,
            "title": self.title,
            "severity": self.severity,
            "confidence_label": self.confidence_label,
            "criterion": self.criterion,
            "count": self.count,
            "sources": list(self.sources),
            "upstream_families": list(self.upstream_families),
            "entities": list(self.entities),
            "label": self.label(),
        }


# ----------------------------------------------------------------------------------------
# keys
# ----------------------------------------------------------------------------------------


def normalize_url_key(url: Any) -> str | None:
    """The grouping key of a URL (Ceos rules, P335 cond 5), or None when it must never group.

    Refanged; scheme dropped for http/https (kept as a prefix for any other scheme); host lower-cased
    without leading ``www.`` / ``m.``; default ports and credentials dropped; no trailing slash; query
    parameters ``utm_*``, fbclid, gclid, igshid, ref, si, hl and trk dropped and the rest sorted;
    fragment dropped. A URL without a path (``https://example.com/?id=1``) returns None: portals reuse
    the homepage for different records. Example: ``hxxps://WWW.Example[.]com/a/b/?utm_source=x&z=1&a=2``
    -> ``example.com/a/b?a=2&z=1``."""
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text:
        return None
    try:
        text = _entities.refang(text)
    except Exception:  # noqa: BLE001 - an odd value is used as given
        pass
    if "://" not in text:
        if text.startswith("//"):
            text = "http:" + text
        else:
            text = "http://" + text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").strip().lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    changed = True
    while changed:
        changed = False
        for prefix in HOST_PREFIXES:
            rest = host[len(prefix):]
            if host.startswith(prefix) and "." in rest:
                host = rest
                changed = True
    path = parts.path.rstrip("/")
    if not path:
        return None
    scheme = (parts.scheme or "http").lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = host if port is None or _DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _tracking(k)]
    query = urlencode(sorted(pairs))
    prefix = "" if scheme in _DEFAULT_PORTS else f"{scheme}://"
    return f"{prefix}{netloc}{path}" + (f"?{query}" if query else "")


def _tracking(name: str) -> bool:
    low = str(name).strip().lower()
    return low.startswith("utm_") or low in TRACKING_PARAMS


def _breach_key(data: Any) -> str:
    if not isinstance(data, Mapping):
        return ""
    raw = data.get("breach_key")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().lower()
    for name in ("name", "breach", "breach_name"):
        value = data.get(name)
        if isinstance(value, str) and value.strip():
            key = re.sub(r"[^0-9a-z]+", "", value.strip().lower())
            if key and key not in _SENSITIVE_NAMES:
                return key
    return ""


def _cve_of(d: Mapping[str, Any]) -> str:
    entity = str(d.get("entity") or "")
    if entity.lower().startswith("cve:"):
        found = _CVE_RE.findall(entity)
        return found[0].upper() if found else ""
    data = d.get("data") if isinstance(d.get("data"), Mapping) else {}
    for name in ("cve", "cve_id"):
        value = data.get(name)
        if isinstance(value, str):
            found = _CVE_RE.findall(value)
            if len(found) == 1:
                return found[0].upper()
    found = {m.upper() for m in _CVE_RE.findall(str(d.get("title") or ""))}
    return next(iter(found)) if len(found) == 1 else ""


def _fact(d: Mapping[str, Any]) -> str:
    from v3lum.core.scoring import tag_family  # lazy: scoring pulls in the graph

    return tag_family(d)


def _keys(d: Mapping[str, Any]) -> list[str]:
    """The grouping keys of one finding dict (see the module docstring)."""
    keys: list[str] = []
    entity = str(d.get("entity") or "")
    etype, _, value = entity.partition(":")
    tags = {str(t) for t in d.get("tags") or ()}
    if entity and "breach" in tags:
        bk = _breach_key(d.get("data"))
        if bk:
            keys.append(f"breach|{entity}|{bk}")
    if etype == "url" and value:
        uk = normalize_url_key(value)
        if uk:
            keys.append(f"url|{uk}|{_fact(d)}")
    cve = _cve_of(d)
    if cve and entity:
        keys.append(f"cve|{entity}|{cve}|{_fact(d)}")
    return keys


# ----------------------------------------------------------------------------------------
# grouping
# ----------------------------------------------------------------------------------------


def group_findings(findings: Iterable[Any]) -> list[FindingGroup]:
    """Group finding dicts (case JSON) or ``Finding`` objects for display (P335).

    Every finding lands in exactly one group (a finding without a match is a group of one); the input
    is never modified. Groups are ordered by severity, then confidence (both highest first), then key.
    """
    items = [_finding_dict(f, i) for i, f in enumerate(findings or ())]
    n = len(items)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    all_keys: list[list[str]] = []
    for i, d in enumerate(items):
        keys = _keys(d)
        all_keys.append(keys)
        for key in keys:
            if key in owner:
                a, b = find(i), find(owner[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                owner[key] = i
    components: dict[int, list[int]] = {}
    for i in range(n):
        components.setdefault(find(i), []).append(i)
    groups: list[FindingGroup] = []
    for members in components.values():
        counts: dict[str, int] = {}
        for i in members:
            for k in set(all_keys[i]):
                counts[k] = counts.get(k, 0) + 1
        # a group of several members is named by the smallest key at least two of them share (a key
        # only one member carries - e.g. a CVE named in one URL variant's title - never names it);
        # a lone finding is keyed by its id
        shared = sorted(k for k, c in counts.items() if c >= 2)
        key = shared[0] if len(members) > 1 and shared else f"finding|{items[members[0]]['id']}"
        kind = key.split("|", 1)[0]
        groups.append(_make_group(key, kind, [items[i] for i in members], families=True))
    groups.sort(key=_group_order)
    return groups


def group_correlations(correlations: Iterable[Any]) -> list[FindingGroup]:
    """Group correlation dicts (case JSON) or ``Correlation`` objects by subject entity (their first
    entity; ``entity|`` for none). Key ``entity|<entity key>``; ``sources`` lists the rule ids. Every
    correlation lands in exactly one group; the input is never modified."""
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for i, c in enumerate(correlations or ()):
        d = _correlation_dict(c, i)
        ents = [str(e) for e in d.get("entities") or () if e]
        by_subject.setdefault(ents[0] if ents else "", []).append(d)
    groups = [_make_group(f"entity|{subject}", "correlation", members, families=False) for subject, members in by_subject.items()]
    groups.sort(key=_group_order)
    return groups


def _make_group(key: str, kind: str, members: list[dict[str, Any]], *, families: bool) -> FindingGroup:
    ordered = sorted(members, key=lambda d: (-_conf(d), -_sev(d), str(d.get("id") or "")))
    principal = ordered[0]
    severity = max(members, key=_sev).get("severity") or "info"
    confidence = max(members, key=_conf).get("confidence_label") or "possible"
    if kind == "correlation":
        sources = sorted({str(d.get("rule") or "") for d in members} - {""})
        ents = sorted({str(e) for d in members for e in d.get("entities") or () if e})
        upstream: list[str] = []
    else:
        sources = sorted({str(d.get("source") or d.get("module") or "") for d in members} - {""})
        ents = sorted({str(d.get("entity") or "") for d in members} - {""})
        upstream = sorted({fam for d in members for fam in _families(d)}) if families else []
    return FindingGroup(
        key=key,
        member_ids=tuple(str(d.get("id") or "") for d in ordered),
        severity=str(severity).lower(),
        confidence_label=str(confidence).lower(),
        criterion=str(principal.get("criterion") or ""),
        count=len(members),
        sources=tuple(sources),
        upstream_families=tuple(upstream),
        kind=kind,
        entities=tuple(ents),
        title=str(principal.get("title") or ""),
        principal_id=str(principal.get("id") or ""),
    )


def _group_order(g: FindingGroup) -> tuple[int, int, str]:
    return (-_SEV_RANK.get(g.severity, 0), -_CONF_RANK.get(g.confidence_label, 0), g.key)


def _sev(d: Mapping[str, Any]) -> int:
    return _SEV_RANK.get(str(d.get("severity") or "info").lower(), 0)


def _conf(d: Mapping[str, Any]) -> int:
    label = str(d.get("confidence_label") or "").lower()
    if label in _CONF_RANK:
        return _CONF_RANK[label]
    try:
        value = float(d.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0
    return 2 if value >= 0.85 else 1 if value >= 0.55 else 0


def _families(d: Mapping[str, Any]) -> list[str]:
    """Upstream families of a finding's source (registry), else of its module's single source."""
    try:
        from v3lum.core import providers as _providers
        from v3lum.core.module import REGISTRY

        reg = _providers.registry()
    except Exception:  # noqa: BLE001 - display helper: no registry, no families
        return []
    sid = str(d.get("source") or "")
    src = reg.source(sid) if sid else None
    if src is None:
        cls = REGISTRY.get(str(d.get("module") or ""))
        declared = tuple(getattr(cls, "sources", ()) or ()) if cls is not None else ()
        if sid and "." not in sid and getattr(cls, "provider", ""):
            src = reg.source(f"{cls.provider}.{sid}")
        if src is None and len(declared) == 1:
            src = reg.source(str(declared[0]))
    if src is None:
        return []
    return sorted(getattr(src, "families", ()) or ({src.upstream_family} - {""}))


def _finding_dict(f: Any, index: int) -> dict[str, Any]:
    """A read-only dict view of a finding (dicts are copied shallowly, objects read)."""
    if isinstance(f, Mapping):
        d = dict(f)
        if not d.get("id"):
            d["id"] = f"#{index}"
        return d
    entity = getattr(f, "entity", None)
    raw_key = getattr(entity, "key", "") if entity is not None else ""
    fid = str(getattr(f, "id", "") or "") or finding_id(str(getattr(f, "module", "") or ""), raw_key, str(getattr(f, "title", "") or ""), str(getattr(f, "key", "") or ""))
    key = _persisted_key(entity, raw_key)
    label = getattr(f, "label", None)
    severity = getattr(f, "severity", None)
    return {
        "id": fid,
        "title": str(getattr(f, "title", "") or ""),
        "severity": getattr(severity, "label", str(severity or "info")),
        "confidence_label": getattr(label, "value", str(label or "")),
        "criterion": str(getattr(f, "criterion", "") or ""),
        "entity": key,
        "module": str(getattr(f, "module", "") or ""),
        "source": str(getattr(f, "source", "") or ""),
        "tags": list(getattr(f, "tags", ()) or ()),
        "data": dict(getattr(f, "data", None) or {}),
    }


def _persisted_key(entity: Any, key: str) -> str:
    """The entity key as the case JSON stores it: SECRET_TYPES values (jwt, bot tokens...) redacted,
    so a group built from ``Finding`` objects never carries a raw secret into a rendered row."""
    etype = getattr(entity, "type", None)
    if etype is None or etype not in _entities.SECRET_TYPES:
        return key
    try:
        return f"{etype.value}:{_entities.redacted_value(etype, entity.value)}"
    except Exception:  # noqa: BLE001 - fail closed: the type only
        return f"{etype.value}:[redacted]"


def _correlation_dict(c: Any, index: int) -> dict[str, Any]:
    if isinstance(c, Mapping):
        d = dict(c)
    else:
        to_dict = getattr(c, "to_dict", None)
        d = dict(to_dict()) if callable(to_dict) else {}
    if not d.get("id"):
        d["id"] = f"#{index}"
    return d
