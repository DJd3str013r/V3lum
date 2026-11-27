"""analytics_ids: offline analytics / tag-manager / AdSense id extraction (P061, batch p2-G03-1).

The offline half of P061 (architect floor, cond 1): ids are extracted locally from bodies already in
hand - text and file inputs, a URL's own text, and (through :func:`extract_analytics_ids`, a library
function) the bodies web_fingerprint (P072), archived snapshots (P060/P070) and urlscan DOMs (P066)
already hold. Disclosure ``none``: no request at all, so it runs under TLP:RED. The Google Tag Manager
fetch is the separate module ``gtm_expand`` (disclosure third_party).

Final conditions implemented here (P061):

* c1 - local extraction only (``disclosure='none'``, ``hosts=()``); GTM expansion lives in gtm_expand.
* c2 - bounded, case-sensitive regexes: ``UA-\\d{4,10}-\\d{1,4}``, ``G-[A-Z0-9]{6,12}`` (the bellingcat
  digits-only regex is fixed), ``GTM-[A-Z0-9]{4,9}``, ``pub-\\d{16}`` and ``ca-pub-``; look-around
  boundaries, no nested quantifiers, tested against a 1 MB adversarial body within a time budget.
  AW-/DC- ids are only read from GTM containers (gtm_expand), never from pages.
* c4 - reverse lookups happen by pivoting ``analytics_id`` entities (expand=True) to the modules that
  accept the type (host.io P004, HackerTarget P014, urlscan P066); no reverse client is re-implemented
  here and SpyOnWeb is left out.
* c5 - template/placeholder ids ('UA-000000-1', all-X, all-zero, ascending digit runs) and known
  agency/CMS/site-builder ids are labelled 'shared ID': info, no pivot, confidence <= 0.3. The
  > 50-domain fan-out rule is applied by the reverse-lookup modules and by the case rule
  ``g03_same_analytics`` (v3lum/correlations/p2_g03_1.py), which also implements c6-c8 over the graph
  (clone rule, same_analytics links with provenance and overlapping dates).
* c7/c8 - every sighting records where it was seen (``text``, ``file``, ``url``, or ``live``/``archive``
  /``urlscan``/``gtm`` for library callers) and when (``seen_at``, archive ``snapshot`` date).
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

# ---------------------------------------------------------------------------------------------- patterns
#: P061 c2 - boundaries stop matches inside longer tokens; quantifiers are bounded, never nested.
ANALYTICS_PATTERNS: dict[str, re.Pattern[str]] = {
    "ua": re.compile(r"(?<![A-Za-z0-9-])UA-\d{4,10}-\d{1,4}(?![0-9])"),
    "ga4": re.compile(r"(?<![A-Za-z0-9-])G-[A-Z0-9]{6,12}(?![A-Za-z0-9])"),
    "gtm": re.compile(r"(?<![A-Za-z0-9-])GTM-[A-Z0-9]{4,9}(?![A-Za-z0-9])"),
    "adsense": re.compile(r"(?<![A-Za-z0-9-])(?:ca-)?pub-\d{16}(?![0-9])"),
}
#: Only inside GTM containers (c2: "in GTM expansion also quoted AW- and DC- ids"), quoted strings only.
GTM_QUOTED_ID_RE = re.compile(r'"((?:G-[A-Z0-9]{6,12})|(?:UA-\d{4,10}-\d{1,4})|(?:AW-\d{6,12})|(?:DC-\d{6,10})|(?:GTM-[A-Z0-9]{4,9}))"')
ANALYTICS_ID_FULL = re.compile(r"(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,9}|(?:ca-)?pub-\d{16}|AW-\d{6,12}|DC-\d{6,10})\Z")
#: ids many unrelated sites carry (HackerTarget answered 'UA-000000-1' with 10 unrelated sites)
KNOWN_TEMPLATE_IDS = frozenset({"UA-000000-1", "UA-0000000-1", "UA-00000000-1", "UA-XXXXX-X", "UA-XXXXX-Y"})
#: known agency / CMS / site-builder ids (c5). Empty until the team-maintained list exists
#: (backlog p2-G03-1: v3lum/data/analytics_shared_ids.json); the > 50-domain rule covers the rest.
KNOWN_SHARED_IDS: frozenset[str] = frozenset()
SHARED_FANOUT_THRESHOLD = 50  # c5: > 50 domains -> shared ID
REVERSE_PIVOT_CAP = 10  # c5: reverse-lookup pivots per id
SAME_ANALYTICS_MAX_CONFIDENCE = 0.7  # c7: PROBABLE at most
SHARED_ID_MAX_CONFIDENCE = 0.3  # c5
OVERLAP_TOLERANCE_DAYS = 90  # c7: archive sightings are point samples, each window is widened by this
MAX_INPUT_BYTES = 5_000_000
MAX_IDS = 200
TEXT_EXT = {".html", ".htm", ".js", ".mjs", ".cjs", ".json", ".txt", ".xml", ".har", ".log", ".md", ".csv", ".svg", ".php", ".asp", ".aspx", ".jsp", ""}
KIND_LABELS = {"ua": "Universal Analytics", "ga4": "Google Analytics 4", "gtm": "Google Tag Manager container", "adsense": "AdSense publisher",
               "aw": "Google Ads conversion", "dc": "Floodlight (Campaign Manager) advertiser"}
SIGHTING_WHERE = ("text", "file", "url", "live", "archive", "urlscan", "gtm")


def _text(raw: Any, limit: int | None = None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    elif not isinstance(raw, str):
        raw = str(raw)
    return raw[:limit] if limit is not None else raw


def parse_iso(value: Any) -> datetime | None:
    """ISO-8601 / RFC 3339 or a Wayback timestamp (YYYYMMDD[hhmmss]) -> aware datetime, else None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if re.fullmatch(r"\d{8}(?:\d{6})?", v):
        try:
            return datetime.strptime(v.ljust(14, "0"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------------------------- id facts
def analytics_kind(value: Any) -> str | None:
    """'ua' | 'ga4' | 'gtm' | 'adsense' | 'aw' | 'dc' | None for one id string (case-sensitive)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not ANALYTICS_ID_FULL.match(v):
        return None
    for prefix, kind in (("UA-", "ua"), ("GTM-", "gtm"), ("G-", "ga4"), ("AW-", "aw"), ("DC-", "dc")):
        if v.startswith(prefix):
            return kind
    return "adsense"


def normalise_analytics_id(value: Any) -> str | None:
    """Canonical id: 'ca-pub-N' -> 'pub-N'; other ids unchanged (case-sensitive). None when invalid."""
    if not analytics_kind(value):
        return None
    v = str(value).strip()
    return v[3:] if v.startswith("ca-pub-") else v


def analytics_key(value: Any) -> str | None:
    """Grouping key for ownership comparisons: UA ids by account ('UA-NNNN', the level reverse services
    index), AdSense by publisher ('pub-N'), other ids by the full id."""
    v = normalise_analytics_id(value)
    if not v:
        return None
    return v.rsplit("-", 1)[0] if v.startswith("UA-") else v


def is_template_id(value: Any) -> bool:
    """c5 'known template id': placeholders many unrelated sites carry - KNOWN_TEMPLATE_IDS, all-X bodies,
    all-zero digits and ascending digit runs ('123456...')."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v in KNOWN_TEMPLATE_IDS:
        return True
    body = re.sub(r"^(?:ca-)?(?:UA|GTM|G|AW|DC|pub)-", "", v)
    core = body.split("-")[0] if v.startswith("UA-") else body
    if core and set(core) <= {"X"}:
        return True
    digits = re.sub(r"\D", "", core)
    return bool(digits and digits == core and (set(digits) == {"0"} or ("12345678901234567890".startswith(digits) and len(digits) >= 6)))


def shared_id_decision(analytics_id: Any, reverse_total: int | None = None, known_shared_ids: Any = ()) -> dict[str, Any]:
    """c5: 'shared ID' when template/placeholder, a known agency/CMS/site-builder id, or a reverse lookup
    with more than 50 domains. Shared -> info, no pivots, no same-owner correlation, confidence <= 0.3."""
    key = analytics_key(analytics_id)
    known = {analytics_key(k) or k for k in (tuple(known_shared_ids or ()) + tuple(KNOWN_SHARED_IDS))}
    if not key:
        return {"shared": True, "reason": "not a valid analytics id", "confidence_cap": 0.0}
    if is_template_id(analytics_id) or is_template_id(key):
        return {"shared": True, "reason": "template/placeholder id", "confidence_cap": SHARED_ID_MAX_CONFIDENCE}
    if key in known or analytics_id in known:
        return {"shared": True, "reason": "known agency/CMS/site-builder template id", "confidence_cap": SHARED_ID_MAX_CONFIDENCE}
    if isinstance(reverse_total, int) and not isinstance(reverse_total, bool) and reverse_total > SHARED_FANOUT_THRESHOLD:
        return {"shared": True, "reason": f"reverse lookup returned {reverse_total} domains (> {SHARED_FANOUT_THRESHOLD})",
                "confidence_cap": SHARED_ID_MAX_CONFIDENCE}
    return {"shared": False, "reason": None, "confidence_cap": SAME_ANALYTICS_MAX_CONFIDENCE}


def windows_overlap(a: tuple[datetime | None, datetime | None], b: tuple[datetime | None, datetime | None], tolerance_days: int = OVERLAP_TOLERANCE_DAYS) -> bool:
    """c7: two sighting windows (first, last) overlap once each is widened by ``tolerance_days`` (archive
    snapshots are point samples). Missing dates never overlap."""
    if not a or not b or None in a or None in b:
        return False
    tol = timedelta(days=tolerance_days)
    return a[0] - tol <= b[1] and b[0] - tol <= a[1]  # type: ignore[operator]


def sighting_label(where: str, *, seen_at: Any = None, snapshot: Any = None, container: Any = None) -> str:
    """c8: where an id was seen, for every same_analytics link ('live page 2026-11-26', 'archive snapshot
    20190101...', 'GTM container GTM-XXXX')."""
    day = str(seen_at or "")[:10]
    if where == "archive":
        return f"archive snapshot {snapshot or day or '?'}"
    if where == "gtm":
        return f"GTM container {container or '?'}" + (f" ({day})" if day else "")
    if where == "urlscan":
        return f"urlscan DOM {day or '?'}"
    if where in ("text", "file", "url"):
        return f"{where} input" + (f" {day}" if day else "")
    return f"live page {day or '?'}"


def extract_analytics_ids(body: Any, where: str = "live", url: str | None = None, seen_at: Any = None, container: str | None = None,
                          snapshot: Any = None, max_bytes: int = MAX_INPUT_BYTES, max_ids: int = MAX_IDS) -> dict[str, Any]:
    """c1/c2: UA-/G-/GTM-/pub-/ca-pub- ids of a body already in hand (no request: library for web_fingerprint,
    archive and urlscan modules). Archived snapshots pass ``where='archive'`` and the snapshot timestamp
    (c7: links need overlapping dates). Returns ``{"ids": [{id, kind, key, template, count, where, url,
    seen_at, snapshot, container}], "truncated"}``."""
    text = _text(body)
    truncated = len(text) > max_bytes
    if truncated:
        text = text[:max_bytes]
    where = where if where in SIGHTING_WHERE else "live"
    found: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for kind, rx in ANALYTICS_PATTERNS.items():
        for m in rx.finditer(text):
            norm = normalise_analytics_id(m.group(0))
            if not norm:
                continue
            if norm not in found:
                if len(order) >= max_ids:
                    truncated = True
                    continue
                found[norm] = {"id": norm, "kind": kind, "key": analytics_key(norm), "template": is_template_id(m.group(0)) or is_template_id(norm),
                               "count": 0, "where": where, "url": url, "seen_at": seen_at, "snapshot": snapshot, "container": container}
                order.append(norm)
            found[norm]["count"] += 1
    return {"ids": [found[k] for k in order], "truncated": truncated}


def adversarial_analytics_body(size: int = 1_000_000) -> str:
    """c2 time-budget input: ~1 MB of long digit/letter runs after each prefix and repeated near misses."""
    unit = size // 8
    parts = ["UA-" + "1" * unit, "G-" + "A" * unit, "GTM-" + "Z" * unit, "pub-" + "9" * unit,
             "UA-1234-" * (unit // 8), "G-ABCDEF-" * (unit // 9), "ca-pub-" * (unit // 7), "-" * unit]
    return "".join(parts)[:size]


def describe_id(value: Any) -> dict[str, Any] | None:
    """Facts about one id for the analytics_id_info attribute (c5)."""
    kind = analytics_kind(value)
    if not kind:
        return None
    norm = normalise_analytics_id(value)
    decision = shared_id_decision(norm)
    return {"id": norm, "kind": kind, "label": KIND_LABELS.get(kind, kind), "key": analytics_key(norm), "template": is_template_id(norm),
            "shared": decision["shared"], "reason": decision["reason"]}


def _reverse_modules(own: str) -> list[str]:
    try:
        from v3lum.core.module import modules_for

        return sorted({c.name for c in modules_for(T.ANALYTICS_ID) if c.name != own})
    except Exception:  # noqa: BLE001 - the listing is informative only
        return []


@register
class AnalyticsIds(Module):
    name = "analytics_ids"
    title = "Analytics / tag-manager / AdSense ids (offline)"
    description = (
        "Extracts Google Analytics (UA-/G-), Tag Manager (GTM-) and AdSense (pub-/ca-pub-) ids from text, files and URLs "
        "already in hand, with case-sensitive bounded regexes; template ids are 'shared ID' (no pivot)."
    )
    category = "url_web"
    accepts = {T.TEXT, T.FILE, T.URL, T.ANALYTICS_ID}
    produces = {T.ANALYTICS_ID}
    tags = {"offline"}
    reference = "https://github.com/bellingcat/wayback-google-analytics"
    terms = "open"  # local algorithm, no registry source
    opsec = Opsec.PASSIVE
    disclosure = "none"  # bodies already in hand: no request, TLP:RED allowed (P061 cond 1)
    hosts = ()
    access_model = "offline"
    default_enabled = True
    max_pivots = MAX_IDS

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            path = entity.value
            ext = os.path.splitext(path)[1].lower()
            # regular text-like files only: a FIFO or device would block (not applicable)
            return ext in TEXT_EXT and os.path.isfile(path) and os.path.getsize(path) <= MAX_INPUT_BYTES
        if entity.type is T.ANALYTICS_ID:
            return analytics_kind(entity.value) is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.ANALYTICS_ID:
            return self._describe(entity, res)
        if entity.type is T.FILE:
            try:
                with open(entity.value, encoding="utf-8", errors="replace") as fh:
                    body = fh.read(MAX_INPUT_BYTES + 1)
            except OSError as exc:
                return res.mark(Status.ERROR, f"cannot read the file: {exc.strerror or type(exc).__name__}")
            where = "file"
        else:
            body = entity.value
            where = "url" if entity.type is T.URL else "text"
        seen_at = ctx.now().isoformat(timespec="seconds").replace("+00:00", "Z")
        out = extract_analytics_ids(body, where=where, url=entity.value if entity.type is T.URL else None, seen_at=seen_at)
        ids = out["ids"]
        res.raw = {"where": where, "truncated": out["truncated"], "ids": [{k: i[k] for k in ("id", "kind", "key", "template", "count")} for i in ids]}
        if not ids:
            return res.mark(Status.EMPTY, f"no Google Analytics, Tag Manager or AdSense id in the {where} input")
        res.attr("analytics_ids", [i["id"] for i in ids])
        res.attr("analytics_sightings", [{k: i[k] for k in ("id", "kind", "key", "count", "where", "seen_at", "template")} for i in ids])
        templates = [i["id"] for i in ids if i["template"]]
        for item in ids:
            if item["template"]:
                continue
            label = sighting_label(where, seen_at=seen_at)
            res.pivot(T.ANALYTICS_ID, item["id"], "mentions", confidence="probable",
                      note=f"{KIND_LABELS.get(item['kind'], item['kind'])} id seen {item['count']}x ({label}); reverse lookups run on it "
                           "(same-owner links stay PROBABLE at most, never alone CONFIRMED)")
        if templates:
            res.finding(
                "Template or placeholder tracking id (shared ID)",
                "info",
                f"{', '.join(templates)}: template/placeholder ids that many unrelated sites carry: info only, no pivot and no "
                "same-owner correlation (P061 cond 5).",
                confidence=SHARED_ID_MAX_CONFIDENCE,
                tags=["shared_tracking_id", "context_only"],
                data={"ids": templates},
            )
        if out["truncated"]:
            res.finding(
                "Tracking-id extraction truncated",
                "info",
                f"the input exceeded the extraction caps ({MAX_INPUT_BYTES} bytes or {MAX_IDS} distinct ids): later ids were not read",
                confidence="confirmed",
                data={"max_bytes": MAX_INPUT_BYTES, "max_ids": MAX_IDS},
            )
        return res

    def _describe(self, entity: Entity, res: ModuleResult) -> ModuleResult:
        info = describe_id(entity.value)
        if info is None:  # pragma: no cover - applies() filters these
            return res.mark(Status.SKIPPED, "not a UA-/G-/GTM-/AW-/DC-/pub- id", reason_code="not_applicable")
        info["expandable_by"] = (["gtm_expand"] if info["kind"] == "gtm" else []) + [m for m in _reverse_modules(self.name) if m != "gtm_expand"]
        res.attr("analytics_id_info", info)
        if info["shared"]:
            res.finding(
                "Shared tracking id (template or placeholder)",
                "info",
                f"{info['id']}: {info['reason']}: a 'shared ID' - info only, no pivots and no same-owner correlation (P061 cond 5).",
                confidence=SHARED_ID_MAX_CONFIDENCE,
                tags=["shared_tracking_id", "context_only"],
                data={"id": info["id"], "reason": info["reason"]},
            )
        return res
