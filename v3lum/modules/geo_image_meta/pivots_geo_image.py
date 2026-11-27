"""Reverse-image and map pivot links: TinEye, Google Lens, ImgOps, Yandex, OpenStreetMap, Google Maps (P260).

Offline data pack plus its renderer (disclosure 'none', terms 'open', provider tier n/a, default-on). V3LUM
never requests these URLs or any API behind them; the analyst opens them by hand. Final conditions:

* c1 the pack is ``v3lum/data/pivot_links/geo_image.json`` in the frozen ``v3lum.pivot_pack/1`` schema. Every
  link is an ``x_module_links`` entry with the frozen link fields plus ``x_max_tlp`` (the per-link max_tlp the
  phase-0 schema lacks), ``x_warning`` and ``x_badge``; this module renders them because the core link model
  cannot check image URLs, file origin, max_tlp or split coordinates (docs/backlog/p2-G12-1.md).
* c2 A2 rendering: at TLP:AMBER and above every label carries 'opening sends <value> to <host>' (the renderers
  show module links as non-clickable text there); at RED nothing is emitted (third-party links hidden from
  reports); links are never opened by V3LUM.
* c3 templates are rendered by whitelist substitution with ``re.sub`` (never ``str.format``, never ``{raw}``)
  from the placeholders of :data:`GEO_PLACEHOLDERS` through their encoders; every rendered URL is re-checked
  (https, the declared host, no userinfo/port, no unencoded quote/space/control character, empty fragment).
  The tests render every template with sample and hostile values.
* c4/c5 every host has a provider fragment with tier and rationale (tineye, google_lens, imgops, yandex,
  openstreetmap, google_web); unknown-tier hosts (ImgOps) get the 'unknown operator' badge and URL values only,
  and are hidden at TLP:AMBER and above (A8: unknown tiers are excluded there).
* c6 file order = curated order (TinEye, Lens, ImgOps, Yandex; OSM, Google Maps), verified links first (stable);
  at most 4 reverse-image or 2 map links per entity, below the terminal cap of :data:`TERMINAL_MAX_LINKS`.
* c7 verified links carry ``checked_at``; :func:`recheck_report` (offline) lists unverified links and links not
  re-checked for more than 180 days, for ``v3lum doctor --links`` (core request: call it).
* c8 reverse-image links only for public http(s) image URLs (known image extension): never page URLs, file://,
  data:, private/reserved IPs, internal hosts, userinfo, odd ports, dot segments, per-recipient token URLs
  (``v3lum.core.policy.recipient_token``) or FILE entities.
* c9 every reverse-image result carries the standing label :data:`REVERSE_IMAGE_LABEL` (an info finding shown
  above the links and the raw ``standing_label``); no links for URLs found inside documents or files.
* c10 Yandex: x_warning 'foreign provider (RU): ...' and x_max_tlp green (hidden at TLP:AMBER and above).
* c11 map templates take lat/lon from the normalised coordinates through the vetted ``{lat}``/``{lon}``
  placeholders; privacy links shown only for coordinates the analyst typed or confirmed, with
  ``--show-personal`` and a recorded purpose (the core's opt-in rule for privacy links).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core import links as _links
from v3lum.core import tlp as _tlp
from v3lum.core.entities import IOC_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

PACK = "geo_image"
EXT_KEY = "x_module_links"
REVERSE_IMAGE_LABEL = ("not for identifying people from facial images: use for impersonation, fake-profile and "
                       "cloned-logo checks within the case purpose")  # c9
GEO_PLACEHOLDERS: dict[str, frozenset[T]] = {  # c3/c11: placeholder -> the only entity type it accepts
    "url_q": frozenset({T.URL}), "url_path": frozenset({T.URL}),
    "lat": frozenset({T.COORDINATES}), "lon": frozenset({T.COORDINATES}),
}
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".jfif", ".pjpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic",
                    ".heif", ".avif", ".svg", ".ico")
INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".corp", ".lan", ".home", ".home.arpa",
                     ".localdomain", ".private", ".test", ".invalid", ".example", ".onion")
FILE_MODULES = frozenset({"image_metadata", "qr_decode", "pe_triage", "yara_scan", "document_metadata",
                          "archive_listing", "apk_triage", "file_type_sniff", "file_hashing", "ioc_extract",
                          "windows_artifact_triage", "email_header_analyzer", "email_header_analyzer_msg"})
LINK_STALE_DAYS = 180  # c7
TERMINAL_MAX_LINKS = 8  # c6
_EXT_FIELDS = frozenset({"x_max_tlp", "x_warning", "x_badge"})
_RE_PH = re.compile(r"\{([^{}]*)\}")
_RE_CTRL = re.compile(r"[\x00-\x20\x7f-\x9f\"<>\\^`{|}]")
_RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_COORD = re.compile(r"^\s*-?\d{1,3}(?:\.\d{1,12})?\s*$")


@dataclass(frozen=True)
class GeoLink:
    """A linted entry of the pack's x_module_links."""

    id: str
    label: str
    template: str
    entity_types: tuple[T, ...]
    category: str
    host: str
    verified: bool
    checked_at: str
    privacy: bool
    touches_target: bool
    antibot: bool
    max_tlp: _tlp.TLP | None
    warning: str
    badge: str
    placeholders: tuple[str, ...]

    @property
    def ref(self) -> str:
        return f"{PACK}:{self.id}"

    @property
    def reverse_image(self) -> bool:
        return T.URL in self.entity_types


# --------------------------------------------------------------------------------------
# Lint (fail closed) and loading
# --------------------------------------------------------------------------------------


def lint_geo_entry(entry: Any) -> list[str]:
    """Every problem of one pack entry (c1, c3, c4, c8, c10, c11 plus the core P311 lint)."""
    if not isinstance(entry, Mapping):
        return ["an entry must be an object"]
    errs: list[str] = []
    template = entry.get("template")
    host = entry.get("host")
    if not isinstance(template, str) or not isinstance(host, str) or not template or not host:
        return ["template and host are required strings"]
    names = _RE_PH.findall(template)
    if not names:
        errs.append("a template needs a placeholder")
    unknown = sorted({n for n in names if n not in GEO_PLACEHOLDERS})
    if unknown:
        errs.append(f"placeholders {unknown} not allowed (only {sorted(GEO_PLACEHOLDERS)}; never {{raw}} or format specs)")
    if "{" in _RE_PH.sub("", template) or "}" in _RE_PH.sub("", template):
        errs.append("stray brace in the template")
    try:
        types = tuple(T(str(t)) for t in entry.get("entity_types") or ())
    except ValueError as exc:
        return errs + [f"unknown entity type ({exc})"]
    if len(types) != 1:
        errs.append("exactly one entity type per link (url or coordinates)")
    for name in names:
        allowed = GEO_PLACEHOLDERS.get(name)
        if allowed is not None and not set(types) <= allowed:
            errs.append(f"placeholder {{{name}}} is only for {sorted(t.value for t in allowed)}")
    if T.COORDINATES in types:
        if sorted(names) != ["lat", "lon"]:
            errs.append("map templates take exactly {lat} and {lon}")
        if entry.get("privacy") is not True:
            errs.append("coordinates links are privacy links (privacy=true, c11)")
    if "url_path" in names and template != f"https://{host}/{{url_path}}":
        errs.append("{url_path} must be the whole path: https://<host>/{url_path}")
    probe = _RE_PH.sub("x", template)
    try:
        parts = urlsplit(probe)
        port = parts.port
    except ValueError:
        return errs + ["unparseable template"]
    if parts.scheme != "https" or (parts.hostname or "") != host or parts.username or parts.password or port is not None:
        errs.append("https on exactly the declared host, without userinfo or port")
    if parts.fragment or "#" in template:
        errs.append("the value never goes into the fragment (P311)")
    for flag in ("publishes", "login_required"):
        if entry.get(flag) is not False:
            errs.append(f"{flag} must be false")
    for flag in ("verified", "privacy", "touches_target", "antibot"):
        if not isinstance(entry.get(flag), bool):
            errs.append(f"{flag} must be a boolean")
    if entry.get("verified") is True and not _valid_date(entry.get("checked_at")):
        errs.append("verified links carry checked_at (YYYY-MM-DD, c7)")
    if entry.get("x_max_tlp") not in (None, ""):
        try:
            _tlp.parse(entry.get("x_max_tlp"))
        except ValueError:
            errs.append(f"x_max_tlp {entry.get('x_max_tlp')!r} is not a TLP value")
    for key in ("x_warning", "x_badge", "label"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, str) or re.search(r"[\x00-\x1f]", value) or len(value) > 300):
            errs.append(f"{key} must be a single-line string")
    tier = _links.host_tier(host)
    if tier not in _links.TRUSTED_TIERS and any(t not in IOC_TYPES for t in types):
        errs.append(f"unknown-tier host {host} receives IOC_TYPES values only (A8 BR4)")
    view = {k: v for k, v in entry.items() if k not in _EXT_FIELDS}
    view["template"] = _RE_PH.sub("{q}", template)
    errs += [e.split(": ", 1)[-1] for e in _links.lint_pack({"schema": _links.SCHEMA, "pack": PACK, "title": PACK, "links": [view]}, source=f"{PACK}.json")]
    return errs


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str) or not _RE_DATE.match(value):
        return False
    try:
        _dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def parse_pack(data: Any) -> tuple[list[GeoLink], list[str]]:
    """Linted links (file order) and the problems of the others (dropped: fail closed)."""
    if not isinstance(data, Mapping) or data.get("schema") != _links.SCHEMA or data.get("pack") != PACK:
        return [], [f"{PACK}: not a {_links.SCHEMA} pack named {PACK!r}"]
    items = data.get(EXT_KEY)
    if not isinstance(items, list):
        return [], [f"{PACK}: {EXT_KEY} must be a list"]
    out: list[GeoLink] = []
    errs: list[str] = []
    seen: set[str] = set()
    for item in items:
        ident = str(item.get("id") if isinstance(item, Mapping) else "?")
        problems = lint_geo_entry(item)
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", ident) or ident in seen:
            problems.append("missing, invalid or duplicate id")
        if problems:
            errs.extend(f"{PACK}:{ident}: {p}" for p in problems)
            continue
        seen.add(ident)
        max_tlp = _tlp.parse(item["x_max_tlp"]) if item.get("x_max_tlp") else None
        out.append(GeoLink(
            id=ident, label=str(item.get("label") or ident), template=item["template"],
            entity_types=tuple(T(str(t)) for t in item["entity_types"]), category=str(item.get("category") or "other"),
            host=item["host"], verified=item["verified"], checked_at=str(item.get("checked_at") or ""),
            privacy=item["privacy"], touches_target=item["touches_target"], antibot=item["antibot"], max_tlp=max_tlp,
            warning=str(item.get("x_warning") or ""), badge=str(item.get("x_badge") or ""),
            placeholders=tuple(_RE_PH.findall(item["template"])),
        ))
    return out, errs


_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {}


def load_pack() -> tuple[list[GeoLink], list[str], dict[str, Any]]:
    """(links, problems, raw pack) of geo_image.json; re-linted when the provider registry changes."""
    from v3lum.core import providers

    token = providers.registry()
    with _LOCK:
        if _CACHE.get("token") is token:
            return _CACHE["links"], _CACHE["errors"], _CACHE["data"]
        try:
            data = json.loads((_links.PACKS_DIR / f"{PACK}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            found, errs, data = [], [f"{PACK}: unreadable pack ({type(exc).__name__})"], {}
        else:
            found, errs = parse_pack(data)
        _CACHE.update(token=token, links=found, errors=errs, data=data)
        return found, errs, data


def pack_errors() -> list[str]:
    return list(load_pack()[1])


# --------------------------------------------------------------------------------------
# Eligibility (c8, c9, c11) and rendering (c3)
# --------------------------------------------------------------------------------------


def from_file(provenance: Any) -> bool:
    """c9: the entity was found inside a document or file (any parent is a FILE or a file-analysis module)."""
    for step in provenance or ():
        try:
            parent, _relation, module = step
        except (TypeError, ValueError):
            continue
        if str(parent).startswith("file:") or str(module) in FILE_MODULES:
            return True
    return False


def _host_reason(host: str) -> str | None:
    import ipaddress

    h = host.strip("[]").lower().rstrip(".")
    if not h:
        return "no host"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if "." not in h or h.endswith(INTERNAL_SUFFIXES) or h in ("localhost",):
            return "internal or single-label host"
        return None
    return None if ip.is_global and not ip.is_multicast else "private, reserved or documentation address"


def image_url_eligible(url: Any, *, provenance: Any = (), org: Any = None) -> tuple[bool, str]:
    """c8/c9: (eligible, reason) for a reverse-image link: a public http(s) URL of an image file that was not
    found inside a document or file and carries no per-recipient token."""
    if from_file(provenance):
        return False, "found inside a document or file: no reverse-image links (c9)"
    u = url if isinstance(url, str) else ""
    if not u or any(ord(ch) < 32 or ord(ch) == 127 for ch in u):
        return False, "not a URL"
    try:
        parts = urlsplit(u)
        port = parts.port
    except ValueError:
        return False, "unparseable URL"
    if parts.scheme.lower() not in ("http", "https"):
        return False, f"scheme {parts.scheme or '-'}: only public http(s) image URLs"
    if parts.username or parts.password:
        return False, "URL with credentials"
    if port not in (None, 80, 443):
        return False, "non-default port"
    reason = _host_reason(parts.hostname or "")
    if reason:
        return False, reason
    if re.search(r"(^|/)\.{1,2}(/|$)", parts.path):
        return False, "dot segments in the path"
    if not parts.path.lower().endswith(IMAGE_EXTENSIONS):
        return False, "not an image URL (page URLs may carry victim identifiers)"
    try:
        from v3lum.core.policy import recipient_token

        if recipient_token(u, org):
            return False, "the URL carries a per-recipient token (opening it would confirm the recipient)"
    except ImportError:  # pragma: no cover - the policy module ships with wave 2
        pass
    return True, ""


def coordinate_values(value: Any) -> dict[str, str] | None:
    """c11: vetted {lat, lon} strings from a normalised 'lat,lon' value: finite, in range, not 0,0, 6 decimals,
    ASCII digits and '-' only."""
    if not isinstance(value, str):
        return None
    parts = value.split(",")
    if len(parts) != 2 or not all(_RE_COORD.match(p) for p in parts):
        return None
    try:
        lat, lon = float(parts[0]), float(parts[1])
    except ValueError:
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    return {"lat": f"{lat:.6f}", "lon": f"{lon:.6f}"}


def placeholder_values(entity: Entity) -> dict[str, str] | None:
    """Encoded placeholder values for an entity: url_q (quote, safe='') and url_path (scheme removed, everything
    but '/' encoded) for URLs; lat/lon for coordinates."""
    if entity.type is T.URL:
        rest = entity.value.split("://", 1)[1] if "://" in entity.value else entity.value
        return {"url_q": quote(entity.value, safe=""), "url_path": quote(rest, safe="/")}
    if entity.type is T.COORDINATES:
        return coordinate_values(entity.value)
    return None


def check_rendered_url(url: str, host: str) -> list[str]:
    """c3 invariants: https, the exact declared host, no userinfo/port, no unencoded quote/space/control
    character, an empty fragment, at most links.MAX_URL characters."""
    problems = []
    if not isinstance(url, str) or len(url) > _links.MAX_URL:
        return ["too long or not text"]
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return ["unparseable"]
    if parts.scheme != "https":
        problems.append("not https")
    if (parts.hostname or "") != host or parts.username or parts.password or port is not None or "@" in parts.netloc:
        problems.append("host differs from the declared host")
    if _RE_CTRL.search(url.replace("{", "").replace("}", "")) or "{" in url or "}" in url:
        problems.append("unencoded character")
    if parts.fragment or "#" in url:
        problems.append("text in the fragment")
    return problems


def render(link: GeoLink, entity: Entity) -> str | None:
    """The URL of ``link`` for ``entity``; None when it does not apply or any check fails (never a guess)."""
    if entity.type not in link.entity_types or entity.type in _links.NO_LINK_TYPES:
        return None
    tier = _links.host_tier(link.host)  # the registry tier now
    if entity.type not in IOC_TYPES and (tier not in _links.TRUSTED_TIERS or not link.privacy):
        return None
    values = placeholder_values(entity)
    if not values:
        return None

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in link.placeholders or name not in values or entity.type not in GEO_PLACEHOLDERS.get(name, ()):
            raise ValueError(name)
        return values[name]

    try:
        url = _RE_PH.sub(repl, link.template)
    except ValueError:
        return None
    return None if check_rendered_url(url, link.host) else url


def tlp_level(ctx: Any) -> _tlp.TLP:
    """The entity TLP of the run; an unreadable value fails closed to RED."""
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


def label_for(link: GeoLink, entity: Entity, url: str, level: _tlp.TLP) -> str:
    """c2/c4/c10 label: badges (unknown operator, unverified, who fetches the image), the link warning and, at
    TLP:AMBER and above, 'opening sends <value> to <host>'."""
    badges = []
    if _links.host_tier(link.host) == "unknown":
        badges.append(_links.BADGE_UNKNOWN_OPERATOR)
    if not link.verified:
        badges.append(_links.BADGE_UNVERIFIED)
    if link.badge:
        badges.append(link.badge)
    elif link.touches_target:
        badges.append(f"opening makes {link.host} fetch the image from its host")
    label = link.label + (" [" + "; ".join(badges) + "]" if badges else "")
    if link.warning:
        label += f" - WARNING: {link.warning}"
    if level >= _tlp.TLP.AMBER:
        rendered = _links.RenderedLink(ref=link.ref, label=link.label, url=url, host=link.host, category=link.category,
                                       verified=link.verified, privacy=link.privacy, touches_target=link.touches_target,
                                       antibot=link.antibot, tier=_links.host_tier(link.host))
        label += " - " + _links.disclosure_note(entity, rendered)
    return label


def recheck_report(today: _dt.date, *, max_age_days: int = LINK_STALE_DAYS) -> list[dict[str, Any]]:
    """c7 (offline, for `v3lum doctor --links`): unverified links and links not re-checked for more than
    ``max_age_days``: [{ref, host, reason, checked_at}]. Reads the pack file only."""
    out: list[dict[str, Any]] = []
    for item in load_pack()[2].get(EXT_KEY) or []:
        if not isinstance(item, Mapping):
            continue
        ref, checked = f"{PACK}:{item.get('id')}", str(item.get("checked_at") or "")
        if not item.get("verified"):
            out.append({"ref": ref, "host": item.get("host"), "reason": "unverified", "checked_at": checked})
        elif not _valid_date(checked):
            out.append({"ref": ref, "host": item.get("host"), "reason": "checked_at missing or invalid", "checked_at": checked})
        elif (today - _dt.date.fromisoformat(checked)).days > max_age_days:
            out.append({"ref": ref, "host": item.get("host"), "reason": f"last checked {(today - _dt.date.fromisoformat(checked)).days} days ago", "checked_at": checked})
    return out


def coordinates_opted_in(entity: Entity, ctx: Any) -> bool:
    """c11: the analyst typed or confirmed these coordinates and the case opted in to personal links
    (--show-personal with a recorded purpose; the core's rule for privacy links)."""
    opts = getattr(ctx, "options", None)
    unconfirmed = set(getattr(opts, "unconfirmed_seeds", None) or ())
    return bool(getattr(ctx, "is_seed", False) and getattr(opts, "show_personal", False) and getattr(opts, "purpose", "")
                and entity.key not in unconfirmed)


@register
class PivotsGeoImage(Module):
    name = "pivots_geo_image"
    title = "Reverse image search and map links (manual)"
    description = (
        "Manual pivot links for public image URLs (TinEye, Google Lens, ImgOps, Yandex) and for coordinates the analyst "
        "confirmed (OpenStreetMap, Google Maps), from the geo_image pack. V3LUM never opens or fetches them."
    )
    category = "geo_image_meta"
    accepts = {T.URL, T.COORDINATES}
    produces = frozenset()
    reference = "https://tineye.com/terms"
    tags = {"offline", "pack"}
    notice = (
        "Reverse-image links are not for identifying people from facial images: use them for impersonation, fake-profile "
        "and cloned-logo checks within the case purpose. Opening a link sends the image URL to that operator, which "
        "fetches the image; Yandex is a Russian operator."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 10.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = tlp_level(ctx)
        if level >= _tlp.TLP.RED:
            return res.mark(Status.SKIPPED, "TLP:RED: third-party links are hidden from reports", reason_code="tlp")
        found, problems, _data = load_pack()
        if entity.type is T.URL:
            ok, why = image_url_eligible(entity.value, provenance=getattr(ctx, "provenance", ()), org=getattr(ctx, "org", None))
            if not ok:
                return res.mark(Status.SKIPPED, f"no reverse-image links: {why}", reason_code="not_applicable")
        elif entity.type is T.COORDINATES:
            if coordinate_values(entity.value) is None:
                return res.mark(Status.SKIPPED, "coordinates out of range or 0,0 (no fix): no map links", reason_code="not_applicable")
            if not coordinates_opted_in(entity, ctx):
                return res.mark(Status.SKIPPED, "map links are privacy links: only for coordinates the analyst typed or "
                                "confirmed, with --show-personal and a recorded purpose (P260 cond 11)", reason_code="privacy")
        candidates = sorted((lk for lk in found if entity.type in lk.entity_types), key=lambda lk: not lk.verified)
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        for link in candidates[:TERMINAL_MAX_LINKS]:
            if link.max_tlp is not None and level > link.max_tlp:
                hidden.append({"ref": link.ref, "reason": f"hidden at {level.label}: listed only up to {link.max_tlp.label} (max_tlp)"})
                continue
            if level >= _tlp.TLP.AMBER and _links.host_tier(link.host) not in _links.TRUSTED_TIERS:
                hidden.append({"ref": link.ref, "reason": f"unknown-tier operator: hidden at {level.label} and above (A8)"})
                continue
            url = render(link, entity)
            if url is None:
                hidden.append({"ref": link.ref, "reason": "did not render (lint, tier or value)"})
                continue
            label = label_for(link, entity, url, level)
            res.link(label, url)
            shown.append({"ref": link.ref, "url": url, "host": link.host, "tier": _links.host_tier(link.host),
                          "clickable": level < _tlp.TLP.AMBER and not link.touches_target, "label": label})
        if shown and entity.type is T.URL:
            res.finding("Reverse-image links: not for identifying people", "info",
                        f"Standing label: {REVERSE_IMAGE_LABEL}. Opening a link sends the image URL to that operator.",
                        tags=["info", "context_only"])
        res.raw = {"tlp": level.value_str, "links": shown, "hidden": hidden, "pack_problems": problems[:10],
                   "standing_label": REVERSE_IMAGE_LABEL if entity.type is T.URL else None}
        if not shown:
            return res.mark(Status.EMPTY, "; ".join(h["reason"] for h in hidden) or "no link applies")
        return res
