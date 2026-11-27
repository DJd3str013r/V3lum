"""pivots_unverified: pivot pages curl cannot verify (SPA or anti-bot walls), manual links only (P304, batch p2-G14-3).

The links live in nine topic packs ``v3lum/data/pivot_links/unverified_<topic>.json`` (frozen schema
``v3lum.pivot_pack/1``): reputation, malware, infra, history, cve, crypto, darkweb, brand and social. V3LUM never
requests these URLs, not even from doctor, and never solves their challenges (cond 1): the packs are offline data.

* Core links (``links``) are rendered by the core like every pack link (engine case links, ``v3lum links``): A2/P311
  rendering (cond 2), the 'unverified' and 'unknown operator' badges (cond 4), privacy links only for analyst-typed
  seeds of a case that opted in (cond 11), verified links first (cond 6).
* Module links (pack-level ``x_module_links``) need what the frozen core cannot express: the vetted module-side
  placeholders ``{url_sha256}`` (VirusTotal URL report, cond 7), ``{url_path}`` (archive.today capture lists, cond 3/7),
  ``{cve_num}`` (Exploit-DB) and ``{hunter_q}`` (hunter.how), and the per-link ``x_max_tlp`` (Kaspersky OpenTIP: CLEAR
  only, with the RU vendor-policy badge, cond 10). This module renders them.

Verification (cond 6): the frozen ``verified`` is a bool, so a dated one-time browser check by a team member is
recorded as ``verified: true`` + ``checked_at`` + ``x_verification: 'browser'`` + ``x_checked_by`` and the label marker
'(browser)'; unchecked links keep ``verified: false`` and the marker '(may show a challenge)'. 'curl' never appears in
these packs (cond 1). :func:`rank_links` orders verified first, then the analysts' top tools (VirusTotal, AbuseIPDB,
Shodan, OTX, Talos, abuse.ch, Wayback), then pack order; the terminal view keeps 8 (cond 6).
:func:`lint_pack_data` adds the P304 rules to the core lint (cond 3, 7-10): no ``{raw}``, no upload/submit/save/
rescan/scan paths, VirusTotal report forms only, Wayback ``/web/*/`` and archive.today capture lists only, no
CentralOps ``svc_scan``, no login pages, the Kaspersky max_tlp and badge. :func:`recheck_report` is the offline data
of ``v3lum doctor --links`` (browser checks older than 90 days and never-checked links, cond 12).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, quote_plus, unquote, urlsplit

from v3lum.core import links as _links
from v3lum.core import tlp as _tlp
from v3lum.core.entities import IOC_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

PACKS: tuple[str, ...] = (
    "unverified_reputation", "unverified_malware", "unverified_infra", "unverified_history", "unverified_cve",
    "unverified_crypto", "unverified_darkweb", "unverified_brand", "unverified_social",
)
EXT_KEY = "x_module_links"
MARKER_BROWSER = "(browser)"
MARKER_CHALLENGE = "(may show a challenge)"
BADGE_RU = "foreign provider (RU) - check the company vendor policy"
TERMINAL_LINK_CAP = 8  # cond 6
RECHECK_DAYS = 90  # cond 12
#: cond 6: the analysts' top tools rank first inside the same verification state.
TOP_TOOL_HOSTS: tuple[str, ...] = (
    "www.virustotal.com", "www.abuseipdb.com", "www.shodan.io", "otx.alienvault.com", "talosintelligence.com",
    "bazaar.abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch", "web.archive.org",
)
#: Module-side placeholders (proposed P311 additions, docs/backlog/p2-G14-3.md) and the types they take.
MODULE_PLACEHOLDERS: dict[str, frozenset[T]] = {
    "url_sha256": frozenset({T.URL}),
    "url_path": frozenset({T.URL}),
    "cve_num": frozenset({T.CVE}),
    "hunter_q": frozenset({T.IPV4, T.DOMAIN, T.FAVICON_HASH}),
}
#: Core placeholders a module link may also use (same encoders as the core).
CORE_PLACEHOLDERS: dict[str, frozenset[T] | None] = {"q": None, "qp": None, "domain": frozenset({T.DOMAIN}),
                                                      "ip": frozenset({T.IPV4, T.IPV6})}
_EXT_FIELDS = frozenset({"x_max_tlp", "x_badge", "x_verification", "x_checked_by", "x_research", "x_routed_from"})
_RE_PH = re.compile(r"\{([a-z0-9_]+)\}")
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_SUBMIT_WORDS = ("upload", "submit", "rescan", "reanaly")
_SUBMIT_SEGMENTS = frozenset({"save", "scan", "analyze", "analyse"})
_KNOWN_LOGIN_PAGES: tuple[tuple[str, str], ...] = (("www.shodan.io", "/search"), ("shodan.io", "/search"))
_VT_HOSTS = frozenset({"www.virustotal.com", "virustotal.com"})
_ARCHIVE_TODAY = frozenset({"archive.ph", "archive.today", "archive.is"})


# --------------------------------------------------------------------------------------
# Encoders (cond 3: whitelisted placeholders through their declared encoder; never str.format, never {raw})
# --------------------------------------------------------------------------------------


def canonical_url(value: Any) -> str | None:
    """http(s) URL with a host: lower-case scheme and host, '/' for an empty path, default port and fragment dropped
    (the input of ``{url_sha256}`` and ``{url_path}``); None for anything else (userinfo, controls, spaces)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 4096 or _RE_CTRL.search(v) or any(c.isspace() for c in v):
        return None
    try:
        p = urlsplit(v)
        port = p.port
    except ValueError:
        return None
    scheme = p.scheme.lower()
    if scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        return None
    host = p.hostname.lower()
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host + ("" if port is None or default else f":{port}")
    return f"{scheme}://{netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


def url_sha256(value: Any) -> str | None:
    """``{url_sha256}``: SHA-256 hex of :func:`canonical_url` (VirusTotal /gui/url/<id>, cond 7)."""
    url = canonical_url(value)
    return hashlib.sha256(url.encode("utf-8")).hexdigest() if url else None


def url_path(value: Any) -> str | None:
    """``{url_path}``: the canonical URL inside a path (archive.today capture lists): ':' and '/' kept, everything else
    percent-encoded ('?', '#', '%', quotes, unicode), and any dot segment ('.', '..', '%2e%2e'...) refused so a value
    can never climb to /submit or /save (cond 3, 7, 8)."""
    url = canonical_url(value)
    if url is None:
        return None
    for seg in url.split("/"):
        if unquote(unquote(seg)).strip().lower() in (".", ".."):
            return None
    return quote(url, safe=":/")


def cve_num(value: Any) -> str | None:
    """``{cve_num}``: 'CVE-2021-44228' -> '2021-44228' (Exploit-DB search?cve=)."""
    m = re.fullmatch(r"(?i)CVE-(\d{4}-\d{4,7})", str(value or "").strip())
    return m.group(1) if m else None


def hunter_q(etype: T, value: Any) -> str | None:
    """``{hunter_q}``: hunter.how searchValue = percent-encoded base64 of 'field="value"' (IOC types only, cond 4)."""
    field = {T.IPV4: "ip", T.DOMAIN: "domain", T.FAVICON_HASH: "favicon_hash"}.get(etype)
    v = str(value or "").strip()
    if not field or not v or '"' in v or "\\" in v or _RE_CTRL.search(v) or any(c.isspace() for c in v):
        return None
    return quote(base64.b64encode(f'{field}="{v}"'.encode()).decode("ascii"), safe="")


def encode(name: str, entity: Entity) -> str | None:
    """Encoder of one whitelisted module-link placeholder for ``entity``; None rejects the rendering."""
    allowed = MODULE_PLACEHOLDERS.get(name, CORE_PLACEHOLDERS.get(name, frozenset()))
    if name not in MODULE_PLACEHOLDERS and name not in CORE_PLACEHOLDERS:
        return None
    if allowed is not None and entity.type not in allowed:
        return None
    v = entity.value
    if name == "q":
        return None if v.strip() in (".", "..") else quote(v, safe="")
    if name == "qp":
        return quote_plus(v)
    if name in ("domain", "ip"):
        return quote(v, safe=":")
    if name == "url_sha256":
        return url_sha256(v)
    if name == "url_path":
        return url_path(v)
    if name == "cve_num":
        return cve_num(v)
    if name == "hunter_q":
        return hunter_q(entity.type, v)
    return None


def _dot_segment(seg: str) -> bool:
    return unquote(unquote(seg)).strip().lower() in (".", "..")


def check_rendered(url: Any, *, host: str, template: str) -> list[str]:
    """Post-render assertions (cond 3): https, exactly the declared host, no userinfo or port, URL-safe ASCII only, no
    dot segment, the template's static prefix intact and no injected '?', '#' or '&'."""
    if not isinstance(url, str) or not url:
        return ["not rendered"]
    problems: list[str] = []
    if len(url) > _links.MAX_URL or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in url) or any(c in url for c in "\"'<>\\`{}|^"):
        problems.append("unsafe characters")
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return problems + ["unparseable"]
    if p.scheme != "https":
        problems.append("not https")
    if (p.hostname or "") != host or "@" in p.netloc or port is not None:
        problems.append("host, userinfo or port differs from the declared host")
    if any(_dot_segment(s) for s in p.path.split("/")):
        problems.append("dot segment in the path")
    if not url.startswith(template.split("{", 1)[0]):
        problems.append("static prefix changed")
    static = _RE_PH.sub("", template)
    for ch in "?#&":
        if url.count(ch) != static.count(ch):
            problems.append(f"injected {ch!r}")
    return problems


# --------------------------------------------------------------------------------------
# Pack lint (cond 1, 3, 6-11) and loading
# --------------------------------------------------------------------------------------


def _segments(template: str) -> list[str]:
    sample = _RE_PH.sub("x", template).lower()
    try:
        parts = urlsplit(sample)
    except ValueError:
        return []
    segs = [s for s in parts.path.split("/") if s]
    query = [s for s in re.split(r"[&=]", parts.query) if s] if parts.query else []
    return segs + query


def p304_rule_problems(entry: Mapping[str, Any], *, today: _dt.date | None = None) -> list[str]:
    """The P304 rules on one pack entry (core or module link), on top of the core lint."""
    errs: list[str] = []
    template = str(entry.get("template") or "")
    host = str(entry.get("host") or "").lower()
    names = _RE_PH.findall(template)
    if "raw" in names:
        errs.append("{raw} is never used in these packs (cond 3)")
    bad = [s for s in _segments(template) if any(w in s for w in _SUBMIT_WORDS) or s in _SUBMIT_SEGMENTS or s.startswith("save")]
    if bad:
        errs.append(f"submission/upload/save/rescan/scan path or parameter {bad} (cond 7-8, rule 7)")
    if host == "centralops.net" and "svc_scan" in template.lower():
        errs.append("CentralOps Domain Dossier never carries svc_scan: it port-probes the target (cond 8)")
    if host in _VT_HOSTS:
        try:
            path, query = urlsplit(template).path, urlsplit(template).query
        except ValueError:
            path, query = "", ""
        m = re.fullmatch(r"/gui/(file|domain|ip-address|url)/\{([a-z0-9_]+)\}", path)
        if not m or query or (m.group(1) == "url") != (m.group(2) == "url_sha256"):
            errs.append("VirusTotal: only /gui/file|domain|ip-address/{..} and /gui/url/{url_sha256} report pages (cond 7)")
    if host == "web.archive.org" and not template.startswith("https://web.archive.org/web/*/"):
        errs.append("Wayback: calendar or URL list /web/*/ only, never /save (cond 7)")
    if host in _ARCHIVE_TODAY and not re.fullmatch(r"https://archive\.(?:ph|today|is)/(?:newest/)?\{(?:url_path|domain)\}", template):
        errs.append("archive.today: capture lists only, never /submit (cond 7)")
    try:
        tpath = urlsplit(template).path
    except ValueError:
        tpath = ""
    if entry.get("login_required") is not False or any(host == h and tpath.startswith(pth) for h, pth in _KNOWN_LOGIN_PAGES):
        errs.append("pages that require a login are excluded (cond 9)")
    if entry.get("publishes") is not False or entry.get("touches_target") is not False:
        errs.append("publishes and touches_target must be false (cond 1, rule 7)")
    # cond 6: verification state
    verified, checked = entry.get("verified"), str(entry.get("checked_at") or "")
    method = entry.get("x_verification")
    label = str(entry.get("label") or "")
    if method not in (None, "browser"):
        errs.append("x_verification is 'browser' or null: curl-verified links belong to the P311 topic packs (cond 1, 6)")
    if verified is True:
        today = today or _dt.date.today()
        try:
            when = _dt.date.fromisoformat(checked)
        except ValueError:
            when = None
        if method != "browser" or when is None or when > today or not str(entry.get("x_checked_by") or "").strip():
            errs.append("a verified link records a dated browser check: x_verification 'browser', a past checked_at and "
                        "x_checked_by (cond 6)")
        if not label.endswith(MARKER_BROWSER):
            errs.append(f"browser-verified labels end with {MARKER_BROWSER!r} (cond 6)")
    else:
        if method is not None:
            errs.append("x_verification 'browser' needs verified=true (cond 6)")
        if not label.endswith(MARKER_CHALLENGE):
            errs.append(f"unverified labels end with {MARKER_CHALLENGE!r} (cond 6)")
    max_tlp = entry.get("x_max_tlp")
    if max_tlp not in (None, ""):
        try:
            _tlp.parse(max_tlp)
        except ValueError:
            errs.append(f"x_max_tlp {max_tlp!r} is not a TLP value")
    if host.endswith("kaspersky.com") and (str(max_tlp or "").lower() != "clear" or entry.get("x_badge") != BADGE_RU):
        errs.append("Kaspersky OpenTIP: x_max_tlp 'clear' and the vendor-policy badge (cond 10)")
    return errs


@dataclass(frozen=True)
class ModuleLink:
    """A linted ``x_module_links`` entry of a P304 pack."""

    pack: str
    id: str
    label: str
    template: str
    entity_types: tuple[T, ...]
    category: str
    host: str
    verified: bool
    checked_at: str
    antibot: bool
    max_tlp: _tlp.TLP | None
    badge: str
    verification: str

    @property
    def ref(self) -> str:
        return f"{self.pack}:{self.id}"


def _core_view(entry: Mapping[str, Any]) -> dict[str, Any]:
    """The entry as the core lint sees it: module placeholders become {q}, extension fields dropped."""
    out = {k: v for k, v in entry.items() if k not in _EXT_FIELDS}
    template = str(entry.get("template") or "")
    for name in MODULE_PLACEHOLDERS:
        template = template.replace("{" + name + "}", "{q}")
    out["template"] = template
    return out


def _parse_module_link(pack: str, entry: Any, *, today: _dt.date | None = None) -> tuple[ModuleLink | None, list[str]]:
    if not isinstance(entry, Mapping):
        return None, [f"{pack}:{EXT_KEY}: entries must be objects"]
    ident = str(entry.get("id") or "?")
    where = f"{pack}:{ident} ({EXT_KEY})"
    template = entry.get("template")
    if not isinstance(template, str) or not template:
        return None, [f"{where}: missing template"]
    errs: list[str] = []
    names = _RE_PH.findall(template)
    unknown = sorted({n for n in names if n not in MODULE_PLACEHOLDERS and n not in CORE_PLACEHOLDERS})
    if unknown:
        errs.append(f"unknown placeholders {unknown}")
    if len(names) != 1:
        errs.append("one placeholder per module link")
    try:
        types = tuple(T(str(t)) for t in entry.get("entity_types") or ())
    except ValueError as exc:
        types = ()
        errs.append(str(exc))
    for name in names:
        allowed = MODULE_PLACEHOLDERS.get(name) or CORE_PLACEHOLDERS.get(name)
        if allowed is not None and not set(types) <= allowed:
            errs.append(f"{{{name}}} takes only {sorted(t.value for t in allowed)}")
    for key in ("x_badge", "x_checked_by"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, str) or _RE_CTRL.search(value) or len(value) > 200):
            errs.append(f"{key} must be a single-line string")
    errs += p304_rule_problems(entry, today=today)
    view = _core_view(entry)
    errs += [e.split(": ", 2)[-1] for e in _links.lint_pack(
        {"schema": _links.SCHEMA, "pack": pack, "title": pack, "links": [view]}, source=f"{pack}.json")]
    if errs:
        return None, [f"{where}: {e}" for e in errs]
    max_tlp = _tlp.parse(entry["x_max_tlp"]) if entry.get("x_max_tlp") else None
    return ModuleLink(
        pack=pack, id=ident, label=str(entry.get("label") or ident), template=template, entity_types=types,
        category=str(entry.get("category") or "other"), host=str(entry.get("host") or "").lower(),
        verified=entry.get("verified") is True, checked_at=str(entry.get("checked_at") or ""),
        antibot=entry.get("antibot") is True, max_tlp=max_tlp, badge=str(entry.get("x_badge") or ""),
        verification=str(entry.get("x_verification") or ""),
    ), []


def lint_pack_data(data: Any, *, pack: str, today: _dt.date | None = None) -> list[str]:
    """Every problem of a P304 pack: the core lint of ``links``, the P304 rules on every core link and the full lint of
    ``x_module_links`` (CI and the loader use it). Empty list = clean."""
    if not isinstance(data, Mapping):
        return [f"{pack}: a pack is an object"]
    errs = list(_links.lint_pack(data, source=f"{pack}.json"))
    ids: set[str] = set()
    for item in data.get("links") or []:
        if isinstance(item, Mapping):
            ids.add(str(item.get("id")))
            errs += [f"{pack}:{item.get('id')}: {e}" for e in p304_rule_problems(item, today=today)]
    module_links = data.get(EXT_KEY) or []
    if not isinstance(module_links, list):
        return errs + [f"{pack}: {EXT_KEY} must be a list"]
    for entry in module_links:
        ml, problems = _parse_module_link(pack, entry, today=today)
        errs += problems
        if ml is not None:
            if ml.id in ids:
                errs.append(f"{pack}:{ml.id} ({EXT_KEY}): duplicate link id")
            ids.add(ml.id)
    return errs


_LOCK = threading.Lock()
_CACHE: dict[str, tuple[Any, dict[str, Any], dict[str, ModuleLink], list[str]]] = {}


def _registry_token() -> Any:
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry leaves every host unknown (fail closed)
        return None


def _load(pack: str) -> tuple[Any, dict[str, Any], dict[str, ModuleLink], list[str]]:
    token = _registry_token()
    with _LOCK:
        cached = _CACHE.get(pack)
        if cached is not None and cached[0] is token:
            return cached
        try:
            data = json.loads((_links.PACKS_DIR / f"{pack}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state: tuple[Any, dict[str, Any], dict[str, ModuleLink], list[str]] = (
                token, {}, {}, [f"{pack}: unreadable pack ({type(exc).__name__})"])
        else:
            if not isinstance(data, dict):
                state = (token, {}, {}, [f"{pack}: a pack is an object"])
            else:
                found: dict[str, ModuleLink] = {}
                errs: list[str] = []
                for entry in data.get(EXT_KEY) or []:
                    ml, problems = _parse_module_link(pack, entry)
                    errs += problems
                    if ml is not None and ml.id not in found:
                        found[ml.id] = ml
                state = (token, data, found, errs)
        _CACHE[pack] = state
        return state


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def module_links(pack: str | None = None) -> list[ModuleLink]:
    """The valid module links of one P304 pack (or of all of them), in pack order."""
    return [ml for p in ((pack,) if pack else PACKS) for ml in _load(p)[2].values()]


def module_link_errors(pack: str | None = None) -> list[str]:
    return [e for p in ((pack,) if pack else PACKS) for e in _load(p)[3]]


def pack_entries(pack: str | None = None) -> list[tuple[str, dict[str, Any], bool]]:
    """(pack, raw entry, is_module_link) of every entry of the P304 packs, in file order (lint, doctor, tests)."""
    out: list[tuple[str, dict[str, Any], bool]] = []
    for p in (pack,) if pack else PACKS:
        data = _load(p)[1]
        out += [(p, dict(i), False) for i in data.get("links") or [] if isinstance(i, Mapping)]
        out += [(p, dict(i), True) for i in data.get(EXT_KEY) or [] if isinstance(i, Mapping)]
    return out


# --------------------------------------------------------------------------------------
# Rendering, TLP and ranking
# --------------------------------------------------------------------------------------


def render_module_link(ml: ModuleLink, entity: Entity) -> _links.RenderedLink | None:
    """Render one module link for ``entity``: whitelisted placeholders via re.sub through their encoders, tier rules
    of the core (unknown-tier hosts receive IOC values only, A8), then the post-render checks; None = not shown."""
    if not isinstance(ml, ModuleLink) or not isinstance(entity, Entity):
        return None
    if entity.type in _links.NO_LINK_TYPES or entity.type not in ml.entity_types:
        return None
    tier = _links.host_tier(ml.host)  # the registry tier now, never one recorded at load
    if entity.type in _links.PRIVACY_TYPES:
        return None  # module links carry IOC/brand values only; personal values are core privacy links (cond 11)
    if tier not in _links.TRUSTED_TIERS and entity.type not in IOC_TYPES:
        return None

    def repl(m: re.Match[str]) -> str:
        out = encode(m.group(1), entity)
        if not out:
            raise ValueError(m.group(1))
        return out

    try:
        url = _RE_PH.sub(repl, ml.template)
    except ValueError:
        return None
    if check_rendered(url, host=ml.host, template=ml.template):
        return None
    badges = []
    if tier == "unknown":
        badges.append(_links.BADGE_UNKNOWN_OPERATOR)
    if not ml.verified:
        badges.append(_links.BADGE_UNVERIFIED)
    return _links.RenderedLink(
        ref=ml.ref, label=ml.label, url=url, host=ml.host, category=ml.category, verified=ml.verified, privacy=False,
        touches_target=False, antibot=ml.antibot, tier=tier, badge=", ".join(badges),
    )


def tlp_level(ctx: Any) -> _tlp.TLP:
    """The entity TLP of the run; an unreadable value fails closed to RED."""
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


def hidden_reason(ml: ModuleLink | None, level: _tlp.TLP, tier: str = "") -> str:
    """Why a link is not shown at ``level`` ('' = shown): TLP:RED hides every third-party link (A2), ``max_tlp``
    (cond 10), unknown-tier hosts are excluded at AMBER and above and AMBER+STRICT keeps trusted hosts only (A2/A8)."""
    if level >= _tlp.TLP.RED:
        return "TLP:RED: third-party links are hidden from reports (v3lum links lists pack links with the warning)"
    if ml is not None and ml.max_tlp is not None and level > ml.max_tlp:
        return f"hidden at {level.label}: listed only up to {ml.max_tlp.label} (max_tlp, cond 10)"
    if tier == "unknown" and level >= _tlp.TLP.AMBER:
        return f"hidden at {level.label}: unknown-tier host (A8: excluded at TLP:AMBER and above)"
    if tier and tier != "trusted" and level >= _tlp.TLP.AMBER_STRICT:
        return f"hidden at {level.label}: {tier}-tier host (A2: TLP:AMBER+STRICT allows trusted providers only)"
    return ""


def marker(verified: bool, verification: str = "") -> str:
    """cond 6 markers: '(browser)' after a dated browser check, '(may show a challenge)' otherwise."""
    return MARKER_BROWSER if verified and verification == "browser" else MARKER_CHALLENGE


def sent_value(ml: ModuleLink, entity: Entity) -> str:
    """What opening the link discloses, in words (A2 disclosure warning)."""
    if "{url_sha256}" in ml.template:
        return f"the SHA-256 of {entity.display}"
    if "{hunter_q}" in ml.template:
        return f"{entity.display} (base64 query)"
    return entity.display


def label_for(ml: ModuleLink, rendered: _links.RenderedLink, entity: Entity, level: _tlp.TLP) -> str:
    """Label of a module-emitted link: badges ('unknown operator', 'unverified', the entry's own) and, at TLP:AMBER and
    above, the A2 warning 'opening sends <value> to <host>' (renderers show module links as plain text there)."""
    badges = [b for b in (rendered.badge, ml.badge) if b]
    label = rendered.label
    if badges:
        label += " [" + "; ".join(dict.fromkeys(", ".join(badges).split(", "))) + "]"
    if level >= _tlp.TLP.AMBER:
        label += f" - opening sends {sent_value(ml, entity)} to {rendered.host}"
    return label


def _rank_key(index: int, host: str, verified: bool) -> tuple[int, int, int]:
    prio = TOP_TOOL_HOSTS.index(host) if host in TOP_TOOL_HOSTS else len(TOP_TOOL_HOSTS)
    return (0 if verified else 1, prio, index)


def rank_links(entity: Entity, level: _tlp.TLP, *, include_privacy: bool = False,
               limit: int = TERMINAL_LINK_CAP) -> dict[str, Any]:
    """cond 6 ordering of every P304 link that applies to ``entity`` (core and module links): verified (a dated browser
    check counts as verified) first, then the analysts' top tools, then pack order. Returns {'terminal': the first
    ``limit`` as [{ref, host, marker, module}], 'rest': the number of other links, 'hidden': [{ref, reason}]}."""
    rows: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    hidden: list[dict[str, str]] = []
    index = 0
    for pack, entry, is_module in pack_entries():
        index += 1
        ref = f"{pack}:{entry.get('id')}"
        verified = entry.get("verified") is True
        method = str(entry.get("x_verification") or "")
        if is_module:
            ml = _load(pack)[2].get(str(entry.get("id")))
            if ml is None or entity.type not in ml.entity_types:
                continue
            reason = hidden_reason(ml, level, _links.host_tier(ml.host))
            if reason:
                hidden.append({"ref": ref, "reason": reason})
                continue
            rendered = render_module_link(ml, entity)
        else:
            link = _links.get_link(ref)
            if link is None or entity.type not in link.entity_types or (link.privacy and not include_privacy):
                continue
            rendered = _links.render(link, entity)
        if rendered is None:
            continue
        row = {"ref": ref, "host": rendered.host, "marker": marker(verified, method), "module": is_module}
        rows.append((_rank_key(index, rendered.host, verified), row))
    rows.sort(key=lambda r: r[0])
    ordered = [r for _k, r in rows]
    return {"terminal": ordered[:limit], "rest": max(0, len(ordered) - limit), "hidden": hidden}


def recheck_report(today: _dt.date, *, max_age_days: int = RECHECK_DAYS) -> dict[str, list[dict[str, Any]]]:
    """``v3lum doctor --links`` data (cond 12), offline from the pack files only (cond 1: never the URLs):
    browser-verified links checked more than ``max_age_days`` ago (or with an unreadable date) are 'due', links never
    checked are 'never_checked'."""
    due: list[dict[str, Any]] = []
    never: list[dict[str, Any]] = []
    for pack, entry, is_module in pack_entries():
        ref = f"{pack}:{entry.get('id')}" + (" (module link)" if is_module else "")
        if entry.get("verified") is not True:
            never.append({"ref": ref, "host": entry.get("host")})
            continue
        try:
            age = (today - _dt.date.fromisoformat(str(entry.get("checked_at") or ""))).days
        except ValueError:
            due.append({"ref": ref, "host": entry.get("host"), "age_days": None})
            continue
        if age > max_age_days:
            due.append({"ref": ref, "host": entry.get("host"), "age_days": age})
    return {"due": due, "never_checked": never}


def _typed_and_opted_in(ctx: Any, entity: Entity) -> bool:
    """Privacy links (cond 11): analyst-typed seeds of a case that opted in (show_personal + a recorded purpose), the
    engine's rule for privacy pack links."""
    opts = getattr(ctx, "options", None)
    unconfirmed = set(getattr(opts, "unconfirmed_seeds", ()) or ())
    typed = bool(getattr(ctx, "is_seed", False)) and entity.key not in unconfirmed
    return typed and bool(getattr(opts, "show_personal", False) and getattr(opts, "purpose", ""))


@register
class PivotsUnverified(Module):
    name = "pivots_unverified"
    title = "Unverified pivot pages (SPA / anti-bot, manual links)"
    description = (
        "Manual links to analyst tools curl cannot verify (VirusTotal URL report, archive.today capture lists, Exploit-DB "
        "CVE search, hunter.how, Kaspersky OpenTIP at TLP:CLEAR), rendered with module-side placeholders; the other "
        "challenge-walled pages of the unverified_* packs are rendered by the core. V3LUM never fetches them."
    )
    category = "search_dorks"
    accepts = {T.IPV4, T.DOMAIN, T.URL, T.MD5, T.SHA256, T.CVE, T.FAVICON_HASH}
    produces = frozenset()
    reference = "https://www.virustotal.com/gui/home/search"
    tags = {"offline"}
    notice = (
        "Manual links only: V3LUM never requests these pages and never solves their challenges. Links stay unverified "
        "until a team member records a dated browser check; at TLP:AMBER and above they are plain text ('opening sends "
        "<value> to <host>'), at RED they are hidden. Kaspersky OpenTIP is listed only at TLP:CLEAR (vendor policy)."
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
        red = hidden_reason(None, level)
        if red:
            return res.mark(Status.SKIPPED, red, reason_code="tlp")
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        for ml in module_links():
            if entity.type not in ml.entity_types:
                continue
            reason = hidden_reason(ml, level, _links.host_tier(ml.host))
            if reason:
                hidden.append({"ref": ml.ref, "reason": reason})
                continue
            rendered = render_module_link(ml, entity)
            if rendered is None:
                hidden.append({"ref": ml.ref, "reason": "not rendered (value, tier or URL checks)"})
                continue
            label = label_for(ml, rendered, entity, level)
            res.link(label, rendered.url)
            shown.append({"ref": ml.ref, "url": rendered.url, "host": rendered.host, "tier": rendered.tier,
                          "marker": marker(ml.verified, ml.verification),
                          "clickable": level < _tlp.TLP.AMBER, "label": label})
        ranked = rank_links(entity, level, include_privacy=_typed_and_opted_in(ctx, entity))
        res.raw = {"tlp": level.value_str, "links": shown, "hidden": hidden,
                   "ranked": ranked["terminal"], "ranked_rest": ranked["rest"]}
        if not shown:
            return res.mark(Status.EMPTY)
        return res
