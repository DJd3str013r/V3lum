"""Module-rendered links of the G14 pivot packs (batch p2-G14-2: P203, P216, P231, P250, P290, P300).

The six packs ship in ``v3lum/data/pivot_links/<pack>.json`` in the frozen schema ``v3lum.pivot_pack/1``
(darkweb, crypto, company_org, brazil, pentest, cti). The core (:mod:`v3lum.core.links`) loads and renders
their ``links``. Some links of the final conditions cannot be rendered correctly by the frozen core yet:

* a value transformation (per-site tracker slugs, P203 cond 8; ``{mitre_path}`` and ATT&CK/Malpedia ids from
  the P295 alias index, P300 cond 8-9; chain-validated addresses, P216 cond 8);
* a TLP ceiling (``max_tlp``, P203 cond 10) or a warning (P203 cond 11) the core link model does not carry;
* a static page without a value (P250 cond 10-11: the analyst types the value behind a JavaScript form).

Those live in the same pack file under the pack-level extension key ``x_module_links`` (pack-level ``x_`` keys
are allowed and ignored by the core loader) and are rendered by the pack's module (pivots_darkweb,
pivots_crypto, pivots_brazil, pivots_cti) through this file:

* **lint (fail closed).** Every entry is linted like a pack link: the core lint (:func:`links.lint_pack`) runs
  on a copy whose resolver placeholders are replaced by ``{q}`` (https, declared host, no userinfo/port,
  forbidden probe tables, publishing hosts, A8 tiers, CPF), plus the batch rules of :data:`PACK_RULES`
  (rule 3 for the darkweb pack, rule 4 for the brazil pack, no wallet/payment pages, no GrayhatWarfare file
  links, no ViewDNS reverseip/iphistory, SSL Labs keeps hideResults=on&latest) and no ``.onion`` host. A static
  entry (``x_static``) is linted as an inline manual link (the only placeholder-less form the core accepts).
  Entries with problems are dropped and listed by :func:`module_link_errors`.
* **render.** Whitelisted placeholders substituted with ``re.sub`` (never ``str.format``, never ``{raw}``):
  ``{q}`` is the entity value percent-encoded like the core's; a resolver placeholder takes a value the
  module computed and validated (:data:`RESOLVER_PLACEHOLDERS`), encoded with ``quote(safe='')`` (path segments
  of ``{mitre_path}`` one by one). A value that is missing or not a safe token renders nothing (no guessed
  path). The URL is re-checked (https, declared host, no userinfo/port, no whitespace or control characters)
  and the tier is read from the provider registry at render time.
* **TLP (A2).** At RED nothing is emitted (third-party links are hidden from reports); a link above its
  ``x_max_tlp`` is hidden; at AMBER and above the label carries 'opening sends <value> to <host>' (the
  renderers show module links as non-clickable text there).

V3LUM never fetches any of these URLs.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core import links as _links
from v3lum.core import tlp as _tlp
from v3lum.core.entities import IOC_TYPES, Entity, EntityType

EXT_KEY = "x_module_links"
BATCH_PACKS: tuple[str, ...] = ("darkweb", "crypto", "company_org", "brazil", "pentest", "cti")
RECHECK_MAX_AGE_DAYS = 180  # P203/P216/P231/P250/P290/P300 cond 7
ANTIBOT_BADGE = "opens in browser; may require challenge"  # P216 cond 9
UNVERIFIED_BADGE = _links.BADGE_UNVERIFIED
UNKNOWN_OPERATOR_BADGE = _links.BADGE_UNKNOWN_OPERATOR

#: Module-side placeholders (proposed for P311; see docs/backlog/p2-G14-2.md). The module computes and
#: validates the value (never parsed from free text); this file encodes it.
RESOLVER_PLACEHOLDERS: dict[str, str] = {
    "mitre_path": "ATT&CK technique path: T1059.001 -> T1059/001 (P300 cond 8)",
    "attack_id": "ATT&CK G id (threat_actor) or S id (malware_family) from the P295 alias index (P300 cond 8)",
    "malpedia_id": "Malpedia family id '<platform>.<name>' or actor id from the P295 alias index (P300 cond 9)",
    "ransomlook_slug": "RansomLook group name from the pack's x_tracker_slugs (P203 cond 8)",
    "rlive_slug": "ransomware.live group slug from the pack's x_tracker_slugs (P203 cond 8)",
    "ltc": "Litecoin address (base58check or bech32 'ltc1', P217)",
    "doge": "Dogecoin address (base58check, P217)",
    "bch": "Bitcoin Cash cashaddr without the 'bitcoincash:' prefix (checksum-validated)",
    "tron": "TRON address (T + base58check, P217)",
}
#: Placeholders whose value keeps '/' between path segments (each segment encoded separately).
SEGMENTED = frozenset({"mitre_path"})
_EXT_LINK_FIELDS = frozenset({"x_max_tlp", "x_warning", "x_fallback_for", "x_accepts", "x_badge", "x_static"})
_RE_PH = re.compile(r"\{([a-z0-9_]+)\}")
_RE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$")
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

#: Batch lint rules over the template path/query (P311 lint additions the final conditions ask for).
RULE3_PATH_RE = re.compile(r"(?i)/(?:id|post|posts|claim|claims|leak|leaks|download|downloads|victim|victims|file|files|"
                           r"dump|dumps|proof|proofs)(?:/|$)")
WALLET_ACTION_RE = re.compile(r"(?i)(wallet-?connect|connect-?wallet|/connect(?:/|$)|/swap(?:/|$|\?)|/pay(?:/|$|\?)|"
                              r"payment|checkout|donat|/buy(?:/|$|\?)|/send(?:/|$|\?))")
GRAYHAT_FILE_RE = re.compile(r"(?i)(/files/[^?#]|download|/buckets/\d+/|[?&](?:file_id|fid)=)")
VIEWDNS_EXCLUDED_RE = re.compile(r"(?i)^https://viewdns\.info/(?:reverseip|iphistory)/")
BRAZIL_TYPES = frozenset({EntityType.CNPJ, EntityType.ORG})


def _rule_darkweb(entry: Mapping[str, Any], template: str) -> list[str]:
    path = urlsplit(_RE_PH.sub("x", template)).path
    return ["rule 3: claim, leak-file, download and victim-file paths are never linked (P203 cond 9)"] if RULE3_PATH_RE.search(path) else []


def _rule_crypto(entry: Mapping[str, Any], template: str) -> list[str]:
    errs = []
    if WALLET_ACTION_RE.search(template):
        errs.append("no wallet-connect, payment, swap or donation page is ever linked (P216 cond 10)")
    if "chainabuse.com" in template:
        errs.append("Chainabuse address reports belong to the unverified pack of P304 (P216 cond 10)")
    return errs


def _rule_company(entry: Mapping[str, Any], template: str) -> list[str]:
    return ["ViewDNS reverseip and iphistory are not in this pack (P231 cond 11)"] if VIEWDNS_EXCLUDED_RE.match(template) else []


def _rule_brazil(entry: Mapping[str, Any], template: str) -> list[str]:
    types = {str(t) for t in entry.get("entity_types") or ()}
    bad = sorted(types - {t.value for t in BRAZIL_TYPES})
    return [f"rule 4: CNPJ and company types only, never {', '.join(bad)} (P250 cond 9)"] if bad else []


def _rule_pentest(entry: Mapping[str, Any], template: str) -> list[str]:
    errs = []
    if "grayhatwarfare.com" in template and GRAYHAT_FILE_RE.search(template):
        errs.append("GrayhatWarfare: bucket and file names only, never file links or downloads (P290 cond 8)")
    if "ssllabs.com" in template:
        query = urlsplit(template).query.split("&")
        if "hideResults=on" not in query or "latest" not in query:
            errs.append("SSL Labs templates always carry hideResults=on&latest (P290 cond 9)")
        if entry.get("touches_target") is not True:
            errs.append("SSL Labs starts a third-party assessment on a cache miss: touches_target=true (P290 cond 9)")
    return errs


PACK_RULES: dict[str, Any] = {
    "darkweb": _rule_darkweb,
    "crypto": _rule_crypto,
    "company_org": _rule_company,
    "brazil": _rule_brazil,
    "pentest": _rule_pentest,
}


def batch_rule_problems(pack: str, entry: Mapping[str, Any]) -> list[str]:
    """Batch lint rules (:data:`PACK_RULES`) plus the host rules shared by every batch pack."""
    template = str(entry.get("template") or "")
    host = str(entry.get("host") or "")
    errs: list[str] = []
    if host.endswith(".onion") or ".onion/" in template.split("?", 1)[0]:
        errs.append(".onion addresses are never linked or fetched (P203 cond 11)")
    rule = PACK_RULES.get(pack)
    if rule is not None:
        errs.extend(rule(entry, template))
    return errs


def lint_pack_data(data: Any, *, pack: str) -> list[str]:
    """Every problem of a batch pack: the core lint of ``links``, the batch rules on every link, and the full
    lint of ``x_module_links`` (CI, tests and the loader use it)."""
    if not isinstance(data, Mapping):
        return [f"{pack}: a pack is an object"]
    errs = list(_links.lint_pack(data, source=f"{pack}.json"))
    for item in data.get("links") or []:
        if isinstance(item, Mapping):
            errs.extend(f"{pack}:{item.get('id')}: {e}" for e in batch_rule_problems(pack, item))
    _items, ext_errs = _parse_module_links(pack, data)
    return errs + ext_errs


# --------------------------------------------------------------------------------------
# Module links
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleLink:
    """A linted ``x_module_links`` entry. ``link`` is its core view (the template with every resolver
    placeholder replaced by ``{q}``), which carries the frozen fields; ``template`` is the real one."""

    link: _links.PivotLink
    template: str
    placeholders: tuple[str, ...]
    max_tlp: _tlp.TLP | None = None
    warning: str = ""
    fallback_for: str = ""
    accepts: tuple[str, ...] = ()
    badge: str = ""
    static: bool = False

    @property
    def id(self) -> str:
        return self.link.id

    @property
    def ref(self) -> str:
        return self.link.ref

    @property
    def host(self) -> str:
        return self.link.host

    @property
    def label(self) -> str:
        return self.link.label


def _core_view(entry: Mapping[str, Any], names: Iterable[str]) -> dict[str, Any]:
    template = str(entry.get("template") or "")
    resolvers = [n for n in names if n in RESOLVER_PLACEHOLDERS]
    for name in resolvers:
        template = template.replace("{" + name + "}", "{q}")
    out = {k: v for k, v in entry.items() if k not in _EXT_LINK_FIELDS}
    out["template"] = template
    return out


def _lint_static(pack: str, entry: Mapping[str, Any]) -> list[str]:
    """A placeholder-less static page (P250 cond 10-11): the core's inline manual-link lint plus the A8 type rules."""
    template = str(entry.get("template") or "")
    host = str(entry.get("host") or "")
    errs = list(_links.validate_manual_link(template))
    errs += _links.validate_template(template, host=host, entity_types=entry.get("entity_types") or None)
    if _RE_PH.search(template):
        errs.append("a static entry carries no placeholder (the analyst types the value on the page)")
    tier = _links.host_tier(host)
    types: list[EntityType] = []
    for raw in entry.get("entity_types") or ():
        try:
            types.append(EntityType(str(raw)))
        except ValueError:
            errs.append(f"unknown entity type {raw!r}")
    if any(t in _links.NO_LINK_TYPES for t in types):
        errs.append("CPF, secrets, blobs and files never go into links")
    if any(t in _links.PRIVACY_TYPES for t in types) and entry.get("privacy") is not True:
        errs.append("templates for personal/company values need privacy=true")
    if tier not in _links.TRUSTED_TIERS and any(t not in IOC_TYPES for t in types):
        errs.append(f"unknown-tier hosts receive IOC_TYPES values only (A8); {host!r} is {tier}")
    for flag in ("publishes", "login_required"):
        if entry.get(flag) is not False:
            errs.append(f"{flag} must be false")
    return errs


def _parse_entry(pack: str, entry: Any) -> tuple[ModuleLink | None, list[str]]:
    if not isinstance(entry, Mapping):
        return None, [f"{pack}:{EXT_KEY}: entries must be objects"]
    ident = str(entry.get("id") or "?")
    where = f"{pack}:{ident} ({EXT_KEY})"
    template = entry.get("template")
    if not isinstance(template, str) or not template:
        return None, [f"{where}: missing template"]
    names = tuple(_RE_PH.findall(template))
    errs: list[str] = []
    unknown = sorted({n for n in names if n != "q" and n not in RESOLVER_PLACEHOLDERS})
    if unknown:
        errs.append(f"unknown placeholders {unknown} (module links take {{q}} or {sorted(RESOLVER_PLACEHOLDERS)})")
    if len(names) > 1:
        errs.append("one placeholder per module link")
    static = entry.get("x_static") is True
    max_tlp: _tlp.TLP | None = None
    if entry.get("x_max_tlp") not in (None, ""):
        try:
            max_tlp = _tlp.parse(entry.get("x_max_tlp"))
        except ValueError:
            errs.append(f"x_max_tlp {entry.get('x_max_tlp')!r} is not a TLP value")
    for key in ("x_warning", "x_fallback_for", "x_badge"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, str) or _RE_CTRL.search(value) or len(value) > 300):
            errs.append(f"{key} must be a single-line string")
    accepts = entry.get("x_accepts") or []
    if not isinstance(accepts, list) or not all(isinstance(a, str) for a in accepts):
        errs.append("x_accepts must be a list of strings")
        accepts = []
    errs += batch_rule_problems(pack, entry)
    if static:
        errs += _lint_static(pack, entry)
        view = dict(_core_view(entry, names))
        core_pack = _links.INLINE_PACK
    else:
        if not names:
            errs.append("template has no placeholder (set x_static for a page where the analyst types the value)")
        view = _core_view(entry, names)
        errs += [e.split(": ", 2)[-1] if e.startswith(f"{pack}.json: ") else e for e in _links.lint_pack(
            {"schema": _links.SCHEMA, "pack": pack, "title": pack, "links": [view]}, source=f"{pack}.json")]
        core_pack = pack
    if errs:
        return None, [f"{where}: {e}" for e in errs]
    try:
        types = tuple(EntityType(str(t)) for t in entry.get("entity_types") or ())
    except ValueError as exc:  # pragma: no cover - the lint above refuses unknown types
        return None, [f"{where}: {exc}"]
    link = _links.PivotLink(
        pack=core_pack if static else pack,
        id=ident,
        label=str(entry.get("label") or ""),
        template=str(view["template"]),
        entity_types=types,
        category=str(entry.get("category") or "other"),
        host=str(entry.get("host") or ""),
        verified=bool(entry.get("verified", False)),
        checked_at=str(entry.get("checked_at") or ""),
        privacy=bool(entry.get("privacy", False)),
        publishes=False,
        touches_target=bool(entry.get("touches_target", False)),
        login_required=False,
        antibot=bool(entry.get("antibot", False)),
        tier=_links.host_tier(str(entry.get("host") or "")),
        notes=str(entry.get("notes") or ""),
    )
    return ModuleLink(
        link=link,
        template=template,
        placeholders=names,
        max_tlp=max_tlp,
        warning=str(entry.get("x_warning") or ""),
        fallback_for=str(entry.get("x_fallback_for") or ""),
        accepts=tuple(accepts),
        badge=str(entry.get("x_badge") or ""),
        static=static,
    ), []


def _parse_module_links(pack: str, data: Mapping[str, Any]) -> tuple[dict[str, ModuleLink], list[str]]:
    items = data.get(EXT_KEY) or []
    if not isinstance(items, list):
        return {}, [f"{pack}: {EXT_KEY} must be a list"]
    out: dict[str, ModuleLink] = {}
    errs: list[str] = []
    core_ids = {str(i.get("id")) for i in data.get("links") or [] if isinstance(i, Mapping)}
    for entry in items:
        ml, problems = _parse_entry(pack, entry)
        errs.extend(problems)
        if ml is None:
            continue
        if ml.id in out or ml.id in core_ids:
            errs.append(f"{pack}:{ml.id} ({EXT_KEY}): duplicate link id")
            continue
        out[ml.id] = ml
    for ident in [i for i, ml in out.items() if ml.fallback_for and ml.fallback_for not in out]:
        errs.append(f"{pack}:{ident} ({EXT_KEY}): x_fallback_for names no module link {out[ident].fallback_for!r}")
        del out[ident]  # fail closed: a fallback whose primary link is missing would always render
    return out, errs


_LOCK = threading.Lock()
_CACHE: dict[str, tuple[Any, dict[str, Any], dict[str, ModuleLink], list[str]]] = {}


def _registry_token() -> Any:
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry leaves every host unknown (fail closed)
        return None


def pack_data(pack: str) -> dict[str, Any]:
    """The parsed pack file (``{}`` when missing or unreadable)."""
    return dict(_load(pack)[1])


def _load(pack: str) -> tuple[Any, dict[str, Any], dict[str, ModuleLink], list[str]]:
    token = _registry_token()
    with _LOCK:
        cached = _CACHE.get(pack)
        if cached is not None and cached[0] is token:
            return cached
        path = _links.PACKS_DIR / f"{pack}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state = (token, {}, {}, [f"{pack}: unreadable pack ({type(exc).__name__})"])
        else:
            if not isinstance(data, dict):
                state = (token, {}, {}, [f"{pack}: a pack is an object"])
            else:
                found, errs = _parse_module_links(pack, data)
                state = (token, data, found, errs)
        _CACHE[pack] = state
        return state


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def module_links(pack: str) -> dict[str, ModuleLink]:
    """The valid ``x_module_links`` of a pack, by id (file order)."""
    return dict(_load(pack)[2])


def module_link_errors(pack: str | None = None) -> list[str]:
    """Problems of the ``x_module_links`` of one batch pack (or of all of them)."""
    packs = (pack,) if pack else BATCH_PACKS
    return [e for p in packs for e in _load(p)[3]]


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------


def safe_token(value: Any) -> str | None:
    """A resolver value fit for one URL path segment or query value: a short token of letters, digits,
    spaces, '.', '_', ':' and '-' that is not a dot segment; else None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v in (".", "..") or not _RE_TOKEN.match(v) or _RE_CTRL.search(v):
        return None
    return v


def encode_value(name: str, value: Any) -> str | None:
    """Encode a resolver value (``quote(safe='')``; ``{mitre_path}`` segment by segment). None = not safe."""
    if not isinstance(value, str):
        return None
    if name in SEGMENTED:
        parts = value.split("/")
        if not 1 <= len(parts) <= 4:
            return None
        tokens = [safe_token(p) for p in parts]
        if any(t is None or t != p for t, p in zip(tokens, parts, strict=True)):
            return None
        return "/".join(quote(str(t), safe="") for t in tokens)
    token = safe_token(value)
    if token is None or token != value:
        return None
    return quote(token, safe="")


def url_ok(url: str, host: str) -> bool:
    """The core's re-check of a rendered URL: https, exactly the declared host, no userinfo or port, no
    whitespace or control characters, at most links.MAX_URL characters."""
    if not isinstance(url, str) or len(url) > _links.MAX_URL or _RE_CTRL.search(url) or any(c.isspace() for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "https" and (parts.hostname or "") == host and parts.username is None
            and parts.password is None and port is None and "@" not in parts.netloc)


def _badge(link: _links.PivotLink, tier: str) -> str:
    badges = []
    if tier == "unknown":
        badges.append(UNKNOWN_OPERATOR_BADGE)
    if not link.verified:
        badges.append(UNVERIFIED_BADGE)
    return ", ".join(badges)


def render(ml: ModuleLink, entity: Entity, values: Mapping[str, str] | None = None) -> _links.RenderedLink | None:
    """Render a module link for ``entity``; ``values`` holds the validated resolver values. None when it does
    not apply (type, tier, value not vouched for) - never a guessed URL."""
    if not isinstance(ml, ModuleLink) or not isinstance(entity, Entity):
        return None
    link = ml.link
    if ml.static:
        return _links.render(link, entity)  # the core lints and renders inline manual links itself
    if entity.type in _links.NO_LINK_TYPES or entity.type not in link.entity_types:
        return None
    tier = _links.host_tier(link.host)  # the registry tier now, never the one recorded at load
    if entity.type in _links.PRIVACY_TYPES and (not link.privacy or tier not in _links.TRUSTED_TIERS):
        return None
    if tier not in _links.TRUSTED_TIERS and entity.type not in IOC_TYPES:
        return None
    values = values or {}

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name == "q":
            return quote(entity.value, safe="")
        if name not in RESOLVER_PLACEHOLDERS or name not in ml.placeholders:
            raise ValueError(name)
        encoded = encode_value(name, values.get(name))
        if encoded is None:
            raise ValueError(name)
        return encoded

    try:
        url = _RE_PH.sub(repl, ml.template)
    except ValueError:
        return None
    if "{" in url or "}" in url or not url_ok(url, link.host):
        return None
    return _links.RenderedLink(
        ref=link.ref, label=link.label, url=url, host=link.host, category=link.category, verified=link.verified,
        privacy=link.privacy, touches_target=link.touches_target, antibot=link.antibot, tier=tier,
        badge=_badge(link, tier),
    )


# --------------------------------------------------------------------------------------
# TLP (A2) and labels
# --------------------------------------------------------------------------------------


def tlp_level(ctx: Any) -> _tlp.TLP:
    """The entity TLP of the run; an unreadable value fails closed to RED."""
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


def hidden_reason(ml: ModuleLink | None, level: _tlp.TLP) -> str:
    """Why a link is not shown at ``level`` ('' = shown)."""
    if level >= _tlp.TLP.RED:
        return "TLP:RED: third-party links are hidden from reports (v3lum links lists pack links with the warning)"
    if ml is not None and ml.max_tlp is not None and level > ml.max_tlp:
        return f"hidden at {level.label}: this link is listed only up to {ml.max_tlp.label} (max_tlp)"
    return ""


def label_for(entity: Entity, rendered: _links.RenderedLink, level: _tlp.TLP, *, ml: ModuleLink | None = None,
              extra_badges: Iterable[str] = (), note: str = "", sent: str = "") -> str:
    """The label shown with a module-emitted link: badges (unknown operator, unverified, antibot, the
    entry's own), the entry's warning, an optional note and, at TLP:AMBER and above, the A2 disclosure
    warning ('opening sends <value> to <host>'; ``sent`` names the resolved value when the URL carries one
    derived from the entity, e.g. a tracker slug; a static page sends nothing until the analyst types)."""
    badges = [b for b in (rendered.badge, ANTIBOT_BADGE if rendered.antibot else "", ml.badge if ml else "", *extra_badges) if b]
    label = rendered.label
    if note:
        label += f" ({note})"
    if badges:
        label += " [" + "; ".join(dict.fromkeys(badges)) + "]"
    if ml is not None and ml.warning:
        label += f" - WARNING: {ml.warning}"
    if level >= _tlp.TLP.AMBER:
        if ml is not None and ml.static:
            label += f" - opening sends nothing; typing {entity.display} on that page sends it to {rendered.host}"
        elif sent and sent != entity.value:
            label += f" - opening sends {sent} (for {entity.display}) to {rendered.host}"
        else:
            label += " - " + _links.disclosure_note(entity, rendered)
    return label


def emit(res: Any, entity: Entity, level: _tlp.TLP, rendered: _links.RenderedLink, *, ml: ModuleLink | None = None,
         extra_badges: Iterable[str] = (), note: str = "", sent: str = "") -> dict[str, Any]:
    """Add the link to ``res`` and return its raw record (id, url, host, tier, clickable, label)."""
    label = label_for(entity, rendered, level, ml=ml, extra_badges=extra_badges, note=note, sent=sent)
    res.link(label, rendered.url)
    return {
        "ref": rendered.ref, "url": rendered.url, "host": rendered.host, "tier": rendered.tier,
        "verified": rendered.verified, "antibot": rendered.antibot, "clickable": level < _tlp.TLP.AMBER and not rendered.touches_target,
        "label": label,
    }


# --------------------------------------------------------------------------------------
# Re-check report (P203/P216/P231/P250/P290/P300 cond 7: `v3lum doctor --links` data, offline)
# --------------------------------------------------------------------------------------


def recheck_report(today: _dt.date, *, max_age_days: int = RECHECK_MAX_AGE_DAYS,
                   packs: Iterable[str] = BATCH_PACKS) -> list[dict[str, Any]]:
    """Links of the batch packs (core links and x_module_links) that are unverified or were last checked more
    than ``max_age_days`` ago: ``[{ref, host, reason, checked_at}]``. Offline: reads the pack files only."""
    out: list[dict[str, Any]] = []
    for pack in packs:
        data = _load(pack)[1]
        entries = [(i, "") for i in data.get("links") or []] + [(i, " (module link)") for i in data.get(EXT_KEY) or []]
        for item, kind in entries:
            if not isinstance(item, Mapping):
                continue
            ref = f"{pack}:{item.get('id')}"
            checked = str(item.get("checked_at") or "")
            if not item.get("verified"):
                out.append({"ref": ref + kind, "host": item.get("host"), "reason": "unverified", "checked_at": checked})
                continue
            try:
                age = (today - _dt.date.fromisoformat(checked)).days
            except ValueError:
                out.append({"ref": ref + kind, "host": item.get("host"), "reason": "checked_at missing or invalid", "checked_at": checked})
                continue
            if age > max_age_days:
                out.append({"ref": ref + kind, "host": item.get("host"), "reason": f"last checked {age} days ago", "checked_at": checked})
    return out
