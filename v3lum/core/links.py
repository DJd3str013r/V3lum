"""Manual pivot links (P311): data-driven packs of web-tool URL templates, rendered for an entity.

Packs live in ``v3lum/data/pivot_links/<pack>.json`` (schema ``'v3lum.pivot_pack/1'``, frozen in wave 1;
see ``v3lum/data/pivot_links/README.md``)::

    {"schema": "v3lum.pivot_pack/1", "pack": "<file stem>", "title": "...",
     "links": [{"id", "label", "template", "entity_types", "category", "host", "verified", "checked_at",
                "privacy", "publishes", "touches_target", "login_required", "antibot", "notes"}]}

The legacy item format ``{name, types, url, category, description, source}`` (a list, or ``{"links": [...]}``,
also in ``v3lum/data/pivot_links.json``) is migrated on load (name -> label, types -> entity_types,
url -> template, host from the URL, verified False).

Safety (P311 cond 1-4, 6-7; A2/A8; team rules 1, 4 and 7):

* templates are rendered by whitelist substitution of ``{name}`` placeholders with ``re.sub`` (never
  ``str.format``) through per-type encoders, then re-checked (https, declared host, no userinfo/port);
* load-time validation: https only, hostname == declared host, no userinfo/port, placeholders only in
  path/query/fragment, known placeholders and entity types, type-restricted placeholders;
* lint (:func:`lint_pack`): publishes/login_required must be false, no CPF template ever, no
  submission/scan/publish endpoints, no enumeration/reset/login endpoints, no people-search/painel/leak
  hosts (:mod:`v3lum.core.lint`), no host of a provider flagged publishes_queries, PERSONAL_TYPES/CNPJ/
  EU VAT templates need privacy=true and a trusted/community provider host (unregistered = unknown =
  rejected), and unknown-tier hosts receive IOC_TYPES values only (A8). IOC-only links to unknown-tier
  hosts carry the badge 'unknown operator'; unverified links the badge 'unverified';
* a PivotLink built by a caller is validated and linted like a pack link before it renders, with its tier
  read from the provider registry (never the tier it claims).

V3LUM never fetches these links itself. TLP rendering (non-clickable text at AMBER+), ranking and the
case page are renderer concerns (waves 3-4); :class:`RenderedLink` carries the flags they need.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit

from v3lum.core import lint as _lint
from v3lum.core.entities import (
    COMPANY_ID_TYPES,
    IOC_TYPES,
    PERSONAL_TYPES,
    SECRET_TYPES,
    Entity,
    EntityType,
    normalize,
    normalize_domain,
    url_host,
)

SCHEMA = "v3lum.pivot_pack/1"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PACKS_DIR = DATA_DIR / "pivot_links"
LEGACY_FILE = DATA_DIR / "pivot_links.json"

#: Link categories = the analyst questions links are grouped by (P311 cond 10), in display order.
LINK_CATEGORIES: tuple[str, ...] = (
    "reputation", "history", "passive_dns", "code_paste", "social", "company", "crypto", "geo", "search", "other",
)

#: Whitelisted placeholders (anything else is rejected at load and never rendered).
PLACEHOLDERS: dict[str, str] = {
    "q": "value, percent-encoded (RFC 3986, nothing kept)",
    "qp": "value, form-encoded (quote_plus)",
    "raw": "value as is (only spaces, quotes, angle brackets, braces, control and non-ASCII characters encoded); "
    "only at the very end of the path of a template without query or fragment (archive-style lookups)",
    "domain": "the domain: domain/onion itself, e-mail domain or URL host",
    "user": "the account part: e-mail local part, username, social/telegram/fediverse/bsky/steam handle",
    "b64": "base64 of the value (percent-encoded; FOFA, Pulsedive)",
    "b64url": "URL-safe base64 of the value without padding",
    "e164": "phone in E.164 digits without '+' (5511987654321)",
    "e164_plus": "phone in E.164 with '+' (percent-encoded: %2B5511987654321)",
    "br_national": "Brazilian phone, DDD + number with the 9 (11987654321)",
    "br_national_no9": "Brazilian phone, DDD + number without the mobile 9 (1187654321)",
    "wa": "wa.me digits (international, no '+')",
    "cnpj_fmt": "CNPJ formatted 00.000.000/0001-91 (percent-encoded)",
    "cnpj_digits": "CNPJ unformatted (14 characters)",
    "cnpj_root": "CNPJ root (first 8 characters)",
    "idn": "domain in Unicode (IDN), percent-encoded",
    "punycode": "domain in ASCII/punycode",
    "ip": "the IP address (IPv4 or IPv6)",
    "asn_num": "AS number without the 'AS' prefix",
}

#: Placeholders valid only for some entity types (validated at load and at render).
PLACEHOLDER_TYPES: dict[str, frozenset[EntityType]] = {
    "domain": frozenset({EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL, EntityType.ONION}),
    "idn": frozenset({EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL}),
    "punycode": frozenset({EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL}),
    "user": frozenset({
        EntityType.EMAIL, EntityType.USERNAME, EntityType.SOCIAL_ACCOUNT, EntityType.TELEGRAM_HANDLE,
        EntityType.FEDIVERSE_HANDLE, EntityType.BSKY_HANDLE, EntityType.STEAM_PROFILE,
    }),
    "e164": frozenset({EntityType.PHONE}),
    "e164_plus": frozenset({EntityType.PHONE}),
    "br_national": frozenset({EntityType.PHONE}),
    "br_national_no9": frozenset({EntityType.PHONE}),
    "wa": frozenset({EntityType.PHONE}),
    "cnpj_fmt": frozenset({EntityType.CNPJ}),
    "cnpj_digits": frozenset({EntityType.CNPJ}),
    "cnpj_root": frozenset({EntityType.CNPJ}),
    "ip": frozenset({EntityType.IPV4, EntityType.IPV6}),
    "asn_num": frozenset({EntityType.ASN}),
}

#: Entity types that never go into a link: CPF (team rule 4, AR24), secrets (rule 1), blobs and files.
NO_LINK_TYPES: frozenset[EntityType] = frozenset({
    EntityType.CPF, EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS,
}) | SECRET_TYPES

#: Types whose templates need privacy=true and a trusted/community host (A8 BR4).
PRIVACY_TYPES: frozenset[EntityType] = PERSONAL_TYPES | COMPANY_ID_TYPES

BADGE_UNKNOWN_OPERATOR = "unknown operator"
BADGE_UNVERIFIED = "unverified"
TRUSTED_TIERS = frozenset({"trusted", "community"})
MAX_URL = 4096
#: Pack name of the PivotLink built by :func:`render_manual` for an inline Module.manual_link template.
INLINE_PACK = "inline"

_RE_PLACEHOLDER = re.compile(r"\{([a-z0-9_]+)\}")
_RE_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_RE_REF = re.compile(r"^([a-z][a-z0-9_]{1,63}):([a-z][a-z0-9_]{1,63})$")
_RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_LINK_FIELDS = frozenset({
    "id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy",
    "publishes", "touches_target", "login_required", "antibot", "notes", "scan_trigger",
})
_BOOL_FIELDS = ("verified", "privacy", "publishes", "touches_target", "login_required", "antibot", "scan_trigger")
_LEGACY_CATEGORIES = {
    "dns": "passive_dns", "passive_dns": "passive_dns", "pdns": "passive_dns", "whois": "history", "history": "history",
    "archive": "history", "threat_intel": "reputation", "reputation": "reputation", "malware": "reputation",
    "ioc": "reputation", "code": "code_paste", "paste": "code_paste", "code_paste": "code_paste", "social": "social",
    "company": "company", "crypto": "crypto", "blockchain": "crypto", "geo": "geo", "search": "search",
}


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PivotLink:
    """One validated pivot-link template (``ref`` = 'pack:id')."""

    pack: str
    id: str
    label: str
    template: str
    entity_types: tuple[EntityType, ...]
    category: str
    host: str
    verified: bool = False
    checked_at: str = ""
    privacy: bool = False
    publishes: bool = False
    touches_target: bool = False
    login_required: bool = False
    antibot: bool = False
    tier: str = "unknown"
    notes: str = ""

    @property
    def ref(self) -> str:
        return f"{self.pack}:{self.id}"

    def accepts(self, etype: EntityType) -> bool:
        return etype in self.entity_types

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["entity_types"] = [t.value for t in self.entity_types]
        out["ref"] = self.ref
        return out


@dataclass(frozen=True)
class RenderedLink:
    """A link rendered for one entity (never fetched by V3LUM)."""

    ref: str
    label: str
    url: str
    host: str
    category: str
    verified: bool
    privacy: bool
    touches_target: bool
    antibot: bool
    tier: str
    badge: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Pack:
    """A loaded pack: its valid links only (the problems are in :func:`errors`)."""

    name: str
    title: str
    source: str
    links: tuple[PivotLink, ...] = ()


@dataclass
class _State:
    packs: dict[str, Pack] = field(default_factory=dict)
    links: dict[str, PivotLink] = field(default_factory=dict)
    ordered: list[PivotLink] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    registry: Any = None


# --------------------------------------------------------------------------------------
# Provider tiers (WP02 registry; unregistered hosts are 'unknown')
# --------------------------------------------------------------------------------------


def _registry() -> Any:
    try:
        from v3lum.core import providers
    except ImportError:  # pragma: no cover - wave-1 transition
        return None
    try:
        return providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry must not break link loading
        return None


def _provider_for_host(host: str) -> Any:
    reg = _registry()
    if reg is None or not host:
        return None
    try:
        return reg.provider_for_host(host)
    except Exception:  # noqa: BLE001
        return None


def host_tier(host: str) -> str:
    """Trust tier of the provider owning ``host`` ('trusted'|'community'|'unknown'; unregistered = unknown)."""
    provider = _provider_for_host(host)
    tier = getattr(provider, "tier", "unknown") if provider is not None else "unknown"
    return tier if tier in ("trusted", "community", "unknown") else "unknown"


def _host_publishes(host: str) -> bool:
    provider = _provider_for_host(host)
    return bool(getattr(getattr(provider, "flags", None), "publishes_queries", False))


# --------------------------------------------------------------------------------------
# Encoders (P311 cond 3)
# --------------------------------------------------------------------------------------


def encode_e164(phone: str, *, plus: bool = False) -> str:
    """E.164 digits of a phone ('5511987654321'; '+5511987654321' with plus=True). Raises ValueError."""
    digits = normalize(EntityType.PHONE, phone)[1:]
    return "+" + digits if plus else digits


def encode_br_national(phone: str, *, with_nine: bool = True) -> str:
    """Brazilian national form DDD + number, with or without the mobile 9 ('11987654321' / '1187654321').

    A mobile written without the 9 (8 digits starting 6-9) gets it back with ``with_nine=True``; landlines
    are the same in both forms. Raises ValueError for non-Brazilian numbers.
    """
    digits = encode_e164(phone)
    if not digits.startswith("55") or len(digits) not in (12, 13) or digits[2] == "0":
        raise ValueError("not a Brazilian phone number")
    ddd, number = digits[2:4], digits[4:]
    if len(number) == 9:
        if number[0] != "9":
            raise ValueError("invalid Brazilian mobile number")
        return ddd + (number if with_nine else number[1:])
    if number[0] in "6789":  # mobile written without the 9
        return ddd + ("9" + number if with_nine else number)
    return ddd + number


def encode_wa(phone: str) -> str:
    """wa.me / api.whatsapp.com digits: the international number without '+'."""
    return encode_e164(phone)


def cnpj_fmt(cnpj: str) -> str:
    """'00.000.000/0001-91' (alphanumeric CNPJ supported)."""
    c = normalize(EntityType.CNPJ, cnpj)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}"


def cnpj_digits(cnpj: str) -> str:
    """The 14 unformatted CNPJ characters."""
    return normalize(EntityType.CNPJ, cnpj)


def cnpj_root(cnpj: str) -> str:
    """The 8-character CNPJ root (company, all branches)."""
    return normalize(EntityType.CNPJ, cnpj)[:8]


def punycode(domain: str) -> str:
    """ASCII (IDNA/punycode) form of a domain: 'münchen.de' -> 'xn--mnchen-3ya.de'."""
    return normalize_domain(domain)


def idn_unicode(domain: str) -> str:
    """Unicode form of a domain: 'xn--mnchen-3ya.de' -> 'münchen.de'."""
    labels = []
    for label in punycode(domain).split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError as exc:
                raise ValueError(f"invalid IDN label {label!r}") from exc
        labels.append(label)
    return ".".join(labels)


def b64(value: str) -> str:
    """Standard base64 of the UTF-8 value (the {b64} placeholder percent-encodes it)."""
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def b64url(value: str) -> str:
    """URL-safe base64 of the UTF-8 value without '=' padding."""
    return base64.urlsafe_b64encode(str(value).encode("utf-8")).decode("ascii").rstrip("=")


#: Characters {raw} keeps literally (URL delimiters and '%'); spaces, quotes, angle brackets, braces,
#: backslashes, control and non-ASCII characters are percent-encoded so the URL stays well-formed.
_RAW_SAFE = "/:@!$&()*+,;=?#~%"


def _raw(value: str) -> str:
    return quote(value, safe=_RAW_SAFE)


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------


class _NotApplicable(ValueError):
    """A placeholder cannot be computed for this entity."""


def _domain_of(entity: Entity) -> str:
    t, v = entity.type, entity.value
    if t in (EntityType.DOMAIN, EntityType.ONION):
        return v
    if t is EntityType.EMAIL:
        return v.rsplit("@", 1)[1]
    if t is EntityType.URL:
        host = url_host(v)
        if not host or re.match(r"^[0-9.]+$", host) or ":" in host:
            raise _NotApplicable("URL host is not a domain")
        return host
    raise _NotApplicable(f"no domain for {t.value}")


def _user_of(entity: Entity) -> str:
    t, v = entity.type, entity.value
    if t is EntityType.EMAIL:
        return v.rsplit("@", 1)[0]
    if t is EntityType.FEDIVERSE_HANDLE:
        return v.split("@", 1)[0]
    if t in (EntityType.SOCIAL_ACCOUNT, EntityType.STEAM_PROFILE):
        return v.split(":", 1)[1]
    if t in (EntityType.USERNAME, EntityType.TELEGRAM_HANDLE, EntityType.BSKY_HANDLE):
        return v
    raise _NotApplicable(f"no account part for {t.value}")


def _placeholder(name: str, entity: Entity) -> str:
    allowed = PLACEHOLDER_TYPES.get(name)
    if allowed is not None and entity.type not in allowed:
        raise _NotApplicable(f"{{{name}}} does not apply to {entity.type.value}")
    v = entity.value
    if name == "q":
        return quote(v, safe="")
    if name == "qp":
        return quote_plus(v)
    if name == "raw":
        return _raw(v)
    if name == "domain":
        return quote(_domain_of(entity), safe="")
    if name == "user":
        return quote(_user_of(entity), safe="")
    if name == "b64":
        return quote(b64(v), safe="")
    if name == "b64url":
        return b64url(v)
    if name == "e164":
        return encode_e164(v)
    if name == "e164_plus":
        return quote(encode_e164(v, plus=True), safe="")
    if name == "br_national":
        return encode_br_national(v, with_nine=True)
    if name == "br_national_no9":
        return encode_br_national(v, with_nine=False)
    if name == "wa":
        return encode_wa(v)
    if name == "cnpj_fmt":
        return quote(cnpj_fmt(v), safe="")
    if name == "cnpj_digits":
        return cnpj_digits(v)
    if name == "cnpj_root":
        return cnpj_root(v)
    if name == "idn":
        return quote(idn_unicode(_domain_of(entity)), safe="")
    if name == "punycode":
        return punycode(_domain_of(entity))
    if name == "ip":
        return quote(v, safe=":")
    if name == "asn_num":
        return v[2:]
    raise _NotApplicable(f"unknown placeholder {{{name}}}")


def _substitute(template: str, entity: Entity) -> str | None:
    """Whitelist substitution with re.sub (never str.format); None when anything does not apply."""

    def repl(m: re.Match[str]) -> str:
        if m.group(1) not in PLACEHOLDERS:
            raise _NotApplicable(f"unknown placeholder {m.group(0)}")
        return _placeholder(m.group(1), entity)

    try:
        out = _RE_PLACEHOLDER.sub(repl, template)
    except ValueError:  # _NotApplicable and encoder errors
        return None
    if "{" in out or "}" in out:  # a malformed placeholder such as {0.__class__} survived
        return None
    return out


def _rendered_ok(url: str, host: str) -> bool:
    if len(url) > MAX_URL or _RE_CTRL.search(url) or any(c.isspace() for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and (parts.hostname or "") == host
        and parts.username is None
        and parts.password is None
        and port is None
        and "@" not in parts.netloc
    )


def _badge(link: PivotLink) -> str:
    badges = []
    if link.tier == "unknown":
        badges.append(BADGE_UNKNOWN_OPERATOR)
    if not link.verified:
        badges.append(BADGE_UNVERIFIED)
    return ", ".join(badges)


def _checked_adhoc(link: PivotLink) -> PivotLink | None:
    """A PivotLink that does not come from a loaded pack (built by a caller or by :func:`render_manual`),
    validated and linted like a pack link, with its tier taken from the provider registry (a caller's
    claimed tier is never trusted). None when it would not pass the pack lint."""
    label = link.label
    if not isinstance(label, str) or not label or len(label) > 120 or _RE_CTRL.search(label):
        return None
    if link.category not in LINK_CATEGORIES or not isinstance(link.template, str) or not isinstance(link.host, str):
        return None
    if not isinstance(link.entity_types, tuple) or not all(isinstance(t, EntityType) for t in link.entity_types):
        return None
    tier = host_tier(link.host)
    checked = link if link.tier == tier else replace(link, tier=tier)
    errs = validate_template(link.template, host=link.host, entity_types=link.entity_types or None)
    errs += _lint_link(checked, {}, tier, _host_publishes(link.host), require_placeholder=link.pack != INLINE_PACK)
    return None if errs else checked


def render(link_or_ref: PivotLink | str, entity: Entity) -> RenderedLink | None:
    """Render one link for ``entity`` (a PivotLink or a 'pack:id' ref); None when it does not apply.

    Never renders CPF, secrets, blobs or files; personal/company values only through privacy links to
    trusted/community hosts; unknown-tier hosts only receive IOC_TYPES values (A8). A PivotLink that is
    not a loaded pack link is validated and linted first, with its tier read from the provider registry.
    The result is re-checked (https, declared host, no userinfo/port).
    """
    link = get_link(link_or_ref) if isinstance(link_or_ref, str) else link_or_ref
    if not isinstance(link, PivotLink) or not isinstance(entity, Entity):
        return None
    if _state().links.get(link.ref) is not link:
        link = _checked_adhoc(link)
        if link is None:
            return None
    if entity.type in NO_LINK_TYPES or entity.type not in link.entity_types:
        return None
    if entity.type in PRIVACY_TYPES and (not link.privacy or link.tier not in TRUSTED_TIERS):
        return None
    if link.tier not in TRUSTED_TIERS and entity.type not in IOC_TYPES:
        return None
    if link.publishes or link.login_required:
        return None
    url = _substitute(link.template, entity)
    if url is None or not _rendered_ok(url, link.host):
        return None
    return RenderedLink(
        ref=link.ref,
        label=link.label,
        url=url,
        host=link.host,
        category=link.category,
        verified=link.verified,
        privacy=link.privacy,
        touches_target=link.touches_target,
        antibot=link.antibot,
        tier=link.tier,
        badge=_badge(link),
    )


# --------------------------------------------------------------------------------------
# Validation and lint
# --------------------------------------------------------------------------------------


def _parse_types(raw: Any) -> tuple[tuple[EntityType, ...], list[str]]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        return (), ["entity_types must be a non-empty list of entity types"]
    out: list[EntityType] = []
    errs: list[str] = []
    for item in raw:
        if isinstance(item, EntityType):
            out.append(item)
            continue
        try:
            out.append(EntityType(str(item)))
        except ValueError:
            errs.append(f"unknown entity type {item!r}")
    return tuple(dict.fromkeys(out)), errs


def validate_template(template: str, *, host: str, entity_types: Iterable[EntityType | str] | None) -> list[str]:
    """Structural problems of a template (empty list = valid).

    https only; hostname == ``host``; no userinfo or port; placeholders only in path/query/fragment;
    placeholders from the whitelist only (no ``str.format`` syntax); type-restricted placeholders valid
    for every declared type (skipped when ``entity_types`` is empty/None, e.g. inline manual links).
    """
    errs: list[str] = []
    if not isinstance(template, str) or not template:
        return ["template must be a non-empty string"]
    if len(template) > 2048:
        errs.append("template longer than 2048 characters")
    if _RE_CTRL.search(template) or any(c.isspace() for c in template):
        errs.append("template contains whitespace or control characters")
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", template, flags=re.S)
    if not m:
        return errs + ["template must be an absolute https URL"]
    scheme, netloc, rest = m.group(1), m.group(2), m.group(3)
    if scheme != "https":
        errs.append("https only (scheme must be literally 'https')")
    if "{" in netloc or "}" in netloc:
        errs.append("placeholders are allowed only in the path, query or fragment")
    if "@" in netloc:
        errs.append("userinfo is not allowed in templates")
    hostname = netloc
    if ":" in netloc and not netloc.startswith("["):
        hostname = netloc.split(":", 1)[0]
        errs.append("explicit ports are not allowed in templates")
    declared = (host or "").strip()
    if not declared:
        errs.append("declared host missing")
    elif declared != declared.lower():
        errs.append(f"declared host {declared!r} must be lower-case")
    elif hostname.lower() != declared:
        errs.append(f"template host {hostname!r} differs from the declared host {declared!r}")
    else:
        try:
            if normalize_domain(declared) != declared:
                errs.append(f"host {declared!r} is not a canonical lower-case hostname")
        except ValueError:
            errs.append(f"host {declared!r} is not a valid hostname")
    names = _RE_PLACEHOLDER.findall(rest)
    leftover = _RE_PLACEHOLDER.sub("", rest)
    if "{" in leftover or "}" in leftover:
        errs.append("malformed placeholder (only {name} from the whitelist; never str.format syntax)")
    if "raw" in names and (names.count("raw") > 1 or not rest.endswith("{raw}") or "?" in rest or "#" in rest):
        # {raw} keeps '?', '&', '=' and '#': anywhere else an untrusted value could inject or override
        # query parameters of the third-party request (e.g. force a public scan, rule 7).
        errs.append("{raw} is allowed only once, at the very end of the path, in a template without query or "
                    "fragment (use {q} or {qp} in queries)")
    unknown = sorted({n for n in names if n not in PLACEHOLDERS})
    if unknown:
        errs.append(f"unknown placeholders {unknown}")
    types, type_errs = _parse_types(list(entity_types)) if entity_types else ((), [])
    errs.extend(type_errs)
    for name in sorted({n for n in names if n in PLACEHOLDER_TYPES}):
        bad = [t.value for t in types if t not in PLACEHOLDER_TYPES[name]]
        if bad:
            allowed = ", ".join(sorted(t.value for t in PLACEHOLDER_TYPES[name]))
            errs.append(f"placeholder {{{name}}} is valid only for {allowed} (declared {', '.join(bad)})")
    return errs


def _probe_sample(template: str) -> str:
    """The template as the probe lint sees it: every placeholder becomes the neutral token '{value}', so
    patterns that look at where the value goes (e.g. 'verify/{value}') still apply."""
    return _RE_PLACEHOLDER.sub("{value}", template)


def _valid_date(text: str) -> bool:
    if not _RE_DATE.match(text):
        return False
    try:
        _dt.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _lint_link(
    link: PivotLink, raw: Mapping[str, Any], tier: str, publishes_host: bool, *, require_placeholder: bool = True
) -> list[str]:
    errs: list[str] = []
    if link.publishes:
        errs.append("publishes must be false: links never submit or publish the value (rule 7)")
    if link.login_required:
        errs.append("login_required must be false: no pages behind a login (rule 1)")
    if raw.get("scan_trigger") is True:
        errs.append("scan_trigger links are not allowed (rule 7)")
    if EntityType.CPF in link.entity_types:
        errs.append("no template accepts CPF (team rule 4, AR24)")
    for t in link.entity_types:
        if t in NO_LINK_TYPES and t is not EntityType.CPF:
            errs.append(f"{t.value} values never go into links")
    if require_placeholder and not _RE_PLACEHOLDER.search(link.template):
        errs.append("template has no placeholder (the link would not carry the value)")
    rule = _lint.forbidden_probe(_probe_sample(link.template))
    if rule is not None:
        errs.append(f"{rule}: {_lint.PROBE_RULES[rule]}")
    if publishes_host:
        errs.append("the host's provider publishes submitted values (publishes_queries, rule 7)")
    sensitive = [t.value for t in link.entity_types if t in PRIVACY_TYPES]
    if sensitive:
        if not link.privacy:
            errs.append(f"templates for personal/company values ({', '.join(sensitive)}) need privacy=true")
        if tier not in TRUSTED_TIERS:
            errs.append(
                f"personal/company values ({', '.join(sensitive)}) only go to trusted/community provider hosts; "
                f"{link.host!r} is {tier} (register its provider with a reviewed tier, A8 BR4)"
            )
    other = [t.value for t in link.entity_types if t not in IOC_TYPES and t not in PRIVACY_TYPES and t not in NO_LINK_TYPES]
    if other and tier not in TRUSTED_TIERS:
        errs.append(
            f"unknown-tier hosts receive IOC_TYPES values only (A8); {link.host!r} is {tier} and the link accepts "
            f"{', '.join(other)} (register its provider with a reviewed tier)"
        )
    if link.verified and not link.checked_at:
        errs.append("verified links record checked_at (YYYY-MM-DD)")
    return errs


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")
    if not s or not s[0].isalpha():
        s = "link_" + s
    return s[:64].rstrip("_") or "link"


def _migrate_legacy(item: Mapping[str, Any], used_ids: set[str]) -> dict[str, Any]:
    """Legacy {name, types, url, category, description, source} -> schema v3lum.pivot_pack/1 item."""
    base = _slug(item.get("name") or "link")
    ident, n = base, 2
    while ident in used_ids:
        ident, n = f"{base[:60]}_{n}", n + 1
    url = str(item.get("url") or "")
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    notes = " ".join(str(x) for x in (item.get("description") or "", f"(source: {item['source']})" if item.get("source") else "") if x)
    category = _LEGACY_CATEGORIES.get(str(item.get("category") or "").lower(), "other")
    return {
        "id": ident, "label": str(item.get("name") or ident), "template": url, "entity_types": item.get("types") or [],
        "category": category, "host": host, "verified": False, "notes": notes,
    }


def _parse_link(pack: str, item: Any, where: str) -> tuple[PivotLink | None, list[str]]:
    if not isinstance(item, Mapping):
        return None, [f"{where}: link entries must be objects"]
    errs: list[str] = []
    unknown = sorted(k for k in item if k not in _LINK_FIELDS and not str(k).startswith("x_"))
    if unknown:
        errs.append(f"unknown fields {unknown}")
    for name in ("id", "label", "template", "entity_types", "category", "host"):
        if item.get(name) in (None, "", []):
            errs.append(f"missing {name}")
    ident = str(item.get("id") or "")
    if ident and not _RE_NAME.match(ident):
        errs.append(f"invalid id {ident!r} (^[a-z][a-z0-9_]{{1,63}}$)")
    label = item.get("label")
    if label is not None and (not isinstance(label, str) or len(label) > 120 or _RE_CTRL.search(label)):
        errs.append("label must be a single-line string of at most 120 characters")
    category = item.get("category")
    if category not in (None, "") and category not in LINK_CATEGORIES:
        errs.append(f"category {category!r} not in {list(LINK_CATEGORIES)}")
    for name in _BOOL_FIELDS:
        if name in item and not isinstance(item[name], bool):
            errs.append(f"{name} must be true or false")
    checked_at = item.get("checked_at") or ""
    if checked_at and (not isinstance(checked_at, str) or not _valid_date(checked_at)):
        errs.append("checked_at must be a date YYYY-MM-DD")
    notes = item.get("notes")
    if notes is not None and not isinstance(notes, str):
        errs.append("notes must be a string")
    types, type_errs = _parse_types(item.get("entity_types"))
    errs.extend(type_errs)
    template = item.get("template")
    host = str(item.get("host") or "")
    if isinstance(template, str) and template:
        errs.extend(validate_template(template, host=host, entity_types=types))
    if errs:
        return None, [f"{where}: {e}" for e in errs]
    tier = host_tier(host)
    link = PivotLink(
        pack=pack,
        id=ident,
        label=str(label),
        template=str(template),
        entity_types=types,
        category=str(category),
        host=host,
        verified=bool(item.get("verified", False)),
        checked_at=str(checked_at),
        privacy=bool(item.get("privacy", False)),
        publishes=bool(item.get("publishes", False)),
        touches_target=bool(item.get("touches_target", False)),
        login_required=bool(item.get("login_required", False)),
        antibot=bool(item.get("antibot", False)),
        tier=tier,
        notes=str(item.get("notes") or ""),
    )
    lint_errs = _lint_link(link, item, tier, _host_publishes(host))
    if lint_errs:
        return None, [f"{where}: {e}" for e in lint_errs]
    return link, []


def _parse_pack(data: Any, *, source: str) -> tuple[Pack | None, list[str]]:
    stem = Path(source).stem if source.endswith(".json") else ""
    errs: list[str] = []
    if isinstance(data, list):  # legacy list of items
        items, name, title, legacy = data, stem or "legacy", stem or "legacy", True
    elif isinstance(data, Mapping):
        schema = data.get("schema")
        items = data.get("links")
        if schema is None:
            legacy = isinstance(items, list) and all(isinstance(i, Mapping) and "url" in i and "template" not in i for i in items)
            if not legacy:  # a v2-shaped pack without its schema is not loaded (fail closed)
                return None, [f"{source}: missing \"schema\": {SCHEMA!r}"]
            name, title = stem or str(data.get("pack") or "legacy"), str(data.get("title") or stem or "legacy")
        elif schema != SCHEMA:
            return None, [f"{source}: unknown schema {schema!r} (expected {SCHEMA!r})"]
        else:
            legacy = False
            name = str(data.get("pack") or "")
            title = str(data.get("title") or name)
            unknown = sorted(k for k in data if k not in ("schema", "pack", "title", "links", "notes") and not str(k).startswith("x_"))
            if unknown:
                errs.append(f"{source}: unknown pack fields {unknown}")
            if not _RE_NAME.match(name):
                errs.append(f"{source}: invalid pack name {name!r} (^[a-z][a-z0-9_]{{1,63}}$)")
            if stem and name != stem:
                errs.append(f"{source}: pack {name!r} must equal the file stem {stem!r}")
    else:
        return None, [f"{source}: a pack is an object (or a legacy list)"]
    if not isinstance(items, list):
        return None, errs + [f"{source}: 'links' must be a list"]
    links: list[PivotLink] = []
    used: set[str] = set()
    for i, item in enumerate(items):
        if legacy and isinstance(item, Mapping) and "url" in item and "template" not in item:
            item = _migrate_legacy(item, used)
        ident = str(item.get("id") or f"#{i}") if isinstance(item, Mapping) else f"#{i}"
        where = f"{source}: {name}:{ident}"
        if ident in used:
            errs.append(f"{where}: duplicate link id")
            continue
        used.add(ident)
        link, link_errs = _parse_link(name, item, where)
        errs.extend(link_errs)
        if link is not None:
            links.append(link)
    if any(e.startswith(f"{source}: invalid pack name") or "must equal the file stem" in e for e in errs):
        return None, errs
    return Pack(name=name, title=title, source=source, links=tuple(links)), errs


def lint_pack(data: Any, *, source: str = "<pack>") -> list[str]:
    """Every validation and lint problem of a parsed pack (empty list = the pack is clean).

    ``source`` names the pack in messages; when it is a '<stem>.json' file name the pack name must equal
    the stem. Used by CI (WP09 lint_data_file) and by the loader.
    """
    return _parse_pack(data, source=source)[1]


# --------------------------------------------------------------------------------------
# Loading and queries
# --------------------------------------------------------------------------------------

_LOCK = threading.Lock()
_STATE: _State | None = None
_EXTRA_DIRS: tuple[str, ...] = ()


def _pack_files(extra_dirs: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    if LEGACY_FILE.is_file():
        files.append(LEGACY_FILE)
    for directory in (PACKS_DIR, *(Path(d) for d in extra_dirs)):
        if directory.is_dir():
            files.extend(sorted(p for p in directory.iterdir() if p.suffix == ".json" and p.is_file()))
    return files


def _load(extra_dirs: Iterable[str]) -> _State:
    state = _State(registry=_registry())
    seen: set[tuple[str, tuple[EntityType, ...]]] = set()
    for path in _pack_files(extra_dirs):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state.errors.append(f"{path.name}: unreadable pack ({exc})")
            continue
        pack, errs = _parse_pack(data, source=path.name)
        state.errors.extend(errs)
        if pack is None:
            continue
        if pack.name in state.packs:
            state.errors.append(f"{path.name}: duplicate pack name {pack.name!r} (already loaded from {state.packs[pack.name].source})")
            continue
        kept: list[PivotLink] = []
        for link in pack.links:
            sig = (link.template, link.entity_types)
            if sig in seen:  # the same template is already served by an earlier pack
                continue
            seen.add(sig)
            state.links[link.ref] = link
            state.ordered.append(link)
            kept.append(link)
        state.packs[pack.name] = Pack(pack.name, pack.title, pack.source, tuple(kept))
    return state


def _state() -> _State:
    global _STATE
    st = _STATE
    if st is not None and st.registry is _registry():
        return st
    with _LOCK:
        if _STATE is None or _STATE.registry is not _registry():  # provider tiers changed: re-lint
            _STATE = _load(_EXTRA_DIRS)
        return _STATE


def reload(extra_dirs: Iterable[str] = ()) -> None:
    """Re-read every pack (plus ``extra_dirs``, e.g. a test's tmp directory); no args = bundled packs."""
    global _STATE, _EXTRA_DIRS
    with _LOCK:
        _EXTRA_DIRS = tuple(str(d) for d in extra_dirs)
        _STATE = _load(_EXTRA_DIRS)


def packs() -> dict[str, Pack]:
    """Loaded packs by name (valid links only)."""
    return dict(_state().packs)


def templates() -> list[PivotLink]:
    """Every valid link of every pack, in load order."""
    return list(_state().ordered)


def errors() -> list[str]:
    """Load, validation and lint problems of every pack (empty for the shipped packs)."""
    return list(_state().errors)


def get_link(ref: str) -> PivotLink | None:
    """A valid link by its 'pack:id' reference, or None."""
    return _state().links.get(str(ref or "").strip())


def pivot_links_for(
    entity: Entity, *, categories: Iterable[str] | None = None, include_privacy: bool = False
) -> list[RenderedLink]:
    """Rendered links for ``entity``: verified first, unverified with the badge 'unverified'.

    privacy=true links (person, phone, e-mail...) are included only with ``include_privacy=True``: callers
    pass it only for analyst-typed seeds whose case opted in (P311 cond 6), never for auto-discovered
    entities.
    """
    if not isinstance(entity, Entity):
        return []
    wanted = {categories} if isinstance(categories, str) else (set(categories) if categories else None)
    out: list[RenderedLink] = []
    for link in templates():
        if entity.type not in link.entity_types:
            continue
        if wanted is not None and link.category not in wanted:
            continue
        if link.privacy and not include_privacy:
            continue
        rendered = render(link, entity)
        if rendered is not None:
            out.append(rendered)
    out.sort(key=lambda r: not r.verified)
    return out


def links_for(entity: Entity, categories: set[str] | None = None) -> list[tuple[str, str]]:
    """Legacy API: (label, url) pairs for ``entity`` (privacy links excluded)."""
    return [(r.label, r.url) for r in pivot_links_for(entity, categories=categories, include_privacy=False)]


def disclosure_note(entity: Entity, rendered: RenderedLink) -> str:
    """The A2 disclosure warning shown with a link at TLP:AMBER and above (masked value):
    ``'opening sends 8.8.8.8 to www.shodan.io'``."""
    return f"opening sends {entity.display} to {rendered.host}"


def validate_manual_link(value: str | None) -> list[str]:
    """Problems of a Module.manual_link ('' = none declared): a resolvable '<pack>:<link_id>' or an inline
    https template with whitelisted placeholders that passes the same lint as pack templates."""
    if value in (None, ""):
        return []
    if not isinstance(value, str):
        return ["manual_link must be a string"]
    v = value.strip()
    if _RE_REF.match(v):
        if get_link(v) is None:
            return [f"manual_link {v!r} does not resolve to a valid pivot link (see links.errors())"]
        return []
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", v):
        return ["manual_link must be '<pack>:<link_id>' or an https URL template"]
    try:
        host = (urlsplit(v).hostname or "").lower()
    except ValueError:
        host = ""
    errs = validate_template(v, host=host, entity_types=None)
    rule = _lint.forbidden_probe(_probe_sample(v))
    if rule is not None:
        errs.append(f"{rule}: {_lint.PROBE_RULES[rule]}")
    if host and _host_publishes(host):
        errs.append("the host's provider publishes submitted values (publishes_queries, rule 7)")
    return errs


def render_manual(manual_link: str | None, entity: Entity, *, include_privacy: bool = False) -> RenderedLink | None:
    """Render a Module.manual_link for ``entity`` (the fallback when automation is skipped or blocked).

    Refs render through the pack; inline templates render as an unverified link to their host with the
    same rules (no CPF/secrets, personal/company values only to trusted/community hosts, unknown-tier
    hosts for IOC_TYPES only). Like :func:`pivot_links_for`, privacy links (personal or company values)
    render only with ``include_privacy=True``: callers pass it for analyst-typed seeds of a case that opted
    in, never for auto-discovered entities (P311 cond 6). An inline template may lack placeholders (a
    search form behind an anti-bot wall: the analyst types the value).
    """
    if not isinstance(entity, Entity) or not manual_link or validate_manual_link(manual_link):
        return None
    v = manual_link.strip()
    if _RE_REF.match(v):
        link = get_link(v)
        if link is None or (link.privacy and not include_privacy):
            return None
        return render(link, entity)
    if entity.type in PRIVACY_TYPES and not include_privacy:
        return None
    host = (urlsplit(v).hostname or "").lower()
    link = PivotLink(
        pack=INLINE_PACK,
        id="manual",
        label=f"{host} (manual lookup)",
        template=v,
        entity_types=(entity.type,),
        category="other",
        host=host,
        verified=False,
        privacy=entity.type in PRIVACY_TYPES,
        tier=host_tier(host),
    )
    return render(link, entity)
