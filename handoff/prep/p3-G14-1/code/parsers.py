"""Pure reference helpers for batch p3-G14-1 (group G14, pivot links and dorks).

Proposals:
  P098 pivots_email            data/pivot_links/email.json            (email-format.com, offline pack)
  P125 pivots_username_social  data/pivot_links/username_social.json  (Bluesky, Mastodon, offline pack)
  P144 pivots_breach_leak      HIBP breach-page link emitted by the breach modules (no pack, FC1)
  P257 pivots_person           data/pivot_links/person.json           (Webmii, offline pack, opt-in)
  P289 employee_xray           aggregate X-ray over P307's Brave source (keyed, own-org / SE scope only)
  P307 web_search_api          Brave (key), DuckDuckGo Instant Answer (keyless context), Marginalia/Tavily/Exa
                               (keyed, gated), SerpApi refused

Standard library only, no V3LUM imports, no network. Every function is defensive: wrong types, missing fields,
bytes, HTML instead of JSON and JSON instead of HTML return a value or None and never raise.

Names tagged 'core:' mirror the frozen contract (module_author_contract s.15, schema v3lum.pivot_pack/1, A2, A8).
Names tagged 'proposed:' are additions this batch needs (see notes.md section 0). "FCn" = final condition n of the
proposal in specs/p3-G14-1.md.

Sections
  A. constants                      B. small text/HTTP helpers         C. value validators and encoders
  D. template rendering (FC3)       E. pack lint                       F. link view, ordering, doctor, dedupe
  G. P098 company -> domain         H. P144 HIBP breach link           I. maintainer re-check classifiers
  J. P307 web search APIs           K. P289 employee X-ray aggregate
"""
from __future__ import annotations

import datetime as _dt
import html as _html
import json
import re
import unicodedata
from collections import Counter
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit

# ================================================================================================ A. constants

PACK_SCHEMA = "v3lum.pivot_pack/1"  # core
FROZEN_LINK_KEYS = (  # core: module_author_contract s.15
    "id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy",
    "publishes", "touches_target", "login_required", "antibot", "notes",
)
REQUIRED_LINK_KEYS = FROZEN_LINK_KEYS[:-1]  # notes is optional
EXTENSION_LINK_KEYS = ("max_tlp",)  # proposed: P257 FC1 asks the phase-0 schema for an optional per-link max_tlp
LINK_CATEGORIES = ("reputation", "history", "passive_dns", "code_paste", "social", "company", "crypto", "geo",
                   "search", "other")  # core: frozen enum; also the analyst-question group order (P311 cond 10)
TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
TIERS = ("trusted", "community", "unknown")

# A8 canonical type sets (core/entities.py is the authority).
PERSONAL_TYPES = frozenset({
    "email", "phone", "username", "person_name", "cpf", "pix_key", "plate_br", "imei", "coordinates",
    "social_account", "telegram_handle", "telegram_invite", "discord_invite", "fediverse_handle", "bsky_handle",
    "steam_profile", "vin", "email_headers"})
IOC_TYPES = frozenset({
    "domain", "url", "ipv4", "ipv6", "cidr", "asn", "md5", "sha1", "sha256", "sha512", "ssdeep", "cve",
    "mitre_technique", "onion", "btc_address", "eth_address", "xmr_address", "other_crypto_address",
    "favicon_hash", "cert_fingerprint", "analytics_id"})
COMPANY_ID_TYPES = frozenset({"cnpj"})
FREE_TEXT_TYPES = frozenset({"keyword", "company_name", "malware_family", "threat_actor"})
KNOWN_TYPES = PERSONAL_TYPES | IOC_TYPES | COMPANY_ID_TYPES | FREE_TEXT_TYPES

# Labels the final conditions fix verbatim.
EMAIL_PATTERN_LABEL = "corporate address pattern: use the pattern, never the sample people"  # P098 FC9
SAME_HANDLE_LABEL = "same handle does not prove identity"  # P125 FC10 (A5)
PEOPLE_SEARCH_LABEL = "people search engine - homonyms likely"  # P257 FC2
XRAY_LABEL = "social-engineering exposure (aggregate)"  # P289 FC6
HIBP_ATTRIBUTION = "Have I Been Pwned"  # P144 FC4 (CC BY 4.0)
HIBP_HOST = "haveibeenpwned.com"
HIBP_BREACH_TEMPLATE = "https://haveibeenpwned.com/breach/{q}"  # P144 FC1 (lower-case /breach/, verified 200)

BADGE_UNVERIFIED = "unverified"  # core: links.BADGE_UNVERIFIED
BADGE_UNKNOWN_OPERATOR = "unknown operator"  # core: A8
BADGE_PRIVACY = "privacy: analyst-typed seed, case opt-in"  # P311 cond 6
TERMINAL_MAX_LINKS = 8  # FC6 of every pack
RECHECK_MAX_AGE_DAYS = 180  # FC7 of every pack

INTERNAL_SUFFIXES = ("local", "localhost", "internal", "intranet", "lan", "home.arpa", "corp", "private",
                     "localdomain", "test", "example", "invalid", "arpa", "onion", "alt")
ATPROTO_DISALLOWED_TLDS = ("alt", "arpa", "example", "internal", "invalid", "local", "localhost", "onion")

PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")  # core: the re.sub pattern of the frozen renderer
# Value: the entity types a placeholder accepts (None = any type).
FROZEN_PLACEHOLDERS = {  # core: module_author_contract s.15
    "q": None, "qp": None, "raw": None, "domain": {"domain"}, "user": {"username"}, "b64": None, "b64url": None,
    "e164": {"phone"}, "e164_plus": {"phone"}, "br_national": {"phone"}, "br_national_no9": {"phone"},
    "wa": {"phone"}, "cnpj_fmt": {"cnpj"}, "cnpj_digits": {"cnpj"}, "cnpj_root": {"cnpj"}, "idn": {"domain"},
    "punycode": {"domain"}, "ip": {"ipv4", "ipv6"}, "asn_num": {"asn"},
}
PROPOSED_PLACEHOLDERS = {  # proposed: P125 FC8/FC9 'vetted placeholders'
    "bsky_handle": {"bsky_handle", "username"},  # domain-style handle (contains a dot), atproto syntax
    "bsky_social": {"username"},                  # bare username -> '<user>.bsky.social' (analyst-typed seeds)
    "fedi_user": {"fediverse_handle"},            # '@user@instance' -> 'user' only when instance == link host
}
ALL_PLACEHOLDERS = {**FROZEN_PLACEHOLDERS, **PROPOSED_PLACEHOLDERS}

# ======================================================================================= B. text / HTTP helpers

_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_META_RE = re.compile(r"<meta\b[^>]*>", re.I | re.S)


def as_text(raw) -> str:
    """bytes/str -> str (UTF-8 with replacement); dict/list -> JSON text; anything else -> ''."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (dict, list)):
        try:
            return json.dumps(raw)
        except (TypeError, ValueError):
            return ""
    return ""


def json_body(raw):
    """dict/list as-is; str/bytes parsed as JSON; HTML, plain text, empty or invalid JSON -> None."""
    if isinstance(raw, (dict, list)):
        return raw
    text = as_text(raw).strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def lower_headers(headers) -> dict:
    """dict or list of (name, value) pairs -> {lower-case name: str(value)}; anything else -> {}."""
    out = {}
    items = headers.items() if isinstance(headers, dict) else headers if isinstance(headers, (list, tuple)) else ()
    for item in items:
        try:
            k, v = item
        except (TypeError, ValueError):
            continue
        if isinstance(k, str):
            out[k.strip().lower()] = "" if v is None else str(v)
    return out


def _int_status(status) -> int | None:
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def html_title(body) -> str | None:
    """<title> text (entities unescaped, whitespace collapsed) outside HTML comments, or None."""
    text = _COMMENT_RE.sub("", as_text(body))
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return None
    title = re.sub(r"\s+", " ", _html.unescape(m.group(1))).strip()
    return title or None


def meta_content(body, key) -> str | None:
    """content of <meta property|name=key> outside HTML comments (email-format.com keeps a commented-out
    RocketReach og: block that must not be read as live metadata), or None."""
    if not isinstance(key, str):
        return None
    text = _COMMENT_RE.sub("", as_text(body))
    for m in _META_RE.finditer(text):
        tag = m.group(0)
        k = re.search(r"\b(?:property|name)\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        if not k or k.group(1).strip().lower() != key.lower():
            continue
        c = re.search(r"\bcontent\s*=\s*\"([^\"]*)\"|\bcontent\s*=\s*'([^']*)'", tag, re.I)
        if c:
            return _html.unescape(c.group(1) if c.group(1) is not None else c.group(2)).strip()
    return None


def tlp_level(value) -> int | None:
    """Index of a TLP 2.0 label in TLP_ORDER ('TLP:AMBER+STRICT' -> 3); unknown -> None."""
    if not isinstance(value, str):
        return None
    t = value.strip().lower().replace("tlp:", "").replace(" ", "")
    return TLP_ORDER.index(t) if t in TLP_ORDER else None


def _level_or_amber(value) -> int:
    lvl = tlp_level(value)
    return TLP_ORDER.index("amber") if lvl is None else lvl  # A2 default, fail closed


def _parse_date(value) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip()[:10])
        except ValueError:
            return None
    return None


def _parse_dt(value) -> _dt.datetime | None:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, _dt.date):
        return _dt.datetime(value.year, value.month, value.day, tzinfo=_dt.timezone.utc)
    if isinstance(value, str):
        v = value.strip().replace("Z", "+00:00")
        try:
            d = _dt.datetime.fromisoformat(v)
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)
    return None


# ================================================================================ C. value validators/encoders

_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_CPF_RE = re.compile(r"\d{3}[.\s]?\d{3}[.\s]?\d{3}[-.\s/]?\d{2}")


def _bad_chars(s: str) -> bool:
    """Control, format (RLO, zero-width...), line and paragraph separator characters."""
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in s)


def clean_text(value, max_len: int = 200) -> str | None:
    """NFC, trimmed, single-spaced text; None for non-str, empty, too long or any control/format character
    (newlines included: FC3 hostile values never reach a URL)."""
    if not isinstance(value, str):
        return None
    v = unicodedata.normalize("NFC", value).strip()
    if not v or _bad_chars(v):
        return None
    v = re.sub(r"\s+", " ", v)
    return v if len(v) <= max_len else None


def looks_like_cpf(value) -> bool:
    """Team rule 4 / P311 cond 6: a CPF never appears in a link (formatted or 11 bare digits)."""
    return isinstance(value, str) and bool(_CPF_RE.fullmatch(value.strip()))


def enc_q(value) -> str | None:
    """{q}: every character but unreserved ones percent-encoded (quote(safe='')), so the value can never add a
    path segment, query parameter or fragment. Dot-only values ('.', '..') are refused (dot-segments)."""
    v = clean_text(value)
    if v is None or looks_like_cpf(v) or not v.strip("."):
        return None
    return quote(v, safe="")


def enc_qp(value) -> str | None:
    """{qp}: like {q} with '+' for spaces (query position only)."""
    v = clean_text(value)
    if v is None or looks_like_cpf(v) or not v.strip("."):
        return None
    return quote_plus(v, safe="")


def domain_value(value) -> str | None:
    """{domain}: lower-case ASCII (IDN -> punycode) host name with >= 2 labels and an alphabetic or xn-- TLD;
    internal/reserved suffixes refused. None otherwise (no link). FC3/FC8 of P098."""
    if not isinstance(value, str):
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253 or _bad_chars(v) or any(c.isspace() for c in v):
        return None
    try:
        a = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    labels = a.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.fullmatch(lab) for lab in labels):
        return None
    tld = labels[-1]
    if not (re.fullmatch(r"[a-z]{2,63}", tld) or re.fullmatch(r"xn--[a-z0-9-]{1,59}", tld)):
        return None
    if any(a == s or a.endswith("." + s) for s in INTERNAL_SUFFIXES):
        return None
    return a


def bsky_handle_value(value, etype: str = "bsky_handle") -> str | None:
    """proposed {bsky_handle} (P125 FC8): a domain-style handle (contains a dot) in atproto handle syntax, for
    bsky_handle entities and domain-style usernames only; '@' prefix dropped, lower-cased. Bare usernames and
    DIDs -> None (they would give dead links)."""
    if etype not in ("bsky_handle", "username") or not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("@"):
        v = v[1:]
    if "." not in v or v.lower().startswith("did:"):
        return None
    d = domain_value(v)
    if d is None or d.rsplit(".", 1)[-1] in ATPROTO_DISALLOWED_TLDS:
        return None
    return d


def bsky_social_value(value, etype: str = "username") -> str | None:
    """proposed {bsky_social} (P125 FC8): a bare username -> '<user>.bsky.social' when it fits the bsky.social
    handle rule (3-18 of [a-z0-9-], no leading/trailing hyphen). Only for username entities; the pack entry is
    privacy=true, so it renders only for analyst-typed seeds."""
    if etype != "username" or not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("@"):
        v = v[1:]
    v = v.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,16}[a-z0-9]", v):
        return None
    return v + ".bsky.social"


def parse_fediverse_handle(value):
    """'@user@instance' | 'user@instance' | 'acct:user@instance' -> (user, instance_host) or None.
    The instance is validated as a domain (lower-case, punycode)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.lower().startswith("acct:"):
        v = v[5:]
    if v.startswith("@"):
        v = v[1:]
    if v.count("@") != 1:
        return None
    user, inst = v.split("@")
    if not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?", user):
        return None
    host = domain_value(inst)
    return (user, host) if host else None


def fedi_user_value(value, host) -> str | None:
    """proposed {fedi_user} (P125 FC9): the user part of a full fediverse handle, only when the handle's
    instance equals the link's declared host (an allow-listed instance) and the user fits Mastodon's local
    username rule ([A-Za-z0-9_]{1,30}). Any other instance -> None: unknown operators never get usernames."""
    p = parse_fediverse_handle(value)
    if not p or not isinstance(host, str):
        return None
    user, inst = p
    if inst != host.strip().lower():
        return None
    return user if re.fullmatch(r"[A-Za-z0-9_]{1,30}", user) else None


_NAME_FORBIDDEN_RE = re.compile(r"[0-9@/\\?#&=:;<>\"{}\[\]|_*+$%^~`!(),]")


def person_name_value(value) -> str | None:
    """P257 FC2/FC6: a person name with >= 2 alphabetic tokens (Webmii asks for 'first name and last name');
    letters, spaces, apostrophes, hyphens and dots only. Digits (CPF, phones), '@' (e-mails), URL and markup
    characters, newlines and control characters -> None (no link)."""
    v = clean_text(value, max_len=100)
    if v is None or _NAME_FORBIDDEN_RE.search(v):
        return None
    tokens = [t for t in v.split(" ") if t]
    if len(tokens) < 2 or not all(any(ch.isalpha() for ch in t) for t in tokens):
        return None
    return v


def type_value(etype, value) -> str | None:
    """Type-level normalisation before an encoder (core: entities normaliser + P311 eligibility)."""
    if etype == "cpf" or looks_like_cpf(value):
        return None
    if etype == "domain":
        return domain_value(value)
    if etype == "person_name":
        return person_name_value(value)
    return clean_text(value)


# ============================================================================== D. template rendering (FC3)

def placeholder_value(name, etype, value, host=None) -> str | None:
    """Encoded string for one placeholder, or None when the placeholder is unknown, does not accept the entity
    type or refuses the value. Only the placeholders this batch uses are implemented (core implements the rest)."""
    allowed = ALL_PLACEHOLDERS.get(name, False)
    if allowed is False or (allowed is not None and etype not in allowed):
        return None
    if name in ("q", "qp"):
        v = type_value(etype, value)
        if v is None:
            return None
        return enc_q(v) if name == "q" else enc_qp(v)
    if name in ("domain", "punycode"):
        return domain_value(value)
    if name == "bsky_handle":
        return bsky_handle_value(value, etype)
    if name == "bsky_social":
        return bsky_social_value(value, etype)
    if name == "fedi_user":
        return fedi_user_value(value, host)
    return None


def render_template(template, etype, value, host=None) -> str | None:
    """Whitelist substitution with re.sub (never str.format). None when any placeholder is unknown or refuses
    the value, so a link renders completely or not at all."""
    if not isinstance(template, str):
        return None
    failed = []

    def sub(m):
        out = placeholder_value(m.group(1), etype, value, host)
        if out is None:
            failed.append(m.group(1))
            return ""
        return out

    url = PLACEHOLDER_RE.sub(sub, template)
    return None if failed else url


def _netloc_problem(parts) -> bool:
    return bool(parts.username or parts.password or parts.port is not None) if parts else True


def template_problems(template, host, entity_types) -> list:
    """Load-time checks (core: links.validate_template): https, fixed host == declared host, no userinfo/port,
    known type-compatible placeholders only in path/query/fragment, never {raw}, no stray braces."""
    if not isinstance(template, str) or not template:
        return ["template missing"]
    problems = []
    probe = PLACEHOLDER_RE.sub("V", template)
    try:
        parts = urlsplit(probe)
        port_bad = _netloc_problem(parts)
    except ValueError:
        return ["unparseable template"]
    if parts.scheme != "https":
        problems.append("not https")
    if port_bad:
        problems.append("userinfo or port in template")
    if (parts.hostname or "") != host:
        problems.append(f"host {parts.hostname!r} != declared {host!r}")
    netloc_end = template.find("/", len("https://")) if template.startswith("https://") else -1
    if netloc_end == -1 or PLACEHOLDER_RE.search(template[:netloc_end]):
        problems.append("placeholder in scheme/host position")
    rest = PLACEHOLDER_RE.sub("", template)
    if "{" in rest or "}" in rest:
        problems.append("stray brace: only {name} placeholders are allowed (never str.format fields)")
    names = PLACEHOLDER_RE.findall(template)
    if not names:
        problems.append("no placeholder")
    for name in names:
        if name == "raw":
            problems.append("{raw} is not allowed in URL position (FC3)")
        elif name not in ALL_PLACEHOLDERS:
            problems.append(f"unknown placeholder {{{name}}}")
        else:
            allowed = ALL_PLACEHOLDERS[name]
            bad = [t for t in (entity_types or []) if allowed is not None and t not in allowed]
            if bad:
                problems.append(f"{{{name}}} does not accept {bad}")
    return problems


def check_rendered_url(url, template, host) -> list:
    """FC3 invariants for one rendered URL: https on exactly the declared host, no userinfo/port, no whitespace
    or control character, no dot-segment, same path-segment count and query keys as the template, template
    literals unchanged (the value never adds segments or parameters)."""
    if not isinstance(url, str) or not isinstance(template, str):
        return ["not rendered"]
    problems = []
    if any(c.isspace() or unicodedata.category(c) in ("Cc", "Cf") for c in url):
        problems.append("whitespace/control character in URL")
    try:
        parts = urlsplit(url)
        bad_netloc = _netloc_problem(parts)
    except ValueError:
        return problems + ["unparseable URL"]
    if parts.scheme != "https":
        problems.append("not https")
    if (parts.hostname or "") != host or bad_netloc:
        problems.append("host/userinfo/port changed")
    segs = parts.path.split("/")
    if any(s.lower() in (".", "..", "%2e", "%2e%2e", ".%2e", "%2e.") for s in segs):
        problems.append("dot-segment in path")
    tparts = urlsplit(PLACEHOLDER_RE.sub("V", template))
    if len(segs) != len(tparts.path.split("/")):
        problems.append("path segment count changed")
    if [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)] != \
            [k for k, _ in parse_qsl(tparts.query, keep_blank_values=True)]:
        problems.append("query parameters changed")
    if parts.fragment != tparts.fragment and "{" not in (template.split("#", 1)[1] if "#" in template else ""):
        problems.append("fragment changed")
    pos = 0
    for lit in [p for p in PLACEHOLDER_RE.split(template)[::2] if p]:
        j = url.find(lit, pos)
        if j < 0:
            problems.append("template literal lost")
            break
        pos = j + len(lit)
    return problems


def render_link(link, etype, value) -> str | None:
    """URL for one entity, or None (wrong type, value refused by its placeholder)."""
    if not isinstance(link, dict) or etype not in (link.get("entity_types") or []):
        return None
    return render_template(link.get("template"), etype, value, link.get("host"))


# ======================================================================================== E. pack lint

def lint_link(link, *, pack: str, host_tiers: dict) -> list:
    """Problems of one pack entry ([] = passes): the frozen lint where the contract states it, plus this
    batch's final conditions (P098 FC4/FC8/FC9, P125 FC8-FC10, P257 FC1-FC4)."""
    if not isinstance(link, dict):
        return ["entry is not an object"]
    lid = link.get("id", "?")
    p = [f"{lid}: missing {k}" for k in REQUIRED_LINK_KEYS if k not in link]
    p += [f"{lid}: unknown key {k}" for k in link if k not in FROZEN_LINK_KEYS and k not in EXTENSION_LINK_KEYS]
    if p:
        return p
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", str(lid)):
        p.append(f"{lid}: bad id")
    for k in ("verified", "privacy", "publishes", "touches_target", "login_required", "antibot"):
        if not isinstance(link[k], bool):
            p.append(f"{lid}: {k} must be a boolean")
    if link["publishes"] is not False:
        p.append(f"{lid}: publishes must be false (rule 7)")
    if link["login_required"] is not False:
        p.append(f"{lid}: login_required must be false (P311 lint drops login pages)")
    if link["category"] not in LINK_CATEGORIES:
        p.append(f"{lid}: bad category")
    if not isinstance(link["label"], str) or not link["label"].strip():
        p.append(f"{lid}: empty label")
    et = link["entity_types"]
    if not isinstance(et, list) or not et or not all(isinstance(t, str) for t in et):
        return p + [f"{lid}: entity_types must be a non-empty list of strings"]
    unknown = [t for t in et if t not in KNOWN_TYPES]
    if unknown:
        p.append(f"{lid}: unknown entity types {unknown}")
    if "cpf" in et:
        p.append(f"{lid}: no template ever takes a CPF (rule 4)")
    if link["verified"] and _parse_date(link["checked_at"]) is None:
        p.append(f"{lid}: verified link without a real checked_at date (FC7)")
    host = link["host"] if isinstance(link["host"], str) else ""
    p += [f"{lid}: {x}" for x in template_problems(link["template"], host, et)]
    tier = host_tiers.get(host) if isinstance(host_tiers, dict) else None
    tier = tier if tier in TIERS else "unknown"
    personal = [t for t in et if t in PERSONAL_TYPES or t in COMPANY_ID_TYPES]
    if personal and not link["privacy"]:
        p.append(f"{lid}: {personal} need privacy=true (P311 cond 6)")
    if personal and tier == "unknown":
        p.append(f"{lid}: personal/CNPJ values to an unknown-tier host (A8 BR4)")
    if tier == "unknown" and any(t not in IOC_TYPES for t in et):
        p.append(f"{lid}: unknown-tier host takes IOC_TYPES only (A8 BR4)")
    mt = link.get("max_tlp")
    if mt is not None and tlp_level(mt) is None:
        p.append(f"{lid}: bad max_tlp")
    tpl = link["template"] if isinstance(link["template"], str) else ""
    path = urlsplit(PLACEHOLDER_RE.sub("V", tpl)).path if tpl else ""
    label = link["label"] if isinstance(link["label"], str) else ""
    if pack == "email":
        if host != "www.email-format.com":
            p.append(f"{lid}: email-format.com links use the www host (apex answers 301)")
        if et != ["domain"]:
            p.append(f"{lid}: email-format.com takes domain entities only (P098 FC8; company_name via its domain)")
        if not re.fullmatch(r"https://www\.email-format\.com/d/\{domain\}/", tpl):
            p.append(f"{lid}: template must be https://www.email-format.com/d/{{domain}}/ (P098 FC8)")
        if EMAIL_PATTERN_LABEL not in label:
            p.append(f"{lid}: label must carry '{EMAIL_PATTERN_LABEL}' (P098 FC9)")
        if re.search(r"/m/export|/i/search|/i/account", path):
            p.append(f"{lid}: export/search/account pages expose or query people (P098 FC9)")
    elif pack == "username_social":
        if not link["privacy"]:
            p.append(f"{lid}: social profile links are privacy=true (P125 FC10)")
        if SAME_HANDLE_LABEL not in label:
            p.append(f"{lid}: label must carry '{SAME_HANDLE_LABEL}' (P125 FC10)")
        if host == "bsky.app":
            if not re.fullmatch(r"https://bsky\.app/profile/\{(bsky_handle|bsky_social)\}", tpl):
                p.append(f"{lid}: Bluesky takes {{bsky_handle}} or {{bsky_social}} only, never a raw username "
                         "(P125 FC8)")
            if "{bsky_social}" in tpl and et != ["username"]:
                p.append(f"{lid}: the .bsky.social form is for username seeds only (P125 FC8)")
            if set(et) - {"bsky_handle", "username"}:
                p.append(f"{lid}: Bluesky takes bsky_handle/username only (P125 FC8)")
        else:
            if not re.fullmatch(r"https://" + re.escape(host) + r"/@\{fedi_user\}", tpl):
                p.append(f"{lid}: fediverse links are https://<instance>/@{{fedi_user}} (P125 FC9)")
            if et != ["fediverse_handle"]:
                p.append(f"{lid}: fediverse links take full fediverse handles only (P125 FC9)")
            if tier not in ("trusted", "community"):
                p.append(f"{lid}: instance {host!r} is not a trusted/community registry host (P125 FC9, A8)")
    elif pack == "person":
        if et != ["person_name"]:
            p.append(f"{lid}: person pack takes person_name only (P257 FC2)")
        if not link["privacy"]:
            p.append(f"{lid}: person links are privacy=true (P257 FC2)")
        if link.get("max_tlp") != "clear":
            p.append(f"{lid}: person links need max_tlp=clear (P257 FC3)")
        if PEOPLE_SEARCH_LABEL not in label:
            p.append(f"{lid}: label must carry '{PEOPLE_SEARCH_LABEL}' (P257 FC2)")
        if tier not in ("trusted", "community"):
            p.append(f"{lid}: {host!r} must be a community/trusted registry host before it ships (P257 FC4)")
    return p


def lint_pack(data, *, host_tiers: dict) -> list:
    """Problems of a whole pack ([] = passes): schema id, pack name, links list, unique ids."""
    if not isinstance(data, dict):
        return ["pack is not an object"]
    p = []
    if data.get("schema") != PACK_SCHEMA:
        p.append("schema must be " + PACK_SCHEMA)
    pack = data.get("pack")
    if not isinstance(pack, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", pack):
        p.append("bad pack name")
    links = data.get("links")
    if not isinstance(links, list) or not links:
        return p + ["links must be a non-empty list"]
    ids = [lk.get("id") for lk in links if isinstance(lk, dict)]
    if len(ids) != len(set(ids)):
        p.append("duplicate link ids")
    for lk in links:
        p += lint_link(lk, pack=pack if isinstance(pack, str) else "", host_tiers=host_tiers)
    return p


def breach_pack_problems(packs) -> list:
    """P144 FC1: no entity template on keyword (or any type) points to haveibeenpwned.com; the breach link
    comes only from the breach modules' output."""
    out = []
    for pack in packs or []:
        if not isinstance(pack, dict):
            continue
        for lk in pack.get("links") or []:
            if isinstance(lk, dict) and str(lk.get("host", "")).lower() == HIBP_HOST:
                out.append(f"{pack.get('pack')}:{lk.get('id')}: HIBP breach links are emitted by the breach "
                           "modules, never as an entity template (P144 FC1)")
    return out


# ======================================================================= F. link view, ordering, doctor, dedupe

def _defang(url: str) -> str:
    return url.replace("https://", "hxxps://", 1).replace(".", "[.]", 1)


def link_view(link, etype, value, *, tlp="amber", provenance="seed", privacy_opt_in=False, purpose="",
              host_tier=None, pack_enabled=True, hostile=False, expanded=False, display=None, url=None) -> dict:
    """How one link is shown (FC2 of every pack; P311 conds 5-8; A2; A8; P257 FC2/FC3/FC5).
    provenance: 'seed' (analyst-typed) | 'pivot' (any depth, QSA partners included) | 'extracted' (text/files).
    where: 'report' | 'links_only' (hidden from reports, listed by `v3lum links` with the warning) |
    'collapsed' (touches_target, shown only when expanded) | 'hidden'. Clickable only at CLEAR/GREEN; at AMBER+
    the text is non-clickable with 'opening sends <value> to <host>'. Links are never auto-opened."""
    view = {"ref": link.get("id") if isinstance(link, dict) else None, "label": None, "host": None,
            "category": None, "verified": False, "url": None, "where": "hidden", "clickable": False, "text": "",
            "disclosure": "", "badges": [], "warnings": [], "reason": ""}
    if not isinstance(link, dict):
        view["reason"] = "not_applicable"
        return view
    view.update(label=link.get("label"), host=link.get("host"), category=link.get("category"),
                verified=bool(link.get("verified")))
    if not pack_enabled:
        view["reason"] = "pack_disabled"  # P257 FC5: person pack hidden unless person_name modules are enabled
        return view
    url = url or render_link(link, etype, value)
    if not url:
        view["reason"] = "not_applicable"
        return view
    tier = host_tier if host_tier in TIERS else "unknown"
    if tier == "unknown" and etype not in IOC_TYPES:
        view["reason"] = "tier"  # A8 BR4: unknown operators never receive personal or free-text values
        return view
    if link.get("privacy"):
        if provenance != "seed":
            view["reason"] = "privacy_not_seed"  # QSA partners, names from text/documents, pivots
            return view
        if not privacy_opt_in or not str(purpose or "").strip():
            view["reason"] = "privacy_opt_in"
            return view
    level = _level_or_amber(tlp)
    shown = display if display is not None else str(value)
    view["url"] = url
    view["disclosure"] = f"opening sends {shown} to {link.get('host')}"
    if not link.get("verified"):
        view["badges"].append(BADGE_UNVERIFIED)
    if tier == "unknown":
        view["badges"].append(BADGE_UNKNOWN_OPERATOR)
    if link.get("privacy"):
        view["badges"].append(BADGE_PRIVACY)
    where = "report"
    if level >= TLP_ORDER.index("red"):
        where = "links_only"
        view["reason"] = "tlp_red"
        view["warnings"].append("TLP:RED: third-party link hidden from reports, listed only by `v3lum links`")
    elif link.get("max_tlp") is not None and level > (tlp_level(link["max_tlp"]) or 0):
        where = "links_only"
        view["reason"] = "max_tlp"
        view["warnings"].append(f"case TLP above this link's max_tlp ({link['max_tlp']}): listed only by "
                                "`v3lum links`")
    if link.get("touches_target"):
        view["warnings"].append("opening contacts the target or makes a third party fetch it")
        if where == "report" and (hostile or level >= TLP_ORDER.index("amber")) and not expanded:
            where = "collapsed"
            view["reason"] = "touches_target"
    view["where"] = where
    view["clickable"] = where == "report" and level <= TLP_ORDER.index("green") and not link.get("touches_target")
    view["text"] = url if view["clickable"] else f"{_defang(url)} ({view['disclosure']})"
    return view


def open_decision(view, tlp, *, tty: bool, confirmed_host: str | None = None) -> str:
    """`v3lum links --open` (A2): never auto-opened; at AMBER+ an interactive confirmation naming the host is
    required and a non-TTY refuses. Returns 'open' | 'ask' | 'refuse'."""
    if not isinstance(view, dict) or not view.get("url"):
        return "refuse"
    if _level_or_amber(tlp) <= TLP_ORDER.index("green"):
        return "open"
    if not tty:
        return "refuse"
    return "open" if confirmed_host and confirmed_host == view.get("host") else "ask"


def order_views(views, *, max_terminal: int = TERMINAL_MAX_LINKS):
    """FC6: group by analyst question (category order), verified first, then the pack's file order (the order
    of `views`); the terminal shows at most 8 per seed, the rest go to HTML and `v3lum links`."""
    cat = {c: n for n, c in enumerate(LINK_CATEGORIES)}
    shown = [(i, v) for i, v in enumerate(views or []) if isinstance(v, dict) and v.get("where") == "report"]
    shown.sort(key=lambda iv: (cat.get(iv[1].get("category"), len(cat)), not iv[1].get("verified"), iv[0]))
    ordered = [v for _, v in shown]
    return ordered[:max_terminal], ordered[max_terminal:]


def doctor_links(packs, today, *, max_age_days: int = RECHECK_MAX_AGE_DAYS) -> list:
    """FC7 `v3lum doctor --links` (offline): unverified links and links not re-checked for more than
    max_age_days. Returns [{'ref', 'reason', 'age_days'}]."""
    out = []
    today = _parse_date(today)
    if today is None:
        return out
    for pack in packs or []:
        if not isinstance(pack, dict):
            continue
        for lk in pack.get("links") or []:
            if not isinstance(lk, dict):
                continue
            ref = f"{pack.get('pack')}:{lk.get('id')}"
            if not lk.get("verified"):
                out.append({"ref": ref, "reason": "unverified", "age_days": None})
                continue
            checked = _parse_date(lk.get("checked_at"))
            if checked is None:
                out.append({"ref": ref, "reason": "bad checked_at", "age_days": None})
                continue
            age = (today - checked).days
            if age > max_age_days:
                out.append({"ref": ref, "reason": f"not re-checked for {age} days", "age_days": age})
    return out


def profile_key(url):
    """P125 FC10: comparable key of a social profile URL (case-insensitive handle: bsky.app/profile/BSKY.APP and
    mastodon.social/@mastodon answered the same page live). ('bsky.app', handle) | (host, user) | (host, path)."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    path = unquote(parts.path)
    m = re.fullmatch(r"/profile/([^/]+)/?", path) if host == "bsky.app" else None
    if m:
        h = m.group(1).lower()
        return ("bsky.app", h[1:] if h.startswith("@") else h)
    m = re.fullmatch(r"/(?:@|users/)([A-Za-z0-9_]{1,30})/?", path)
    if m:
        return (host, m.group(1).lower())
    return (host, path.rstrip("/").lower())


def skip_already_linked(views, existing_profile_urls) -> list:
    """P125 FC10: drop pivot-link views whose profile username_check (P113) already linked as FOUND. The
    dropped views stay in the output with where='hidden' and reason='username_check' for coverage."""
    existing = {profile_key(u) for u in existing_profile_urls or [] if profile_key(u)}
    out = []
    for v in views or []:
        if isinstance(v, dict) and v.get("url") and profile_key(v["url"]) in existing:
            v = dict(v, where="hidden", clickable=False, reason="username_check")
        out.append(v)
    return out


# ============================================================================ G. P098 company -> domain

def email_link_domains(etype, value, related_domains=()) -> list:
    """P098 FC8: the email-format.com link renders for domain entities, and for a company_name only through its
    known domain(s) (graph relation or org_profile). Returns the validated, de-duplicated domains to render."""
    if etype == "domain":
        d = domain_value(value)
        return [d] if d else []
    if etype != "company_name":
        return []
    out = []
    for d in related_domains or ():
        v = domain_value(d)
        if v and v not in out:
            out.append(v)
    return out


# ============================================================================== H. P144 HIBP breach link

def hibp_names(obj) -> list:
    """Breach names (the 'Name' field) from any HIBP response: one breach object (/breach/{name},
    /latestbreach), a list (/breaches, /breaches?domain=, /breachedaccount truncated or full). Other shapes,
    HTML, error text -> []."""
    data = json_body(obj)
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    out = []
    for it in items:
        if isinstance(it, dict) and isinstance(it.get("Name"), str) and it["Name"].strip():
            name = it["Name"].strip()
            if name not in out:
                out.append(name)
    return out


def hibp_catalog_index(obj) -> dict:
    """{casefolded Name: Name} from the /breaches catalogue (P144 FC2 exact case-insensitive match)."""
    return {n.casefold(): n for n in hibp_names(obj)}


def hibp_catalog_facts(obj) -> list:
    """Per-breach metadata the report shows next to the link: Name, Title, Domain, BreachDate and the flags
    that change how a breach is read (IsVerified, IsFabricated, IsSensitive, IsRetired, IsSpamList,
    IsMalware, IsStealerLog). No PwnCount-based scoring here; descriptions stay out (HTML)."""
    data = json_body(obj)
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    out = []
    for it in items:
        if not isinstance(it, dict) or not isinstance(it.get("Name"), str):
            continue
        row = {"name": it["Name"].strip(), "title": it.get("Title") if isinstance(it.get("Title"), str) else None,
               "domain": it.get("Domain") if isinstance(it.get("Domain"), str) and it.get("Domain") else None,
               "breach_date": it.get("BreachDate") if isinstance(it.get("BreachDate"), str) else None}
        for k in ("IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware",
                  "IsStealerLog"):
            row[k] = it.get(k) if isinstance(it.get(k), bool) else None
        out.append(row)
    return out


def hibp_breach_url(name) -> str | None:
    """https://haveibeenpwned.com/breach/<Name> with the name through the P311 {q} encoder (quote, safe='').
    None for names that are empty, too long, carry control characters/newlines, an '@' (never an investigated
    e-mail, FC3) or look like a CPF."""
    v = clean_text(name, max_len=100)
    if v is None or "@" in v or looks_like_cpf(v):
        return None
    return render_template(HIBP_BREACH_TEMPLATE, "keyword", v, HIBP_HOST)


def hibp_link_for(name, *, from_hibp: bool = False, catalog_index=None) -> dict | None:
    """P144 FC1-FC4: the link a breach module puts next to a breach name.
    from_hibp=True: the name came from an HIBP response's Name field and is used as-is.
    from_hibp=False (another provider's breach name): only an exact case-insensitive match with an HIBP Name
    already in the case (catalog_index from hibp_catalog_index) gets a link, with HIBP's spelling; otherwise
    None, so no dead links. The link carries the breach name only (metadata, rule 3)."""
    if not isinstance(name, str):
        return None
    if from_hibp:
        canonical = name.strip()
    else:
        idx = catalog_index if isinstance(catalog_index, dict) else {}
        canonical = idx.get(name.strip().casefold())
    if not canonical:
        return None
    url = hibp_breach_url(canonical)
    if not url:
        return None
    return {"name": canonical, "url": url, "host": HIBP_HOST, "attribution": HIBP_ATTRIBUTION,
            "licence": "CC BY 4.0", "label": f"{canonical} on Have I Been Pwned (breach details)"}


# ================================================================== I. maintainer re-check classifiers (FC7)

def challenge_marker(status, headers, body) -> str | None:
    """Strong bot-wall markers only (P321): Cloudflare managed challenge (cf-mitigated header, 'Just a moment'
    / 'Attention Required' titles, _cf_chl_opt). Weak captcha words count only on 403/429/503 (P321 cond 3):
    email-format.com pages carry a reCAPTCHA domain-removal form and HIBP pages load Cloudflare's
    /cdn-cgi/challenge-platform/scripts/precursor beacon on normal 200 answers; neither is a challenge."""
    h = lower_headers(headers)
    st = _int_status(status)
    text = as_text(body)
    if h.get("cf-mitigated", "").lower() == "challenge":
        return "cloudflare_challenge"
    title = (html_title(text) or "").lower()
    if title.startswith("just a moment") or title.startswith("attention required"):
        return "cloudflare_challenge"
    if "window._cf_chl_opt" in text or "/cdn-cgi/challenge-platform/h/" in text:
        return "cloudflare_challenge"
    if st in (403, 429, 503) and re.search(r"(?i)captcha|verify you are human|unusual traffic", text):
        return "captcha"
    return None


def rate_limit_marker(status, headers, body) -> str | None:
    """'quota_text' (e.g. Marginalia's 429 'Daily Limit Exceeded') | 'http_429' | 'retry_after' | None.
    Text markers count only on error statuses (a normal page may mention 'too many requests')."""
    st = _int_status(status)
    head = as_text(body)[:2000].lower()
    if (st is None or st >= 400) and ("daily limit exceeded" in head or "quota exceeded" in head):
        return "quota_text"
    if st == 429:
        return "http_429"
    if st in (503, 509) and "retry-after" in lower_headers(headers):
        return "retry_after"
    return None


def classify_check(kind, status, headers, body, value: str = "") -> dict:
    """Classify a page a maintainer re-checked (never fetched by V3LUM at runtime) for the verified/checked_at
    evidence (FC7). kind: 'email_format' | 'bsky_profile' | 'mastodon_profile' | 'hibp_breach_page' |
    'webmii_people'. Returns {'state': ok|not_found|gone|redirect|challenge|rate_limited|mismatch|error,
    'detail': str}."""
    st = _int_status(status)
    h = lower_headers(headers)
    text = as_text(body)
    title = html_title(text) or ""
    marker = challenge_marker(st, h, text)
    if marker:
        return {"state": "challenge", "detail": marker}
    rl = rate_limit_marker(st, h, text)
    if rl:
        return {"state": "rate_limited", "detail": rl}
    v = value.strip() if isinstance(value, str) else ""
    if kind == "email_format":
        loc = h.get("location", "")
        if st in (301, 302, 303, 307, 308):
            if loc.rstrip("/").endswith("/i/main"):
                return {"state": "not_found", "detail": "redirect to /i/main/ (domain unknown to email-format)"}
            return {"state": "redirect", "detail": loc}
        if st == 200:
            if title.lower().startswith(f"email address format for {v.lower()}") and v:
                return {"state": "ok", "detail": title}
            return {"state": "mismatch", "detail": title}
    elif kind == "bsky_profile":
        if st == 200:
            og = meta_content(text, "og:title")
            handle = v.lstrip("@").lower()
            if og and title.lower() == f"@{handle} on bluesky":
                return {"state": "ok", "detail": title}
            if not og and title == "Bluesky":
                return {"state": "not_found", "detail": "app shell without profile metadata (soft 404)"}
            return {"state": "mismatch", "detail": title}
    elif kind == "mastodon_profile":
        if st == 200:
            p = parse_fediverse_handle(v)
            if p and f"(@{p[0].lower()}@{p[1]})" in title.lower():
                return {"state": "ok", "detail": title}
            return {"state": "mismatch", "detail": title}
        if st == 404:
            return {"state": "not_found", "detail": title or "404"}
        if st == 410:
            return {"state": "gone", "detail": title or "410 (account deleted or suspended)"}
    elif kind == "hibp_breach_page":
        if st == 200 and title.lower() == f"have i been pwned: {v.lower()} data breach" and v:
            return {"state": "ok", "detail": title}
        if st == 404:
            return {"state": "not_found", "detail": title or "404"}
        if st == 200:
            return {"state": "mismatch", "detail": title}
    elif kind == "webmii_people":
        if st == 200:
            if v and title.lower() == f"webmii - {v.lower()}":
                return {"state": "ok", "detail": title + " (results load client-side)"}
            return {"state": "mismatch", "detail": title}
    else:
        return {"state": "error", "detail": f"unknown kind {kind!r}"}
    if st is not None and st >= 500:
        return {"state": "error", "detail": f"HTTP {st}"}
    return {"state": "error", "detail": f"unexpected HTTP {st}"}


# ===================================================================================== J. P307 web search

PROVIDERS = {  # P307 FC2-FC5 (tiers FC5; classes FC2-FC4; reuses_queries for the A2 gate: reviewer to confirm)
    "brave": {"host": "api.search.brave.com", "key_env": "V3LUM_BRAVE_KEY", "auth_header": "X-Subscription-Token",
              "tier": "trusted", "terms_class": "key-terms", "reuses_queries": False, "kind": "web"},
    "duckduckgo": {"host": "api.duckduckgo.com", "key_env": None, "auth_header": None, "tier": "trusted",
                   "terms_class": "open", "reuses_queries": False, "kind": "context"},
    "marginalia": {"host": "api2.marginalia-search.com", "key_env": "V3LUM_MARGINALIA_KEY",
                   "auth_header": "API-Key", "tier": "community", "terms_class": "license",
                   "reuses_queries": False, "kind": "web"},
    "tavily": {"host": "api.tavily.com", "key_env": "V3LUM_TAVILY_KEY", "auth_header": "Authorization",
               "tier": "community", "terms_class": "unknown", "reuses_queries": True, "kind": "web"},
    "exa": {"host": "api.exa.ai", "key_env": "V3LUM_EXA_KEY", "auth_header": "x-api-key", "tier": "community",
            "terms_class": "unknown", "reuses_queries": True, "kind": "web"},
}
REFUSED_HOSTS = {  # P307 FC1 (veto_lift 1): no registry entry, never requested
    "serpapi.com": "SerpApi removed (veto_lift 1): resells Google/Bing results obtained with CAPTCHA solving",
}
DEFAULT_CASE_BUDGET = 10  # P307 FC8 setting web_search_case_budget; P289 FC2 <= 10


def refused_host(host) -> str | None:
    """P307 FC1: reason when a host must never be requested (serpapi.com and its subdomains), else None."""
    if not isinstance(host, str):
        return None
    h = host.strip().lower().rstrip(".")
    for bad, reason in REFUSED_HOSTS.items():
        if h == bad or h.endswith("." + bad):
            return reason
    return None


def provider_gate(pid, *, tlp="amber", key_present=False, business_plan=False, licence_cleared=False,
                  legal_terms_recorded=False) -> dict:
    """P307 FC2-FC5 and FC8 per-provider sub-source gate -> {'run', 'status', 'reason'}; status is one of
    ok | needs_key | licence | unknown_terms | tlp | policy (each provider gets its own coverage row, FC5).
    business_plan: Brave key plan recorded as business-compatible in key_plans (FC2);
    licence_cleared: Marginalia commercial key plan or licence_allow entry (FC3);
    legal_terms_recorded: company-account key and terms recorded by legal for Tavily/Exa (FC4)."""
    p = PROVIDERS.get(pid)
    if p is None:
        return {"run": False, "status": "policy", "reason": "no provider-registry entry (SerpApi and SERP "
                                                            "scrapers are refused, FC1)"}
    level = _level_or_amber(tlp)
    if level >= TLP_ORDER.index("red"):
        return {"run": False, "status": "tlp", "reason": "TLP:RED: queries never leave the premises"}
    if level >= TLP_ORDER.index("amber") and p["reuses_queries"]:
        return {"run": False, "status": "tlp", "reason": "provider flagged reuses_queries: excluded at AMBER+"}
    if level >= TLP_ORDER.index("amber+strict") and p["tier"] != "trusted":
        return {"run": False, "status": "tlp", "reason": "AMBER+STRICT: trusted providers only"}
    if pid == "duckduckgo":
        return {"run": True, "status": "ok", "reason": "keyless Instant Answer (context only, attribution)"}
    if p["terms_class"] == "unknown" and not legal_terms_recorded:
        return {"run": False, "status": "unknown_terms",
                "reason": "class 'unknown' until a company-account key and terms are recorded by legal (FC4)"}
    if not key_present:
        return {"run": False, "status": "needs_key", "reason": f"set {p['key_env']}"}
    if pid == "brave" and not business_plan:
        return {"run": False, "status": "licence", "reason": "Brave key plan not recorded as business-compatible "
                                                            "in key_plans (FC2)"}
    if pid == "marginalia" and not licence_cleared:
        return {"run": False, "status": "licence", "reason": "Marginalia free keys are CC BY-NC-SA 4.0: needs a "
                                                            "commercial key plan or licence_allow entry (FC3)"}
    return {"run": True, "status": "ok", "reason": ""}


def x402_offer(status, headers, body) -> str | None:
    """P307 FC4: HTTP 402 or an x402 pay-per-call offer -> a short reason (the module maps it to NEEDS_KEY;
    no payment code path exists). None otherwise."""
    st = _int_status(status)
    h = lower_headers(headers)
    obj = json_body(body)
    if isinstance(obj, dict):
        accepts = obj.get("accepts")
        if obj.get("x402Version") is not None or str(obj.get("tag", "")).upper().startswith("X402") or (
                isinstance(accepts, list) and any(isinstance(a, dict) and "payTo" in a for a in accepts)):
            return "x402 pay-per-call offer refused (no autonomous payments): needs a company key"
    if h.get("www-authenticate", "").strip().lower().startswith("payment"):
        return "HTTP Payment challenge refused (no autonomous payments): needs a company key"
    if st == 402:
        return "HTTP 402 payment required: needs a company key"
    return None


def classify_search_response(pid, status, headers, body) -> dict | None:
    """Error-in-status/body classification BEFORE parsing or caching (P321) for the P307 sub-sources.
    None = parse it. Otherwise {'status': needs_key|quota|rate_limited|blocked|error|malformed, 'reason'}."""
    st = _int_status(status)
    h = lower_headers(headers)
    text = as_text(body)
    pay = x402_offer(st, h, body)
    if pay:
        return {"status": "needs_key", "reason": pay}
    obj = json_body(body)
    if pid == "brave":
        err = obj.get("error") if isinstance(obj, dict) and isinstance(obj.get("error"), dict) else {}
        code = str(err.get("code") or "").upper()
        if st == 422 and "x-subscription-token" in text.lower():
            return {"status": "needs_key", "reason": "Brave: X-Subscription-Token missing (422 VALIDATION)"}
        if st in (401, 403) or "TOKEN_INVALID" in code or "SUBSCRIPTION" in code:
            return {"status": "needs_key", "reason": f"Brave: subscription token rejected ({st} {code})".strip()}
        if st == 429 or "RATE_LIMIT" in code or "QUOTA" in code:
            if "QUOTA" in code:
                return {"status": "quota", "reason": "Brave: monthly quota/credits exhausted"}
            return {"status": "rate_limited", "reason": "Brave: rate limited (429)"}
    elif pid == "marginalia":
        if st == 429 or "daily limit exceeded" in text.lower():
            return {"status": "quota", "reason": "Marginalia: Daily Limit Exceeded"}
        if st in (401, 403):
            return {"status": "needs_key", "reason": f"Marginalia: API key rejected ({st})"}
    elif pid == "tavily":
        if st == 401:
            return {"status": "needs_key", "reason": "Tavily: missing or invalid API key (401)"}
        if st in (432, 433):
            return {"status": "quota", "reason": f"Tavily: plan/pay-as-you-go limit ({st})"}
        if st == 429:
            return {"status": "rate_limited", "reason": "Tavily: rate limited (429)"}
    elif pid == "exa":
        if st == 401:
            return {"status": "needs_key", "reason": "Exa: missing or invalid API key (401)"}
        if st == 429:
            return {"status": "rate_limited", "reason": "Exa: rate limited (429)"}
    elif pid == "duckduckgo":
        if st in (403, 418) or challenge_marker(st, h, text):
            return {"status": "blocked", "reason": f"DuckDuckGo: blocked ({st})"}
        if st == 429:
            return {"status": "rate_limited", "reason": "DuckDuckGo: rate limited (429)"}
    if st is not None and st >= 500:
        return {"status": "error", "reason": f"HTTP {st}"}
    if st is not None and st >= 400:
        return {"status": "error", "reason": f"HTTP {st}"}
    if not isinstance(obj, dict):
        return {"status": "malformed", "reason": "body is not a JSON object"}
    return None


def _clean_title(value) -> str | None:
    if not isinstance(value, str):
        return None
    t = re.sub(r"<[^>]+>", "", value)
    return clean_text(_html.unescape(t), max_len=300)


def _http_url(value) -> str | None:
    if not isinstance(value, str):
        return None
    u = value.strip()
    if _bad_chars(u) or any(c.isspace() for c in u):
        return None
    try:
        parts = urlsplit(u)
    except ValueError:
        return None
    return u if parts.scheme in ("http", "https") and parts.hostname else None


def _url_title_rows(items, url_key="url", title_key="title") -> list:
    out, seen = [], set()
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        url = _http_url(it.get(url_key))
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "title": _clean_title(it.get(title_key)), "host": urlsplit(url).hostname})
    return out


def parse_brave_web(obj) -> dict | None:
    """Brave /res/v1/web/search -> {'query', 'more_results', 'results': [{'url', 'title', 'host'}]}.
    P307 FC6: URL + title only; descriptions/snippets, extra_snippets, page_age and thumbnails are never read.
    None for error bodies or non-JSON."""
    data = json_body(obj)
    if not isinstance(data, dict) or data.get("type") == "ErrorResponse" or "error" in data:
        return None
    q = data.get("query") if isinstance(data.get("query"), dict) else {}
    web = data.get("web") if isinstance(data.get("web"), dict) else {}
    return {"query": q.get("original") if isinstance(q.get("original"), str) else None,
            "more_results": bool(q.get("more_results_available")),
            "results": _url_title_rows(web.get("results"))}


def parse_marginalia(obj) -> dict | None:
    """Marginalia api2 /search -> {'license', 'results': [{'url', 'title', 'host'}]} (descriptions dropped)."""
    data = json_body(obj)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None
    lic = data.get("license") if isinstance(data.get("license"), str) else None
    return {"license": lic, "results": _url_title_rows(data["results"])}


def parse_tavily(obj) -> dict | None:
    """Tavily POST /search -> {'results': [{'url', 'title', 'host'}]} (content/raw_content/answer dropped:
    third-party copies of pages)."""
    data = json_body(obj)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None
    return {"results": _url_title_rows(data["results"])}


def parse_exa(obj) -> dict | None:
    """Exa POST /search -> {'results': [{'url', 'title', 'host'}]} (text/highlights/author dropped)."""
    data = json_body(obj)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None
    return {"results": _url_title_rows(data["results"])}


DDG_INFOBOX_KEEP = frozenset({  # organisation/domain context only; personal rows (Founders, Key people, Born,
    "type", "industry", "founded", "headquarters", "website", "official website", "owner", "registry",  # Spouse,
    "sponsor", "tld type", "status", "current status", "launched", "introduced", "traded as",  # social profiles)
    "number of employees", "services", "products", "area served", "parent", "subsidiaries", "available in",  # are
    "intended use", "actual use", "dnssec", "named after", "wikidata id", "wikidata label",  # never kept
    "wikidata description",
})


def parse_ddg(obj) -> dict | None:
    """DuckDuckGo Instant Answer (?format=json&no_html=1&skip_disambig=1) -> context facts (P307 FC2: context
    only, not web search; attribution to DuckDuckGo and the AbstractSource). Infobox rows are allow-listed
    (DDG_INFOBOX_KEEP) so people named in company infoboxes are not ingested. None for non-JSON bodies."""
    data = json_body(obj)
    if not isinstance(data, dict):
        return None

    def s(key):
        v = data.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else None

    infobox = []
    ib = data.get("Infobox")
    for row in (ib.get("content") if isinstance(ib, dict) and isinstance(ib.get("content"), list) else []):
        if not isinstance(row, dict) or not isinstance(row.get("label"), str):
            continue
        label = row["label"].strip()
        val = row.get("value")
        if label.lower() in DDG_INFOBOX_KEEP and isinstance(val, (str, int, float)) and not isinstance(val, bool):
            text = clean_text(str(val), max_len=300)
            if text:
                infobox.append({"label": label, "value": text})

    def topics(items):
        out = []
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("Topics"), list):  # grouped related topics
                out.extend(topics(it["Topics"]))
                continue
            url = _http_url(it.get("FirstURL"))
            text = clean_text(_html.unescape(it.get("Text") or ""), max_len=300) if isinstance(
                it.get("Text"), str) else None
            if url:
                out.append({"url": url, "text": text})
        return out

    facts = {
        "heading": s("Heading"), "abstract": s("AbstractText") or s("Abstract"), "abstract_source": s("AbstractSource"),
        "abstract_url": _http_url(data.get("AbstractURL")), "entity": s("Entity"), "answer": s("Answer"),
        "answer_type": s("AnswerType"), "definition": s("Definition"), "official_domain": s("OfficialDomain"),
        "official_website": _http_url(data.get("OfficialWebsite")), "infobox": infobox,
        "related": topics(data.get("RelatedTopics")), "results": topics(data.get("Results")), "type": s("Type"),
    }
    facts["empty"] = not any(facts[k] for k in ("heading", "abstract", "answer", "definition", "infobox", "related",
                                                "results"))
    src = facts["abstract_source"]
    facts["attribution"] = "Results from DuckDuckGo" + (f" (source: {src})" if src else "")
    return facts


def evidence_records(results, selected_urls=None) -> list:
    """P307 FC6: what the case/evidence may keep: URL + title of the results the analyst selected (all
    results when selected_urls is None, e.g. counts only). Never snippets, never the raw JSON (Brave ttl=0)."""
    keep = None if selected_urls is None else {u for u in selected_urls if isinstance(u, str)}
    out = []
    for r in results or []:
        if isinstance(r, dict) and _http_url(r.get("url")) and (keep is None or r["url"] in keep):
            out.append({"url": r["url"], "title": r.get("title") if isinstance(r.get("title"), str) else None})
    return out


def result_pivots(results) -> list:
    """P307 produces url and domain: [('url', u), ('domain', host)] de-duplicated, hosts lower-case."""
    out, seen = [], set()
    for r in results or []:
        if not isinstance(r, dict):
            continue
        u = _http_url(r.get("url"))
        if not u:
            continue
        for item in (("url", u), ("domain", domain_value(urlsplit(u).hostname or ""))):
            if item[1] and item not in seen:
                seen.add(item)
                out.append(item)
    return out


def brave_rate_headers(headers) -> dict:
    """X-RateLimit-Limit/Remaining/Reset ('1, 15000' = per-second and per-month windows in Brave's docs; NOT
    observed live: no key) -> {'limit': [...], 'remaining': [...], 'reset': [...], 'month_remaining': int|None}."""
    h = lower_headers(headers)
    out = {}
    for k in ("limit", "remaining", "reset"):
        raw = h.get(f"x-ratelimit-{k}", "")
        vals = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                vals.append(int(part))
        out[k] = vals
    out["month_remaining"] = out["remaining"][-1] if len(out["remaining"]) >= 2 else None
    return out


_SECRET_PARAM_RE = re.compile(r"(?i)\b(api[_-]?key|apikey|access[_-]?token|token|secret|password|passwd|pwd|sig|"
                              r"auth|session|bearer)\s*[=:]")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")
_OPAQUE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-]{32,}(?![A-Za-z0-9])")


def query_problem(query) -> str | None:
    """P307 FC7: a query never carries secrets, tokens or full URLs with query strings (victim identifiers),
    nor a CPF. Also Brave's documented limits (400 chars, 50 words). Returns a reason or None."""
    q = clean_text(query, max_len=400)
    if q is None:
        return "empty, too long (> 400) or control characters"
    if len(q.split(" ")) > 50:
        return "more than 50 words"
    if re.search(r"(?i)\bhttps?://\S*\?\S*=", q):
        return "full URL with a query string"
    if _JWT_RE.search(q):
        return "JWT-like token"
    if _SECRET_PARAM_RE.search(q):
        return "secret-like parameter"
    if _OPAQUE_RE.search(q):
        return "opaque token (>= 32 chars)"
    if _CPF_RE.search(q):
        return "CPF"
    return None


QUERY_TEMPLATES = {"domain": 'site:{v}', "keyword": '{v}', "company_name": '"{v}"', "person_name": '"{v}"',
                   "email": '"{v}"'}


def build_query(etype, value, *, provenance="seed", purpose="", template=None):
    """P307 FC7/FC9: (query, None) or (None, reason). Seed-only by default; person_name and e-mail only for
    analyst-typed subjects in a case with a recorded purpose; built with a whitelist {v} substitution (never
    str.format); '"' is stripped from values so they cannot break out of a phrase."""
    if etype not in QUERY_TEMPLATES:
        return None, f"entity type {etype!r} not accepted"
    if provenance != "seed":
        return None, "seed-only: never automatically from pivots (FC7/FC9)"
    if etype in ("person_name", "email") and not str(purpose or "").strip():
        return None, "person_name/e-mail queries need a recorded case purpose (FC7)"
    if etype == "domain":
        v = domain_value(value)
    elif etype == "person_name":
        v = person_name_value(value)
    else:
        v = clean_text(value, max_len=200)
        v = v.replace('"', "").strip() if v else None
    if not v:
        return None, "value refused"
    tpl = template if isinstance(template, str) and "{v}" in template else QUERY_TEMPLATES[etype]
    q = re.sub(r"\{v\}", lambda _m: v, tpl)
    reason = query_problem(q)
    return (None, reason) if reason else (q, None)


def budget_allows(used, budget=DEFAULT_CASE_BUDGET) -> bool:
    """P307 FC8 / P289 FC2: one more query fits the per-case budget."""
    try:
        return 0 <= int(used) < int(budget)
    except (TypeError, ValueError):
        return False


def budget_line(used, budget=DEFAULT_CASE_BUDGET) -> str:
    """P307 FC8 coverage line, e.g. '3/10 queries used'."""
    try:
        return f"{int(used)}/{int(budget)} queries used"
    except (TypeError, ValueError):
        return f"?/{budget} queries used"


# ============================================================================ K. P289 employee X-ray

XRAY_PROFILE_RE = re.compile(r"https://(?:[a-z]{2,3}\.|www\.)?linkedin\.com/in/[^/?#\s]+/?", re.I)
DEPARTMENTS = (  # P289 FC3: counts by role/department keyword (EN + PT-BR), first match wins
    ("security", r"secur|seguran|ciso\b|\bsoc\b|pentest|infosec|cyber|ciber"),
    ("executive", r"\bceo\b|\bcfo\b|\bcto\b|\bcoo\b|\bcio\b|chief|diretor|director|presiden|\bvp\b|vice[- ]pres|"
                  r"head of|founder|fundador|s[oó]cio|\bpartner\b|superintendent"),
    ("it", r"\bti\b|\bit\b|information technology|tecnologia da informa|sysadmin|infraestrutura|infrastructure|"
           r"suporte|support|network|redes|helpdesk|service desk"),
    ("engineering", r"engineer|engenheir|developer|desenvolvedor|devops|software|programador|arquitet|architect|"
                    r"data scien|cientista de dados|\bqa\b|tester"),
    ("finance", r"financ|contab|contador|accountant|accounting|tesour|treasur|fiscal|controller|controladoria|audit"),
    ("hr", r"\bhr\b|\brh\b|human resources|recursos humanos|recruit|recrut|talent|\bpeople\b|gente e gest"),
    ("legal", r"legal|jur[ií]dic|advogad|lawyer|attorney|compliance|counsel"),
    ("sales", r"sales|vendas|comercial|account executive|business development|key account|executivo de contas"),
    ("marketing", r"marketing|comunica|communication|brand|social media|growth"),
    ("operations", r"operations|opera[çc][õo]es|logist|supply|procurement|compras|facilities"),
    ("customer", r"customer|cliente|atendimento|success"),
)


def _norm_name(value) -> str:
    v = clean_text(value, max_len=200) or ""
    v = unicodedata.normalize("NFKD", v)
    v = "".join(c for c in v if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", " ", v.casefold()).strip()


def _domain_in_scope(domain, scope) -> bool:
    d = domain_value(domain) if domain else None
    targets = scope.get("targets") if isinstance(scope.get("targets"), dict) else {}
    for pat in targets.get("domains") or []:
        if not isinstance(pat, str) or not d:
            continue
        pat = pat.strip().lower()
        if pat.startswith("*.") and (d.endswith(pat[1:])):
            return True
        if d == pat:
            return True
    return False


def xray_gate(company=None, domain=None, *, org_profile=None, scope=None, now=None) -> dict:
    """P289 FC1: run only for the own organisation (verified org_profile entry) or under an --authorized
    engagement whose scope file explicitly sets social_engineering: true and lists the target.
    org_profile (normalised view of core P378): {'names': [...], 'domains': {domain: 'txt_verified' |
    'attested' | 'unverified'}}; scope: parsed scope file (A7) plus the proposed boolean 'social_engineering'
    and optional 'organisations'. -> {'run', 'basis': own_org|engagement|None, 'reason_code', 'reason'}."""
    op = org_profile if isinstance(org_profile, dict) else {}
    doms = op.get("domains") if isinstance(op.get("domains"), dict) else {}
    verified = {domain_value(k) for k, v in doms.items() if v in ("txt_verified", "attested") and domain_value(k)}
    names = {_norm_name(n) for n in op.get("names") or [] if isinstance(n, str) and _norm_name(n)}
    d = domain_value(domain) if domain else None
    if d and d in verified:
        return {"run": True, "basis": "own_org", "reason_code": None, "reason": "verified own domain"}
    if company and verified and _norm_name(company) in names and (d is None or d in verified):
        return {"run": True, "basis": "own_org", "reason_code": None, "reason": "own organisation name"}
    sc = scope if isinstance(scope, dict) else None
    if sc and sc.get("authorization_ref"):
        if sc.get("social_engineering") is not True:
            return {"run": False, "basis": None, "reason_code": "scope",
                    "reason": "scope file does not set social_engineering: true"}
        orgs = {_norm_name(n) for n in sc.get("organisations") or [] if isinstance(n, str)}
        if not (_domain_in_scope(domain, sc) or (company and _norm_name(company) in orgs)):
            return {"run": False, "basis": None, "reason_code": "scope", "reason": "target not in the scope file"}
        start, end = _parse_dt(sc.get("window_start")), _parse_dt(sc.get("window_end"))
        when = _parse_dt(now) or _dt.datetime.now(_dt.timezone.utc)
        if (start and when < start) or (end and when > end):
            return {"run": False, "basis": None, "reason_code": "scope", "reason": "outside the engagement window"}
        return {"run": True, "basis": "engagement", "reason_code": None, "reason": "authorized SE engagement"}
    return {"run": False, "basis": None, "reason_code": "own_asset",
            "reason": "not the verified own organisation and no authorized social-engineering engagement"}


def xray_queries(company, *, budget_left=DEFAULT_CASE_BUDGET, max_queries=2) -> list:
    """P289 FC2: Brave X-ray queries for the company (never more than the remaining case budget, <= 10).
    'site:linkedin.com/in "<company>"' then the br. sub-domain variant; every query passes query_problem."""
    c = clean_text(company, max_len=120)
    if not c:
        return []
    c = c.replace('"', "").strip()
    if not c:
        return []
    try:
        n = max(0, min(int(budget_left), int(max_queries), DEFAULT_CASE_BUDGET))
    except (TypeError, ValueError):
        return []
    out = []
    for tpl in ('site:linkedin.com/in "{v}"', 'site:br.linkedin.com/in "{v}"'):
        q = re.sub(r"\{v\}", lambda _m: c, tpl)
        if query_problem(q) is None:
            out.append(q)
    return out[:n]


def parse_linkedin_title(title) -> dict | None:
    """'Name - Role - Company | LinkedIn' (also en/em dashes, ' | LinkedIn' or ' - LinkedIn' suffix) ->
    {'name', 'role', 'org'}; None when nothing name-like is left."""
    t = _clean_title(title)
    if not t:
        return None
    t = re.sub(r"\s*[|\-–—]\s*LinkedIn\s*$", "", t, flags=re.I)
    parts = [x.strip() for x in re.split(r"\s+[-–—|]\s+", t) if x.strip()]
    if not parts:
        return None
    name = parts[0]
    if not re.search(r"[^\W\d_]", name):
        return None
    # 'Name - Company' is ambiguous (the second part is usually the company): role only with 3+ parts
    role = parts[1] if len(parts) >= 3 else None
    org = parts[2] if len(parts) >= 3 else (parts[1] if len(parts) == 2 else None)
    return {"name": name, "role": role, "org": org}


def department_of(role) -> str:
    """Department bucket of a role string (DEPARTMENTS, first match), 'other' when nothing matches."""
    r = clean_text(role, max_len=300) if isinstance(role, str) else None
    if not r:
        return "other"
    low = r.lower()
    for dept, rx in DEPARTMENTS:
        if re.search(rx, low):
            return dept
    return "other"


def aggregate_xray(results, company, *, max_samples: int = 10) -> dict:
    """P289 FC3/FC4/FC6: aggregate Brave results (parse_brave_web()['results']) into counts by department.
    Only linkedin.com/in profile URLs whose title names the company count. At most 10 sample names (kept in the
    case only); names are never pivots, never auto-checked; no e-mail address is generated."""
    target = _norm_name(company)
    try:
        cap = max(0, min(int(max_samples), 10))
    except (TypeError, ValueError):
        cap = 10
    seen, by_dept, samples = set(), Counter(), []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not isinstance(url, str) or not XRAY_PROFILE_RE.fullmatch(url.strip()):
            continue
        key = url.strip().rstrip("/").lower()
        if key in seen:
            continue
        parsed = parse_linkedin_title(r.get("title"))
        if not parsed or not target or target not in _norm_name(r.get("title") or ""):
            continue
        seen.add(key)
        by_dept[department_of(parsed["role"] or "")] += 1
        if len(samples) < cap and parsed["name"] not in samples:
            samples.append(parsed["name"])
    return {"label": XRAY_LABEL, "company": company if isinstance(company, str) else None,
            "profiles": len(seen), "by_department": dict(sorted(by_dept.items())), "sample_names": samples,
            "pivots": [], "emails": [], "auto_check": False}


def export_view(aggregate, *, include_personal: bool = False) -> dict:
    """P289 FC3: exported reports and STIX/MISP carry counts only; sample names only with --include-personal
    (the caller records that choice in the case audit)."""
    if not isinstance(aggregate, dict):
        return {}
    out = {k: v for k, v in aggregate.items() if k != "sample_names"}
    out["personal_included"] = bool(include_personal)
    if include_personal:
        out["sample_names"] = list(aggregate.get("sample_names") or [])
    return out


def sample_expiry(collected_at, *, retention_days, window_end=None):
    """P289 FC5: the name sample expires at the engagement window end or after retention_days, whichever comes
    first (A10 purge). Returns an aware datetime, or None when collected_at is unparseable."""
    start = _parse_dt(collected_at)
    if start is None:
        return None
    try:
        expiry = start + _dt.timedelta(days=max(0, int(retention_days)))
    except (TypeError, ValueError):
        expiry = start
    end = _parse_dt(window_end)
    return min(expiry, end) if end else expiry
