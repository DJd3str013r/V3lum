"""Reference helpers for batch p3-G14-2: P308 `pivots_search`, the offline pivot-link pack
data/pivot_links/search.json (Lyzem Telegram content search and WikiLeaks search).

Pure functions, standard library only, no V3LUM imports, no network. The module IS a pack (disclosure
'none'): V3LUM never requests these URLs or anything behind them (FC1). The helpers cover two jobs:

1. Pack behaviour the final conditions (FCn = final condition n of P308 in specs/p3-G14-2.md) pin down,
   written as executable reference semantics the implementer mirrors with, or checks against,
   v3lum.core.links / lint:
   - whitelist placeholder encoders and a re.sub renderer, never str.format (FC3);
   - the rendered-URL invariants CI asserts with sample and hostile values (FC3);
   - the pack lint, including the P308-specific rules: A8 tier gate (FC4, FC5, FC9), the WikiLeaks
     type floor (FC8), Lyzem privacy (FC9), analyst-typed seeds and the caution marker (FC10), the
     curated file order (FC6);
   - the A2/P311 view of a link at a TLP (FC2), the 8-link terminal cap and ordering (FC6), the offline
     `doctor --links` staleness list (FC7) and the activation of the Lyzem entries once the registry
     records a community/trusted tier (FC5, FC9).
2. Re-check helpers for maintainers (FC7 checked_at): classify a results page fetched by a person or a
   maintainer script, never by V3LUM at runtime, as ok / empty / mismatch / malformed / error_in_200 /
   not_found / challenge / rate_limited / login_wall / redirect / error, with the markers seen live on
   2026-11-26. They count results only: no Telegram message text and no WikiLeaks document title or
   excerpt is ever extracted (FC8, rule 3: link only, nothing ingested or stored).

Names tagged 'core:' mirror the frozen contract (module_author_contract s.15, schema v3lum.pivot_pack/1).
Names tagged 'proposed:' are additions this pack needs (notes.md section 0).
"""
from __future__ import annotations

import html as _html
import re
import unicodedata
from datetime import date
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

# ----------------------------------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------------------------------

PACK_SCHEMA = "v3lum.pivot_pack/1"  # core: frozen schema id
PACK_NAME = "search"  # FC1: data/pivot_links/search.json
FROZEN_LINK_KEYS = (  # core: module_author_contract s.15 (FC1)
    "id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy",
    "publishes", "touches_target", "login_required", "antibot", "notes",
)
REQUIRED_LINK_KEYS = FROZEN_LINK_KEYS[:-1]  # notes is optional
# proposed: per-link keys this pack needs. seed_only = FC10 (same name as batch p2-G14-1), warning = the
# FC8 banner / FC10 caution text (same name as batch p2-G14-2), max_tlp = P311 optional field (unused here).
EXTENSION_LINK_KEYS = ("seed_only", "warning", "max_tlp")
LINK_CATEGORIES = ("reputation", "history", "passive_dns", "code_paste", "social", "company", "crypto",
                   "geo", "search", "other")  # core: frozen enum, also the group order (P311 cond 10)
TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
TIERS = ("trusted", "community", "unknown")

# A8 canonical type sets (core/entities.py); the P333 structural hashes are omitted here.
PERSONAL_TYPES = frozenset({
    "email", "phone", "username", "person_name", "cpf", "pix_key", "plate_br", "imei", "coordinates",
    "social_account", "telegram_handle", "telegram_invite", "discord_invite", "fediverse_handle",
    "bsky_handle", "steam_profile", "vin", "email_headers",
})
IOC_TYPES = frozenset({
    "domain", "url", "ipv4", "ipv6", "cidr", "asn", "md5", "sha1", "sha256", "sha512", "ssdeep", "cve",
    "mitre_technique", "onion", "btc_address", "eth_address", "xmr_address", "other_crypto_address",
    "favicon_hash", "cert_fingerprint", "analytics_id",
})
COMPANY_ID_TYPES = frozenset({"cnpj"})
FREE_TEXT_TYPES = frozenset({"keyword", "company_name", "person_name", "threat_actor", "malware_family"})

LYZEM_HOST = "lyzem.com"
WIKILEAKS_HOST = "search.wikileaks.org"
PACK_HOSTS = (LYZEM_HOST, WIKILEAKS_HOST)  # FC6: curated file order, Lyzem then WikiLeaks
WIKILEAKS_TYPES = frozenset({"company_name", "keyword"})  # FC8: never person names or usernames
LYZEM_PRE_REVIEW_TYPES = frozenset({"domain", "url"})  # FC9: until the reviewer records community tier
LYZEM_PRIVACY_TYPES = frozenset({"person_name", "username"})  # FC9: privacy=true, analyst-entered subjects
LYZEM_ALLOWED_TYPES = LYZEM_PRE_REVIEW_TYPES | LYZEM_PRIVACY_TYPES | {"keyword", "company_name"}

WIKILEAKS_BANNER = "leaked documents: open manually and handle per policy"  # FC8, verbatim
LYZEM_WARNING = ("Telegram content search: results are third-party channel content and may include fraud, "
                 "illegal or graphic material; open manually and handle per policy")  # FC10 caution text
BADGE_CAUTION = "caution"  # FC10: every link of this pack carries the caution marker
BADGE_UNKNOWN_OPERATOR = "unknown operator"  # core: A8 / P311 cond 7
BADGE_UNVERIFIED = "unverified"  # core: P311 cond 10
BADGE_PRIVACY = "privacy: analyst-typed seed, case opt-in"  # P311 cond 6, FC9
ANTIBOT_BADGE = "opens in browser; may require challenge"
RED_WARNING = "TLP:RED - third-party link, listed only by `v3lum links`"  # FC2
TERMINAL_MAX_LINKS = 8  # FC6
RECHECK_MAX_AGE_DAYS = 180  # FC7

PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")  # core: the re.sub pattern of the frozen renderer
# core: frozen placeholder whitelist. Value: entity types the placeholder accepts (None = any type).
FROZEN_PLACEHOLDERS = {
    "q": None, "qp": None, "raw": None, "domain": {"domain"}, "user": {"username"}, "b64": None,
    "b64url": None, "e164": {"phone"}, "e164_plus": {"phone"}, "br_national": {"phone"},
    "br_national_no9": {"phone"}, "wa": {"phone"}, "cnpj_fmt": {"cnpj"}, "cnpj_digits": {"cnpj"},
    "cnpj_root": {"cnpj"}, "idn": {"domain"}, "punycode": {"domain"}, "ip": {"ipv4", "ipv6"},
    "asn_num": {"asn"},
}
PACK_PLACEHOLDERS = ("q", "domain")  # the only encoders this pack uses (FC3: 'through the declared encoder')

# Bidirectional/isolate controls (category Cf) that can spoof how a value reads in 'opening sends <value>'.
_BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")


# ----------------------------------------------------------------------------------------------------
# Small text helpers
# ----------------------------------------------------------------------------------------------------

def as_text(raw, encoding: str | None = None) -> str:
    """bytes/str/None -> str; tries the declared encoding, then UTF-8, then ISO-8859-1. Never raises."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        for enc in (encoding, "utf-8", "iso-8859-1"):
            if not enc:
                continue
            try:
                return bytes(raw).decode(enc)
            except (LookupError, UnicodeDecodeError):
                continue
    return str(raw)


def html_title(body) -> str | None:
    """The unescaped, whitespace-collapsed <title> of an HTML page, or None."""
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", as_text(body)[:200_000])
    if not m:
        return None
    title = re.sub(r"\s+", " ", _html.unescape(m.group(1))).strip()
    return title or None


def _lower_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _netloc_problem(parts) -> bool:
    """True when a split URL carries userinfo or a port (an invalid port counts too)."""
    try:
        port = parts.port
    except ValueError:
        return True
    return bool(parts.username or parts.password or port)


def tlp_level(value) -> int | None:
    """'TLP:AMBER+STRICT' / 'amber_strict' / 'white' -> index in TLP_ORDER; None when unknown."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    v = v.removeprefix("tlp:")
    v = {"white": "clear", "amber_strict": "amber+strict", "amber-strict": "amber+strict"}.get(v, v)
    return TLP_ORDER.index(v) if v in TLP_ORDER else None


def _to_int(text) -> int | None:
    """'9,196' / '1835042' / ' 0 ' -> int; None when not a plain count."""
    if not isinstance(text, str):
        return None
    t = text.strip().replace(",", "").replace(".", "").replace("\u00a0", "")
    return int(t) if t.isdigit() else None


# ----------------------------------------------------------------------------------------------------
# Value guards and encoders (FC3, FC8, P311 cond 6)
# ----------------------------------------------------------------------------------------------------

def _clean_free_text(value) -> str | None:
    """Free-text value as V3LUM would hold it: str, NFC, trimmed, 1..200 chars, no control characters
    (newline, CR, tab, NUL, ESC) and no bidi overrides. None when refused (the link then does not render)."""
    if not isinstance(value, str):
        return None
    v = unicodedata.normalize("NFC", value).strip()
    if not v or len(v) > 200:
        return None
    if any(unicodedata.category(c) == "Cc" or c in _BIDI for c in v):
        return None
    return v


_CPF_FMT_RE = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
_DIGIT_RUN_RE = re.compile(r"(?<![\d.-])\d{11}(?![\d.-])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_PHONE_RE = re.compile(r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?\(?\d{2}\)?[\s.-]?9?\d{4}[\s.-]?\d{4}(?!\d)")


def _cpf_valid(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit() or len(set(digits)) == 1:
        return False
    for n in (9, 10):
        s = sum(int(d) * w for d, w in zip(digits[:n], range(n + 1, 1, -1)))
        if (s * 10 % 11) % 10 != int(digits[n]):
            return False
    return True


def personal_marker(value) -> str | None:
    """Reason string when a free-text value (keyword / company_name) carries a personal identifier, else
    None. A CPF never appears in a link (P311 cond 6, team rule 4); WikiLeaks never gets a people search
    (FC8), so an e-mail address or a phone number typed as a keyword does not render either.
    Formatted CPF shapes are refused whatever their check digits; bare 11-digit runs only when valid."""
    if not isinstance(value, str):
        return None
    if _CPF_FMT_RE.search(value):
        return "cpf"
    for run in _DIGIT_RUN_RE.findall(value):
        if _cpf_valid(run):
            return "cpf"
    if _EMAIL_RE.search(value):
        return "email"
    if _PHONE_RE.search(value):
        return "phone"
    return None


def enc_q(value) -> str | None:
    """{q} reference: percent-encode everything but unreserved characters (quote(safe='')): spaces -> %20,
    '/', '?', '#', '&', '=' and quotes encoded, UTF-8 for non-ASCII, so the value can never add a path
    segment or a query parameter. Refuses dot-only values and everything _clean_free_text refuses.
    Live 2026-11-26: both hosts decode %20 and UTF-8 ('CVE-2021-44228 log4j', '"Ação" example')."""
    v = _clean_free_text(value)
    if v is None or set(v) <= {"."}:
        return None
    return quote(v, safe="")


def enc_qp(value) -> str | None:
    """{qp} reference: form encoding (quote_plus), spaces -> '+'. Query values only. Not used by this pack
    (WikiLeaks' own pagination uses '+', both forms work there)."""
    v = _clean_free_text(value)
    if v is None or set(v) <= {"."}:
        return None
    return quote_plus(v, safe="")


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def domain_value(value) -> str | None:
    """{domain} reference: lower-case ASCII (IDNA/punycode) host name with >= 2 labels, else None.
    Used for Lyzem (FC9: IOC values only), so free text can never reach the unknown-tier host."""
    if not isinstance(value, str) or any(unicodedata.category(c) == "Cc" for c in value):
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253 or any(c in v for c in "/?#@:%\\ \t\r\n\"'<>"):
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    labels = v.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(lb) for lb in labels):
        return None
    return v


def placeholder_value(name: str, etype: str, value) -> str | None:
    """Encoded string for one placeholder, or None when the placeholder does not apply to the value (FC3).
    Free-text types also pass the personal_marker guard (FC8, P311 cond 6)."""
    allowed = FROZEN_PLACEHOLDERS.get(name, False)
    if allowed is False or name not in PACK_PLACEHOLDERS:
        return None
    if allowed is not None and etype not in allowed:
        return None
    if etype in FREE_TEXT_TYPES and personal_marker(value):
        return None
    if name == "q":
        return enc_q(value)
    if name == "domain":
        return domain_value(value)
    return None


def render_template(template: str, etype: str, value) -> str | None:
    """Whitelist substitution with re.sub (never str.format). None when any placeholder is unknown or does
    not apply, so a link either renders completely or not at all (FC3)."""
    if not isinstance(template, str):
        return None
    failed = []

    def sub(m):
        out = placeholder_value(m.group(1), etype, value)
        if out is None:
            failed.append(m.group(1))
            return ""
        return out

    url = PLACEHOLDER_RE.sub(sub, template)
    return None if failed else url


def template_problems(template, host, entity_types) -> list:
    """Load-time template checks (core: links template validation, FC3): https, fixed host == declared
    host, no userinfo/port, placeholders whitelisted, type-compatible and only in path/query, no {raw}."""
    problems = []
    if not isinstance(template, str) or not template:
        return ["template missing"]
    names = PLACEHOLDER_RE.findall(template)
    parts = urlsplit(PLACEHOLDER_RE.sub("V", template))
    if parts.scheme != "https":
        problems.append("not https")
    if _netloc_problem(parts):
        problems.append("userinfo or port in template")
    if (parts.hostname or "") != host:
        problems.append(f"host {parts.hostname!r} != declared {host!r}")
    netloc_end = template.find("/", len("https://")) if template.startswith("https://") else -1
    if netloc_end == -1 or PLACEHOLDER_RE.search(template[:netloc_end]):
        problems.append("placeholder in scheme/host position")
    rest = PLACEHOLDER_RE.sub("", template)
    if "{" in rest or "}" in rest:
        problems.append("stray brace: only {name} placeholders are allowed (never str.format fields)")
    if parts.fragment:
        problems.append("fragment in template")
    if not names:
        problems.append("no placeholder: the link would not carry the value")
    for name in names:
        if name == "raw":
            problems.append("{raw} is not allowed in this pack (FC3)")
        elif name not in FROZEN_PLACEHOLDERS:
            problems.append(f"unknown placeholder {{{name}}}")
        elif name not in PACK_PLACEHOLDERS:
            problems.append(f"{{{name}}} is not an encoder of this pack")
        else:
            allowed = FROZEN_PLACEHOLDERS[name]
            bad = [t for t in (entity_types or []) if allowed is not None and t not in allowed]
            if bad:
                problems.append(f"{{{name}}} does not accept {bad}")
    return problems


def check_rendered_url(url, template: str, host: str) -> list:
    """FC3 invariants for one rendered URL ([] = passes): https on exactly the declared host, no userinfo or
    port, no whitespace/control character, path unchanged, the same query parameter names as the template
    (so the value never adds a parameter), every template literal kept in order."""
    problems = []
    if not isinstance(url, str):
        return ["not rendered"]
    if any(c.isspace() or unicodedata.category(c) in ("Cc", "Cf") for c in url):
        problems.append("whitespace/control character in URL")
    parts = urlsplit(url)
    if parts.scheme != "https":
        problems.append("not https")
    if (parts.hostname or "") != host or _netloc_problem(parts):
        problems.append("host/userinfo/port changed")
    tparts = urlsplit(PLACEHOLDER_RE.sub("V", template))
    if parts.path != tparts.path:
        problems.append("path changed")
    if parts.fragment:
        problems.append("fragment added")
    if [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)] != \
            [k for k, _ in parse_qsl(tparts.query, keep_blank_values=True)]:
        problems.append("query parameters changed")
    pos = 0
    for lit in (p for p in PLACEHOLDER_RE.split(template)[::2] if p):
        j = url.find(lit, pos)
        if j < 0:
            problems.append("template literal lost")
            break
        pos = j + len(lit)
    if not all(ord(c) < 128 for c in url):
        problems.append("non-ASCII character in URL")
    return problems


# ----------------------------------------------------------------------------------------------------
# Pack lint (P308 rules on top of the core lint)
# ----------------------------------------------------------------------------------------------------

def lint_link(link, *, host_tiers: dict) -> list:
    """Problems of one pack entry ([] = passes). Mirrors the frozen lint where the contract states it
    (FC1, FC3, P311 conds 4, 6, 7) and adds the P308 rules: FC4/FC5/FC9 tier gate (unknown tier = IOC
    values only, never free text), FC8 WikiLeaks types and banner, FC9 Lyzem privacy, FC10 seed_only and
    caution marker. host_tiers: {host: tier} from the provider registry; a host missing from it fails FC4."""
    p = []
    if not isinstance(link, dict):
        return ["entry is not an object"]
    lid = link.get("id", "?")
    for k in REQUIRED_LINK_KEYS:
        if k not in link:
            p.append(f"{lid}: missing {k}")
    for k in link:
        if k not in FROZEN_LINK_KEYS and k not in EXTENSION_LINK_KEYS:
            p.append(f"{lid}: unknown key {k}")
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
    if link["touches_target"] is not False:
        p.append(f"{lid}: content search never touches the target (research: touches_target false)")
    if link["category"] not in LINK_CATEGORIES:
        p.append(f"{lid}: bad category")
    if not isinstance(link["label"], str) or not link["label"].strip():
        p.append(f"{lid}: label missing")
    et = link["entity_types"]
    if not isinstance(et, list) or not et or not all(isinstance(t, str) for t in et):
        return p + [f"{lid}: entity_types must be a non-empty list"]
    if len(set(et)) != len(et):
        p.append(f"{lid}: duplicate entity types")
    if "cpf" in et:
        p.append(f"{lid}: no template ever takes a CPF (rule 4)")
    if link["verified"]:
        try:
            date.fromisoformat(str(link["checked_at"]))
        except ValueError:
            p.append(f"{lid}: verified link without a real checked_at date (FC7)")
    host = link["host"]
    p += [f"{lid}: {x}" for x in template_problems(link["template"], host, et)]
    if host not in host_tiers:
        p.append(f"{lid}: host {host!r} has no provider-registry entry (FC4)")
    tier = host_tiers.get(host, "unknown")
    personal = [t for t in et if t in PERSONAL_TYPES or t in COMPANY_ID_TYPES]
    if personal and not link["privacy"]:
        p.append(f"{lid}: {personal} need privacy=true (P311 cond 6)")
    if personal and tier == "unknown":
        p.append(f"{lid}: personal/CNPJ values to an unknown-tier host (A8 BR4)")
    if tier == "unknown" and any(t not in IOC_TYPES for t in et):
        p.append(f"{lid}: unknown-tier host takes IOC_TYPES only, never free text (FC4)")
    # P308 pack rules
    if host not in PACK_HOSTS:
        p.append(f"{lid}: host {host!r} is not a P308 host")
    if host == WIKILEAKS_HOST:
        if set(et) - WIKILEAKS_TYPES:
            p.append(f"{lid}: WikiLeaks takes company_name/keyword only, never person names or usernames (FC8)")
        if link.get("warning") != WIKILEAKS_BANNER:
            p.append(f"{lid}: WikiLeaks needs the banner '{WIKILEAKS_BANNER}' (FC8)")
        if urlsplit(PLACEHOLDER_RE.sub("V", link["template"])).path not in ("/", ""):
            p.append(f"{lid}: WikiLeaks search page only, never a document or download path (FC8, rule 3)")
    if host == LYZEM_HOST:
        if set(et) - LYZEM_ALLOWED_TYPES:
            p.append(f"{lid}: Lyzem takes {sorted(LYZEM_ALLOWED_TYPES)} only (FC9)")
        if set(et) & LYZEM_PRIVACY_TYPES and not link["privacy"]:
            p.append(f"{lid}: Lyzem person-name/username links need privacy=true (FC9)")
        if set(et) & LYZEM_PRIVACY_TYPES and set(et) - LYZEM_PRIVACY_TYPES:
            p.append(f"{lid}: keep Lyzem subject links (privacy) apart from IOC/keyword links (FC9)")
    if link.get("seed_only") is not True:
        p.append(f"{lid}: seed_only must be true: analyst-typed seeds only (FC10)")
    if not isinstance(link.get("warning"), str) or not link["warning"].strip():
        p.append(f"{lid}: caution marker (warning text) missing (FC10)")
    mt = link.get("max_tlp")
    if mt is not None and tlp_level(mt) is None:
        p.append(f"{lid}: bad max_tlp")
    return p


def lint_pack(data, *, host_tiers: dict) -> list:
    """Problems of the whole pack ([] = passes): schema id, pack name, unique ids, entries, and the FC6
    curated order (every Lyzem entry before every WikiLeaks entry)."""
    if not isinstance(data, dict):
        return ["pack is not an object"]
    p = []
    if data.get("schema") != PACK_SCHEMA:
        p.append("schema must be " + PACK_SCHEMA)
    if data.get("pack") != PACK_NAME:
        p.append(f"pack must be {PACK_NAME!r} (file stem, FC1)")
    if not isinstance(data.get("title"), str) or not data["title"].strip():
        p.append("title missing")
    links = data.get("links")
    if not isinstance(links, list) or not links:
        return p + ["links must be a non-empty list"]
    ids = [lk.get("id") for lk in links if isinstance(lk, dict)]
    if len(ids) != len(set(ids)):
        p.append("duplicate link ids")
    for lk in links:
        p += lint_link(lk, host_tiers=host_tiers)
    hosts = [lk.get("host") for lk in links if isinstance(lk, dict)]
    ranks = [PACK_HOSTS.index(h) for h in hosts if h in PACK_HOSTS]
    if ranks != sorted(ranks):
        p.append("file order must be Lyzem entries, then WikiLeaks (FC6)")
    return p


def activate_pending(pack: dict, pending: dict, host_tiers: dict) -> dict:
    """FC5/FC9: the Lyzem keyword/company and subject entries join the pack only once the registry records
    lyzem.com as community or trusted. Returns a new pack (inserted after the last Lyzem entry, keeping
    the FC6 order); unchanged while the tier is unknown."""
    if host_tiers.get(LYZEM_HOST) not in ("community", "trusted"):
        return pack
    links = list((pack or {}).get("links", []))
    extra = [dict(lk) for lk in (pending or {}).get("links", []) if isinstance(lk, dict)]
    last_lyzem = max((i for i, lk in enumerate(links) if lk.get("host") == LYZEM_HOST), default=-1)
    new = dict(pack)
    new["links"] = links[:last_lyzem + 1] + extra + links[last_lyzem + 1:]
    return new


# ----------------------------------------------------------------------------------------------------
# Applicability, the A2/P311 view, ordering, doctor (FC2, FC6, FC7, FC9, FC10)
# ----------------------------------------------------------------------------------------------------

def render_link(link: dict, etype: str, value) -> str | None:
    """URL for one entity, or None (type not declared, or the value refused by its encoder/guard)."""
    if not isinstance(link, dict) or etype not in (link.get("entity_types") or []):
        return None
    return render_template(link.get("template"), etype, value)


def _defang(url: str) -> str:
    return url.replace("https://", "hxxps://", 1).replace(".", "[.]", 1)


def link_view(link: dict, etype: str, value, *, tlp="amber", provenance="seed", privacy_opt_in=False,
              purpose="", host_tier=None, display=None) -> dict:
    """How one link is shown (FC2, FC4, FC9, FC10; P311 conds 5-7; A2, A8):
    where: 'report' | 'links_only' (TLP:RED: hidden from reports, listed only by `v3lum links`) | 'hidden';
    clickable only at CLEAR/GREEN; at AMBER and above the text is non-clickable with
    'opening sends <value> to <host>'. reason says why a link is hidden or moved:
    not_applicable | seed_only (FC10) | tier (FC4) | privacy_opt_in (FC9) | tlp_red | max_tlp.
    provenance: 'seed' (analyst-typed) or anything else (pivot, extracted, QSA partner...)."""
    view = {"ref": link.get("id"), "label": link.get("label"), "host": link.get("host"),
            "category": link.get("category"), "verified": bool(link.get("verified")), "url": None,
            "where": "hidden", "clickable": False, "text": "", "disclosure": "", "badges": [],
            "warnings": [], "reason": ""}
    url = render_link(link, etype, value)
    if not url:
        view["reason"] = "not_applicable"
        return view
    if link.get("seed_only") and provenance != "seed":
        view["reason"] = "seed_only"
        return view
    tier = host_tier if host_tier in TIERS else "unknown"
    if tier == "unknown" and etype not in IOC_TYPES:
        view["reason"] = "tier"
        return view
    if link.get("privacy") and provenance != "seed":
        view["reason"] = "privacy_not_seed"  # P311 cond 6: never auto-discovered entities
        return view
    if link.get("privacy") and (not privacy_opt_in or not str(purpose or "").strip()):
        view["reason"] = "privacy_opt_in"
        return view
    level = tlp_level(tlp)
    level = TLP_ORDER.index("amber") if level is None else level
    shown = display if display is not None else str(value)
    view["url"] = url
    view["disclosure"] = f"opening sends {shown} to {link.get('host')}"
    if not link.get("verified"):
        view["badges"].append(BADGE_UNVERIFIED)
    if tier == "unknown":
        view["badges"].append(BADGE_UNKNOWN_OPERATOR)
    if link.get("antibot"):
        view["badges"].append(ANTIBOT_BADGE)
    if link.get("privacy"):
        view["badges"].append(BADGE_PRIVACY)
    if link.get("warning"):
        view["badges"].append(BADGE_CAUTION)
        view["warnings"].append(link["warning"])
    where = "report"
    if level >= TLP_ORDER.index("red"):
        where = "links_only"
        view["warnings"].append(RED_WARNING)
        view["reason"] = "tlp_red"
    elif link.get("max_tlp") is not None and level > (tlp_level(link["max_tlp"]) or 0):
        where = "links_only"
        view["reason"] = "max_tlp"
    view["where"] = where
    clickable = where == "report" and level <= TLP_ORDER.index("green")
    view["clickable"] = clickable
    view["text"] = url if clickable else f"{_defang(url)} ({view['disclosure']})"
    return view


def open_decision(view: dict, tlp, *, tty: bool, confirmed_host: str | None = None) -> str:
    """`v3lum links --open` (FC2, A2): never automatic; at AMBER and above an interactive confirmation that
    names the host is required and a non-TTY session refuses. Returns 'open' | 'ask' | 'refuse'."""
    if not view or not view.get("url"):
        return "refuse"
    level = tlp_level(tlp)
    level = TLP_ORDER.index("amber") if level is None else level
    if level <= TLP_ORDER.index("green"):
        return "open"
    if not tty:
        return "refuse"
    return "open" if confirmed_host == view.get("host") else "ask"


def order_views(views: list, *, max_terminal: int = TERMINAL_MAX_LINKS):
    """FC6: group by analyst question (category order), verified first, then pack file order (the order of
    `views`, i.e. Lyzem then WikiLeaks); the terminal shows at most 8 per seed, the rest go to HTML and
    `v3lum links`. Returns (terminal, rest)."""
    shown = [(i, v) for i, v in enumerate(views) if v.get("where") == "report"]
    cat = {c: n for n, c in enumerate(LINK_CATEGORIES)}
    shown.sort(key=lambda iv: (cat.get(iv[1].get("category"), len(cat)), not iv[1].get("verified"), iv[0]))
    ordered = [v for _, v in shown]
    return ordered[:max_terminal], ordered[max_terminal:]


def doctor_links(packs: list, today: date, *, max_age_days: int = RECHECK_MAX_AGE_DAYS) -> list:
    """FC7 `v3lum doctor --links` (offline): unverified links and links not re-checked for more than
    max_age_days. Returns [{'ref', 'reason', 'age_days'}]."""
    out = []
    for pack in packs or []:
        for lk in (pack or {}).get("links", []):
            ref = f"{pack.get('pack')}:{lk.get('id')}"
            if not lk.get("verified"):
                out.append({"ref": ref, "reason": "unverified", "age_days": None})
                continue
            try:
                age = (today - date.fromisoformat(str(lk.get("checked_at")))).days
            except ValueError:
                out.append({"ref": ref, "reason": "bad checked_at", "age_days": None})
                continue
            if age > max_age_days:
                out.append({"ref": ref, "reason": f"not re-checked for {age} days", "age_days": age})
    return out


# ----------------------------------------------------------------------------------------------------
# Re-check markers (FC7 evidence; maintainers only, never V3LUM runtime)
# ----------------------------------------------------------------------------------------------------

def challenge_marker(status, headers, body) -> str | None:
    """Anti-bot wall (A9: reported as BLOCKED/challenge, never bypassed). None seen on either host on
    2026-11-26 (lyzem.com: Caddy, no CDN; search.wikileaks.org: nginx + Varnish)."""
    h = _lower_headers(headers)
    t = as_text(body)[:50_000]
    title = (html_title(t) or "").lower()
    if h.get("cf-mitigated", "").lower() == "challenge":
        return "challenge: Cloudflare managed challenge (cf-mitigated)"
    if "just a moment" in title and ("challenge-platform" in t or "cf-chl" in t):
        return "challenge: Cloudflare 'Just a moment'"
    if title.startswith("attention required") and "cloudflare" in title:
        return "challenge: Cloudflare block page"
    if "ddos-guard" in t.lower() and status in (403, 503):
        return "challenge: DDoS-Guard"
    low = t.lower()
    for key, name in (("hcaptcha.com", "hCaptcha"), ("g-recaptcha", "reCAPTCHA"),
                      ("challenges.cloudflare.com/turnstile", "Turnstile")):
        if key in low:
            return f"challenge: {name}"
    return None


def rate_limit_marker(status, headers, body=None) -> str | None:
    """HTTP 429 (with Retry-After when given). Neither host sent rate-limit headers on 2026-11-26."""
    if status == 429:
        ra = _lower_headers(headers).get("retry-after")
        return "rate_limited" + (f": retry after {ra}" if ra else "")
    return None


def login_redirect_marker(status, headers) -> str | None:
    """Redirect to a login/SSO page (P311 lint: login pages are excluded)."""
    if status in (301, 302, 303, 307, 308):
        loc = _lower_headers(headers).get("location", "")
        if re.search(r"(?i)(/login|/signin|/sign-in|/auth/|/sso/|openidconnect)", loc):
            return f"login_wall: redirect to {loc[:120]}"
    return None


# ----------------------------------------------------------------------------------------------------
# Results-page parsers (counts and echoes only; FC8 rule 3: nothing ingested)
# ----------------------------------------------------------------------------------------------------

_LYZEM_COUNT_RE = re.compile(r"(?s)<p class=\"is-size-6\">\s*([\d,]+)\s+results\s*\S\s*(\d+)\s*ms")
_LYZEM_ECHO_RE = re.compile(r"(?s)<input\b[^>]*?\bname=\"q\"[^>]*?\bvalue=\"([^\"]*)\"")
_LYZEM_ITEM_RE = re.compile(r"(?s)<div class=\"search-result-type-wrapper([^\"]*)\"[^>]*?\btitle=\"([^\"]*)\"")


def parse_lyzem_results(body) -> dict:
    """Lyzem /search?q= page -> {'is_results_page', 'query', 'results_total', 'took_ms', 'items',
    'item_types': {type: n}, 'with_profile', 'complete'}. Counts only: titles, message text and t.me
    handles are never extracted (third-party Telegram content). Two item variants seen live: plain
    (title="article") and with a channel profile (title="channel - with profile",
    data-profile-link=...). Defensive: missing pieces give None / 0, never an exception."""
    t = as_text(body)
    out = {"is_results_page": False, "query": None, "results_total": None, "took_ms": None, "items": 0,
           "item_types": {}, "with_profile": 0, "complete": False}
    if not t.strip():
        return out
    title = html_title(t) or ""
    m = _LYZEM_ECHO_RE.search(t)
    if m:
        out["query"] = _html.unescape(m.group(1))
    m = _LYZEM_COUNT_RE.search(t)
    if m:
        out["results_total"] = _to_int(m.group(1))
        out["took_ms"] = _to_int(m.group(2))
    types = {}
    for cls, ttl in _LYZEM_ITEM_RE.findall(t):
        base = ttl.split(" - ")[0].strip().lower() or "unknown"
        types[base] = types.get(base, 0) + 1
        if "with-profile" in cls:
            out["with_profile"] += 1
    out["item_types"] = types
    out["items"] = len(re.findall(r'<li class="search-result"', t))
    out["is_results_page"] = title == "Search results" and 'class="search-results"' in t
    out["complete"] = bool(re.search(r"(?is)</ul>\s*</div>.*</html>\s*$", t)) and out["results_total"] is not None
    return out


_WL_ECHO_RE = re.compile(r"<input type=\"text\" name=\"query\" value=\"([^\"]*)\"")
_WL_SEARCHING_RE = re.compile(r"(?s)Searching for <i>(.*?)</i>")
_WL_COUNT_RE = re.compile(r"(?s)class=\"total-count\">\s*<span>\s*([\d,]+)\s+results?")
_WL_TOTAL_RE = re.compile(r"(?s)<label for=\"[^\"]+\" class=\"label\">([^<]+)</label>\s*"
                          r"<div class=\"total\">\s*([\d,]+)\s*</div>")


def parse_wikileaks_results(body) -> dict:
    """search.wikileaks.org/?query= page -> {'is_results_page', 'query', 'results_total', 'leak_totals':
    {release label: n}, 'items', 'no_filters', 'complete'}. Release labels (Plusd, Cablegate, Global
    Intelligence Files...) are WikiLeaks' own collection names. Document titles, excerpts and links are
    never extracted (FC8, rule 3: link only, nothing ingested or stored)."""
    t = as_text(body)
    out = {"is_results_page": False, "query": None, "results_total": None, "leak_totals": {}, "items": 0,
           "no_filters": False, "complete": False}
    if not t.strip():
        return out
    title = html_title(t) or ""
    m = _WL_ECHO_RE.search(t) or _WL_SEARCHING_RE.search(t)
    if m:
        out["query"] = _html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
    m = _WL_COUNT_RE.search(t)
    if m:
        out["results_total"] = _to_int(m.group(1))
    totals = {}
    for label, n in _WL_TOTAL_RE.findall(t):
        v = _to_int(n)
        if v is not None:
            totals[_html.unescape(label).strip()] = v
    out["leak_totals"] = totals
    out["items"] = len(re.findall(r'<div class="result">', t))
    out["no_filters"] = bool(re.search(r"(?s)class=\"publication-totals\">\s*No filters available", t))
    out["is_results_page"] = title == "Search WikiLeaks" and 'id="results"' in t
    out["complete"] = "</html>" in t[-200:].lower() and out["results_total"] is not None
    return out


def error_in_200(source: str, status, body) -> str | None:
    """A 200 answer that is not the expected results page (maintenance page, JSON, another page, empty
    body). Short reason or None. A truncated results page is 'malformed', not error-in-200."""
    if status != 200:
        return None
    t = as_text(body)
    if not t.strip():
        return "error_in_200: empty body"
    if t.lstrip()[:1] in ("{", "["):
        return "error_in_200: JSON instead of the HTML results page"
    title = html_title(t) or ""
    expected = {"lyzem": "Search results", "wikileaks": "Search WikiLeaks"}.get(source)
    if expected and title != expected:
        return f"error_in_200: unexpected page title {title[:60]!r}"
    return None


def _fold(value) -> str:
    nfkd = unicodedata.normalize("NFKD", value or "")
    return " ".join("".join(c for c in nfkd if not unicodedata.combining(c)).casefold().split())


def classify_check(source: str, status, headers, body, value: str = "") -> dict:
    """Verdict for one maintainer re-check of a pack link (FC7): {'verdict', 'reason', 'facts'} with verdict
    in ok | empty | mismatch | malformed | error_in_200 | not_found | challenge | rate_limited |
    login_wall | redirect | error. source: 'lyzem' | 'wikileaks'. value: the probe value as typed (the
    page must echo it back decoded, which proves the encoder: %20 and UTF-8 seen live on both hosts).
    ok/empty is the verified state; the link stays verified=true with the new checked_at."""
    h = _lower_headers(headers)
    status = status if isinstance(status, int) else -1
    res = {"verdict": "error", "reason": "", "facts": {}}
    for verdict, fn in (("rate_limited", lambda: rate_limit_marker(status, h, body)),
                        ("challenge", lambda: challenge_marker(status, h, body)),
                        ("login_wall", lambda: login_redirect_marker(status, h))):
        r = fn()
        if r:
            res.update(verdict=verdict, reason=r)
            return res
    if status in (301, 302, 303, 307, 308):
        res.update(verdict="redirect", reason=f"redirect to {h.get('location', '')[:120]}")
        return res
    if status in (404, 410):
        res.update(verdict="not_found", reason=f"HTTP {status}")
        return res
    if status != 200:
        res.update(verdict="error", reason=f"HTTP {status}")
        return res
    e200 = error_in_200(source, status, body)
    if e200:
        res.update(verdict="error_in_200", reason=e200)
        return res
    if source == "lyzem":
        facts = parse_lyzem_results(body)
    elif source == "wikileaks":
        facts = parse_wikileaks_results(body)
    else:
        res.update(verdict="error", reason=f"unknown source {source!r}")
        return res
    res["facts"] = facts
    if not facts["is_results_page"] or facts["results_total"] is None or not facts["complete"]:
        res.update(verdict="malformed", reason="results page incomplete (count or closing markup missing)")
        return res
    if value and _fold(facts["query"]) != _fold(value):
        res.update(verdict="mismatch", reason=f"page echoes {facts['query']!r}, not the probe value")
        return res
    if facts["results_total"] == 0:
        res.update(verdict="empty", reason="search page, 0 results")
        return res
    res.update(verdict="ok", reason=f"{facts['results_total']} results")
    return res


def parse_envelope(data) -> tuple:
    """A fixture envelope {'status', 'headers', 'body'} (dict or JSON text) -> (status, headers, body).
    Wrong shapes give (-1, {}, '')."""
    import json
    if isinstance(data, (str, bytes, bytearray)):
        try:
            data = json.loads(as_text(data))
        except ValueError:
            return -1, {}, ""
    if not isinstance(data, dict):
        return -1, {}, ""
    st = data.get("status")
    return (st if isinstance(st, int) else -1, data.get("headers") if isinstance(data.get("headers"), dict) else {},
            data.get("body") if isinstance(data.get("body"), str) else "")
