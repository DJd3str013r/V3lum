"""Hunter.io domain search, address counts and person finder (P090), keyed - plus the offline
'plausible sender for our company' check fed by the own-domain address pattern.

Four modules, one source family (provider ``hunter``, key ``hunter`` in ``config.KNOWN_KEYS``):

* ``hunter_io`` - **own-asset-only domain search** (cond 2, A11 BR4): ``run_on='own_assets_only'``
  (txt_verified or attested org-profile entry, else SKIPPED ``own_asset``). ``email-count`` +
  ``domain-search`` of a verified own domain: address pattern, counts and - only here - the individual
  addresses, minimised and tagged privacy (cond 4).
* ``hunter_io_count`` - **counts only** for third-party domains and company names, inside a case with a
  recorded purpose (cond 2; SKIPPED ``privacy`` without one). Never an address.
* ``hunter_io_finder`` - **email-finder** for a person the analyst typed (``run_on='seeds'``) inside a
  case with a recorded purpose (cond 3). Input ``"First Last @ example.com"`` (or setting
  ``hunter_io_finder_domain``). The guessed address pivots with ``expand=False``, relation
  ``guessed_email``: account-revealing and key-server modules never run on it (P092 cond 1).
* ``hunter_sender_check`` - **offline** (disclosure none): is a sender address plausible for our company?
  Own domains come from the org profile, address patterns from setting ``hunter_sender_check_patterns``
  (``{"example.com": "{first}.{last}"}``, the pattern ``hunter_io`` reports); lookalike sender domains
  (TLD swap, homoglyphs, edit distance, hyphen/digit variants, own label inside) are flagged for BEC
  triage (cond 4).

Endpoint allow-list in code (cond 1): ``domain-search``, ``email-count`` and ``email-finder`` only.
:func:`hunter_url` refuses the email-verifier (Hunter's SMTP probing on our behalf, rule 2) and every
other endpoint, so its URL cannot be built. The key travels as ``api_key=`` in the query string: the
central redaction (AR01) masks it in every URL that is cached, logged, emitted or stored (cond 5).
401 ``authentication_failed`` = NEEDS_KEY; 403 (rate limit) = RATE_LIMITED; 429 (monthly credits) =
QUOTA; 451 = the person asked Hunter not to process their data (honoured: nothing kept). Monthly
credits (free plan: 25 searches) are paced by the provider quota block (P334). The provider is flagged
sensitive: per-source P145 schemas drop names, positions, phones, social handles and Hunter's own
verification verdicts before the HTTP cache, so the module never sees them. ``default_enabled=False``
(cond 6); key-terms - a company/team account on a plan recorded by legal (cond 5). The success fixtures
are documentation-shaped until a trimmed real capture made with the team key replaces them.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.psl import registrable_domain

HOST = "api.hunter.io"
KEY_NAME = "hunter"
SRC_DOMAIN = "hunter.domain_search"
SRC_COUNT = "hunter.email_count"
SRC_FINDER = "hunter.email_finder"

#: cond 1: endpoint -> (required params, optional params). The verifier is not in this table.
HUNTER_ENDPOINTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "domain-search": (("domain",), ("limit", "offset", "type")),
    "email-count": ((), ("domain", "company", "type")),
    "email-finder": (("domain",), ("first_name", "last_name", "full_name")),
}
DOMAIN_SEARCH_LIMIT = 10
MAX_ADDRESSES = 10
OPT_OUT_MARKER = "hunter_opt_out"
HUNTER_MARKERS = (
    {"id": "hunter_rate_limit", "statuses": [403], "regex": "(?i)rate.?limit|too_many_requests", "maps_to": "rate_limited",
     "reason_code": "rate_limited", "reason": "Hunter: request rate limit reached (HTTP 403): could not verify now"},
    {"id": "hunter_usage_limit", "statuses": [429], "regex": "(?i)usage limit|credits|upgrade|too_many_requests", "maps_to": "quota",
     "reason_code": "quota", "reason": "Hunter: monthly usage limit (credits) reached"},
    {"id": OPT_OUT_MARKER, "statuses": [451], "json_path": "errors[].id", "equals": "unavailable_for_legal_reasons", "maps_to": "error",
     "reason_code": "error", "reason": "Hunter: the person asked Hunter not to process their data (HTTP 451)"},
)
OPT_OUT_TEXT = "Hunter declined to process this person's data (opt-out, HTTP 451): nothing is looked up or kept"
_DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_EMAIL = re.compile(r"^[a-z0-9.!#$%&'*+=?^_`{|}~-]{1,64}@[a-z0-9.-]+$")
_PERSON_AT = re.compile(r"^(?P<name>[^@<>]+?)\s*(?:@|<)\s*(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*>?$")
_NAME_TOKEN = re.compile(r"^[^\W\d_][^\W\d_'.-]*(?:['.-][^\W\d_]+)*\.?$", re.UNICODE)


class EndpointRefused(ValueError):
    """A Hunter request that must never be built (verifier, unknown endpoint or parameter)."""


def normalise_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    host = value.strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return host if _DOMAIN.match(host) else None


def normalise_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if not _EMAIL.match(v) or ".." in v:
        return None
    return v if normalise_domain(v.rsplit("@", 1)[1]) else None


def hunter_url(endpoint: str, api_key: Any, **params: Any) -> str:
    """An allow-listed Hunter v2 URL (cond 1). Raises :class:`EndpointRefused` for the email-verifier
    (rule 2: SMTP probing on our behalf), any endpoint outside :data:`HUNTER_ENDPOINTS` and unknown or
    missing parameters; ValueError for a missing key. The key goes in ``api_key=`` (masked by AR01)."""
    name = str(endpoint or "").strip().strip("/").lower()
    if name.startswith("v2/"):
        name = name[3:]
    if "verif" in name:
        raise EndpointRefused("hunter: the email-verifier is never wired (rule 2: SMTP probing on our behalf, P090 cond 1)")
    if name not in HUNTER_ENDPOINTS:
        raise EndpointRefused(f"hunter: endpoint not allow-listed: {endpoint!r}")
    required, optional = HUNTER_ENDPOINTS[name]
    unknown = set(params) - set(required) - set(optional)
    if unknown:
        raise EndpointRefused(f"hunter: parameter(s) not allowed for {name}: {sorted(unknown)}")
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("hunter key not configured")
    clean: dict[str, str] = {}
    for key, value in params.items():
        if value in (None, ""):
            continue
        if key == "domain":
            dom = normalise_domain(str(value))
            if dom is None:
                raise EndpointRefused("hunter: invalid domain")
            value = dom
        clean[key] = " ".join(str(value).split())[:120]
    for key in required:
        if key not in clean:
            raise EndpointRefused(f"hunter: {name} needs {key}")
    if name == "email-count" and not (clean.get("domain") or clean.get("company")):
        raise EndpointRefused("hunter: email-count needs a domain or a company")
    if name == "email-finder" and not (clean.get("full_name") or (clean.get("first_name") and clean.get("last_name"))):
        raise EndpointRefused("hunter: email-finder needs first_name + last_name or full_name")
    if name == "domain-search":
        try:
            limit = int(clean.get("limit") or DOMAIN_SEARCH_LIMIT)
        except ValueError:
            limit = DOMAIN_SEARCH_LIMIT
        clean["limit"] = str(max(1, min(limit, DOMAIN_SEARCH_LIMIT)))
    clean["api_key"] = api_key.strip()
    return f"https://{HOST}/v2/{name}?{urlencode(clean)}"


def _data(body: Any) -> dict[str, Any] | None:
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _day(value: Any) -> str | None:
    return value[:10] if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}", value) else None


def _window(sources: Any) -> tuple[int, str | None, str | None]:
    """(source count, first extracted_on, last last_seen_on) of a Hunter sources list."""
    count, first, last = 0, None, None
    for src in sources if isinstance(sources, list) else []:
        if not isinstance(src, dict):
            continue
        count += 1
        a, b = _day(src.get("extracted_on")), _day(src.get("last_seen_on"))
        if a and (first is None or a < first):
            first = a
        if b and (last is None or b > last):
            last = b
    return count, first, last


def parse_domain_search(body: Any, *, own_domain: bool, max_addresses: int = MAX_ADDRESSES) -> dict[str, Any] | None:
    """domain-search -> pattern, totals and counts; individual addresses only for a verified own domain
    (cond 2/4: never for third parties). None when the body is not a domain-search result."""
    data = _data(body)
    if data is None or ("emails" not in data and "pattern" not in data):
        return None
    emails = data.get("emails") if isinstance(data.get("emails"), list) else []
    type_counts: dict[str, int] = {}
    dept_counts: dict[str, int] = {}
    addresses: list[dict[str, Any]] = []
    for item in emails:
        if not isinstance(item, dict):
            continue
        etype = item.get("type") if item.get("type") in ("personal", "generic") else "unknown"
        type_counts[etype] = type_counts.get(etype, 0) + 1
        dept = item.get("department") if isinstance(item.get("department"), str) and item.get("department") else None
        if dept:
            dept = dept.strip().lower()[:40]
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
        if not own_domain or len(addresses) >= max_addresses:
            continue
        addr = normalise_email(item.get("value"))
        if addr is None:
            continue
        count, first, last = _window(item.get("sources"))
        conf = _int(item.get("confidence"))
        addresses.append({"email": addr, "type": etype, "confidence": conf if conf is not None and 0 <= conf <= 100 else None,
                          "department": dept, "source_count": count, "first_seen": first, "last_seen": last})
    pattern = data.get("pattern") if isinstance(data.get("pattern"), str) and data.get("pattern") else None
    meta = body.get("meta") if isinstance(body, dict) and isinstance(body.get("meta"), dict) else {}
    total = _int(meta.get("results"))
    org = data.get("organization") if isinstance(data.get("organization"), str) else None
    return {
        "domain": normalise_domain(data.get("domain")) if isinstance(data.get("domain"), str) else None,
        "organization": " ".join(org.split())[:120] if org else None,
        "pattern": pattern if pattern and hunter_pattern_regex(pattern) is not None else None,
        "total": total if total is not None else len(emails),
        "returned": len(emails),
        "type_counts": type_counts,
        "department_counts": dept_counts,
        "addresses": addresses if own_domain else None,
    }


def parse_email_count(body: Any) -> dict[str, Any] | None:
    """email-count -> totals only (cond 2). None when the body is not an email-count result."""
    data = _data(body)
    if data is None or "total" not in data:
        return None

    def nonzero(obj: Any) -> dict[str, int]:
        if not isinstance(obj, dict):
            return {}
        return {str(k)[:40]: v for k, v in obj.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0}

    return {
        "total": _int(data.get("total")) or 0,
        "personal": _int(data.get("personal_emails")) or 0,
        "generic": _int(data.get("generic_emails")) or 0,
        "department": nonzero(data.get("department")),
        "seniority": nonzero(data.get("seniority")),
    }


def parse_email_finder(body: Any) -> dict[str, Any] | None:
    """email-finder -> the guessed address (cond 3: provenance 'generated'), score, source window.
    None when not a finder result; ``email`` None when Hunter found nothing."""
    data = _data(body)
    if data is None or ("email" not in data and "score" not in data):
        return None
    count, first, last = _window(data.get("sources"))
    score = _int(data.get("score"))
    return {
        "email": normalise_email(data.get("email")),
        "score": score if score is not None and 0 <= score <= 100 else None,
        "source_count": count,
        "first_seen": first,
        "last_seen": last,
        "provenance": "generated",
    }


_PATTERN_TOKENS = {"{first}": "[a-z]{2,}", "{last}": "[a-z]{2,}", "{f}": "[a-z]", "{l}": "[a-z]"}


def hunter_pattern_regex(pattern: Any) -> re.Pattern[str] | None:
    """Compile a Hunter address pattern ('{first}.{last}', '{f}{last}'...) into a local-part regex with an
    optional 1-2 digit homonym suffix. None for an unusable pattern."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > 64:
        return None
    pieces = re.split(r"(\{first\}|\{last\}|\{f\}|\{l\})", pattern.strip().lower())
    if not any(p in _PATTERN_TOKENS for p in pieces):
        return None
    out = []
    for piece in pieces:
        if piece in _PATTERN_TOKENS:
            out.append(_PATTERN_TOKENS[piece])
        elif piece:
            if not re.fullmatch(r"[a-z0-9._-]+", piece):
                return None
            out.append(re.escape(piece))
    return re.compile("^" + "".join(out) + r"(?P<suffix>\d{1,2})?$")


_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("5", "s"), ("3", "e"))


def _skeleton(label: str) -> str:
    for fake, real in _HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def _label(domain: str) -> tuple[str, str]:
    """(registrable label, public suffix) through the PSL ('example', 'com.br')."""
    reg = registrable_domain(domain) or domain
    label, _, suffix = reg.partition(".")
    return label, suffix


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Optimal-string-alignment distance with an early exit above ``cap``."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
        if min(cur) > cap:
            return cap + 1
    return prev[-1]


def _within(domain: str, base: str) -> bool:
    return domain == base or domain.endswith("." + base)


def domain_lookalike(candidate: str, own_domains: Any) -> tuple[str, str] | None:
    """Offline BEC lookalike check of a sender domain against own domains (cond 4): (reason, own domain)
    with reason 'tld_swap' | 'homoglyph' | 'hyphen_or_digit_variant' | 'edit_distance=N' |
    'own_label_inside', or None (an own domain, a subdomain of one, or unrelated)."""
    cand = normalise_domain(candidate)
    if cand is None:
        return None
    owns = [d for d in (normalise_domain(x) for x in own_domains or ()) if d]
    if any(_within(cand, own) for own in owns):
        return None
    cand_label, cand_suffix = _label(cand)
    for own in owns:  # the strongest signal first, whichever own domain it concerns
        own_label, own_suffix = _label(own)
        if len(own_label) >= 3 and cand_label == own_label and cand_suffix != own_suffix:
            return "tld_swap", own
    for own in owns:
        own_label, own_suffix = _label(own)
        if len(own_label) < 3:
            continue
        if cand_label != own_label and _skeleton(cand_label) == _skeleton(own_label):
            return "homoglyph", own
        if cand_label != own_label and cand_label.replace("-", "").rstrip("0123456789") == own_label:
            return "hyphen_or_digit_variant", own
        dist = _edit_distance(cand_label, own_label)
        if 0 < dist <= (1 if len(own_label) <= 5 else 2):
            return f"edit_distance={dist}", own
        if len(own_label) >= 4 and own_label in cand.split(".")[0] and cand_label != own_label:
            return "own_label_inside", own
    return None


def sender_plausible(email: Any, own_domains: Any, patterns: dict[str, str] | None = None) -> dict[str, Any]:
    """'Is this sender address plausible for our company?' (cond 4, offline, no request).

    verdict: 'plausible' | 'pattern_mismatch' (own domain, local part does not fit the own pattern) |
    'lookalike_domain' (BEC lookalike of an own domain) | 'other_domain' | 'invalid'."""
    addr = normalise_email(email)
    out: dict[str, Any] = {"verdict": "invalid", "domain_check": None, "own_domain": None, "pattern": None,
                           "pattern_match": None, "numeric_suffix": False}
    if addr is None:
        return out
    local, dom = addr.rsplit("@", 1)
    owns = [d for d in (normalise_domain(x) for x in own_domains or ()) if d]
    pats = {normalise_domain(k): v for k, v in (patterns or {}).items() if normalise_domain(k) and isinstance(v, str)}
    exact = next((d for d in owns if dom == d), None)
    if exact:
        out.update(domain_check="own", own_domain=exact)
        rx = hunter_pattern_regex(pats.get(exact))
        if rx is None:
            out["verdict"] = "plausible"
            return out
        m = rx.match(local)
        out.update(verdict="plausible" if m else "pattern_mismatch", pattern=pats.get(exact), pattern_match=bool(m),
                   numeric_suffix=bool(m and m.group("suffix")))
        return out
    sub = next((d for d in owns if _within(dom, d)), None)
    if sub:
        out.update(verdict="plausible", domain_check="own_subdomain", own_domain=sub)
        return out
    look = domain_lookalike(dom, owns)
    if look:
        out.update(verdict="lookalike_domain", domain_check=look[0], own_domain=look[1])
        return out
    out["verdict"] = "other_domain"
    return out


def split_person(value: Any, default_domain: Any = "") -> tuple[str, str, str] | None:
    """('First', 'Last', 'example.com') from 'First Last @ example.com' (or 'First Last <example.com>'),
    else from the name plus ``default_domain``; None when no two-token name or no domain is found."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    m = _PERSON_AT.match(text)
    if m:
        name, domain = m.group("name").strip(), normalise_domain(m.group("domain"))
    else:
        name, domain = text, normalise_domain(str(default_domain or ""))
    if domain is None:
        return None
    tokens = [t for t in name.split(" ") if t]
    if len(tokens) < 2 or len(name) > 120 or not all(_NAME_TOKEN.match(t) for t in tokens):
        return None
    return tokens[0], tokens[-1], domain


def _fetch(ctx: Any, endpoint: str, source: str, **params: Any) -> Any:
    """GET one allow-listed endpoint; returns the JSON body, or :data:`OPT_OUT_TEXT` for a 451 opt-out.
    Everything classified or non-2xx raises (NEEDS_KEY, RATE_LIMITED, QUOTA, BLOCKED, ERROR)."""
    url = hunter_url(endpoint, ctx.key(KEY_NAME), **params)
    resp = ctx.http.get(url, source=source, headers={"Accept": "application/json"})
    found = getattr(resp, "classification", None)
    if found is not None and getattr(found, "marker_id", "") == OPT_OUT_MARKER:
        return OPT_OUT_TEXT
    ctx.http.check(resp)
    return resp.json()


class _HunterBase(Module):
    """Shared declarations of the keyed Hunter modules (registered subclasses only)."""

    category = "email"
    reference = "https://hunter.io/api-documentation/v2"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hunter"
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    expected_latency = 1.5
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 604800  # sanitized bodies only (sensitive provider, A4 cap 7 days): credits are scarce
    default_enabled = False  # cond 6
    error_markers = HUNTER_MARKERS

    @staticmethod
    def _missing_key(res: ModuleResult, ctx: Any) -> ModuleResult | None:
        """NEEDS_KEY before any request when the key 'hunter' is not configured (cond 6)."""
        if str(ctx.key(KEY_NAME) or "").strip():
            return None
        return res.mark(Status.NEEDS_KEY, "Hunter needs the key 'hunter' (V3LUM_HUNTER_KEY / HUNTER_API_KEY)", reason_code="needs_key")


@register
class HunterIo(_HunterBase):
    name = "hunter_io"
    title = "Hunter.io own-domain address search"
    description = (
        "Address pattern, counts and published addresses of a VERIFIED own domain from Hunter.io domain-search "
        "(own-asset-only, keyed); addresses minimised and tagged privacy."
    )
    accepts = {T.DOMAIN}
    produces = {T.EMAIL}
    run_on = "own_assets_only"
    notice = (
        "Own-asset-only (A11 BR4): needs a txt_verified or attested org-profile domain. Employee addresses are personal "
        "data (LGPD): case retention, privacy tag, never bulk-exported. The email-verifier is never used. Key-terms: a "
        "company/team account on a plan recorded by legal."
    )
    sources = (SRC_DOMAIN, SRC_COUNT)
    max_requests = 2  # email-count + domain-search
    max_pivots = MAX_ADDRESSES

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = normalise_domain(entity.value)
        if domain is None:
            return res.mark(Status.SKIPPED, "not a domain", reason_code="not_applicable")
        org = getattr(ctx, "org", None)
        if org is None or not org.is_verified_domain(domain):  # defence in depth next to POL-08
            return res.mark(Status.SKIPPED, "own-asset-only source: needs a txt_verified or attested org-profile domain (v3lum org verify)",
                            reason_code="own_asset")
        missing = self._missing_key(res, ctx)
        if missing is not None:
            return missing
        count_body = _fetch(ctx, "email-count", SRC_COUNT, domain=domain)
        counts = parse_email_count(count_body) if isinstance(count_body, dict) else None
        if counts is None:
            return res.mark(Status.ERROR, "unexpected Hunter email-count answer: could not verify")
        search_body = _fetch(ctx, "domain-search", SRC_DOMAIN, domain=domain, limit=DOMAIN_SEARCH_LIMIT)
        found = parse_domain_search(search_body, own_domain=True) if isinstance(search_body, dict) else None
        if found is None:
            res.attr("email_counts", counts)
            res.raw = {"email_counts": counts}
            return res.mark(Status.ERROR, "unexpected Hunter domain-search answer: could not verify")
        res.raw = {"email_counts": counts, "pattern": found["pattern"], "total": found["total"], "returned": found["returned"],
                   "addresses": len(found["addresses"] or [])}
        res.attr("email_counts", counts)
        res.attr("email_pattern", found["pattern"])
        if not counts["total"] and not found["returned"] and not found["pattern"]:
            res.error = "Hunter lists no published address for this own domain"
            return res.mark(Status.EMPTY)
        addresses = found["addresses"] or []
        res.attr("own_domain_addresses", addresses)
        for item in addresses:
            res.pivot(T.EMAIL, item["email"], "published_address", confidence="probable", expand=False,
                      note="own-domain address Hunter found published on the web (privacy: case retention, never bulk-exported)")
        hint = ""
        if found["pattern"]:
            hint = (f" Record the pattern for the offline sender check: v3lum config set hunter_sender_check_patterns "
                    f"'{{\"{domain}\": \"{found['pattern']}\"}}'.")
        res.finding(
            "Own-domain address exposure (Hunter)",
            "info",
            f"Hunter counts {counts['total']} address(es) published on the web for {domain} ({counts['personal']} personal, "
            f"{counts['generic']} generic); pattern {found['pattern'] or 'unknown'}; {len(addresses)} address(es) shown "
            f"(privacy, case retention).{hint}",
            confidence="probable",
            criterion="Hunter email-count and domain-search answered for a txt_verified/attested own domain",
            data={"total": counts["total"], "personal": counts["personal"], "generic": counts["generic"],
                  "pattern": found["pattern"], "shown": len(addresses), "departments": found["department_counts"]},
            tags=["privacy", "exposure", "own_asset"],
            source=SRC_DOMAIN,
        )
        return res


@register
class HunterIoCount(_HunterBase):
    name = "hunter_io_count"
    title = "Hunter.io address counts (no addresses)"
    description = (
        "How many addresses Hunter.io has for a third-party domain or company (by type, department and seniority): "
        "counts only, never an address; case with a recorded purpose."
    )
    accepts = {T.DOMAIN, T.ORG}
    produces = frozenset()
    run_on = "any"
    notice = "Counts only (P090 cond 2): third-party domains never get addresses. Needs a case with a recorded purpose."
    sources = (SRC_COUNT,)
    max_requests = 1
    max_pivots = 0

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return res.mark(Status.SKIPPED, "Hunter email-count of a third party needs a case with a recorded purpose (--purpose)",
                            reason_code="privacy")
        if entity.type is T.DOMAIN:
            domain = normalise_domain(entity.value)
            if domain is None:
                return res.mark(Status.SKIPPED, "not a domain", reason_code="not_applicable")
            params = {"domain": domain}
        else:
            company = " ".join(str(entity.value).split())
            if not (2 <= len(company) <= 120):
                return res.mark(Status.SKIPPED, "company name too short or too long for Hunter", reason_code="not_applicable")
            params = {"company": company}
        missing = self._missing_key(res, ctx)
        if missing is not None:
            return missing
        body = _fetch(ctx, "email-count", SRC_COUNT, **params)
        counts = parse_email_count(body) if isinstance(body, dict) else None
        if counts is None:
            return res.mark(Status.ERROR, "unexpected Hunter email-count answer: could not verify")
        res.raw = {"email_counts": counts}
        if not counts["total"]:
            res.error = "Hunter counts no published address for this value"
            res.attr("email_counts", counts)
            return res.mark(Status.EMPTY)
        res.attr("email_counts", counts)
        res.finding(
            "Published address count (Hunter)",
            "info",
            f"Hunter counts {counts['total']} published address(es) ({counts['personal']} personal, {counts['generic']} generic); "
            "counts only - third-party addresses are never retrieved.",
            confidence="probable",
            criterion="Hunter email-count answered for the domain or company",
            data=counts,
            tags=["context_only"],
            source=SRC_COUNT,
        )
        return res


@register
class HunterIoFinder(_HunterBase):
    name = "hunter_io_finder"
    title = "Hunter.io address finder for a named person"
    description = (
        "One guessed address for an analyst-typed person at a domain ('First Last @ example.com') from Hunter.io "
        "email-finder: a generated hypothesis, never expanded."
    )
    accepts = {T.PERSON}
    produces = {T.EMAIL}
    run_on = "seeds"
    notice = (
        "Person lookups: analyst-typed names inside a case with a recorded purpose only, never default (A3). The "
        "guessed address is generated (expand=False): account-revealing modules never run on it."
    )
    sources = (SRC_FINDER,)
    max_requests = 1
    max_pivots = 1
    settings = {"hunter_io_finder_domain": ""}

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return split_person(entity.value, ctx.setting("hunter_io_finder_domain", "")) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", False):
            return res.mark(Status.SKIPPED, "email-finder runs only for a person the analyst typed", reason_code="privacy")
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return res.mark(Status.SKIPPED, "email-finder needs a case with a recorded purpose (--purpose)", reason_code="privacy")
        person = split_person(entity.value, ctx.setting("hunter_io_finder_domain", ""))
        if person is None:
            return res.mark(Status.SKIPPED, "needs 'First Last @ domain' (or setting hunter_io_finder_domain)", reason_code="not_applicable")
        first, last, domain = person
        missing = self._missing_key(res, ctx)
        if missing is not None:
            return missing
        body = _fetch(ctx, "email-finder", SRC_FINDER, domain=domain, first_name=first, last_name=last)
        if body == OPT_OUT_TEXT:
            res.error = OPT_OUT_TEXT
            res.raw = {"opt_out": True}
            return res.mark(Status.EMPTY)
        found = parse_email_finder(body) if isinstance(body, dict) else None
        if found is None:
            return res.mark(Status.ERROR, "unexpected Hunter email-finder answer: could not verify")
        if not found["email"]:
            res.error = f"Hunter did not find an address for this person at {domain}"
            res.raw = {"email": None}
            return res.mark(Status.EMPTY)
        res.raw = {k: found[k] for k in ("email", "score", "source_count", "first_seen", "last_seen", "provenance")}
        res.attr("guessed_address", dict(res.raw))
        res.pivot(T.EMAIL, found["email"], "guessed_email", confidence="possible", expand=False,
                  note="generated by Hunter email-finder (provenance 'generated'): never sent to account-revealing modules")
        res.finding(
            "Address guessed for the person (Hunter)",
            "info",
            f"Hunter's email-finder guesses an address at {domain} (score {found['score'] if found['score'] is not None else 'n/a'}, "
            f"{found['source_count']} web source(s)). A hypothesis, not a verified mailbox: never verified, never expanded.",
            confidence="possible",
            criterion="Hunter email-finder returned an address for the typed first and last name at the domain",
            data={"score": found["score"], "source_count": found["source_count"], "provenance": "generated"},
            tags=["privacy", "generated_address"],
            source=SRC_FINDER,
            observed_last=found["last_seen"],
        )
        return res


@register
class HunterSenderCheck(Module):
    name = "hunter_sender_check"
    title = "Sender plausibility for our company (offline)"
    description = (
        "Offline check of a sender address against the organisation's own domains and their Hunter address pattern: "
        "flags look-alike sender domains (BEC) and own-domain addresses that do not fit the pattern."
    )
    category = "email"
    accepts = {T.EMAIL}
    produces = frozenset()
    reference = "https://hunter.io/api-documentation/v2"
    notice = (
        "Offline: the address never leaves the machine. Own domains come from the org profile; address patterns from "
        "setting hunter_sender_check_patterns (the pattern hunter_io reports for a verified own domain)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    default_enabled = False  # P090 is opt-in (cond 6)
    settings = {"hunter_sender_check_patterns": {}}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        org = getattr(ctx, "org", None)
        own = [d.name for d in getattr(org, "domains", []) or [] if getattr(d, "name", "")]
        raw_patterns = ctx.setting("hunter_sender_check_patterns", {}) or {}
        patterns = {str(k): str(v) for k, v in raw_patterns.items()} if isinstance(raw_patterns, dict) else {}
        own += [d for d in (normalise_domain(k) for k in patterns) if d and d not in own]
        if not own:
            return res.mark(Status.SKIPPED, "no own domains: configure the org profile (v3lum org) or hunter_sender_check_patterns",
                            reason_code="config")
        verdict = sender_plausible(entity.value, own, patterns)
        res.raw = dict(verdict)
        res.attr("sender_check", verdict)
        if verdict["verdict"] == "lookalike_domain":
            res.finding(
                "Sender domain imitates an own domain",
                "medium",
                f"The sender domain looks like the own domain {verdict['own_domain']} ({verdict['domain_check']}): a typical "
                "business e-mail compromise (BEC) lure. Check the message headers before acting on it.",
                confidence="probable",
                criterion=f"offline lookalike check against the org-profile domains: {verdict['domain_check']}",
                data=dict(verdict),
                tags=["typosquat", "suspicious"],
            )
        elif verdict["verdict"] == "pattern_mismatch":
            res.finding(
                "Own-domain sender does not fit the address pattern",
                "low",
                f"The address is on the own domain {verdict['own_domain']} but its local part does not follow the pattern "
                f"{verdict['pattern']}: a role mailbox, an exception or a spoofed/compromised sender. Check the headers.",
                confidence="possible",
                criterion="offline match of the local part against the own-domain Hunter pattern",
                data=dict(verdict),
                tags=["suspicious"],
            )
        elif verdict["verdict"] == "plausible":
            res.finding(
                "Sender address plausible for our company",
                "info",
                f"On {verdict['own_domain']}" + (f", matching the pattern {verdict['pattern']}" if verdict["pattern"] else "")
                + ": plausible, not proof (headers decide whether it was spoofed).",
                confidence="possible",
                criterion="offline own-domain and pattern check",
                data=dict(verdict),
            )
        else:
            res.error = "not an own domain and no look-alike of one"
            return res.mark(Status.EMPTY)
        return res
