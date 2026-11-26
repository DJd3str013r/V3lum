"""Declarative JSON/NDJSON/CSV/RSS/XML/HTML-JSON collectors (P331): the spec compiler.

Module-author contract v2, section 17 (docs/MODULE_GUIDE.md; the names added by this package are
listed in docs/contract_additions/WP12.md and the file format in v3lum/data/specs/README.md).

A *declarative spec* is one JSON file ``v3lum/data/specs/<name>.json`` (schema ``v3lum.spec/1``)
that describes one GET lookup against a public API and how its answer maps to the shared
vocabulary. :func:`compile_spec` turns it into a **real Module subclass** whose class body declares
every contract field of the spec, so ``@register`` (the contract lint), the policy gate, quotas,
status semantics, the sanitizer and the registry contract test apply exactly as to a hand-written
module. :func:`load_specs` (called by ``module.load_modules``) compiles the bundled specs and the
user specs of ``~/.v3lum/specs``.

Safety rules enforced by the compiler (team rules and P331 final conditions):

* the request URL is ``https://`` + one **literal** declared host + a path/query template: the host
  can never be templated, so a passive spec never contacts the target (P331 cond 3), and the
  rendered URL is re-checked before every request (scheme, host, no userinfo or port); redirects
  are host-checked by ``ctx.http`` against the spec's literal hosts only (its provider may not
  declare ``hosts_from_settings``);
* placeholders come from a whitelist (``{value}`` ``{value_q}`` ``{value_qp}`` ``{domain}``
  ``{user}`` ``{b64}``), are type-validated against ``accepts`` and URL-encoded, and are substituted
  with ``re.sub`` (never ``str.format``; there is no eval/exec anywhere);
* GET only; headers are literal values or ``{key:<name>}`` references to the spec's registered
  keys (credentials never appear literally: a credential-like header or parameter name - 'key',
  'token', 'secret', 'session', 'auth'... - never takes a literal value); request bodies, cookies,
  logins and CAPTCHA handling cannot be expressed; account-enumeration, people-search and submission
  endpoints are refused by ``lint.forbidden_probe`` (rules 2, 4 and 7);
* the P321 classifier runs before anything is parsed (``ctx.http.check``): challenge, quota and
  rate-limit pages - also inside HTTP-200 bodies, through the spec's ``error_markers`` - are
  'could not verify', never an absence; a challenge ends BLOCKED with the spec's manual link (A9);
  so are answers that are not the data: HTTP 202/206, an HTML/JSON page served to a CSV spec, an
  (X)HTML page served to an XML spec, unparsable or truncated bodies;
* absence (``presence`` 'absent') only on positive evidence: the ``absent`` rule or a documented
  ``absent_statuses`` code (rule 5);
* regexes are bounded and reviewed: at most 200 characters, compiled, no backreferences, no
  nested or alternating repeats, at most one unbounded quantifier (none in error markers), a
  worst-case backtracking cost within budget (no optional or variable repeat inside a repeat), a
  ReDoS smoke test at load, and they only ever see 512 characters of a value;
* hostile answers never crash or stall a run: non-finite numbers become null, huge integers are no
  number, result values are size-bounded and the mapping stops at the run deadline or on cancel;
* XML is parsed with expat directly: DOCTYPE and entity declarations are refused by the parser
  handlers before anything is declared (no entity expansion, no external entities);
* A3/A5/A8: unknown-tier or unknown-terms specs ship ``default_enabled: false`` and unknown-tier
  specs accept IOC types only (never PERSONAL_TYPES or company ids); username/handle specs
  (community profile sites, also an e-mail's local part sent as a handle) follow the A5 rules
  (analyst-typed seeds only, explicit presence and absence markers, one request without retries or
  redirects, >= 1 s politeness, pivots never expanded, POSSIBLE confidence, high-collision handles
  flagged, never default); a spec receiving person names is never default (A3);
* user specs load only from an owner-only directory (``paths.insecure_reasons``, AR12), every spec
  needs its fixtures (``ok.*``, ``error_in_200.*``, ``expected.json``) and passes the P327 data lint;
  a user spec must also give its own expected.json on its fixtures, run offline at load
  (:func:`check_fixtures`: no CI runs it); a spec sends only its own provider's keys;
  each file loads in isolation (one broken spec never stops the others) and a refused file never
  reports under the name of a registered module (the policy gate would skip that module);
* specs that fail their health check on 7 consecutive days are auto-disabled (A3/P331 cond 9).

Adapted design: the declarative site pattern of Machinae
(https://github.com/HurricaneLabs/machinae, commit d5deae8d231810c47b2e89a9df8a20ebe358912b,
MIT licence, Copyright (c) 2015 Hurricane Labs): request {url template, params, method, headers,
ignored_status_codes}, results [{key dotted.path, pretty_name, regex, match_all, format}],
multi_match/onlyif, pagination and multi_json (NDJSON). It is re-implemented here from the
documentation (no Machinae code is copied) and Machinae's site list is not ported (notice fragment
v3lum/data/notices/machinae.json).
"""

from __future__ import annotations

import base64
import contextlib
import csv
import datetime as _dt
import email.utils
import io
import itertools
import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, quote_plus, urlencode, urlsplit
from xml.parsers import expat

from v3lum.core import lint as _lint
from v3lum.core import providers as _providers
from v3lum.core import vocab as _vocab
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, EntityType, url_host
from v3lum.core.http import (
    NEVER_ABSENT_STATUS,
    AuthRequired,
    Blocked,
    Cancelled,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import Confidence, ModuleResult, Opsec, Severity, Status, valid_reason
from v3lum.core.module import (
    ACCESS_MODELS,
    BENIGN_VALUES,
    CATEGORIES,
    RESERVED_NAMES,
    RUN_ON,
    TERMS,
    HealthCheck,
    HealthResult,
    Module,
    RegistrationError,
    register,
)
from v3lum.core.redact import CREDENTIAL_HEADERS, KEY_PARAMS

try:  # Python 3.11+
    from re import _constants as _sre_constants
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

__all__ = [
    "AUTO_DISABLE_DAYS",
    "FORMATS",
    "MARKER_COST_BUDGET",
    "PLACEHOLDERS",
    "REGEX_COST_BUDGET",
    "SPEC_SCHEMA",
    "SpecError",
    "SpecModule",
    "auto_disabled",
    "check_fixtures",
    "compile_spec",
    "disabled",
    "extract",
    "fixture_problems",
    "load_specs",
    "failing_days",
    "loaded",
    "regex_problems",
    "validate_spec",
]

log = logging.getLogger("v3lum.specs")

#: Schema id of declarative spec files (module contract v2, section 17).
SPEC_SCHEMA = "v3lum.spec/1"
#: Bundled specs (``<name>.json``; files starting with '_' or '.' are ignored).
BUNDLED_DIR: Path = Path(__file__).resolve().parent.parent / "data" / "specs"
#: Repository root (bundled spec origins are recorded relative to it).
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
#: Fixtures of the bundled specs: ``tests/fixtures/specs/<name>/{ok.*, error_in_200.*, expected.json}``.
BUNDLED_FIXTURES_DIR: Path = REPO_ROOT / "tests" / "fixtures" / "specs"
#: Directory of user specs under the V3LUM home (``~/.v3lum/specs``; fixtures in ``specs/<name>/``).
USER_DIR_NAME = "specs"
#: Answer formats a spec may declare.
FORMATS: tuple[str, ...] = ("json", "ndjson", "csv", "rss", "xml", "html_json")
#: Whitelisted request placeholders (substituted with re.sub, never str.format).
PLACEHOLDERS: dict[str, str] = {
    "value": "the entity value, percent-encoded (':' and '@' kept)",
    "value_q": "the entity value, percent-encoded (nothing kept)",
    "value_qp": "the entity value, form-encoded (quote_plus)",
    "domain": "the domain: domain/onion itself, e-mail domain or URL host name",
    "user": "the account part: e-mail local part, username or handle",
    "b64": "base64 of the entity value (percent-encoded)",
}
#: Placeholders valid only for some entity types (checked against every accepted type).
PLACEHOLDER_TYPES: dict[str, frozenset[EntityType]] = {
    "domain": frozenset({EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL, EntityType.ONION}),
    "user": frozenset({
        EntityType.EMAIL, EntityType.USERNAME, EntityType.SOCIAL_ACCOUNT, EntityType.TELEGRAM_HANDLE,
        EntityType.FEDIVERSE_HANDLE, EntityType.BSKY_HANDLE, EntityType.STEAM_PROFILE,
    }),
}
#: Account/handle types: a spec accepting one of them is a profile-site spec (A5 username rules).
PROFILE_TYPES: frozenset[EntityType] = frozenset({
    EntityType.USERNAME, EntityType.SOCIAL_ACCOUNT, EntityType.TELEGRAM_HANDLE, EntityType.FEDIVERSE_HANDLE,
    EntityType.BSKY_HANDLE, EntityType.STEAM_PROFILE,
})
#: Types a spec never sends anywhere: CPF (team rule 4), secrets, blobs and files.
FORBIDDEN_TYPES: frozenset[EntityType] = frozenset({
    EntityType.CPF, EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS,
}) | SECRET_TYPES
#: Result value conversions (``results[].format``).
RESULT_FORMATS: tuple[str, ...] = ("str", "int", "float", "bool", "lower", "as_list", "as_time")
#: Pagination ceiling (P331: at most 5 pages per lookup).
MAX_PAGES = 5
#: Regex length ceiling (characters) and the longest text a spec regex ever sees.
REGEX_MAX_LENGTH = 200
MAX_REGEX_INPUT = 512
#: Values kept per result rule and run; records read per page; answer size parsed.
MAX_VALUES = 100
#: Longest text value and largest object/list value (JSON bytes) a result rule keeps.
MAX_VALUE_CHARS = 4096
MAX_VALUE_JSON = 64 * 1024
MAX_RECORDS = 10_000
MAX_DOC_BYTES = 5 * 1024 * 1024
#: Parsed pages kept as evidence (serialised JSON size).
MAX_RAW_BYTES = 1024 * 1024
#: Largest spec file (and expected.json) the loader reads.
_MAX_SPEC_BYTES = 512 * 1024
#: A spec failing its health check on this many consecutive days is auto-disabled (P331 cond 9).
AUTO_DISABLE_DAYS = 7
#: Profile-site specs (A5): politeness floor and per-site timeout in seconds.
PROFILE_MIN_INTERVAL = 1.0
PROFILE_TIMEOUT = 10.0
#: Handles shorter than this are high-collision (A5: '<= 4 chars ... flagged high-collision').
PROFILE_COLLISION_LENGTH = 5
#: 2xx answers that are not the requested data (could not verify, never 'nothing found').
_NOT_READY_STATUSES: dict[int, str] = {
    202: "the request was accepted but the answer is not ready yet: could not verify",
    206: "partial content: the answer is incomplete: could not verify",
}

#: Top-level fields every spec declares (section 17; null/empty where the field allows it).
REQUIRED_FIELDS: tuple[str, ...] = (
    "schema", "name", "title", "description", "category", "accepts", "produces", "provider", "sources", "hosts",
    "terms", "disclosure", "opsec", "access_model", "run_on", "requires_keys", "optional_keys", "max_requests",
    "expected_latency", "min_interval", "cache_ttl", "absent_statuses", "error_markers", "manual_link",
    "default_enabled", "health_check", "request", "format", "results", "multi_match", "found", "absent", "findings",
)
#: Optional top-level fields (WP12 additions, docs/contract_additions/WP12.md); ``x_*`` and ``$comment`` are ignored.
OPTIONAL_FIELDS: tuple[str, ...] = ("reference", "tags", "notice", "requires_egress", "notes")
REQUEST_FIELDS: tuple[str, ...] = ("url", "method", "params", "headers", "ignored_status_codes", "paginate")
PAGINATE_FIELDS: tuple[str, ...] = ("param", "start", "step", "max_pages", "stop_when_empty")
RESULT_FIELDS: tuple[str, ...] = ("key", "pretty_name", "attribute", "tag", "pivot", "regex", "match_all", "format")
PIVOT_FIELDS: tuple[str, ...] = ("type", "relation", "expand", "confidence")
RULE_FIELDS: tuple[str, ...] = ("path", "equals", "regex")
FINDING_FIELDS: tuple[str, ...] = ("when", "title", "severity", "criterion", "tags", "confidence")
WHEN_FIELDS: tuple[str, ...] = ("path", "equals", "regex", "gte")
HEALTH_FIELDS: tuple[str, ...] = ("etype", "value", "expect")
HEALTH_EXPECT: tuple[str, ...] = ("ok", "empty")
#: Request fields Machinae knows that the spec language refuses on purpose (rule 7, team rule 1).
_REFUSED_REQUEST_FIELDS: dict[str, str] = {
    "data": "request bodies cannot be expressed (GET lookups only, rule 7)",
    "json": "request bodies cannot be expressed (GET lookups only, rule 7)",
    "body": "request bodies cannot be expressed (GET lookups only, rule 7)",
    "auth": "logins cannot be expressed (team rule 1): API keys go in headers as {key:<name>}",
    "cookies": "cookies cannot be expressed (team rule 1: no borrowed cookies or sessions)",
    "verify_ssl": "TLS verification is always on (A12)",
    "decompress": "answers are parsed as served",
}
#: Header names a spec may never set (cookies, hop-by-hop, identity and routing headers).
FORBIDDEN_HEADERS: frozenset[str] = frozenset({
    "cookie", "set-cookie", "proxy-authorization", "host", "content-length", "content-type", "transfer-encoding",
    "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer", "expect", "user-agent", "referer",
    "origin", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "via",
})
#: Words allowed before a ``{key:<name>}`` reference in a header value.
KEY_PREFIXES: tuple[str, ...] = ("Bearer", "Token", "Key", "ApiKey", "Api-Key", "Bot", "SSWS")
#: Header/parameter names that carry a credential (besides redact.CREDENTIAL_HEADERS/KEY_PARAMS): a
#: name containing one of the fragments, or one of the words as a '-'/'_'/'.'-separated token
#: ('X-RapidAPI-Key', 'Private-Token', 'api_token', 'access_key', 'session_id'). Such values are
#: never literal in a spec: a literal one would be a secret in the spec file that the central
#: redactor does not know (logs, cache keys, evidence); headers take '{key:<name>}' instead.
_CREDENTIAL_NAME_PARTS: tuple[str, ...] = (
    "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key", "secret", "token", "passw", "credential",
)
_CREDENTIAL_NAME_WORDS: frozenset[str] = frozenset({
    "key", "auth", "authorization", "authentication", "session", "sessionid", "sid", "sig", "signature", "cookie",
    "bearer", "jwt", "otp", "pwd", "pass", "pin",
})


def _credential_like(name: str) -> bool:
    """True when a header or query-parameter name carries a credential (see _CREDENTIAL_NAME_PARTS)."""
    low = str(name).strip().lower()
    if any(part in low for part in _CREDENTIAL_NAME_PARTS):
        return True
    return any(token in _CREDENTIAL_NAME_WORDS for token in re.split(r"[^a-z0-9]+", low) if token)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_SOURCE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}\.[a-z][a-z0-9_]{0,63}$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")
_KEY_REF_RE = re.compile(r"^(?:(" + "|".join(re.escape(p) for p in KEY_PREFIXES) + r") )?\{key:([a-z][a-z0-9_]{1,63})\}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SEGMENT_RE = re.compile(r"^(?:\[\]|\*|[^.\[\]\x00-\x1f\x7f]{1,64}(?:\[\])?)$")
_URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", re.S)
_MAX_TEXT = 1000

_LOCK = threading.RLock()
#: Specs registered by the last load_specs(): name -> class.
_LOADED: dict[str, type[Module]] = {}
#: Auto-disabled specs of the last load: name -> reason.
_DISABLED: dict[str, str] = {}
_SKIP = object()


class SpecError(ValueError):
    """A declarative spec was refused. ``name`` is the spec name, ``problems`` lists every problem as
    '<field>: <problem>' (validation) or the registration error of ``@register``."""

    def __init__(self, name: str, problems: Iterable[str]) -> None:
        self.name = str(name or "?")
        self.problems = [str(p) for p in problems] or ["invalid spec"]
        super().__init__(f"spec {self.name}: " + "; ".join(self.problems))


class _NotApplicable(ValueError):
    """A placeholder cannot be computed for this entity (e.g. {domain} of a URL with an IP host)."""


class _ParseError(ValueError):
    """The answer could not be parsed in the declared format (could not verify)."""


# ======================================================================================
# Regex safety (bounded, reviewed, ReDoS-tested)
# ======================================================================================

_REPEAT_OPS = tuple(getattr(_sre_constants, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(_sre_constants, n))
_GROUPREF_OPS = tuple(getattr(_sre_constants, n) for n in ("GROUPREF", "GROUPREF_EXISTS", "GROUPREF_IGNORE", "GROUPREF_LOC_IGNORE", "GROUPREF_UNI_IGNORE") if hasattr(_sre_constants, n))
_ASSERT_OPS = tuple(getattr(_sre_constants, n) for n in ("ASSERT", "ASSERT_NOT") if hasattr(_sre_constants, n))
_ATOMIC = getattr(_sre_constants, "ATOMIC_GROUP", None)
_BRANCH = _sre_constants.BRANCH
_SUBPATTERN = _sre_constants.SUBPATTERN
_MAXREPEAT = _sre_constants.MAXREPEAT
#: A repeat whose maximum exceeds this counts as unbounded; nested repeat products stay below it.
_UNBOUNDED_AT = 64
_PROBE_UNITS = ("a", "A", "0", "1", " ", ".", "-", "_", "/", ":", "@", "=", "a1", "a ", "\t", "aA0.")
_PROBE_SECONDS = 0.25
#: Worst-case backtracking budget of one regex (see :func:`_backtracking_cost`): result and rule
#: regexes see at most 512 characters; error markers scan up to 64 KB of a body (128 times more),
#: so their budget is 128 times smaller. Patterns within budget search 512 adversarial characters in
#: well under 0.1 s; exponential shapes ('(a?){24}', '(a{1,2}){24}') and stacked overlapping
#: quantifiers ('\w{0,64}\w{0,64}\w{0,64}') are far above it.
REGEX_COST_BUDGET = 1 << 15
MARKER_COST_BUDGET = 1 << 8
_COST_CEILING = 1e12


def _backtracking_cost(items: Any) -> float:
    """Upper estimate of the ways a parsed pattern can split one input (the backtracking work per
    start position): sequences multiply, alternatives add, a repeat contributes its count range (an
    unbounded maximum counts as the 512-character input), and a repeat of a variable sub-pattern
    multiplies the sub-pattern's own cost once per repetition (the exponential ReDoS shapes)."""
    total = 1.0
    for op, av in items:
        if op in _REPEAT_OPS:
            low, high, sub = av
            inner = _backtracking_cost(sub)
            hi = MAX_REGEX_INPUT if (high == _MAXREPEAT or high > MAX_REGEX_INPUT) else int(high)
            lo = min(int(low), hi)
            if inner <= 1.0:
                part = float(hi - lo + 1)
            else:
                part = 0.0
                for count in range(lo, hi + 1):
                    part += _COST_CEILING if count * math.log10(inner) >= 12 else inner ** count
                    if part >= _COST_CEILING:
                        break
            total *= part
        elif op is _BRANCH or op == _BRANCH:
            total *= sum(_backtracking_cost(alternative) for alternative in av[1])
        elif op == _SUBPATTERN:
            total *= _backtracking_cost(av[-1])
        elif op in _ASSERT_OPS:
            total *= _backtracking_cost(av[1])
        elif _ATOMIC is not None and op == _ATOMIC:
            total *= _backtracking_cost(av)
        if total >= _COST_CEILING:
            return _COST_CEILING
    return total


def regex_problems(pattern: Any, *, max_unbounded: int = 1, budget: int | None = None) -> list[str]:
    """Why ``pattern`` is not a bounded, reviewed spec regex (empty list = acceptable).

    Rules: a non-empty string of at most 200 characters that compiles; no backreferences or
    conditional groups; no repeat nested in a repeat unless both are small and bounded (product of
    the maxima <= 64); no alternation inside a repeated group (use a character class); at most
    ``max_unbounded`` unbounded quantifiers (``+``, ``*``, ``{n,}`` or a maximum above 64) in the
    whole pattern (error markers allow none: they scan up to 64 KB of a body); a worst-case
    backtracking cost within ``budget`` (default :data:`REGEX_COST_BUDGET`, or
    :data:`MARKER_COST_BUDGET` when no unbounded quantifier is allowed), which refuses optional or
    variable repeats inside repeats ('(a?){24}') and stacked overlapping quantifiers; and a ReDoS
    smoke test on adversarial 512-character inputs (run only on patterns within budget, so the test
    itself always ends quickly).
    """
    if not isinstance(pattern, str) or not pattern:
        return ["regex must be a non-empty string"]
    if len(pattern) > REGEX_MAX_LENGTH:
        return [f"regex longer than {REGEX_MAX_LENGTH} characters"]
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return [f"regex does not compile ({exc})"]
    except (RecursionError, OverflowError, ValueError) as exc:  # pragma: no cover - pathological nesting
        return [f"regex cannot be compiled ({type(exc).__name__})"]
    try:
        tree = _sre_parse.parse(pattern)
    except Exception as exc:  # pragma: no cover - compile() succeeded, the parser agrees
        return [f"regex cannot be analysed ({exc})"]
    if budget is None:
        budget = REGEX_COST_BUDGET if max_unbounded >= 1 else MARKER_COST_BUDGET
    problems: set[str] = set()
    unbounded = 0

    def walk(items: Any, outer: int) -> None:
        nonlocal unbounded
        for op, av in items:
            if op in _GROUPREF_OPS:
                problems.add("backreferences and conditional groups are not allowed")
            elif op in _REPEAT_OPS:
                _low, high, sub = av
                is_unbounded = high == _MAXREPEAT or high > _UNBOUNDED_AT
                if is_unbounded:
                    unbounded += 1
                if outer > 1 and high > 1 and (is_unbounded or outer * high > _UNBOUNDED_AT):
                    problems.add("nested repeats ('(a+)+', '(\\w+\\s?)*') are not allowed: catastrophic backtracking (ReDoS)")
                walk(sub, _UNBOUNDED_AT + 1 if is_unbounded else max(outer, 1) * max(high, 1))
            elif op is _BRANCH or op == _BRANCH:
                if outer > 1:
                    problems.add("alternation inside a repeated group is not allowed (use a character class)")
                for alternative in av[1]:
                    walk(alternative, outer)
            elif op == _SUBPATTERN:
                walk(av[-1], outer)
            elif op in _ASSERT_OPS:
                walk(av[1], outer)
            elif _ATOMIC is not None and op == _ATOMIC:
                walk(av, outer)

    walk(tree, 1)
    if unbounded > max_unbounded:
        problems.add(
            f"at most {max_unbounded} unbounded quantifier(s) ('+', '*', '{{n,}}' or a maximum above {_UNBOUNDED_AT}) per regex "
            f"(found {unbounded}); use bounded ones such as \\d{{1,6}}"
        )
    cost = _backtracking_cost(tree)
    if cost > budget:
        shown = f"{cost:.0f}" if cost < _COST_CEILING else "unbounded"
        problems.add(
            f"worst-case backtracking cost {shown} above {budget} (ReDoS): no optional or variable repeat inside a repeated "
            "group ('(a?){24}', '(\\w{1,2}){24}') and fewer overlapping quantifiers in a row"
        )
    if not problems and not _probe_fast(compiled):
        problems.add("regex is slow on adversarial input (ReDoS smoke test)")
    return sorted(problems)


def _probe_fast(compiled: re.Pattern[str]) -> bool:
    """ReDoS smoke test: every search over adversarial 512-character strings stays fast."""
    for unit in _PROBE_UNITS:
        text = (unit * (MAX_REGEX_INPUT // len(unit) + 1))[: MAX_REGEX_INPUT - 2] + "\x00!"
        start = time.perf_counter()
        compiled.search(text)
        if time.perf_counter() - start > _PROBE_SECONDS:
            return False
    return True


# ======================================================================================
# Minimal dotted-path extractor (no JSONPath library)
# ======================================================================================


def _path_problem(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return "must be a non-empty dotted path ('a.b', 'items[].name', '@' for the record itself)"
    if len(path) > 200:
        return "path longer than 200 characters"
    if path == "@":
        return ""
    for segment in path.split("."):
        if not _SEGMENT_RE.match(segment) or segment != segment.strip():
            return f"invalid path segment {segment!r} (names, '*', 'name[]', '[]' or list indexes separated by '.')"
    return ""


def extract(document: Any, path: str) -> list[Any]:
    """Values at a dotted ``path`` of a parsed document (the minimal extractor of P331).

    ``'a.b'`` walks object keys; ``'items[]'`` iterates a list (a single object counts as a
    one-element list, as XML gives for one child); ``'[]'`` iterates the root list; ``'*'`` takes
    every value of an object (or every item of a list); a numeric segment indexes a list; ``'@'``
    is the document itself. Missing keys give no value; at most 10000 values are returned.
    """
    if path == "@":
        return [document]
    current: list[Any] = [document]
    for segment in path.split("."):
        many = segment.endswith("[]")
        name = segment[:-2] if many else segment
        nxt: list[Any] = []
        for item in current:
            if name == "":
                values = [item]
            elif name == "*":
                values = list(item.values()) if isinstance(item, dict) else list(item) if isinstance(item, list) else []
            elif isinstance(item, dict):
                values = [item[name]] if name in item else []
            elif isinstance(item, list) and name.isascii() and name.isdigit():  # '²' is a digit for str.isdigit()
                index = int(name)
                values = [item[index]] if index < len(item) else []
            else:
                values = []
            for value in values:
                if many:
                    if isinstance(value, list):
                        nxt.extend(value)
                    elif value is not None:
                        nxt.append(value)
                else:
                    nxt.append(value)
            if len(nxt) >= MAX_RECORDS:
                break
        current = nxt[:MAX_RECORDS]
        if not current:
            break
    return current


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return str(int(value))
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            return "<unserialisable value>"
    return str(value)


def _equals(value: Any, expected: Any) -> bool:
    """Rule equality, tolerant of JSON scalar typing like the P321 markers ("0" == 0, "true" == true,
    case-insensitive text); objects and lists compare structurally."""
    if isinstance(value, (dict, list)) or isinstance(expected, (dict, list)):
        return value == expected
    left = "null" if value is None else _text(value).strip().lower()
    right = "null" if expected is None else _text(expected).strip().lower()
    return left == right


def _number(value: Any) -> float | None:
    """A finite float for a JSON number or numeric text, else None (huge integers included: a
    hostile answer never crashes a run)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            number = float(value)
        elif isinstance(value, str) and len(value) <= 64:
            number = float(value.strip())
        else:
            return None
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _bounded(value: Any) -> Any:
    """A result value of bounded size: text is cut to MAX_VALUE_CHARS (marked with an ellipsis), an
    object or list larger than MAX_VALUE_JSON bytes of JSON is dropped (a hostile answer never
    bloats the case store, reports or the terminal)."""
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + "\u2026"
    if isinstance(value, (dict, list)):
        try:
            size = len(json.dumps(value, ensure_ascii=False))
        except (TypeError, ValueError, RecursionError):
            return _SKIP
        if size > MAX_VALUE_JSON:
            return _SKIP
    return value


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().lower() not in ("false", "0", "null", "none", "no")
    return value is not None and value is not False and value != [] and value != {} and value != 0


# ======================================================================================
# Parsers (json, ndjson, csv, rss, xml, html_json)
# ======================================================================================


def _decode(content: bytes, text: str) -> str:
    if len(content) > MAX_DOC_BYTES:
        raise _ParseError(f"answer larger than {MAX_DOC_BYTES // (1024 * 1024)} MB")
    return text[1:] if text.startswith("﻿") else text


def _finite_float(text: str) -> float | None:
    number = float(text)
    return number if math.isfinite(number) else None  # '1e400' would be inf: kept as no value


def _json_loads(text: str) -> Any:
    """json.loads for provider answers: NaN/Infinity constants and out-of-range floats become null,
    so a parsed answer never carries a non-finite number into attributes, findings or evidence."""
    return json.loads(text, parse_constant=lambda _name: None, parse_float=_finite_float)


def _lines(text: str) -> list[str]:
    """Physical lines split on LF only (CRLF tolerated). str.splitlines() would also split on U+2028,
    U+2029, VT, FF and other separators that are legal inside JSON strings and CSV fields."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def _parse_json(text: str) -> Any:
    if not text.strip():
        raise _ParseError("empty answer where JSON was expected")
    try:
        return _json_loads(text)
    except ValueError as exc:
        raise _ParseError(f"invalid JSON ({exc.__class__.__name__})") from None


def _parse_ndjson(text: str) -> list[Any]:
    out: list[Any] = []
    for number, line in enumerate(_lines(text), start=1):
        if not line.strip():
            continue
        if len(out) >= MAX_RECORDS:
            break
        try:
            out.append(_json_loads(line))
        except ValueError:
            raise _ParseError(f"invalid NDJSON line {number}") from None
    return out


#: The first characters of an answer that is no CSV at all: an HTML/XML page or a JSON document (an
#: error page or error object served with HTTP 200 is 'could not verify', never zero rows).
_NOT_CSV_RE = re.compile(r"^\s*(?:<|\{|\[\s*[\[{\"\]])")


def _parse_csv(text: str) -> list[dict[str, str]]:
    """Rows as objects keyed by the header row (the first line that is not blank or a '#' comment).

    An answer that starts like HTML/XML or a JSON object/array is refused (_ParseError): a
    maintenance page or a JSON error served with HTTP 200 would otherwise read as rows of noise or as
    'no rows' (rule 5)."""
    if _NOT_CSV_RE.match(text[:256]):
        raise _ParseError("the answer is HTML/XML or JSON, not CSV (an error page served with HTTP 200?)")
    lines = [line for line in _lines(text) if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return []
    try:
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        rows: list[dict[str, str]] = []
        for row in itertools.islice(reader, MAX_RECORDS):
            rows.append({str(k).strip(): (v.strip() if isinstance(v, str) else "") for k, v in row.items() if k is not None})
    except csv.Error as exc:
        raise _ParseError(f"invalid CSV ({exc})") from None
    return rows


_XML_MAX_ELEMENTS = 100_000
_XML_MAX_DEPTH = 64


def _xml_local(tag: str) -> str:
    """Local part of an element name: 'rdf:RDF' -> 'RDF', '{uri}feed' -> 'feed'."""
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _child(obj: Mapping[str, Any], local: str) -> Any:
    """The child of a parsed element whose (possibly prefixed) tag has the local name ``local``."""
    if local in obj:
        return obj[local]
    return next((value for key, value in obj.items() if not key.startswith(("@", "#")) and _xml_local(key) == local), None)


def _parse_xml(content: bytes) -> Any:
    """XML -> nested objects with expat directly: no DTD, no entity declarations, no external entities.

    The expat handlers refuse a DOCTYPE (and any entity declaration) the moment the parser meets it,
    before anything is declared or expanded, and parameter-entity parsing is off, so no entity is
    ever expanded and no external entity or DTD is fetched; an undefined entity is a parse error.
    Text that merely mentions '<!DOCTYPE' or '<!ENTITY' (a CDATA section of an advisory feed) is
    data, not a declaration. Element names keep their prefix ('dc:date').

    An element becomes its text when it has no attributes and no children, else an object with
    '@attr' keys, one key per child tag (a list when the tag repeats) and '#text' for mixed text.
    The result is ``{root_tag: root_object}``.
    """
    parser = expat.ParserCreate()
    with contextlib.suppress(AttributeError):  # pragma: no branch - present on every CPython build
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack: list[tuple[str, dict[str, str], dict[str, list[Any]], list[str]]] = []
    root: list[tuple[str, Any]] = []
    count = 0

    def refuse(*_args: Any) -> None:
        raise _ParseError("XML with a DOCTYPE or entity declarations is refused (no entity expansion)")

    def start(tag: str, attrs: dict[str, str]) -> None:
        nonlocal count
        count += 1
        if count > _XML_MAX_ELEMENTS or len(stack) >= _XML_MAX_DEPTH:
            raise _ParseError("XML document too large or too deep")
        stack.append((tag, dict(attrs), {}, []))

    def end(_tag: str) -> None:
        name, attrs, children, texts = stack.pop()
        text = "".join(texts).strip()
        if not attrs and not children:
            value: Any = text
        else:
            obj: dict[str, Any] = {f"@{k}": v for k, v in attrs.items()}
            for child, values in children.items():
                obj[child] = values[0] if len(values) == 1 else values
            if text:
                obj["#text"] = text
            value = obj
        if stack:
            stack[-1][2].setdefault(name, []).append(value)
        else:
            root.append((name, value))

    def chars(data: str) -> None:
        if stack:
            stack[-1][3].append(data)

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(content, True)
    except expat.ExpatError as exc:
        raise _ParseError(f"invalid XML ({expat.ErrorString(exc.code)})") from None
    if not root:
        raise _ParseError("empty XML document")
    name, value = root[0]
    return {name: value}


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _parse_rss(content: bytes) -> dict[str, Any]:
    """RSS 2.0, RSS 1.0 (``rdf:RDF``) or Atom -> ``{"channel": {...}, "items": [...]}`` (roots and
    item elements are matched by their local name, so prefixed feeds parse too)."""
    tree = _parse_xml(content)
    (root_name, root), = tree.items()
    root = root if isinstance(root, dict) else {}
    kind = _xml_local(root_name)
    if kind == "rss":
        channel = _child(root, "channel")
        channel = channel if isinstance(channel, dict) else {}
        items = _as_list(_child(channel, "item"))
        meta = {k: v for k, v in channel.items() if _xml_local(k) != "item"}
    elif kind == "RDF":
        meta = _child(root, "channel")
        meta = meta if isinstance(meta, dict) else {}
        items = _as_list(_child(root, "item"))
    elif kind == "feed":
        items = _as_list(_child(root, "entry"))
        meta = {k: v for k, v in root.items() if _xml_local(k) != "entry"}
    else:
        raise _ParseError(f"not an RSS/Atom feed (root element {root_name!r})")
    return {"channel": meta, "items": items[:MAX_RECORDS]}


class _ScriptJson(HTMLParser):
    """Collects the __NEXT_DATA__ and application/ld+json script contents of an HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.next_data: list[str] = []
        self.ld_json: list[str] = []
        self._kind = ""
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script" or self._kind:
            return
        found = {k.lower(): (v or "") for k, v in attrs}
        kind = found.get("type", "").split(";", 1)[0].strip().lower()
        if found.get("id", "") == "__NEXT_DATA__":
            self._kind = "next"
        elif kind == "application/ld+json" and len(self.ld_json) < 50:
            self._kind = "ld"
        self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._kind:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._kind:
            target = self.next_data if self._kind == "next" else self.ld_json
            target.append("".join(self._buffer))
            self._kind = ""
            self._buffer = []


def _parse_html_json(text: str) -> dict[str, Any]:
    """HTML page -> ``{"next_data": <__NEXT_DATA__ JSON or null>, "ld_json": [<ld+json objects>]}``."""
    finder = _ScriptJson()
    try:
        finder.feed(text)
        finder.close()
    except Exception as exc:  # pragma: no cover - HTMLParser is tolerant
        raise _ParseError(f"invalid HTML ({exc.__class__.__name__})") from None
    next_data: Any = None
    for block in finder.next_data[:1]:
        with contextlib.suppress(ValueError):
            next_data = _json_loads(block)
    ld_json: list[Any] = []
    for block in finder.ld_json:
        try:
            value = _json_loads(block)
        except ValueError:
            continue
        ld_json.extend(value if isinstance(value, list) else [value])
    if next_data is None and not ld_json:
        raise _ParseError("no embedded JSON (__NEXT_DATA__ or application/ld+json) in the page")
    return {"next_data": next_data, "ld_json": ld_json[:MAX_RECORDS]}


def _parse(fmt: str, content: bytes, text: str) -> Any:
    """Parse an answer in the declared format; _ParseError (could not verify) on any failure,
    including documents nested too deeply for the parsers (a hostile answer never crashes a run)."""
    try:
        return _parse_format(fmt, content, text)
    except RecursionError:
        raise _ParseError(f"{fmt} document nested too deeply") from None


def _parse_format(fmt: str, content: bytes, text: str) -> Any:
    if fmt == "json":
        return _parse_json(_decode(content, text))
    if fmt == "ndjson":
        return _parse_ndjson(_decode(content, text))
    if fmt == "csv":
        return _parse_csv(_decode(content, text))
    _decode(content, "")
    if fmt == "xml":
        document = _parse_xml(content)
        if _xml_local(next(iter(document))).lower() == "html":
            raise _ParseError("the answer is an (X)HTML page, not the XML document (an error page served with HTTP 200?)")
        return document
    if fmt == "rss":
        return _parse_rss(content)
    if fmt == "html_json":
        return _parse_html_json(_decode(content, text))
    raise _ParseError(f"unknown format {fmt!r}")  # pragma: no cover - validated


# ======================================================================================
# Value conversion
# ======================================================================================


def _as_time(value: Any) -> Any:
    number = _number(value)
    when: _dt.datetime | None = None
    if number is not None:
        seconds = number / 1000.0 if abs(number) > 1e11 else number
        try:
            when = _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return _SKIP
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            when = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(raw)
            except (TypeError, ValueError, IndexError):
                return _SKIP
    if when is None:
        return _SKIP
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    return when.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _convert(fmt: str, value: Any) -> Any:
    if fmt in ("", "as_list"):
        return value
    if isinstance(value, (dict, list)):
        return _SKIP
    if fmt == "str":
        return _text(value)
    if fmt == "lower":
        return _text(value).lower()
    if fmt == "int":
        number = _number(value)
        return int(number) if number is not None else _SKIP
    if fmt == "float":
        number = _number(value)
        return number if number is not None else _SKIP
    if fmt == "bool":
        if isinstance(value, bool):
            return value
        text = _text(value).strip().lower()
        if text in ("true", "yes", "y", "t", "1"):
            return True
        if text in ("false", "no", "n", "f", "0"):
            return False
        return _SKIP
    if fmt == "as_time":
        return _as_time(value)
    return _SKIP  # pragma: no cover - validated


# ======================================================================================
# Compiled representation
# ======================================================================================


@dataclass(frozen=True)
class _Match:
    """A found/absent/onlyif/when rule: path + equals | regex | gte."""

    path: str
    op: str
    expected: Any = None
    regex: re.Pattern[str] | None = None

    def hits(self, record: Any) -> list[str]:
        out: list[str] = []
        for value in extract(record, self.path):
            if value is None and self.op != "equals":
                continue
            if self.op == "equals":
                ok = _equals(value, self.expected)
            elif self.op == "regex":
                ok = not isinstance(value, (dict, list)) and self.regex is not None and self.regex.search(_text(value)[:MAX_REGEX_INPUT]) is not None
            else:
                number = _number(value)
                ok = number is not None and number >= float(self.expected)
            if ok:
                out.append(_text(value)[:200])
                if len(out) >= MAX_VALUES:
                    break
        return out

    def describe(self) -> str:
        if self.op == "regex":
            return f"{self.path} matches {self.regex.pattern if self.regex else ''!r}"
        if self.op == "gte":
            return f"{self.path} >= {_text(self.expected)}"
        return f"{self.path} equals {json.dumps(self.expected, ensure_ascii=False)}"


@dataclass(frozen=True)
class _ResultRule:
    key: str
    pretty_name: str
    kind: str  # attribute | tag | pivot
    target: str  # attribute name, tag name or pivot entity type value
    relation: str = ""
    expand: bool = True
    confidence: Any = 0.9
    regex: re.Pattern[str] | None = None
    match_all: bool = False
    fmt: str = ""

    def values(self, record: Any) -> list[Any]:
        raw = [v for v in extract(record, self.key) if v is not None and v != ""]
        many = self.match_all or self.fmt == "as_list"
        out: list[Any] = []
        for value in raw:
            if self.regex is not None:
                if isinstance(value, (dict, list)):
                    continue
                text = _text(value)[:MAX_REGEX_INPUT]
                matches = itertools.islice(self.regex.finditer(text), MAX_VALUES) if many else [self.regex.search(text)]
                for m in matches:
                    if m is None:
                        continue
                    got = m.group(1) if m.groups() else m.group(0)
                    if got is not None and got != "":
                        out.append(got)
                if out and not many:
                    break
            else:
                out.append(value)
                if not many:
                    break
            if len(out) >= MAX_VALUES:
                break
        converted = [_bounded(_convert(self.fmt, v)) for v in out[:MAX_VALUES]]
        return [v for v in converted if v is not _SKIP]


@dataclass(frozen=True)
class _FindingRule:
    when: _Match
    title: str
    severity: str
    criterion: str
    tags: tuple[str, ...]
    confidence: Any


@dataclass(frozen=True)
class _Paginate:
    param: str
    start: int
    step: int
    max_pages: int
    stop_when_empty: bool


@dataclass(frozen=True)
class _Compiled:
    """Everything the runtime needs, prepared once at compile time."""

    name: str
    title: str
    fmt: str
    url: str
    host: str
    params: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str, str, str], ...]  # (name, literal value, key prefix, key name)
    ignored: frozenset[int]
    paginate: _Paginate | None
    source: str
    results: tuple[_ResultRule, ...]
    multi_match: str | None
    onlyif: _Match | None
    found: _Match | None
    absent: _Match | None
    findings: tuple[_FindingRule, ...]
    required_keys: frozenset[str]
    profile: bool
    health: tuple[str, str, str]
    absent_statuses: frozenset[int] = frozenset()

    @property
    def presence_rules(self) -> bool:
        return self.found is not None or self.absent is not None

    def pages(self, max_requests: int) -> list[int | None]:
        if self.paginate is None:
            return [None]
        count = max(1, min(self.paginate.max_pages, int(max_requests or 1), MAX_PAGES))
        return [self.paginate.start + i * self.paginate.step for i in range(count)]

    def url_for(self, entity: Entity, page: int | None) -> str:
        """The request URL for ``entity`` (placeholders encoded, params appended) - confined to the host."""
        url = _PLACEHOLDER_RE.sub(lambda m: _placeholder(m.group(1), entity, encoded=True), self.url)
        query = [(name, _PLACEHOLDER_RE.sub(lambda m: _placeholder(m.group(1), entity, encoded=False), value)) for name, value in self.params]
        if page is not None and self.paginate is not None:
            query.append((self.paginate.param, str(page)))
        if query:
            url = url + ("&" if "?" in url else "?") + urlencode(query)
        _confine(url, self.host)
        return url

    def records(self, document: Any) -> list[Any]:
        if self.multi_match is None:
            return [document] if document not in (None, "", [], {}) else []
        out: list[Any] = []
        for item in extract(document, self.multi_match):
            if isinstance(item, list):
                out.extend(item)
            elif item is not None:
                out.append(item)
            if len(out) >= MAX_RECORDS:
                break
        if self.onlyif is not None:
            out = [record for record in out if self.onlyif.hits(record)]
        return out[:MAX_RECORDS]


def _placeholder(name: str, entity: Entity, *, encoded: bool) -> str:
    """Value of one whitelisted placeholder for ``entity`` (URL-encoded in the URL template, raw in
    params, which urlencode() encodes)."""
    value = entity.value
    if name in ("value", "value_q", "value_qp"):
        raw = value
    elif name == "domain":
        raw = _domain_of(entity)
    elif name == "user":
        raw = _user_of(entity)
    elif name == "b64":
        raw = base64.b64encode(value.encode("utf-8")).decode("ascii")
    else:  # pragma: no cover - validated at load
        raise _NotApplicable(f"unknown placeholder {{{name}}}")
    if not encoded:
        return raw
    if name == "value":
        out = quote(raw, safe=":@")
    elif name == "value_qp":
        out = quote_plus(raw)
    else:
        out = quote(raw, safe="")
    if out in (".", ".."):  # a dot segment would move the request to another path of the host
        raise _NotApplicable("a '.' or '..' value is never put in a request path")
    return out


def _domain_of(entity: Entity) -> str:
    etype, value = entity.type, entity.value
    if etype in (EntityType.DOMAIN, EntityType.ONION):
        return value
    if etype is EntityType.EMAIL:
        return value.rsplit("@", 1)[1]
    if etype is EntityType.URL:
        host = url_host(value)
        if not host or re.match(r"^[0-9.]+$", host) or ":" in host:
            raise _NotApplicable("the URL host is not a domain name")
        return host
    raise _NotApplicable(f"{{domain}} does not apply to {etype.value}")


def _user_of(entity: Entity) -> str:
    etype, value = entity.type, entity.value
    if etype is EntityType.EMAIL:
        return value.rsplit("@", 1)[0]
    if etype is EntityType.FEDIVERSE_HANDLE:
        return value.split("@", 1)[0]
    if etype in (EntityType.SOCIAL_ACCOUNT, EntityType.STEAM_PROFILE):
        return value.split(":", 1)[1] if ":" in value else value
    if etype in (EntityType.USERNAME, EntityType.TELEGRAM_HANDLE, EntityType.BSKY_HANDLE):
        return value
    raise _NotApplicable(f"{{user}} does not apply to {etype.value}")


def _collision_reason(entity: Entity) -> str:
    """A5: why a handle is high-collision ('' when it is not): shorter than 5 characters."""
    try:
        handle = _user_of(entity)
    except _NotApplicable:
        handle = str(entity.value)
    handle = handle.strip().lstrip("@")
    return f"shorter than {PROFILE_COLLISION_LENGTH} characters" if len(handle) < PROFILE_COLLISION_LENGTH else ""


def _confine(url: str, host: str) -> None:
    """Refuse a rendered URL that is not https to exactly the spec's literal host (no userinfo/port)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise PolicyError("policy", "declarative spec: refused an unparsable request URL") from None
    if (
        parts.scheme != "https"
        or (parts.hostname or "") != host
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or "@" in parts.netloc
        or parts.fragment
        or _CTRL_RE.search(url)
        or any(c.isspace() for c in url)
    ):
        raise PolicyError("policy", f"declarative spec: refused a request URL outside its literal host {host}")


# ======================================================================================
# Validation
# ======================================================================================


def _canonical_type(value: Any) -> EntityType | None:
    if not isinstance(value, str):
        return None
    try:
        return EntityType(value)
    except ValueError:
        return None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_num(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:  # an integer too large for a float is no usable number of seconds or threshold
        return False


def _confidence_ok(value: Any) -> bool:
    if _is_num(value):
        return 0.0 <= float(value) <= 1.0
    if isinstance(value, str):
        try:
            Confidence.from_value(value)
        except (ValueError, KeyError):
            return False
        return value.strip().lower() in ("confirmed", "probable", "possible")
    return False


def _confidence_rank(value: Any) -> int:
    return Confidence.from_value(value).rank


def _text_field(value: Any, *, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        return "must be a string"
    if not allow_empty and not value.strip():
        return "must not be empty"
    if len(value) > limit:
        return f"longer than {limit} characters"
    if _CTRL_RE.search(value.replace("\n", " ")):
        return "contains control characters"
    return ""


def _template_problems(url: Any, hosts: tuple[str, ...]) -> tuple[list[str], str]:
    """Problems of the request URL template and its literal host."""
    if not isinstance(url, str) or not url:
        return ["request.url: must be a non-empty https URL template"], ""
    errs: list[str] = []
    if len(url) > 2048:
        errs.append("request.url: longer than 2048 characters")
    if _CTRL_RE.search(url) or any(c.isspace() for c in url):
        errs.append("request.url: contains whitespace or control characters")
    if not url.isascii():
        errs.append("request.url: non-ASCII characters must be percent-encoded")
    m = _URL_RE.match(url)
    if not m:
        return errs + ["request.url: must be an absolute https:// URL template"], ""
    scheme, authority, rest = m.group(1), m.group(2), m.group(3)
    if scheme != "https":
        errs.append(f"request.url: https only (got {scheme}://): an http URL is refused")
    if "{" in authority or "}" in authority:
        errs.append("request.url: a templated host is refused - the host must be a literal declared host (P331 cond 3: a passive spec never contacts the target)")
        return errs, ""
    if "@" in authority:
        errs.append("request.url: userinfo is not allowed")
    if ":" in authority:
        errs.append("request.url: explicit ports are not allowed")
    host = authority.lower()
    if host != authority:
        errs.append("request.url: the host must be written in lower case")
    if host not in hosts:
        errs.append(f"request.url: host {host!r} is not one of the spec's literal hosts {list(hosts)}")
    if rest and not rest.startswith(("/", "?")):
        errs.append("request.url: the path must start with '/' right after the host")
    if "#" in rest:
        errs.append("request.url: fragments are not allowed")
    names = _PLACEHOLDER_RE.findall(rest)
    leftover = _PLACEHOLDER_RE.sub("", rest)
    if "{" in leftover or "}" in leftover:
        errs.append("request.url: malformed placeholder (only {name} from the whitelist; never str.format syntax)")
    unknown = sorted({n for n in names if n not in PLACEHOLDERS})
    if unknown:
        errs.append(f"request.url: unknown placeholder(s) {unknown} (allowed: {sorted(PLACEHOLDERS)})")
    return errs, host


def _profile_spec(accepts: Iterable[EntityType], placeholder_names: Iterable[str]) -> bool:
    """A profile-site spec (A5 username rules): it accepts a username/handle type, or it sends the
    local part of an e-mail as a handle ({user} of an email) - a username lookup derived from an
    address, which A5 allows only on analyst-typed seeds."""
    types = set(accepts)
    if types & PROFILE_TYPES:
        return True
    return EntityType.EMAIL in types and "user" in set(placeholder_names)


def _check_placeholders(names: Iterable[str], accepts: Iterable[EntityType], where: str) -> list[str]:
    errs = []
    for name in sorted(set(names)):
        allowed = PLACEHOLDER_TYPES.get(name)
        if allowed is None:
            continue
        bad = sorted(t.value for t in accepts if t not in allowed)
        if bad:
            errs.append(f"{where}: placeholder {{{name}}} applies only to {', '.join(sorted(t.value for t in allowed))} (accepts {', '.join(bad)})")
    return errs


def _match_rule(raw: Any, where: str, errs: list[str], *, ops: tuple[str, ...]) -> _Match | None:
    """Parse a {path, equals | regex [| gte]} rule (exactly one operator)."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        errs.append(f"{where}: must be an object {{path, {' | '.join(ops)}}} or null")
        return None
    allowed = ("path", *ops)
    unknown = sorted(k for k in raw if k not in allowed)
    if unknown:
        errs.append(f"{where}: unknown field(s) {unknown}")
    path = raw.get("path")
    problem = _path_problem(path)
    if problem:
        errs.append(f"{where}.path: {problem}")
    given = [op for op in ops if op in raw]
    if len(given) != 1:
        errs.append(f"{where}: exactly one of {', '.join(ops)} is required")
        return None
    op = given[0]
    if op == "regex":
        problems = regex_problems(raw.get("regex"))
        if problems:
            errs.extend(f"{where}.regex: {p}" for p in problems)
            return None
        return _Match(str(path), "regex", regex=re.compile(raw["regex"])) if not problem else None
    if op == "gte":
        if not _is_num(raw.get("gte")):
            errs.append(f"{where}.gte: must be a number")
            return None
        return _Match(str(path), "gte", expected=raw["gte"]) if not problem else None
    expected = raw.get("equals")
    if isinstance(expected, (dict, list)):
        errs.append(f"{where}.equals: must be a JSON scalar (string, number, boolean or null)")
        return None
    return _Match(str(path), "equals", expected=expected) if not problem else None


def _str_list(raw: Any, where: str, errs: list[str]) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        errs.append(f"{where}: must be a list of strings")
        return []
    return list(raw)


def _types(raw: Any, where: str, errs: list[str], *, allow_empty: bool) -> list[EntityType]:
    names = _str_list(raw, where, errs)
    if not names and not allow_empty and isinstance(raw, list):
        errs.append(f"{where}: must not be empty")
    out = []
    for name in names:
        etype = _canonical_type(name)
        if etype is None:
            errs.append(f"{where}: unknown entity type {name!r} (use the canonical value, e.g. 'ipv4', 'domain')")
        elif etype not in out:
            out.append(etype)
    return out


def validate_spec(spec: Any) -> list[str]:  # noqa: C901 - one linear schema check
    """Every problem of a declarative spec (empty list = valid), as '<field>: <problem>'.

    Checks the ``v3lum.spec/1`` schema of module contract v2 section 17 (every field present, types
    and enums), the P331 safety rules (literal https host, GET only, whitelisted type-validated
    placeholders in path/query only, literal or ``{key:<name>}`` headers, no bodies/cookies/logins,
    forbidden probe endpoints, bounded reviewed regexes, vocabulary names), the provider registry
    (registered provider/sources/hosts, no ``hosts_from_settings``, rule 7, A8 tier rules), A3/A8
    defaults, the A5 rules of profile-site specs and the central benign health-check value.
    ``@register`` re-checks the module contract when the spec is compiled.
    """
    if not isinstance(spec, Mapping):
        return ["the spec must be a JSON object"]
    errs: list[str] = []
    missing = [f for f in REQUIRED_FIELDS if f not in spec]
    if missing:
        errs.append(f"missing contract field(s) {missing}: every field of 'v3lum.spec/1' is declared explicitly (null or [] where allowed)")
    allowed = set(REQUIRED_FIELDS) | set(OPTIONAL_FIELDS)
    unknown = sorted(k for k in spec if k not in allowed and not str(k).startswith("x_") and k != "$comment")
    if unknown:
        errs.append(f"unknown field(s) {unknown}")
    if spec.get("schema") != SPEC_SCHEMA:
        errs.append(f"schema: must be {SPEC_SCHEMA!r}")
    name = spec.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        errs.append("name: must match ^[a-z][a-z0-9_]{2,63}$ (the module name)")
    elif name in RESERVED_NAMES:
        errs.append(f"name: {name!r} is reserved")
    for fld, limit in (("title", 120), ("description", 1000)):
        problem = _text_field(spec.get(fld), limit=limit)
        if problem and fld in spec:
            errs.append(f"{fld}: {problem}")
    if "category" in spec and not (isinstance(spec.get("category"), str) and spec["category"] in CATEGORIES):
        errs.append(f"category: must be one of {', '.join(CATEGORIES)}")
    if spec.get("category") == "breach_leak":
        errs.append("category: breach/leak sources are hand-written modules with a reviewed P145 schema, never declarative specs (team rule 3)")
    accepts = _types(spec.get("accepts"), "accepts", errs, allow_empty=False) if "accepts" in spec else []
    produces = _types(spec.get("produces"), "produces", errs, allow_empty=True) if "produces" in spec else []
    forbidden = sorted(t.value for t in accepts if t in FORBIDDEN_TYPES)
    if forbidden:
        errs.append(f"accepts: {forbidden} are never sent to a provider (CPF is validated offline only, secrets and blobs stay local)")
    if "disclosure" in spec and spec.get("disclosure") != "third_party":
        errs.append("disclosure: declarative specs are 'third_party' lookups")
    if "opsec" in spec and spec.get("opsec") != "passive":
        errs.append("opsec: declarative specs are 'passive' (they never contact the target)")
    if "terms" in spec and spec.get("terms") not in TERMS:
        errs.append(f"terms: must be one of {', '.join(TERMS)}")
    if "access_model" in spec and spec.get("access_model") not in ACCESS_MODELS:
        errs.append(f"access_model: must be one of {', '.join(ACCESS_MODELS)}")
    if "run_on" in spec and spec.get("run_on") not in RUN_ON:
        errs.append(f"run_on: must be one of {', '.join(RUN_ON)}")
    if "default_enabled" in spec and not isinstance(spec.get("default_enabled"), bool):
        errs.append("default_enabled: must be true or false")
    keys: list[str] = []
    required_keys: list[str] = []
    for fld in ("requires_keys", "optional_keys"):
        if fld in spec:
            values = _str_list(spec.get(fld), fld, errs)
            keys += values
            if fld == "requires_keys":
                required_keys = values
    if "max_requests" in spec:
        max_requests = spec.get("max_requests")
        if not _is_int(max_requests) or not 1 <= max_requests <= MAX_PAGES:
            errs.append(f"max_requests: must be an integer 1..{MAX_PAGES} (one request per page, at most {MAX_PAGES} pages)")
    for fld in ("expected_latency", "min_interval"):
        if fld in spec and (not _is_num(spec.get(fld)) or spec.get(fld) < 0 or spec.get(fld) > 3600):
            errs.append(f"{fld}: must be a number of seconds 0..3600")
    cache_ttl = spec.get("cache_ttl")
    if "cache_ttl" in spec and cache_ttl is not None and (not _is_int(cache_ttl) or cache_ttl < 0):
        errs.append("cache_ttl: must be null or a non-negative integer (seconds)")
    absent_statuses: list[int] = []
    if "absent_statuses" in spec:
        raw = spec.get("absent_statuses")
        if not isinstance(raw, list) or not all(_is_int(s) and 100 <= s <= 599 for s in raw):
            errs.append("absent_statuses: must be a list of HTTP status codes 100-599")
        else:
            absent_statuses = list(raw)
            refused = sorted(s for s in raw if s in NEVER_ABSENT_STATUS or s >= 500 or 200 <= s < 300)
            if refused:
                errs.append(f"absent_statuses: {refused} are never an absence (rule 5: 401/403/407/429/430/451/5xx mean 'could not verify'; 2xx answers are parsed)")
    if "error_markers" in spec:
        markers = spec.get("error_markers")
        if not isinstance(markers, list):
            errs.append("error_markers: must be a list of error-marker objects")
        else:
            for index, marker in enumerate(markers):
                try:
                    _providers.parse_marker(marker)
                except ValueError as exc:
                    errs.append(f"error_markers[{index}]: {exc}")
                    continue
                for fld in ("regex", "final_url_regex"):
                    if isinstance(marker, Mapping) and marker.get(fld) is not None:
                        errs.extend(f"error_markers[{index}].{fld}: {p}" for p in regex_problems(marker.get(fld), max_unbounded=0))
    if "manual_link" in spec and not isinstance(spec.get("manual_link"), str):
        errs.append("manual_link: must be a string ('' for none, '<pack>:<link_id>' or an inline https template)")
    for fld, limit in (("reference", 500), ("notice", 1000), ("notes", 2000)):
        if fld in spec:
            problem = _text_field(spec.get(fld), limit=limit, allow_empty=True)
            if problem:
                errs.append(f"{fld}: {problem}")
    reference = spec.get("reference")
    if isinstance(reference, str) and reference and not re.match(r"^https?://\S+$", reference):
        errs.append("reference: must be an http(s) URL (the source's documentation or terms page)")
    tags = []
    if "tags" in spec:
        tags = _str_list(spec.get("tags"), "tags", errs)
        bad = [t for t in tags if not _TAG_RE.match(t)]
        if bad:
            errs.append(f"tags: invalid tag(s) {bad} (lower-case, ^[a-z0-9][a-z0-9_.-]{{0,63}}$)")
        if "offline" in tags:
            errs.append("tags: 'offline' is reserved for modules that work without network; a spec is a third-party lookup")
    if "requires_egress" in spec:
        codes = _str_list(spec.get("requires_egress"), "requires_egress", errs)
        bad = [c for c in codes if not _COUNTRY_RE.match(c)]
        if bad:
            errs.append(f"requires_egress: invalid ISO 3166 alpha-2 code(s) {bad}")

    # ---- provider registry (A1/A8, rule 7) ----------------------------------------------
    reg = _providers.registry()
    hosts: tuple[str, ...] = ()
    if "hosts" in spec:
        host_list = _str_list(spec.get("hosts"), "hosts", errs)
        if isinstance(spec.get("hosts"), list) and not host_list:
            errs.append("hosts: at least one literal host is required")
        for host in host_list:
            if host.startswith("*.") or not _providers.valid_host_pattern(host):
                errs.append(f"hosts: {host!r} is not a literal lower-case host name (wildcards are refused in specs)")
        hosts = tuple(host_list)
    provider_id = spec.get("provider")
    provider = reg.get(provider_id) if isinstance(provider_id, str) and provider_id else None
    if "provider" in spec and provider is None:
        errs.append(f"provider: {provider_id!r} is not registered (add a v3lum/data/providers/<id>.json fragment)")
    source_ids = _str_list(spec.get("sources"), "sources", errs) if "sources" in spec else []
    if "sources" in spec and isinstance(spec.get("sources"), list) and not source_ids:
        errs.append("sources: at least one registry source is required")
    resolved = []
    for sid in source_ids:
        src = reg.source(sid) if _SOURCE_RE.match(sid) else None
        if src is None:
            errs.append(f"sources: {sid!r} is not a registered 'provider.source' id")
        else:
            resolved.append(src)
    pids = {s.provider for s in resolved} | ({provider.id} if provider is not None else set())
    known = [reg.get(pid) for pid in sorted(pids) if reg.get(pid) is not None]
    tier = _providers.lowest_tier(p.tier for p in known) if known else "unknown"
    for prov in known:
        if prov.hosts_from_settings:
            errs.append(f"provider: {prov.id} declares hosts_from_settings: declarative specs reach literal hosts only")
        if prov.flags.publishes_queries:
            errs.append(f"provider: {prov.id} publishes submitted values (rule 7): it never receives a value")
        if prov.flags.sensitive:
            errs.append(f"provider: {prov.id} is flagged sensitive (breach/infostealer/people data): hand-written modules with a P145 schema only")
        if prov.internal:
            errs.append(f"provider: {prov.id} is internal: declarative specs are third-party lookups")
    for host in hosts:
        owner = reg.provider_for_host(host)
        if owner is None:
            errs.append(f"hosts: {host!r} is not in the provider registry")
        elif owner.id not in {s.provider for s in resolved}:
            errs.append(f"hosts: {host!r} belongs to provider {owner.id!r}, which has none of the spec's sources")
    if "terms" in spec and resolved:
        expected_terms = _providers.most_restrictive(s.terms.class_ for s in resolved)
        if spec.get("terms") != expected_terms:
            errs.append(f"terms: {spec.get('terms')!r} but the most restrictive source class is {expected_terms!r}")
    known_keys = reg.keys()
    for key in dict.fromkeys(keys):
        owner_key = known_keys.get(key)
        if owner_key is None:
            try:
                from v3lum import config as _config

                registered = key in _config.key_registry()
            except Exception:  # pragma: no cover - registry problems are reported by @register
                registered = False
            if not registered:
                errs.append(f"requires_keys/optional_keys: key {key!r} is not registered (declare it in the provider fragment)")
            else:
                errs.append(
                    f"requires_keys/optional_keys: key {key!r} is a legacy key without a provider: a spec sends only keys declared "
                    "in the 'keys' block of its own provider fragment"
                )
        elif pids and owner_key.provider not in pids:
            errs.append(
                f"requires_keys/optional_keys: key {key!r} belongs to provider {owner_key.provider or '?'!r}: a spec sends only its own "
                "provider's keys (never another provider's key to its hosts)"
            )
    default_enabled = spec.get("default_enabled") is True
    if default_enabled and tier == "unknown" and known:
        errs.append("default_enabled: must be false for an unknown-tier provider (A3/A8)")
    if default_enabled and spec.get("terms") == "unknown":
        errs.append("default_enabled: must be false for unknown terms (A1/A3)")
    if default_enabled and EntityType.PERSON in accepts:
        errs.append("default_enabled: must be false for a spec that receives person names (A3: person-name sources are never default)")
    if known and tier == "unknown":
        non_ioc = sorted(t.value for t in accepts if t not in IOC_TYPES)
        if non_ioc:
            errs.append(f"accepts: an unknown-tier provider receives IOC types only, never {non_ioc} (A8: no PERSONAL_TYPES, company ids or other values)")

    # ---- health check (P332 cond 9: central benign value) ---------------------------------
    hc = spec.get("health_check")
    if "health_check" in spec:
        if not isinstance(hc, Mapping):
            errs.append("health_check: must be an object {etype, value, expect}")
        else:
            unknown_hc = sorted(k for k in hc if k not in HEALTH_FIELDS)
            if unknown_hc:
                errs.append(f"health_check: unknown field(s) {unknown_hc}")
            etype = _canonical_type(hc.get("etype"))
            value = hc.get("value")
            expect = hc.get("expect", "ok")
            if etype is None:
                errs.append("health_check.etype: must be a canonical entity type the spec accepts")
            elif etype not in accepts:
                errs.append(f"health_check.etype: {etype.value!r} is not accepted by the spec")
            elif not isinstance(value, str) or Entity.try_make(etype, value) is None:
                errs.append(f"health_check.value: {value!r} is not a valid {etype.value}")
            else:
                benign = BENIGN_VALUES.get(etype)
                if benign is not None and value != benign:
                    errs.append(f"health_check.value: use the central benign value {benign!r} (module.BENIGN_VALUES, P332 cond 9)")
                elif benign is None and etype in PERSONAL_TYPES:
                    errs.append(f"health_check.etype: personal type {etype.value!r} has no central benign value: probe another accepted type")
            if expect not in HEALTH_EXPECT:
                errs.append(f"health_check.expect: must be one of {', '.join(HEALTH_EXPECT)}")

    # ---- request (P331 cond 2-4) -----------------------------------------------------------
    request = spec.get("request")
    placeholder_names: list[str] = []
    request_host = ""
    paginate_raw: Any = None
    if "request" in spec:
        if not isinstance(request, Mapping):
            errs.append("request: must be an object {url, method, params, headers, ignored_status_codes, paginate}")
            request = {}
        for fld, why in _REFUSED_REQUEST_FIELDS.items():
            if fld in request:
                errs.append(f"request.{fld}: {why}")
        unknown_rq = sorted(k for k in request if k not in REQUEST_FIELDS and k not in _REFUSED_REQUEST_FIELDS)
        if unknown_rq:
            errs.append(f"request: unknown field(s) {unknown_rq}")
        for fld in ("url", "method"):
            if fld not in request:
                errs.append(f"request.{fld}: required")
        method = request.get("method")
        if "method" in request and (not isinstance(method, str) or method.upper() != "GET"):
            errs.append(f"request.method: only 'GET' search lookups are allowed (got {method!r}; no POST of values, rule 7)")
        url_errs, request_host = _template_problems(request.get("url"), hosts)
        if "url" in request:
            errs.extend(url_errs)
            placeholder_names += _PLACEHOLDER_RE.findall(str(request.get("url") or ""))
        params = request.get("params", {}) or {}
        if not isinstance(params, Mapping):
            errs.append("request.params: must be an object name -> value")
            params = {}
        lower_key_params = {p.lower() for p in KEY_PARAMS}
        for pname, pvalue in params.items():
            if not isinstance(pname, str) or not _PARAM_NAME_RE.match(pname):
                errs.append(f"request.params: invalid parameter name {pname!r}")
                continue
            if pname.lower() in lower_key_params or _credential_like(pname):
                errs.append(f"request.params.{pname}: credential-like parameters are refused (keys go in headers as {{key:<name>}})")
            if isinstance(pvalue, bool) or not isinstance(pvalue, (str, int, float)):
                errs.append(f"request.params.{pname}: must be a string or number")
                continue
            text = str(pvalue)
            if len(text) > 512 or _CTRL_RE.search(text):
                errs.append(f"request.params.{pname}: at most 512 printable characters")
            names = _PLACEHOLDER_RE.findall(text)
            leftover = _PLACEHOLDER_RE.sub("", text)
            if "{" in leftover or "}" in leftover:
                errs.append(f"request.params.{pname}: malformed placeholder ({{key:...}} is allowed in headers only)")
            unknown_ph = sorted({n for n in names if n not in PLACEHOLDERS})
            if unknown_ph:
                errs.append(f"request.params.{pname}: unknown placeholder(s) {unknown_ph}")
            placeholder_names += names
        headers = request.get("headers", {}) or {}
        if not isinstance(headers, Mapping):
            errs.append("request.headers: must be an object name -> value")
            headers = {}
        for hname, hvalue in headers.items():
            if not isinstance(hname, str) or not _HEADER_NAME_RE.match(hname):
                errs.append(f"request.headers: invalid header name {hname!r}")
                continue
            lname = hname.lower()
            if lname in FORBIDDEN_HEADERS or lname.startswith(("proxy-", "sec-", "x-forwarded-")):
                errs.append(f"request.headers.{hname}: this header cannot be set by a spec (no cookies, identity or routing headers; the provider profile chooses the User-Agent)")
                continue
            if not isinstance(hvalue, str) or not hvalue or len(hvalue) > 256 or _CTRL_RE.search(hvalue):
                errs.append(f"request.headers.{hname}: must be a printable string of at most 256 characters")
                continue
            ref = _KEY_REF_RE.match(hvalue)
            if ref:
                if ref.group(2) not in keys:
                    errs.append(f"request.headers.{hname}: key {ref.group(2)!r} is not in requires_keys/optional_keys")
                continue
            if "{" in hvalue or "}" in hvalue:
                errs.append(f"request.headers.{hname}: literal value or '{{key:<name>}}' only (values never go into headers)")
            elif lname in CREDENTIAL_HEADERS or _credential_like(lname):
                errs.append(f"request.headers.{hname}: credentials are never literal: use '{{key:<name>}}' (optionally 'Bearer {{key:<name>}}')")
        ignored = request.get("ignored_status_codes", []) or []
        if not isinstance(ignored, list) or not all(_is_int(s) and 100 <= s <= 599 for s in ignored):
            errs.append("request.ignored_status_codes: must be a list of HTTP status codes 100-599")
        else:
            refused = sorted(s for s in ignored if s in NEVER_ABSENT_STATUS or s >= 500 or 200 <= s < 300)
            if refused:
                errs.append(f"request.ignored_status_codes: {refused} cannot be ignored (rule 5: refusals and failures are 'could not verify'; 2xx answers are parsed)")
            overlap = sorted(set(ignored) & set(absent_statuses))
            if overlap:
                errs.append(f"request.ignored_status_codes: {overlap} are also absent_statuses")
        paginate_raw = request.get("paginate")
        if paginate_raw is not None:
            if not isinstance(paginate_raw, Mapping):
                errs.append("request.paginate: must be null or {param, start, step, max_pages, stop_when_empty}")
            else:
                unknown_pg = sorted(k for k in paginate_raw if k not in PAGINATE_FIELDS)
                if unknown_pg:
                    errs.append(f"request.paginate: unknown field(s) {unknown_pg}")
                param = paginate_raw.get("param")
                if not isinstance(param, str) or not _PARAM_NAME_RE.match(param):
                    errs.append("request.paginate.param: must be a query parameter name")
                elif param in params or re.search(r"[?&]" + re.escape(param) + r"=", str(request.get("url") or "")):
                    errs.append(f"request.paginate.param: {param!r} is already set by the request")
                for fld, low in (("start", 0), ("step", 1)):
                    if not _is_int(paginate_raw.get(fld)) or paginate_raw.get(fld) < low:
                        errs.append(f"request.paginate.{fld}: must be an integer >= {low}")
                pages = paginate_raw.get("max_pages")
                if not _is_int(pages) or not 1 <= pages <= MAX_PAGES:
                    errs.append(f"request.paginate.max_pages: must be an integer 1..{MAX_PAGES}")
                elif _is_int(spec.get("max_requests")) and spec["max_requests"] < pages:
                    errs.append(f"max_requests: {spec['max_requests']} is below request.paginate.max_pages ({pages})")
                if "stop_when_empty" in paginate_raw and not isinstance(paginate_raw.get("stop_when_empty"), bool):
                    errs.append("request.paginate.stop_when_empty: must be true or false")
        errs.extend(_check_placeholders(placeholder_names, accepts, "request"))
        if request_host and "url" in request and isinstance(request.get("url"), str):
            sample = _PLACEHOLDER_RE.sub("{value}", str(request["url"]))
            sample_params = [(k, _PLACEHOLDER_RE.sub("{value}", str(v))) for k, v in params.items() if isinstance(k, str)]
            if sample_params:
                sample += ("&" if "?" in sample else "?") + "&".join(f"{k}={v}" for k, v in sample_params)
            rule = _lint.forbidden_probe(sample, method="GET")
            if rule is not None:
                errs.append(f"request.url: {rule}: {_lint.PROBE_RULES.get(rule, 'forbidden endpoint')}")
            try:
                if _lint.people_search_host(request_host):
                    errs.append("request.url: LINT-04: people-search, CPF-lookup and leaked-database hosts are refused (team rule 4)")
            except AttributeError:  # pragma: no cover - older lint module
                pass

    # ---- format, results, rules ---------------------------------------------------------
    if "format" in spec and spec.get("format") not in FORMATS:
        errs.append(f"format: must be one of {', '.join(FORMATS)}")
    titles: list[str] = []
    results = spec.get("results")
    pivot_rules: list[Mapping[str, Any]] = []
    if "results" in spec:
        if not isinstance(results, list):
            errs.append("results: must be a list of result rules")
            results = []
        if len(results) > 50:
            errs.append("results: at most 50 result rules")
        for index, rule in enumerate(results):
            where = f"results[{index}]"
            if not isinstance(rule, Mapping):
                errs.append(f"{where}: must be an object")
                continue
            unknown_rs = sorted(k for k in rule if k not in RESULT_FIELDS)
            if unknown_rs:
                errs.append(f"{where}: unknown field(s) {unknown_rs}")
            problem = _path_problem(rule.get("key"))
            if problem:
                errs.append(f"{where}.key: {problem}")
            targets = [k for k in ("attribute", "tag", "pivot") if k in rule]
            if len(targets) != 1:
                errs.append(f"{where}: exactly one of attribute, tag or pivot is required")
                continue
            pretty = rule.get("pretty_name", "")
            if pretty and _text_field(pretty, limit=120):
                errs.append(f"{where}.pretty_name: {_text_field(pretty, limit=120)}")
            if "regex" in rule:
                errs.extend(f"{where}.regex: {p}" for p in regex_problems(rule.get("regex")))
            if "match_all" in rule and not isinstance(rule.get("match_all"), bool):
                errs.append(f"{where}.match_all: must be true or false")
            fmt = rule.get("format", "")
            if fmt and fmt not in RESULT_FORMATS:
                errs.append(f"{where}.format: must be one of {', '.join(RESULT_FORMATS)}")
            kind = targets[0]
            if kind == "attribute":
                attr = rule.get("attribute")
                if not isinstance(attr, str) or not _vocab.is_known_attribute(attr):
                    errs.append(f"{where}.attribute: {attr!r} is not a vocabulary attribute (core or a v3lum/data/vocab fragment)")
                elif attr == "presence":
                    errs.append(f"{where}.attribute: 'presence' comes from the found/absent rules only")
            elif kind == "tag":
                tag = rule.get("tag")
                if not isinstance(tag, str) or not _vocab.is_known_tag(tag):
                    errs.append(f"{where}.tag: {tag!r} is not a vocabulary tag")
                if fmt:
                    errs.append(f"{where}.format: tag rules take no format")
                titles.append(str(pretty or f"{spec.get('title', '')}: {tag}"))
            else:
                pivot = rule.get("pivot")
                if not isinstance(pivot, Mapping):
                    errs.append(f"{where}.pivot: must be an object {{type, relation, expand, confidence}}")
                    continue
                pivot_rules.append(pivot)
                unknown_pv = sorted(k for k in pivot if k not in PIVOT_FIELDS)
                if unknown_pv:
                    errs.append(f"{where}.pivot: unknown field(s) {unknown_pv}")
                ptype = _canonical_type(pivot.get("type"))
                if ptype is None:
                    errs.append(f"{where}.pivot.type: unknown entity type {pivot.get('type')!r}")
                elif ptype not in produces:
                    errs.append(f"{where}.pivot.type: {ptype.value!r} is not listed in produces")
                elif ptype in SECRET_TYPES or ptype is EntityType.CPF:
                    errs.append(f"{where}.pivot.type: {ptype.value!r} is never produced by a spec")
                relation = pivot.get("relation")
                if not isinstance(relation, str) or not _vocab.is_known_relation(relation):
                    errs.append(f"{where}.pivot.relation: {relation!r} is not a vocabulary relation")
                if "expand" in pivot and not isinstance(pivot.get("expand"), bool):
                    errs.append(f"{where}.pivot.expand: must be true or false")
                if "confidence" in pivot and not _confidence_ok(pivot.get("confidence")):
                    errs.append(f"{where}.pivot.confidence: a number 0..1 or 'confirmed' | 'probable' | 'possible'")
                if fmt in ("as_list", "as_time", "bool", "int", "float"):
                    errs.append(f"{where}.format: pivots take a text value ('str' or 'lower')")
    multi_match = spec.get("multi_match")
    if "multi_match" in spec and multi_match is not None:
        if not isinstance(multi_match, Mapping):
            errs.append("multi_match: must be null or {path, onlyif}")
        else:
            unknown_mm = sorted(k for k in multi_match if k not in ("path", "onlyif"))
            if unknown_mm:
                errs.append(f"multi_match: unknown field(s) {unknown_mm}")
            problem = _path_problem(multi_match.get("path"))
            if problem:
                errs.append(f"multi_match.path: {problem}")
            _match_rule(multi_match.get("onlyif"), "multi_match.onlyif", errs, ops=("equals",))
    found = _match_rule(spec.get("found"), "found", errs, ops=("equals", "regex"))
    absent = _match_rule(spec.get("absent"), "absent", errs, ops=("equals", "regex"))
    findings = spec.get("findings")
    finding_confidences: list[Any] = []
    if "findings" in spec:
        if not isinstance(findings, list):
            errs.append("findings: must be a list of finding rules")
            findings = []
        if len(findings) > 20:
            errs.append("findings: at most 20 finding rules")
        for index, rule in enumerate(findings):
            where = f"findings[{index}]"
            if not isinstance(rule, Mapping):
                errs.append(f"{where}: must be an object")
                continue
            unknown_fd = sorted(k for k in rule if k not in FINDING_FIELDS)
            if unknown_fd:
                errs.append(f"{where}: unknown field(s) {unknown_fd}")
            if "when" not in rule:
                errs.append(f"{where}.when: required")
            else:
                _match_rule(rule.get("when"), f"{where}.when", errs, ops=("equals", "regex", "gte"))
            problem = _text_field(rule.get("title"), limit=200)
            if problem:
                errs.append(f"{where}.title: {problem}")
            else:
                titles.append(rule["title"])
            severity = rule.get("severity", "info")
            try:
                sev = Severity.parse(severity) if isinstance(severity, str) else None
            except KeyError:
                sev = None
            if sev is None:
                errs.append(f"{where}.severity: must be one of info, low, medium, high, critical")
            elif sev >= Severity.LOW and (not isinstance(rule.get("criterion"), str) or not rule["criterion"].strip()):
                errs.append(f"{where}.criterion: required for severity >= low (P322: why the finding is believed)")
            if "criterion" in rule and _text_field(rule.get("criterion"), limit=500, allow_empty=True):
                errs.append(f"{where}.criterion: {_text_field(rule.get('criterion'), limit=500, allow_empty=True)}")
            ftags = _str_list(rule.get("tags", []), f"{where}.tags", errs)
            bad = [t for t in ftags if not _vocab.is_known_tag(t)]
            if bad:
                errs.append(f"{where}.tags: {bad} are not vocabulary tags")
            if "confidence" in rule:
                if not _confidence_ok(rule.get("confidence")):
                    errs.append(f"{where}.confidence: a number 0..1 or 'confirmed' | 'probable' | 'possible'")
                else:
                    finding_confidences.append(rule.get("confidence"))
            else:
                finding_confidences.append("probable")
    duplicates = sorted({t for t in titles if titles.count(t) > 1})
    if duplicates:
        errs.append(f"findings: titles must be unique (finding ids derive from them): {duplicates}")
    if isinstance(results, list) and isinstance(findings, list) and not results and not findings and found is None and absent is None and "results" in spec:
        errs.append("results: the spec extracts nothing (declare results, found/absent rules or findings)")

    # ---- A5: community profile-site specs ------------------------------------------------
    profile = _profile_spec(accepts, placeholder_names)
    if profile:
        a5 = "profile-site spec (A5 username rules)"
        if spec.get("run_on") != "seeds":
            errs.append(f"run_on: a {a5} runs on analyst-typed seeds only ('seeds')")
        if spec.get("default_enabled") is not False:
            errs.append(f"default_enabled: a {a5} is never default (the A5 default subset is the username_check pack)")
        if found is None:
            errs.append(f"found: a {a5} needs an explicit presence marker")
        if absent is None and not absent_statuses:
            errs.append(f"absent: a {a5} needs an explicit absence marker (an absent rule or absent_statuses)")
        if spec.get("max_requests") != 1 or paginate_raw is not None:
            errs.append(f"max_requests: a {a5} sends exactly one request per handle (no pagination)")
        if not _is_num(spec.get("min_interval")) or spec.get("min_interval") < PROFILE_MIN_INTERVAL:
            errs.append(f"min_interval: a {a5} waits >= {PROFILE_MIN_INTERVAL} s between requests to a host")
        if isinstance(request, Mapping) and request.get("ignored_status_codes"):
            errs.append(f"request.ignored_status_codes: a {a5} is tri-state: anything but the markers is 'unknown'")
        if known and tier not in ("trusted", "community"):
            errs.append(f"provider: a {a5} is queried only when its provider is trusted or community (A5)")
        for pivot in pivot_rules:
            if pivot.get("expand", True) is not False:
                errs.append(f"results: pivots of a {a5} never expand (expand: false)")
            if _confidence_ok(pivot.get("confidence", 0.9)) and _confidence_rank(pivot.get("confidence", 0.9)) > _confidence_rank("possible"):
                errs.append(f"results: pivots of a {a5} are POSSIBLE at most (the same handle does not prove identity)")
        if any(_confidence_rank(c) > _confidence_rank("possible") for c in finding_confidences if _confidence_ok(c)):
            errs.append(f"findings: findings of a {a5} are POSSIBLE at most (the same handle does not prove identity)")
    if required_keys and spec.get("access_model") in ("free_noauth_unlimited", "free_noauth_limited"):
        errs.append("access_model: a spec with requires_keys is not 'free_noauth_*'")
    # the P327 data lint of the spec document itself (hosts: people-search, mailbox verification,
    # CAPTCHA solvers...; credential fields; probe URLs), so compile_spec enforces it on every path
    for problem in _lint_document(spec):
        if problem not in errs:
            errs.append(problem)
    return errs


def _lint_document(spec: Mapping[str, Any]) -> list[str]:
    """Blocking issues of ``lint.lint_data_file`` (WP09) on a parsed spec ('<rule>: <message>')."""
    fn = getattr(_lint, "lint_data_file", None)
    if not callable(fn):  # pragma: no cover - a tree without the WP09 lint
        return []
    try:
        issues = fn(spec, kind="spec", display=f"spec:{spec.get('name', '?')}")
    except Exception as exc:  # noqa: BLE001 - a lint crash refuses the spec, it never passes it
        return [f"lint: failed ({type(exc).__name__}: {exc})"]
    out = []
    for issue in issues or ():
        if getattr(issue, "allowed", False):
            continue
        rule = getattr(issue, "rule_id", "")
        message = getattr(issue, "message", "") or str(issue)
        out.append(f"lint: {rule}: {message}" if rule else f"lint: {message}")
    return out


# ======================================================================================
# Compiler
# ======================================================================================


def _compile_internal(spec: Mapping[str, Any]) -> _Compiled:
    request = spec["request"]
    url = str(request["url"])
    host = _URL_RE.match(url).group(2).lower()  # type: ignore[union-attr] - validated
    params = tuple((str(k), str(v)) for k, v in (request.get("params") or {}).items())
    headers = []
    for name, value in (request.get("headers") or {}).items():
        ref = _KEY_REF_RE.match(value)
        if ref:
            headers.append((name, "", ref.group(1) or "", ref.group(2)))
        else:
            headers.append((name, value, "", ""))
    paginate = None
    raw_pg = request.get("paginate")
    if raw_pg:
        paginate = _Paginate(
            param=raw_pg["param"], start=int(raw_pg["start"]), step=int(raw_pg["step"]),
            max_pages=int(raw_pg["max_pages"]), stop_when_empty=bool(raw_pg.get("stop_when_empty", True)),
        )
    reg = _providers.registry()
    owner = reg.provider_for_host(host)
    source = next((s for s in spec["sources"] if owner is not None and s.split(".", 1)[0] == owner.id), spec["sources"][0])
    rules = []
    for rule in spec["results"]:
        if "attribute" in rule:
            kind, target, pivot = "attribute", rule["attribute"], {}
        elif "tag" in rule:
            kind, target, pivot = "tag", rule["tag"], {}
        else:
            pivot = rule["pivot"]
            kind, target = "pivot", EntityType(pivot["type"]).value
        rules.append(_ResultRule(
            key=rule["key"],
            pretty_name=str(rule.get("pretty_name") or ""),
            kind=kind,
            target=target,
            relation=str(pivot.get("relation", "")),
            expand=bool(pivot.get("expand", True)),
            confidence=pivot.get("confidence", 0.9),
            regex=re.compile(rule["regex"]) if rule.get("regex") else None,
            match_all=bool(rule.get("match_all", False)),
            fmt=str(rule.get("format") or ""),
        ))
    errs: list[str] = []
    multi = spec.get("multi_match")
    onlyif = _match_rule(multi.get("onlyif"), "multi_match.onlyif", errs, ops=("equals",)) if multi else None
    found = _match_rule(spec.get("found"), "found", errs, ops=("equals", "regex"))
    absent = _match_rule(spec.get("absent"), "absent", errs, ops=("equals", "regex"))
    finding_rules = []
    for rule in spec["findings"]:
        when = _match_rule(rule["when"], "when", errs, ops=("equals", "regex", "gte"))
        if when is None:  # pragma: no cover - validated
            continue
        finding_rules.append(_FindingRule(
            when=when, title=rule["title"], severity=str(rule.get("severity", "info")), criterion=str(rule.get("criterion", "")),
            tags=tuple(rule.get("tags", [])), confidence=rule.get("confidence", "probable"),
        ))
    accepts = {EntityType(t) for t in spec["accepts"]}
    hc = spec["health_check"]
    return _Compiled(
        name=spec["name"],
        title=spec["title"],
        fmt=spec["format"],
        url=url,
        host=host,
        params=params,
        headers=tuple(headers),
        ignored=frozenset(int(s) for s in (request.get("ignored_status_codes") or [])),
        paginate=paginate,
        source=source,
        results=tuple(rules),
        multi_match=str(multi["path"]) if multi else None,
        onlyif=onlyif,
        found=found,
        absent=absent,
        findings=tuple(finding_rules),
        required_keys=frozenset(spec["requires_keys"]),
        profile=_profile_spec(accepts, _PLACEHOLDER_RE.findall(url) + [n for _k, v in params for n in _PLACEHOLDER_RE.findall(v)]),
        health=(hc["etype"], hc["value"], hc.get("expect", "ok")),
        absent_statuses=frozenset(int(s) for s in spec["absent_statuses"]),
    )


def _freeze(value: Any) -> Any:
    """A deep copy of the spec document (the compiled class keeps its own copy)."""
    return json.loads(json.dumps(value))


def compile_spec(spec: Mapping[str, Any], *, origin: str, register_class: bool = True, disabled: str = "") -> type[Module]:
    """Compile a declarative spec into a real Module subclass and (by default) register it.

    The class body declares every contract field of the spec (identity, accepts/produces, terms,
    opsec PASSIVE, disclosure 'third_party', literal hosts, provider/sources, access model, run_on,
    keys, max_requests, expected_latency, min_interval, cache_ttl, absent_statuses, error_markers,
    manual_link, default_enabled) plus ``spec_origin`` (``origin``, e.g.
    'bundled:v3lum/data/specs/<name>.json' or 'user:<path>'), so ``@register``, the policy gate,
    quotas and the registry contract test treat it like a hand-written module. ``disabled`` (a
    reason) compiles an auto-disabled spec: it stays visible but is never default and refuses to run.

    Raises :class:`SpecError` with every schema problem, or with the registration error of
    ``@register`` (the class is then not registered).
    """
    name = str(spec.get("name") or "?") if isinstance(spec, Mapping) else "?"
    if not isinstance(origin, str) or not origin.strip():
        raise SpecError(name, ["origin: compile_spec needs the spec's origin (file path or label)"])
    problems = validate_spec(spec)
    if problems:
        raise SpecError(name, problems)
    doc = _freeze(spec)
    compiled = _compile_internal(doc)
    terms = doc["terms"]
    body: dict[str, Any] = {
        "__module__": "v3lum.core.specs" if origin.startswith("bundled:") else "v3lum_user_specs",
        "__qualname__": f"Spec_{doc['name']}",
        "__doc__": doc["description"],
        "__v3lum_compiled_spec__": True,
        # identity
        "name": doc["name"],
        "title": doc["title"],
        "description": doc["description"],
        "category": doc["category"],
        "reference": doc.get("reference", "") or "",
        "tags": frozenset(doc.get("tags", []) or ()),
        "notice": doc.get("notice", "") or "",
        # inputs / outputs
        "accepts": frozenset(EntityType(t) for t in doc["accepts"]),
        "produces": frozenset(EntityType(t) for t in doc["produces"]),
        "run_on": doc["run_on"],
        # MUST-declare
        "terms": terms,
        "opsec": Opsec.PASSIVE,
        "disclosure": "third_party",
        "hosts": tuple(doc["hosts"]),
        # other ClassVars
        "provider": doc["provider"],
        "sources": tuple(doc["sources"]),
        "access_model": doc["access_model"],
        "requires_keys": tuple(doc["requires_keys"]),
        "optional_keys": tuple(doc["optional_keys"]),
        "max_requests": int(doc["max_requests"]),
        "expected_latency": float(doc["expected_latency"]),
        "min_interval": float(doc["min_interval"]),
        "cache_ttl": doc["cache_ttl"],
        "absent_statuses": frozenset(int(s) for s in doc["absent_statuses"]),
        "error_markers": tuple(doc["error_markers"]),
        "manual_link": doc["manual_link"],
        "default_enabled": bool(doc["default_enabled"]) and not disabled,
        "requires_egress": frozenset(doc.get("requires_egress", []) or ()),
        # spec metadata
        "spec_origin": origin,
        "spec_disabled": str(disabled or ""),
        "spec_document": doc,
        "_compiled": compiled,
    }
    cls = type(f"Spec_{doc['name']}", (SpecModule,), body)
    if register_class:
        from v3lum.core import module as modreg

        with modreg._REGISTER_LOCK:
            existing = modreg.REGISTRY.get(doc["name"])
            if existing is not None:
                # every compiled spec has the synthetic qualname 'Spec_<name>', which @register's
                # same-class rule (meant for re-imported module files) would take for this class
                where = getattr(existing, "spec_origin", "") or f"{existing.__module__}.{existing.__qualname__}"
                raise SpecError(name, [f"registration: duplicate module name {doc['name']!r} (already registered by {where})"])
            try:
                register(cls)
            except RegistrationError as exc:
                raise SpecError(name, [f"registration: {exc}"]) from exc
    return cls


# ======================================================================================
# The runtime base class
# ======================================================================================


@dataclass
class _RunState:
    attr_values: dict[str, list[Any]] = field(default_factory=dict)
    attr_seen: dict[str, set[str]] = field(default_factory=dict)
    attr_list: set[str] = field(default_factory=set)
    tag_hits: dict[int, list[str]] = field(default_factory=dict)
    finding_hits: dict[int, list[str]] = field(default_factory=dict)
    finding_counts: dict[int, int] = field(default_factory=dict)
    made: dict[tuple[str, int], Any] = field(default_factory=dict)
    pivots: int = 0
    pages: list[Any] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class SpecModule(Module):
    """Base class of the modules compiled from declarative specs (never registered itself).

    The compiled subclass declares every contract field; this base only implements ``run()``,
    ``applies()`` and ``health_check()`` from the prepared spec. Spec authors never subclass it:
    they write ``v3lum/data/specs/<name>.json``.
    """

    #: where the spec came from ('bundled:<path>', 'user:<path>' or a caller label); set by compile_spec only.
    spec_origin: ClassVar[str] = ""
    #: auto-disable reason ('' = enabled; P331 cond 9).
    spec_disabled: ClassVar[str] = ""
    #: the validated spec document (a copy).
    spec_document: ClassVar[dict[str, Any]] = {}
    _compiled: ClassVar[_Compiled | None] = None

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        """The spec's ``health_check`` (central benign value; P332 cond 9).

        An auto-disabled spec refuses ordinary runs; its health check also carries a ``selftest``
        that performs the real lookup on the benign value, so ``doctor --sources`` can record a
        passing check and the next load re-enables the spec.
        """
        compiled = cls._compiled
        if compiled is None:
            return None
        etype, value, expect = compiled.health
        if not cls.spec_disabled:
            return HealthCheck(etype=EntityType(etype), value=value, expect=expect)
        return HealthCheck(etype=EntityType(etype), value=value, expect=expect, selftest=cls._selftest)

    @classmethod
    def _selftest(cls, ctx: Any) -> HealthResult:
        """Health probe of an auto-disabled spec: the lookup on the benign value, judged against the
        declared ``expect`` ('ok': the source returns data; 'empty': it answers without data).

        What the environment refuses is never recorded as a failed check: a cancelled run
        (:class:`Cancelled`), a policy or configuration refusal (:class:`PolicyError`,
        :class:`ConfigError`, also when the lookup ends SKIPPED, e.g. a licence-narrowed source) and
        offline mode (:class:`OfflineError`) propagate to the caller (doctor). Quota and missing keys
        are neutral results (HealthState)."""
        compiled = cls._compiled
        if compiled is None:  # pragma: no cover - compiled subclasses only
            return HealthResult("dead", "declarative spec without a compiled body")
        entity = Entity.try_make(EntityType(compiled.health[0]), compiled.health[1])
        if entity is None:  # pragma: no cover - validated at load
            return HealthResult("dead", "invalid health-check value")
        try:
            res = cls()._lookup(entity, ctx)
        except (Cancelled, PolicyError, ConfigError, OfflineError):
            raise
        except (QuotaExceeded, RateLimited) as exc:
            return HealthResult("quota", str(exc))
        except Blocked as exc:
            return HealthResult("blocked", str(exc))
        except AuthRequired as exc:
            return HealthResult("needs_key" if cls.requires_keys or cls.optional_keys else "blocked", str(exc))
        except Exception as exc:  # noqa: BLE001 - every other failure is a dead source for doctor
            return HealthResult("dead", f"{type(exc).__name__}: {exc}")
        status = res.status
        if status is Status.SKIPPED:  # the lookup was refused before any request: not a source failure
            raise PolicyError(res.error or "health check not run", reason_code=res.reason_code or "policy")
        if status is Status.OK and not res.has_data:
            status = Status.EMPTY  # the engine's rule: ok without data is empty
        if status in (Status.OK, Status.EMPTY):
            expect = compiled.health[2] or "ok"
            if status.value != expect:
                return HealthResult("dead", f"health check expected '{expect}' but the source answered '{status.value}' for the benign value")
            return HealthResult("ok", "")
        mapping = {Status.BLOCKED: "blocked", Status.QUOTA: "quota", Status.RATE_LIMITED: "quota", Status.NEEDS_KEY: "needs_key"}
        return HealthResult(mapping.get(status, "dead"), res.error)

    def applies(self, entity: Entity, ctx: Any) -> bool:  # noqa: ARG002 - hook signature
        """False when a placeholder cannot be computed for ``entity`` (e.g. {domain} of a URL with an
        IP host). A URL refused by the host confinement is not 'not applicable': run() raises it and
        the engine reports SKIPPED 'policy'."""
        compiled = type(self)._compiled
        if compiled is None:
            return False
        try:
            compiled.url_for(entity, None)
        except _NotApplicable:
            return False
        except PolicyError:
            return True
        return True

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        """GET the spec's URL for ``entity`` (at most ``max_requests`` pages), classify, parse and map."""
        cls = type(self)
        if cls.spec_disabled:
            return self.result(entity).mark(Status.SKIPPED, cls.spec_disabled, reason_code="demoted")
        return self._lookup(entity, ctx)

    def _lookup(self, entity: Entity, ctx: Any) -> ModuleResult:
        cls = type(self)
        compiled = cls._compiled
        res = self.result(entity)
        if compiled is None:  # pragma: no cover - only compiled subclasses are registered
            return res.mark(Status.ERROR, "declarative spec without a compiled body", reason_code="error")
        if entity.type not in cls.accepts:
            return res.mark(Status.SKIPPED, f"{entity.type.value} is not accepted by this spec", reason_code="not_applicable")
        if cls.trust_tier == "unknown" and entity.type not in IOC_TYPES:  # A8: belt and braces after validation
            return res.mark(Status.SKIPPED, "unknown-tier source: only IOC values are sent (A8)", reason_code="tier")
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and compiled.source not in allowed:  # the policy narrowed the sources (A1)
            return res.mark(Status.SKIPPED, f"source {compiled.source} is not allowed in this run", reason_code="licence")
        headers: dict[str, str] = {}
        missing: list[str] = []
        for name, literal, prefix, key in compiled.headers:
            if not key:
                headers[name] = literal
                continue
            value = ctx.key(key)
            if value:
                headers[name] = f"{prefix} {value}" if prefix else value
            elif key in compiled.required_keys:
                missing.append(key)
        if missing:
            return res.mark(Status.NEEDS_KEY, f"needs API key: {', '.join(sorted(set(missing)))}", reason_code="needs_key")
        options: dict[str, Any] = {"source": compiled.source}
        if headers:
            options["headers"] = headers
        if compiled.profile:
            options.update(allow_redirects=False, retries=0, timeout=PROFILE_TIMEOUT)
        state = _RunState()
        for index, page in enumerate(compiled.pages(cls.max_requests)):
            try:
                url = compiled.url_for(entity, page)
            except _NotApplicable as exc:
                return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
            try:
                resp = ctx.http.get(url, **options)
                outcome = self._outcome(ctx, resp, compiled)
                document = _parse(compiled.fmt, resp.content, resp.text) if outcome == "data" else None
            except (RateLimited, QuotaExceeded, DeadlineExceeded, Cancelled, RequestCapReached):
                raise  # partial runs: the engine keeps what earlier pages produced (stop_reason)
            except Blocked as exc:
                if index == 0:
                    return self._blocked(res, entity, exc)
                state.notes.append(f"page {index + 1}: {exc}: later pages could not be verified")
                break
            except _ParseError as exc:
                if index == 0:
                    return res.mark(Status.ERROR, f"{compiled.title}: {exc}: could not verify", reason_code="error")
                state.notes.append(f"page {index + 1}: {exc}: later pages could not be verified")
                break
            except (HttpError, NetworkError, PolicyError) as exc:
                if index == 0:
                    raise
                state.notes.append(f"page {index + 1}: {exc}: later pages could not be verified")
                break
            if outcome != "data":
                if index == 0:
                    self._no_data(res, compiled, outcome, resp, url)
                break
            produced = self._apply(res, compiled, entity, document, state, ctx)
            state.pages.append(document)
            res.raw = _raw_pages(state.pages)  # evidence kept page by page (a later failure keeps it)
            if index == 0 and compiled.presence_rules:
                self._presence(res, compiled, document, url)
            if compiled.paginate is not None and compiled.paginate.stop_when_empty and not produced:
                break
        if state.notes:
            res.error = "; ".join(state.notes)
        return res

    @staticmethod
    def _outcome(ctx: Any, resp: Any, compiled: _Compiled) -> str:
        """'data', 'absent' or 'ignored'. Classification first (P321): a classified answer raises,
        so an error page - also inside HTTP 200 - is never read as an absence (rule 5)."""
        try:
            ctx.http.check(resp)
        except HttpError:
            if getattr(resp, "classification", None) is None:
                if resp.status in compiled.absent_statuses:
                    return "absent"
                if resp.status in compiled.ignored:
                    return "ignored"
            raise
        if resp.status == 204:
            return "ignored"
        if resp.status in _NOT_READY_STATUSES:  # accepted for later / partial content: the answer is not the data
            raise _ParseError(f"HTTP {resp.status}: {_NOT_READY_STATUSES[resp.status]}")
        if getattr(resp, "truncated", False):
            raise _ParseError("answer truncated at the size limit")
        return "data"

    def _no_data(self, res: ModuleResult, compiled: _Compiled, outcome: str, resp: Any, url: str) -> None:
        source = compiled.source
        if outcome == "absent":
            if compiled.presence_rules:
                res.presence("absent", marker=f"HTTP {resp.status} (documented absence)", url=url, source=source)
            else:
                res.mark(Status.EMPTY)
        elif compiled.presence_rules:
            res.presence("unknown", marker=f"HTTP {resp.status}", url=url, source=source)
        else:
            res.mark(Status.EMPTY)

    def _blocked(self, res: ModuleResult, entity: Entity, exc: Exception) -> ModuleResult:
        """A challenge/geo-block/login wall: BLOCKED with the spec's manual link (A9), never EMPTY."""
        code = str(getattr(exc, "reason_code", "") or "")
        if not valid_reason(Status.BLOCKED, code):
            code = "challenge"
        res.mark(Status.BLOCKED, str(exc) or "blocked: could not verify", reason_code=code)
        link = _manual_link(type(self).manual_link, entity)
        if link is not None:
            res.link(*link)
        return res

    def _presence(self, res: ModuleResult, compiled: _Compiled, document: Any, url: str) -> None:
        found = bool(compiled.found.hits(document)) if compiled.found is not None else False
        absent = bool(compiled.absent.hits(document)) if compiled.absent is not None else False
        source = compiled.source
        if found and not absent:
            marker = f"found: {compiled.found.describe()}" if compiled.found else "found"
            res.presence("found", marker=marker, url=url, source=source)
            if compiled.profile:
                collision = _collision_reason(res.entity)
                res.finding(
                    f"Account found: {compiled.title}",
                    "info",
                    "The handle answers on this site. The same handle does not prove identity (A5)."
                    + (f" High-collision handle ({collision}): many unrelated people use it." if collision else ""),
                    confidence="possible",
                    criterion=f"presence marker matched ({marker}); weak signal: the same handle does not prove identity",
                    tags=["account", "weak_signal"] + (["high_collision"] if collision else []),
                    data={"collision": collision} if collision else None,
                    source=source,
                )
        elif absent and not found:
            marker = f"absent: {compiled.absent.describe()}" if compiled.absent else "absent"
            res.presence("absent", marker=marker, url=url, source=source)
        else:
            res.presence("unknown", marker="contradictory markers" if found and absent else "no marker matched", url=url, source=source)

    @staticmethod
    def _check_time(ctx: Any, res: ModuleResult) -> None:
        """Mapping is CPU work the HTTP deadline never sees: stop it when the run is cancelled or its
        deadline passed (partial results when something was mapped, else 'could not verify')."""
        cancelled = getattr(ctx, "cancelled", None)
        if callable(cancelled) and cancelled():
            raise Cancelled()
        remaining = getattr(ctx, "remaining", None)
        left = remaining() if callable(remaining) else None
        if left is not None and left <= 0:
            if res.has_data:
                raise Cancelled("run deadline reached while mapping the answer: partial results", stop_reason="deadline")
            raise DeadlineExceeded("run deadline reached while mapping the answer: could not verify")

    def _apply(self, res: ModuleResult, compiled: _Compiled, entity: Entity, document: Any, state: _RunState, ctx: Any = None) -> bool:
        """Map one page into ``res`` (attributes, tags, pivots, findings); True when it produced values."""
        cls = type(self)
        produced = False
        records = compiled.records(document)
        for record in records:
            if ctx is not None:
                self._check_time(ctx, res)
            for index, rule in enumerate(compiled.results):
                values = rule.values(record)
                if not values:
                    continue
                produced = True
                if rule.kind == "attribute":
                    bucket = state.attr_values.setdefault(rule.target, [])
                    seen = state.attr_seen.setdefault(rule.target, set())
                    if rule.fmt == "as_list":
                        state.attr_list.add(rule.target)
                    for value in values:
                        key = _text(value)
                        if key not in seen and len(bucket) < MAX_VALUES:
                            seen.add(key)
                            bucket.append(value)
                elif rule.kind == "tag":
                    hits = state.tag_hits.setdefault(index, [])
                    for value in values:
                        if _truthy(value) and len(hits) < MAX_VALUES:
                            hits.append(_text(value)[:200])
                else:
                    for value in values:
                        if state.pivots >= cls.max_pivots or isinstance(value, (dict, list)):
                            break
                        added = res.pivot(rule.target, _text(value), rule.relation, confidence=rule.confidence, expand=rule.expand, note=rule.pretty_name)
                        if added is not None:
                            state.pivots += 1
            for index, frule in enumerate(compiled.findings):
                hits = frule.when.hits(record)
                if hits:
                    state.finding_counts[index] = state.finding_counts.get(index, 0) + 1
                    bucket = state.finding_hits.setdefault(index, [])
                    for hit in hits:
                        if hit not in bucket and len(bucket) < 20:
                            bucket.append(hit)
        for attr, values in state.attr_values.items():
            if values:
                res.attr(attr, list(values) if attr in state.attr_list else values[0])
        for index, hits in state.tag_hits.items():
            if not hits:
                continue
            rule = compiled.results[index]
            title = rule.pretty_name or f"{compiled.title}: {rule.target}"
            description = f"{len(hits)} value(s) at {rule.key}: {', '.join(hits[:5])}"
            # A5: whatever a profile site says about a handle is a weak signal (POSSIBLE at most)
            confidence = "possible" if compiled.profile else "probable"
            self._upsert(res, state, ("tag", index), title, "info", description, confidence,
                         f"{compiled.title} reports {rule.key} = {hits[0]}", (rule.target,), {"path": rule.key, "values": hits[:20]}, compiled.source)
        for index, hits in state.finding_hits.items():
            frule = compiled.findings[index]
            count = state.finding_counts.get(index, 0)
            description = f"{count} record(s) where {frule.when.describe()}: {', '.join(hits[:5])}"
            self._upsert(res, state, ("finding", index), frule.title, frule.severity, description, frule.confidence,
                         frule.criterion, frule.tags, {"rule": frule.when.describe(), "matched": hits, "count": count}, compiled.source)
        return produced

    @staticmethod
    def _upsert(res: ModuleResult, state: _RunState, key: tuple[str, int], title: str, severity: str, description: str,
                confidence: Any, criterion: str, tags: Iterable[str], data: dict[str, Any], source: str) -> None:
        made = state.made.get(key)
        if made is None:
            state.made[key] = res.finding(title, severity, description, confidence=confidence, criterion=criterion,
                                          data=data, tags=list(tags), source=source)
        else:  # a later page matched again: one finding per rule, counts updated
            made.description = description
            made.data = dict(data)


def _manual_link(manual_link: str, entity: Entity) -> tuple[str, str] | None:
    if not manual_link:
        return None
    try:
        from v3lum.core import links

        rendered = links.render_manual(manual_link, entity)
    except Exception:  # pragma: no cover - a link problem never hides the BLOCKED status
        return None
    if rendered is None:
        return None
    return rendered.label, rendered.url


def _raw_pages(pages: list[Any]) -> Any:
    try:
        size = len(json.dumps(pages, ensure_ascii=False))
    except (TypeError, ValueError, RecursionError):
        return {"omitted": "answer is not JSON-serialisable"}
    if size > MAX_RAW_BYTES:
        return {"omitted": f"parsed answer larger than {MAX_RAW_BYTES // 1024} KB", "pages": len(pages)}
    return pages[0] if len(pages) == 1 else {"pages": pages}


# ======================================================================================
# Fixtures, health and loading
# ======================================================================================

def fixture_problems(directory: Path, *, expect: str | None = None) -> list[str]:
    """Why ``directory`` does not hold the fixtures that enable a spec (empty list = complete).

    Needed: ``ok.<ext>`` (trimmed real answer for the health-check value), ``error_in_200.<ext>``
    (a real error/quota/challenge body served with HTTP 200) and ``expected.json``
    (``{"ok": {"status", "attributes", "pivots"}, "error_in_200": {"status", "reason_code"}}``):
    ``ok.status`` is 'ok' or 'empty' (the spec's ``health_check.expect`` when ``expect`` is given),
    the error status a could-not-verify one with a canonical reason code. Never raises.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return [f"fixtures missing: {directory} (ok.*, error_in_200.*, expected.json)"]
    problems = []
    for pattern in ("ok.*", "error_in_200.*"):
        if not [p for p in directory.glob(pattern) if p.is_file() and p.name != "expected.json"]:
            problems.append(f"fixture missing: {directory / pattern}")
    expected_path = directory / "expected.json"
    if not expected_path.is_file():
        return problems + [f"fixture missing: {expected_path}"]
    try:
        if expected_path.stat().st_size > _MAX_SPEC_BYTES:
            return problems + [f"{expected_path}: larger than {_MAX_SPEC_BYTES // 1024} KB"]
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        return problems + [f"{expected_path}: unreadable or invalid JSON ({type(exc).__name__})"]
    if not isinstance(expected, dict) or not isinstance(expected.get("ok"), dict) or not isinstance(expected.get("error_in_200"), dict):
        return problems + [f"{expected_path}: must be {{'ok': {{status, attributes, pivots}}, 'error_in_200': {{status, reason_code}}}}"]
    ok = expected["ok"]
    ok_status = ok.get("status")
    if not isinstance(ok_status, str) or ok_status not in HEALTH_EXPECT:
        problems.append(f"{expected_path}: ok.status must be 'ok' or 'empty' (the answer for the health-check value)")
    elif expect is not None and ok_status != expect:
        problems.append(f"{expected_path}: ok.status {ok_status!r} differs from the spec's health_check.expect {expect!r}")
    if "attributes" in ok and not isinstance(ok["attributes"], dict):
        problems.append(f"{expected_path}: ok.attributes must be an object (a subset of the result attributes)")
    if "pivots" in ok and (not isinstance(ok["pivots"], list) or not all(isinstance(p, str) for p in ok["pivots"])):
        problems.append(f"{expected_path}: ok.pivots must be a list of 'type:value' keys")
    err = expected["error_in_200"]
    status = err.get("status")
    code = err.get("reason_code", "")
    if not isinstance(status, str) or status not in ("blocked", "quota", "rate_limited", "error"):
        problems.append(f"{expected_path}: error_in_200.status must be blocked, quota, rate_limited or error (an error inside HTTP 200 is never an absence)")
    elif not isinstance(code, str) or not valid_reason(status, code):
        problems.append(f"{expected_path}: error_in_200.reason_code {code!r} is not a canonical code of {status!r}")
    return problems


#: Body served for a page of a paginated spec that has no ``ok_page<N>`` fixture (an empty page).
_EMPTY_PAGES: dict[str, bytes] = {
    "json": b"{}", "ndjson": b"", "csv": b"", "rss": b"<rss><channel></channel></rss>", "xml": b"<empty/>",
    "html_json": b"<html><body></body></html>",
}
_FIXTURE_CONTENT_TYPES: dict[str, str] = {
    ".json": "application/json", ".ndjson": "application/x-ndjson", ".jsonl": "application/x-ndjson", ".csv": "text/csv",
    ".rss": "application/rss+xml", ".xml": "application/xml", ".html": "text/html", ".htm": "text/html", ".txt": "text/plain",
}


class _FixtureClient:
    """Offline HTTP client of :func:`check_fixtures`: answers the spec's own request URLs with its
    fixture files (HTTP 200) and refuses anything else (no network, ever)."""

    def __init__(self, routes: Mapping[str, tuple[bytes, str]]) -> None:
        self.routes = dict(routes)

    def request(self, method: str, url: str, **kw: Any) -> Any:
        from v3lum.core.http import Response

        if method.upper() != "GET" or url not in self.routes:
            raise NetworkError(f"offline fixture check: no fixture answers {method} {url}")
        body, ctype = self.routes[url]
        return Response(200, url, {"content-type": ctype}, body, request_url=url, source=str(kw.get("source") or ""))


class _FixtureCtx:
    """The minimal context :func:`check_fixtures` runs a compiled spec with (offline, no deadline)."""

    allowed_sources = None

    def __init__(self, http: Any) -> None:
        self.http = http

    def key(self, name: str) -> str:  # noqa: ARG002 - every declared key is 'configured' with a dummy offline value
        return "offline-fixture-key"

    def cancelled(self) -> bool:
        return False

    def remaining(self) -> float | None:
        return None


def _fixture_file(directory: Path, stem: str) -> Path | None:
    found = sorted(p for p in directory.glob(f"{stem}.*") if p.is_file() and p.name != "expected.json")
    return found[0] if found else None


def _offline_outcome(cls: type[Module], entity: Entity, directory: Path, stem: str) -> tuple[str, str, Any]:
    """(status, reason_code, result) of running ``cls`` on ``entity`` over the ``<stem>.*`` fixtures."""
    from v3lum.core.http import ScopedHttp

    compiled = cls._compiled  # type: ignore[attr-defined]
    routes: dict[str, tuple[bytes, str]] = {}
    for index, page in enumerate(compiled.pages(cls.max_requests)):
        name = stem if index == 0 else f"{stem}_page{index + 1}"
        path = _fixture_file(directory, name)
        if path is None and index == 0:
            return "missing", "", None
        if path is None:
            body, ctype = _EMPTY_PAGES.get(compiled.fmt, b""), "text/plain"
        else:
            body, ctype = path.read_bytes(), _FIXTURE_CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
        routes[compiled.url_for(entity, page)] = (body, ctype)
        if stem != "ok":
            break  # the error fixture answers the first page only
    keyed = bool(cls.requires_keys or cls.optional_keys)
    http = ScopedHttp(
        _FixtureClient(routes), module=cls.name, provider=cls.provider, sources=cls.sources, allowed_hosts=cls.hosts,
        disclosure="third_party", max_requests=cls.max_requests, error_markers=cls.error_markers, keyless=not keyed,
    )
    try:
        res = cls()._lookup(entity, _FixtureCtx(http))  # type: ignore[attr-defined]
    except QuotaExceeded as exc:
        return "quota", str(getattr(exc, "reason_code", "") or "quota"), None
    except RateLimited:
        return "rate_limited", "rate_limited", None
    except Blocked as exc:
        code = str(getattr(exc, "reason_code", "") or "")
        return "blocked", code if valid_reason(Status.BLOCKED, code) else "challenge", None
    except AuthRequired:
        return ("needs_key", "needs_key", None) if keyed else ("blocked", "challenge", None)
    except HttpError as exc:
        code = str(getattr(exc, "reason_code", "") or "")
        return "error", code if valid_reason(Status.ERROR, code) else "error", None
    except (NetworkError, RequestCapReached, Cancelled) as exc:
        return "error", "error", str(exc)
    except PolicyError as exc:
        return "skipped", str(getattr(exc, "reason_code", "") or "policy"), None
    status = res.status
    if status is Status.OK and not res.has_data:
        status = Status.EMPTY
    return status.value, res.reason_code or "", res


def check_fixtures(cls: type[Module], directory: str | Path) -> list[str]:
    """Run a compiled, registered spec offline over its own fixtures - the 'parametrized test' of
    P331 cond 7 for specs that no CI runs (user specs): ``ok.*`` (and ``ok_page<N>.*``) must give
    ``expected.ok`` (status, attributes subset, pivots subset) and ``error_in_200.*`` served with HTTP
    200 must give ``expected.error_in_200`` (a could-not-verify status and reason code, never an
    absence). Empty list = the spec behaves as its fixtures say. Never raises, never uses the network.
    """
    directory = Path(directory)
    compiled = getattr(cls, "_compiled", None)
    hc = cls.health_check() if compiled is not None else None
    entity = hc.entity if hc is not None else None
    if compiled is None or entity is None:
        return ["not a compiled spec with a health-check value"]
    try:
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        want_ok, want_err = dict(expected["ok"]), dict(expected["error_in_200"])
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        return [f"expected.json unreadable ({type(exc).__name__})"]
    problems: list[str] = []
    try:
        status, code, res = _offline_outcome(cls, entity, directory, "ok")
        if status != want_ok.get("status"):
            detail = f" ({code})" if code else ""
            problems.append(f"fixture ok: the spec gives {status!r}{detail}, expected.json says {want_ok.get('status')!r}")
        elif res is not None:
            attrs = want_ok.get("attributes") or {}
            wrong = sorted(k for k, v in attrs.items() if res.attributes.get(k) != v) if isinstance(attrs, dict) else ["?"]
            if wrong:
                problems.append(f"fixture ok: attributes {wrong} differ from expected.json")
            keys = {p.entity.key for p in res.pivots}
            missing = sorted(set(want_ok.get("pivots") or []) - keys)
            if missing:
                problems.append(f"fixture ok: pivots {missing} not produced")
        status, code, _res = _offline_outcome(cls, entity, directory, "error_in_200")
        if (status, code) != (want_err.get("status"), want_err.get("reason_code")):
            problems.append(
                f"fixture error_in_200: the spec gives {status!r}/{code!r}, expected.json says "
                f"{want_err.get('status')!r}/{want_err.get('reason_code')!r} (an error inside HTTP 200 must be 'could not verify')"
            )
    except Exception as exc:  # noqa: BLE001 - a fixture that breaks the spec refuses it, never the loader
        problems.append(f"fixture check failed ({type(exc).__name__}: {exc})")
    return problems


def _insecure(path: Path) -> list[str]:
    """paths.insecure_reasons (WP10), with an equivalent local check while it is unavailable."""
    from v3lum import paths

    check = getattr(paths, "insecure_reasons", None)
    if callable(check):
        return list(check(path))
    import os  # pragma: no cover - fallback for a tree without WP10
    import stat

    try:  # pragma: no cover
        st = os.stat(path)
    except FileNotFoundError:  # pragma: no cover
        return []
    reasons = []  # pragma: no cover
    if hasattr(os, "getuid") and st.st_uid != os.getuid():  # pragma: no cover
        reasons.append(f"{path}: owned by another user")
    if stat.S_IMODE(st.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):  # pragma: no cover
        reasons.append(f"{path}: group- or world-writable")
    return reasons  # pragma: no cover


def _tree_insecure(directory: Path) -> list[str]:
    reasons = list(_insecure(directory))
    if directory.is_dir():
        for item in sorted(directory.rglob("*")):
            reasons.extend(_insecure(item))
    return reasons


def _home_path() -> Path:
    """The V3LUM home path (``$V3LUM_HOME`` or ``~/.v3lum``) without creating it."""
    return Path(os.environ.get("V3LUM_HOME") or Path.home() / ".v3lum")


def _health_state(health: Any) -> Any:
    """The health state to consult: ``health`` when given, else ``health.HealthState.load()`` of the
    home's health file (WP07; read only - a missing file is an empty state)."""
    if health is not None:
        return health
    try:
        from v3lum.core import health as health_mod
    except ImportError:  # pragma: no cover - a tree without WP07
        return None
    state_cls = getattr(health_mod, "HealthState", None)
    loader = getattr(state_cls, "load", None) if state_cls is not None else None
    if not callable(loader):  # pragma: no cover
        return None
    try:
        return loader(_home_path() / str(getattr(health_mod, "HEALTH_FILE", "health.json")))
    except Exception:  # pragma: no cover - a broken health file never blocks loading
        log.warning("health state unavailable: specs are not auto-disabled")
        return None


def failing_days(name: str, *, health: Any = None) -> int:
    """Consecutive days on which the health checks of ``name`` failed, since its last passing check
    (``HealthState.consecutive_failed_days``; 0 without a health state or records)."""
    state = _health_state(health)
    fn = getattr(state, "consecutive_failed_days", None) if state is not None else None
    if not callable(fn):
        return 0
    try:
        value = fn(name)
    except Exception:  # pragma: no cover - a broken record means 'no evidence'
        return 0
    return int(value) if _is_int(value) and value > 0 else 0


def auto_disabled(name: str, *, health: Any = None) -> str:
    """The auto-disable reason of a spec ('' = enabled): its health checks failed on
    ``AUTO_DISABLE_DAYS`` (7) consecutive days (P331 cond 9; the next passing check lifts it)."""
    days = failing_days(name, health=health)
    if days >= AUTO_DISABLE_DAYS:
        return (
            f"auto-disabled: health checks failed on {days} consecutive days (P331) - it returns once a check passes "
            "again (v3lum doctor --sources)"
        )
    return ""


def _set_error(key: str, message: str) -> None:
    from v3lum.core import module as modreg

    modreg._set_load_error(key, message)


def _clear_errors() -> None:
    from v3lum.core import module as modreg

    modreg._clear_load_errors("spec:")


def _lint_problems(path: Path) -> list[str]:
    """P327 data lint (WP09 ``lint.lint_data_file``) of one spec file."""
    fn = getattr(_lint, "lint_data_file", None)
    if not callable(fn):
        return []
    try:
        issues = fn(path)
    except Exception as exc:
        return [f"lint failed ({type(exc).__name__}: {exc})"]
    out = []
    for issue in issues or ():
        if getattr(issue, "allowed", False):
            continue
        rule = getattr(issue, "rule_id", "")
        message = getattr(issue, "message", "") or str(issue)
        out.append(f"{rule}: {message}" if rule else message)
    return out


def _read_spec(path: Path) -> tuple[Any, str]:
    """(parsed spec, '') or (None, problem); never raises (one broken file never stops the others)."""
    try:
        if path.stat().st_size > _MAX_SPEC_BYTES:
            return None, f"spec file larger than {_MAX_SPEC_BYTES // 1024} KB"
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"unreadable ({exc.strerror or exc})"
    except UnicodeDecodeError:
        return None, "not UTF-8 text"
    try:
        return json.loads(text), ""
    except ValueError as exc:
        return None, f"invalid JSON ({exc})"
    except RecursionError:
        return None, "invalid JSON (nested too deeply)"


def _spec_files(directory: Path) -> list[Path]:
    try:
        if not directory.is_dir():
            return []
        return sorted(p for p in directory.glob("*.json") if p.is_file() and not p.name.startswith(("_", ".")))
    except OSError as exc:  # an unreadable directory has nothing to load (and never stops the bundled specs)
        _set_error(f"spec:{directory}", f"spec directory unreadable ({exc.strerror or exc})")
        return []


def _user_dir() -> Path:
    return _home_path() / USER_DIR_NAME


def _origin_label(kind: str, path: Path) -> str:
    """'bundled:v3lum/data/specs/<name>.json' (repository-relative when possible) or 'user:<path>'."""
    if kind == "bundled":
        try:
            return f"bundled:{path.resolve().relative_to(REPO_ROOT).as_posix()}"
        except ValueError:
            return f"bundled:{path.as_posix()}"
    return f"user:{path}"


def _error_key(name: Any, path: Path, claimed: Mapping[str, str]) -> str:
    """Load-error key of a refused spec file: 'spec:<name>' for a well-formed name that nothing else
    uses, else 'spec:<path>'. A refused file must never put an error under the name of a registered
    module or of another spec: the policy gate (POL-02) skips a registered class whose name carries a
    'spec:<name>' load error, so a broken or colliding user spec would disable the module it collides
    with."""
    from v3lum.core import module as modreg

    if isinstance(name, str) and _NAME_RE.match(name) and name == path.stem and name not in claimed and name not in modreg.REGISTRY:
        return f"spec:{name}"
    return f"spec:{path}"


def _load_one(
    kind: str, path: Path, fixture_dir: Path, origin: str, claimed: dict[str, str], health: Any, state: Any
) -> tuple[type[Module] | None, str, Any]:
    """Load one spec file: (registered class | None, auto-disable reason, health state)."""
    from v3lum.core import module as modreg

    data, problem = _read_spec(path)
    if problem:
        _set_error(f"spec:{path}", problem)
        return None, "", state
    raw_name = data.get("name") if isinstance(data, dict) else None
    name = raw_name if isinstance(raw_name, str) and raw_name else path.stem
    key = _error_key(name, path, claimed)
    problems: list[str] = []
    if name != path.stem:
        problems.append(f"file name must be '{str(name)[:64]}.json' (spec name = file stem)")
    if kind == "user":
        problems += [f"refused (AR12): {r}" for r in _insecure(path) + _tree_insecure(fixture_dir)]
    if name in claimed:
        problems.append(f"name already used by {claimed[name]}")
    existing = modreg.REGISTRY.get(name)
    if existing is not None:
        problems.append(f"name collides with module {existing.__module__}.{existing.__qualname__}")
    if not problems:
        problems += validate_spec(data)
    if not problems:
        problems += _lint_problems(path)
    if not problems:
        expect = data["health_check"].get("expect", "ok")
        problems += fixture_problems(fixture_dir, expect=expect)
    if problems:
        _set_error(key, "; ".join(problems))
        if key == f"spec:{name}":
            claimed.setdefault(name, origin)  # a refused spec still owns its name: a later file never takes it over
        return None, "", state
    if state is None:
        state = _health_state(health) or False
    reason = auto_disabled(name, health=state) if state else ""
    try:
        cls = compile_spec(data, origin=origin, disabled=reason)
    except SpecError as exc:
        _set_error(key, "; ".join(exc.problems))
        claimed.setdefault(name, origin)
        return None, "", state
    if kind == "user":  # no CI runs a user spec: its own fixtures are its test (P331 cond 7)
        problems = check_fixtures(cls, fixture_dir)
        if problems:
            if modreg.REGISTRY.get(name) is cls:
                modreg.unregister(name)
            _set_error(key, "; ".join(problems))
            claimed.setdefault(name, origin)
            return None, "", state
    claimed[name] = origin
    return cls, reason, state


def load_specs(
    *,
    bundled_dir: str | Path | None = None,
    user_dir: str | Path | None = None,
    fixtures_dir: str | Path | None = None,
    health: Any = None,
    include_user: bool = True,
) -> list[type[Module]]:
    """Compile and register the bundled and user specs; problems go to ``module.load_errors()``.

    * bundled: ``v3lum/data/specs/<name>.json`` with fixtures in ``tests/fixtures/specs/<name>/``;
    * user: ``~/.v3lum/specs/<name>.json`` with fixtures in ``~/.v3lum/specs/<name>/``, loaded only
      when the directory, every spec file and every fixture is owned by the current user and not
      group/world-writable (``paths.insecure_reasons``, AR12);
    * every spec is schema-validated, linted (``lint.lint_data_file``), refused without its fixtures
      (``ok.*``, ``error_in_200.*``, ``expected.json``) and registered through ``@register``; a name
      already taken by a module or an earlier spec is refused (user specs never shadow bundled ones);
    * specs whose health checks failed on 7 consecutive days load auto-disabled (:func:`disabled`;
      ``HealthState.notices()`` carries the doctor notice).

    ``include_user=False`` skips the user directory (``module.load_modules()`` without user
    directories). Errors are recorded under ``'spec:<name>'`` (``'spec:<path>'`` for an unreadable
    file or a refused directory), never raised. Every spec of an earlier load is unregistered first, so a
    removed or now-refused spec disappears. Returns the registered spec classes.
    """
    from v3lum.core import module as modreg

    bundled = Path(bundled_dir) if bundled_dir is not None else BUNDLED_DIR
    fixtures = Path(fixtures_dir) if fixtures_dir is not None else BUNDLED_FIXTURES_DIR
    user = Path(user_dir) if user_dir is not None else _user_dir()
    with _LOCK:
        _clear_errors()
        for name, cls in _LOADED.items():  # a reload starts from scratch: removed specs disappear
            if modreg.REGISTRY.get(name) is cls:
                modreg.unregister(name)
        _LOADED.clear()
        _DISABLED.clear()
        state: Any = None
        loaded: list[type[Module]] = []
        claimed: dict[str, str] = {}
        sources: list[tuple[str, Path, Path]] = [("bundled", path, fixtures / path.stem) for path in _spec_files(bundled)]
        user_refused = _insecure(user) if include_user else []
        if user_refused:
            _set_error(f"spec:{user}", "user spec directory refused (AR12): " + "; ".join(user_refused) + " - chmod 700 and own it")
        elif include_user:
            sources += [("user", path, user / path.stem) for path in _spec_files(user)]
        for kind, path, fixture_dir in sources:
            origin = _origin_label(kind, path)
            try:
                cls, reason, state = _load_one(kind, path, fixture_dir, origin, claimed, health, state)
            except Exception as exc:  # noqa: BLE001 - one broken spec never stops the others (or the tool)
                _set_error(f"spec:{path}", f"spec not loaded: {type(exc).__name__}: {exc}")
                log.warning("declarative spec %s not loaded: %s", path, exc)
                continue
            if cls is None:
                continue
            _LOADED[cls.name] = cls
            if reason:
                _DISABLED[cls.name] = reason
            loaded.append(cls)
        return loaded


def loaded() -> dict[str, type[Module]]:
    """The spec classes registered by the last :func:`load_specs` (name -> class)."""
    with _LOCK:
        return dict(_LOADED)


def disabled() -> dict[str, str]:
    """Auto-disabled specs of the last load (name -> reason; P331 cond 9)."""
    with _LOCK:
        return dict(_DISABLED)
