"""Shared lint tables for the team rules on probe and link URLs (thin wave-1 file, WP05).

Rule ids (WP09 extends this file in wave 2 with the full static lint, keeping these names):

* ``LINT-03`` - account-enumeration, availability, password-reset, SMTP-verification and login endpoints
  (team rule 2, A5 rule 2, A7): :data:`FORBIDDEN_PROBE_PATTERNS`;
* ``LINT-04`` - CPF lookups, people-search 'painéis' and leaked-database sites (team rule 4, LGPD):
  :data:`CPF_LOOKUP_HOSTS`, :data:`PEOPLE_SEARCH_DENYLIST`, 'painel' hosts and a ``cpf`` token in the path
  or query;
* ``LINT-05`` - endpoints that submit or publish the value (team rule 7: urlscan.io scan submission,
  VirusTotal upload/scan, web.archive.org/save, archive.today submit, public recent-searches boards,
  scan triggers): :data:`SUBMISSION_PATTERNS`.

:func:`forbidden_probe` is the single check used by the pivot-pack lint (``links.lint_pack``) and by
module authors to drop forbidden entries from runtime-downloaded site lists (WhatsMyName/Maigret data
that CI cannot see)::

    from v3lum.core.lint import forbidden_probe
    sites = [s for s in sites if forbidden_probe(s["uri_check"], method=s.get("method", "GET")) is None]

Endpoint keywords are matched in the path, query and fragment only (never the host name), as whole
tokens: separators, string ends and camelCase boundaries delimit them (``check_username``,
``checkUsername``, ``validateField`` match; ``invalidate`` and ``registered`` do not). Oracles that take
the account as a query parameter are caught too: a verb in the last path segment (check, verify,
available, exists, taken, reset...) with an account-named parameter (``/api/check?username=``,
``/v2/verify?email=``), and verification/availability paths around a placeholder
(``/verify/{account}``, ``/usernames/{account}/available``). A reputation page such as
``/check/{ip}`` stays allowed. Patterns are linear (no nested unbounded quantifiers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

LINT_ENUMERATION = "LINT-03"
LINT_PEOPLE_SEARCH = "LINT-04"
LINT_SUBMISSION = "LINT-05"

#: The probe/link rules of this file (id -> text). WP09 publishes the complete table as LINT_RULES.
PROBE_RULES: dict[str, str] = {
    LINT_ENUMERATION: "account-enumeration, availability, password-reset, e-mail verification and login endpoints "
    "are never probed (team rule 2, A5 rule 2, A7)",
    LINT_PEOPLE_SEARCH: "no CPF lookups, people-search panels ('painéis') or leaked-database sites (team rule 4, LGPD)",
    LINT_SUBMISSION: "never send values to endpoints that submit, scan or publish them (team rule 7)",
}

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _kw(body: str) -> str:
    """Whole-token keyword: start/separator or camelCase boundary on the left, no lower-case letter or
    digit on the right (case-sensitive), so 'checkUsername' and 'login.php' match but 'invalidate' not."""
    return r"(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z0-9])(?=[A-Z])))(?:" + body + r")(?-i:(?![a-z0-9]))"


def _segment_and_params(request: str) -> tuple[str, list[str]]:
    """(last path segment, query parameter names) of a request part; at most 64 parameters are read."""
    head = request.split("#", 1)[0]
    path, _, query = head.partition("?")
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    names = [unquote_plus(p.split("=", 1)[0]) for p in query.split("&", 64)[:64] if p] if query else []
    return segment, names


@dataclass(frozen=True)
class ProbePattern:
    """One lint pattern.

    ``target`` is 'request' (matched against path + query + fragment) or 'location' (host + path + query +
    fragment, for host-specific endpoints). ``methods`` limits the pattern to those HTTP methods (None =
    any method). With ``params`` set, ``regex`` is searched in the last path segment only and the pattern
    matches when a query parameter name fully matches ``params`` (e.g. ``/api/check?username=``).
    """

    rule_id: str
    name: str
    regex: re.Pattern[str]
    target: str = "request"
    methods: frozenset[str] | None = None
    description: str = ""
    params: re.Pattern[str] | None = None

    def matches(self, host: str, request: str, method: str | None = "GET") -> bool:
        if self.methods is not None and str(method or "GET").upper() not in self.methods:
            return False
        if self.params is not None:
            segment, names = _segment_and_params(request)
            return self.regex.search(segment) is not None and any(self.params.fullmatch(n) for n in names)
        subject = request if self.target == "request" else host + request
        return self.regex.search(subject) is not None


def _p(rule: str, name: str, body: str, *, target: str = "request", methods: frozenset[str] | None = None,
       description: str = "", raw: bool = False, params: str | None = None) -> ProbePattern:
    pattern = body if raw else _kw(body)
    compiled_params = re.compile(params, re.I) if params is not None else None
    return ProbePattern(rule, name, re.compile(pattern, re.I), target, methods, description, compiled_params)


_ACCOUNT_NOUN = r"user[-_]?name|unique[-_]?id|e[-_]?mail|email|phone|account|handle|login"
#: Query parameter names that carry an account identifier ('username', 'requested_username', 'emailAddress',
#: 'phone_number', 'login'...), for the parameter form of the existence/availability checks.
_ACCOUNT_PARAM = (
    r"(?:[a-z0-9]{0,24}[-_])?(?:user[-_]?name|user|e[-_]?mail|email|login|handle|account|phone|mobile|msisdn|"
    r"unique[-_]?id|nick(?:name)?|screen[-_]?name)(?:[-_]?(?:address|addr|id|number|name))?"
)
#: Verbs of existence/availability/verification oracles (and of reset flows in the parameter form).
_ORACLE_VERB = r"check|verify|verification|validate|validation|available|availability|exists?|taken"
#: Neutral placeholder tokens of probe/link templates: '{account}' (WhatsMyName), '{}' (Sherlock),
#: '{username}' (Maigret), '{value}' (links._probe_sample) and '%s'.
_VALUE_TOKEN = r"(?:\{[A-Za-z0-9_]{0,32}\}|%s)"

#: LINT-03: account enumeration, availability checks, password reset/recovery, e-mail (SMTP) verification
#: and login/sign-up endpoints (team rule 2, A5 rule 2, A7).
FORBIDDEN_PROBE_PATTERNS: tuple[ProbePattern, ...] = (
    # 'signup' also inside a word (emailsignup, accountsignup): never a profile page.
    _p(LINT_ENUMERATION, "signup", r"sign[-_]?up(?-i:(?![a-z0-9]))", raw=True, description="sign-up endpoint"),
    _p(LINT_ENUMERATION, "register", r"register|registration", description="registration endpoint"),
    _p(LINT_ENUMERATION, "create_account", r"create[-_]?(?:an[-_]?)?account|account[-_/]?creat(?:e|ion)|new[-_]?account|"
       r"web[-_]?create(?:[-_]?ajax)?", description="account-creation endpoint"),
    _p(LINT_ENUMERATION, "availability", r"availability", description="availability check"),
    _p(LINT_ENUMERATION, "check_account", r"(?:check|verify|validate|lookup)[-_/]?(?:" + _ACCOUNT_NOUN + r")",
       description="account/username/e-mail existence check"),
    _p(LINT_ENUMERATION, "account_check", r"(?:" + _ACCOUNT_NOUN + r")[-_/]?(?:check|exists?|available|availability|taken|"
       r"verif[a-z]*|validat[a-z]*|suggest[a-z]*)", description="account/username/e-mail existence or verification check"),
    _p(LINT_ENUMERATION, "check_account_param", _ORACLE_VERB + r"|recover|reset|forgot", params=_ACCOUNT_PARAM,
       description="existence/availability/verification/reset endpoint taking the account as a query parameter "
       "(/api/check?username=, /verify?email=)"),
    _p(LINT_ENUMERATION, "verify_value", r"(?:verify|verification|validate|validation|available|availability|exists?|taken)/"
       + _VALUE_TOKEN, description="verification/availability endpoint taking the value as a path segment (/verify/{value})"),
    _p(LINT_ENUMERATION, "account_state_path", r"(?:users?|" + _ACCOUNT_NOUN + r")s?/[^/?#]{1,128}/(?:available|availability|"
       r"exists?|taken)", description="availability/existence state of an account path (/usernames/{account}/available)"),
    _p(LINT_ENUMERATION, "user_state", r"users?[-_/]?(?:exists?|available|availability|taken)|is[-_]?(?:available|taken|registered)",
       description="account existence/availability oracle (user/exists, isAvailable, is_taken)"),
    _p(LINT_ENUMERATION, "validate", r"validate", description="validation endpoint (enumeration oracle)"),
    _p(LINT_ENUMERATION, "password_reset", r"password[-_/]?(?:reset|recover[a-z]*|forgot[a-z]*|new|lost)|reset[-_/]?password|"
       r"lost[-_]?password|recover[-_/]?(?:password|account)|account[-_/]?recovery|forgot(?:ten)?(?:[-_]?password)?",
       description="password reset / account recovery"),
    _p(LINT_ENUMERATION, "login", r"log[-_]?in|sign[-_]?in", description="login page or endpoint"),
    _p(LINT_ENUMERATION, "credential_post", r"passwords?|passwd|sessions?|authenticate|auth",
       methods=STATE_CHANGING_METHODS, description="state-changing request to a password/session/auth endpoint (login attempt)"),
)

#: LINT-04 hosts whose purpose is a lookup by CPF (CPF is validated offline only; research C0294, C0583, C0591).
CPF_LOOKUP_HOSTS: frozenset[str] = frozenset({
    "cadastropre.com.br",  # prepaid phone lines by CPF
    "valoresareceber.bcb.gov.br",  # CPF + birth date lookup
    "portalbnmp.cnj.jus.br",  # arrest-warrant search by CPF/name
})

#: LINT-04 people-search panels, leaked-database / plaintext-password services, identity aggregators built
#: on enumeration, caller-ID people search and face-search engines (research C0216, C0295, C0320, C0592,
#: C0595, C0607; biometrics are out of scope). A subdomain of a listed host is listed too.
PEOPLE_SEARCH_DENYLIST: frozenset[str] = frozenset({
    # Brazilian people-search panels
    "tudosobretodos.info",
    "buscaprime.com.br",
    # leaked databases / plaintext passwords
    "dehashed.com",
    "snusbase.com",
    "leakedpassword.com",
    "antipublic.net",
    "osint.lolarchiver.com",
    "leaks-api.io",
    "hackcheck.io",
    "scatteredsecrets.com",
    "osintleak.com",
    "breachbase.com",
    # commercial identity aggregators built on account enumeration
    "osint.industries",
    "predictasearch.com",
    "castrickclues.com",
    "defastra.com",
    # crowd-sourced caller-ID people search
    "truecaller.com",
    "getcontact.com",
    "sync.me",
    # face-search engines (biometrics)
    "pimeyes.com",
    "facecheck.id",
    "search4faces.com",
    "lenso.ai",
    "findclone.ru",
    "faceonlive.com",
})

#: Official suffixes exempt from the 'painel' host heuristic (government data dashboards).
_OFFICIAL_SUFFIXES = (".gov.br", ".jus.br", ".leg.br", ".mil.br", ".mp.br", ".def.br", ".gov")
_RE_CPF_TOKEN = re.compile(_kw(r"cpfs?"), re.I)
_RE_PAINEL_HOST = re.compile(r"painel|paineis", re.I)

#: LINT-05: submission/publishing endpoints (team rule 7). Host-specific entries use target 'location'.
SUBMISSION_PATTERNS: tuple[ProbePattern, ...] = (
    _p(LINT_SUBMISSION, "urlscan_scan", r"(?:^|\.)urlscan\.io/api/v\d+/scan(?![A-Za-z0-9])", target="location", raw=True,
       description="urlscan.io scan submission (public scans by default)"),
    _p(LINT_SUBMISSION, "virustotal_submit", r"(?:^|\.)virustotal\.com/(?:api/v3/(?:files|urls)/?(?:$|[?#])|"
       r"api/v3/files/upload_url|api/v3/(?:files|urls)/[^/?#]+/analyse|vtapi/v2/(?:file|url)/(?:scan|rescan)|gui/home/upload)",
       target="location", raw=True, description="VirusTotal upload / URL scan (shared with the community)"),
    _p(LINT_SUBMISSION, "archive_save", r"(?:^|\.)web\.archive\.org/save(?![A-Za-z0-9])", target="location", raw=True,
       description="Wayback Machine 'save page now' (publishes the URL)"),
    _p(LINT_SUBMISSION, "archive_today_submit", r"(?:^|\.)archive\.(?:ph|today|is|li|vn|fo|md)/submit", target="location", raw=True,
       description="archive.today submission (publishes the URL)"),
    _p(LINT_SUBMISSION, "archive_today_run", r"(?:^|\.)archive\.(?:ph|today|is|li|vn|fo|md)/[^#]*?[?&]run=1(?![0-9])",
       target="location", raw=True, description="archive.today '?run=1&url=' shortcut (archives and publishes the URL)"),
    _p(LINT_SUBMISSION, "ssllabs_public_board", r"(?:^|\.)ssllabs\.com/ssltest/analyze\.html(?![^#]*hideResults=on)",
       target="location", raw=True, description="SSL Labs scan shown on the public 'recently seen' boards (needs hideResults=on)"),
    _p(LINT_SUBMISSION, "securityheaders_public", r"(?:^|\.)securityheaders\.com/(?:\?|$)(?![^#]*\bhide=on)",
       target="location", raw=True, description="securityheaders.com scan listed publicly (needs hide=on)"),
    _p(LINT_SUBMISSION, "recent_searches", r"recent[-_/]?(?:searches|search|lookups|lookup|scans|queries|checks)",
       description="public recent-searches/lookups page"),
    _p(LINT_SUBMISSION, "submit", r"submit[a-z]*|submission", description="submission endpoint"),
    _p(LINT_SUBMISSION, "scan_trigger", r"scan[-_]?trigger", description="scan trigger"),
    _p(LINT_SUBMISSION, "state_changing_submission", r"(?:re)?scan|upload|analy[sz]e|analysis|save|publish",
       methods=STATE_CHANGING_METHODS, description="state-changing submission (scan/upload/analysis/save/publish)"),
)

_RE_AUTHORITY = re.compile(r"^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]*)(.*)$", re.I | re.S)
_RE_BARE_HOST = re.compile(r"^([A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?::\d{1,5})?)([/?#].*)?$", re.S)


def split_probe_url(url: str) -> tuple[str, str]:
    """(host, request part) of a URL, a scheme-less 'host/path' or a bare path/string literal.

    The host is lower-cased without userinfo, port or brackets; the request part is path + query +
    fragment. Placeholders such as ``{account}`` or ``%s`` are kept as text.
    """
    s = str(url or "").strip()
    m = _RE_AUTHORITY.match(s)
    if m:
        authority, rest = m.group(1), m.group(2)
    else:
        b = _RE_BARE_HOST.match(s)
        authority, rest = (b.group(1), b.group(2) or "") if b else ("", s)
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1 : host.find("]")] if "]" in host else host[1:]
    else:
        host = host.split(":", 1)[0]
    return host.lower().rstrip("."), rest


def _host_listed(host: str, table: frozenset[str]) -> bool:
    return any(host == h or host.endswith("." + h) for h in table)


def people_search_host(host: str) -> bool:
    """True for CPF-lookup hosts, people-search/leak denylist hosts and non-official 'painel' hosts."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if _host_listed(h, CPF_LOOKUP_HOSTS) or _host_listed(h, PEOPLE_SEARCH_DENYLIST):
        return True
    return bool(_RE_PAINEL_HOST.search(h)) and not h.endswith(_OFFICIAL_SUFFIXES)


def probe_violations(url: str, *, method: str | None = "GET") -> list[str]:
    """Every LINT rule id (sorted) that ``url`` violates for ``method`` (None = GET); [] when it is allowed."""
    method = str(method or "GET")
    host, request = split_probe_url(url)
    found: set[str] = set()
    if people_search_host(host) or _RE_CPF_TOKEN.search(request):
        found.add(LINT_PEOPLE_SEARCH)
    if any(p.matches(host, request, method) for p in SUBMISSION_PATTERNS):
        found.add(LINT_SUBMISSION)
    if any(p.matches(host, request, method) for p in FORBIDDEN_PROBE_PATTERNS):
        found.add(LINT_ENUMERATION)
    return sorted(found)


def forbidden_probe(url: str, *, method: str | None = "GET") -> str | None:
    """The LINT rule id the URL violates ('LINT-03', 'LINT-04' or 'LINT-05', lowest first), else None.

    Use it to drop forbidden entries from runtime-downloaded site lists and from any data file with
    probe URLs; ``links.lint_pack`` applies the same check to every pivot-link template.
    """
    hits = probe_violations(url, method=method)
    return hits[0] if hits else None
