"""Forbidden-capability lint (P327 static rules, WP09) and the shared probe/link tables (WP05).

Every rule has an id quoted in its messages and in docs/RULES.md (:data:`LINT_RULES`):

* ``LINT-00`` - a source or data file the lint cannot parse, or a data file that fails its schema;
* ``LINT-01`` - direct network or process APIs in modules: socket, ssl sockets outside ctx.net,
  urllib.request, http.client, requests/httpx/aiohttp and other clients, browser automation,
  subprocess/os.system (modules use ctx.http, ctx.dns and ctx.net; external binaries only through
  ``ctx.net.run_tool``; subprocess is accepted only in ``v3lum/core/tools.py``); core clients built
  in a module (:data:`CORE_CLIENT_CLASSES`, ``ScopedHttp`` included; :data:`CORE_BUILT_NAMES`, a
  Runtime or Context of its own), code that reaches the shared client around ctx.http/ctx.net
  (:data:`REACH_AROUND_PATH`: ``ctx.http.client``, ``ctx.runtime.http``, private ctx.net members...,
  through aliases of ctx, helper parameters and getattr too) and code that rebinds the module's
  network scope (:data:`CTX_NETWORK_PATH`: ``ctx.http.allowed_hosts = None``,
  ``ctx.runtime.in_scan = False``...);
* ``LINT-02`` - anti-bot/CAPTCHA bypass and borrowed-session dependencies (cloudscraper,
  FlareSolverr, undetected browsers, stealth plugins, TLS impersonation, CAPTCHA solvers,
  browser-cookie readers) and CAPTCHA-solver service hosts;
* ``LINT-03`` - account-enumeration, availability, password-reset, e-mail (SMTP) verification and
  login endpoints, identity-host account lookups and credentials or borrowed sessions sent in a
  request (team rule 2, A5 rule 2, A7): :data:`FORBIDDEN_PROBE_PATTERNS`, :data:`SMTP_VERIFICATION_HOSTS`;
* ``LINT-04`` - CPF lookups, people-search 'painéis' and leaked-database sites (team rule 4, LGPD):
  :data:`CPF_LOOKUP_HOSTS`, :data:`PEOPLE_SEARCH_DENYLIST`, 'painel' hosts and a ``cpf`` token in the
  path or query;
* ``LINT-05`` - endpoints that submit or publish the value (team rule 7: urlscan.io scan submission,
  VirusTotal upload/scan, web.archive.org/save, archive.today submit, public recent-searches boards,
  scan triggers): :data:`SUBMISSION_PATTERNS`;
* ``LINT-06`` - state-changing HTTP methods (POST/PUT/PATCH/DELETE) in LIGHT/ACTIVE modules (any
  non-GET method in a declarative spec) unless an approved fragment of
  ``v3lum/data/policy/method_allowlist/`` lists the module and the method;
* ``LINT-07`` - credential/password field names produced outside a P145 sanitizer schema;
* ``LINT-08`` - hash or JWT cracking (hashcat/john wrappers, JWT brute forcers, hash-reversal sites);
* ``LINT-09`` - exploitation payloads, brute force/spraying/default-login checks, DoS tools,
  OAST/interactsh callbacks and upload/write/delete helpers (A7 BR8-9);
* ``LINT-10`` - TLS verification disabled anywhere under ``v3lum/`` (``verify=False``,
  ``ssl.CERT_NONE``, ``check_hostname=False``, ``ssl._create_unverified_context``,
  ``urllib3.disable_warnings``): no pragma is accepted (A12 BR4).

API: :func:`lint_module_source` (AST + regex lint of one Python file: a module or a plugin),
:func:`lint_data_file` (pivot packs, declarative specs, provider fragments, extras, method
allow-lists, username site lists and any data file with probe URLs) and :func:`lint_tree`
(``lint_tree('v3lum')`` in CI; ``lint_tree(path)`` for ~/.v3lum/plugins and ~/.v3lum/specs). Each
returns a list of :class:`LintIssue`. An issue on a line carrying the pragma
``# v3lum-lint: allow LINT-xx -- <justification>`` is still returned (``allowed=True``, never
silent) but does not fail the gate; a pragma without a justification, or one for LINT-10, is ignored.

:func:`forbidden_probe` is the single probe check used by the pivot-pack lint (``links.lint_pack``)
and by module authors to drop forbidden entries from runtime-downloaded site lists (WhatsMyName/
Maigret data that CI cannot see)::

    from v3lum.core.lint import forbidden_probe
    sites = [s for s in sites if forbidden_probe(s["uri_check"], method=s.get("method", "GET")) is None]

Endpoint keywords are matched in the path, query and fragment only (never the host name), as whole
tokens: separators, string ends and camelCase boundaries delimit them (``check_username``,
``checkUsername``, ``validateField`` match; ``invalidate`` and ``registered`` do not). Oracles that take
the account as a query parameter are caught too: a verb in the last path segment (check, verify,
available, exists, taken, reset, join...) with an account-named parameter (``/api/check?username=``,
``/v2/verify?email=``, ``/join?email=``), and verification/availability paths around a placeholder
(``/verify/{account}``, ``/usernames/{account}/available``). Host-level signals complete them: account
collections on identity hosts (``passport.twitch.tv/usernames/{account}``) and e-mail verification
services (``emailverification.<host>``). A reputation page such as ``/check/{ip}`` stays allowed.
Patterns are linear (no nested unbounded quantifiers).

The host tables (:data:`CPF_LOOKUP_HOSTS`, :data:`PEOPLE_SEARCH_DENYLIST`,
:data:`SMTP_VERIFICATION_HOSTS`, :data:`CAPTCHA_SOLVER_HOSTS`, :data:`OAST_HOSTS`,
:data:`CRACKING_HOSTS`) grow with data fragments ``v3lum/data/lint/<name>.json`` (schema
``v3lum.lint_tables/1``, see docs/contract_additions/WP09.md), merged at import time.
"""

from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

LINT_INVALID = "LINT-00"
LINT_NETWORK = "LINT-01"
LINT_DEPENDENCY = "LINT-02"
LINT_ENUMERATION = "LINT-03"
LINT_PEOPLE_SEARCH = "LINT-04"
LINT_SUBMISSION = "LINT-05"
LINT_METHOD = "LINT-06"
LINT_CREDENTIAL_FIELD = "LINT-07"
LINT_CRACKING = "LINT-08"
LINT_OFFENSIVE = "LINT-09"
LINT_TLS = "LINT-10"

#: The probe/link rules of the WP05 tables (id -> text), used by the pivot-pack lint messages.
PROBE_RULES: dict[str, str] = {
    LINT_ENUMERATION: "account-enumeration, availability, password-reset, e-mail verification and login endpoints "
    "are never probed (team rule 2, A5 rule 2, A7)",
    LINT_PEOPLE_SEARCH: "no CPF lookups, people-search panels ('painéis') or leaked-database sites (team rule 4, LGPD)",
    LINT_SUBMISSION: "never send values to endpoints that submit, scan or publish them (team rule 7)",
}

#: Every rule of the forbidden-capability lint (id -> text), in id order (for docs/RULES.md, AR22).
LINT_RULES: dict[str, str] = {
    LINT_INVALID: "source or data file that cannot be parsed, or a data file that fails its schema: fix the file "
    "(the lint cannot vouch for it)",
    LINT_NETWORK: "no direct network or process APIs in modules (socket, ssl sockets, urllib.request, http.client, "
    "requests/httpx/aiohttp and other clients, browser automation, subprocess/os.system) and nothing the lint cannot "
    "see (eval/exec, imports of computed names, deserialisers that execute code such as pickle or yaml.load): modules "
    "use ctx.http, ctx.dns and ctx.net, external binaries only through ctx.net.run_tool, never a core client of their "
    "own (ScopedHttp, HttpClient, Runtime...), the shared client reached around ctx.http/ctx.net (ctx.http.client, "
    "ctx.runtime.http, private ctx.net members) or the module's network scope rebound (ctx.http.allowed_hosts = None, "
    "ctx.runtime.in_scan = False); subprocess is accepted only in v3lum/core/tools.py (P327 cond 6, A6, A7)",
    LINT_DEPENDENCY: "no anti-bot/CAPTCHA bypass or borrowed-session dependency (cloudscraper, FlareSolverr, undetected "
    "or stealth browsers, TLS impersonation, CAPTCHA solvers, browser-cookie readers) and no CAPTCHA-solver "
    "service (team rule 1, A9)",
    LINT_ENUMERATION: PROBE_RULES[LINT_ENUMERATION] + "; no SMTP mailbox probing (RCPT TO/VRFY/EXPN); no credential or "
    "borrowed session (cookie or session key/setting) is ever sent in a request (no login attempt, team rule 1)",
    LINT_PEOPLE_SEARCH: PROBE_RULES[LINT_PEOPLE_SEARCH],
    LINT_SUBMISSION: PROBE_RULES[LINT_SUBMISSION],
    LINT_METHOD: "no state-changing HTTP method (POST/PUT/PATCH/DELETE) in LIGHT/ACTIVE modules, and only GET in "
    "declarative specs, unless an approved v3lum/data/policy/method_allowlist/<module>.json fragment lists the "
    "module and the method (A7)",
    LINT_CREDENTIAL_FIELD: "no credential/password field produced outside a P145 sanitizer schema (team rule 3, A4, "
    "P327 cond 10); only the password FORM survives, as 'password_form'",
    LINT_CRACKING: "no hash or JWT cracking: hashcat/john wrappers, JWT brute forcers and hash-reversal lookup "
    "services are forbidden (A7 BR8)",
    LINT_OFFENSIVE: "no exploitation or payload confirmation, brute force, spraying or default-login checks, DoS tools, "
    "OAST/interactsh callbacks, uploads, writes or deletes, in any mode (A7 BR8-9)",
    LINT_TLS: "TLS verification is never disabled anywhere under v3lum/ (verify=False and its aliases such as ssl=False "
    "or verify_ssl=False, ssl.CERT_NONE, check_hostname=False, ssl._create_unverified_context, "
    "urllib3.disable_warnings, TLS environment variables); no pragma accepted (A12 BR4)",
}
#: Rules whose pragma is never accepted.
NO_PRAGMA_RULES: frozenset[str] = frozenset({LINT_TLS})

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: Methods that write or delete on the receiving side (forbidden in every module, A7 BR9).
WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})


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
    _p(LINT_ENUMERATION, "check_account_param", _ORACLE_VERB + r"|recover|reset|forgot|join|subscribe|invite", params=_ACCOUNT_PARAM,
       description="existence/availability/verification/reset/sign-up endpoint taking the account as a query parameter "
       "(/api/check?username=, /verify?email=, /join?email=)"),
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
    # wave-2 review additions (WP09): oracles the patterns above let through
    _p(LINT_ENUMERATION, "username_attempt", r"(?:user[-_]?name|handle|unique[-_]?username)[-_/]?attempts?[a-z]*",
       description="username claim/availability attempt (/username-attempt-unauthed)"),
    _p(LINT_ENUMERATION, "credential_type", r"get[-_]?credential[-_]?type",
       description="account existence oracle (Microsoft GetCredentialType)"),
    _p(LINT_ENUMERATION, "account_recovery", r"recovery|recover[-_]?(?:access|username|e[-_]?mail|login)",
       description="account recovery flow"),
    _p(LINT_ENUMERATION, "message_trigger", r"(?:send|request|resend|trigger)[-_/]?(?:otp|sms|code|verification[-_]?code|magic[-_]?link|"
       r"login[-_]?link|one[-_]?time[-_]?(?:password|code))|(?:otp|sms|magic[-_]?link|login[-_]?link)[-_/]?(?:send|request|resend)|"
       r"magic[-_]?link", description="endpoint that sends an OTP, SMS or magic link to the account holder (existence oracle)"),
    _p(LINT_ENUMERATION, "is_registered", r"is[-_]?(?:" + _ACCOUNT_NOUN + r")[-_]?(?:registered|available|taken|exists?|valid|in[-_]?use)",
       description="account existence oracle (isEmailRegistered, is_username_taken)"),
    _p(LINT_ENUMERATION, "validation_account", r"(?:validations?|verifications?)[-_/]?(?:" + _ACCOUNT_NOUN + r")",
       description="account/e-mail validation endpoint (/validations/email)"),
    # wave-2 integration (WP12 review): SMTP mailbox probing behind an HTTP API (team rule 2: no SMTP
    # probing); only smtp + a probing verb, so DNS names such as '_smtp._tls' (TLS-RPT) stay allowed
    _p(LINT_ENUMERATION, "smtp_check", r"smtp[-_]?(?:check(?:er)?|verif[a-z]*|validat[a-z]*|test(?:er)?|probe|ping|exists?)",
       description="SMTP mailbox verification endpoint (/smtp-check/{value}; team rule 2)"),
)


def _valid_host(text: Any) -> bool:
    return isinstance(text, str) and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?", text)) and "." in text


#: LINT-04 hosts whose purpose is a lookup by CPF (CPF is validated offline only; research C0294, C0583, C0591).
_SEED_CPF_LOOKUP_HOSTS: frozenset[str] = frozenset({
    "cadastropre.com.br",  # prepaid phone lines by CPF
    "valoresareceber.bcb.gov.br",  # CPF + birth date lookup
    "portalbnmp.cnj.jus.br",  # arrest-warrant search by CPF/name
})

#: LINT-04 people-search panels, leaked-database / plaintext-password services, identity aggregators built
#: on enumeration, caller-ID people search and face-search engines (research C0216, C0295, C0320, C0592,
#: C0595, C0607; biometrics are out of scope). A subdomain of a listed host is listed too.
_SEED_PEOPLE_SEARCH: frozenset[str] = frozenset({
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

#: LINT-03 mailbox (SMTP) verification services: they probe mail servers for the address (team rule 2).
_SEED_SMTP_VERIFICATION: frozenset[str] = frozenset({
    "api.kickbox.com", "api.neverbounce.com", "api.zerobounce.net", "api.emailable.com", "api.debounce.io",
    "api.usebouncer.com", "api.verifalia.com", "api.millionverifier.com", "api.mailboxvalidator.com", "isitarealemail.com",
    "verify-email.org", "api.hippoapi.com", "api.reacher.email", "emailverification.whoisxmlapi.com",
    "emailvalidation.abstractapi.com", "api.emailverifyapi.com", "api.quickemailverification.com", "app.verify-email.org",
})
#: LINT-02 CAPTCHA-solving services (team rule 1, A9: challenges are never bypassed).
_SEED_CAPTCHA_SOLVERS: frozenset[str] = frozenset({
    "2captcha.com", "rucaptcha.com", "anti-captcha.com", "capsolver.com", "capmonster.cloud", "deathbycaptcha.com",
    "dbcapi.me", "nopecha.com", "azcaptcha.com", "solvecaptcha.com", "captchaai.com", "ez-captcha.com", "endcaptcha.com",
    "imagetyperz.com", "bestcaptchasolver.com", "9kw.eu", "truecaptcha.org", "metabypass.tech", "captchas.io",
})
#: LINT-09 out-of-band (OAST) callback and request-catcher services used to confirm blind vulnerabilities.
_SEED_OAST: frozenset[str] = frozenset({
    "interact.sh", "interactsh.com", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
    "oastify.com", "burpcollaborator.net", "dnslog.cn", "dnslog.link", "ceye.io", "requestbin.net", "requestbin.com",
    "webhook.site", "requestcatcher.com", "xss.ht", "bxss.me", "eyes.sh", "dig.pm",
})
#: LINT-08 hash-reversal (cracking) lookup services.
_SEED_CRACKING: frozenset[str] = frozenset({
    "crackstation.net", "hashes.com", "md5decrypt.net", "hashkiller.io", "hashkiller.co.uk", "cmd5.org", "cmd5.com",
    "md5online.org", "hashtoolkit.com", "md5hashing.net", "dehash.me", "nitrxgen.net", "md5.gromweb.com",
    "onlinehashcrack.com", "gpuhash.me", "hashmob.net", "hashes.org",
})

#: Data fragments extending the host tables (``v3lum.lint_tables/1``): table field -> global name.
LINT_TABLES_SCHEMA = "v3lum.lint_tables/1"
LINT_TABLES_DIR = Path(__file__).resolve().parent.parent / "data" / "lint"
_TABLE_FIELDS: dict[str, str] = {
    "cpf_lookup_hosts": "CPF_LOOKUP_HOSTS",
    "people_search_hosts": "PEOPLE_SEARCH_DENYLIST",
    "smtp_verification_hosts": "SMTP_VERIFICATION_HOSTS",
    "captcha_solver_hosts": "CAPTCHA_SOLVER_HOSTS",
    "oast_hosts": "OAST_HOSTS",
    "cracking_hosts": "CRACKING_HOSTS",
}
_TABLE_SEEDS: dict[str, frozenset[str]] = {
    "CPF_LOOKUP_HOSTS": _SEED_CPF_LOOKUP_HOSTS,
    "PEOPLE_SEARCH_DENYLIST": _SEED_PEOPLE_SEARCH,
    "SMTP_VERIFICATION_HOSTS": _SEED_SMTP_VERIFICATION,
    "CAPTCHA_SOLVER_HOSTS": _SEED_CAPTCHA_SOLVERS,
    "OAST_HOSTS": _SEED_OAST,
    "CRACKING_HOSTS": _SEED_CRACKING,
}
_TABLE_ERRORS: list[str] = []


def _table_fragment_problems(data: Any, stem: str) -> list[str]:
    """Schema problems of one ``v3lum.lint_tables/1`` fragment (empty list = valid)."""
    if not isinstance(data, Mapping):
        return ["a lint-tables fragment must be a JSON object"]
    problems: list[str] = []
    if data.get("schema") != LINT_TABLES_SCHEMA:
        problems.append(f"schema must be {LINT_TABLES_SCHEMA!r}")
    if data.get("name") != stem:
        problems.append(f"name must equal the file stem {stem!r}")
    allowed = {"schema", "name", "notes", "sources", *_TABLE_FIELDS}
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        problems.append(f"unknown field(s) {', '.join(unknown)}")
    for field_name in _TABLE_FIELDS:
        hosts = data.get(field_name, [])
        if not isinstance(hosts, list) or not all(_valid_host(h) for h in hosts):
            problems.append(f"{field_name} must be a list of lower-case host names")
    if not isinstance(data.get("notes", ""), str) or not isinstance(data.get("sources", []), list):
        problems.append("notes must be a string and sources a list (research record ids)")
    return problems


def reload_tables(directory: str | Path | None = None) -> list[str]:
    """Rebuild the host tables from their seeds plus the fragments of ``directory`` (default
    ``v3lum/data/lint``); returns the fragment problems (an invalid fragment is ignored whole)."""
    base = Path(directory) if directory is not None else LINT_TABLES_DIR
    merged = {name: set(seed) for name, seed in _TABLE_SEEDS.items()}
    errors: list[str] = []
    files = sorted(p for p in base.glob("*.json") if p.is_file()) if base.is_dir() else []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: invalid JSON ({exc})")
            continue
        problems = _table_fragment_problems(data, path.stem)
        if problems:
            errors.extend(f"{path.name}: {p}" for p in problems)
            continue
        for field_name, global_name in _TABLE_FIELDS.items():
            merged[global_name].update(data.get(field_name, []))
    for global_name, hosts in merged.items():
        globals()[global_name] = frozenset(hosts)
    _TABLE_ERRORS[:] = errors
    return list(errors)


def lint_table_errors() -> list[str]:
    """Problems of the ``v3lum/data/lint`` fragments seen by the last :func:`reload_tables`."""
    return list(_TABLE_ERRORS)


CPF_LOOKUP_HOSTS: frozenset[str] = _SEED_CPF_LOOKUP_HOSTS
PEOPLE_SEARCH_DENYLIST: frozenset[str] = _SEED_PEOPLE_SEARCH
SMTP_VERIFICATION_HOSTS: frozenset[str] = _SEED_SMTP_VERIFICATION
CAPTCHA_SOLVER_HOSTS: frozenset[str] = _SEED_CAPTCHA_SOLVERS
OAST_HOSTS: frozenset[str] = _SEED_OAST
CRACKING_HOSTS: frozenset[str] = _SEED_CRACKING
reload_tables()

#: Official suffixes exempt from the 'painel' host heuristic (government data dashboards).
_OFFICIAL_SUFFIXES = (".gov.br", ".jus.br", ".leg.br", ".mil.br", ".mp.br", ".def.br", ".gov")
_RE_CPF_TOKEN = re.compile(_kw(r"cpfs?"), re.I)
_RE_PAINEL_HOST = re.compile(r"painel|paineis", re.I)
#: e-mail (SMTP) verification services recognisable by their host name ('emailverification.example.com').
#: ('mailcheck'/'mailtester' style names are not enough: a domain-classification API is not an SMTP probe)
_RE_SMTP_VERIFY_HOST = re.compile(
    r"(?:^|[.\-])(?:e[-_]?)?mail(?:box)?[-_]?(?:verif|validat)|(?:^|[.\-])verif(?:y|ication)?[-_]?e?mail(?:s|address)?(?:[.\-]|$)",
    re.I,
)
#: first host labels of identity/authentication hosts; an account collection there is an account oracle
_IDENTITY_LABELS = frozenset({
    "passport", "account", "accounts", "auth", "login", "signin", "signup", "sso", "id", "identity", "oauth", "register",
    "registration", "join",
})
_ACCOUNT_COLLECTIONS = frozenset({
    "user", "users", "username", "usernames", "email", "emails", "e-mail", "account", "accounts", "handle", "handles",
    "login", "logins", "phone", "phones", "member", "members",
})
#: first host labels of password-recovery services: any request there is a reset/recovery flow
_RECOVERY_LABELS = frozenset({
    "iforgot", "forgot", "forgotpassword", "recover", "recovery", "passwordreset", "password-reset", "resetpassword",
    "reset-password", "accountrecovery", "account-recovery",
})

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


def smtp_verification_host(host: str) -> bool:
    """True for mailbox (SMTP) verification services: listed hosts and 'emailverification'-style names."""
    h = (host or "").lower().rstrip(".")
    return bool(h) and (_host_listed(h, SMTP_VERIFICATION_HOSTS) or bool(_RE_SMTP_VERIFY_HOST.search(h)))


def _identity_account_lookup(host: str, request: str) -> bool:
    """An account collection on an identity/authentication host ('passport.example/usernames/{account}')."""
    first = host.split(".", 1)[0]
    if first not in _IDENTITY_LABELS or "." not in host:
        return False
    segments = request.split("#", 1)[0].split("?", 1)[0].split("/")
    # '/usernames/<value>' or '/usernames/' (the value appended by the caller)
    return any(seg.lower() in _ACCOUNT_COLLECTIONS and i + 1 < len(segments) for i, seg in enumerate(segments))


def probe_violations(url: str, *, method: str | None = "GET") -> list[str]:
    """Every LINT rule id (sorted) that ``url`` violates for ``method`` (None = GET); [] when it is allowed."""
    method = str(method or "GET")
    host, request = split_probe_url(url)
    found: set[str] = set()
    if people_search_host(host) or _RE_CPF_TOKEN.search(request):
        found.add(LINT_PEOPLE_SEARCH)
    if any(p.matches(host, request, method) for p in SUBMISSION_PATTERNS):
        found.add(LINT_SUBMISSION)
    if (any(p.matches(host, request, method) for p in FORBIDDEN_PROBE_PATTERNS) or smtp_verification_host(host)
            or _identity_account_lookup(host, request) or (host.split(".", 1)[0] in _RECOVERY_LABELS and "." in host)):
        found.add(LINT_ENUMERATION)
    return sorted(found)


def forbidden_probe(url: str, *, method: str | None = "GET") -> str | None:
    """The LINT rule id the URL violates ('LINT-03', 'LINT-04' or 'LINT-05', lowest first), else None.

    Use it to drop forbidden entries from runtime-downloaded site lists and from any data file with
    probe URLs; ``links.lint_pack`` applies the same check to every pivot-link template.
    """
    hits = probe_violations(url, method=method)
    return hits[0] if hits else None


# ============================================================================================
# The forbidden-capability lint (P327 static rules)
# ============================================================================================


@dataclass(frozen=True)
class LintIssue:
    """One lint finding. ``allowed`` issues carry a valid pragma: reported, never silent, but they
    do not fail the gate (``justification`` repeats the pragma's reason)."""

    path: str
    line: int
    rule_id: str
    message: str
    allowed: bool = False
    justification: str = ""

    def __str__(self) -> str:
        tail = f" [allowed: {self.justification}]" if self.allowed else ""
        return f"{self.path}:{self.line}: {self.rule_id} {self.message}{tail}"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "rule_id": self.rule_id, "message": self.message,
                "allowed": self.allowed, "justification": self.justification}


def blocking(issues: Iterable[LintIssue]) -> list[LintIssue]:
    """The issues that fail the gate (every issue without a valid pragma)."""
    return [i for i in issues if not i.allowed]


# ---- tables of the source lint ------------------------------------------------------------

#: LINT-01: network clients and protocol libraries (import names; a dotted entry covers its submodules).
NETWORK_MODULES: frozenset[str] = frozenset({
    "socket", "socketserver", "asyncore", "asynchat", "urllib.request", "urllib2", "urllib3", "http.client", "httplib",
    "http.server", "xmlrpc.client", "xmlrpc.server", "xmlrpclib", "ftplib", "smtplib", "smtpd", "poplib", "imaplib",
    "nntplib", "telnetlib", "requests", "requests_html", "requests_futures", "requests_toolbelt", "httpx", "aiohttp",
    "pycurl", "httplib2", "grequests", "treq", "tornado.httpclient", "twisted.web.client", "twisted.internet",
    "websocket", "websockets", "asyncssh", "paramiko", "pysftp", "ftputil", "fabric", "scapy", "pyshark", "nmap",
    "dns.resolver", "dns.query", "dns.asyncresolver", "dns.asyncquery", "socks", "sockshandler", "selenium",
    "seleniumwire", "seleniumbase", "playwright", "pyppeteer", "splinter", "mechanize", "mechanicalsoup", "robobrowser",
    "scrapy", "boto3", "botocore", "pymongo", "redis", "psycopg2", "psycopg", "pymysql", "mysql", "pymssql", "cx_Oracle",
    "oracledb", "elasticsearch", "kafka", "pika", "paho", "ldap3", "ldap", "pysnmp", "smbclient", "smbprotocol",
    "pywinrm", "winrm", "telethon", "pyrogram", "tweepy", "praw", "instaloader", "instagrapi", "facebook_scraper",
    "snscrape", "twint", "linkedin_api", "shodan", "censys", "vt", "OTXv2", "pymisp", "pycti",
    # wave-2 review: clients that open their own connections (WHOIS, NTP, DNS, SOAP/GraphQL, IPC, web services)
    "webbrowser", "whois", "ipwhois", "pythonwhois", "asyncwhois", "ntplib", "aiodns", "pycares", "httpcore",
    "requests_cache", "requests_oauthlib", "zeep", "suds", "gql", "netmiko", "pypsrp", "smb", "geoip2.webservice",
    "multiprocessing.connection", "multiprocessing.managers",
})
#: LINT-01: process execution (modules run external binaries only through ctx.net.run_tool).
SUBPROCESS_MODULES: frozenset[str] = frozenset({
    "subprocess", "pty", "pexpect", "sh", "plumbum", "commands", "popen2", "sarge", "delegator", "invoke", "ptyprocess", "envoy",
})
SUBPROCESS_CALLS: frozenset[str] = frozenset({
    "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv",
    "os.spawnve", "os.spawnvp", "os.spawnvpe", "os.posix_spawn", "os.posix_spawnp", "os.startfile", "os.forkpty",
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell", "pty.spawn",
})
#: LINT-01: calls that open sockets or TLS connections outside ctx.net.
SOCKET_CALLS: frozenset[str] = frozenset({
    "ssl.get_server_certificate", "ssl.wrap_socket", "asyncio.open_connection", "asyncio.open_unix_connection",
    "asyncio.start_server", "asyncio.start_unix_server",
})
#: socket names that never touch the network (address parsing, constants, exception classes)
_SOCKET_SAFE = frozenset({
    "inet_pton", "inet_ntop", "inet_aton", "inet_ntoa", "htons", "htonl", "ntohs", "ntohl", "AF_INET", "AF_INET6",
    "AF_UNSPEC", "has_ipv6", "error", "gaierror", "herror", "timeout",
})
#: methods that open connections whatever the receiver (loop.create_connection, ctx.wrap_socket...)
_SOCKET_METHODS = frozenset({
    "wrap_socket", "create_connection", "create_datagram_endpoint", "sock_connect", "open_connection", "connect_tcp",
    "open_tcp_stream", "open_ssl_over_tcp_stream",
})
#: LINT-01: builtins that run code built at runtime (untrusted data is never executed; the lint cannot see it)
_DYNAMIC_CODE = frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"})
#: LINT-01: deserialisers that execute code from the data they load
UNSAFE_LOADERS: frozenset[str] = frozenset({
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads", "marshal.load",
    "marshal.loads", "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "joblib.load", "jsonpickle.decode",
    "shelve.open", "pandas.read_pickle", "torch.load", "yaml.unsafe_load", "yaml.full_load", "yaml.unsafe_load_all",
    "yaml.full_load_all",
})
#: SMTP mailbox probing commands in module strings (team rule 2: no SMTP probing): protocol-shaped only
#: ('RCPT TO:<...>' anywhere, 'VRFY x' / 'EXPN x' starting a line), so prose that names them is not code
_SMTP_PROBE = re.compile(r"(?im)RCPT[ \t]{1,3}TO[ \t]{0,3}:|^[ \t]*(?:VRFY|EXPN)(?:[ \t]|\r?$)")
#: LINT-01: core clients a module never builds itself (they would bypass the ctx host/scope checks;
#: a ScopedHttp of its own carries no declared hosts, run/scope binding or egress profile).
CORE_CLIENT_CLASSES: frozenset[str] = frozenset({"HttpClient", "RequestsTransport", "Connector", "EgressProfiles", "ScopedHttp"})
#: LINT-01: attribute paths that reach the shared client around the module's ScopedHttp/Connector (no host,
#: scope or egress checks): ``ctx.http.client``/``ctx.http._client`` (also behind ctx.net/ctx.dns and the
#: core DoH scope ``ctx.doh``), private members of ctx.net/ctx.dns/ctx.data/ctx.data.store and the
#: runtime's network plumbing (``ctx.runtime.http`` ... also through ``ctx.data[.store].runtime``), its
#: factories of new scopes (``ctx.runtime.context(cls)``: a Context of a class without module metadata
#: has no host list; ``ctx.runtime.doh_scope()``: a public DoH scope) and private members, and the
#: egress profiles behind ctx.net (``ctx.net.egress.session_for()/transport_for()`` hand out raw
#: sessions). Matched on the canonical path (aliases of ctx resolved); legitimate reads such as
#: ``ctx.runtime.meta``, ``ctx.runtime.clock`` or ``ctx.data.store.path(name)`` stay clean.
REACH_AROUND_PATH = re.compile(
    r"^(?:self\.)?ctx\.(?:"
    r"(?:(?:net|dns)\.)?(?:http|doh)\.(?:client\b|_\w+)"
    r"|(?:net|dns|data)\._\w+"
    r"|net\.egress\b"
    r"|data\.store\._\w+"
    r"|(?:data\.(?:store\.)?)?runtime\.(?:http|net|dns|transport|egress|data|connector|context|doh_scope|_\w+)\b"
    r")"
)
#: LINT-01: the module's network objects (and anything below them): an attribute assigned or deleted on
#: one of these (``ctx.http.allowed_hosts = None``, ``ctx.runtime.in_scan = False``, ``ctx.http = x``),
#: also through setattr/delattr and aliases, rebinds the host, scope or egress checks of the run.
CTX_NETWORK_PATH = re.compile(r"^(?:self\.)?ctx\.(?:http|net|dns|doh|data|runtime)(?:\.|$)")
#: LINT-01: core objects a module never builds itself, by their full import name: a Runtime of its own
#: carries its own HTTP client, a Context of its own a scope without the module's host list.
CORE_BUILT_NAMES: frozenset[str] = frozenset({"v3lum.core.context.Runtime", "v3lum.core.context.Context"})
#: LINT-01: ctx.data readers whose v1 ``(name, url)`` form downloads from an unregistered URL.
_DATASET_FETCHES: frozenset[str] = frozenset({"fetch", "fetch_text", "fetch_json", "fetch_lines"})
#: LINT-01: the Runtime object of a module's ctx (handed to a call it can build clients around ctx.http).
_RUNTIME_PATH = re.compile(r"(?:self\.)?ctx(?:\.data(?:\.store)?)?\.runtime")
#: builtins that only read or test the runtime they are given.
_RUNTIME_SAFE_CALLS: frozenset[str] = frozenset({"getattr", "hasattr", "isinstance", "id", "type", "callable", "repr", "bool"})
#: container methods that only use their argument as a key (a per-runtime table keyed on ``ctx.runtime``).
_KEY_METHODS: frozenset[str] = frozenset({"get", "setdefault", "pop", "add", "discard", "__contains__", "__getitem__"})
#: LINT-01: dict methods that edit the dataset registry (``DATASETS``) when a module calls them on it.
_MUTATING_METHODS: frozenset[str] = frozenset({"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"})
#: LINT-02: anti-bot/CAPTCHA bypass, TLS impersonation and borrowed-session libraries (import names).
FORBIDDEN_DEPENDENCIES: frozenset[str] = frozenset({
    "cloudscraper", "cfscrape", "cloudflare_scrape", "cf_clearance", "cloudflare_bypass", "flaresolverr",
    "undetected_chromedriver", "undetected_playwright", "nodriver", "selenium_stealth", "playwright_stealth",
    "pyppeteer_stealth", "puppeteer_stealth", "botasaurus", "botright", "curl_cffi", "tls_client", "hrequests", "primp",
    "noble_tls", "twocaptcha", "python_anticaptcha", "anticaptchaofficial", "anticaptcha", "capsolver",
    "python3_capsolver", "capmonster_python", "capmonstercloudclient", "deathbycaptcha", "solvecaptcha", "nopecha",
    "pypasser", "recaptcha_solver", "hcaptcha_challenger", "captcha_solver", "browser_cookie3", "pycookiecheat",
    "rookiepy", "browsercookie",
})
#: LINT-08: hash/JWT cracking libraries and binaries.
CRACKING_MODULES: frozenset[str] = frozenset({
    "hashcat", "pyhashcat", "hashcrack", "hashcracker", "jwtcrack", "jwt_cracker", "jwt_tool", "jwtxploiter", "john",
    "pyjohn", "findmyhash", "hash_buster", "hashbuster", "ophcrack",
})
CRACKING_TOOLS: frozenset[str] = frozenset({
    "hashcat", "john", "john-the-ripper", "jwt_tool", "jwt-tool", "jwt-cracker", "jwtcrack", "c-jwt-cracker", "ophcrack",
    "rcracki_mt", "findmyhash", "hash-buster", "aircrack-ng", "pyrit", "cowpatty", "fcrackzip", "pdfcrack", "rarcrack",
})
#: LINT-09: exploitation, brute-force, OAST and DoS libraries and binaries.
OFFENSIVE_MODULES: frozenset[str] = frozenset({
    "pwn", "pwnlib", "pwntools", "pymetasploit3", "pymetasploit", "metasploit", "msfrpc", "impacket", "sqlmap",
    "routersploit", "commix", "xsstrike", "dalfox", "tplmap", "sstimap", "interactsh", "interactsh_client",
    "pyinteractsh", "ysoserial", "crackmapexec", "netexec", "nxc", "kerbrute", "patator", "sprayhound", "o365spray",
    "trevorspray", "mfasweep", "mitm6", "bettercap",
})
OFFENSIVE_TOOLS: frozenset[str] = frozenset({
    "hydra", "medusa", "ncrack", "patator", "crackmapexec", "cme", "netexec", "nxc", "kerbrute", "sprayhound",
    "o365spray", "trevorspray", "sqlmap", "msfconsole", "msfvenom", "metasploit", "commix", "xsstrike", "dalfox", "tplmap",
    "sstimap", "interactsh-client", "interactsh", "ysoserial", "responder", "mitm6", "bettercap", "evil-winrm",
    "searchsploit", "routersploit", "beef-xss", "slowloris", "hping3", "loic", "t50", "mhddos", "goldeneye",
})
#: LINT-09: SDK methods that upload, write or delete remote objects.
REMOTE_WRITE_METHODS: frozenset[str] = frozenset({
    "put_object", "upload_file", "upload_fileobj", "delete_object", "delete_objects", "delete_bucket", "put_bucket_acl",
    "put_bucket_policy", "put_object_acl", "copy_object", "storbinary", "storlines", "upload_blob", "delete_blob",
    "create_blob_from_bytes",
})
#: LINT-09/08: payload markers searched in module string literals (A7 BR8-9).
PAYLOAD_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (LINT_OFFENSIVE, "SQL injection payload", re.compile(
        r"(?i)['\"]\s{0,3}(?:or|and)\s{1,3}['\"]?\d{1,3}['\"]?\s{0,3}=\s{0,3}['\"]?\d{1,3}|\bunion\s{1,3}(?:all\s{1,3})?select\b|"
        r"\bwaitfor\s{1,3}delay\b|\bxp_cmdshell\b|\bbenchmark\s{0,3}\(\s{0,3}\d{4,}|\bsleep\s{0,3}\(\s{0,3}\d{1,3}\s{0,3}\)\s{0,3}(?:--|#|;)|"
        r"\bpg_sleep\s{0,3}\(|\bdbms_pipe\.receive_message\b|\binformation_schema\.(?:tables|columns)\b")),
    (LINT_OFFENSIVE, "cross-site scripting payload", re.compile(
        r"(?i)<script[^>]{0,40}>\s{0,3}(?:alert|prompt|confirm)\s{0,3}\(|javascript:\s{0,3}(?:alert|prompt|confirm)\s{0,3}\(|"
        r"\bon(?:error|load|mouseover|focus)\s{0,3}=\s{0,3}['\"]?\s{0,3}(?:alert|prompt|confirm)\s{0,3}\(|<svg[^>]{0,40}\son\w{2,20}\s{0,3}=|"
        r"<img[^>]{0,40}\sonerror\s{0,3}=")),
    (LINT_OFFENSIVE, "path traversal / local file inclusion payload", re.compile(
        r"(?:\.\./){3,}|(?:\.\.\\){3,}|(?i:(?:%2e%2e(?:%2f|/)){2,})|/etc/(?:passwd|shadow)\b|(?i:c:\\windows\\win\.ini)|"
        r"(?i:php://(?:filter|input))|(?i:file:///etc/)")),
    (LINT_OFFENSIVE, "template injection payload", re.compile(
        r"\{\{\s{0,3}\d{1,4}\s{0,3}\*\s{0,3}\d{1,4}\s{0,3}\}\}|\$\{\s{0,3}\d{1,4}\s{0,3}\*\s{0,3}\d{1,4}\s{0,3}\}|"
        r"<%=\s{0,3}\d{1,4}\s{0,3}\*\s{0,3}\d{1,4}\s{0,3}%>")),
    (LINT_OFFENSIVE, "JNDI/Log4Shell payload", re.compile(r"(?i)\$\{(?:jndi:|\$\{|lower:|upper:|::-j)")),
    (LINT_OFFENSIVE, "command injection / reverse shell payload", re.compile(
        r"(?i)(?:;|\|\||&&|\|)\s{0,3}(?:cat\s{1,3}/etc/|id\s{0,3}(?:;|$)|whoami\b|uname\s{1,3}-a\b)|`(?:id|whoami)`|"
        r"\$\((?:id|whoami)\)|bash\s{1,3}-i\s{1,3}>&\s{0,3}/dev/tcp/|\bnc\s{1,3}(?:-[a-z]{0,4}e|-c)\s|/bin/(?:ba)?sh\s{1,3}-i\b|"
        r"\bpowershell(?:\.exe)?\s{1,3}-(?:e|enc|encodedcommand)\b|\biex\s{0,3}\(\s{0,3}new-object\b")),
    (LINT_OFFENSIVE, "shellshock payload", re.compile(r"\(\)\s{0,3}\{\s{0,3}:;\s{0,3}\};")),
    (LINT_OFFENSIVE, "XML external entity payload", re.compile(r"(?i)<!ENTITY\s{1,3}\S{1,64}\s{1,3}(?:SYSTEM|PUBLIC)\b")),
    (LINT_OFFENSIVE, "SSRF to a cloud metadata endpoint", re.compile(r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254|100\.100\.100\.200")),
    (LINT_OFFENSIVE, "deserialization gadget", re.compile(r"\brO0AB|\baced0005\b")),
    (LINT_OFFENSIVE, "JWT 'alg: none' forgery", re.compile(r"(?i)[\"']alg[\"']\s{0,3}:\s{0,3}[\"']none[\"']|\beyJhbGciOiJub25lI")),
)
#: LINT-09: brute-force/DoS markers, searched in identifiers and in string literals without whitespace
#: (prose such as 'no brute force' in a description is not code).
_BRUTE_FORCE = re.compile(
    r"(?i)rockyou|brute[-_ ]?forc|password[-_ ]?spray|credential[-_ ]?stuff|default[-_ ]?(?:creds|credentials|logins?|passwords?)|"
    r"(?:seclists|wordlists?)/passwords?\b|slowloris|syn[-_]?flood|http[-_]?flood"
)
_CRACKING_WORDS = re.compile(r"(?i)crack[-_]?(?:hash|hashes|jwt|password|passwords)|(?:hash|jwt|password)[-_]?crack")
_DETECTOR_NAME = re.compile(r"(?i)detect|^_?(?:is|has|looks_like)_|flag|parse|classif|score|count|match|warn")
_OFFENSIVE_IDENT = re.compile(r"(?i)^(?:run_|do_|send_|fire_)?(?:exploit|payload)_(?:target|host|vuln|it|send|fire)|^send_payload|^fire_payload")
#: FlareSolverr's local API (LINT-02).
_FLARESOLVERR = re.compile(r"(?i)flaresolverr|:8191/v1\b")
#: methods of string processing: a constant passed to them is detection, not a request
_DETECTION_METHODS = frozenset({
    "startswith", "endswith", "find", "rfind", "index", "rindex", "count", "search", "match", "fullmatch", "findall",
    "finditer", "compile", "split", "rsplit", "partition", "rpartition", "replace", "strip", "lstrip", "rstrip",
    "removeprefix", "removesuffix", "sub", "subn", "escape",
})
#: methods of the core HTTP facade (and of common clients) and the method they imply (None: from args)
_HTTP_CALLS: dict[str, str | None] = {
    "get": "GET", "head": "HEAD", "options": "OPTIONS", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
    "get_json": "GET", "post_json": "POST", "request": None, "send": None, "fetch": "GET", "json": "GET", "text": "GET",
}
_HTTP_RECEIVER = re.compile(r"(?i)^_{0,2}(?:http|https|session|sess|client|transport|requests|httpx|aiohttp|web|api|Session|AsyncClient|Client)$")
#: credential/password field names (LINT-07; the password FORM 'password_form' is metadata)
#: ('combo' is also combosquatting, 'pass' an SPF/DMARC result and 'cookies' a list of cookie names in web
#: fingerprints: those stay with the runtime second net, the static rule names credentials only)
_CRED_EXACT = frozenset({
    "password", "passwords", "passwd", "pwd", "pswd", "senha", "senhas", "passwort", "contrasena", "salt",
    "password_hash", "passwordhash", "hashed_password", "password_hint", "masked_password", "password_masked",
    "top_passwords", "top_logins", "cleartext", "plaintext_password", "credential", "credentials", "creds",
    "combo_line", "session_cookie", "session_token", "autofill", "autofills",
})
_CRED_SUBSTRINGS = ("password", "passwd", "senha", "passwort", "top_login", "autofill", "combo_line")
#: key names of borrowed sessions (LINT-03, team rule 1)
_SESSION_KEY = re.compile(r"(?i)session|cookie|sessid")
#: environment variables that turn TLS verification off (LINT-10)
_TLS_ENV = frozenset({"PYTHONHTTPSVERIFY", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_TLS_REJECT_UNAUTHORIZED"})
#: keyword arguments whose False value turns certificate verification off (requests/httpx verify=, aiohttp ssl=,
#: verify_ssl=, elasticsearch verify_certs=, ansible-style validate_certs=...) (LINT-10)
_TLS_VERIFY_KWARGS = frozenset({"verify", "ssl", "verify_ssl", "ssl_verify", "verify_certs", "validate_certs", "verify_tls", "tls_verify"})
#: setting names that carry a borrowed session (cookie, session id or token copied from a browser; LINT-03)
_SESSION_SETTING = re.compile(r"(?i)cookie|sessid|session[-_]?(?:id|token|key|cookie)|login[-_]?token")
_PRAGMA = re.compile(r"#\s*v3lum-lint:\s*allow\s+(LINT-\d{2}(?:\s*,\s*LINT-\d{2})*)\s*(?:--\s*(.*?))?\s*$")
_REGEX_FALLBACK: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (LINT_TLS, "TLS verification disabled", re.compile(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|_create_unverified_context|disable_warnings")),
    (LINT_NETWORK, "direct network or process API", re.compile(r"^\s*(?:import|from)\s+(?:socket|requests|httpx|aiohttp|urllib\.request|http\.client|subprocess|urllib3|pycurl)\b", re.M)),
    (LINT_DEPENDENCY, "forbidden anti-bot/CAPTCHA dependency", re.compile(r"^\s*(?:import|from)\s+(?:cloudscraper|cfscrape|undetected_chromedriver|twocaptcha|capsolver|curl_cffi|tls_client)\b", re.M)),
)

PROFILE_MODULE = "module"
PROFILE_CODE = "code"
PROFILE_CORE = "core"
_PROFILES = (PROFILE_MODULE, PROFILE_CODE, PROFILE_CORE)


def _norm_key(name: Any) -> str:
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def is_credential_field(name: Any) -> bool:
    """True for credential/password field names (LINT-07); 'password_form' is metadata and is not one."""
    norm = _norm_key(name)
    if not norm or norm == "password_form" or norm.endswith("_form"):
        return False
    return norm in _CRED_EXACT or any(s in norm for s in _CRED_SUBSTRINGS)


#: a provider field that names the password FORM under another name (XposedOrNot 'password_risk' /
#: 'passwordRisk', 'password_type', 'password_algorithm'): a P145 schema may keep it, because the
#: sanitizer renames it 'password_form' when it holds a form word and drops it otherwise
#: (docs/contract_additions/WP09.md, 'sensitive modules')
_FORM_CARRIER_FIELD = re.compile(r"^(?:password|passwd|senha|pwd|pass)_(?:risk|type|kind|format|algorithm|algo|scheme|storage)$")


def is_password_form_carrier(name: Any) -> bool:
    """True for a provider field carrying the password FORM (a schema may keep it; LINT-07 exempt)."""
    return bool(_FORM_CARRIER_FIELD.match(_norm_key(name)))


def _module_covered(name: str, table: frozenset[str]) -> str | None:
    """The table entry ``name`` (an import name, dotted) falls under, else None."""
    parts = name.split(".")
    for i in range(len(parts), 0, -1):
        cand = ".".join(parts[:i])
        if cand in table:
            return cand
    return None


def _host_rules(host: str) -> list[tuple[str, str]]:
    """Host-level rules of LINT-02/08/09 for one host (the probe rules come from probe_violations)."""
    out: list[tuple[str, str]] = []
    if not host:
        return out
    if _host_listed(host, CAPTCHA_SOLVER_HOSTS):
        out.append((LINT_DEPENDENCY, f"CAPTCHA-solving service {host!r} (challenges are never bypassed)"))
    if _host_listed(host, OAST_HOSTS):
        out.append((LINT_OFFENSIVE, f"out-of-band callback service {host!r} (OAST/interactsh)"))
    if _host_listed(host, CRACKING_HOSTS):
        out.append((LINT_CRACKING, f"hash-reversal lookup service {host!r} (hash cracking)"))
    return out


def _url_like(text: str) -> bool:
    if not text or len(text) > 4096 or any(c.isspace() for c in text):
        return False
    if "://" in text:
        return True
    if text.startswith("//"):
        return "." in text
    if text.startswith("/") and len(text) > 1:
        return True
    return bool(_RE_BARE_HOST.match(text))


#: code-hosting hosts: below '<owner>/<repo>' a path names files, not endpoints
_CODE_HOSTS = frozenset({
    "github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com", "objects.githubusercontent.com",
    "media.githubusercontent.com", "gitlab.com", "codeberg.org", "bitbucket.org", "sourceforge.net",
})


def _repository_path(host: str, request: str) -> bool:
    segments = [s for s in request.split("?", 1)[0].split("#", 1)[0].split("/") if s]
    return host in _CODE_HOSTS and len(segments) >= 2


def _probe_issues(url: str, method: str | None, *, dataset: bool = False) -> list[tuple[str, str]]:
    """(rule, message) pairs for one URL-like literal: probe rules plus host-level rules. Dataset URLs
    (``register_dataset``) and repository files on code hosts carry no value: host-level rules only."""
    out: list[tuple[str, str]] = []
    shown = url if len(url) <= 120 else url[:117] + "..."
    method = (method or "GET").upper()
    request_like = "://" in url or url.startswith("/")
    host, request = split_probe_url(url)
    if dataset or _repository_path(host, request):
        found = [LINT_PEOPLE_SEARCH] if people_search_host(host) else []
    else:
        found = probe_violations(url, method=method)
    for rule in found:
        out.append((rule, f"{method + ' ' if request_like else ''}{shown}: {PROBE_RULES[rule]}"))
    out.extend((rule, f"{shown}: {why}") for rule, why in _host_rules(host))
    if _FLARESOLVERR.search(url):
        out.append((LINT_DEPENDENCY, f"{shown}: FlareSolverr endpoint (challenge bypass)"))
    return out


#: module names that may name an allow-list fragment file (no separators, no '..': the name comes from
#: the linted source and must never reach a file outside the allow-list directory)
_MODULE_FILE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-]{0,127}")


def _method_allowlisted(module: str, method: str, root: Path | None = None) -> bool:
    """True when an approved ``v3lum.method_allow/1`` fragment lists ``module`` and ``method`` (WP11)."""
    if not module or not _MODULE_FILE_NAME.fullmatch(module):
        return False
    base = (root / "data" / "policy" / "method_allowlist") if root is not None else (
        Path(__file__).resolve().parent.parent / "data" / "policy" / "method_allowlist")
    path = base / f"{module}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, Mapping) or data.get("schema", "v3lum.method_allow/1") != "v3lum.method_allow/1":
        return False
    if data.get("module") != module or not str(data.get("approved_by") or "").strip() or not str(data.get("decision_ref") or "").strip():
        return False
    methods = data.get("methods")
    return isinstance(methods, Mapping) and any(str(m).upper() == method.upper() for m in methods) and method.upper() not in WRITE_METHODS


def _dotted(node: ast.AST) -> str:
    """'ctx.http.post' for an Attribute/Name chain ('' when the chain holds calls or subscripts)."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        return ".".join([inner + "()", *reversed(parts)]) if inner else ""
    return ""


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _const_strings(node: ast.AST) -> list[ast.Constant]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _opsec_of(value: ast.AST) -> str:
    """'light'/'active'/'passive'/'' for a class-level ``opsec = ...`` value."""
    if isinstance(value, ast.Attribute):
        return value.attr.lower() if value.attr.upper() in ("PASSIVE", "LIGHT", "ACTIVE") else ""
    if isinstance(value, ast.Constant):
        if isinstance(value.value, str):
            return value.value.lower() if value.value.lower() in ("passive", "light", "active") else ""
        if isinstance(value.value, int) and not isinstance(value.value, bool):
            return {0: "passive", 1: "light", 2: "active"}.get(value.value, "")
    if isinstance(value, ast.Call) and value.args:
        return _opsec_of(value.args[0])
    return ""


class _SourceLint(ast.NodeVisitor):
    """One pass over a parsed module; issues are (line, end_line, rule, message)."""

    def __init__(self, tree: ast.Module, *, profile: str, rel: str, root: Path | None) -> None:
        self.tree = tree
        self.profile = profile
        self.rel = rel.replace("\\", "/")
        self.root = root
        self.issues: list[tuple[int, int, str, str]] = []
        self.parents: dict[ast.AST, ast.AST] = {}
        self.nodes: list[ast.AST] = []
        stack: list[ast.AST] = [tree]
        while stack:  # one iterative traversal (no recursion limit): parent links + the nodes in source pre-order
            node = stack.pop()
            self.nodes.append(node)
            children = list(ast.iter_child_nodes(node))
            for child in children:
                self.parents[child] = node
            stack.extend(reversed(children))
        self.aliases: dict[str, str] = {}
        self.docstrings: set[int] = set()
        self.skip: set[int] = set()
        self.string_consts: dict[str, str] = {}
        self.has_schema = False
        self.socket_helpers_only = False
        self.class_opsec: dict[ast.ClassDef, str] = {}
        self.class_name: dict[ast.ClassDef, str] = {}
        self.class_sources: dict[ast.ClassDef, tuple[str, ...]] = {}
        self.class_disclosure: dict[ast.ClassDef, str] = {}
        self.class_by_name: dict[str, ast.ClassDef] = {}
        self.opsec_consts: dict[str, str] = {}
        self.http_names: set[str] = set()
        self.defined_names: set[str] = set()
        #: aliases of the module's ctx: name (or 'self.attr') -> canonical ctx path ('ctx.http', 'self.ctx.runtime')
        self.ctx_aliases: dict[str, str] = {}
        #: parameters bound to a ctx path by a call in this file: (id(function), parameter) -> ctx path
        self.param_aliases: dict[tuple[int, str], str] = {}
        #: innermost enclosing function (or lambda) of every node inside one, and of every function
        self._enclosing: dict[int, ast.AST] = {}
        self._fn_parent: dict[int, ast.AST | None] = {}
        self._prepare()

    def run(self) -> None:
        """Visit every node once, parents before children, siblings in source order (iterative: a deeply
        nested expression cannot exhaust the interpreter stack)."""
        for node in self.nodes:
            self.visit(node)

    def generic_visit(self, node: ast.AST) -> None:  # noqa: D102 - children are visited by run()
        return None

    # -- preparation ------------------------------------------------------------------------
    def _prepare(self) -> None:
        for node in self.nodes:  # names first: class bodies below may refer to constants defined anywhere
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target, value = node.targets[0].id, node.value
                found = _opsec_of(value)
                if found:
                    self.opsec_consts[target] = found
                receiver = _dotted(value).replace("()", "") if isinstance(value, (ast.Attribute, ast.Name, ast.Call)) else ""
                if receiver and _HTTP_RECEIVER.match(receiver.rsplit(".", 1)[-1]):
                    self.http_names.add(target)  # h = ctx.http; h.post(...) is an HTTP call too
            if isinstance(node, ast.ClassDef):
                self.class_by_name.setdefault(node.name, node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.defined_names.add(node.name)
        for node in self.nodes:
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                    self.docstrings.add(id(first.value))
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self.docstrings.add(id(node.value))  # bare string statements are comments
            if isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name.split(".")[-1] == "register_schema":
                    self.has_schema = True
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                text = _const_str(node.value)
                if text is not None:
                    self.string_consts[node.targets[0].id] = text
            if isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        target = stmt.targets[0].id
                        if target == "opsec":
                            value = stmt.value
                            self.class_opsec[node] = (self.opsec_consts.get(value.id, "") if isinstance(value, ast.Name)
                                                      else _opsec_of(value))
                        elif target == "name" and _const_str(stmt.value):
                            self.class_name[node] = str(_const_str(stmt.value))
                        elif target == "sources":
                            self.class_sources[node] = tuple(c.value for c in _const_strings(stmt.value))
                        elif target == "disclosure" and _const_str(stmt.value):
                            self.class_disclosure[node] = str(_const_str(stmt.value))
                        elif target == "error_markers":
                            self.skip.update(id(c) for c in _const_strings(stmt.value))  # detection markers (P321)
        if self.module:
            self._collect_ctx_aliases()  # after string_consts: getattr(ctx.http, NAME) reads the constant
        if self.profile != PROFILE_CORE:  # core files get no string rules
            self._detection_only_names()
        self.socket_helpers_only = self._socket_helpers_only()

    # -- ctx paths (LINT-01: reaching around ctx.http/ctx.net) ------------------------------
    def _collect_ctx_aliases(self) -> None:
        """Names and ``self.<attr>`` bound to a ctx path (``c = ctx``, ``rt = ctx.runtime``,
        ``self.http = ctx.http``, ``h = getattr(ctx, 'http')``): flow-insensitive, so a name bound to a
        ctx path anywhere in the file is read as that path everywhere (fail closed; a pragma documents
        a false positive). Parameters of a function of this file that a call passes a ctx path to
        (``helper(ctx)``, ``self._fetch(entity, ctx)``, ``partial(helper, ctx)``) are aliases inside
        that function (and the functions nested in it) only."""
        functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        bindings: list[tuple[ast.AST, ast.AST]] = []
        calls: list[ast.Call] = []
        enclosing, parents, may_be = self._enclosing, self.parents, self._may_be_ctx
        for node in self.nodes:  # pre-order: a parent (and so an outer function) comes before its children
            parent = parents.get(node)
            if parent is not None:
                scope = parent if isinstance(parent, scopes) else enclosing.get(id(parent))
                if scope is not None:
                    enclosing[id(node)] = scope
            if isinstance(node, scopes):
                if not isinstance(node, ast.Lambda):
                    functions.setdefault(node.name, []).append(node)
                self._fn_parent[id(node)] = enclosing.get(id(node))
            elif isinstance(node, ast.Assign):
                if may_be(node.value):
                    bindings.extend((target, node.value) for target in node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                if node.value is not None and may_be(node.value):
                    bindings.append((node.target, node.value))
            elif isinstance(node, ast.Call) and (node.args or node.keywords):
                calls.append(node)
        params: list[tuple[ast.AST, str, ast.AST]] = []
        for call in calls:
            params.extend(b for b in self._param_bindings(call, functions) if may_be(b[2]))
        for _ in range(6):  # chains bound out of source order (h = c.http before c = ctx) settle in a few passes
            changed = False
            for target, value in bindings:
                if isinstance(target, ast.Name):
                    key = target.id
                elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    key = f"self.{target.attr}"
                else:
                    continue
                if key in ("ctx", "self.ctx"):
                    continue  # the roots themselves
                path = self._ctx_path(value)
                if path and self.ctx_aliases.get(key) != path and not path.startswith(f"{key}."):
                    self.ctx_aliases[key] = path
                    changed = True
            for fn, param, value in params:
                if param == "ctx":
                    continue  # already the root
                path = self._ctx_path(value)
                if path and self.param_aliases.get((id(fn), param)) != path and not path.startswith(f"{param}."):
                    self.param_aliases[(id(fn), param)] = path
                    changed = True
            if not changed:
                break

    @staticmethod
    def _may_be_ctx(node: ast.AST | None) -> bool:
        """Cheap pre-filter: only these expressions can have a ctx path (see :meth:`_ctx_path`)."""
        if isinstance(node, (ast.Name, ast.Attribute, ast.NamedExpr)):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            return (isinstance(func, ast.Name) and func.id in ("getattr", "vars", "type", "copy", "deepcopy")) or \
                (isinstance(func, ast.Attribute) and func.attr in ("copy", "deepcopy"))
        return False

    @staticmethod
    def _param_bindings(call: ast.Call, functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]) -> list[tuple[ast.AST, str, ast.AST]]:
        """(function, parameter, argument) of a call to a function of this file: ``helper(ctx)`` binds
        helper's parameter to ctx (``def helper(c): c.http.client`` is ``ctx.http.client``). Direct calls,
        ``self.method(...)`` / ``cls.method(...)`` and ``functools.partial(fn, ...)`` / ``pool.submit(fn,
        ...)``."""
        func, args, skip_self = call.func, list(call.args), False
        if isinstance(func, (ast.Name, ast.Attribute)) and (func.id if isinstance(func, ast.Name) else func.attr) in ("partial", "submit") \
                and args and isinstance(args[0], (ast.Name, ast.Attribute)):
            func, args = args[0], args[1:]
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in ("self", "cls"):
            name, skip_self = func.attr, True
        else:
            return []
        out: list[tuple[ast.AST, str, ast.AST]] = []
        for fn in functions.get(name, ()):
            positional = [*fn.args.posonlyargs, *fn.args.args]
            if skip_self and positional and positional[0].arg in ("self", "cls"):
                positional = positional[1:]
            for param, arg in zip(positional, args):
                if not isinstance(arg, ast.Starred):
                    out.append((fn, param.arg, arg))
            names = {p.arg for p in [*positional, *fn.args.kwonlyargs]}
            out.extend((fn, kw.arg, kw.value) for kw in call.keywords if kw.arg in names)
        return out

    def _alias_of(self, node: ast.Name) -> str:
        """The ctx path a name stands for: a parameter alias of an enclosing function, else a name alias."""
        scope = self._enclosing.get(id(node))
        while scope is not None:
            hit = self.param_aliases.get((id(scope), node.id))
            if hit:
                return hit
            scope = self._fn_parent.get(id(scope))
        return self.ctx_aliases.get(node.id, "")

    def _ctx_path(self, node: ast.AST | None, depth: int = 0) -> str:
        """The canonical ctx path of an expression (``ctx.http.client``: aliases resolved,
        ``getattr(x, 'name')`` - also through a string constant - read as ``x.name``, ``vars(x)`` as
        ``x.__dict__``, ``(h := x)`` as ``x``); '' when it is not rooted at the module's ctx."""
        if node is None or depth > 32:
            return ""
        if isinstance(node, ast.Name):
            return "ctx" if node.id == "ctx" else self._alias_of(node)
        if isinstance(node, ast.NamedExpr):
            return self._ctx_path(node.value, depth + 1)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "self":
                key = f"self.{node.attr}"
                return "self.ctx" if node.attr == "ctx" else self.ctx_aliases.get(key, "")
            base = self._ctx_path(node.value, depth + 1)
            return f"{base}.{node.attr}" if base else ""
        if isinstance(node, ast.Call) and self._builtin_call(node, "getattr") and len(node.args) >= 2:
            attr = self._const_arg(node.args[1])
            base = self._ctx_path(node.args[0], depth + 1)
            return f"{base}.{attr}" if base and attr and attr.isidentifier() else ""
        if isinstance(node, ast.Call) and self._builtin_call(node, "vars") and len(node.args) == 1:
            base = self._ctx_path(node.args[0], depth + 1)
            return f"{base}.__dict__" if base else ""
        if isinstance(node, ast.Call) and self._builtin_call(node, "type") and len(node.args) == 1:
            base = self._ctx_path(node.args[0], depth + 1)
            return f"{base}.__class__" if base else ""
        if isinstance(node, ast.Call) and node.args and _dotted(node.func) in ("copy.copy", "copy.deepcopy", "copy", "deepcopy"):
            return self._ctx_path(node.args[0], depth + 1)  # a copy of ctx.http is ctx.http (mutating it rebinds the scope)
        return ""

    def _builtin_call(self, node: ast.Call, name: str) -> bool:
        """``node`` calls the builtin ``name`` (not a local or imported name that shadows it)."""
        return isinstance(node.func, ast.Name) and node.func.id == name and name not in self.aliases and name not in self.defined_names

    def _check_rebind(self, node: ast.Attribute) -> None:
        """LINT-01 for an attribute stored or deleted on ctx.http/ctx.net/ctx.dns/ctx.doh/ctx.data/
        ctx.runtime (or below, aliases resolved): ``ctx.http.allowed_hosts = None``,
        ``ctx.runtime.in_scan = False``, ``ctx.http = other`` rebind the module's network scope."""
        base = self._ctx_path(node.value)
        if base:
            self._report_rebind(node, f"{base}.{node.attr}")

    def _report_rebind(self, node: ast.AST, path: str) -> None:
        m = REACH_AROUND_PATH.match(path)
        if m is not None and m.end() == len(path):
            self.add(node, LINT_NETWORK, f"{path}: reaches around ctx.http/ctx.net (no host, scope or egress checks)")
        elif CTX_NETWORK_PATH.match(path):
            self.add(node, LINT_NETWORK, f"{path} assigned or deleted: rebinds the module's network scope (its host, scope or "
                                         "egress checks)")

    def _check_runtime_handed(self, node: ast.Call, callee: str) -> None:
        """LINT-01 when the Runtime itself (``ctx.runtime``, also ``ctx.data[.store].runtime`` and aliases)
        is handed to a call: a helper given the runtime can build a client or scope of its own around
        ctx.http/ctx.net (``job_http(ctx.runtime, hosts=...)``, ``DataStore(ctx.runtime)``) - the lint
        cannot follow it into another file. Reading it (``getattr(ctx.runtime, 'meta', None)``) is fine."""
        if isinstance(node.func, ast.Name) and node.func.id in _RUNTIME_SAFE_CALLS and self._builtin_call(node, node.func.id):
            return
        if isinstance(node.func, ast.Attribute) and node.func.attr in _KEY_METHODS:
            return  # the runtime as the identity key of a per-runtime table (table.get(ctx.runtime))
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            value = arg.value if isinstance(arg, ast.Starred) else arg
            if not self._may_be_ctx(value):
                continue
            path = self._ctx_path(value)
            if _RUNTIME_PATH.fullmatch(path):
                self.add(arg, LINT_NETWORK, f"{path} handed to {callee or 'a call'}(): a helper given the runtime can build a client "
                                            "around ctx.http/ctx.net (pass the value it needs, e.g. ctx.runtime.meta)")

    def _check_dynamic_ctx(self, node: ast.Call) -> None:
        """LINT-01 for ``setattr``/``delattr`` on a ctx network object and for ``getattr`` of a computed
        name on one (the lint cannot see what is reached)."""
        if not isinstance(node.func, ast.Name) or len(node.args) < 2:
            return
        fn = node.func.id
        if fn not in ("getattr", "setattr", "delattr") or not self._builtin_call(node, fn):
            return
        base = self._ctx_path(node.args[0])
        if not base:
            return
        attr = self._const_arg(node.args[1])
        if fn in ("setattr", "delattr"):
            if attr and attr.isidentifier():
                self._report_rebind(node, f"{base}.{attr}")
            elif base in ("ctx", "self.ctx") or CTX_NETWORK_PATH.match(base):
                self.add(node, LINT_NETWORK, f"{fn}({base}, <computed>): rebinds the module's network scope (the lint cannot see "
                                             "what is changed)")
        elif not attr and (base in ("ctx", "self.ctx") or CTX_NETWORK_PATH.match(base)):
            self.add(node, LINT_NETWORK, f"getattr({base}, <computed>): the lint cannot see what is reached around ctx.http/ctx.net "
                                         "(name it as a constant)")

    def _check_reach_around(self, node: ast.AST) -> None:
        """LINT-01 when ``node`` (an attribute access or a getattr call) is a ctx path that reaches the
        shared client around the module's ScopedHttp/Connector (:data:`REACH_AROUND_PATH`); only the
        innermost matching access of a chain is reported."""
        path = self._ctx_path(node)
        if not path:
            return
        m = REACH_AROUND_PATH.match(path)
        if m is not None and m.end() == len(path):
            self.add(node, LINT_NETWORK, f"{path}: reaches around ctx.http/ctx.net (no host, scope or egress checks)")

    def _socket_helpers_only(self) -> bool:
        """True when every use of the socket module is an address helper (inet_pton, AF_INET...)."""
        bound: set[str] = set()
        from_helpers = False
        for node in self.nodes:
            if isinstance(node, ast.Import):
                bound.update(a.asname or "socket" for a in node.names if a.name == "socket")
            elif isinstance(node, ast.ImportFrom) and node.module == "socket" and node.level == 0:
                if any(a.name not in _SOCKET_SAFE for a in node.names):
                    return False
                from_helpers = True
        uses = 0
        for node in self.nodes:
            if isinstance(node, ast.Name) and node.id in bound and isinstance(node.ctx, ast.Load):
                parent = self.parents.get(node)
                if not (isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in _SOCKET_SAFE):
                    return False
                uses += 1
        return uses > 0 if bound else from_helpers

    def _detection_only_names(self) -> None:
        """Constants assigned to a name whose every use is detection (comparisons, startswith...)."""
        assigned: dict[str, list[ast.Constant]] = {}
        for node in self.nodes:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                consts = _const_strings(node.value)
                if consts and all(isinstance(n, (ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Call, ast.Name, ast.Load, ast.Dict))
                                  for n in ast.walk(node.value)):
                    assigned.setdefault(node.targets[0].id, []).extend(consts)
        if not assigned:
            return
        uses: dict[str, list[ast.AST]] = {}
        for node in self.nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in assigned:
                uses.setdefault(node.id, []).append(node)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and node.attr in assigned:
                uses.setdefault(node.attr, []).append(node)
        for name, consts in assigned.items():
            loads = uses.get(name, [])
            if loads and all(self._detection(load) for load in loads):
                self.skip.update(id(c) for c in consts)

    # -- context helpers --------------------------------------------------------------------
    def _parent(self, node: ast.AST) -> ast.AST | None:
        return self.parents.get(node)

    def _uses_in_detection(self, name: str, scope: ast.AST) -> bool:
        for node in ast.walk(scope):
            if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load) and self._detection(node, loops=False):
                return True
        return False

    def _detection(self, node: ast.AST, *, loops: bool = True) -> bool:
        """True when ``node`` is used only to look at data (compare, startswith, regex), not to request."""
        child, cur = node, self._parent(node)
        while cur is not None and not isinstance(cur, (ast.stmt, ast.Module)):
            if isinstance(cur, ast.Compare):
                return True
            if isinstance(cur, ast.Call) and child is not cur.func:
                fn = _dotted(cur.func).split(".")[-1]
                if fn in _DETECTION_METHODS:
                    return True
            if loops and isinstance(cur, ast.comprehension) and child is cur.iter:
                comp = self._parent(cur)
                target = cur.target.id if isinstance(cur.target, ast.Name) else ""
                if target and comp is not None and self._uses_in_detection(target, comp):
                    return True
            child, cur = cur, self._parent(cur)
        if loops and isinstance(cur, ast.For) and child is cur.iter and isinstance(cur.target, ast.Name):
            return any(self._uses_in_detection(cur.target.id, stmt) for stmt in cur.body)
        # P321 error markers declared on the class are detection data by definition
        return isinstance(cur, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "error_markers" for t in cur.targets)

    def _dataset_argument(self, node: ast.AST) -> bool:
        """True for a constant passed to register_dataset()/register_list(): a dataset URL, fetched without
        any investigated value by the dataset manager."""
        cur = self._parent(node)
        while cur is not None and not isinstance(cur, (ast.stmt, ast.Module)):
            if isinstance(cur, ast.Call) and _dotted(cur.func).split(".")[-1] in ("register_dataset", "register_list"):
                return True
            cur = self._parent(cur)
        return False

    def _class_of(self, node: ast.AST) -> ast.ClassDef | None:
        cur = self._parent(node)
        while cur is not None:
            if isinstance(cur, ast.ClassDef):
                return cur
            cur = self._parent(cur)
        return None

    def _opsec_of_class(self, cls: ast.ClassDef) -> str:
        """The class's opsec, else the first one found on its bases defined in this file (bounded)."""
        seen: set[str] = set()
        todo = [cls]
        while todo and len(seen) < 32:
            cur = todo.pop(0)
            if cur.name in seen:
                continue
            seen.add(cur.name)
            if self.class_opsec.get(cur):
                return self.class_opsec[cur]
            for base in cur.bases:
                name = _dotted(base).rsplit(".", 1)[-1]
                if name in self.class_by_name:
                    todo.append(self.class_by_name[name])
        return ""

    def _contact_opsec(self, node: ast.AST) -> str:
        """'light'/'active' when the code belongs to (or shares a file with) a LIGHT/ACTIVE module class."""
        cls = self._class_of(node)
        if cls is not None:
            found = self._opsec_of_class(cls)
            if found in ("light", "active"):
                return found
        if cls is None:
            for value in self.class_opsec.values():
                if value in ("light", "active"):
                    return value
        return ""

    def _module_name(self, node: ast.AST) -> str:
        cls = self._class_of(node)
        if cls is not None and cls in self.class_name:
            return self.class_name[cls]
        names = set(self.class_name.values())
        return next(iter(names)) if len(names) == 1 else ""

    def _schema_covered(self) -> bool:
        """LINT-07 does not apply: a P145 schema covers the file, or no class of it reads registry
        sources (offline and target modules have no source schema; the runtime sanitizer covers them)."""
        if self.has_schema:
            return True
        if self.class_disclosure and not any(self.class_sources.values()) and \
                all(d in ("none", "target") for d in self.class_disclosure.values()):
            return True
        sources = [s for srcs in self.class_sources.values() for s in srcs]
        if not sources:
            return False
        try:
            from v3lum.core import sanitize  # lazy: the lint stays importable without the registry
        except ImportError:  # pragma: no cover
            return False
        try:
            return all(sanitize.schema_for(s) is not None for s in sources)
        except Exception:  # noqa: BLE001 - a broken registry never makes the lint pass
            return False

    def add(self, node: ast.AST, rule: str, message: str) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        end = int(getattr(node, "end_lineno", line) or line)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = line  # an issue about the name: a pragma inside the body must not cover it
        self.issues.append((line, end, rule, message))

    @property
    def module(self) -> bool:
        return self.profile == PROFILE_MODULE

    @property
    def tools_file(self) -> bool:
        return self.rel.endswith("core/tools.py")

    # -- imports ----------------------------------------------------------------------------
    def _check_import(self, node: ast.AST, name: str, *, dynamic: bool = False) -> None:
        if not name:
            return
        if name == "socket" and self.socket_helpers_only and not dynamic:
            return  # address parsing (socket.inet_pton...) is not network use (P327 cond 6)
        if self.profile != PROFILE_CORE and _module_covered(name, NETWORK_MODULES):
            self.add(node, LINT_NETWORK, f"import of {name!r}: direct network API (use ctx.http, ctx.dns or ctx.net)")
        if _module_covered(name, SUBPROCESS_MODULES) and not self.tools_file:
            self.add(node, LINT_NETWORK, f"import of {name!r}: process execution (external binaries only through ctx.net.run_tool; "
                                         "subprocess lives in v3lum/core/tools.py)")
        if _module_covered(name, FORBIDDEN_DEPENDENCIES):
            self.add(node, LINT_DEPENDENCY, f"import of {name!r}: anti-bot/CAPTCHA bypass or borrowed-session library")
        if _module_covered(name, CRACKING_MODULES):
            self.add(node, LINT_CRACKING, f"import of {name!r}: hash/JWT cracking library")
        if _module_covered(name, OFFENSIVE_MODULES):
            self.add(node, LINT_OFFENSIVE, f"import of {name!r}: exploitation/brute-force/OAST library")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                head = alias.name.split(".")[0]
                self.aliases.setdefault(head, head)
            self._check_import(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level == 0 and base:
            self._check_import(node, base)
            for alias in node.names:
                full = f"{base}.{alias.name}"
                self.aliases[alias.asname or alias.name] = full
                if _module_covered(full, NETWORK_MODULES) and not _module_covered(base, NETWORK_MODULES) and self.profile != PROFILE_CORE:
                    self.add(node, LINT_NETWORK, f"import of {full!r}: direct network API (use ctx.http, ctx.dns or ctx.net)")
                if full in SUBPROCESS_CALLS and not self.tools_file:
                    self.add(node, LINT_NETWORK, f"import of {full!r}: process execution (only through ctx.net.run_tool)")
        self.generic_visit(node)

    # -- calls ------------------------------------------------------------------------------
    def _resolve(self, name: str) -> str:
        head, _, rest = name.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    def _method_arg(self, call: ast.Call, fn: str) -> str | None:
        implied = _HTTP_CALLS.get(fn)
        if implied is not None:
            return implied
        node: ast.AST | None = call.args[0] if call.args else None
        for kw in call.keywords:
            if kw.arg == "method":
                node = kw.value
        text = _const_str(node)
        if text is None and isinstance(node, ast.Name):
            text = self.string_consts.get(node.id)
        return text.upper() if isinstance(text, str) else None

    def _url_arg(self, call: ast.Call, fn: str) -> ast.AST | None:
        for kw in call.keywords:
            if kw.arg == "url":
                return kw.value
        index = 1 if _HTTP_CALLS.get(fn, "x") is None else 0
        return call.args[index] if len(call.args) > index else None

    def _http_call(self, call: ast.Call) -> tuple[str, str | None] | None:
        """(function name, method) for an HTTP request call on an HTTP-like receiver, else None."""
        if not isinstance(call.func, ast.Attribute):
            return None
        fn = call.func.attr
        if fn not in _HTTP_CALLS:
            return None
        receiver = self._resolve(_dotted(call.func.value)).replace("()", "")
        last = receiver.rsplit(".", 1)[-1] if receiver else ""
        if not last or not (_HTTP_RECEIVER.match(last) or last in self.http_names):
            return None
        return fn, self._method_arg(call, fn)

    def _const_arg(self, node: ast.AST | None) -> str | None:
        """A string constant, or the string a module-level name was assigned."""
        text = _const_str(node)
        if text is None and isinstance(node, ast.Name):
            text = self.string_consts.get(node.id)
        return text

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(_dotted(node.func))
        last = name.rsplit(".", 1)[-1] if name else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        # dynamic imports and dynamic code
        if last in ("__import__", "import_module") and (node.args or node.keywords):
            arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "name"), None)
            target = self._const_arg(arg)
            if target:
                self._check_import(node, target, dynamic=True)
            elif self.profile != PROFILE_CORE:
                self.add(node, LINT_NETWORK, f"{last}() of a computed name: the lint cannot see what is imported (name it as a constant)")
        if self.profile != PROFILE_CORE:
            bare = isinstance(node.func, ast.Name) and node.func.id not in self.aliases and node.func.id not in self.defined_names
            if name in _DYNAMIC_CODE and (bare or name.startswith("builtins.")):
                self.add(node, LINT_NETWORK, f"{name}(): dynamic code execution (untrusted data is never executed; the lint cannot "
                                             "see what runs)")
            if name in UNSAFE_LOADERS or (name in ("yaml.load", "yaml.load_all") and not self._safe_yaml(node)):
                self.add(node, LINT_NETWORK, f"{name}(): deserialiser that can execute code from the data it loads (use json, or "
                                             "yaml.safe_load)")
        # process execution (only through names an import bound: a loop variable called 'sh' is not the sh package)
        imported = _dotted(node.func).split(".", 1)[0] in self.aliases
        if imported and (name in SUBPROCESS_CALLS or _module_covered(name, SUBPROCESS_MODULES)) and not self.tools_file:
            self.add(node, LINT_NETWORK, f"{name}(): process execution (external binaries only through ctx.net.run_tool)")
        if self.profile != PROFILE_CORE:
            receiver = _dotted(node.func.value) if isinstance(node.func, ast.Attribute) else ""
            if name in SOCKET_CALLS or (last in _SOCKET_METHODS and not re.search(r"(?:^|\.)_?net$", receiver)):
                self.add(node, LINT_NETWORK, f"{name or last}(): opens a socket/TLS connection outside ctx.net")
        if self.module:
            # a class reached through getattr(module, 'Name')(...) is built like Name(...)
            built = last
            if isinstance(node.func, ast.Call) and self._builtin_call(node.func, "getattr") and len(node.func.args) >= 2:
                built = self._const_arg(node.func.args[1]) or last
                gotten = self._resolve(_dotted(node.func.args[0]))
                name = f"{gotten}.{built}" if gotten else name
            callee = self._ctx_path(node.func)  # aliases of ctx resolved: d.fetch(...) with d = ctx.data
            if built in CORE_CLIENT_CLASSES:
                self.add(node, LINT_NETWORK, f"{built}(...) built inside a module: use ctx.http / ctx.net (host, scope and egress checks)")
            elif name in CORE_BUILT_NAMES or re.fullmatch(r"(?:self\.)?ctx(?:\.(?:http|net|dns|doh|data|runtime)(?:\.\w+)*)?\.__class__",
                                                          callee):
                self.add(node, LINT_NETWORK, f"{name.rsplit('.', 1)[-1] if name in CORE_BUILT_NAMES else callee}(...) built inside a "
                                             "module: a core object of its own has no module host list, scope or egress binding "
                                             "(use ctx.http / ctx.net)")
            if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "vars") and self._builtin_call(node, node.func.id):
                self._check_reach_around(node)  # getattr(ctx.http, "client"), vars(ctx.runtime)
            self._check_dynamic_ctx(node)  # setattr/delattr on ctx.http..., getattr(ctx.http, <computed>)
            if isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATING_METHODS and self._dataset_registry(node.func.value):
                self.add(node, LINT_NETWORK, f"DATASETS...{node.func.attr}(): edits the dataset registry: register_dataset at import time instead")
            self._check_runtime_handed(node, callee or name or last)
            if last in REMOTE_WRITE_METHODS:
                self.add(node, LINT_OFFENSIVE, f"{last}(): uploads, writes or deletes remote objects")
            fetch = callee.rsplit(".", 1)[-1] if re.fullmatch(r"(?:self\.)?ctx\.data(?:\.store)?\.\w+", callee) else ""
            if fetch not in _DATASET_FETCHES and last in _DATASET_FETCHES and isinstance(node.func, ast.Attribute) and \
                    re.search(r"(?:^|\.)data(?:\.store)?$", _dotted(node.func.value) or ""):
                fetch = last
            if fetch in _DATASET_FETCHES:
                url = node.args[1] if len(node.args) >= 2 else next((kw.value for kw in node.keywords if kw.arg == "url"), None)
                if url is not None and not (isinstance(url, ast.Constant) and url.value is None):
                    # the v1 fetch(name, url) form downloads from any URL outside the registry: no host check, no
                    # licence/terms class for the policy gate (A1), no size rule (A6) - register_dataset it instead
                    self.add(node, LINT_NETWORK, f"ctx.data.{fetch}(name, url): ad-hoc dataset download outside the registry "
                                                 "(register_dataset with its source, licence and terms class, then fetch by name)")
            if last == "run_tool" and (node.args or node.keywords):
                arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in ("name", "tool")), None)
                tool = re.split(r"[\\/]", (self._const_arg(arg) or "").strip())[-1].lower()
                tool = re.sub(r"\.(?:exe|bin|py|sh|bat|cmd)$", "", tool)
                if tool in CRACKING_TOOLS:
                    self.add(node, LINT_CRACKING, f"run_tool({tool!r}): hash/JWT cracking tool")
                if tool in OFFENSIVE_TOOLS:
                    self.add(node, LINT_OFFENSIVE, f"run_tool({tool!r}): exploitation, brute-force, OAST or DoS tool")
            if last in ("key", "has_key", "key_plan") and node.args:
                key = _const_str(node.args[0]) or ""
                if _SESSION_KEY.search(key):
                    self.add(node, LINT_ENUMERATION, f"ctx.{last}({key!r}): a session/cookie 'key' is a borrowed session (team rule 1)")
            if last == "setting" and node.args and isinstance(node.func, ast.Attribute):
                key = _const_str(node.args[0]) or ""
                if _SESSION_SETTING.search(key):
                    self.add(node, LINT_ENUMERATION, f"ctx.setting({key!r}): a session cookie or token setting is a borrowed session "
                                                     "(team rule 1)")
            http = self._http_call(node)
            if http is not None:
                self._check_request(node, *http)
            if last in ("attr", "set_attr") and len(node.args) >= 2 and isinstance(node.func, ast.Attribute):
                key = _const_str(node.args[0])
                if key and is_credential_field(key) and not isinstance(node.args[1], ast.Constant) and not self._schema_covered():
                    self.add(node, LINT_CREDENTIAL_FIELD, f"attribute {key!r} is a credential/password field (keep only 'password_form')")
            if last == "dict":
                for kw in node.keywords:
                    if kw.arg and is_credential_field(kw.arg) and not isinstance(kw.value, ast.Constant) and not self._schema_covered():
                        self.add(node, LINT_CREDENTIAL_FIELD, f"dict field {kw.arg!r} is a credential/password field")
        # TLS (every profile)
        for kw in node.keywords:
            off = isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, (bool, int)) and not kw.value.value
            if kw.arg in _TLS_VERIFY_KWARGS and off:
                self.add(kw.value, LINT_TLS, f"{name or last}({kw.arg}=False): TLS verification disabled")
            if kw.arg == "check_hostname" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.add(kw.value, LINT_TLS, f"{name or last}(check_hostname=False): TLS host check disabled")
            if kw.arg in ("cert_reqs", "verify_mode", "ssl_cert_reqs") and (str(_const_str(kw.value) or "").upper() in ("CERT_NONE", "NONE")):
                self.add(kw.value, LINT_TLS, f"{name or last}({kw.arg}='CERT_NONE'): TLS verification disabled")
            if kw.arg in ("insecure", "insecure_skip_verify", "skip_verify", "no_verify") and isinstance(kw.value, ast.Constant) \
                    and kw.value.value is True:
                self.add(kw.value, LINT_TLS, f"{name or last}({kw.arg}=True): TLS verification disabled")
        if last == "disable_warnings" or (last in ("filterwarnings", "simplefilter") and "InsecureRequestWarning" in ast.dump(node)):
            self.add(node, LINT_TLS, f"{name or last}(): silences TLS verification warnings")
        if last == "putenv" and node.args and (_const_str(node.args[0]) or "") in _TLS_ENV:
            self.add(node, LINT_TLS, f"os.putenv({_const_str(node.args[0])!r}): disables TLS verification")
        if last in ("setdefault", "update") and isinstance(node.func, ast.Attribute) and _dotted(node.func.value).endswith("environ"):
            names = [_const_str(node.args[0])] if (last == "setdefault" and node.args) else []
            for arg in node.args if last == "update" else ():
                if isinstance(arg, ast.Dict):
                    names.extend(_const_str(k) for k in arg.keys)
            names.extend(kw.arg for kw in node.keywords if last == "update")
            for env in names:
                if env in _TLS_ENV:
                    self.add(node, LINT_TLS, f"os.environ.{last}({env!r}): disables TLS verification")
        if last == "setattr" and len(node.args) >= 3 and _const_str(node.args[1]) in ("verify", "check_hostname") and \
                isinstance(node.args[2], ast.Constant) and node.args[2].value is False:
            self.add(node, LINT_TLS, f"setattr(..., {_const_str(node.args[1])!r}, False): TLS verification disabled")

    @staticmethod
    def _safe_yaml(node: ast.Call) -> bool:
        """yaml.load(..., Loader=SafeLoader / CSafeLoader / BaseLoader) is safe; anything else is not."""
        loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
        return loader is not None and _dotted(loader).rsplit(".", 1)[-1] in ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader")

    def _check_request(self, node: ast.Call, fn: str, method: str | None) -> None:
        opsec = self._contact_opsec(node)
        if method in STATE_CHANGING_METHODS and opsec:
            module = self._module_name(node)
            if not _method_allowlisted(module, method, self.root):
                self.add(node, LINT_METHOD, f"{method} request in a module with opsec {opsec.upper()} (LIGHT uses GET/HEAD, ACTIVE "
                                            f"GET/HEAD/OPTIONS; allow-list it in v3lum/data/policy/method_allowlist/{module or '<module>'}.json)")
        if method in WRITE_METHODS:
            self.add(node, LINT_OFFENSIVE, f"{method} request: writes or deletes on the receiving side")
        for kw in node.keywords:
            if kw.arg == "files":
                self.add(kw.value, LINT_OFFENSIVE, "request with files=: uploads are forbidden")
            if kw.arg in ("json", "data", "params") and isinstance(kw.value, ast.Dict):
                for key in kw.value.keys:
                    text = _const_str(key)
                    if text and _norm_key(text) in ("password", "passwd", "pass", "pwd", "senha", "passphrase", "otp", "totp", "mfa_code"):
                        self.add(key, LINT_ENUMERATION, f"credential field {text!r} sent in a request (login attempt)")
            static_cookies = isinstance(kw.value, ast.Dict) and all(isinstance(v, ast.Constant) for v in kw.value.values)
            if kw.arg == "cookies" and not (isinstance(kw.value, ast.Constant) and kw.value.value is None) and not static_cookies:
                self.add(kw.value, LINT_ENUMERATION, "cookies= with runtime values: borrowed sessions are forbidden (team rule 1)")
            if kw.arg == "headers" and isinstance(kw.value, ast.Dict):
                for key, value in zip(kw.value.keys, kw.value.values):
                    if (_const_str(key) or "").lower() == "cookie" and not isinstance(value, ast.Constant):
                        self.add(key, LINT_ENUMERATION, "Cookie header with a runtime value: borrowed sessions are forbidden (team rule 1)")
        url = self._url_arg(node, fn)
        text = _const_str(url)
        if text is not None and url is not None and id(url) not in self.skip:
            self.skip.add(id(url))
            self._check_string(url, text, method)
        elif isinstance(url, ast.JoinedStr):
            self._check_joined(url, method)

    # -- attributes and assignments ---------------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load) and node.attr in ("CERT_NONE", "_create_unverified_context") and not self._detection(node, loops=False):
            self.add(node, LINT_TLS, f"{_dotted(node) or node.attr}: TLS verification disabled")
        if self.module:
            if isinstance(node.ctx, ast.Load):
                self._check_reach_around(node)  # ctx.http.client, ctx.runtime.http, ctx.net._x...
            else:
                self._check_rebind(node)  # ctx.http.allowed_hosts = None, del ctx.runtime.http, ctx.runtime.in_scan = False
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in ("CERT_NONE", "_create_unverified_context") and \
                self.aliases.get(node.id, "").startswith("ssl.") and not self._detection(node, loops=False):
            self.add(node, LINT_TLS, f"{node.id}: TLS verification disabled")
        self.generic_visit(node)

    def _dataset_registry(self, node: ast.AST) -> bool:
        """``node`` is the dataset registry (``v3lum.core.datasets.DATASETS``) or an entry of it."""
        while isinstance(node, ast.Subscript):
            node = node.value
        return self._resolve(_dotted(node)).endswith("core.datasets.DATASETS")

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.module and not isinstance(node.ctx, ast.Load) and self._dataset_registry(node.value):
            # DATASETS['x'] = {...} / DATASETS['x']['url'] = ...: a registration nobody reviewed (register_dataset is an
            # import-time call; an edited entry would keep the reviewed dataset scope for a new URL)
            self.add(node, LINT_NETWORK, "edits the dataset registry (DATASETS): register_dataset at import time instead")
        self.generic_visit(node)

    def _check_target(self, target: ast.AST, value: ast.AST | None) -> None:
        if isinstance(target, ast.Attribute):
            if target.attr in ("verify", "check_hostname") and isinstance(value, ast.Constant) and value.value is False:
                self.add(target, LINT_TLS, f"{_dotted(target) or target.attr} = False: TLS verification disabled")
            if target.attr == "_create_default_https_context":
                self.add(target, LINT_TLS, "ssl._create_default_https_context replaced: TLS verification disabled")
        if isinstance(target, ast.Subscript):
            key = _const_str(target.slice)
            owner = _dotted(target.value)
            if key in _TLS_ENV and owner.endswith("environ"):
                self.add(target, LINT_TLS, f"os.environ[{key!r}] set: disables TLS verification")
            elif key and self.module and is_credential_field(key) and not isinstance(value, ast.Constant) and not self._schema_covered():
                self.add(target, LINT_CREDENTIAL_FIELD, f"field {key!r} is a credential/password field (keep only 'password_form')")
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._check_target(elt, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_target(node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_target(node.target, node.value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.module:
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("requires_keys", "optional_keys") for t in stmt.targets):
                    for const in _const_strings(stmt.value):
                        if _SESSION_KEY.search(const.value):
                            self.add(const, LINT_ENUMERATION, f"key {const.value!r} names a session/cookie: borrowed sessions are forbidden (team rule 1)")
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "settings" for t in stmt.targets) \
                        and isinstance(stmt.value, ast.Dict):
                    for key in stmt.value.keys:
                        text = _const_str(key)
                        if text and _SESSION_SETTING.search(text):
                            self.add(key, LINT_ENUMERATION, f"setting {text!r} holds a session cookie or token: borrowed sessions are "
                                                            "forbidden (team rule 1)")
            self._check_identifier(node, node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.module:
            self._check_identifier(node, node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _check_identifier(self, node: ast.AST, name: str) -> None:
        if _DETECTOR_NAME.search(name):
            return  # detect_brute_force, is_default_login_page: analysis of data, not the capability
        if _CRACKING_WORDS.search(name):
            self.add(node, LINT_CRACKING, f"{name!r}: hash/JWT cracking helper")
        elif _BRUTE_FORCE.search(name):
            self.add(node, LINT_OFFENSIVE, f"{name!r}: brute-force/spraying/DoS helper")
        elif _OFFENSIVE_IDENT.search(name):
            self.add(node, LINT_OFFENSIVE, f"{name!r}: exploitation helper")

    def visit_Dict(self, node: ast.Dict) -> None:
        parent = self._parent(node)
        call = self._parent(parent) if isinstance(parent, ast.keyword) else None
        # a request payload (checked by _check_request) - not finding data: res.finding(..., data={...}) is produced data
        payload = (isinstance(parent, ast.keyword) and parent.arg in ("json", "data", "params", "headers", "cookies")
                   and isinstance(call, ast.Call) and self._http_call(call) is not None)
        if self.module and not payload and not self._schema_covered():
            for key, value in zip(node.keys, node.values):
                text = _const_str(key)
                # a constant value is a static table ('credential': 'credential line'), not produced data
                if text and is_credential_field(text) and not isinstance(value, ast.Constant) and not self._detection(node, loops=False):
                    self.add(key, LINT_CREDENTIAL_FIELD, f"field {text!r} is a credential/password field (keep only 'password_form')")
        self.generic_visit(node)

    # -- strings ----------------------------------------------------------------------------
    def _check_joined(self, node: ast.JoinedStr, method: str | None) -> None:
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                self.skip.add(id(value))
            else:
                parts.append("{value}")
        self.skip.add(id(node))
        if self.profile == PROFILE_CORE or self._detection(node):
            return
        self._check_string(node, "".join(parts), method)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if id(node) not in self.skip:
            self._check_joined(node, None)
        self.generic_visit(node)

    def _check_string(self, node: ast.AST, text: str, method: str | None) -> None:
        """Probe/host rules for URL-like strings (modules), host rules only (rule packs), payload markers."""
        if not self.module:
            if _url_like(text):
                for rule, why in _host_rules(split_probe_url(text)[0]):
                    self.add(node, rule, f"{text[:120]}: {why}")
            return
        if _url_like(text):
            for rule, message in _probe_issues(text, method, dataset=self._dataset_argument(node)):
                self.add(node, rule, message)
        for rule, label, pattern in PAYLOAD_PATTERNS:
            if pattern.search(text):
                self.add(node, rule, f"{label} in a string literal")
        if _SMTP_PROBE.search(text):
            self.add(node, LINT_ENUMERATION, f"{text[:60]!r}: SMTP mailbox probing command (RCPT TO/VRFY/EXPN; team rule 2)")
        if not any(c.isspace() for c in text):
            if _CRACKING_WORDS.search(text):
                self.add(node, LINT_CRACKING, f"{text[:60]!r}: hash/JWT cracking")
            elif _BRUTE_FORCE.search(text):
                self.add(node, LINT_OFFENSIVE, f"{text[:60]!r}: brute-force/spraying/DoS material")

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, bytes) and self.module and not self._detection(node):
            if _SMTP_PROBE.search(node.value.decode("latin-1")):
                self.add(node, LINT_ENUMERATION, "bytes literal: SMTP mailbox probing command (RCPT TO/VRFY/EXPN; team rule 2)")
            return
        if not isinstance(node.value, str) or id(node) in self.docstrings or self.profile == PROFILE_CORE:
            return
        if id(node) in self.skip or self._detection(node):
            return
        self._check_string(node, node.value, None)


def _pragmas(text: str) -> dict[int, tuple[frozenset[str], str]]:
    """line -> (allowed rule ids, justification) from '# v3lum-lint: allow LINT-xx -- why' comments."""
    out: dict[int, tuple[frozenset[str], str]] = {}
    if "v3lum-lint" not in text:
        return out
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        comments = [(tok.start[0], tok.string) for tok in tokens if tok.type == tokenize.COMMENT]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        comments = [(i, line[line.index("#"):]) for i, line in enumerate(text.splitlines(), 1) if "#" in line]
    for line, comment in comments:
        m = _PRAGMA.search(comment)
        if m:
            rules = frozenset(r.strip() for r in m.group(1).split(","))
            out[line] = (rules, (m.group(2) or "").strip())
    return out


def _pragma_for(rule: str, line: int, end: int, pragmas: dict[int, tuple[frozenset[str], str]]) -> tuple[frozenset[str], str] | None:
    for n in range(line, max(line, end) + 1):
        found = pragmas.get(n)
        if found is not None and rule in found[0]:
            return found
    return None


def _apply_pragmas(raw: list[tuple[int, int, str, str]], pragmas: dict[int, tuple[frozenset[str], str]], rel: str) -> list[LintIssue]:
    issues: list[LintIssue] = []
    seen: set[tuple[int, str, str]] = set()
    for line, end, rule, message in sorted(raw):
        key = (line, rule, message)
        if key in seen:
            continue
        seen.add(key)
        found = _pragma_for(rule, line, end, pragmas)
        if found is None:
            issues.append(LintIssue(rel, line, rule, message))
        elif rule in NO_PRAGMA_RULES:
            issues.append(LintIssue(rel, line, rule, message + f" (no pragma is accepted for {rule})"))
        elif not found[1]:
            issues.append(LintIssue(rel, line, rule, message + " (pragma ignored: '-- <justification>' is missing)"))
        else:
            issues.append(LintIssue(rel, line, rule, message, allowed=True, justification=found[1]))
    return issues


def lint_module_source(path: str | Path, *, source: str | None = None, profile: str = PROFILE_MODULE,
                       display: str | None = None, root: str | Path | None = None) -> list[LintIssue]:
    """Lint one Python source file (AST + regex) and return its issues (pragma'd ones ``allowed``).

    ``profile`` 'module' (modules and plugins: every rule), 'code' (correlation rule packs: network,
    process, dependency, cracking, offensive-library and TLS rules) or 'core' (core files: process
    execution outside core/tools.py, forbidden dependencies, cracking/offensive libraries and TLS).
    ``source`` lints that text instead of reading ``path``; ``display`` names the file in issues;
    ``root`` is the package directory (for the method allow-list fragments).
    """
    if profile not in _PROFILES:
        raise ValueError(f"profile must be one of {_PROFILES}")
    p = Path(path)
    rel = display or str(path).replace("\\", "/")
    if source is None:
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [LintIssue(rel, 1, LINT_INVALID, f"unreadable source ({exc.strerror or exc})")]
    pragmas = _pragmas(source)
    try:
        tree = ast.parse(source, filename=rel)
        visitor = _SourceLint(tree, profile=profile, rel=rel, root=Path(root) if root is not None else None)
        visitor.run()
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        # fail closed: a file the AST pass cannot read is reported (LINT-00, blocking) and gets the regex checks
        line = int(getattr(exc, "lineno", 1) or 1) if isinstance(exc, SyntaxError) else 1
        why = getattr(exc, "msg", None) or str(exc) or type(exc).__name__
        raw = [(line, line, LINT_INVALID, f"cannot parse the source ({type(exc).__name__}: {why}): regex checks only")]
        for rule, label, pattern in _REGEX_FALLBACK:
            if rule != LINT_TLS and profile == PROFILE_CORE:
                continue
            for m in pattern.finditer(source):
                hit = source.count("\n", 0, m.start()) + 1
                raw.append((hit, hit, rule, f"{label}: {m.group(0).strip()!r}"))
        return _apply_pragmas(raw, pragmas, rel)
    return _apply_pragmas(visitor.issues, pragmas, rel)


# ---- data files ---------------------------------------------------------------------------

#: keys of probe URLs in username site lists and other data files (A5 rule 2)
_PROBE_KEYS = frozenset({"uri_check", "urlProbe", "url_probe", "probe_url", "check_url", "probe", "uri_probe", "request_url"})
_METHOD_KEYS = ("method", "request_method", "requestMethod", "http_method")
_BODY_KEYS = ("post_body", "postBody", "request_payload", "requestPayload", "body", "data")
_DOC_KEYS = frozenset({
    "signup_url", "evidence_url", "source_url", "homepage", "url_main", "urlMain", "uri_pretty", "reference", "references",
    "docs", "documentation", "notes", "description", "attribution", "licence_url", "license_url", "terms_url",
})


def _issue(rel: str, rule: str, message: str, line: int = 1) -> LintIssue:
    return LintIssue(rel, line, rule, message)


def _rule_of_pack_problem(problem: str) -> str:
    for rule in (LINT_ENUMERATION, LINT_PEOPLE_SEARCH, LINT_SUBMISSION):
        if rule in problem:
            return rule
    low = problem.lower()
    if "publish" in low or "scan_trigger" in low:
        return LINT_SUBMISSION
    if "login" in low:
        return LINT_ENUMERATION
    if "cpf" in low:
        return LINT_PEOPLE_SEARCH
    return LINT_INVALID


def _probe_entry_issues(rel: str, where: str, url: Any, method: Any) -> list[LintIssue]:
    if not isinstance(url, str) or not url.strip():
        return []
    sample = re.sub(r"\{[A-Za-z0-9_]{0,32}\}", "{value}", url.strip())
    return [_issue(rel, rule, f"{where}: {message}") for rule, message in _probe_issues(sample, str(method or "GET"))]


def _walk_probe_keys(rel: str, data: Any, where: str = "$") -> list[LintIssue]:
    """Probe URLs anywhere in a data file: probe keys, and 'url' entries that come with a method or body."""
    out: list[LintIssue] = []
    stack: list[tuple[Any, str]] = [(data, where)]
    while stack:
        obj, here = stack.pop()
        if isinstance(obj, Mapping):
            method = next((obj[k] for k in _METHOD_KEYS if isinstance(obj.get(k), str)), None)
            if method is None and any(obj.get(k) for k in _BODY_KEYS if k != "data"):
                method = "POST"
            for key, value in obj.items():
                k = str(key)
                if k in _DOC_KEYS:
                    continue
                if isinstance(value, str) and (k in _PROBE_KEYS or (k in ("url", "uri", "endpoint") and method is not None)):
                    out.extend(_probe_entry_issues(rel, f"{here}.{k}", value, method))
                elif isinstance(value, (Mapping, list)):
                    stack.append((value, f"{here}.{k}"))
        elif isinstance(obj, list):
            stack.extend((v, f"{here}[{i}]") for i, v in enumerate(obj))
    return out


def _site_list_issues(rel: str, data: Any) -> list[LintIssue] | None:
    """WhatsMyName / Maigret / Sherlock formats (A5 rule 2); None when ``data`` is none of them."""
    out: list[LintIssue] = []
    if isinstance(data, Mapping) and isinstance(data.get("sites"), list):  # WhatsMyName
        for i, site in enumerate(data["sites"]):
            if isinstance(site, Mapping):
                method = site.get("method") or ("POST" if site.get("post_body") else "GET")
                out.extend(_probe_entry_issues(rel, f"sites[{i}] {site.get('name', '')}".strip(), site.get("uri_check"), method))
        return out
    sites = data.get("sites") if isinstance(data, Mapping) and isinstance(data.get("sites"), Mapping) else data
    if isinstance(sites, Mapping) and sites and all(isinstance(v, Mapping) for v in sites.values()) and \
            any(("checkType" in v or "errorType" in v) and "url" in v for v in sites.values()):  # Maigret / Sherlock
        for name, site in sites.items():
            method = site.get("request_method") or site.get("requestMethod") or ("POST" if site.get("request_payload") else "GET")
            out.extend(_probe_entry_issues(rel, f"{name} url", site.get("url"), method))
            out.extend(_probe_entry_issues(rel, f"{name} urlProbe", site.get("urlProbe"), method))
        return out
    return None


def _spec_issues(rel: str, data: Mapping[str, Any]) -> list[LintIssue]:
    out: list[LintIssue] = []
    request = data.get("request") if isinstance(data.get("request"), Mapping) else {}
    method = str(request.get("method") or "GET").upper()
    if method != "GET":
        out.append(_issue(rel, LINT_METHOD, f"request.method {method}: declarative specs only GET (no value is ever posted)"))
    out.extend(_probe_entry_issues(rel, "request.url", request.get("url"), method))
    manual = data.get("manual_link")
    if isinstance(manual, str) and "://" in manual:
        out.extend(_probe_entry_issues(rel, "manual_link", manual, "GET"))
    hosts = data.get("hosts") if isinstance(data.get("hosts"), list) else []
    for host in hosts:
        if isinstance(host, str):
            h = host.lower().lstrip("*.")
            if people_search_host(h):
                out.append(_issue(rel, LINT_PEOPLE_SEARCH, f"hosts: {host!r}: {PROBE_RULES[LINT_PEOPLE_SEARCH]}"))
            if smtp_verification_host(h):
                out.append(_issue(rel, LINT_ENUMERATION, f"hosts: {host!r}: mailbox verification service (team rule 2)"))
            out.extend(_issue(rel, rule, f"hosts: {why}") for rule, why in _host_rules(h))
    headers = request.get("headers") if isinstance(request.get("headers"), Mapping) else {}
    for name in headers:
        if str(name).lower() in ("cookie", "set-cookie"):
            out.append(_issue(rel, LINT_ENUMERATION, f"request.headers.{name}: cookies are borrowed sessions (team rule 1)"))
    results = data.get("results") if isinstance(data.get("results"), list) else []
    for i, item in enumerate(results):
        if not isinstance(item, Mapping):
            continue
        key = str(item.get("key") or "")
        last = key.replace("[]", "").rsplit(".", 1)[-1]
        if last and is_credential_field(last):
            out.append(_issue(rel, LINT_CREDENTIAL_FIELD, f"results[{i}].key {key!r}: credential/password field extracted (P145)"))
        attribute = item.get("attribute")
        if isinstance(attribute, str) and is_credential_field(attribute):
            out.append(_issue(rel, LINT_CREDENTIAL_FIELD, f"results[{i}].attribute {attribute!r}: credential/password field"))
    return out


def _provider_issues(rel: str, path: Path | None, data: Any, cache: dict[str, Any] | None) -> list[LintIssue]:
    out: list[LintIssue] = []
    fragments = data.get("providers") if isinstance(data, Mapping) and isinstance(data.get("providers"), list) else [data]
    for frag in fragments:
        if not isinstance(frag, Mapping):
            continue
        for host in frag.get("hosts") or ():
            if not isinstance(host, str):
                continue
            h = host.lower().lstrip("*.")
            if people_search_host(h):
                out.append(_issue(rel, LINT_PEOPLE_SEARCH, f"hosts: {host!r}: {PROBE_RULES[LINT_PEOPLE_SEARCH]}"))
            if smtp_verification_host(h):
                out.append(_issue(rel, LINT_ENUMERATION, f"hosts: {host!r}: mailbox verification service (team rule 2)"))
            out.extend(_issue(rel, rule, f"hosts: {why}") for rule, why in _host_rules(h))
        sources = frag.get("sources") if isinstance(frag.get("sources"), Mapping) else {}
        for sid, src in sources.items():
            sanitizer = src.get("sanitizer") if isinstance(src, Mapping) else None
            keep = sanitizer.get("keep") if isinstance(sanitizer, Mapping) else None
            for path_text in keep if isinstance(keep, list) else ():
                last = str(path_text).replace("[]", "").rsplit(".", 1)[-1]
                if last and last != "*" and is_credential_field(last) and not is_password_form_carrier(last):
                    out.append(_issue(rel, LINT_CREDENTIAL_FIELD, f"sources.{sid}.sanitizer keeps {path_text!r}: schemas keep metadata only (P145)"))
    if path is not None:
        out.extend(_provider_schema_issues(rel, path, cache))
    return out


def _provider_schema_issues(rel: str, path: Path, cache: dict[str, Any] | None) -> list[LintIssue]:
    """Schema problems of a provider fragment file, through the provider registry loader."""
    try:
        from v3lum.core import providers
    except ImportError:  # pragma: no cover
        return []
    directory = str(path.resolve().parent)
    store = cache if cache is not None else {}
    errors = store.get(directory)
    if errors is None:
        try:
            errors = list(providers.load_dir(directory).errors)
        except Exception as exc:  # noqa: BLE001 - the lint reports, never crashes
            errors = [f"{path.name}: provider fragments could not be loaded ({type(exc).__name__}: {exc})"]
        store[directory] = errors
    name = path.name
    return [_issue(rel, LINT_INVALID, err) for err in errors if err.startswith((name + ":", name + "["))]


def _extra_issues(rel: str, data: Mapping[str, Any]) -> list[LintIssue]:
    out: list[LintIssue] = []
    package = str(data.get("package") or "")
    pip = re.split(r"[<>=!~\[; ]", str(data.get("pip") or ""), maxsplit=1)[0].replace("-", "_").lower()
    for name in {package, pip} - {""}:
        if _module_covered(name, FORBIDDEN_DEPENDENCIES):
            out.append(_issue(rel, LINT_DEPENDENCY, f"optional dependency {name!r}: anti-bot/CAPTCHA bypass or borrowed-session library"))
        if _module_covered(name, CRACKING_MODULES):
            out.append(_issue(rel, LINT_CRACKING, f"optional dependency {name!r}: hash/JWT cracking library"))
        if _module_covered(name, OFFENSIVE_MODULES):
            out.append(_issue(rel, LINT_OFFENSIVE, f"optional dependency {name!r}: exploitation/brute-force/OAST library"))
    return out


def _method_allow_issues(rel: str, data: Mapping[str, Any]) -> list[LintIssue]:
    out: list[LintIssue] = []
    methods = data.get("methods") if isinstance(data.get("methods"), Mapping) else {}
    for method in methods:
        if str(method).upper() in WRITE_METHODS:
            out.append(_issue(rel, LINT_OFFENSIVE, f"methods.{method}: writes/deletes are never allow-listed (A7 BR9)"))
    if not str(data.get("approved_by") or "").strip() or not str(data.get("decision_ref") or "").strip():
        out.append(_issue(rel, LINT_METHOD, "fragment without approved_by and decision_ref: ignored by the HTTP client (WP11)"))
    return out


def _data_kind(path: Path | None, data: Any) -> str:
    schema = data.get("schema") if isinstance(data, Mapping) else None
    kinds = {
        "v3lum.pivot_pack/1": "pack", "v3lum.spec/1": "spec", "v3lum.provider/1": "provider", "v3lum.provider-ext/1": "provider",
        "v3lum.provider-set/1": "provider", "v3lum.extra/1": "extra", "v3lum.method_allow/1": "method_allow",
        LINT_TABLES_SCHEMA: "lint_tables",
    }
    if schema in kinds:
        return kinds[schema]
    if path is not None:
        if path.name == "pivot_links.json":
            return "pack"
        parent = path.parent.name
        if parent == "providers":
            return "provider"
        if parent == "pivot_links":
            return "pack"
        if parent == "specs":
            return "spec"
        if parent == "method_allowlist":
            return "method_allow"
    return "generic"


def _read_data(path: Path) -> tuple[Any, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"unreadable ({exc.strerror or exc})"
    if path.suffix == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ImportError:  # pragma: no cover - 3.10: TOML data files are skipped
            return None, ""
        try:
            return tomllib.loads(text), ""
        except ValueError as exc:
            return None, f"invalid TOML ({exc})"
    try:
        return json.loads(text), ""
    except ValueError as exc:
        return None, f"invalid JSON ({exc})"


def lint_data_file(path: str | Path | Mapping[str, Any], *, data: Any = None, kind: str | None = None,
                   display: str | None = None, cache: dict[str, Any] | None = None) -> list[LintIssue]:
    """Lint one data file: pivot packs (``links.lint_pack``), declarative specs (request URL and
    method, hosts, extracted credential fields), provider fragments (schema through the provider
    loader, people-search/verification/solver hosts, sanitizer keep paths), extras (forbidden
    dependencies), method allow-lists, username site lists (WhatsMyName, Maigret, Sherlock formats)
    and any data file with probe URLs (LINT-03/05). ``data`` lints an already-parsed object (``path``
    then only names it); a Mapping may also be passed as ``path``. ``kind`` forces the format
    ('pack', 'spec', 'provider', 'extra', 'method_allow', 'lint_tables', 'generic').
    """
    if isinstance(path, Mapping):
        data, file_path, rel = path, None, display or "<data>"
    else:
        file_path = Path(path)
        rel = display or str(path).replace("\\", "/")
    try:
        return _lint_data(file_path, rel, data, kind, cache)
    except (RecursionError, MemoryError, ValueError, TypeError, AttributeError) as exc:  # fail closed, never crash the gate
        return [_issue(rel, LINT_INVALID, f"the lint could not read this data file ({type(exc).__name__}): fix its structure")]


def _lint_data(file_path: Path | None, rel: str, data: Any, kind: str | None, cache: dict[str, Any] | None) -> list[LintIssue]:
    if data is None:
        if file_path is None or file_path.suffix not in (".json", ".toml"):
            return []
        data, problem = _read_data(file_path)
        if problem:
            return [_issue(rel, LINT_INVALID, problem)]
        if data is None:
            return []
    kind = kind or _data_kind(file_path, data)
    if kind == "pack":
        try:
            from v3lum.core import links  # lazy: links imports this module
        except ImportError:  # pragma: no cover
            return []
        source = file_path.name if file_path is not None else "<pack>"
        return [_issue(rel, _rule_of_pack_problem(p), p) for p in links.lint_pack(data, source=source)]
    if not isinstance(data, (Mapping, list)):
        return []
    if kind == "spec" and isinstance(data, Mapping):
        return _spec_issues(rel, data)
    if kind == "provider":
        return _provider_issues(rel, file_path, data, cache)
    if kind == "extra" and isinstance(data, Mapping):
        return _extra_issues(rel, data)
    if kind == "method_allow" and isinstance(data, Mapping):
        return _method_allow_issues(rel, data)
    if kind == "lint_tables":
        stem = file_path.stem if file_path is not None else str(data.get("name", "")) if isinstance(data, Mapping) else ""
        return [_issue(rel, LINT_INVALID, p) for p in _table_fragment_problems(data, stem)]
    listed = _site_list_issues(rel, data)
    if listed is not None:
        return listed
    return _walk_probe_keys(rel, data)


# ---- trees ----------------------------------------------------------------------------------

_SKIP_DIRS = frozenset({"__pycache__", ".git", ".venv", "venv", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache"})
_MAX_DATA_BYTES = 20 * 1024 * 1024
_MAX_SOURCE_BYTES = 5 * 1024 * 1024


def _package_root(root: Path) -> bool:
    return (root / "core" / "module.py").is_file()


def _iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in _SKIP_DIRS or (part.startswith(".") and part not in (".", "..")) for part in rel_parts[:-1]):
            continue
        if path.is_file() and path.suffix in (".py", ".json", ".toml"):
            yield path


def lint_tree(root: str | Path = "v3lum") -> list[LintIssue]:
    """Lint every Python source and data file under ``root`` (sorted issues).

    For the package itself (``lint_tree('v3lum')``; the installed package when no 'v3lum' directory
    exists here) files under ``modules/`` get every rule, ``correlations/`` the code rules and every
    other file the core rules (LINT-10 everywhere; subprocess only in core/tools.py). Any other root
    (~/.v3lum/plugins, ~/.v3lum/specs, a batch directory) is linted as modules and data files.
    """
    base = Path(root)
    if str(root) == "v3lum" and not base.exists():
        base = Path(__file__).resolve().parent.parent
    if not base.exists():
        return [LintIssue(str(root), 1, LINT_INVALID, "path does not exist")]
    package = base.is_dir() and _package_root(base)
    anchor = base.parent if base.is_dir() else base.parent
    cache: dict[str, Any] = {}
    issues: list[LintIssue] = []
    for path in _iter_files(base):
        try:
            display = path.relative_to(anchor).as_posix()
        except ValueError:
            display = path.as_posix()
        try:
            if path.suffix == ".py":
                size = path.stat().st_size
                if size > _MAX_SOURCE_BYTES:  # a plugin pointing at a huge file must not exhaust memory
                    issues.append(LintIssue(display, 1, LINT_INVALID, f"source too large to lint ({size} bytes > {_MAX_SOURCE_BYTES})"))
                    continue
                profile = PROFILE_MODULE
                if package:
                    parts = path.relative_to(base).parts
                    profile = PROFILE_MODULE if parts[0] == "modules" else PROFILE_CODE if parts[0] == "correlations" else PROFILE_CORE
                issues.extend(lint_module_source(path, profile=profile, display=display, root=base if package else None))
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                issues.append(LintIssue(display, 1, LINT_INVALID, f"unreadable data file ({exc.strerror or exc})"))
                continue
            if size > _MAX_DATA_BYTES:  # never skipped silently: the lint cannot vouch for what it did not read
                issues.append(LintIssue(display, 1, LINT_INVALID, f"data file too large to lint ({size} bytes > {_MAX_DATA_BYTES}): "
                                                                  "ship large data as a runtime dataset (register_dataset)"))
                continue
            issues.extend(lint_data_file(path, display=display, cache=cache))
        except Exception as exc:  # noqa: BLE001 - one broken file never aborts the gate: it fails as LINT-00
            issues.append(LintIssue(display, 1, LINT_INVALID, f"the lint failed on this file ({type(exc).__name__}): report it"))
    return sorted(issues, key=lambda i: (i.path, i.line, i.rule_id, i.message))
