"""E-mail hygiene second opinions (P088 C5): Kickbox Open and MailCheck.ai, domain only, opt-in.

Online second opinions next to the offline lists of ``email_hygiene``: Kickbox Open
``GET /v1/disposable/{domain}`` and MailCheck.ai (UserCheck) ``GET /domain/{domain}``. Binding rules:

* only the normalised DOMAIN is ever sent, never the address or its local part; the MailCheck.ai
  ``/email`` endpoint and Disify (it needs the full address) are never used (C5);
* opt-in: ``default_enabled = False``; terms are recorded per provider in the registry before use -
  Kickbox Open publishes no terms for the free endpoint (class 'unknown': the aggregator filter
  of the policy gate drops that feed under the corporate profile), MailCheck.ai's terms allow the
  keyless free plan with no resale or redistribution of results (class 'open', internal use);
* no SMTP check of any kind (C6); relay domains are privacy tools, never scored (C4);
* rule 5: a 403/429/challenge/timeout of one feed is that feed's 'could not verify'
  (``res.source_status``), never a 'not disposable' answer; MailCheck.ai's JSON ``status`` field and
  Kickbox ``error`` fields are error-in-200 markers.
Kickbox answers ``{"disposable": false}`` even for invalid input, so the domain is validated locally
before any call.
"""

from __future__ import annotations

from typing import Any

from v3lum.core import http as _http
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.email.email_hygiene import candidate_domains, normalise_domain

SRC_KICKBOX = "kickbox.disposable"
SRC_MAILCHECK = "mailcheck.domain"
KICKBOX_URL = "https://open.kickbox.com/v1/disposable/{domain}"
MAILCHECK_URL = "https://api.mailcheck.ai/domain/{domain}"

#: exceptions that mean "this feed could not verify" (rule 5): (exception name, status, default code)
_FEED_FAILURES: tuple[tuple[str, Status, str], ...] = (
    ("QuotaExceeded", Status.QUOTA, "quota"),
    ("RateLimited", Status.RATE_LIMITED, "rate_limited"),
    ("Blocked", Status.BLOCKED, "challenge"),
    ("AuthRequired", Status.BLOCKED, "challenge"),
    ("DeadlineExceeded", Status.ERROR, "timeout"),
    ("OfflineError", Status.UNAVAILABLE, "offline"),
    ("NetworkError", Status.ERROR, "error"),
    ("HttpError", Status.ERROR, "error"),
)
#: never caught: the engine keeps what was built (request cap, kill switch) or maps it (policy, config)
_PROPAGATE = ("RequestCapReached", "Cancelled", "PolicyError", "ConfigError")


def query_domain(entity: Entity) -> str | None:
    """The ONLY value this module may send (P088 C5): the normalised domain of an address or a
    domain, never the local part; None (do not query) for an invalid value or a public suffix."""
    value = entity.value.rsplit("@", 1)[-1] if entity.type is T.EMAIL else entity.value
    dom = normalise_domain(value)
    return dom if dom and candidate_domains(dom) else None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _text(value: Any, limit: int = 120) -> str:
    return " ".join(str(value).split())[:limit] if isinstance(value, (str, int, float)) else ""


class FeedError(Exception):
    """An answer that cannot be read as an opinion: status + canonical reason code + text."""

    def __init__(self, status: Status, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.reason_code = reason_code


def parse_kickbox(data: Any) -> dict[str, Any]:
    """Kickbox Open body -> {'disposable': bool}; raises FeedError for odd or error answers."""
    if not isinstance(data, dict):
        raise FeedError(Status.ERROR, "error", "unexpected Kickbox answer (not a JSON object): could not verify")
    if data.get("error") or (data.get("message") and "disposable" not in data):
        raise FeedError(Status.ERROR, "error", "Kickbox error: " + _text(data.get("error") or data.get("message")))
    value = _bool(data.get("disposable"))
    if value is None:
        raise FeedError(Status.ERROR, "error", "Kickbox answer without a boolean 'disposable': could not verify")
    return {"disposable": value}


def parse_mailcheck(data: Any) -> dict[str, Any]:
    """MailCheck.ai /domain body -> normalised opinion; raises FeedError for odd or error answers.
    The JSON carries its own ``status``: anything but 200 is an error inside an HTTP 200."""
    if not isinstance(data, dict):
        raise FeedError(Status.ERROR, "error", "unexpected MailCheck.ai answer (not a JSON object): could not verify")
    inner = _int(data.get("status"))
    if inner is not None and inner != 200:
        detail = _text(data.get("error") or data.get("message"), 160)
        if inner == 429:
            raise FeedError(Status.RATE_LIMITED, "rate_limited", f"MailCheck.ai status 429 {detail}".strip())
        if inner in (401, 402, 403):
            raise FeedError(Status.BLOCKED, "challenge", f"MailCheck.ai status {inner} {detail}".strip())
        raise FeedError(Status.ERROR, "error", f"MailCheck.ai status {inner} {detail}".strip())
    disposable = _bool(data.get("disposable"))
    if disposable is None:
        raise FeedError(Status.ERROR, "error", "MailCheck.ai answer without a boolean 'disposable': could not verify")
    mx_hosts: list[str] = []
    for record in data.get("mx_records") if isinstance(data.get("mx_records"), list) else []:
        host = record.get("hostname") if isinstance(record, dict) else record
        dom = normalise_domain(host) if isinstance(host, str) else None
        if dom and dom not in mx_hosts:
            mx_hosts.append(dom)
    providers = []
    for item in data.get("mx_providers") if isinstance(data.get("mx_providers"), list) else []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and name.strip():
            providers.append(_text(name, 80))
    out: dict[str, Any] = {
        "disposable": disposable,
        "free_provider": _bool(data.get("public_domain")),
        "relay": _bool(data.get("relay_domain")),
        "free_subdomain": _bool(data.get("free_subdomain")),
        "spam": _bool(data.get("spam")),
        "mx": _bool(data.get("mx")),
        "mx_hosts": mx_hosts[:20],
        "mx_providers": providers[:10],
        "spf": _text(data.get("spf"), 40) or None,
        "dmarc": _text(data.get("dmarc"), 40) or None,
        "domain_age_days": _int(data.get("domain_age_in_days")),
        "did_you_mean": normalise_domain(data.get("did_you_mean")) if isinstance(data.get("did_you_mean"), str) else None,
    }
    return {k: v for k, v in out.items() if v is not None and v != []}


def _failure(exc: BaseException) -> tuple[Status, str] | None:
    if type(exc).__name__ in _PROPAGATE:
        return None
    for name, status, code in _FEED_FAILURES:
        klass = getattr(_http, name, None)
        if klass is not None and isinstance(exc, klass):
            given = str(getattr(exc, "reason_code", "") or "")
            if status is Status.BLOCKED and given in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                return status, given
            if status is Status.ERROR and given in ("timeout", "error"):
                return status, given
            return status, code
    return None


@register
class EmailHygieneOnline(Module):
    name = "email_hygiene_online"
    title = "E-mail hygiene second opinions (Kickbox Open, MailCheck.ai)"
    description = (
        "Asks Kickbox Open and MailCheck.ai whether an e-mail domain is disposable, a relay or a public provider, plus "
        "domain age and MX facts; only the domain is sent, never the address."
    )
    category = "email"
    accepts = {T.EMAIL, T.DOMAIN}
    tags = {"free"}
    reference = "https://www.usercheck.com/legal/terms"
    notice = (
        "Opt-in (P088 C5): sends only the domain, never the address. Kickbox Open publishes no terms for the free endpoint "
        "(terms unknown: skipped under the corporate profile); MailCheck.ai results are for internal use only (no "
        "redistribution, its s.12). Keyless MailCheck.ai allows about 5 requests per hour."
    )
    terms = "unknown"  # most restrictive source class: kickbox.disposable is 'unknown', mailcheck.domain 'open'
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "mailcheck"
    sources = (SRC_MAILCHECK, SRC_KICKBOX)
    hosts = ("api.mailcheck.ai", "open.kickbox.com")
    access_model = "free_noauth_limited"
    max_requests = 2  # one per provider
    expected_latency = 0.8
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 7 * 86400  # one opinion per domain and week
    default_enabled = False
    max_pivots = 0

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_domain(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = query_domain(entity)
        if domain is None:  # applies() filters these; defensive
            return res.mark("error", "no valid domain to query")
        allowed = getattr(ctx, "allowed_sources", None)
        feeds = [s for s in self.sources if allowed is None or s in allowed]
        opinions: dict[str, dict[str, Any]] = {}
        raw: dict[str, Any] = {"domain_sent": domain}
        failures: list[tuple[Status, str, str]] = []
        for source in feeds:
            url = (MAILCHECK_URL if source == SRC_MAILCHECK else KICKBOX_URL).format(domain=domain)
            try:
                data = ctx.http.get_json(url, source=source)
                opinion = parse_mailcheck(data) if source == SRC_MAILCHECK else parse_kickbox(data)
            except FeedError as exc:
                failures.append((exc.status, exc.reason_code, str(exc)))
                res.source_status(source, exc.status, reason_code=exc.reason_code, reason=str(exc))
                continue
            except Exception as exc:  # noqa: BLE001 - per-feed rule 5, the rest propagates
                mapped = _failure(exc)
                if mapped is None:
                    raise
                failures.append((mapped[0], mapped[1], str(exc)[:200]))
                res.source_status(source, mapped[0], reason_code=mapped[1], reason=str(exc)[:200])
                continue
            key = "mailcheck" if source == SRC_MAILCHECK else "kickbox"
            opinions[key] = opinion
            raw[source] = opinion
        res.raw = raw
        if not opinions:
            if not feeds:
                return res.mark("skipped", "no feed allowed for this run", reason_code="licence")
            status, code, text = failures[0]
            return res.mark(status, "; ".join(f for _s, _c, f in failures) or text, reason_code=code)
        res.attr("hygiene_opinions", opinions)
        self._findings(res, domain, opinions)
        return res

    @staticmethod
    def _findings(res: ModuleResult, domain: str, opinions: dict[str, dict[str, Any]]) -> None:
        relay = any(o.get("relay") is True for o in opinions.values())
        disposable_by = sorted(k for k, o in opinions.items() if o.get("disposable") is True)
        mail = opinions.get("mailcheck") or {}
        if relay:
            res.finding(
                "Privacy relay domain (second opinion)",
                "info",
                f"MailCheck.ai reports {domain} as a forwarding/relay domain: a privacy tool, never scored as malicious.",
                confidence="possible",
                criterion="MailCheck.ai relay_domain=true (P088 C4: relay is never disposable)",
                tags=["info", "privacy_relay", "context_only"],
                source=SRC_MAILCHECK,
            )
        elif disposable_by:
            res.finding(
                "Disposable e-mail domain (second opinion)",
                "low",
                f"{', '.join(disposable_by)} report(s) {domain} as disposable: a weak fraud signal, not proof.",
                confidence="probable" if len(disposable_by) > 1 else "possible",
                criterion="online second opinion: disposable=true from " + " and ".join(disposable_by),
                data={"providers": disposable_by},
                tags=["weak_signal"],
                source=SRC_MAILCHECK if "mailcheck" in disposable_by else SRC_KICKBOX,
            )
        age = mail.get("domain_age_days")
        if isinstance(age, int) and 0 <= age <= 30:
            res.finding(
                "Very young e-mail domain",
                "low",
                f"{domain} was registered about {age} days ago (MailCheck.ai): new domains are common in fraud and phishing.",
                confidence="possible",
                criterion="MailCheck.ai domain_age_in_days <= 30",
                data={"domain_age_days": age},
                tags=["weak_signal"],
                source=SRC_MAILCHECK,
            )
        if mail.get("mx") is False:
            res.finding(
                "Domain has no MX according to MailCheck.ai",
                "info",
                f"MailCheck.ai sees no mail exchanger for {domain} (second opinion; email_basics checks DNS directly).",
                confidence="possible",
                criterion="MailCheck.ai mx=false",
                source=SRC_MAILCHECK,
            )
        if isinstance(age, int) and age >= 0:
            res.attr("domain_age_days", age)
