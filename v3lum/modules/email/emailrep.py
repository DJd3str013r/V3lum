"""EmailRep.io reputation of one analyst-typed address (P089), keyed.

``GET https://emailrep.io/{email}`` with the headers ``Key: <key>`` and ``Accept: application/json``
(without Accept the endpoint serves its HTML site with HTTP 200, cond 3).

* **Terms unknown** (cond 1): the EmailRep (Sublime Security) terms were not reachable on 2026-11-26,
  so the source class is ``unknown``: the licence gate keeps the module disabled in every profile until
  legal records the terms; afterwards it becomes key-terms with a company account and a recorded plan.
  ``default_enabled=False``.
* **Full address disclosed** (cond 2): runs only on analyst-typed seed addresses (``run_on='seeds'``;
  sender addresses in phishing triage, own-domain addresses), never on pivots. The provider fragment
  carries ``reuses_queries=true`` (fail closed), so the policy gate skips it at TLP:AMBER and above
  (``max_tlp`` GREEN); the module repeats both checks itself (SKIPPED ``privacy`` / ``tlp``). The
  recipient is recorded in the ROPA (docs, legal).
* **Errors** (cond 3): a missing key is NEEDS_KEY before any request; an invalid key (401 JSON) is
  NEEDS_KEY; anonymous or throttled 429 is RATE_LIMITED; the HTML site served with 200 and a
  ``{"status": "fail"}`` body are errors inside an HTTP-200 answer (error markers), never an absence.
* **Dropped at ingestion** (cond 4): ``deliverable``, ``accept_all`` (provider-side SMTP verification)
  and ``profiles`` (server-side account checks) are never stored, pivoted or scored - only their names
  are counted. The HTTP cache never stores the answer (``cache_ttl=0``, provider ttl 0).
* **Kept** (cond 5): reputation, suspicious, blacklisted, malicious activity (and its recent variant),
  the credential-leak and data-breach flags (metadata only, A4: renamed ``leak_reported`` so the P145
  second net does not mistake a boolean for a credential), first/last seen, spoofable, spf_strict,
  dmarc_enforced and the domain age. Everything else of the answer is dropped.
* Merge gate (cond 6): the success fixtures are documentation-shaped until a trimmed real capture made
  with the team key replaces them (docs/backlog/p3-G04-1.md).
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "emailrep.reputation"
HOST = "emailrep.io"
API = "https://emailrep.io/{email}"
KEY_NAME = "emailrep"

#: P089 cond 4: provider-side mailbox/account checks, dropped at ingestion (rule 2 by proxy).
DROPPED_FIELDS = ("deliverable", "accept_all", "profiles")
#: P089 cond 5 allow-list of ``details`` booleans -> kept flag name.
KEPT_FLAGS = {
    "blacklisted": "blacklisted",
    "malicious_activity": "malicious_activity",
    "malicious_activity_recent": "malicious_activity_recent",
    "credentials_leaked": "leak_reported",
    "credentials_leaked_recent": "leak_reported_recent",
    "data_breach": "data_breach",
    "spoofable": "spoofable",
    "spf_strict": "spf_strict",
    "dmarc_enforced": "dmarc_enforced",
}
REPUTATIONS = ("high", "medium", "low", "none")
TLP_REFUSED = ("amber", "amber+strict", "red")
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def normalise_email(value: Any) -> str | None:
    """Trimmed lower-case address, or None for anything that is not a plain address."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not _EMAIL.match(v) or ".." in v or len(v) > 254:
        return None
    return v.lower()


def emailrep_url(email: Any) -> str:
    """The only request this module builds (cond 2): ``https://emailrep.io/<address>``. ValueError for
    anything that is not a plain address (no path or query injection)."""
    addr = normalise_email(email)
    if addr is None:
        raise ValueError("emailrep: not an e-mail address")
    return API.format(email=quote(addr, safe="@+"))


def emailrep_headers(key: Any) -> dict[str, str]:
    """Request headers (cond 3): ``Key`` and ``Accept: application/json``; never a User-Agent (the
    provider profile chooses it). ValueError without a key (NEEDS_KEY before any request)."""
    if not isinstance(key, str) or not key.strip():
        raise ValueError("emailrep key not configured")
    return {"Key": key.strip(), "Accept": "application/json"}


def _date(value: Any) -> str | None:
    """EmailRep dates 'MM/DD/YYYY' (or ISO) -> 'YYYY-MM-DD'; 'never', empty or invalid -> None."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\s*(\d{1,2})/(\d{1,2})/(\d{4})\s*", value)
    if m:
        month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    else:
        m = re.fullmatch(r"\s*(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?", value)
        if not m:
            return None
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def parse_emailrep(data: Any, queried: str | None = None) -> dict[str, Any] | None:
    """Kept facts of an EmailRep answer (cond 4/5), or None when it is not an EmailRep result.

    Returns {reputation, suspicious, flags {kept flag: bool}, first_seen, last_seen, domain_age_days,
    dropped [field names], email_matches_query}. ``deliverable``, ``accept_all``, ``profiles`` and every
    other field are dropped: only their names reach ``dropped``.
    """
    if not isinstance(data, dict) or "reputation" not in data:
        return None
    rep = data.get("reputation")
    reputation = rep.strip().lower() if isinstance(rep, str) and rep.strip().lower() in REPUTATIONS else None
    suspicious = data.get("suspicious") if isinstance(data.get("suspicious"), bool) else None
    details = data.get("details") if isinstance(data.get("details"), dict) else {}
    flags = {name: details[field] for field, name in KEPT_FLAGS.items() if isinstance(details.get(field), bool)}
    age = details.get("days_since_domain_creation")
    domain_age = age if isinstance(age, int) and not isinstance(age, bool) and 0 <= age < 100_000 else None
    known = {"reputation", "suspicious", "details", "email"}
    kept_details = set(KEPT_FLAGS) | {"first_seen", "last_seen", "days_since_domain_creation"}
    dropped = sorted({str(k) for k in data if k not in known} | {str(k) for k in details if k not in kept_details})
    echoed = normalise_email(data.get("email"))
    wanted = normalise_email(queried)
    return {
        "reputation": reputation,
        "suspicious": suspicious,
        "flags": flags,
        "first_seen": _date(details.get("first_seen")),
        "last_seen": _date(details.get("last_seen")),
        "domain_age_days": domain_age,
        "dropped": dropped,
        "email_matches_query": (echoed == wanted) if (echoed and wanted) else None,
    }


@register
class EmailRep(Module):
    name = "emailrep"
    title = "EmailRep.io address reputation"
    description = (
        "Reputation of an analyst-typed e-mail address from EmailRep.io (keyed): reputation, suspicious and blacklist "
        "flags, malicious-activity and credential-leak/breach flags (metadata), first/last seen, spoofability and domain age."
    )
    category = "email"
    accepts = {T.EMAIL}
    produces = frozenset()
    run_on = "seeds"
    tags = {"reputation"}
    reference = "https://emailrep.io/docs/"
    notice = (
        "Terms unknown (2026-11-26): disabled in every profile until legal records the EmailRep terms. EmailRep receives "
        "the full address and may reuse it: analyst-typed seeds only, never at TLP:AMBER or above; the recipient goes in "
        "the ROPA. Deliverability, accept-all and profile fields are dropped at ingestion."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "emailrep"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 1
    expected_latency = 1.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 0  # cond 4: the raw answer (profiles, deliverability) is never written to the HTTP cache
    max_pivots = 0
    default_enabled = False  # cond 1 (unknown terms, A3)
    error_markers = (
        {"id": "emailrep_fail_body", "statuses": [200], "json_path": "status", "equals": "fail", "maps_to": "error",
         "reason_code": "error", "reason": "EmailRep: error object (status 'fail') inside an HTTP 200 answer"},
        {"id": "emailrep_html_page", "statuses": [200], "regex": "Javascript is required to query EmailRep|<title>Simple Email Reputation",
         "maps_to": "error", "reason_code": "error",
         "reason": "EmailRep served its HTML site instead of JSON (Accept: application/json missing): could not verify"},
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return normalise_email(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        # defence in depth next to the policy gate (cond 2): typed seeds only, never at TLP:AMBER and above
        if not getattr(ctx, "is_seed", False) or int(getattr(ctx, "depth", 0) or 0) != 0:
            return res.mark(Status.SKIPPED, "EmailRep receives the full address: analyst-typed seed addresses only (never pivots)",
                            reason_code="privacy")
        tlp = str(getattr(ctx, "tlp", "") or "amber").strip().lower()
        if tlp in TLP_REFUSED:
            return res.mark(Status.SKIPPED, f"EmailRep may reuse submitted addresses: skipped at TLP:{tlp.upper()} (allowed at CLEAR/GREEN only)",
                            reason_code="tlp")
        try:
            headers = emailrep_headers(ctx.key(KEY_NAME))
        except ValueError:
            return res.mark(Status.NEEDS_KEY, "EmailRep needs the key 'emailrep' (V3LUM_EMAILREP_KEY): the anonymous API is disabled",
                            reason_code="needs_key")
        url = emailrep_url(entity.value)
        data = ctx.http.get_json(url, headers=headers, source=SOURCE, ttl=0)
        parsed = parse_emailrep(data, entity.value)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected EmailRep answer (no reputation object): could not verify")
        if parsed["email_matches_query"] is False:
            return res.mark(Status.ERROR, "EmailRep answered for another address: could not verify")
        # raw evidence = the kept facts only (cond 4: the dropped fields are named, never stored)
        res.raw = {k: parsed[k] for k in ("reputation", "suspicious", "flags", "first_seen", "last_seen", "domain_age_days")}
        res.raw["dropped_fields"] = parsed["dropped"]
        self._record(res, parsed)
        return res

    @staticmethod
    def _record(res: ModuleResult, parsed: dict[str, Any]) -> None:
        flags = parsed["flags"]
        if parsed["reputation"]:
            res.attr("reputation", {"emailrep": parsed["reputation"]})
        if parsed["suspicious"] is not None:
            res.attr("suspicious", parsed["suspicious"])
        res.attr("emailrep_flags", dict(flags))
        res.attr("first_seen", parsed["first_seen"])
        res.attr("last_seen", parsed["last_seen"])
        res.attr("domain_age_days", parsed["domain_age_days"])
        bits = [f"reputation {parsed['reputation'] or 'unknown'}"]
        for name in ("blacklisted", "malicious_activity", "leak_reported", "data_breach", "spoofable"):
            if flags.get(name):
                bits.append(name.replace("_", " "))
        if parsed["first_seen"]:
            bits.append(f"first seen {parsed['first_seen']}")
        summary = "; ".join(bits)
        if parsed["suspicious"] or flags.get("blacklisted") or flags.get("malicious_activity"):
            res.finding(
                "Address flagged by EmailRep",
                "medium" if (flags.get("blacklisted") or flags.get("malicious_activity")) else "low",
                f"EmailRep: {summary}. One reputation source: confirm with the message evidence before acting.",
                confidence="possible",
                criterion="EmailRep 'suspicious' or details.blacklisted / details.malicious_activity is true",
                data={"reputation": parsed["reputation"], "suspicious": parsed["suspicious"], **{k: flags.get(k) for k in ("blacklisted", "malicious_activity", "malicious_activity_recent")}},
                tags=["suspicious"],
                source=SOURCE,
                observed_last=parsed["last_seen"],
            )
        if flags.get("leak_reported") or flags.get("data_breach"):
            res.finding(
                "EmailRep reports the address in breach or credential-leak data",
                "info",
                "EmailRep flags the address in data-breach or credential-leak sources (metadata only: no breach names, "
                "dates or credentials are returned or kept). Third-party context, never an exposure score.",
                confidence="possible",
                criterion="EmailRep details.credentials_leaked or details.data_breach is true",
                data={"leak_reported": flags.get("leak_reported"), "leak_reported_recent": flags.get("leak_reported_recent"),
                      "data_breach": flags.get("data_breach")},
                tags=["breach", "context_only"],
                source=SOURCE,
            )
        if flags.get("spoofable") is True and (flags.get("dmarc_enforced") is False or flags.get("spf_strict") is False):
            res.finding(
                "Sender domain spoofable according to EmailRep",
                "low",
                "EmailRep reports the address's domain as spoofable (SPF not strict and/or DMARC not enforced): messages "
                "claiming this sender can be forged. Confirm with the domain's own SPF/DMARC records.",
                confidence="possible",
                criterion="EmailRep details.spoofable true with spf_strict or dmarc_enforced false",
                data={k: flags.get(k) for k in ("spoofable", "spf_strict", "dmarc_enforced")},
                tags=["weak_email_security"],
                source=SOURCE,
            )
        res.finding(
            "EmailRep reputation",
            "info",
            f"EmailRep: {summary}.",
            confidence="probable",
            criterion="EmailRep answered with a reputation object for the address",
            data={"reputation": parsed["reputation"], "first_seen": parsed["first_seen"], "last_seen": parsed["last_seen"],
                  "domain_age_days": parsed["domain_age_days"]},
            source=SOURCE,
            observed_first=parsed["first_seen"],
            observed_last=parsed["last_seen"],
        )
