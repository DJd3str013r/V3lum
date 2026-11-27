"""Correlation pack: e-mail spoofing posture (P027: CR01-CR03).

Inputs are only vocab attributes produced by ``email_security_posture``/``dns_records`` (cond 3):
``spf``, ``spf_status``, ``spf_lookups``, ``spf_void_lookups``, ``dmarc``, ``dmarc_policy``,
``dmarc_pct``, ``dmarc_sp``, ``dmarc_rua_external``, ``mx`` and the posture summary
``email_posture``. The producers write them only from NOERROR/NXDOMAIN answers; SERVFAIL, REFUSED,
timeouts or an unevaluated SPF chain leave them unset or say 'could not verify' - and then these
rules do not fire (cond 6, rule 5): 'SPF/DMARC missing' is never reported on missing data. No rule
makes a network call (the SPF evaluation itself is bounded in the producing module, cond 5).

* CR01 ``spoofable_email_domain`` (cond 1, 4, 7, 8): weak DMARC (none, p=none, pct<100; p=quarantine
  with pct=100 enforces) AND weak SPF (missing, ~all, ?all, +all, permerror). DMARC of a subdomain
  is the producing module's discovery (_dmarc.<name>, then the organisational domain with its sp=
  tag): an org with p=reject and a subdomain without a record is not spoofable. An organisational
  record whose sp=none leaves every (even non-existent) subdomain spoofable: CR01 on that domain.
  HIGH only for analyst-typed seeds, verified org-profile domains and the sending domain of the
  phishing case under triage; other domains LOW, omitted at depth >= 2; non-sending domains (null
  MX, no MX) MEDIUM with the specific advice; never on entities tagged malicious/phishing.
* CR02 ``spf_lookup_limit`` (cond 2): MEDIUM above 10 DNS-mechanism lookups or 2 void lookups (RFC
  7208 permerror), LOW at exactly 10.
* CR03 ``dmarc_reports_external_unauthorized`` (cond 2): LOW (INFO in the terminal) when a rua/ruf
  destination outside the policy domain lacks its ``<domain>._report._dmarc.<dest>`` record; a
  failed lookup is 'could not verify'.

Every correlation shows the record observed, the record to publish and its criterion, and carries
T1566 and T1684.001 (cond 9). Thresholds are the named constants below.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from v3lum.core import psl
from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, ModuleResult, Severity
from v3lum.correlations.threat_intel import edges_in, hostile, org_of, own_asset

# ----------------------------------------------------------------------------------------
# Thresholds (P027) - one block, named constants only
# ----------------------------------------------------------------------------------------

#: RFC 7208 4.6.4: DNS-mechanism lookups and void lookups an SPF evaluation may need.
SPF_MAX_LOOKUPS = 10
SPF_MAX_VOID_LOOKUPS = 2
#: DMARC pct= below this is partial enforcement (p=quarantine with pct=100 enforces).
DMARC_FULL_PCT = 100
#: DMARC policies that enforce.
ENFORCING_POLICIES = frozenset({"quarantine", "reject"})
#: SPF 'all' qualifiers that let spoofed mail through (softfail, neutral, pass).
WEAK_ALL = frozenset({"~all", "?all", "+all"})
#: Depth from which pivot/third-party domains are omitted (cond 7).
OMIT_DEPTH = 2
#: Severities (cond 1, 2, 7, 8).
SUBJECT_SEVERITY = Severity.HIGH
NON_SENDING_SEVERITY = Severity.MEDIUM
PIVOT_SEVERITY = Severity.LOW
LOOKUP_OVER_SEVERITY = Severity.MEDIUM
LOOKUP_AT_LIMIT_SEVERITY = Severity.LOW
REPORT_AUTH_SEVERITY = Severity.LOW
#: Entity tags that make a domain an attacker's (cond 7: never the subject of a posture finding).
ATTACKER_TAGS = frozenset({"malicious", "phishing"})
#: ATT&CK ids on every finding of the pack (cond 9).
SPOOFING_ATTACK = ("T1566", "T1684.001")
#: Advice for domains without mail service (cond 8, verbatim).
NON_SENDING_ADVICE = "no mail service: publish v=spf1 -all, a null MX and DMARC p=reject"
#: SPF states that are 'could not verify' (cond 6, rule 5): an unevaluated include chain
#: (temperror) or a failed TXT lookup never feeds CR01, even when the top record is readable.
UNVERIFIED_SPF_STATUSES = frozenset({"temperror", "could_not_verify"})
UNVERIFIED_SPF_POSTURES = ("present; include chain could not be verified", "could not verify")
#: Severity a terminal renderer shows per rule when it differs from the stored one (cond 2: CR03 is
#: LOW in HTML/MD and INFO in the terminal). Read by the UI; the correlation itself stays LOW.
TERMINAL_SEVERITY: dict[str, Severity] = {"dmarc_reports_external_unauthorized": Severity.INFO}
#: The reference module's finding for a name without A/AAAA/CNAME (verified NOERROR answers, cond 8).
NO_ADDRESS_MODULE = "dns_records"
NO_ADDRESS_TITLE = "No web-facing address"

CR01 = "spoofable_email_domain"
CR02 = "spf_lookup_limit"
CR03 = "dmarc_reports_external_unauthorized"

_REFS = ("https://www.rfc-editor.org/rfc/rfc7489", "https://www.rfc-editor.org/rfc/rfc7208", "https://www.rfc-editor.org/rfc/rfc7505")
_ALL_RE = re.compile(r"(?:^|\s)([+~?-]?)all(?:\s|$)", re.I)
_POSTURE_ALL_RE = re.compile(r"\(([+~?-]?all)\)", re.I)


def _fixtures(rule_id: str, *names: str) -> tuple[str, ...]:
    """Graph-fixture paths of a rule (tests/fixtures/rules/<rule_id>/<name>.json)."""
    return tuple(f"tests/fixtures/rules/{rule_id}/{name}.json" for name in names)


# ----------------------------------------------------------------------------------------
# Facts (verified answers only)
# ----------------------------------------------------------------------------------------


def _posture(node: Node) -> dict[str, Any]:
    """The ``email_posture`` summary table (first dict value), {} when absent."""
    for value in node.attr_values("email_posture"):
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _ints(values: Iterable[Any]) -> list[int]:
    out = []
    for v in values:
        if isinstance(v, bool):
            continue
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


@dataclass(frozen=True)
class Spf:
    """SPF state of a name from verified answers. ``known`` False = could not verify (never fires)."""

    known: bool
    record: str = ""
    missing: bool = False
    permerror: bool = False
    qualifier: str = ""  # effective 'all' ('-all', '~all', '?all', '+all') or '' when undetermined
    lookups: int | None = None
    void: int | None = None
    status: str = ""

    @property
    def weak(self) -> bool:
        return self.known and (self.missing or self.permerror or self.qualifier in WEAK_ALL)

    def describe(self) -> str:
        if self.missing:
            return "no SPF record (verified)"
        if self.permerror:
            return "SPF permerror" + (f" ({self.lookups} lookups, {self.void} void)" if self.lookups is not None else "")
        return f"SPF {self.qualifier or 'without an all mechanism'}"


def spf_state(node: Node) -> Spf:
    """SPF of ``node`` from ``spf``/``spf_status``/``spf_lookups``/``spf_void_lookups``/``email_posture``."""
    statuses = {str(v).strip().lower() for v in node.attr_values("spf_status")}
    posture = str(_posture(node).get("spf") or "").strip().lower()
    record = next((str(v).strip() for v in node.attr_values("spf") if isinstance(v, str) and v.strip().lower().startswith("v=spf1")), "")
    lookups = max(_ints(node.attr_values("spf_lookups")), default=None)
    void = max(_ints(node.attr_values("spf_void_lookups")), default=None)
    status = next((s for s in ("none", "permerror", "ok", "temperror", "could_not_verify") if s in statuses), "")
    if not record and (status == "none" or posture.startswith("absent")):
        return Spf(True, missing=True, status="none")
    over = (lookups is not None and lookups > SPF_MAX_LOOKUPS) or (void is not None and void > SPF_MAX_VOID_LOOKUPS)
    if status == "permerror" or posture.startswith("permerror") or over:
        # a lookup count above the limit is a lower bound already past it: permerror whatever the rest
        return Spf(True, record=record, permerror=True, lookups=lookups, void=void, status="permerror")
    if status in UNVERIFIED_SPF_STATUSES or posture.startswith(UNVERIFIED_SPF_POSTURES):
        # rule 5 (cond 6): an unevaluated include chain or a failed TXT lookup is 'could not verify'
        return Spf(False, record=record, lookups=lookups, void=void, status=status or "could_not_verify")
    if not record:
        return Spf(False, status=status or "unknown")  # nothing verified: could not verify
    qualifier = ""
    m = _POSTURE_ALL_RE.search(posture)
    if m:
        qualifier = m.group(1).lower()
    else:
        found = _ALL_RE.findall(record)
        if found:
            qualifier = (found[-1] or "+") + "all"
        elif "redirect=" not in record.lower():
            qualifier = "?all"  # RFC 7208 4.7: no 'all' and no redirect = neutral
    if qualifier == "all":
        qualifier = "+all"
    return Spf(bool(qualifier), record=record, qualifier=qualifier, lookups=lookups, void=void, status=status or "ok")


@dataclass(frozen=True)
class Dmarc:
    """DMARC applying to a name. ``known`` False = could not verify (never fires)."""

    known: bool
    record: str = ""
    policy: str = ""  # applied policy (p= or the organisational sp=)
    pct: int = DMARC_FULL_PCT
    sp: str = ""
    missing: bool = False
    invalid: bool = False
    inherited_from: str = ""  # organisational domain whose record (and sp=) applies (cond 4)

    @property
    def weak(self) -> bool:
        if not self.known:
            return False
        if self.missing or self.invalid:
            return True
        return self.policy not in ENFORCING_POLICIES or self.pct < DMARC_FULL_PCT

    def describe(self) -> str:
        if self.missing:
            return "no DMARC record (verified)"
        if self.invalid:
            return "invalid DMARC record (ignored by receivers)"
        text = f"DMARC p={self.policy}"
        text += f" pct={self.pct}" if self.pct != DMARC_FULL_PCT else ""
        return text + (f" (organisational domain {self.inherited_from})" if self.inherited_from else "")


def _own_dmarc(node: Node) -> Dmarc:
    record = next((str(v).strip() for v in node.attr_values("dmarc") if isinstance(v, str)), "")
    policies = [str(v).strip().lower() for v in node.attr_values("dmarc_policy") if isinstance(v, str) and v.strip()]
    pct = min(_ints(node.attr_values("dmarc_pct")), default=DMARC_FULL_PCT)
    sp = next((str(v).strip().lower() for v in node.attr_values("dmarc_sp") if isinstance(v, str) and v.strip()), "")
    if policies:
        return Dmarc(True, record=record, policy=policies[0], pct=pct, sp=sp)
    posture = str(_posture(node).get("dmarc") or "").strip().lower()
    if posture.startswith("absent"):
        return Dmarc(True, missing=True)
    if posture.startswith("invalid"):
        return Dmarc(True, record=record, invalid=True)
    return Dmarc(False)


def dmarc_state(node: Node, graph: Graph | None = None) -> Dmarc:
    """DMARC applying to ``node``: ``dmarc_policy`` is already the applied policy (the producer's
    discovery: _dmarc.<name>, then the organisational domain with its sp= tag, cond 4).

    With ``graph``, a subdomain whose own answer is a verified absence also inherits the record of
    its organisational domain (PSL) when that node is in the graph: the org's sp= (default p=)
    applies, so an org with p=reject protects a subdomain without a record whatever the producer."""
    state = _own_dmarc(node)
    if not state.missing or graph is None:
        return state
    name = str(node.entity.value)
    try:
        org = psl.registrable_domain(name) or ""
    except Exception:  # noqa: BLE001 - a malformed name has no organisational domain
        org = ""
    parent_node = graph.nodes.get(f"domain:{org}") if org and org != name else None
    if parent_node is None:
        return state
    parent = _own_dmarc(parent_node)
    if not parent.known or parent.missing or parent.invalid or not parent.policy:
        return state
    return Dmarc(True, record=parent.record, policy=parent.sp or parent.policy, pct=parent.pct, sp=parent.sp, inherited_from=org)


def mail_service(node: Node) -> str:
    """'' for a mail domain (or unknown), else why the domain sends no mail (cond 8): a null MX,
    a verified empty MX answer, or no A/AAAA/CNAME (dns_records, NOERROR answers) and no MX host."""
    mx_values = [str(v).strip() for v in node.attr_values("mx") if isinstance(v, str)]
    posture_mx = str(_posture(node).get("mx") or "").strip().lower()
    if mx_values and all(v in (".", "") for v in mx_values):
        return "null MX ('0 .')"
    if posture_mx.startswith("null mx"):
        return "null MX ('0 .')"
    if posture_mx.startswith("none"):
        return "no MX record (verified)"
    if posture_mx.startswith("nxdomain") or any(v is False for v in node.attr_values("valid")):
        return "the name does not exist (NXDOMAIN: no MX and no A record)"
    no_address = any(f.module == NO_ADDRESS_MODULE and f.title.startswith(NO_ADDRESS_TITLE) for f in node.findings)
    if no_address and not [v for v in mx_values if v not in (".", "")] and not posture_mx:
        return "no A/AAAA record and no MX host (verified NOERROR answers)"
    return ""


# ----------------------------------------------------------------------------------------
# Ownership scoping (cond 7)
# ----------------------------------------------------------------------------------------


def _sending_domain(graph: Graph, node: Node) -> bool:
    """The sender domain of the phishing case under triage: reached from an analysed e-mail seed
    (``sender_domain``) or the domain of an analyst-typed e-mail address (``email_domain``)."""
    for edge in edges_in(graph, node.key, "sender_domain"):
        src = graph.nodes.get(edge.src)
        if src is not None and src.seed:
            return True
    for edge in edges_in(graph, node.key, "email_domain"):
        src = graph.nodes.get(edge.src)
        if src is not None and src.seed and src.entity.type is EntityType.EMAIL:
            return True
    return False


def subject_reason(graph: Graph, node: Node, rctx: Any) -> str:
    """Why the domain is a subject of the investigation ('' for a pivot/third-party domain)."""
    unconfirmed = set(getattr(getattr(rctx, "options", None), "unconfirmed_seeds", ()) or ())
    if node.seed and node.key not in unconfirmed:
        return "analyst-typed input"
    org = org_of(rctx)
    verified = getattr(org, "is_verified_domain", None)
    if callable(verified):
        try:
            if verified(str(node.entity.value)):
                return "verified org-profile domain"
        except Exception:  # noqa: BLE001 - a profile problem never makes a domain verified
            pass
    if _sending_domain(graph, node):
        return "sending domain of the phishing case under triage"
    return ""


def _skip(node: Node, rctx: Any = None) -> bool:
    """Not a mail domain we judge: not a domain, noise, or an attacker's domain (cond 7). An
    org-profile domain is never an attacker's domain, even when a feed tags it (compromise or FP)."""
    if node.entity.type is not EntityType.DOMAIN or node.noise:
        return True
    return hostile(node, ATTACKER_TAGS) and not own_asset(node, rctx)


# ----------------------------------------------------------------------------------------
# CR01 spoofable_email_domain
# ----------------------------------------------------------------------------------------


def _publish_spf(spf: Spf, non_sending: bool) -> str:
    if non_sending:
        return "v=spf1 -all"
    if spf.record and spf.qualifier in WEAK_ALL:
        return re.sub(r"(?:^|\s)[+~?]?all(?=\s|$)", " -all", spf.record).strip()
    if spf.record and spf.permerror:
        return "an SPF record within 10 DNS lookups and 2 void lookups (flatten or drop include: mechanisms), ending in -all"
    return "v=spf1 <the senders you use> -all"


def _publish_dmarc(non_sending: bool, *, subdomains: bool = False) -> str:
    if non_sending:
        return "v=DMARC1; p=reject"
    if subdomains:
        return "the organisational record without sp=none (e.g. v=DMARC1; p=reject; sp=reject)"
    return "v=DMARC1; p=quarantine; pct=100 (then p=reject once the aggregate reports are clean)"


def _severity(subject: str, non_sending: bool) -> Severity:
    if not subject:
        return PIVOT_SEVERITY
    return NON_SENDING_SEVERITY if non_sending else SUBJECT_SEVERITY


@rule(
    CR01,
    "E-mail domain can be spoofed (weak DMARC and weak SPF)",
    "CR01 (P027 cond 1, 4, 6-9): no DMARC, p=none or pct<100 (p=quarantine with pct=100 enforces) AND SPF missing, "
    "~all, ?all, +all or permerror, from verified DNS answers only. HIGH for analyst-typed seeds, verified org-profile "
    "domains and the sending domain of the phishing case; LOW for pivots (omitted at depth >= 2); MEDIUM with the "
    "no-mail advice for non-sending domains; never on malicious/phishing-tagged domains.",
    version="1",
    code="CR01",
    severity="high",
    criterion="weak DMARC (none/p=none/pct<100) and weak SPF (missing/~all/?all/+all/permerror), verified DNS answers only",
    references=_REFS,
    attack=SPOOFING_ATTACK,
    false_positives="Receivers with local anti-spoofing policies may still block spoofed mail; DKIM alignment is not "
    "evaluated from DNS alone. Could-not-verify answers never fire.",
    fixtures=_fixtures(
        CR01, "positive_p_none_softfail_on_seed_high", "positive_p_none_softfail_on_pivot_low", "positive_missing_records",
        "positive_org_sp_none", "positive_null_mx_non_sending", "negative_doh_servfail_timeout", "negative_quarantine_pct_100",
        "negative_org_reject_subdomain_without_record", "negative_attacker_and_deep_pivot",
    ),
)
def spoofable_email_domain(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if _skip(node, rctx):
            continue
        subject = subject_reason(graph, node, rctx)
        if not subject and node.depth >= OMIT_DEPTH:
            continue
        spf, dmarc = spf_state(node), dmarc_state(node, graph)
        if not (spf.known and dmarc.known):
            continue  # rule 5: a could-not-verify answer never reads 'missing'
        no_mail = mail_service(node)
        non_sending = bool(no_mail)
        observed_spf = spf.record or "none (verified NOERROR/NXDOMAIN answer)"
        observed_dmarc = dmarc.record or ("none (verified at _dmarc and the organisational domain)" if dmarc.missing else "")
        if spf.weak and dmarc.weak:
            severity = _severity(subject, non_sending)
            yield Correlation(
                rule=CR01,
                title=f"{node.entity.display} can be spoofed in e-mail ({dmarc.describe()}, {spf.describe()})",
                severity=severity,
                description=(
                    f"Receivers get no enforcing DMARC policy ({dmarc.describe()}) and SPF does not reject unauthorised senders "
                    f"({spf.describe()}): mail forging {node.entity.display} in the From header is delivered."
                    + (f" The domain sends no mail ({no_mail}): {NON_SENDING_ADVICE}." if non_sending else "")
                    + ("" if subject else " Pivot/third-party domain: context for the investigation.")
                ),
                entities=[node.entity],
                confidence=Confidence.CONFIRMED,
                evidence=[
                    f"observed SPF: {observed_spf}", f"observed DMARC: {observed_dmarc}",
                    f"publish SPF: {_publish_spf(spf, non_sending)}", f"publish DMARC: {_publish_dmarc(non_sending)}",
                ] + ([f"publish MX: 0 . (null MX, RFC 7505) - {no_mail}"] if non_sending else []) + [f"scope: {subject or 'pivot/third-party domain'}"],
                recommendation=NON_SENDING_ADVICE if non_sending else (
                    "Publish DMARC p=quarantine (pct=100) and move to p=reject once aggregate reports are clean; end SPF with -all."
                ),
                tags=["weak_email_security"],
                criterion=f"{dmarc.describe()} and {spf.describe()} (verified answers)",
                key="name",
            )
        if dmarc.known and not dmarc.weak and dmarc.sp == "none" and node.entity.value == psl.registrable_domain(str(node.entity.value)):
            # sp=none on the organisational record: every subdomain, even a non-existent one (no SPF), is spoofable
            severity = _severity(subject, False)
            yield Correlation(
                rule=CR01,
                title=f"Subdomains of {node.entity.display} can be spoofed (DMARC sp=none)",
                severity=severity,
                description=(
                    f"The organisational DMARC record enforces p={dmarc.policy} for {node.entity.display} but sp=none for its "
                    "subdomains: mail forging any subdomain - even one that does not exist and so has no SPF record - is delivered."
                ),
                entities=[node.entity],
                confidence=Confidence.CONFIRMED,
                evidence=[f"observed DMARC: {dmarc.record or 'sp=none'}", f"observed SPF: {observed_spf}",
                          f"publish DMARC: {_publish_dmarc(False, subdomains=True)}", f"scope: {subject or 'pivot/third-party domain'}"],
                recommendation="Remove sp=none (subdomains then inherit p=) or set sp=reject; give sending subdomains their own SPF/DMARC.",
                tags=["weak_email_security"],
                criterion="organisational DMARC sp=none: subdomains (also non-existent ones, which have no SPF) are not protected",
                key="subdomains",
            )


# ----------------------------------------------------------------------------------------
# CR02 spf_lookup_limit
# ----------------------------------------------------------------------------------------


@rule(
    CR02,
    "SPF needs too many DNS lookups (RFC 7208 limit)",
    "CR02 (P027 cond 2): MEDIUM when the SPF evaluation needs > 10 DNS-mechanism lookups or > 2 void lookups (RFC 7208 "
    "permerror: receivers may treat the record as broken), LOW at exactly 10.",
    version="1",
    code="CR02",
    severity="medium",
    criterion="spf_lookups > 10 or spf_void_lookups > 2 (bounded evaluation through the core DoH resolver); == 10 is LOW",
    references=_REFS,
    attack=SPOOFING_ATTACK,
    false_positives="Lookup counts can change when an included provider changes its own record.",
    fixtures=_fixtures(CR02, "positive_over_ten_lookups", "positive_exactly_ten_is_low", "negative_within_limit_or_unverified"),
)
def spf_lookup_limit(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if _skip(node, rctx):
            continue
        subject = subject_reason(graph, node, rctx)
        if not subject and node.depth >= OMIT_DEPTH:
            continue
        statuses = {str(v).strip().lower() for v in node.attr_values("spf_status")}
        lookups = max(_ints(node.attr_values("spf_lookups")), default=None)
        void = max(_ints(node.attr_values("spf_void_lookups")), default=None)
        if lookups is None and void is None:
            continue
        over = (lookups or 0) > SPF_MAX_LOOKUPS or (void or 0) > SPF_MAX_VOID_LOOKUPS
        if "could_not_verify" in statuses and not over:
            continue
        if "temperror" in statuses and not over:
            continue  # an unevaluated include chain: the count is a lower bound (rule 5)
        if over:
            severity = LOOKUP_OVER_SEVERITY
        elif lookups == SPF_MAX_LOOKUPS:
            severity = LOOKUP_AT_LIMIT_SEVERITY
        else:
            continue
        if not subject:
            severity = min(severity, PIVOT_SEVERITY)
        record = next((str(v) for v in node.attr_values("spf") if isinstance(v, str)), "")
        yield Correlation(
            rule=CR02,
            title=f"{node.entity.display}: SPF needs {lookups if lookups is not None else '?'} DNS lookups ({void if void is not None else '?'} void)",
            severity=severity,
            description=(
                f"RFC 7208 allows {SPF_MAX_LOOKUPS} DNS-mechanism lookups and {SPF_MAX_VOID_LOOKUPS} void lookups per SPF evaluation. "
                + ("Above the limit receivers return permerror: SPF stops protecting the domain." if over else
                   "The record is exactly at the limit: one more include breaks it.")
            ),
            entities=[node.entity],
            confidence=Confidence.CONFIRMED,
            evidence=[f"observed SPF: {record or '(record text not recorded)'}", f"lookups {lookups}, void lookups {void}",
                      "publish SPF: flatten or drop include:/a/mx/ptr/exists mechanisms to stay within 10 lookups and 2 void lookups",
                      f"scope: {subject or 'pivot/third-party domain'}"],
            recommendation="Remove unused include: mechanisms, replace a/mx by ip4/ip6 where stable, or use subdomains per sender.",
            tags=["weak_email_security", "misconfiguration"],
            criterion=f"spf_lookups={lookups} (limit {SPF_MAX_LOOKUPS}), spf_void_lookups={void} (limit {SPF_MAX_VOID_LOOKUPS})",
        )


# ----------------------------------------------------------------------------------------
# CR03 dmarc_reports_external_unauthorized
# ----------------------------------------------------------------------------------------


@rule(
    CR03,
    "DMARC reports go to an external destination that did not authorise them",
    "CR03 (P027 cond 2): a rua/ruf destination outside the policy domain without its <domain>._report._dmarc.<dest> "
    "authorization record (RFC 7489 7.1): receivers drop those reports. LOW in HTML/MD, INFO in the terminal; a failed "
    "lookup is 'could not verify' and never fires.",
    version="1",
    code="CR03",
    severity="low",
    criterion="dmarc_rua_external entry with authorized=false (NXDOMAIN or no v=DMARC1 TXT at the authorization name)",
    references=_REFS,
    attack=SPOOFING_ATTACK,
    false_positives="Report processors publish wildcard authorization records; a recent change may not be visible yet.",
    fixtures=_fixtures(CR03, "positive_unauthorized_destination", "negative_authorized_or_unverified"),
)
def dmarc_reports_external_unauthorized(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if _skip(node, rctx):
            continue
        subject = subject_reason(graph, node, rctx)
        if not subject and node.depth >= OMIT_DEPTH:
            continue
        unauthorized: list[str] = []
        unverified: list[str] = []
        for value in node.attr_values("dmarc_rua_external"):
            if not isinstance(value, Mapping):
                continue
            dest = str(value.get("dest_domain") or "").strip().lower()
            if not dest:
                continue
            if value.get("authorized") is False:
                unauthorized.append(dest)
            elif value.get("authorized") is None:
                unverified.append(dest)
        if not unauthorized:
            continue
        policy_domain = str(node.entity.value)
        severity = REPORT_AUTH_SEVERITY if subject else Severity.INFO
        dests = sorted(set(unauthorized))
        yield Correlation(
            rule=CR03,
            title=f"{node.entity.display}: DMARC reports to {', '.join(dests)} are not authorised",
            severity=severity,
            description=(
                f"The DMARC record sends reports to {', '.join(dests)}, outside {policy_domain}, but "
                f"{', '.join(f'{policy_domain}._report._dmarc.{d}' for d in dests)} has no v=DMARC1 record: receivers drop the "
                "reports, so spoofing attempts go unseen."
                + (f" Could not verify: {', '.join(sorted(set(unverified)))}." if unverified else "")
                + " Shown as INFO in the terminal."
            ),
            entities=[node.entity],
            confidence=Confidence.CONFIRMED,
            evidence=[f"observed DMARC: {next((str(v) for v in node.attr_values('dmarc') if isinstance(v, str)), '(record text not recorded)')}"]
            + [f"publish at the destination: {policy_domain}._report._dmarc.{d} TXT \"v=DMARC1\"" for d in dests]
            + [f"scope: {subject or 'pivot/third-party domain'}"],
            recommendation="Ask the report processor to publish the authorization record, or point rua/ruf to a mailbox of your own domain.",
            tags=["weak_email_security", "misconfiguration"],
            criterion="external rua/ruf destination without its RFC 7489 7.1 authorization record (verified NXDOMAIN/NOERROR)",
            why="terminal: INFO (P027 cond 2)",
        )
