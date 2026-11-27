"""dnsbl: DNSBL / RBL listings of an IP or a domain, with per-list terms, routes and return codes (P045).

Batch p2-G02-2, proposal P045 ``dnsbl``. Final conditions implemented here:

* c1 - per-list terms registry: every list is a registry source with its own terms entry
  (``spamcop.bl``, ``dronebl.dnsbl`` 'open'; ``spamhaus_dqs.zen`` / ``spamhaus_dqs.dbl`` key-terms on
  the plan recorded in ``key_plans.spamhaus_dqs``; ``projecthoneypot.httpbl`` key-terms;
  UCEPROTECT, Barracuda, SURBL, URIBL 'noncommercial') and :data:`LISTS` wires only lists whose
  source is registered. Public Spamhaus mirrors (zen/dbl.spamhaus.org) are never used.
* c2 - the noncommercial lists are off under the corporate profile until licence-cleared: the
  policy gate leaves them out of ``ctx.allowed_sources`` and the engine reports them 'licence'.
* c3 - keyed zones (Spamhaus DQS, http:BL) carry the key inside the query name: they go only
  through the system resolver (setting ``dns_mode=system``) with dnspython installed (else
  UNAVAILABLE 'package'), never through public DoH; the query name is never stored and every
  resolver message is redacted (:func:`redact_qname`; the core redactor also masks key values).
* c4 - lists that refuse public resolvers (Spamhaus without DQS, URIBL, SURBL, unregistered
  Barracuda) are not queried through DoH and appear as ONE coverage line ('needs DQS
  key/registration', attribute ``dnsbl_not_queried``). SpamCop, DroneBL and UCEPROTECT answer
  public resolvers and go through the core DoH layer (``ctx.dns``).
* c5 - bundled per-list return-code tables (:data:`LISTS`); refusal answers (Spamhaus
  127.255.255.252/254/255, URIBL/SURBL 127.0.0.1, any 127.255.255.x, NXDOMAIN from a public
  resolver for a list that refuses them) give BLOCKED 'could not verify' (P321), never 'listed' or
  'not listed'; codes outside the table or outside 127.0.0.0/8 are ERROR.
* c6 - a per-run test-point check per list (127.0.0.2 for IP zones, the documented test name for
  domain zones and 127.1.1.1 for http:BL; the IPv6 nibble test point ::ffff:7f00:2 for IPv6
  lookups): when it fails the list is could-not-verify for the run and the entity is not queried.
* c7 - only UCEPROTECT Level 1 counts; Levels 2/3 (whole allocations/ASNs), Spamhaus PBL,
  DroneBL's test class and http:BL search engines are info 'neighbourhood/policy listing', zero
  risk.
* c8 - ONE aggregated finding 'listed on k of n queried lists (names, return codes)': one counted
  listing = LOW, two or more = MEDIUM (never higher); tag 'spam', never 'malicious'; every DNSBL is
  ONE 'spam' family vote in P171 consensus (registry upstream_family 'dnsbl', attribute
  ``blocklist_families``).
* c9 - domain zones (DBL/SURBL/URIBL) for domains, IP zones for IPs; at most :data:`MAX_LISTS`
  lists per entity; http:BL scores are log-scaled (score bands) and its NXDOMAIN means not listed.

Rule 5: a list that did not answer (SERVFAIL, timeout, refusal, failed test point) is 'could not
verify' (``res.source_status``), never 'not listed'.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, package_available, register
from v3lum.core.noise import is_public_ip

DOH_SOURCE = "core_doh.resolvers"
MAX_LISTS = 10  # P045 c9: lookups per entity
FAMILY = "dnsbl"  # P045 c8: every DNSBL is ONE 'spam' family vote (P171)
REDACTED = "[redacted]"
COVERAGE_NEEDS = "not queried through public DoH (needs DQS key/registration)"
#: Spamhaus convention, honoured for every list: 127.255.255.x is a refusal, never a listing.
GENERIC_REFUSALS: dict[str, tuple[Status, str, str]] = {
    "127.255.255.252": (Status.ERROR, "error", "typing error in the DNSBL name"),
    "127.255.255.254": (Status.BLOCKED, "challenge", "query through a public/open resolver refused"),
    "127.255.255.255": (Status.RATE_LIMITED, "rate_limited", "excessive number of queries refused"),
}
REFUSAL_PREFIX = "127.255.255."
LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
HTTPBL_SEARCH_ENGINES = {
    0: "undocumented", 1: "AltaVista", 2: "Ask", 3: "Baidu", 4: "Excite", 5: "Google", 6: "Looksmart", 7: "Lycos",
    8: "MSN", 9: "Yahoo", 10: "Cuil", 11: "InfoSeek", 12: "miscellaneous",
}
HTTPBL_TYPES = ((1, "suspicious"), (2, "harvester"), (4, "comment_spammer"))
_KEY_RES = {"spamhaus_dqs": re.compile(r"^[a-z0-9]{8,64}$"), "httpbl": re.compile(r"^[a-z]{12}$")}
_DQS_RE = re.compile(r"\.([a-z0-9]{8,64})\.((?:zen|dbl)\.dq\.spamhaus\.net)", re.I)
_HTTPBL_RE = re.compile(r"(?<![a-z0-9])([a-z]{12})\.((?:\d{1,3}\.){4}dnsbl\.httpbl\.org)", re.I)


@dataclass(frozen=True)
class DnsblList:
    """One wired list: its registry source, zone, route and bundled return-code table (P045 c1, c5).

    ``route``: 'doh' (answers public resolvers: the core DoH layer), 'refuses' (registered
    resolvers only: queried only when the registration is recorded in setting
    ``dnsbl_registered_lists`` and a non-public resolver exists) or 'keyed' (access key inside the
    query name: system resolver through dnspython only, P045 c3). ``codes``: answer -> (meaning,
    counts as evidence). ``bitmask``: bit -> (meaning, counts) for SURBL/URIBL-style answers.
    ``refusals``: answer -> (status, reason code, meaning), on top of :data:`GENERIC_REFUSALS`.
    """

    id: str
    name: str
    source: str
    zone: str
    kind: str  # 'ip' | 'domain'
    route: str  # 'doh' | 'refuses' | 'keyed'
    test_query: str
    test_expect: frozenset[str]
    codes: dict[str, tuple[str, bool]] = field(default_factory=dict)
    bitmask: dict[int, tuple[str, bool]] = field(default_factory=dict)
    refusals: dict[str, tuple[Status, str, str]] = field(default_factory=dict)
    ipv6: bool = False
    test_query_v6: str = ""
    key_name: str = ""
    needs: str = ""
    neighbourhood: bool = False
    txt_reason: bool = False


_SPAMHAUS_REFUSALS = {
    "127.0.1.255": (Status.ERROR, "error", "IP queries prohibited for this zone"),
}
_DRONEBL_CODES = {
    "127.0.0.1": ("testing class (test entry)", False),
    "127.0.0.2": ("sample data for heuristic analysis", True),
    "127.0.0.3": ("IRC spam drone", True),
    "127.0.0.5": ("bottler", True),
    "127.0.0.6": ("unknown spambot or drone", True),
    "127.0.0.7": ("DDoS drone", True),
    "127.0.0.8": ("open SOCKS proxy", True),
    "127.0.0.9": ("open HTTP proxy", True),
    "127.0.0.10": ("proxy chain", True),
    "127.0.0.11": ("web page proxy", True),
    "127.0.0.12": ("open DNS resolver", True),
    "127.0.0.13": ("brute-force attacker", True),
    "127.0.0.14": ("open Wingate proxy", True),
    "127.0.0.15": ("compromised router/gateway", True),
    "127.0.0.16": ("autorooting worm", True),
    "127.0.0.17": ("automatically determined botnet IP", True),
    "127.0.0.18": ("DNS/MX type hostname detected on IRC", True),
    "127.0.0.19": ("abused VPN service", True),
    "127.0.0.255": ("uncategorized threat class", True),
}

#: The wired lists (P045 c1): a list is wired only once its registry entry exists.
LISTS: tuple[DnsblList, ...] = (
    DnsblList(
        "spamcop", "SpamCop", "spamcop.bl", "bl.spamcop.net", "ip", "doh", "127.0.0.2", frozenset({"127.0.0.2"}),
        codes={"127.0.0.2": ("reported spam source", True)}, txt_reason=True,
    ),
    DnsblList(
        "dronebl", "DroneBL", "dronebl.dnsbl", "dnsbl.dronebl.org", "ip", "doh", "127.0.0.2",
        frozenset({"127.0.0.1", "127.0.0.2"}), codes=_DRONEBL_CODES, ipv6=True, test_query_v6="::ffff:7f00:2",
    ),
    DnsblList(
        "spamhaus_zen", "Spamhaus ZEN", "spamhaus_dqs.zen", "zen.dq.spamhaus.net", "ip", "keyed", "127.0.0.2",
        frozenset({"127.0.0.2", "127.0.0.4", "127.0.0.10"}),
        codes={
            "127.0.0.2": ("SBL: spam source or spam operation", True),
            "127.0.0.3": ("SBL CSS: snowshoe spam", True),
            "127.0.0.4": ("XBL: exploited or compromised host", True),
            "127.0.0.5": ("XBL (reserved)", True),
            "127.0.0.6": ("XBL (reserved)", True),
            "127.0.0.7": ("XBL (reserved)", True),
            "127.0.0.9": ("SBL DROP/EDROP: hijacked or criminal netblock", True),
            "127.0.0.10": ("PBL: ISP-maintained end-user range (policy listing, not abuse)", False),
            "127.0.0.11": ("PBL: Spamhaus-maintained end-user range (policy listing, not abuse)", False),
        },
        refusals=_SPAMHAUS_REFUSALS, ipv6=True, key_name="spamhaus_dqs", needs="DQS key",
    ),
    DnsblList(
        "spamhaus_dbl", "Spamhaus DBL", "spamhaus_dqs.dbl", "dbl.dq.spamhaus.net", "domain", "keyed", "dbltest.com",
        frozenset({"127.0.1.2"}),
        codes={
            "127.0.1.2": ("spam domain", True),
            "127.0.1.4": ("phishing domain", True),
            "127.0.1.5": ("malware domain", True),
            "127.0.1.6": ("botnet C&C domain", True),
            "127.0.1.102": ("abused legitimate domain: spam", True),
            "127.0.1.103": ("abused legitimate domain: spammed redirector", True),
            "127.0.1.104": ("abused legitimate domain: phishing", True),
            "127.0.1.105": ("abused legitimate domain: malware", True),
            "127.0.1.106": ("abused legitimate domain: botnet C&C", True),
        },
        refusals=_SPAMHAUS_REFUSALS, key_name="spamhaus_dqs", needs="DQS key",
    ),
    DnsblList(
        "uceprotect_l1", "UCEPROTECT L1", "uceprotect.level1", "dnsbl-1.uceprotect.net", "ip", "doh", "127.0.0.2",
        frozenset({"127.0.0.2"}), codes={"127.0.0.2": ("listed: single IP (Level 1)", True)},
    ),
    DnsblList(
        "uceprotect_l2", "UCEPROTECT L2", "uceprotect.level2", "dnsbl-2.uceprotect.net", "ip", "doh", "127.0.0.2",
        frozenset({"127.0.0.2"}), codes={"127.0.0.2": ("neighbourhood listing: whole allocation (Level 2)", False)},
        neighbourhood=True,
    ),
    DnsblList(
        "uceprotect_l3", "UCEPROTECT L3", "uceprotect.level3", "dnsbl-3.uceprotect.net", "ip", "doh", "127.0.0.2",
        frozenset({"127.0.0.2"}), codes={"127.0.0.2": ("neighbourhood listing: whole ASN (Level 3)", False)},
        neighbourhood=True,
    ),
    DnsblList(
        "barracuda", "Barracuda BRBL", "barracuda.brbl", "b.barracudacentral.org", "ip", "refuses", "127.0.0.2",
        frozenset({"127.0.0.2"}), codes={"127.0.0.2": ("poor sender reputation", True)}, needs="resolver registration",
    ),
    DnsblList(
        "surbl", "SURBL multi", "surbl.multi", "multi.surbl.org", "domain", "refuses", "test.surbl.org",
        frozenset({"127.0.0.254"}),
        bitmask={
            2: ("SC (retired list)", False), 4: ("WS (retired list)", False), 8: ("PH: phishing", True), 16: ("MW: malware", True),
            32: ("AB (retired list)", False), 64: ("ABUSE: spam/abuse", True), 128: ("CR: cracked site", True),
        },
        refusals={"127.0.0.1": (Status.BLOCKED, "challenge", "query refused (public resolver or query volume)")},
        needs="registration",
    ),
    DnsblList(
        "uribl", "URIBL multi", "uribl.multi", "multi.uribl.com", "domain", "refuses", "test.uribl.com",
        frozenset({"127.0.0.14"}),
        bitmask={2: ("black list", True), 4: ("grey list", False), 8: ("red list", True)},
        refusals={"127.0.0.1": (Status.BLOCKED, "challenge", "query refused (public resolver or query volume)")},
        needs="registration",
    ),
    DnsblList(
        "httpbl", "Project Honey Pot http:BL", "projecthoneypot.httpbl", "dnsbl.httpbl.org", "ip", "keyed", "127.1.1.1",
        frozenset({"127.1.1.1"}), key_name="httpbl", needs="access key",
    ),
)
LIST_BY_ID: dict[str, DnsblList] = {lst.id: lst for lst in LISTS}
SOURCES: tuple[str, ...] = (DOH_SOURCE, *(lst.source for lst in LISTS))


# --------------------------------------------------------------------------------------
# pure helpers (no network)
# --------------------------------------------------------------------------------------


def reverse_ip(value: str, *, unmap: bool = True) -> str | None:
    """DNSBL label of an IP: '1.2.3.4' -> '4.3.2.1'; IPv6 -> 32 reversed nibbles (P045 c6).

    ``unmap`` turns an IPv4-mapped IPv6 address into its IPv4 form; the RFC 5782 IPv6 test point
    ::ffff:7f00:2 keeps its nibble form (``unmap=False``). None for anything that is not an IP."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if unmap and ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return ".".join(reversed(str(ip).split(".")))
    return ip.reverse_pointer[: -len(".ip6.arpa")]


def query_label(lst: DnsblList, value: str, key: str = "", *, unmap: bool = True) -> str | None:
    """The label placed before the list's zone (P045 c3, c9): reversed IP or domain, with the access
    key where the layout needs it (DQS '<rev>.<key>', http:BL '<key>.<rev>'). Never log it: keyed
    labels carry the key (see :func:`redact_qname`)."""
    if lst.kind == "ip":
        label = reverse_ip(value, unmap=unmap)
        if label is None:
            return None
    else:
        label = str(value or "").strip().rstrip(".").lower()
        if not label or "." not in label:
            return None
    if lst.key_name == "spamhaus_dqs":
        return f"{label}.{key}"
    if lst.key_name == "httpbl":
        return f"{key}.{label}"
    return label


def redact_qname(text: str, key: str = "") -> str:
    """Mask an access key inside a query name or a resolver message (P045 c3, AR01): the given key
    value anywhere, and the key label of the DQS and http:BL layouts even when the value is unknown."""
    out = str(text or "")
    if key:
        out = re.sub(re.escape(key), REDACTED, out, flags=re.I)
    out = _DQS_RE.sub(lambda m: f".{REDACTED}.{m.group(2)}", out)
    return _HTTPBL_RE.sub(lambda m: f"{REDACTED}.{m.group(2)}", out)


def score_band(score: int) -> str:
    """http:BL threat scores are log-scaled (P045 c9): about 25 ~ 100 spam messages, 50 ~ 10,000,
    75 ~ 1,000,000 (API documentation). Bands instead of linear percentages."""
    if score <= 0:
        return "none"
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "very high"


@dataclass
class Outcome:
    """One list's answer for one name (P045 c5-c7). ``state``: listed | not_listed | refused | error |
    test_point_failed; ``status``/``code`` are the could-not-verify mapping of refused/error."""

    lst: DnsblList
    state: str = "error"
    codes: list[str] = field(default_factory=list)
    meanings: list[str] = field(default_factory=list)
    counts: bool = False
    status: Status = Status.ERROR
    code: str = "error"
    reason: str = ""
    route: str = "doh"
    txt: str = ""
    httpbl: dict[str, Any] | None = None

    @property
    def answered(self) -> bool:
        return self.state in ("listed", "not_listed")

    @property
    def info_only(self) -> bool:
        return self.state == "listed" and not self.counts

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "list": self.lst.id, "name": self.lst.name, "source": self.lst.source, "state": self.state,
            "codes": list(self.codes), "meanings": list(self.meanings), "counts": self.counts, "route": self.route,
        }
        if self.reason:
            out["reason"] = self.reason
        if self.txt:
            out["txt"] = self.txt
        if self.httpbl:
            out["httpbl"] = dict(self.httpbl)
        return out


def _fail(lst: DnsblList, status: Status, code: str, reason: str, route: str, state: str = "error") -> Outcome:
    return Outcome(lst, state=state, status=status, code=code, reason=reason, route=route)


def classify(lst: DnsblList, rcode: str, records: list[str], *, route: str, error: str = "", public: bool = False) -> Outcome:
    """Classify one answer (P045 c4, c5, c7). ``rcode``: NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT...;
    ``records``: A records; ``public``: the answer came from a public resolver (a list that
    refuses public resolvers can then never be read as listed or not listed)."""
    if rcode not in ("NOERROR", "NXDOMAIN") or error:
        status_code = "timeout" if rcode == "TIMEOUT" else "error"
        detail = f" ({error[:160]})" if error else ""
        return _fail(lst, Status.ERROR, status_code, f"{lst.name}: resolver answered {rcode}{detail}: could not verify", route)
    refuses_here = public and lst.route != "doh"
    if rcode == "NXDOMAIN":
        if refuses_here:
            return _fail(lst, Status.BLOCKED, "challenge", f"{lst.name} refuses public resolvers (NXDOMAIN through DoH): could not verify", route, "refused")
        return Outcome(lst, state="not_listed", status=Status.EMPTY, code="", reason="NXDOMAIN (not listed)", route=route)
    codes = [c.strip() for c in records if isinstance(c, str) and c.strip()]
    if not codes:
        if refuses_here:
            return _fail(lst, Status.BLOCKED, "challenge", f"{lst.name} refuses public resolvers: could not verify", route, "refused")
        return Outcome(lst, state="not_listed", status=Status.EMPTY, code="", reason="NOERROR without an address record (not listed)", route=route)
    for c in codes:
        refusal = lst.refusals.get(c) or GENERIC_REFUSALS.get(c)
        if refusal is None and c.startswith(REFUSAL_PREFIX):
            refusal = (Status.BLOCKED, "challenge", "refusal code")
        if refusal is not None:
            st, code, meaning = refusal
            out = _fail(lst, st, code, f"{lst.name} refused the query: {meaning} ({c}): could not verify", route, "refused")
            out.codes = codes
            return out
    bad = [c for c in codes if not _in_loopback(c)]
    if bad:
        out = _fail(lst, Status.ERROR, "error", f"{lst.name}: answer outside 127.0.0.0/8 ({', '.join(bad[:3])}): resolver rewriting or wildcard, could not verify", route)
        out.codes = codes
        return out
    if refuses_here:
        out = _fail(lst, Status.BLOCKED, "challenge", f"{lst.name} is never read through public resolvers (P045 c4): could not verify", route, "refused")
        out.codes = codes
        return out
    if lst.id == "httpbl":
        return _httpbl(lst, codes, route)
    meanings, counts, unknown = _decode(lst, codes)
    if unknown:
        out = _fail(lst, Status.ERROR, "error", f"{lst.name}: unexpected return code(s) {', '.join(unknown[:3])} not in the bundled table: could not verify", route)
        out.codes = codes
        return out
    out = Outcome(lst, state="listed", codes=codes, meanings=meanings, counts=counts, status=Status.OK, code="", route=route)
    out.reason = "; ".join(meanings)
    if lst.neighbourhood:
        out.reason = f"{out.reason}: neighbourhood listing (whole allocation/ASN), info only, zero risk"
    return out


def _in_loopback(code: str) -> bool:
    try:
        ip = ipaddress.ip_address(code)
    except ValueError:
        return False
    return ip.version == 4 and ip in LOOPBACK


def _decode(lst: DnsblList, codes: list[str]) -> tuple[list[str], bool, list[str]]:
    meanings: list[str] = []
    counts = False
    unknown: list[str] = []
    if lst.bitmask:
        known = sum(lst.bitmask)
        for c in codes:
            last = int(c.rsplit(".", 1)[1])
            hits = [(meaning, cnt) for bit, (meaning, cnt) in sorted(lst.bitmask.items()) if last & bit]
            if not hits or last & ~known:
                unknown.append(c)
                continue
            for meaning, cnt in hits:
                if meaning not in meanings:
                    meanings.append(meaning)
                counts = counts or cnt
        return meanings, counts, unknown
    for c in codes:
        if c in lst.codes:
            meaning, cnt = lst.codes[c]
            if meaning not in meanings:
                meanings.append(meaning)
            counts = counts or cnt
        else:
            unknown.append(c)
    return meanings, counts, unknown


def _httpbl(lst: DnsblList, codes: list[str], route: str) -> Outcome:
    """Project Honey Pot http:BL answer 127.<days>.<score>.<type> (P045 c9). Type 0 = search engine
    (the third octet is an engine serial, not a score): info only. Bits 1/2/4 = suspicious /
    harvester / comment spammer with a log-scaled threat score."""
    code = codes[0]
    parts = code.split(".")
    if len(parts) != 4 or parts[0] != "127" or not all(p.isdigit() and int(p) <= 255 for p in parts):
        return _fail(lst, Status.ERROR, "error", f"{lst.name}: not an http:BL answer ({code[:40]}): could not verify", route)
    days, third, vtype = int(parts[1]), int(parts[2]), int(parts[3])
    if vtype == 0:
        engine = HTTPBL_SEARCH_ENGINES.get(third, "unknown")
        out = Outcome(lst, state="listed", codes=[code], meanings=[f"search engine ({engine})"], counts=False, status=Status.OK, code="", route=route)
        out.reason = "search engine, not a threat"
        out.httpbl = {"search_engine": engine, "days_since_last_activity": days}
        return out
    if vtype > 7:
        return _fail(lst, Status.ERROR, "error", f"{lst.name}: unknown visitor type bits ({vtype}): could not verify", route)
    types = [name for bit, name in HTTPBL_TYPES if vtype & bit]
    band = score_band(third)
    meaning = f"{'+'.join(types)} (threat score {third}, {band}, log-scaled; last activity {days} days ago)"
    out = Outcome(lst, state="listed", codes=[code], meanings=[meaning], counts=True, status=Status.OK, code="", route=route)
    out.reason = meaning
    out.httpbl = {"threat_score": third, "score_band": band, "days_since_last_activity": days, "visitor_types": types}
    return out


def check_test_point(outcome: Outcome) -> tuple[bool, str]:
    """P045 c6: the list's test point must answer one of its documented codes, else the list is
    could-not-verify for the run (never 'not listed')."""
    lst = outcome.lst
    if outcome.state != "listed":
        return False, f"{lst.name} test point failed ({outcome.state}: {outcome.reason or 'no answer'})"
    if not set(outcome.codes) & lst.test_expect:
        return False, f"{lst.name} test point answered {', '.join(outcome.codes)}, expected one of {', '.join(sorted(lst.test_expect))}"
    return True, ""


def aggregate(outcomes: list[Outcome]) -> dict[str, Any]:
    """ONE aggregated finding (P045 c8): k counted listings of n answering lists."""
    listed = [o for o in outcomes if o.state == "listed" and o.counts]
    info = [o for o in outcomes if o.info_only]
    answered = [o for o in outcomes if o.answered]
    cnv = [o for o in outcomes if not o.answered]
    k, n = len(listed), len(answered)
    names = "; ".join(f"{o.lst.name} {'/'.join(o.codes)} {', '.join(o.meanings)}".strip() for o in listed)
    if k:
        line = f"listed on {k} of {n} queried lists ({names})"
    elif n:
        line = f"not listed on {n} queried list{'' if n == 1 else 's'}"
    else:
        line = "could not verify any DNSBL"
    if cnv:
        line += "; could not verify: " + ", ".join(o.lst.name for o in cnv)
    return {"line": line, "listed": listed, "info": info, "answered": answered, "could_not_verify": cnv, "k": k, "n": n}


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class Dnsbl(Module):
    name = "dnsbl"
    title = "DNSBL / RBL listings"
    description = (
        "Spam-reputation listings of an IP or a domain on DNS blocklists: SpamCop and DroneBL through the core DoH layer, "
        "Spamhaus ZEN/DBL (DQS key) and Project Honey Pot http:BL (access key) through the system resolver only; "
        "UCEPROTECT, Barracuda, SURBL and URIBL under their own terms. Per-list return-code tables and test points."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6, T.DOMAIN}
    produces = frozenset()
    tags = {"reputation", "free"}
    reference = "https://www.rfc-editor.org/rfc/rfc5782"
    notice = (
        "DNSBL listings mean spam reputation, never 'malicious'; all DNSBLs count as ONE family vote. Lookups disclose the "
        "IP/domain to the resolver and the list operator. Spamhaus ZEN/DBL need a DQS key (commercial DQS for business use, "
        "key_plans.spamhaus_dqs) and http:BL an access key: keyed zones go only through the system resolver (dns_mode system, "
        "dnspython), never public DoH. UCEPROTECT, Barracuda, SURBL and URIBL are noncommercial: off under the corporate "
        "profile until licence-cleared."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "spamcop"
    sources = SOURCES
    hosts = ()
    access_model = "free_noauth_limited"
    optional_keys = ("spamhaus_dqs", "httpbl")
    max_requests = 0  # DNS only: ctx.dns is not counted
    expected_latency = 1.5
    max_pivots = 0
    default_enabled = True
    settings = {
        "dnsbl_registered_lists": SettingSpec(
            [],
            "DNSBLs whose registration (or data-feed subscription) covers this installation's non-public resolver: "
            "barracuda, surbl, uribl. They are queried only through that resolver (dns_mode system or doh_internal), "
            "never through public DoH (P045 c4).",
            choices=("barracuda", "surbl", "uribl"),
        ),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return is_public_ip(entity.value)  # private/reserved addresses are never sent to a DNSBL
        return "." in entity.value

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind = "domain" if entity.type is T.DOMAIN else "ip"
        value = _subject(entity)
        is_v6 = kind == "ip" and ":" in value
        allowed = ctx.allowed_sources
        registered = {str(x).strip().lower() for x in (ctx.setting("dnsbl_registered_lists", []) or [])}
        dns_mode = str(getattr(ctx.dns, "mode", "doh") or "doh")
        non_public = bool(getattr(ctx.dns, "non_public_available", lambda: False)())
        candidates = [lst for lst in LISTS if lst.kind == kind and (lst.ipv6 or not is_v6)]
        not_queried: list[str] = []
        unusable: list[tuple[Status, str, str]] = []  # allowed keyed lists that cannot be queried here
        planned: list[tuple[DnsblList, str]] = []
        for lst in candidates:
            if lst.source not in allowed:
                continue  # licence (P045 c1-c2): the engine reports the source 'licence'
            if lst.route == "keyed":
                key = str(ctx.key(lst.key_name) or "").strip().lower()
                if not key:
                    not_queried.append(lst.name)
                    res.source_status(lst.source, Status.SKIPPED, reason_code="config", reason=f"{lst.name}: {COVERAGE_NEEDS}")
                    continue
                problem: tuple[Status, str, str] | None = None
                if not _KEY_RES[lst.key_name].match(key):
                    problem = (Status.SKIPPED, "config", f"{lst.name}: the configured {lst.key_name} key has an invalid format")
                elif not package_available("dns"):
                    problem = (Status.UNAVAILABLE, "package",
                               f"{lst.name}: keyed zones use only the system resolver through dnspython (pip install 'v3lum[full]'); never public DoH")
                elif dns_mode != "system":
                    problem = (Status.SKIPPED, "config", f"{lst.name}: keyed zones use only the system resolver (set dns_mode system); never public DoH")
                if problem is not None:
                    unusable.append(problem)
                    res.source_status(lst.source, problem[0], reason_code=problem[1], reason=problem[2])
                    continue
                planned.append((lst, key))
            elif lst.route == "refuses":
                if lst.id in registered and non_public:
                    planned.append((lst, ""))
                else:
                    not_queried.append(lst.name)
                    res.source_status(lst.source, Status.SKIPPED, reason_code="config", reason=f"{lst.name}: {COVERAGE_NEEDS}")
            else:
                planned.append((lst, ""))
        if len(planned) > MAX_LISTS:  # P045 c9
            for lst, _key in planned[MAX_LISTS:]:
                res.source_status(lst.source, Status.SKIPPED, reason_code="not_applicable", reason=f"per-entity cap of {MAX_LISTS} lists reached")
            planned = planned[:MAX_LISTS]
        coverage_line = f"{', '.join(not_queried)}: {COVERAGE_NEEDS}" if not_queried else ""
        if coverage_line:
            res.attr("dnsbl_not_queried", coverage_line)
        if not planned:
            if not any(lst.source in allowed for lst in candidates):
                return res.mark(Status.SKIPPED, "no DNSBL list for this entity type is allowed under the licence profile", reason_code="licence")
            why = "; ".join([coverage_line, *(text for _s, _c, text in unusable)] if coverage_line else [text for _s, _c, text in unusable])
            if any(st is Status.UNAVAILABLE for st, _c, _t in unusable):
                return res.mark(Status.UNAVAILABLE, why, reason_code="package")  # P045 c3: dnspython is the only route
            return res.mark(Status.SKIPPED, why or "no DNSBL list could be queried for this entity", reason_code="config")
        outcomes: list[Outcome] = []
        for lst, key in planned:  # the kill switch raises Cancelled from ctx.dns (partial result kept by the engine)
            outcome = self._lookup(ctx, lst, value, key, is_v6=is_v6)
            outcomes.append(outcome)
            if outcome.answered:
                res.source_status(lst.source, Status.OK if outcome.state == "listed" else Status.EMPTY, reason=outcome.reason[:200])
            else:
                res.source_status(lst.source, outcome.status, reason_code=outcome.code, reason=outcome.reason[:300])
        return self._report(res, entity, outcomes, coverage_line)

    # ---- one list ----------------------------------------------------------------------
    def _lookup(self, ctx: Any, lst: DnsblList, value: str, key: str, *, is_v6: bool) -> Outcome:
        """Test point first (P045 c6), then the entity: both through the list's route."""
        test_value = lst.test_query_v6 if (is_v6 and lst.test_query_v6) else lst.test_query
        test_label = query_label(lst, test_value, key, unmap=False)
        label = query_label(lst, value, key)
        if test_label is None or label is None:
            return _fail(lst, Status.ERROR, "error", f"{lst.name}: no query name for this value", "doh")
        test = self._ask(ctx, lst, test_label, key)
        ok, why = check_test_point(test)
        if not ok:
            out = _fail(lst, test.status if test.state == "refused" else Status.ERROR, test.code if test.state == "refused" else "error",
                        f"{why}: could not verify this run, never 'not listed'", test.route, "test_point_failed")
            out.codes = list(test.codes)
            return out
        outcome = self._ask(ctx, lst, label, key)
        if outcome.state == "listed" and lst.txt_reason and lst.route == "doh":
            outcome.txt = self._txt(ctx, f"{label}.{lst.zone}")
        return outcome

    def _ask(self, ctx: Any, lst: DnsblList, label: str, key: str) -> Outcome:
        if lst.route == "doh":
            ans = ctx.dns.query(f"{label}.{lst.zone}", "A")
            route = _route_of(ans)
            return classify(lst, ans.status, list(ans.records), route=route, error=ans.error, public=route == "doh")
        # keyed and registered lists: a non-public resolver only (ctx.dns.dnsbl refuses public ones)
        found = ctx.dns.dnsbl(label, lst.zone)
        reason = redact_qname(str(getattr(found, "reason", "") or ""), key)
        status = str(getattr(found, "status", "") or "")
        codes = [str(c) for c in (getattr(found, "codes", None) or [])]
        listed = getattr(found, "listed", None)
        if status == "ok" and listed is False:
            return classify(lst, "NXDOMAIN", [], route="system")
        if status == "ok" and listed is True:
            return classify(lst, "NOERROR", codes, route="system")
        if status in ("blocked", "rate_limited", "error") and codes:
            return classify(lst, "NOERROR", codes, route="system")  # the bundled table names the refusal
        if status == "blocked":
            return _fail(lst, Status.BLOCKED, "challenge", f"{lst.name}: {reason or 'query refused'}: could not verify", "system", "refused")
        if status == "rate_limited":
            return _fail(lst, Status.RATE_LIMITED, "rate_limited", f"{lst.name}: {reason or 'rate limited'}: could not verify", "system", "refused")
        code = "timeout" if "TIMEOUT" in reason else "error"
        return _fail(lst, Status.ERROR, code, f"{lst.name}: {reason or 'no answer from the system resolver'}: could not verify", "system")

    @staticmethod
    def _txt(ctx: Any, qname: str) -> str:
        """Best-effort TXT reason of a listing (SpamCop publishes the lookup URL there)."""
        try:
            ans = ctx.dns.query(qname, "TXT")
        except Exception:  # noqa: BLE001 - optional context: a failure never changes the listing
            return ""
        if not getattr(ans, "ok", False):
            return ""
        text = " ".join(str(r) for r in ans.records if isinstance(r, str))
        return " ".join(text.split())[:200]

    # ---- report ------------------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, outcomes: list[Outcome], coverage_line: str) -> ModuleResult:
        agg = aggregate(outcomes)
        res.raw = {"lists": [o.to_dict() for o in outcomes], "coverage_line": coverage_line or None, "family": FAMILY}
        res.attr("dnsbl_listings", [o.to_dict() for o in outcomes])
        res.attr("dnsbl_summary", agg["line"])
        for o in outcomes:
            if o.httpbl and o.state == "listed":
                res.attr("httpbl", dict(o.httpbl))
        if not agg["answered"]:
            first = agg["could_not_verify"][0] if agg["could_not_verify"] else None
            status, code = (first.status, first.code) if first is not None else (Status.ERROR, "error")
            return res.mark(status, f"could not verify any DNSBL: {'; '.join(o.reason for o in agg['could_not_verify'])[:600]}", reason_code=code)
        if agg["listed"]:
            k, n = agg["k"], agg["n"]
            first = agg["listed"][0]
            res.attr("blocklist_families", [FAMILY])
            res.finding(
                "Listed on DNS blocklists (spam reputation)",
                "low" if k == 1 else "medium",  # P045 c8: one SpamCop/DroneBL listing = LOW; never above MEDIUM
                f"{agg['line']}. DNSBL listings describe spam/abuse reputation of the address or domain, never proof of "
                "malicious activity; all DNSBLs count as ONE 'spam' family vote.",
                confidence="probable",
                criterion=f"listed by {k} of {n} DNSBLs whose per-run test point answered as documented; return codes read from the bundled per-list tables",
                data={"listed": k, "answered": n, "lists": [o.to_dict() for o in agg["listed"]], "family": FAMILY,
                      "could_not_verify": [o.lst.name for o in agg["could_not_verify"]]},
                tags=["spam"],
                source=first.lst.source,
            )
            for o in agg["listed"]:
                if o.lst.id == "spamcop" and entity.type is T.IPV4:
                    res.link("SpamCop blocking list lookup", f"https://www.spamcop.net/bl.shtml?{entity.value}")
        if agg["info"]:
            res.finding(
                "DNSBL context listings (no risk)",
                "info",
                "; ".join(f"{o.lst.name} {'/'.join(o.codes)}: {o.reason}" for o in agg["info"]),
                confidence="probable",
                data={"lists": [o.to_dict() for o in agg["info"]]},
                tags=["context_only"],
                source=agg["info"][0].lst.source,
            )
        if not agg["listed"] and not agg["info"]:
            return res.mark("empty")
        return res


def _subject(entity: Entity) -> str:
    """The value looked up: IPv4-mapped IPv6 is read as its IPv4 address."""
    if entity.type is T.DOMAIN:
        return entity.value.strip().rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(entity.value)
    except ValueError:
        return entity.value
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def _route_of(answer: Any) -> str:
    """'doh' when a public DoH resolver gave (or failed to give) the answer, else 'system' or
    'internal' (the organisation's own resolver)."""
    resolver = str(getattr(answer, "resolver", "") or "")
    names = {r.strip() for r in resolver.split(",") if r.strip()}
    if not names or names & {"google", "cloudflare", "quad9"}:
        return "doh"
    return "system" if "system" in names else "internal"
