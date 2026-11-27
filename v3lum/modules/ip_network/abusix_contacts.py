"""abusix_contacts: the abuse mailbox of the network that holds an IP, from the Abusix Abuse Contact DB (P041).

Batch p2-G02-1, proposal P041 (approved, P2). The Abusix Abuse Contact DB is a DNS zone: one TXT query
``{reversed IP}.abuse-contacts.abusix.zone`` answers with the abuse address of the network (built from
the RIR databases). Final conditions implemented here:

* c1 - one TXT query through ``ctx.dns`` (the core DoH resolver chain, ECS 0/0 on Google): reversed
  octets for IPv4 and the 32 reversed nibbles for IPv6 (``v3lum.core.dns.dnsbl_label``); an IPv4-mapped
  IPv6 address is queried as its IPv4 address. Answers are cached by the core resolver (at most one
  hour); the published TTL is recorded with the answer (``ttl``).
* c2 - the answer becomes attribute ``abuse_contact`` (the first role mailbox) and ``abuse_contacts``
  records (the P345 takedown-packet shape shared with ``ripestat.abuse_contact_records``: kind
  ``abusix_contact``, authority rank 3 after registrar RDAP abuse and the RIR abuse-c), plus an
  ``email`` pivot with relation ``contact_email`` and ``expand=False``. Only role mailboxes
  (abuse@, noc@, network-abuse@, helpdesk@...) are pivoted; any other address is kept in attribute
  ``abuse_contact_non_role`` and never pivoted (it may be a person).
* c3 - SERVFAIL, REFUSED, timeouts and resolver failures are 'could not verify' (ERROR); NXDOMAIN, or
  NOERROR without TXT data, means 'no abuse contact published' (EMPTY); a TXT answer that holds no
  e-mail address is 'could not verify' as well. Abusix asks reports that use its contacts to carry a
  reference text: every record carries it in ``report_reference`` for the takedown packet.

Private, reserved and documentation addresses are never queried (SKIPPED not_applicable).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from v3lum.core.dns import dnsbl_label
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "abusix.abuse_contacts"
DOH_SOURCE = "core_doh.resolvers"
ZONE = "abuse-contacts.abusix.zone"
ATTRIBUTION = "Abuse contact: Abusix Abuse Contact DB (abuse-contacts.abusix.zone), built on the RIR databases"
#: Reference text Abusix asks every report message that used a Contact DB address to carry (terms).
REPORT_REFERENCE = (
    "Abusix is neither responsible nor liable for the content or accuracy of the abuse being reported in this message. "
    "The Abusix Abuse Contact DB provided only the abuse contact for the originating network for this report. This free "
    "abuse@ address, proxy DB service, is built on top of the RIR databases. Therefore, if you wish to change or report a "
    "non-working abuse contact address, please contact the parent ASN operator or the appropriate RIR responsible for "
    "managing the underlying IP address on the abuse contact map."
)
#: P345 authority ranking shared with ripestat (1 registrar RDAP abuse, 2 RIR abuse-c, 3 Abusix, 4 CDN portals).
AUTHORITY_RANK = 3
#: Local-part tokens of role (non-personal) mailboxes, on top of the shared A4 list (generic_addresses.json).
ROLE_TOKENS = frozenset({
    "abuse", "abusedesk", "antispam", "spam", "noc", "soc", "cert", "csirt", "cirt", "irt", "security", "secops",
    "helpdesk", "help", "support", "suporte", "hostmaster", "postmaster", "webmaster", "admin", "administrator",
    "sysadmin", "netadmin", "ipadmin", "ipam", "network", "networks", "netops", "ops", "operations", "nic", "lir",
    "dns", "registry", "ripe", "arin", "apnic", "lacnic", "afrinic", "contact", "contato", "info", "report",
    "reports", "trust", "safety", "legal", "dmca", "compliance", "peering", "hosting", "servicedesk", "service",
    "services", "desk", "team", "noreply", "donotreply", "sac", "atendimento", "seguranca", "incident", "incidents",
    "domains", "domain", "billing", "tech", "technical", "isp",
})
_SPLIT_RE = re.compile(r"[\s,;<>\"']+")
_LOCAL_SPLIT_RE = re.compile(r"[._+\-]+")
MAX_ADDRESSES = 10


def query_name(ip: str) -> str | None:
    """``{reversed octets | reversed nibbles}.abuse-contacts.abusix.zone`` of a public IP (c1), else None.

    An IPv4-mapped IPv6 address is queried as its IPv4 address."""
    try:
        addr = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not is_public_ip(str(addr)):
        return None
    return f"{dnsbl_label(str(addr))}.{ZONE}"


def is_role_address(email: str) -> bool:
    """True when the mailbox reads as a role/desk address (c2: only those are pivoted).

    The shared A4 list (``generic_address_kind`` 'role') or a local part made of role tokens joined by
    '.', '-', '_' or '+' ('network-abuse', 'arin-contact', 'abuse_desk'); never a prefix guess."""
    if generic_address_kind(email) == "role":
        return True
    local = str(email).split("@", 1)[0].lower()
    tokens = [t for t in _LOCAL_SPLIT_RE.split(local) if t]
    if not tokens:
        return False
    return any(t in ROLE_TOKENS for t in tokens) or "".join(tokens) in ROLE_TOKENS


def addresses_in(records: list[str]) -> list[str]:
    """Normalised e-mail addresses found in TXT strings (deduplicated, in order, capped)."""
    out: list[str] = []
    for record in records:
        for token in _SPLIT_RE.split(str(record)):
            token = token.strip().strip(".").removeprefix("mailto:")
            if "@" not in token:
                continue
            ent = Entity.try_make(T.EMAIL, token)
            if ent is not None and ent.value not in out:
                out.append(ent.value)
    return out[:MAX_ADDRESSES]


def contact_records(role: list[str], *, resource: str, retrieved_at: str, ttl: int | None) -> list[dict[str, Any]]:
    """c2/c3: abuse_contacts records for the P345 takedown packet (the ripestat record shape)."""
    return [
        {
            "email": email,
            "kind": "abusix_contact",
            "authority_rank": AUTHORITY_RANK,
            "authority": "Abusix Abuse Contact DB (RIR-derived abuse mailbox)",
            "source": SOURCE,
            "resource": resource,
            "retrieved_at": retrieved_at,
            "ttl": ttl,
            "attribution": ATTRIBUTION,
            "report_reference": REPORT_REFERENCE,
        }
        for email in role
    ]


@register
class AbusixContacts(Module):
    name = "abusix_contacts"
    title = "Abusix abuse contact"
    description = (
        "Abuse mailbox of the network that holds an IP from the Abusix Abuse Contact DB (one DNS TXT query "
        "through the core DoH resolvers): role mailboxes become takedown contacts."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.EMAIL}
    tags = {"free"}
    reference = "https://docs.abusix.com/docs/abuse-reporting/abuse-contact-db/overview"
    notice = (
        "Free Abusix service built on the RIR databases. Reports that use an Abusix contact must carry Abusix's "
        "reference text (kept in every abuse_contacts record as report_reference). Only role mailboxes are pivoted; "
        "NXDOMAIN means 'no abuse contact published', a resolver failure means 'could not verify'."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the DoH resolver operator sees the reversed-IP query name
    provider = "core_doh"
    sources = (DOH_SOURCE, SOURCE)
    hosts = ()  # DoH hosts are core, not declared
    access_model = "free_noauth_unlimited"
    max_requests = 0  # ctx.dns is not counted
    expected_latency = 0.5
    timeout = 30.0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_name(entity.value) is not None  # private/reserved/documentation space: never queried

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        qname = query_name(entity.value)
        if qname is None:  # pragma: no cover - applies() filters these
            return res.mark(Status.SKIPPED, "not a public address: no Abusix query", reason_code="not_applicable")
        ans = ctx.dns.query(qname, "TXT")
        res.raw = {"query": qname, "status": ans.status, "records": list(ans.records)[:MAX_ADDRESSES], "ttl": ans.ttl,
                   "resolver": ans.resolver, "error": ans.error}
        if ans.could_not_verify:
            code = "timeout" if (ans.status == "TIMEOUT" or "timed out" in ans.error.lower() or "timeout" in ans.error.lower()) else "error"
            reason = f"Abusix lookup could not verify ({ans.status}{': ' + ans.error[:160] if ans.error else ''})"
            res.source_status(SOURCE, Status.ERROR, reason_code=code, reason=reason)
            return res.mark(Status.ERROR, reason, reason_code=code)
        if ans.nxdomain:
            return res.mark(Status.EMPTY, "no abuse contact published in the Abusix Contact DB (NXDOMAIN)")
        if not ans.records:
            return res.mark(Status.EMPTY, "no abuse contact published in the Abusix Contact DB (no TXT data)")
        found = addresses_in(list(ans.records))
        if not found:
            reason = "Abusix TXT answer without an e-mail address: could not verify"
            res.source_status(SOURCE, Status.ERROR, reason_code="error", reason=reason)
            return res.mark(Status.ERROR, reason, reason_code="error")
        role = [e for e in found if is_role_address(e)]
        other = [e for e in found if e not in role]
        retrieved_at = ctx.now().isoformat(timespec="seconds").replace("+00:00", "Z")
        ttl = int(ans.ttl) if isinstance(ans.ttl, int) and ans.ttl > 0 else None
        res.attr("abuse_contact", role[0] if role else other[0])
        res.attr("abuse_contacts", contact_records(role, resource=entity.value, retrieved_at=retrieved_at, ttl=ttl))
        res.attr("abuse_contact_non_role", other)
        res.attr("data_attribution", ATTRIBUTION)
        for email in role:
            res.pivot(T.EMAIL, email, "contact_email", confidence="probable", expand=False,
                      note="abuse role mailbox (Abusix Abuse Contact DB): takedown contact, never scored as exposure")
        return res
