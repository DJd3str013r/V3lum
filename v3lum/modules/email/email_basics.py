"""Email basics: domain pivot, mail acceptance (MX), free-webmail flag, plus-addressing, generic addresses.

Reference implementation (module contract v2) of rule 5 for DNS-backed checks (P328 cond 8):
a DoH failure (SERVFAIL, REFUSED, timeout, transport error) never becomes ``mx_valid=False`` or
'domain does not accept mail' - the answer is simply unknown. 'Does not exist' needs an NXDOMAIN
confirmed by a second resolver; 'does not accept mail' needs NOERROR answers (no MX and no
address record, or an RFC 7505 null MX). An unverified answer is recorded as the source outcome
(``res.source_status``) so coverage counts it as 'could not verify'. Generic, role and test
addresses are flagged through ``entities.generic_address_kind`` as context only (never scored, A4).
Derived personal identifiers (the base mailbox of a sub-address, the local part as a handle) are
pivots for analyst selection (``expand=False``): only the typed address goes to other sources.

The free-webmail flag comes from the one set of e-mail hygiene data files (P088 C1): the AfterShip
free-provider list (bundled, refreshable with ``v3lum data update``) plus the V3LUM supplement, read
through ``email_hygiene.is_free_provider`` (PSL-aware, local copies only, never a download). The
hard-coded FREE_PROVIDERS set of v1 moved into ``v3lum/data/email_hygiene/local_supplement.json``.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.email.email_hygiene import SRC_FREE, is_free_provider

SOURCE = "core_doh.resolvers"
BASE_MAILBOX_NOTE = "base mailbox of a sub-address (same mailbox): analyst selection required"


def _answer(ans: Any) -> dict[str, Any]:
    return {"status": ans.status, "records": ans.records, "error": ans.error, "resolver": getattr(ans, "resolver", "")}


@register
class EmailBasics(Module):
    name = "email_basics"
    title = "Email basics"
    description = "Splits the address, checks the domain accepts mail (MX), flags free webmail, generic/role/test addresses and plus-addressing."
    category = "email"
    accepts = {T.EMAIL}
    produces = {T.DOMAIN, T.USERNAME, T.EMAIL}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "core_doh"
    sources = (SOURCE, SRC_FREE)  # DoH + the free-provider dataset (local copy or bundled, P088 C1)
    hosts = ()
    access_model = "free_noauth_unlimited"
    max_requests = 0  # DoH only: ctx.dns is not counted
    expected_latency = 1.5
    reference = "https://www.rfc-editor.org/rfc/rfc7505"
    tags = {"free", "core"}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        local, domain = entity.value.split("@", 1)
        base_local = local.split("+", 1)[0]
        free = is_free_provider(domain, ctx)
        generic = generic_address_kind(entity.value)
        res.attr("free_provider", free)
        raw: dict[str, Any] = {"local": local, "domain": domain, "free_provider": free, "generic_address": generic}
        res.raw = raw

        res.pivot(T.DOMAIN, domain, "email_domain", expand=not free)
        if not generic and len(base_local) >= 3 and not base_local.isdigit():
            res.pivot(T.USERNAME, base_local, "uses_username", confidence="possible", expand=False, note="local part reused as a handle: weak link")
        if "+" in local:
            res.finding(
                "Plus-addressing used",
                "info",
                f"Base mailbox is {base_local}@{domain}.",
                criterion="'+' sub-address in the local part (RFC 5233)",
                tags=["info"],
            )
            res.pivot(T.EMAIL, f"{base_local}@{domain}", "same_person", confidence=0.95, expand=False, note=BASE_MAILBOX_NOTE)
        if generic:
            res.attr("generic_address", generic)
            res.finding(
                "Generic, role or test address",
                "info",
                f"Kind: {generic}. Usually shared by a team or reserved for tests: shown as context, never scored as exposure.",
                confidence="probable",
                criterion="local part or domain on the bundled generic/role/test address list",
                data={"kind": generic},
                tags=["info", "context_only"],
            )
        if free:
            res.finding(f"Free webmail provider ({domain})", "info", criterion="domain on the free-webmail list", tags=["info"])

        self._mail_acceptance(res, ctx, domain, raw)
        return res

    # ------------------------------------------------------------------ rule 5: no absence from failures
    def _mail_acceptance(self, res: ModuleResult, ctx: Any, domain: str, raw: dict[str, Any]) -> None:
        mx = ctx.dns.query(domain, "MX")
        raw["mx"] = _answer(mx)
        if mx.ok:
            null_mx = any(r == "0 ." or r.endswith(" .") for r in mx.records)
            hosts = [r.split()[-1] for r in mx.records if r.split() and r.split()[-1] != "."]
            res.attr("mx", hosts)
            if mx.records:
                res.attr("mx_valid", bool(hosts) and not null_mx)
                if null_mx:
                    self._refuses_mail(res, "The domain publishes an RFC 7505 null MX: it explicitly refuses email.")
                return
            # NOERROR without MX: mail goes to the address records (implicit MX, RFC 5321 5.1).
            addresses = [ctx.dns.query(domain, rt) for rt in ("A", "AAAA")]
            raw["implicit_mx"] = [_answer(a) for a in addresses]
            if any(a.ok and a.records for a in addresses):
                res.attr("mx_valid", True)
            elif all(a.ok for a in addresses):
                res.attr("mx_valid", False)
                self._refuses_mail(res, "No MX and no A/AAAA records: the address cannot receive email.")
            else:
                failed = next(a for a in addresses if not a.ok)
                self._unknown(res, f"address records: {failed.error or failed.status}", timeout=failed.status == "TIMEOUT")
            return
        if mx.nxdomain:
            confirmed = ctx.dns.confirm_nxdomain(domain, "MX")
            raw["nxdomain_confirmed"] = confirmed
            if confirmed is True:
                res.attr("mx_valid", False)
                res.finding(
                    "Email domain does not exist (NXDOMAIN)",
                    "low",
                    "Undeliverable address: typo, expired domain or fake identity.",
                    confidence="confirmed",
                    criterion="NXDOMAIN (Status 3) for the e-mail domain confirmed by a second resolver",
                    tags=["suspicious"],
                    source=SOURCE,
                )
                return
            self._unknown(res, "NXDOMAIN not confirmed by a second resolver")
            return
        self._unknown(res, mx.error or mx.status, timeout=mx.status == "TIMEOUT")

    @staticmethod
    def _refuses_mail(res: ModuleResult, why: str) -> None:
        res.finding(
            "Email domain does not accept mail",
            "low",
            why,
            confidence="confirmed",
            criterion="NOERROR DNS answers: no MX and no A/AAAA records, or an RFC 7505 null MX",
            tags=["suspicious"],
            source=SOURCE,
        )

    @staticmethod
    def _unknown(res: ModuleResult, why: str, *, timeout: bool = False) -> None:
        """Rule 5: the DoH source did not answer - no mx_valid, no absence finding, the source
        outcome says 'could not verify' (the offline facts about the address still stand)."""
        res.error = f"mail acceptance could not be verified ({why})"
        res.source_status(SOURCE, Status.ERROR, reason_code="timeout" if timeout else "error", reason=res.error)
