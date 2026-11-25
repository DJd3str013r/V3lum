"""Email basics: domain pivot, deliverability (MX), free-webmail flag, plus-addressing, role accounts."""

from __future__ import annotations

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult
from v3lum.core.module import Module, register

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.com.br",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.io",
    "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "mail.ru", "zoho.com", "uol.com.br", "bol.com.br",
    "terra.com.br", "ig.com.br", "hotmail.com.br", "outlook.com.br", "live.com.br", "rocketmail.com", "inbox.com",
}
ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "contact", "contato", "support", "suporte", "sales", "vendas", "billing",
    "financeiro", "rh", "hr", "jobs", "noreply", "no-reply", "postmaster", "abuse", "security", "webmaster", "hostmaster",
    "marketing", "comercial", "atendimento", "sac", "ti", "it", "helpdesk", "office",
}


@register
class EmailBasics(Module):
    name = "email_basics"
    title = "Email basics"
    description = "Splits the address, checks the domain accepts mail (MX), flags free webmail, role accounts and plus-addressing."
    category = "email"
    accepts = {T.EMAIL}
    produces = {T.DOMAIN, T.USERNAME}
    hosts = ("dns.google",)
    tags = {"free", "core"}
    cache_ttl = 3600

    def run(self, entity: Entity, ctx: object) -> ModuleResult:
        res = self.result(entity)
        local, domain = entity.value.split("@", 1)
        base_local = local.split("+", 1)[0]
        free = domain in FREE_PROVIDERS
        res.attr("free_provider", free)
        mx = ctx.dns.query(domain, "MX")
        a = ctx.dns.query(domain, "A") if not mx.records else None
        accepts_mail = bool(mx.records) or bool(a and a.records)
        null_mx = any(r.endswith(" .") or r == "0 ." for r in mx.records)
        res.attr("mx_valid", accepts_mail and not null_mx)
        res.attr("mx", [r.split()[-1] for r in mx.records if r.split()])
        res.pivot(T.DOMAIN, domain, "email_domain", expand=not free)
        if len(base_local) >= 3 and not base_local.isdigit():
            res.pivot(T.USERNAME, base_local, "uses_username", confidence=0.4, expand=False, note="local part reused as a handle: weak link")
        if "+" in local:
            res.finding("Plus-addressing used", "info", f"Base mailbox is {base_local}@{domain}.", tags=["info"])
            res.pivot(T.EMAIL, f"{base_local}@{domain}", "same_person", confidence=0.95)
        if base_local in ROLE_ACCOUNTS:
            res.finding("Role/shared mailbox", "info", "Generic addresses are usually shared by a team, not a single person.", tags=["info"])
        if mx.nxdomain:
            res.finding("Email domain does not exist (NXDOMAIN)", "low", "Undeliverable address: typo, expired domain or fake identity.", tags=["suspicious"])
        elif not accepts_mail or null_mx:
            res.finding("Email domain does not accept mail", "low", "No MX/A records (or a null MX): the address cannot receive email.", tags=["suspicious"])
        if free:
            res.finding(f"Free webmail provider ({domain})", "info", tags=["info"])
        res.raw = {"local": local, "domain": domain, "mx": mx.records, "free_provider": free}
        return res
