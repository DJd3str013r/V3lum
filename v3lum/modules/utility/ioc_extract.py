"""Extract indicators (IOCs) from free text or text files and pivot on each of them."""

from __future__ import annotations

import os

from v3lum.core.detect import extract_iocs
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult
from v3lum.core.module import Module, register

TEXT_EXT = {".txt", ".log", ".csv", ".json", ".md", ".eml", ".msg", ".html", ".htm", ".xml", ".yaml", ".yml", ".ini", ".conf", ".ioc", ".tsv", ""}
MAX_READ = 20 * 1024 * 1024


@register
class IocExtract(Module):
    name = "ioc_extract"
    title = "IOC extractor"
    description = "Pulls URLs, domains, IPs, emails, hashes, CVEs, ATT&CK ids, wallets, CNPJ/CPF... out of text (defanged forms included)."
    category = "utility"
    accepts = {T.TEXT, T.FILE}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.SHA512, T.CVE, T.MITRE, T.BTC, T.ETH}
    tags = {"offline"}
    max_pivots = 500

    def applies(self, entity: Entity, ctx: object) -> bool:
        if entity.type is T.FILE:
            ext = os.path.splitext(entity.value)[1].lower()
            return ext in TEXT_EXT and os.path.getsize(entity.value) <= MAX_READ
        return True

    def run(self, entity: Entity, ctx: object) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.FILE:
            with open(entity.value, encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_READ)
        else:
            text = entity.value
        iocs = extract_iocs(text)
        counts: dict[str, int] = {}
        for ioc in iocs:
            counts[ioc.type.value] = counts.get(ioc.type.value, 0) + 1
            res.pivot(ioc.type, ioc.value, "mentions", confidence=0.85)
        if iocs:
            res.finding(
                f"{len(iocs)} indicators extracted",
                "info",
                ", ".join(f"{n} {t}" for t, n in sorted(counts.items(), key=lambda kv: -kv[1])),
                data={"counts": counts},
                tags=["info"],
            )
        res.raw = {"indicators": [e.key for e in iocs]}
        return res
