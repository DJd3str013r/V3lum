"""Extract indicators (IOCs) from free text or text files and pivot on them.

Reference implementation (module contract v2) for offline modules (``disclosure='none'``: the
text never leaves the machine and ``ctx.http`` refuses every request):

* IOC_TYPES (domains, URLs, IPs, hashes, CVEs, ATT&CK ids, wallets...) pivot with ``expand=True``;
* PERSONAL_TYPES found in text (e-mail, phone...) pivot with ``expand=False`` - the analyst selects
  them (AR07; never auto-investigated from pasted text);
* CPF and SECRET_TYPES (JWTs, tokens, keys, cards) are never pivoted: they are counted and shown
  as masked previews only (team rule 4, A8);
* every other type (CNPJ, MAC...) is kept for analyst selection (``expand=False``).
"""

from __future__ import annotations

import os
from typing import Any

from v3lum.core.detect import extract_iocs
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, display_value
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

TEXT_EXT = {".txt", ".log", ".csv", ".json", ".md", ".eml", ".msg", ".html", ".htm", ".xml", ".yaml", ".yml", ".ini", ".conf", ".ioc", ".tsv", ""}
MAX_READ = 20 * 1024 * 1024
PERSONAL_NOTE = "personal identifier from text: analyst selection required"
OTHER_NOTE = "found in text: analyst selection required"
WITHHELD_TYPES = SECRET_TYPES | {T.CPF}


@register
class IocExtract(Module):
    name = "ioc_extract"
    title = "IOC extractor"
    description = "Pulls URLs, domains, IPs, emails, hashes, CVEs, ATT&CK ids, wallets, CNPJ... out of text (defanged forms included); CPF and secrets are only counted, masked."
    category = "utility"
    accepts = {T.TEXT, T.FILE}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.SHA512, T.CVE, T.MITRE, T.BTC, T.ETH}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    tags = {"offline"}
    max_pivots = 500

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            path = entity.value
            ext = os.path.splitext(path)[1].lower()
            # regular text files only: a FIFO or device would block or never end (not applicable)
            return ext in TEXT_EXT and os.path.isfile(path) and os.path.getsize(path) <= MAX_READ
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.FILE:
            try:
                with open(entity.value, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(MAX_READ)
            except OSError as exc:
                return res.mark("error", f"cannot read the file: {exc.strerror or type(exc).__name__}")
        else:
            text = entity.value
        iocs = extract_iocs(text)
        counts: dict[str, int] = {}
        withheld: dict[str, dict[str, Any]] = {}
        listed: list[str] = []
        for ioc in iocs:
            counts[ioc.type.value] = counts.get(ioc.type.value, 0) + 1
            if ioc.type in WITHHELD_TYPES:
                slot = withheld.setdefault(ioc.type.value, {"count": 0, "previews": []})
                slot["count"] += 1
                preview = display_value(ioc.type, ioc.value)
                if len(slot["previews"]) < 5 and preview not in slot["previews"]:
                    slot["previews"].append(preview)
                continue
            listed.append(ioc.key)
            if ioc.type in IOC_TYPES:
                res.pivot(ioc.type, ioc.value, "mentions", confidence=0.85)
            elif ioc.type in PERSONAL_TYPES:
                res.pivot(ioc.type, ioc.value, "mentions", confidence=0.85, expand=False, note=PERSONAL_NOTE)
            else:
                res.pivot(ioc.type, ioc.value, "mentions", confidence=0.85, expand=False, note=OTHER_NOTE)
        if iocs:
            summary = ", ".join(f"{n} {t}" for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
            res.finding(
                "Indicators extracted from text",
                "info",
                f"{len(iocs)} indicators: {summary}.",
                data={"counts": counts, "withheld": withheld},
                tags=["info"],
            )
        if withheld:
            res.finding(
                "CPF or secrets in the text (not pivoted)",
                "info",
                "Counted and shown masked only: CPF is never looked up and secrets are never sent anywhere.",
                data={"withheld": withheld},
                tags=["info"],
            )
        res.raw = {"indicators": listed, "withheld": withheld}
        return res
