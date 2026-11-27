"""Extract indicators (IOCs) from free text or text files and pivot on them.

Reference implementation (module contract v2) for offline modules (``disclosure='none'``: the
text never leaves the machine and ``ctx.http`` refuses every request). A thin wrapper over the
P172 engine :func:`v3lum.core.ioc.extract` (decode layers, refang, span-masked extraction,
validation, warninglist/org/recipient-token annotation):

* IOC_TYPES (domains, URLs, IPs, hashes, CVEs, ATT&CK ids, wallets...) pivot with ``expand=True``
  unless the engine flagged them (private/bogon IPs, file-name lookalikes, warninglisted, org-profile
  or recipient-token values, unverified ATT&CK ids): those are listed with ``expand=False``;
* PERSONAL_TYPES found in text (e-mail, phone, Telegram/Discord/social accounts, PIX BR Codes...)
  pivot with ``expand=False`` - the analyst selects them (AR07; never auto-investigated from text);
* CPF, IBAN and SECRET_TYPES (secrets as fingerprints, cards as ``BIN6…last4``) are never pivoted:
  they are counted and shown as masked previews only (team rule 4, A8, P323 cond 7);
* every other type (CNPJ, MAC, malware/actor names...) is kept for analyst selection (``expand=False``).

Each pivot note ends with the IOC's provenance in the text ('line 3, chars 120-135'); the first
finding carries the one-line preview ('37 IOCs: 12 domains, 5 IPs, 4 low-confidence').
"""

from __future__ import annotations

import os
from typing import Any

from v3lum.core import ioc as _ioc
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, SECRET_TYPES, Entity, display_value
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

TEXT_EXT = {".txt", ".log", ".csv", ".json", ".md", ".eml", ".msg", ".html", ".htm", ".xml", ".yaml", ".yml", ".ini", ".conf", ".ioc", ".tsv", ""}
MAX_READ = 20 * 1024 * 1024
PERSONAL_NOTE = "personal identifier from text: analyst selection required"
OTHER_NOTE = "found in text: analyst selection required"
FLAGGED_NOTE = "listed, not auto-investigated"
WITHHELD_TYPES = SECRET_TYPES | {T.CPF}
#: masked kinds the engine counts without creating entities
MASKED_KINDS = ("cpf", "iban")
#: at most this many IOCs keep their provenance in res.raw
RAW_IOCS = 1000


def _note(base: str, item: _ioc.ExtractedIOC) -> str:
    return f"{base} ({item.provenance})" if base else item.provenance


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
            ext = os.path.splitext(entity.value)[1].lower()
            source_type = "email" if ext in (".eml", ".msg") else "html" if ext in (".html", ".htm") else "file"
        else:
            text = entity.value
            source_type = "text"
        try:
            org = getattr(ctx, "org", None)
        except Exception:  # noqa: BLE001 - a broken org profile never stops extraction
            org = None
        result = _ioc.extract(text, source_type=source_type, org=org)
        counts: dict[str, int] = dict(result.counts)
        withheld: dict[str, dict[str, Any]] = {}
        listed: list[str] = []
        provenance: list[dict[str, Any]] = []
        pivots = 0
        for item in result.entities:
            ent = item.entity
            if ent.type in WITHHELD_TYPES:
                slot = withheld.setdefault(ent.type.value, {"count": 0, "previews": []})
                slot["count"] += 1
                preview = display_value(ent.type, ent.value)
                if len(slot["previews"]) < 5 and preview not in slot["previews"]:
                    slot["previews"].append(preview)
                continue
            listed.append(ent.key)
            if len(provenance) < RAW_IOCS:
                provenance.append({"entity": ent.key, "line": item.line, "span": list(item.span), "confidence": item.confidence,
                                   "defanged": item.defanged, "flags": sorted(item.flags), "source": item.source})
            if pivots >= self.max_pivots:
                continue
            pivots += 1
            conf = min(0.85, item.confidence)
            if ent.type in IOC_TYPES and item.expand:
                res.pivot(ent.type, ent.value, "mentions", confidence=conf, note=_note("", item))
            elif ent.type in IOC_TYPES:
                why = ", ".join(sorted(item.flags & _ioc.NO_EXPAND_FLAGS))
                res.pivot(ent.type, ent.value, "mentions", confidence=conf, expand=False, note=_note(f"{FLAGGED_NOTE}: {why}", item))
            elif ent.type in PERSONAL_TYPES:
                res.pivot(ent.type, ent.value, "mentions", confidence=conf, expand=False, note=_note(PERSONAL_NOTE, item))
            else:
                res.pivot(ent.type, ent.value, "mentions", confidence=conf, expand=False, note=_note(OTHER_NOTE, item))
        for kind in MASKED_KINDS:
            slot = result.masked.get(kind)
            if slot:
                withheld[kind] = {"count": int(slot["count"]), "previews": list(slot["previews"])[:5]}
        if result.entities or withheld:
            total = sum(counts.values())
            summary = ", ".join(f"{n} {t}" for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
            res.finding(
                "Indicators extracted from text",
                "info",
                f"{result.preview()}. {total} indicators: {summary}.",
                data={"counts": counts, "withheld": withheld, "preview": result.preview(), "limit_hit": result.limit_hit,
                      "decoded": result.decoded, "notes": list(result.notes)},
                tags=["info"],
            )
        if withheld:
            res.finding(
                "CPF or secrets in the text (not pivoted)",
                "info",
                "Counted and shown masked only: CPF is never looked up and secrets are never sent anywhere "
                "(sensitive data in pasted text).",
                data={"withheld": withheld},
                tags=["info"],
            )
        if result.limit_hit:
            res.finding(
                "IOC limit reached",
                "info",
                f"Only the first {result.limit} distinct indicators were extracted; split the text to see the rest.",
                data={"limit": result.limit},
                tags=["info"],
            )
        res.raw = {"indicators": listed, "withheld": withheld, "iocs": provenance, "notes": list(result.notes)}
        return res
