"""Chainabuse community scam reports for wallets and domains (TRM Labs; keyed) (P204).

Final conditions (P204):

* cond 1 - GET https://api.chainabuse.com/v0/reports?address=<a>&page=1&perPage=50 with HTTP Basic auth
  (the API key as user name and password, per the Chainabuse docs 'Screening addresses'), key
  ``chainabuse``; one page (page cap: a standard key allows 10 calls a month, 1 call = at most 50
  reports). Addresses are validated with the core validators (P217) before sending; domains are
  accepted too (same ``address`` parameter).
* cond 2 - the Chainabuse Terms of Use (TRM Labs, 2025-01-20) license content 'solely for your personal,
  non-commercial use': terms 'noncommercial', so the policy gate keeps the module off under the
  corporate profile until a licence_allow entry backed by TRM Labs' written commercial permission
  clears ``trm_chainabuse.reports_api``.
* cond 3 - wording 'N community reports (unverified): categories, last report <date>'. Kept: category,
  report count, first/last date, checked/trusted flags; free-text descriptions are masked (e-mails,
  phones, CPF/CNPJ, cards, IBANs, @handles, URL queries) and kept as short excerpts only.
* cond 4 - 1-2 reports -> suspicious (low); >= 3 reports or a checked/trusted flag -> fraud (medium);
  never above medium here: the correlation rule ``p2g09_chainabuse_corroborated`` raises it only with
  sanctions (P205), GoPlus, ransomware or explorer-label corroboration. Categories -> tags (fraud,
  ransomware, phishing, extortion); one consensus vote.
* cond 5 - without a key (NEEDS_KEY) or licence (SKIPPED licence) the engine emits the manual
  Chainabuse address-page link (``manual_link``, a client-rendered page). The success/empty fixtures are
  synthetic until a team key exists (backlog); the 401 body is the real keyless answer.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.redact import register_secret
from v3lum.core.validators import crypto_address_info
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import fold, parse_day, safe_plain

SOURCE = "trm_chainabuse.reports_api"
KEY = "chainabuse"
REPORTS_URL = "https://api.chainabuse.com/v0/reports"
ADDRESS_PAGE = "https://www.chainabuse.com/address/{address}"
PER_PAGE = 50
MAX_EXCERPTS = 3
EXCERPT_LEN = 120
MAX_RELATED = 10

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PHONE_RE = re.compile(r"(?<![\w.+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,3}\)\s?|\d{2,3}[\s.-]?)\d{3,5}[\s.-]?\d{4}(?!\w)")
_LOCAL_PHONE_RE = re.compile(r"(?<![\w.+/-])\d{4,5}-\d{4}(?![\w-])")
_HANDLE_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,32}\b")
_URL_QUERY_RE = re.compile(r"(https?://[^\s?#]+)[?#][^\s]*", re.I)
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}\b")


def mask_pii(text: Any) -> str:
    """Mask personal data in user-submitted free text (P204 cond 3): e-mails, URL queries, CPF/CNPJ, IBANs,
    phone numbers (BR formats included), card numbers and @handles. Crypto addresses and domains stay
    (they are the reported indicators)."""
    out = safe_plain(text, 4000)
    out = _EMAIL_RE.sub("[email]", out)
    out = _URL_QUERY_RE.sub(r"\1", out)
    out = _CNPJ_RE.sub("[cnpj]", out)
    out = _CPF_RE.sub("[cpf]", out)
    out = _IBAN_RE.sub("[iban]", out)
    out = _PHONE_RE.sub("[phone]", out)
    out = _LOCAL_PHONE_RE.sub("[phone]", out)
    out = _CARD_RE.sub(lambda m: "[card]" if len(re.sub(r"\D", "", m.group(0))) >= 13 else m.group(0), out)
    return _HANDLE_RE.sub("[handle]", out)


def _first(record: Any, *names: str) -> Any:
    for name in names:
        if isinstance(record, dict) and record.get(name) not in (None, ""):
            return record.get(name)
    return None


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in ("1", "true", "yes")


def category_tags(categories: Any) -> list[str]:
    """Scam categories -> descriptive tags (P204 cond 4): ransomware, phishing, extortion. 'fraud' is the
    medium verdict tag (see :func:`assess`)."""
    tags: set[str] = set()
    for category in categories or []:
        folded = fold(category)
        if "ransom" in folded:
            tags.add("ransomware")
        if "phish" in folded or "impersonat" in folded:
            tags.add("phishing")
        if "sextortion" in folded or "blackmail" in folded or "extortion" in folded:
            tags.add("extortion")
    return sorted(tags)


def assess(count: int, checked_or_trusted: bool) -> tuple[str | None, str | None]:
    """(severity, verdict tag) per P204 cond 4: 1-2 unverified reports -> low/'suspicious'; >= 3 reports or a
    checked/trusted flag -> medium/'fraud'; never above medium without corroboration (correlation rule)."""
    if count <= 0:
        return None, None
    if count >= 3 or checked_or_trusted:
        return "medium", "fraud"
    return "low", "suspicious"


def parse_reports(doc: Any, queried: str = "") -> dict[str, Any]:
    """GET /v0/reports answer -> summary (P204 cond 1, 3, 4). Tolerant schema: a list, or {'reports'|'data'|
    'items': [...]} (no keyed capture yet); per report scamCategory/category, createdAt, checked, trusted,
    description, addresses[{address, chain, domain}]. Unmasked free text never leaves this function."""
    out: dict[str, Any] = {"status": "error", "count": 0, "categories": {}, "first_report": None, "last_report": None, "checked": 0,
                           "trusted": 0, "chains": [], "excerpts": [], "related": [], "page_cap_reached": False, "reason": ""}
    reports = doc
    if isinstance(doc, dict):
        reports = next((doc[k] for k in ("reports", "data", "items") if isinstance(doc.get(k), list)), None)
        if reports is None:
            message = safe_plain(doc.get("message") or doc.get("error"), 120)
            out["reason"] = f"Chainabuse: {message}: could not verify" if message else "Chainabuse answer has no report list: could not verify"
            return out
    if not isinstance(reports, list):
        out["reason"] = "Chainabuse answered an unexpected JSON type: could not verify"
        return out
    wanted = str(queried or "").strip().lower()
    days: list[str] = []
    related: list[str] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        out["count"] += 1
        category = _first(report, "scamCategory", "category", "scam_category")
        if isinstance(category, dict):
            category = _first(category, "name", "label", "id")
        name = safe_plain(category, 60) or "uncategorised"
        out["categories"][name] = out["categories"].get(name, 0) + 1
        day = parse_day(_first(report, "createdAt", "created_at", "reportedAt", "date"))
        if day:
            days.append(day)
        out["checked"] += 1 if _flag(_first(report, "checked", "isChecked")) else 0
        out["trusted"] += 1 if _flag(_first(report, "trusted", "isTrusted")) else 0
        description = _first(report, "description", "scamDescription")
        if isinstance(description, str) and len(out["excerpts"]) < MAX_EXCERPTS:
            masked = safe_plain(mask_pii(description), EXCERPT_LEN)
            if masked:
                out["excerpts"].append(masked)
        for item in report.get("addresses") if isinstance(report.get("addresses"), list) else []:
            address = item.get("address") if isinstance(item, dict) else item
            chain = item.get("chain") if isinstance(item, dict) else None
            domain = item.get("domain") if isinstance(item, dict) else None
            if isinstance(chain, str) and chain.strip() and safe_plain(chain, 20) not in out["chains"]:
                out["chains"].append(safe_plain(chain, 20))
            for candidate in (address, domain):
                if isinstance(candidate, str) and candidate.strip() and candidate.strip().lower() != wanted:
                    value = safe_plain(candidate, 120)
                    if value not in related:
                        related.append(value)
    out["related"] = related[:MAX_RELATED]
    out["page_cap_reached"] = len(reports) >= PER_PAGE
    if not out["count"]:
        out["status"] = "empty"
        return out
    out["status"] = "found"
    out["first_report"] = min(days) if days else None
    out["last_report"] = max(days) if days else None
    return out


def wording(summary: dict[str, Any]) -> str:
    """'N community reports (unverified): <categories>, last report <date>' (P204 cond 3)."""
    count = summary.get("count", 0)
    cats = ", ".join(f"{n} ({c})" if c > 1 else n for n, c in sorted(summary.get("categories", {}).items(), key=lambda x: (-x[1], x[0])))
    text = f"{count} community report{'s' if count != 1 else ''} (unverified): {cats or 'uncategorised'}, last report {summary.get('last_report') or 'date unknown'}"
    flags = []
    if summary.get("checked"):
        flags.append(f"{summary['checked']} checked by Chainabuse")
    if summary.get("trusted"):
        flags.append(f"{summary['trusted']} from trusted contributors")
    return text + ("; " + ", ".join(flags) if flags else "")


def basic_auth(key: str) -> str:
    """'Basic base64(key:key)': the API key as user name and password (Chainabuse docs). The encoded form is
    registered with the redactor so it never reaches logs or evidence."""
    token = base64.b64encode(f"{key}:{key}".encode()).decode("ascii")
    register_secret(token, "chainabuse basic auth")
    return f"Basic {token}"


@register
class Chainabuse(Module):
    name = "chainabuse"
    title = "Chainabuse community scam reports (keyed)"
    description = (
        "Community scam reports (user-submitted, unverified) for a crypto address or a domain from Chainabuse (TRM Labs): "
        "report count, categories, first/last report date, checked/trusted flags and masked excerpts."
    )
    category = "crypto"
    accepts = {T.BTC, T.ETH, T.CRYPTO, T.DOMAIN}
    tags = {"reputation"}
    reference = "https://docs.chainabuse.com/docs/welcome-to-chainabuse-api"
    notice = (
        "Chainabuse Terms of Use: content licensed 'solely for your personal, non-commercial use' - off under the corporate "
        "profile until licence-cleared (TRM Labs' written commercial permission in licence_allow). Reports are user-submitted "
        "and unverified."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Chainabuse (TRM Labs) receives the address or domain
    provider = "trm_chainabuse"
    sources = (SOURCE,)
    hosts = ("api.chainabuse.com",)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    max_requests = 1  # page cap: one page of 50 reports (10 calls a month on a standard key)
    expected_latency = 1.0
    timeout = 15.0
    min_interval = 2.0
    cache_ttl = 86400
    manual_link = "https://www.chainabuse.com/address/{q}"
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.DOMAIN:
            return True
        return crypto_address_info(str(entity.value).strip()) is not None  # P217: never send an invalid address

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        value = str(entity.value).strip()
        if entity.type is not T.DOMAIN and crypto_address_info(value) is None:
            return res.mark("skipped", "not a valid crypto address (core validators): never sent", reason_code="not_applicable")
        key = ctx.key(KEY)
        if not key:
            return res.mark("needs_key", "Chainabuse needs the 'chainabuse' key (V3LUM_CHAINABUSE_KEY)")
        doc = ctx.http.get_json(
            REPORTS_URL,
            params={"address": value, "page": 1, "perPage": PER_PAGE},
            headers={"Authorization": basic_auth(key)},
            source=SOURCE,
            allow_redirects=False,  # keyed request: no redirects (AR01)
        )
        summary = parse_reports(doc, value)
        if summary["status"] == "error":
            return res.mark("error", summary["reason"])
        page = ADDRESS_PAGE.format(address=quote(value, safe=""))
        res.link("Chainabuse page (client-rendered; reports are unverified)", page)
        as_of = ctx.now().date().isoformat()
        if summary["status"] == "empty":
            res.attr("chainabuse_reports", {"count": 0, "wording": f"0 community reports on Chainabuse (as of {as_of})"})
            res.raw = {"count": 0}
            return res.mark("empty")
        severity, verdict = assess(summary["count"], bool(summary["checked"] or summary["trusted"]))
        text = wording(summary)
        kept = {k: summary[k] for k in ("count", "categories", "first_report", "last_report", "checked", "trusted", "chains", "excerpts", "related", "page_cap_reached")}
        kept["wording"] = text
        res.attr("chainabuse_reports", kept)
        more = " At least 50 reports exist: only the first page was read (page cap)." if summary["page_cap_reached"] else ""
        tags = sorted({t for t in [verdict, *category_tags(summary["categories"])] if t})
        res.finding(
            "Community scam reports on Chainabuse (unverified)",
            severity or "low",
            f"{text}.{more} Reports are user-submitted and unverified: a lead, not proof; corroborate before acting "
            f"(sanctions lists, GoPlus, explorer labels). Data as of {as_of}.",
            confidence="probable" if severity == "medium" else "possible",
            criterion=(
                ">= 3 community reports or a report checked by Chainabuse / from a trusted contributor (P204 cond 4)"
                if severity == "medium" else "1-2 unverified community reports (P204 cond 4)"
            ),
            data=kept,
            tags=tags,
            source=SOURCE,
            observed_first=summary["first_report"],
            observed_last=summary["last_report"],
        )
        res.raw = kept
        return res


__all__ = ["Chainabuse", "assess", "basic_auth", "category_tags", "mask_pii", "parse_reports", "wording"]
