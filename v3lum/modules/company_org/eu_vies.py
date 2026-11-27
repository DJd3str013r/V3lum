"""P225 EU VIES: is a European counterparty's VAT number registered? (batch p3-G10-1).

Council P225 final conditions, as implemented:

1. Input: the core ``eu_vat`` entity type (P333: a 2-letter EU prefix plus the national pattern and check
   digit, or an explicit ``eu_vat:`` type; never inferred from bare digits) and analyst-typed keywords that
   pass the same core validator (``validators.eu_vat_normalize``). A value that is both a valid EU VAT and a
   valid alphanumeric CNPJ (``NL100000009B20``) is ambiguous: not auto-typed, the analyst prefixes it.
2. Official VIES REST only (``ec.europa.eu/taxation_customs/vies/rest-api/ms/{CC}/vat/{number}``).
   VATComply is dropped (same service, unknown terms): ``api.vatcomply.com`` is never called or registered.
3. Tri-state: valid; invalid only when VIES answers ``isValid=false`` with no ``userError`` or the plain
   ``INVALID`` (VIES always sends one); ``MS_UNAVAILABLE``/``SERVICE_UNAVAILABLE`` -> UNAVAILABLE,
   ``MS_MAX_CONCURRENT_REQ``/``GLOBAL_MAX_CONCURRENT_REQ`` -> RATE_LIMITED, ``TIMEOUT`` -> ERROR timeout,
   ``IP_BLOCKED``/``VAT_BLOCKED`` -> BLOCKED, any other user error -> ERROR: could not verify, never
   'invalid', never cached. HTTP errors and timeouts likewise (raised by ``ctx.http``).
4. Single lookups of analyst-typed seeds only (no bulk validation, no pivots in). The returned name becomes
   a company_name pivot (relation ``vat_holder``, expand=False) only when it carries a legal-entity form
   (S.A., SARL, GmbH, BV, Ltd...) and the number is not person-shaped; a VAT number that may belong to a sole
   trader is personal data: never pivoted, and neither its name nor its address is displayed.
5. Opt-in (default_enabled=False). Official EC service, free; tier trusted.
"""

from __future__ import annotations

import json
import re
from typing import Any

from v3lum.core import validators
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org.registry_text import fold, text

VIES_URL = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{number}"
SOURCE = "european_commission.vies"
CACHE_TTL = 86400
#: userError -> (status, reason_code) for answers that could not verify (cond 3)
VIES_ERRORS = {
    "MS_UNAVAILABLE": (Status.UNAVAILABLE, "offline"),
    "SERVICE_UNAVAILABLE": (Status.UNAVAILABLE, "offline"),
    "TIMEOUT": (Status.ERROR, "timeout"),
    "MS_MAX_CONCURRENT_REQ": (Status.RATE_LIMITED, "rate_limited"),
    "GLOBAL_MAX_CONCURRENT_REQ": (Status.RATE_LIMITED, "rate_limited"),
    "IP_BLOCKED": (Status.BLOCKED, "challenge"),
    "VAT_BLOCKED": (Status.BLOCKED, "challenge"),
}
_LONG_FORMS = ("gmbh", "sarl", "sasu", "sas", "spa", "srl", "bvba", "cvba", "sprl", "eurl", "ltd", "limited", "plc", "llp", "oyj", "aps",
               "asa", "sro", "kft", "zrt", "nyrt", "eood", "ood", "ead", "uab", "teoranta", "dac", "ulc", "kgaa", "sca", "scs", "snc",
               "sicav", "sagl", "lda", "slu", "sau", "scrl", "doo", "ohg", "unipessoal", "spzoo", "inc", "corp", "corporation", "llc", "ltda")
_SHORT_FORMS = frozenset({"ag", "ab", "oy", "se", "kg", "dd", "sia", "ou", "as", "sa", "sl", "ad", "bt", "ks", "vos", "bv", "nv", "co"})
_PREFIX_FORMS = frozenset({"uab", "sia", "as", "ou", "ooo", "zao", "oao", "pao", "tov"})
_SOLE_TRADER = tuple(re.compile(p) for p in (
    r"\be\s?k\b", r"\be\s?kfm\b", r"\bei\b", r"\beirl\b", r"\bmicro ?entreprise\b", r"\bentreprise individuelle\b", r"\bditta individuale\b",
    r"\beenmanszaak\b", r"\bempresario individual\b", r"\bautonomo\b", r"\beinzelunternehmen\b", r"\benkeltmandsvirksomhed\b",
    r"\bjednoosobowa\b", r"\bosoba fizyczna\b", r"\bfysisk person\b", r"\bpf\b", r"\bpfa\b"))


def detect_vat(entity: Entity) -> tuple[str | None, str]:
    """(normalised VAT or None, reason). EU_VAT entities are already validated by the core; keywords must
    pass the same validator and must not also be a valid alphanumeric CNPJ (cond 1)."""
    if entity.type is T.EU_VAT:
        return str(entity.value), ""
    raw = text(entity.value)
    explicit = raw.lower().startswith("eu_vat:")
    if explicit:
        raw = raw[7:]
    try:
        vat = validators.eu_vat_normalize(raw)
    except ValueError as exc:
        return None, f"not an EU VAT number ({exc}): a 2-letter EU prefix plus the national format and check digit, or eu_vat:"
    if not explicit and validators.cnpj_valid(re.sub(r"[\s./-]", "", raw).upper()):
        return None, "ambiguous: both a valid EU VAT number and a valid alphanumeric CNPJ - type it as eu_vat: or cnpj:"
    return vat, ""


def holder_hint(cc: str, number: str) -> str | None:
    """Number shapes that belong to natural persons (personal data, cond 4) -> 'natural_person' | None."""
    n = text(number).upper()
    if (cc == "CZ" and len(n) in (9, 10)) or (cc == "BG" and len(n) == 10):
        return "natural_person"
    if cc == "ES" and (re.fullmatch(r"\d{8}[A-Z]", n) or n[:1] in "KLMXYZ"):
        return "natural_person"
    if (cc == "PT" and n[:1] in "123") or (cc == "LV" and n[:1] in "0123"):
        return "natural_person"
    return None


def _merge_initials(tokens: list[str]) -> list[str]:
    """['core', 's', 'a', 'r', 'l'] -> ['core', 'sarl']."""
    out, run = [], ""
    for t in tokens:
        if len(t) == 1:
            run += t
            continue
        if run:
            out.append(run)
            run = ""
        out.append(t)
    if run:
        out.append(run)
    return out


def legal_form(name: Any) -> str | None:
    """The legal-entity form in a VIES name ('sarl', 'as', 'gmbh'...), or None for sole traders and names
    without a form (possible natural persons)."""
    s = fold(name)
    if not s or s.strip() in ("---", "-", "n/a"):
        return None
    flat = re.sub(r"\s+", " ", re.sub(r"[./,()&'\"`:;´-]", " ", s)).strip()
    if any(rx.search(flat) for rx in _SOLE_TRADER):
        return None
    toks = _merge_initials(flat.split())
    if not toks:
        return None
    if re.search(r"(?:^| )sp z?oo(?: |$)", " ".join(toks)):
        return "spzoo"
    for form in _LONG_FORMS:
        if form in toks:
            return form
    if len(toks) > 1 and toks[-1] in _SHORT_FORMS:
        return toks[-1]
    if len(toks) > 1 and toks[0] in _PREFIX_FORMS:
        return toks[0]
    return None


def holder(name: Any, cc: str, number: str) -> str:
    """'legal_entity' | 'possible_sole_trader' | 'unknown' (name withheld by the member state)."""
    n = text(name)
    if not n or n in ("---", "-"):
        return "unknown"
    if holder_hint(cc, number) == "natural_person":
        return "possible_sole_trader"
    return "legal_entity" if legal_form(n) else "possible_sole_trader"


def _cacheable(resp: Any) -> bool:
    """Only definitive answers (VALID / INVALID) are cached (cond 3)."""
    try:
        doc = json.loads(resp.content)
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False
    return isinstance(doc, dict) and text(doc.get("userError")).upper() in ("VALID", "INVALID", "") and isinstance(doc.get("isValid"), bool)


@register
class EuVies(Module):
    name = "eu_vies"
    title = "EU VIES VAT validation"
    description = (
        "Validates an analyst-typed EU VAT number against the European Commission's VIES REST service (valid / not valid / "
        "could not verify); a legal entity's registered name becomes a company-name hint, sole traders are never exposed."
    )
    category = "company_org"
    accepts = {T.EU_VAT, T.KEYWORD}
    produces = {T.ORG}
    tags = {"free"}
    reference = "https://ec.europa.eu/taxation_customs/vies/"
    notice = (
        "Official EC VIES service; single lookups of analyst-typed VAT numbers only (no bulk validation). Member-state outages "
        "(MS_UNAVAILABLE) are 'could not verify', never 'invalid'. A VAT number that may belong to a sole trader is personal data: "
        "its name and address are never shown or pivoted."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the Commission (and the member state) receive the VAT number
    hosts = ("ec.europa.eu",)
    provider = "european_commission"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    max_requests = 1  # cond 4: one lookup per seed
    expected_latency = 1.0  # ~0.5 s p50, member-state back-ends up to ~11 s
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = CACHE_TTL
    max_pivots = 1
    default_enabled = False  # cond 5

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        unconfirmed = set(getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or ())
        if not (bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0 and entity.key not in unconfirmed):
            return res.mark(Status.SKIPPED, "VIES validates analyst-typed seeds only (no bulk validation, no pivots; P225 cond 4)",
                            reason_code="not_applicable")
        vat, why = detect_vat(entity)
        if not vat:
            return res.mark(Status.SKIPPED, why, reason_code="not_applicable")
        cc, number = vat[:2], vat[2:]
        url = VIES_URL.format(cc=cc, number=number)
        doc = ctx.http.get_json(url, source=SOURCE, cache_if=_cacheable)
        if not isinstance(doc, dict) or not isinstance(doc.get("isValid"), bool):
            raise HttpError("unexpected VIES answer: could not verify", 200, url)
        user_error = text(doc.get("userError")).upper()
        state: dict[str, Any] = {"vat": vat, "country": cc, "request_date": text(doc.get("requestDate")) or None}
        if user_error not in ("", "VALID", "INVALID"):
            status, code = VIES_ERRORS.get(user_error, (Status.ERROR, "error"))
            res.attr("vat_validation", {**state, "state": "not_verified", "reason": user_error})
            return res.mark(status, f"VIES could not verify {vat} ({user_error}): never read as 'invalid'", reason_code=code)
        if doc["isValid"] is False:
            if user_error not in ("", "INVALID"):  # pragma: no cover - guarded above
                raise HttpError("ambiguous VIES answer: could not verify", 200, url)
            res.attr("vat_validation", {**state, "state": "invalid"})
            res.finding(
                "EU VAT number not valid according to VIES",
                "low",
                f"VIES answered isValid=false for {vat} (member-state register: not registered or no longer valid for "
                "intra-EU transactions).",
                confidence="probable",
                criterion="VIES isValid=false with userError INVALID (the member-state register answered; outages are never read as invalid)",
                tags=["context_only"],
                source=SOURCE,
            )
            return res
        name = text(doc.get("name"))
        kind = holder(name, cc, number)
        info = {**state, "state": "valid", "holder": kind}
        if kind == "legal_entity":
            info.update({"legal_form": legal_form(name), "name": name,
                         "address": (text(doc.get("address")) or None) if text(doc.get("address")) not in ("---", "-") else None})
            res.pivot(T.ORG, name, "vat_holder", confidence="confirmed", expand=False,
                      note=f"registered holder of EU VAT {vat} per VIES (legal-entity form '{info['legal_form']}')")
        res.attr("vat_validation", info)
        res.raw = {"vat": vat, "state": "valid", "holder": kind, "request_date": state["request_date"]}
        return res
