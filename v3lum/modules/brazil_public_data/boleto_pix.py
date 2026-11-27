"""Boleto and PIX BR Code parsers with offline bank tables (P233): tampered payment codes, fully offline.

* boleto (cond 1, 2): bancario (47) and arrecadacao (48) lines and 44-digit barcodes, field DVs mod 10
  and the general DV mod 11 (arrecadacao: mod 10 or the mod-11 variant by the value type); the due
  date from both factor cycles (the factor wrapped on 2025-02-22), the nearest to today chosen and an
  ambiguous factor shown with both dates;
* PIX BR Code (cond 3): bounded EMV TLV parse (<= 512 bytes, depth 2), merchant account template 26-51
  with br.gov.bcb.pix, CRC16/CCITT-FALSE through '6304' (BCB manual vector 1D3D);
* keys (cond 4): CPF keys masked and never pivoted; e-mail and phone keys become entities (relation
  pix_key_of) with expand=False - no automatic breach, stealer, username or phone-reputation lookup;
  CNPJ keys pivot to the P236 CNPJ chain (who receives the money); merchant names of natural persons
  are never pivoted;
* dynamic BR Codes (cond 5): the location URL is never fetched in any mode; only its host becomes a
  domain pivot with expand=False and the URL stays the masked attribute ``pix_location_url``;
* verdicts (cond 6-8): a plain-language line first; a barcode bank that differs from the bank named
  in the document is HIGH 'boleto bank mismatch: possible tampering' (PROBABLE); a PIX payee that
  does not match the brand the text claims (org-profile brands, bank names) is MEDIUM 'payee differs
  from claimed brand'; neither is ever labelled malicious; a check-digit or CRC failure reads
  'invalid or altered code (typed or altered line)', or 'could not verify (OCR)' for OCR/QR inputs;
* bank tables (cond 9): BCB STR participants (trusted), BrasilAPI banks and PIX participants
  (community) as full-list datasets refreshed weekly by `v3lum data update`, plus a bundled BCB
  snapshot so triage works offline; never per-value API calls (disclosure 'none'). Each table shows
  its refresh date.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import br_parsers as P

try:  # P360 (batch p1-G10-3): BCB-verified institution domains and conglomerate CNPJ roots (cond 6 claimed brands)
    from v3lum.modules.brazil_public_data import bcb_authorized_institutions as _p360
except ImportError:  # pragma: no cover - without P360: org-profile brands and the bank tables only
    _p360 = None

# --------------------------------------------------------------------------------------
# datasets (P233 cond 9): full lists, weekly, through the dataset manager only
# --------------------------------------------------------------------------------------

DS_STR = "boleto_pix_bcb_str"
DS_BANKS = "boleto_pix_brasilapi_banks"
DS_PIX = "boleto_pix_brasilapi_pix"
STR_URL = "https://www.bcb.gov.br/content/estabilidadefinanceira/str1/ParticipantesSTR.csv"
BANKS_URL = "https://brasilapi.com.br/api/banks/v1"
PIX_URL = "https://brasilapi.com.br/api/pix/v1/participants"
SRC_STR = "bcb.str_participants"
SRC_BANKS = "brasilapi.banks"
WEEK = 7 * 86400
#: The bundled BCB snapshot (ParticipantesSTR.csv as served, Last-Modified 2026-11-25).
BUNDLED_STR = "boleto_pix/bcb_str_participants.csv"
BUNDLED_STR_DATE = "2026-11-25"
BCB_ATTRIBUTION = "Fonte: Banco Central do Brasil (ParticipantesSTR.csv, STR participants)"
BRASILAPI_ATTRIBUTION = "BrasilAPI (MIT licence) relaying Banco Central do Brasil data"
#: A copy older than this is shown as stale (the tables are refreshed weekly).
STALE_DAYS = 14
MAX_CODES = 20  # payment codes analysed in one text
MAX_READ = 20 * 1024 * 1024
TEXT_EXT = {".txt", ".log", ".csv", ".json", ".md", ".eml", ".html", ".htm", ".xml", ""}


def _validate_with(parser: Any, min_rows: int, what: str) -> Any:
    def validate(path: Path) -> bool:
        parsed = parser(Path(path).read_bytes())
        reason = P.validate_table(parsed, min_rows=min_rows, what=what)
        if reason:
            raise ValueError(reason)
        return True

    return validate


validate_str_file = _validate_with(P.parse_bcb_str_csv, P.STR_MIN_ROWS, "STR participants")
validate_banks_file = _validate_with(P.parse_brasilapi_banks, P.BRASILAPI_BANKS_MIN_ROWS, "BrasilAPI banks")
validate_pix_file = _validate_with(P.parse_brasilapi_pix_participants, P.PIX_PARTICIPANTS_MIN_ROWS, "BrasilAPI PIX participants")

register_dataset(
    DS_STR, STR_URL, ttl=WEEK, description="BCB STR participants (bank code / ISPB table; UTF-8 BOM, ',' separated) for boleto_pix (P233)",
    licence="Brazilian open government data (Banco Central do Brasil public information, Lei 12.527/2011)", terms_class="open",
    attribution=BCB_ATTRIBUTION, provider="bcb", source=SRC_STR, validate=validate_str_file, min_bytes=10_000, expect="csv",
    max_bytes=2_000_000, large=False, essential=True,
)
register_dataset(
    DS_BANKS, BANKS_URL, ttl=WEEK, description="BrasilAPI banks v1 full list (code, ISPB, names) for boleto_pix (P233)",
    licence="MIT (BrasilAPI code); Banco Central do Brasil data", terms_class="open", attribution=BRASILAPI_ATTRIBUTION,
    provider="brasilapi", source=SRC_BANKS, validate=validate_banks_file, min_bytes=20_000, expect="json", max_bytes=5_000_000, large=False,
)
register_dataset(
    DS_PIX, PIX_URL, ttl=WEEK, description="BrasilAPI PIX participants full list (ISPB, names) for boleto_pix (P233)",
    licence="MIT (BrasilAPI code); Banco Central do Brasil data", terms_class="open", attribution=BRASILAPI_ATTRIBUTION,
    provider="brasilapi", source=SRC_BANKS, validate=validate_pix_file, min_bytes=20_000, expect="json", max_bytes=5_000_000, large=False,
)

#: A local copy is read with this TTL: the module itself never refreshes a table (cond 9:
#: `v3lum data update` does), so a present copy of any age is served without a request.
_NEVER_REFRESH = 10 * 365 * 86400.0
_TABLES = ((DS_STR, "BCB STR participants", P.parse_bcb_str_csv), (DS_BANKS, "BrasilAPI banks", P.parse_brasilapi_banks),
           (DS_PIX, "BrasilAPI PIX participants", P.parse_brasilapi_pix_participants))
_MEMO: dict[str, tuple[Any, dict[str, Any]]] = {}
_LOCK = threading.Lock()
#: hosts read from one text when looking for BCB-verified institution domains (cond 6)
MAX_TEXT_HOSTS = 200
_HOST_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-]|\.[a-z0-9])")
_LEGAL_TAIL = re.compile(r"(?:\s+(?:s\s?a|ltda|me|epp|eireli))+$")


def _stamp(path: Path) -> tuple[str, int, int, int]:
    st = Path(path).stat()
    return (str(path), st.st_ino, st.st_size, st.st_mtime_ns)


def _parsed_table(name: str, parser: Any, path: Path) -> dict[str, Any]:
    stamp = _stamp(path)
    with _LOCK:
        hit = _MEMO.get(name)
        if hit and hit[0] == stamp:
            return hit[1]
    parsed = parser(Path(path).read_bytes())
    with _LOCK:
        _MEMO[name] = (stamp, parsed)
    return parsed


def load_bank_index(ctx: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The bank index from the local tables (BCB STR first, BrasilAPI fills gaps) and one line per
    table {table, source, refreshed, stale}; the bundled BCB snapshot replaces a missing STR copy.
    Never downloads anything."""
    rows: dict[str, list[dict[str, Any]]] = {}
    tables: list[dict[str, Any]] = []
    now = ctx.now()
    for name, label, parser in _TABLES:
        try:
            info = ctx.data.info(name)
        except (ValueError, OSError):
            info = None
        parsed: dict[str, Any] | None = None
        if info is not None and info.present:
            try:
                parsed = _parsed_table(name, parser, ctx.data.fetch(name, ttl=_NEVER_REFRESH))
            except (DatasetError, OSError, ValueError) as exc:
                tables.append({"table": label, "source": "dataset", "refreshed": None, "stale": True, "problem": str(exc)[:160]})
                parsed = None
            else:
                fetched = (info.fetched_at or "")[:10] or None
                age_days = (info.age_hours or 0) / 24 if info.age_hours is not None else None
                if parsed.get("ok"):
                    tables.append({"table": label, "source": "dataset", "refreshed": fetched, "stale": bool(age_days is None or age_days > STALE_DAYS)})
                else:
                    tables.append({"table": label, "source": "dataset", "refreshed": fetched, "stale": True, "problem": parsed.get("error")})
                    parsed = None
        if parsed is None and name == DS_STR:
            parsed = _bundled_str(ctx)
            if parsed.get("ok"):
                tables.append({"table": label, "source": "bundled snapshot", "refreshed": BUNDLED_STR_DATE,
                               "stale": _age_days(now, BUNDLED_STR_DATE) > STALE_DAYS})
        if parsed is not None and parsed.get("ok"):
            rows[name] = parsed["entries"]
        elif not any(t["table"] == label for t in tables):
            tables.append({"table": label, "source": "not downloaded", "refreshed": None, "stale": True})
    index = P.build_bank_index(rows.get(DS_STR, ()), rows.get(DS_BANKS, ()), rows.get(DS_PIX, ()))
    return index, tables


def _bundled_str(ctx: Any) -> dict[str, Any]:
    with _LOCK:
        hit = _MEMO.get(BUNDLED_STR)
        if hit:
            return hit[1]
    try:
        parsed = P.parse_bcb_str_csv(ctx.data.bundled_text(BUNDLED_STR))
    except (OSError, ValueError) as exc:
        parsed = {"ok": False, "error": f"bundled snapshot unreadable: {exc}"}
    with _LOCK:
        _MEMO[BUNDLED_STR] = (None, parsed)
    return parsed


def _age_days(now: Any, iso_date: str) -> float:
    try:
        from datetime import date

        return float((now.date() - date.fromisoformat(iso_date)).days)
    except (ValueError, AttributeError):
        return 0.0


# --------------------------------------------------------------------------------------
# input origin (cond 7): typed or pasted vs OCR (P363) / QR decode (P261)
# --------------------------------------------------------------------------------------

_OCR_RE = re.compile(r"(?:^|[_\-.])ocr(?:$|[_\-.])|ocr_text|image_text", re.I)
_QR_RE = re.compile(r"(?:^|[_\-.])qr(?:code)?(?:$|[_\-.])|qr_decode|qr_payload|decoded_qr", re.I)


def input_origin(ctx: Any) -> str:
    """'ocr' or 'qr' when the entity was pivoted by an OCR or QR-decoding module (name or relation
    mentions it), else 'typed'. A failed check digit then reads 'could not verify (OCR)'."""
    try:
        steps = tuple(ctx.provenance or ())
    except AttributeError:
        steps = ()
    if not steps:
        return "typed"
    last = steps[-1]
    relation = str(last[1]) if len(last) > 1 else ""
    module = str(last[2]) if len(last) > 2 else ""
    for part in (relation, module):
        if _QR_RE.search(part):
            return "qr"
        if _OCR_RE.search(part):
            return "ocr"
    return "typed"


# --------------------------------------------------------------------------------------
# claimed brands (cond 6): bank names in the document, org-profile brands
# --------------------------------------------------------------------------------------

_BANK_HEADER_RE = re.compile(r"(?<![\d])(\d{3})-([\dXx])(?![\d])")


def _bank_code_dv(code: str) -> set[str]:
    """Check digit shown next to a bank code on boletos (mod 11, weights 2..4 from the right; 10 is
    printed 'X' or '0', 11 as '0'), e.g. 341-7, 237-2, 001-9, 104-0, 748-X."""
    total = sum(int(c) * w for c, w in zip(reversed(code), (2, 3, 4)))
    dv = 11 - total % 11
    if dv == 10:
        return {"X", "0"}
    if dv == 11:
        return {"0"}
    return {str(dv)}


def claimed_bank_codes(text: str, index: dict[str, Any]) -> list[str]:
    """Banks named in a document: brand words (``br_parsers.BANK_ALIASES``) and 'NNN-D' bank codes
    with a valid check digit that exist in the bank tables."""
    codes = P.detect_bank_mentions(text)
    for m in _BANK_HEADER_RE.finditer(text or ""):
        code, dv = m.group(1), m.group(2).upper()
        if dv in _bank_code_dv(code) and code in (index or {}).get("by_code", {}) and code not in codes:
            codes.append(code)
    return codes


def claimed_brands(text: str, ctx: Any, index: dict[str, Any]) -> list[dict[str, Any]]:
    """Brands the text claims: org-profile brands (with the org CNPJ roots), named banks (with their
    ISPB, the 8-digit CNPJ root of the institution, plus its BCB conglomerate roots from P360) and
    BCB-verified institution domains named in the text (P360). Each: {brand, keywords, roots, source}."""
    out: list[dict[str, Any]] = []
    folded = " " + re.sub(r"[\W_]+", " ", P.strip_accents(text or "").casefold()) + " "
    org = getattr(ctx, "org", None)
    for brand in getattr(org, "brands", None) or ():
        variants = tuple(getattr(brand, "variants", ()) or ())
        terms = [str(t) for t in (getattr(brand, "keyword", ""), *variants) if t]
        folded_terms = [" " + re.sub(r"[\W_]+", " ", P.strip_accents(t).casefold()).strip() + " " for t in terms]
        if any(ft.strip() and ft in folded for ft in folded_terms):
            out.append({"brand": terms[0], "keywords": terms, "roots": list(getattr(org, "cnpj_roots", None) or []), "source": "org_profile"})
    aliases_by_code: dict[str, list[str]] = {}
    for alias, code in P.BANK_ALIASES.items():
        aliases_by_code.setdefault(code, []).append(alias)
    for code in claimed_bank_codes(text, index):
        rec = P.bank_record(code, index) or {}
        name = rec.get("name") or code
        keywords = aliases_by_code.get(code, []) + [w for w in (rec.get("name"), rec.get("full_name")) if w]
        out.append({"brand": name, "keywords": keywords, "roots": [rec["ispb"]] if rec.get("ispb") else [], "source": "bank", "code": code})
    _p360_claims(text, ctx, out)
    return out


def p360_brands(ctx: Any) -> dict[str, Any] | None:
    """P360's protected brands from its local BCB copies (read through ``ctx.data``, cited in the
    result, never downloaded): {index, by_root: {institution CNPJ root: [brand entries]}}; None when
    DominiosVerificados is not installed or does not parse."""
    if _p360 is None:
        return None
    try:
        index = _p360.load_bcb(ctx.data, sedes=True)
    except (DatasetError, OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    if not getattr(index, "dominios", False):
        return None
    signature = tuple((str(m.get("name")), str(m.get("sha256"))) for m in index.datasets)
    with _LOCK:
        hit = _MEMO.get("p360")
        if hit and hit[0] == signature:
            return hit[1]
    by_root: dict[str, list[dict[str, Any]]] = {}
    for brand in _p360.protected_brands(index):
        for root in brand.get("institution_cnpj_roots") or ():
            by_root.setdefault(str(root), []).append(brand)
    out = {"index": index, "by_root": by_root}
    with _LOCK:
        _MEMO["p360"] = (signature, out)
    return out


def _brand_roots(brand: dict[str, Any]) -> set[str]:
    """The CNPJ roots that belong to a P360 brand: institutions, domain registrants, conglomerate members."""
    return {str(r) for key in ("institution_cnpj_roots", "registrant_cnpj_roots", "conglomerate_member_roots") for r in brand.get(key) or ()}


def _name_keyword(name: str) -> str:
    """'BANCO DO BRASIL S.A.' -> 'banco do brasil' (folded, trailing legal form removed)."""
    folded = " ".join(re.sub(r"[\W_]+", " ", P.strip_accents(name).casefold()).split())
    return _LEGAL_TAIL.sub("", folded).strip() or folded


def _p360_claims(text: str, ctx: Any, out: list[dict[str, Any]]) -> None:
    """Cond 6 with P360: a claimed bank also owns the CNPJ roots of its BCB conglomerate (a key of a
    conglomerate member is not a payee mismatch), and a BCB-verified institution domain named in the
    text (www.bb.com.br, atendimento@caixa.gov.br) is a claim of that institution."""
    p360 = p360_brands(ctx)
    if not p360:
        return
    for claim in out:
        if claim["source"] != "bank":
            continue
        related = [b for root in claim["roots"] for b in p360["by_root"].get(str(root), ())]
        if related:
            claim["roots"] = sorted(set(claim["roots"]).union(*(_brand_roots(b) for b in related)))
            claim["bcb_verified_domains"] = sorted({b["registrable_domain"] for b in related})
    claimed_roots = {r for c in out for r in c["roots"]}
    hosts: list[str] = []
    for m in _HOST_RE.finditer(text or ""):
        host = m.group(0).lower()
        if host not in hosts:
            hosts.append(host)
            if len(hosts) >= MAX_TEXT_HOSTS:
                break
    for host in hosts:
        brand = _p360.protected_brand_for(host, p360["index"])
        if not brand:
            continue
        roots = _brand_roots(brand)
        if roots & claimed_roots:
            continue  # the institution is already claimed (bank name, bank code or another of its domains)
        names = [str(n) for n in brand.get("names") or () if n]
        out.append({"brand": names[0] if names else brand["registrable_domain"], "keywords": [_name_keyword(n) for n in names],
                    "roots": sorted(roots), "source": "bcb_verified_domain", "domain": brand["registrable_domain"]})
        claimed_roots |= roots


def _cut_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """The text with the payment codes blanked out (a merchant name inside a BR Code is not a claim)."""
    chars = list(text)
    for a, b in spans:
        for i in range(max(0, a), min(len(chars), b)):
            chars[i] = " "
    return "".join(chars)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class BoletoPix(Module):
    name = "boleto_pix"
    title = "Boleto and PIX BR Code checker (offline)"
    description = (
        "Offline boleto (bancario/arrecadacao) and PIX BR Code parsing: check digits, CRC16, due date across both factor cycles, "
        "bank from the BCB/BrasilAPI tables, payee and key, and tampering verdicts (bank or payee mismatch). No network; dynamic "
        "BR Code URLs are never fetched."
    )
    category = "brazil_public_data"
    accepts = {T.BOLETO, T.PIX, T.PIX_BRCODE, T.TEXT, T.FILE}
    produces = {T.EMAIL, T.PHONE, T.CNPJ, T.DOMAIN, T.ORG}
    tags = {"offline", "brazil", "free"}
    reference = "https://www.bcb.gov.br/estabilidadefinanceira/pix"
    notice = (
        "Offline: never fetches a dynamic BR Code URL (a payer-side action returning payee personal data) and never queries "
        "DICT. CPF keys are masked and never pivoted; e-mail and phone keys are listed for the analyst without automatic "
        f"lookups. Bank tables: {BCB_ATTRIBUTION}; {BRASILAPI_ATTRIBUTION} (refreshed weekly by v3lum data update)."
    )
    terms = "open"  # BCB (open government data) and BrasilAPI (MIT, BCB data) tables
    opsec = Opsec.PASSIVE
    disclosure = "none"  # datasets only: no value ever leaves the machine; allowed at TLP:RED
    hosts = ()
    provider = ""
    sources = (SRC_STR, SRC_BANKS)
    access_model = "offline"
    max_pivots = 100
    timeout = 60.0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            path = entity.value
            ext = os.path.splitext(path)[1].lower()
            return ext in TEXT_EXT and os.path.isfile(path) and os.path.getsize(path) <= MAX_READ
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        origin = input_origin(ctx)
        if entity.type is T.PIX:
            kt = P.pix_key_type(entity.value)
            res.attr("pix_key_type", kt)
            res.attr("pix_key", P.mask_pix_key(entity.value, kt))
            res.raw = {"pix_key": {"type": kt}}
            return res
        today = ctx.now().date()
        if entity.type is T.BOLETO:
            index, tables = self._tables(ctx, res)
            parsed = P.parse_boleto(entity.value, today=today)
            self._boleto(res, parsed, index, origin, claim_text="", single=True)
            res.raw = {"boleto": self._raw_boleto(parsed), "bank_tables": tables}
            return res
        if entity.type is T.PIX_BRCODE:
            parsed = P.parse_brcode(entity.value, origin=origin)
            self._brcode(res, parsed, origin, brands=[], single=True)
            res.raw = {"brcode": self._raw_brcode(parsed)}
            return res
        return self._text(entity, ctx, res, origin, today)

    @staticmethod
    def _tables(ctx: Any, res: ModuleResult) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        index, tables = load_bank_index(ctx)
        res.attr("bank_tables", tables)
        res.attr("data_attribution", [BCB_ATTRIBUTION, BRASILAPI_ATTRIBUTION])
        return index, tables

    # ------------------------------------------------------------------ text and files
    def _text(self, entity: Entity, ctx: Any, res: ModuleResult, origin: str, today: Any) -> ModuleResult:
        if entity.type is T.FILE:
            try:
                with open(entity.value, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(MAX_READ)
            except OSError as exc:
                return res.mark("error", f"cannot read the file: {exc.strerror or type(exc).__name__}")
        else:
            text = entity.value[:MAX_READ]
        brcodes = P.find_brcodes(text, limit=MAX_CODES)
        boletos = [b for b in P.find_boleto_lines(text, limit=MAX_CODES) if not any(not (b[1] <= x or b[0] >= y) for x, y, _p in brcodes)]
        if not brcodes and not boletos:
            self._labelled_keys(res, text)  # 'chave pix: <key>' without a code; nothing else: EMPTY
            return res
        index, tables = self._tables(ctx, res)
        claim_text = _cut_spans(text, [(a, b) for a, b, _x in brcodes] + [(a, b) for a, b, _x in boletos])
        brands = claimed_brands(claim_text, ctx, index)
        raw_boletos, raw_codes = [], []
        for _a, _b, digits in boletos:
            parsed = P.parse_boleto(digits, today=today)
            if parsed.get("ok"):
                self._boleto(res, parsed, index, origin, claim_text=claim_text, single=False)
                raw_boletos.append(self._raw_boleto(parsed))
        for _a, _b, payload in brcodes:
            parsed = P.parse_brcode(payload, origin=origin)
            if parsed.get("ok"):
                self._brcode(res, parsed, origin, brands=brands, single=False)
                raw_codes.append(self._raw_brcode(parsed))
        self._labelled_keys(res, text)
        res.raw = {"boletos": raw_boletos, "brcodes": raw_codes, "claimed_brands": [b["brand"] for b in brands], "bank_tables": tables}
        return res

    @staticmethod
    def _labelled_keys(res: ModuleResult, text: str) -> None:
        """'chave pix: <key>' in the text: e-mail/phone listed (expand=False), CNPJ to the P236 chain,
        a CPF key never (rule 4)."""
        for item in P.extract_br_entities(text):
            if item["type"] != "pix_key":
                continue
            kt = item.get("key_type")
            note = "PIX key named in the text: no automatic lookup (analyst-initiated only)"
            if kt == "email":
                res.pivot(T.EMAIL, item["value"], "pix_key_of", confidence=0.9, expand=False, note=note)
            elif kt == "phone":
                res.pivot(T.PHONE, item["value"], "pix_key_of", confidence=0.9, expand=False, note=note)
            elif kt == "cnpj":
                res.pivot(T.CNPJ, item["value"], "pix_key_of", confidence=0.9, expand=True, note="who receives the money: CNPJ chain (P236)")

    # ------------------------------------------------------------------ boleto
    @staticmethod
    def _boleto_facts(parsed: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
        facts: dict[str, Any] = {"type": parsed.get("type"), "input_kind": parsed.get("input_kind"), "check_digits_ok": parsed.get("check_digits_ok"),
                                 "fields_dv_ok": parsed.get("fields_dv_ok"), "general_dv_ok": parsed.get("general_dv_ok"),
                                 "amount": parsed.get("amount_text")}
        if parsed.get("type") == "bancario":
            rec = P.bank_record(parsed.get("bank_code"), index) or {}
            facts.update({"bank_code": parsed.get("bank_code"), "bank_name": rec.get("name"), "bank_ispb": rec.get("ispb"),
                          "bank_source": rec.get("source"), "currency": "BRL" if parsed.get("currency_ok") else parsed.get("currency"),
                          "due": parsed.get("due")})
        else:
            facts.update({"segment": parsed.get("segment"), "segment_name": parsed.get("segment_name"), "company_id": parsed.get("company_id"),
                          "cnpj_root": parsed.get("cnpj_root"), "dv_method": parsed.get("dv_method")})
        return facts

    def _boleto(self, res: ModuleResult, parsed: dict[str, Any], index: dict[str, Any], origin: str, *, claim_text: str, single: bool) -> None:
        if not parsed.get("ok"):
            if single:
                res.attr("boleto_verdict", P.boleto_verdict_line(parsed))
                res.mark("error", str(parsed.get("error") or "not a boleto line"))
            return
        line = P.boleto_verdict_line(parsed, bank_index=index, origin=origin)
        facts = self._boleto_facts(parsed, index)
        self._append(res, "boleto_verdict", line, single)
        self._append(res, "boleto_facts", facts, single)
        key = parsed.get("barcode", "")[:44]
        if not parsed.get("check_digits_ok"):
            if origin in ("ocr", "qr"):
                res.finding("Boleto check digits could not be verified (OCR)", "info", line,
                            data={"barcode_prefix": key[:4], "origin": origin}, tags=["info"], key=key)
            else:
                res.finding(
                    "Boleto check digit mismatch: invalid or altered code",
                    "low",
                    f"{line}. A mistyped line fails the same way: compare with the original document before paying.",
                    confidence="possible",
                    criterion="FEBRABAN check digits (field DVs mod 10, general DV mod 11) do not match the line",
                    data={"fields_dv_ok": parsed.get("fields_dv_ok"), "general_dv_ok": parsed.get("general_dv_ok"), "type": parsed.get("type")},
                    tags=["tampering_suspected"],
                    key=key,
                )
        if parsed.get("type") == "bancario" and parsed.get("check_digits_ok") and not P.bank_record(parsed.get("bank_code"), index):
            res.finding("Boleto bank code not in the BCB tables", "info",
                        f"Bank code {parsed.get('bank_code')} is not a participant of the local BCB/BrasilAPI tables: confirm the issuer.",
                        data={"bank_code": parsed.get("bank_code")}, tags=["info"], key=key)
        mismatch = P.boleto_bank_mismatch(parsed, claim_text, bank_index=index) if claim_text else None
        if mismatch:
            claimed = ", ".join(f"{c} ({n or 'unknown'})" for c, n in zip(mismatch["claimed_banks"], mismatch["claimed_bank_names"] or [None] * 9))
            res.finding(
                "Boleto bank mismatch: possible tampering",
                "high",
                f"The barcode pays bank {mismatch['barcode_bank']} ({mismatch['barcode_bank_name'] or 'unknown'}) while the document names "
                f"{claimed}. Not a malicious verdict on its own: confirm with the issuer through a known channel.",
                confidence="probable",
                criterion="the bank code in the boleto barcode differs from every bank named in the document or OCR text",
                data={k: mismatch[k] for k in ("barcode_bank", "barcode_bank_name", "claimed_banks", "claimed_bank_names")},
                tags=["tampering_suspected"],
                key=key,
            )

    @staticmethod
    def _raw_boleto(parsed: dict[str, Any]) -> dict[str, Any]:
        keep = ("ok", "error", "type", "input_kind", "bank_code", "currency", "due_factor", "due", "amount_cents", "check_digits_ok",
                "fields_dv_ok", "general_dv_ok", "field_dvs", "block_dvs", "segment", "value_type", "dv_method", "company_id", "cnpj_root")
        return {k: parsed.get(k) for k in keep if k in parsed}

    # ------------------------------------------------------------------ BR Code
    def _brcode(self, res: ModuleResult, parsed: dict[str, Any], origin: str, *, brands: list[dict[str, Any]], single: bool) -> None:
        if not parsed.get("ok"):
            if single:
                res.attr("pix_verdict", P.brcode_verdict_line(parsed))
                res.mark("error", str(parsed.get("error") or "not a PIX BR Code"))
            return
        line = P.brcode_verdict_line(parsed)
        self._append(res, "pix_verdict", line, single)
        self._append(res, "pix_crc_status", parsed.get("status_text"), single)
        ents = P.brcode_entities(parsed)
        for name, value in ents["attributes"].items():
            self._append(res, name, value, single)
        for piv in ents["pivots"]:
            res.pivot(piv["type"], piv["value"], piv["relation"], confidence=0.9, expand=piv["expand"], note=piv.get("note", ""))
        key = f"{parsed.get('crc_found')}:{parsed.get('txid') or ''}"
        if parsed.get("crc_ok") is False:
            if origin in ("ocr", "qr"):
                res.finding("PIX BR Code CRC could not be verified (OCR)", "info", line, data={"origin": origin}, tags=["info"], key=key)
            else:
                res.finding(
                    "PIX BR Code CRC mismatch: altered or corrupted payload",
                    "medium",
                    f"{line}. A copied BR Code is never retyped: a CRC failure means the payload was altered after it was generated.",
                    confidence="probable",
                    criterion="CRC16/CCITT-FALSE over the payload through '6304' differs from the CRC field",
                    data={"crc_found": parsed.get("crc_found"), "crc_computed": parsed.get("crc_computed")},
                    tags=["tampering_suspected"],
                    key=key,
                )
        for brand in brands:
            mismatch = P.payee_brand_mismatch(parsed, claimed_brand=brand["brand"], brand_keywords=brand["keywords"], brand_cnpj_roots=brand["roots"])
            if mismatch is None:
                break  # the payee matches one of the claimed brands
        else:
            if brands:
                claimed = ", ".join(b["brand"] for b in brands)
                res.finding(
                    "PIX payee differs from claimed brand",
                    "medium",
                    f"The text claims {claimed} but the BR Code pays merchant '{parsed.get('merchant_name') or '?'}' "
                    f"(key type {parsed.get('key_type') or 'unknown'}). Not a malicious verdict on its own.",
                    confidence="possible",
                    criterion="neither the BR Code merchant name nor the CNPJ root of its key matches a brand the text names (org-profile brands, bank names and codes, BCB-verified institution domains with their conglomerate roots)",
                    data={"claimed_brands": [b["brand"] for b in brands], "merchant_name": parsed.get("merchant_name"), "key_type": parsed.get("key_type")},
                    tags=["tampering_suspected"],
                    key=key,
                )

    @staticmethod
    def _raw_brcode(parsed: dict[str, Any]) -> dict[str, Any]:
        keep = ("ok", "error", "crc_ok", "crc_found", "crc_computed", "point_of_initiation", "dynamic", "key_type", "key_display", "description",
                "location_host", "location_masked", "mcc", "currency", "amount", "country", "merchant_name", "merchant_city", "txid", "status_text", "origin")
        return {k: parsed.get(k) for k in keep}

    @staticmethod
    def _append(res: ModuleResult, name: str, value: Any, single: bool) -> None:
        if value is None or value == "":
            return
        if single:
            res.attr(name, value)
            return
        current = res.attributes.get(name)
        items = list(current) if isinstance(current, list) else ([] if current is None else [current])
        if json.dumps(value, sort_keys=True, default=str) not in {json.dumps(v, sort_keys=True, default=str) for v in items}:
            items.append(value)
        res.attr(name, items)
