"""P239 ``tcu_certidoes`` - TCU consolidated certificate: TCU inidoneos, CNJ CNIA, CEIS and CNEP in one call.

Council P239 final conditions, as implemented here:

1. One keyless GET per CNPJ to certidoes-apf.apps.tcu.gov.br with ``seEmitirPDF=false`` (no PDF is ever
   generated), <= 1 req/s and a 24 h cache (provider profile + ``cache_ttl``). The 14-character CNPJ
   goes in the path: the formatted CNPJ ('00.000.000/0001-91', '/' URL-encoded) is decoded by the
   Apache front and answers a 404 HTML page (live-verified 2026-11-26); the answer carries the
   formatted CNPJ.
2. Results are trusted only when ``seCnpjEncontradoNaBaseTcu`` is true: otherwise every list reads
   'could not verify: CNPJ not found in the TCU base - not evidence of a clean record' (a fictitious
   CNPJ also gets NADA_CONSTA). CNPJ existence comes only from cnpj_lookup (P236).
3. Per-list tri-state (attribute ``certificate_lists``): consta / nada_consta ('no record in <list>
   as of <dataHoraEmissao>') / unknown. SISTEMA_INDISPONIVEL, ALFANUMERICO_NAO_SUPORTADO, any other
   value, a missing entry, 5xx, a challenge or a timeout = unknown, listed per list in coverage as
   'could not verify <list>' (``res.source_status`` on one registry source per list), never clean.
4. Any CONSTA is a HIGH finding tagged sanctions naming the list, emitter, certificate time and the
   manual consultation link; ``data['dedup_key']`` = '<list>|<cnpj>|' is the key shared with P237 and
   P240 (one sanction = one finding with several sources; correlation rule g10_sanction_dedup).
5. The certificate timestamp (dataHoraEmissao) and the per-list states are stored in evidence.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register

SRC_API = "tcu.certidoes"
#: list id -> registry source (one coverage row per list, P239 cond 3)
LIST_SOURCES = {
    "tcu_inidoneos": "tcu.certidoes_inidoneos",
    "cnj_cnia": "tcu.certidoes_cnia",
    "ceis": "tcu.certidoes_ceis",
    "cnep": "tcu.certidoes_cnep",
}
LIST_ORDER = ("tcu_inidoneos", "cnj_cnia", "ceis", "cnep")
#: 'tipo' of a certificate entry -> list id
TCU_TYPES = {"INIDONEOS": "tcu_inidoneos", "CNIA": "cnj_cnia", "CEIS": "ceis", "CNEP": "cnep"}
LIST_LABELS = {
    "tcu_inidoneos": "TCU Licitantes Inidoneos",
    "cnj_cnia": "CNJ CNIA (improbidade/inelegibilidade)",
    "ceis": "CEIS",
    "cnep": "CNEP",
}
TCU_URL = "https://certidoes-apf.apps.tcu.gov.br/api/rest/publico/certidoes/{cnpj}?seEmitirPDF=false"
TCU_NOT_IN_BASE = "could not verify: CNPJ not found in the TCU base - not evidence of a clean record"
#: Brasilia time (UTC-3, no daylight saving since 2019): dataHoraEmissao is local time
BRT = timezone(timedelta(hours=-3))


def _s(v: Any) -> str:
    if v is None or isinstance(v, (bool, dict, list, tuple, set)):
        return ""
    return str(v).strip()


def _fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", _s(text))
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t).strip().upper()


def tcu_request_url(cnpj: str) -> str:
    """P239 cond 1: the 14-character CNPJ in the path and seEmitirPDF=false."""
    return TCU_URL.format(cnpj=re.sub(r"[^0-9A-Za-z]", "", cnpj).upper())


def parse_tcu_datetime(value: Any) -> str | None:
    """'26/11/2026 02:20' (Brasilia time) -> ISO 8601 with offset, else None."""
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?$", _s(value))
    if not m:
        return None
    d, mo, y, hh, mi, ss = m.groups()
    try:
        return datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss or 0), tzinfo=BRT).isoformat()
    except ValueError:
        return None


def dedup_key(list_id: str, cnpj: str, sanction_id: str = "") -> str:
    """The sanction key shared by P237/P239/P240: '<list>|<cnpj14>|<sanction id or empty>'."""
    return f"{list_id}|{cnpj}|{sanction_id or ''}"


def parse_tcu_certidoes(obj: Any) -> dict[str, Any] | None:
    """One TCU answer -> {found_in_base, issued_at, razao_social, lists: {list: entry}} or None when the
    body is not a certificate. entry = {state, text, situacao_raw, issued_at, emitter, link, observacao}."""
    if not isinstance(obj, dict) or not isinstance(obj.get("certidoes"), list) or "seCnpjEncontradoNaBaseTcu" not in obj:
        return None
    found = obj.get("seCnpjEncontradoNaBaseTcu") is True
    by_list: dict[str, dict[str, Any]] = {}
    for c in obj["certidoes"]:
        if not isinstance(c, dict):
            continue
        lid = TCU_TYPES.get(_fold(c.get("tipo")))
        if lid and lid not in by_list:
            by_list[lid] = c
    issued_all = sorted(i for i in (parse_tcu_datetime(c.get("dataHoraEmissao")) for c in by_list.values()) if i)
    out: dict[str, Any] = {
        "found_in_base": found,
        "issued_at": issued_all[-1] if issued_all else None,
        "razao_social": _s(obj.get("razaoSocial")) or None,
        "pdf_present": obj.get("certidaoPDF") is not None,
        "lists": {},
    }
    for lid in LIST_ORDER:
        label = LIST_LABELS[lid]
        c = by_list.get(lid)
        sit = _fold(c.get("situacao")).replace(" ", "_") if c is not None else None
        when_raw = _s((c or {}).get("dataHoraEmissao")) or None
        link = _s((c or {}).get("linkConsultaManual")) or None
        entry: dict[str, Any] = {
            "state": "unknown", "situacao_raw": sit, "issued_at": parse_tcu_datetime(when_raw), "emitter": _s((c or {}).get("emissor")) or None,
            "link": link if link and re.match(r"^https?://", link) else None, "observacao": _s((c or {}).get("observacao")) or None,
        }
        if not found:
            entry["text"] = TCU_NOT_IN_BASE
        elif c is None:
            entry["text"] = f"could not verify {label}: missing from the TCU answer"
        elif sit == "NADA_CONSTA":
            entry.update(state="nada_consta", text=f"no record in {label} as of {when_raw or 'an unknown time'}")
        elif sit == "CONSTA":
            entry.update(state="consta", text=f"record found in {label} (certificate {when_raw or 'time not stated'})")
        elif sit == "SISTEMA_INDISPONIVEL":
            entry["text"] = f"could not verify {label}: source system unavailable (SISTEMA_INDISPONIVEL)"
        elif sit == "ALFANUMERICO_NAO_SUPORTADO":
            entry["text"] = f"could not verify {label}: alphanumeric CNPJ not supported by this list"
        else:
            entry["text"] = f"could not verify {label}: unexpected state {sit or 'empty'}"
        out["lists"][lid] = entry
    return out


@register
class TcuCertidoes(Module):
    name = "tcu_certidoes"
    title = "TCU consolidated sanctions certificate"
    description = (
        "One keyless call to the TCU consolidated certificate (Certidoes APF) per CNPJ: TCU inidoneos, CNJ CNIA, CEIS and "
        "CNEP as consta / nada consta / unknown, trusted only when the CNPJ exists in the TCU base."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ}
    produces: set[Any] = set()
    tags = {"brazil", "free"}
    reference = "https://certidoes-apf.apps.tcu.gov.br/"
    notice = (
        "Official TCU service. A CNPJ missing from the TCU base also gets NADA CONSTA: results count only when "
        "seCnpjEncontradoNaBaseTcu is true, and an unavailable list is 'could not verify', never clean. No PDF is generated."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("certidoes-apf.apps.tcu.gov.br",)
    provider = "tcu"
    sources = (SRC_API, *LIST_SOURCES.values())
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 7.0  # measured p50 6.8 s from a datacenter egress (2026-11-26): the TCU queries four systems
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400
    manual_link = "https://certidoes-apf.apps.tcu.gov.br/"
    default_enabled = True  # A3: TCU certidoes are default-on by decision

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(etype=T.CNPJ, value="00000000000191")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        cnpj = str(entity.value).upper()
        url = tcu_request_url(cnpj)
        try:
            resp = ctx.http.get(url, source=SRC_API, headers={"Accept": "application/json"}, cache_if=_cacheable)
        except RateLimited as exc:
            return self._unknown(res, Status.RATE_LIMITED, "rate_limited", f"TCU: {exc}")
        except QuotaExceeded as exc:
            return self._unknown(res, Status.QUOTA, "quota", f"TCU: {exc}")
        except Blocked as exc:
            code = str(getattr(exc, "reason_code", "") or "challenge")
            return self._unknown(res, Status.BLOCKED, code, f"TCU: {exc}")
        except AuthRequired as exc:
            return self._unknown(res, Status.BLOCKED, "challenge", f"TCU: {exc}")
        except DeadlineExceeded:
            raise  # the run deadline: the engine maps it to ERROR timeout
        except NetworkError as exc:
            code = "timeout" if "timeout" in str(getattr(exc, "kind", "")).lower() else "error"
            return self._unknown(res, Status.ERROR, code, f"TCU did not answer: {exc}")
        except HttpError as exc:
            return self._unknown(res, Status.ERROR, "error", f"TCU: {exc}")
        found = resp.classification
        if found is not None:
            status = {"blocked": Status.BLOCKED, "rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA}.get(str(found.status), Status.ERROR)
            code = str(getattr(found, "reason_code", "") or "")
            return self._unknown(res, status, code, f"TCU: {getattr(found, 'reason', '') or found.status}")
        if resp.status == 429:
            return self._unknown(res, Status.RATE_LIMITED, "rate_limited", "TCU answered HTTP 429")
        if resp.status in (401, 403):
            return self._unknown(res, Status.BLOCKED, "challenge", f"TCU answered HTTP {resp.status}")
        if resp.status != 200:
            return self._unknown(res, Status.ERROR, "error", f"TCU answered HTTP {resp.status}")
        try:
            body = json.loads(resp.text)
        except ValueError:
            return self._unknown(res, Status.ERROR, "error", "TCU answered 200 without a JSON certificate")
        parsed = parse_tcu_certidoes(body)
        if parsed is None:
            return self._unknown(res, Status.ERROR, "error", "TCU answer has an unexpected shape (no certidoes list or base flag)")
        return self._emit(res, cnpj, parsed)

    # ------------------------------------------------------------------ outcomes
    def _unknown(self, res: ModuleResult, status: Status, code: str, reason: str) -> ModuleResult:
        """P239 cond 3: 5xx, timeouts, challenges and unusable answers -> every list unknown, listed per
        list as 'could not verify <list>' (never clean, rule 5)."""
        for lid in LIST_ORDER:
            res.source_status(LIST_SOURCES[lid], status, reason_code=code if code else "", reason=f"could not verify {LIST_LABELS[lid]}: {reason}"[:300])
        res.attr("certificate_lists", {lid: {"state": "unknown", "text": f"could not verify {LIST_LABELS[lid]}: {reason}"} for lid in LIST_ORDER})
        return res.mark(status, f"could not verify the TCU certificate ({reason})", reason_code=code)

    def _emit(self, res: ModuleResult, cnpj: str, parsed: dict[str, Any]) -> ModuleResult:
        lists = parsed["lists"]
        res.attr("tcu_base_found", parsed["found_in_base"])
        res.attr("certificate_issued_at", parsed["issued_at"])
        res.attr("certificate_lists", {lid: {k: v for k, v in e.items() if k in ("state", "text", "issued_at", "emitter", "link")}
                                       for lid, e in lists.items()})
        res.raw = {
            "issued_at": parsed["issued_at"], "found_in_base": parsed["found_in_base"],
            "states": {lid: e["situacao_raw"] for lid, e in lists.items()}, "tri_state": {lid: e["state"] for lid, e in lists.items()},
            "pdf_present": parsed["pdf_present"],
        }
        res.source_status(SRC_API, Status.OK if parsed["found_in_base"] else Status.ERROR, reason="" if parsed["found_in_base"] else TCU_NOT_IN_BASE)
        for lid in LIST_ORDER:
            e = lists[lid]
            src = LIST_SOURCES[lid]
            if e["state"] == "consta":
                res.source_status(src, Status.OK, reason=e["text"])
                self._finding(res, cnpj, lid, e)
            elif e["state"] == "nada_consta":
                res.source_status(src, Status.EMPTY, reason=e["text"])
            else:
                res.source_status(src, Status.ERROR, reason=e["text"][:300])
        if not parsed["found_in_base"]:
            return res.mark(Status.ERROR, TCU_NOT_IN_BASE)
        return res

    def _finding(self, res: ModuleResult, cnpj: str, lid: str, e: dict[str, Any]) -> None:
        label = LIST_LABELS[lid]
        when = e.get("issued_at")
        link = e.get("link")
        res.finding(
            f"{label}: record found (TCU certificate CONSTA)",
            "high",
            f"The TCU consolidated certificate issued {when or 'at an unknown time'} lists this CNPJ in {label} "
            f"(emitter {e.get('emitter') or 'not stated'})." + (f" Note: {e['observacao']}." if e.get("observacao") else "")
            + (f" Manual consultation: {link}" if link else ""),
            confidence="confirmed",
            criterion=f"TCU certificate situacao CONSTA for {label}; seCnpjEncontradoNaBaseTcu true; certificate time {when or 'unknown'}",
            data={"list": lid, "emitter": e.get("emitter"), "issued_at": when, "link": link, "observacao": e.get("observacao"),
                  "dedup_key": dedup_key(lid, cnpj), "match_type": "exact_cnpj"},
            tags=["sanctions"],
            references=[link] if link else (),
            source=LIST_SOURCES[lid],
            observed_last=when,
            key=lid,
        )
        res.attr("sanctioned", True)


def _cacheable(resp: Any) -> bool:
    """Only certificates (JSON with the certidoes list and the base flag) are cached (24 h)."""
    if resp.status != 200:
        return False
    try:
        return parse_tcu_certidoes(json.loads(resp.text)) is not None
    except ValueError:
        return False


__all__ = ["LIST_SOURCES", "TCU_NOT_IN_BASE", "TcuCertidoes", "dedup_key", "parse_tcu_certidoes", "parse_tcu_datetime", "tcu_request_url"]
