"""djen_court_communications (P362): court communications mentioning a company (CNJ DJEN / Comunica PJe).

Batch p2-G10-3. Litigation is a core third-party risk signal in Brazil and the national electronic
justice gazette (DJEN, CNJ Resolucao 455/2022) centralises court communications. This file ships what
the council allows today:

* **FC1 build gate** - the automated query is implemented only after the API parameters and trimmed
  fixtures (results, empty, geo-block) are captured from the team's own Brazilian network. From the
  research egress the API and its swagger answer the CloudFront geo-block and the portal resets the
  connection, so the parameters and the answer shape are unverified. Until then the module **sends no
  request** (``max_requests = 0``): it emits the manual link to ``https://comunica.pje.jus.br/`` (A9) and
  ends SKIPPED ``config`` ('automation pending the Brazilian-egress capture'). The pure helpers below
  (query plan, classification, parser, summary) are written and tested against the recorded geo-block
  and the synthetic, clearly labelled shape, ready for the BR capture (docs/backlog/p2-G10-3.md).
* **FC2 legal floor** - ``terms = 'unknown'`` (the API terms were not readable) and
  ``default_enabled = False``: the licence gate keeps it out of every profile until legal records them.
* **FC3 egress** - ``requires_egress = {'BR'}`` (A9): automated only from the team's own Brazilian
  egress, never through a VPN/proxy chosen to defeat the geo-block. A CloudFront 403 'configured to
  block access from your country' is BLOCKED ``geo_block`` (the core P321 classifier, tested on the live
  capture), never 'no communications', and never retried with other headers.
* **FC4 queries** (:func:`query_plan`) - the formatted CNPJ and the razao social within a 5-year window
  for CNPJ seeds; analyst-typed company names; person names only for due-diligence subjects typed by the
  analyst with a recorded purpose, and never for employee or job-candidate screening
  (:func:`screening_purpose`, refused).
* **FC5 storage** (:func:`parse_djen`) - per communication: court, date, communication type and class,
  CNJ number and an excerpt of at most 300 characters (CPFs masked); full texts are never stored and
  party/lawyer fields (``destinatarios``, ``destinatarioadvogados``) are never read.
* **FC6 output** (:func:`djen_summary`) - counts by litigation class (trabalhista, consumidor, execucao
  fiscal, criminal...) and by court, the 5 most recent communications, CNJ numbers as non-expanding
  pivots routed to DataJud (P241) under its licence gate.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from v3lum.core import validators
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import gazette_excerpts as gx

SOURCE = "pje.djen_api"
DJEN_API = "https://comunicaapi.pje.jus.br/api/v1/comunicacao"
DJEN_MANUAL_LINK = "https://comunica.pje.jus.br/"
DJEN_REQUIRES_EGRESS = frozenset({"BR"})
WINDOW_YEARS = 5
ITEMS_PER_PAGE = 20
SHOWN = 5
BUILD_GATE_TEXT = ("DJEN automation pending: the API parameters and fixtures must first be captured from the team's own Brazilian "
                   "egress (P362 FC1); search manually at https://comunica.pje.jus.br/")
LITIGATION_CLASSES = ("trabalhista", "consumidor", "execucao_fiscal", "criminal", "falencia_recuperacao", "acao_civil_publica",
                      "tributario", "eleitoral", "civel", "outro")
_SCREENING_RE = re.compile(
    r"\b(candidat[oa]s?|admiss(ao|ional)|contratac(ao|oes) de (funcionari|colaborador)\w*|recrutamento|selec(ao|ionar) de pessoal|"
    r"background check|pre-?employment|hiring|funcionari[oa]s?|colaborador(es|as)?|empregad[oa]s?|employees?)\b")
_PARTY_FIELDS = frozenset({"destinatarios", "destinatarioadvogados", "destinatario", "partes", "advogados"})


def date_window(today: _dt.date, years: int = WINDOW_YEARS) -> tuple[str, str]:
    """FC4: default window of 5 years -> (inicio, fim) ISO dates."""
    return gx.years_back(today, years).isoformat(), today.isoformat()


def djen_url(texto: str, since: str, until: str, *, page: int = 1) -> str:
    """Research parameters (UNVERIFIED until the BR capture, FC1): first page only, at most 20 items."""
    return DJEN_API + "?" + urlencode({"texto": texto, "dataDisponibilizacaoInicio": since, "dataDisponibilizacaoFim": until,
                                       "itensPorPagina": str(ITEMS_PER_PAGE), "pagina": str(int(page))})


def screening_purpose(purpose: Any) -> bool:
    """FC4 guard: True when the recorded purpose reads like employee or job-candidate screening (refused).
    A keyword heuristic over the purpose text, not a guarantee (an enumerated purpose category in the case
    model is the core request)."""
    return bool(_SCREENING_RE.search(gx.fold(purpose)))


def query_plan(entity_type: str, value: Any, *, is_seed: bool = True, purpose: Any = "", razao_social: Any = None) -> dict[str, Any]:
    """FC4 -> {'queries': [...], 'skip': None | {'reason_code', 'reason'}}."""
    def skip(code: str, reason: str) -> dict[str, Any]:
        return {"queries": [], "skip": {"reason_code": code, "reason": reason}}

    if purpose and screening_purpose(purpose):
        return skip("privacy", "DJEN is never used to screen employees or job candidates (P362 FC4)")
    if entity_type == "cnpj":
        if not is_seed:
            return skip("not_applicable", "DJEN runs on CNPJ seeds by default (P362 FC4)")
        if not validators.cnpj_valid(gx.normalize_cnpj(value) or ""):
            return skip("not_applicable", "invalid CNPJ")
        queries = [gx.format_cnpj(value)]
        rs = gx.collapse_ws(razao_social)
        if rs:
            queries.append(rs)
        return {"queries": queries, "skip": None}
    if entity_type == "company_name":
        if not is_seed:
            return skip("not_applicable", "company names only when typed by the analyst (P362 FC4)")
        q = gx.collapse_ws(value)
        return {"queries": [q], "skip": None} if q else skip("not_applicable", "empty name")
    if entity_type == "person_name":
        if not is_seed or not gx.collapse_ws(purpose):
            return skip("privacy", "person names only for due-diligence subjects typed by the analyst with a recorded purpose (P362 FC4)")
        return {"queries": [gx.collapse_ws(value)], "skip": None}
    return skip("not_applicable", "unsupported input type")


def _items(js: Mapping[str, Any]) -> list[Any] | None:
    for key in ("items", "comunicacoes", "content", "data"):
        if isinstance(js.get(key), list):
            return js[key]
    return None


def error_in_200(body: Any) -> str | None:
    """UNVERIFIED shape: a 2xx body must be an object with an item list; a 'status' other than success is an error."""
    if not isinstance(body, dict):
        return "body is not a JSON object"
    status = gx.text(body.get("status")).lower()
    if status and status not in ("success", "ok"):
        return f"status {status!r} {gx.text(body.get('message'))[:80]}".strip()
    if _items(body) is None:
        return "no item list"
    return None


def classify_litigation(class_name: Any, cnj: Any = None, excerpt: Any = None) -> str:
    """FC6: litigation class from the CNJ procedural class name, the justice segment of the CNJ number
    (J=5 trabalho, J=6 eleitoral) and consumer cues."""
    f = gx.fold(class_name)
    digits = re.sub(r"\D", "", gx.text(cnj))
    segment = digits[13] if len(digits) == 20 else None
    if "execucao fiscal" in f:
        return "execucao_fiscal"
    if re.search(r"\b(acao penal|inquerito|criminal|crime|termo circunstanciado|habeas corpus)\b", f):
        return "criminal"
    if segment == "5" or "trabalhist" in f:
        return "trabalhista"
    if re.search(r"\b(recuperacao judicial|recuperacao extrajudicial|falencia)\b", f):
        return "falencia_recuperacao"
    if "improbidade" in f or "acao civil publica" in f:
        return "acao_civil_publica"
    if "juizado especial civel" in f or re.search(r"\b(consumidor|relacao de consumo)\b", gx.fold(excerpt)):
        return "consumidor"
    if segment == "6":
        return "eleitoral"
    if re.search(r"\b(tribut|fiscal|anulatoria de debito)", f):
        return "tributario"
    if segment in ("4", "8") or f:
        return "civel"
    return "outro"


def _first(d: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def parse_djen(body: Any, anchors: Any = ()) -> dict[str, Any]:
    """FC5 (UNVERIFIED shape: replace the synthetic fixture by a BR-egress capture before enabling) ->
    {ok, error, count, items [court, date, type, class_name, litigation_class, cnj, organ, excerpt, link]}.
    Party and lawyer fields are never read."""
    err = error_in_200(body)
    if err:
        return {"ok": False, "error": err, "count": None, "items": []}
    items = []
    for it in _items(body) or []:
        if not isinstance(it, dict):
            continue
        it = {k: v for k, v in it.items() if str(k).lower() not in _PARTY_FIELDS}  # FC5: never read
        number = _first(it, "numeroprocessocommascara", "numeroProcessoComMascara", "numero_processo", "numeroProcesso")
        found = gx.extract_cnj(gx.text(number), limit=1)
        cnj = found[0]["number"] if found else None
        class_name = gx.text(_first(it, "nomeClasse", "nome_classe", "classe")) or None
        texto = gx.text(_first(it, "texto", "conteudo"))
        items.append({
            "court": gx.text(_first(it, "siglaTribunal", "sigla_tribunal", "tribunal")) or (found[0].get("court") if found else None),
            "date": gx.iso_date(_first(it, "data_disponibilizacao", "dataDisponibilizacao", "datadisponibilizacao")),
            "type": gx.text(_first(it, "tipoComunicacao", "tipo_comunicacao")) or None,
            "class_name": class_name,
            "litigation_class": classify_litigation(class_name, cnj, texto),
            "cnj": cnj,
            "organ": gx.text(_first(it, "nomeOrgao", "nome_orgao")) or None,
            "excerpt": gx.clean_excerpt(texto, anchors) if texto else None,
            "link": gx.http_url(it.get("link")),
        })
    count = _first(body, "count", "total", "totalElements")
    return {"ok": True, "error": None, "count": count if isinstance(count, int) and not isinstance(count, bool) else len(items),
            "items": items}


def djen_summary(parsed: Mapping[str, Any], *, top: int = SHOWN) -> dict[str, Any]:
    """FC6: counts by litigation class and by court, the 5 most recent communications and the CNJ
    numbers (pivoted with expand=False, routed to DataJud asynchronously under its licence gate)."""
    items = list(parsed.get("items") or [])
    by_class: dict[str, int] = {}
    by_court: dict[str, int] = {}
    for it in items:
        by_class[it["litigation_class"]] = by_class.get(it["litigation_class"], 0) + 1
        court = it.get("court") or "?"
        by_court[court] = by_court.get(court, 0) + 1
    recent = sorted(items, key=lambda i: i.get("date") or "", reverse=True)[:top]
    numbers: list[str] = []
    for it in items:
        if it.get("cnj") and it["cnj"] not in numbers:
            numbers.append(it["cnj"])
    return {"count": parsed.get("count", len(items)), "by_class": by_class, "by_court": by_court, "recent": recent,
            "cnj_numbers": numbers}


@register
class DjenCourtCommunications(Module):
    name = "djen_court_communications"
    title = "DJEN court communications (CNJ Comunica PJe)"
    description = (
        "Court communications (intimacoes, citacoes, editais) mentioning a company in the CNJ national electronic justice gazette "
        "(DJEN). Manual link to comunica.pje.jus.br until the automated query is captured from a Brazilian egress (P362 build gate)."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG}
    produces = {T.KEYWORD}
    tags = {"brazil"}
    reference = "https://comunica.pje.jus.br/"
    notice = (
        "Terms of the Comunica PJe API not yet recorded (unknown): disabled in every licence profile until legal reviews them. "
        "Needs the team's own Brazilian egress (CloudFront geo-block, never bypassed). Never used to screen employees or job "
        "candidates; person names only for due-diligence subjects with a recorded purpose (LGPD)."
    )
    # ---- declarations ------------------------------------------------------------------
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the CNPJ / razao social will go to the CNJ API once the build gate is met
    hosts = ("comunicaapi.pje.jus.br",)
    provider = "pje"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    max_requests = 0  # FC1: no automated request before the Brazilian-egress capture
    expected_latency = 1.0
    requires_egress = DJEN_REQUIRES_EGRESS
    manual_link = DJEN_MANUAL_LINK
    min_interval = 2.0
    cache_ttl = 86400
    daily_quota = 100
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        purpose = gx.collapse_ws(getattr(ctx, "purpose", "") or getattr(getattr(ctx, "options", None), "purpose", "") or "")
        plan = query_plan(entity.type.value, entity.value, is_seed=bool(getattr(ctx, "is_seed", True)), purpose=purpose)
        if plan["skip"]:
            return res.mark(Status.SKIPPED, plan["skip"]["reason"], reason_code=plan["skip"]["reason_code"])
        res.link("Comunica PJe (DJEN) - manual search", DJEN_MANUAL_LINK)
        return res.mark(Status.SKIPPED, BUILD_GATE_TEXT, reason_code="config")
