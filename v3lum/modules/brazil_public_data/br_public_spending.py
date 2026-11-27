"""P246 ``br_public_spending`` - public financing, incentives and procurement tied to a CNPJ.

Batch p3-G10-2. Two module classes, one per egress requirement (``requires_egress`` is a module-level
declaration):

* :class:`BrPublicSpending` (``br_public_spending``) - the verified half (FC1): BNDES CKAN ``datastore_search``
  (dadosabertos.bndes.gov.br) and SALIC ``incentivadores`` (api.salic.cultura.gov.br, HAL JSON), with per-provider
  status in coverage.
* :class:`BrPublicSpendingBr` (``br_public_spending_br``) - Compras.gov.br (SICAF supplier record) and PNCP,
  ``requires_egress = {'BR'}`` (FC2, A9): outside the team's Brazilian egress the policy gate skips it
  (``egress_country``) with the manual links of pivot pack ``br_public_spending_links``. PNCP has no success
  fixture yet (empty reply / timeout from non-BR egress), so it sends no request and only emits its manual link
  until a Brazilian-egress capture exists; Compras.gov.br answered with the required ``ativo=true`` parameter from
  the prep egress (fixture), so its parser is wired, still behind the BR egress gate.

Council P246 final conditions, as implemented here:

1. BNDES + SALIC first, with their fixtures; per-provider status (``res.source_status`` + attribute
   ``public_funding_coverage``).
2. PNCP and Compras.gov.br declare ``requires_egress={'BR'}``: SKIPPED ``egress_country`` with manual links
   otherwise (policy gate POL-11).
3. A9: never through a VPN or proxy exit chosen to defeat a geo-block, never IP rotation; 403, challenge,
   geo-block or an empty reply is BLOCKED 'could not verify' with the manual link, never 'no contracts'.
4. CNPJ-centric queries only, at most 20 rows per provider; output limited to operation id, organ, value,
   dates, status and URL. SALIC natural-person sponsors and the 'responsavel' field are never matched, stored or
   pivoted; BNDES masked-CPF rows are dropped; Compras partners, e-mail and phone are never kept.
5. Opt-in (``default_enabled = False``), tier trusted. Rows carry :func:`contract_dedup_key`, the key proposed to
   be shared with P237 (P237 defines none for its contract rows: a cross-batch request).
6. Offline tests with FakeHttp over trimmed real fixtures; a provider entry for every host; the P327 lint.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import namematch

SOURCE_BNDES = "bndes.ckan_operations"
SOURCE_SALIC = "minc.salic_incentivadores"
SOURCE_COMPRAS = "compras_gov.sicaf_fornecedor"
SOURCE_PNCP = "pncp.pncp_search"
BNDES_DATASTORE = "https://dadosabertos.bndes.gov.br/api/3/action/datastore_search"
BNDES_RESOURCES = {
    "naut": "6f56b78c-510f-44b6-8274-78a5b7e931f4",  # operacoes nao automaticas: full 'cnpj', contract number
    "aut": "612faa0b-b6be-4b2c-9317-da5dc2c0b901",   # operacoes indiretas automaticas: 'cpf_cnpj' masked
}
SALIC_BASE = "https://api.salic.cultura.gov.br/api/v1/"
COMPRAS_BASE = "https://dadosabertos.compras.gov.br/"
PNCP_MANUAL = "br_public_spending_links:pncp_contracts"
COMPRAS_MANUAL = "br_public_spending_links:compras_sicaf_supplier"
MAX_ROWS = 20  # FC4
PROVIDER_TIMEOUT = 20.0
_WS = re.compile(r"\s+")
_MASKED_CPF = re.compile(r"^(?:\*{3}\.\d{3}\.\d{3}-\*{2}|\*{3}\.\*?\d{2,3}\.\d{3}-\*{2}|X{3}\d{3}\.\d{3}X{2}|\d{3}X{6}\d{2})$", re.I)
_EMPTY_REPLY = re.compile(r"RemoteDisconnected|Connection aborted|ConnectionReset|reset by peer|Empty reply|without response", re.I)
_HTML = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b)", re.I)


def clean(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return _WS.sub(" ", str(value)).strip()


def cnpj_normalize(value: Any) -> str | None:
    s = re.sub(r"[\s./-]", "", clean(value)).upper()
    return s if re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", s) and not s.isalpha() else None


def format_cnpj(value: Any) -> str | None:
    s = cnpj_normalize(value)
    return f"{s[:2]}.{s[2:5]}.{s[5:8]}/{s[8:12]}-{s[12:]}" if s else None


def parse_amount(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = clean(value).replace("R$", "").strip()
    if re.fullmatch(r"-?\d{1,3}(\.\d{3})+(,\d+)?|-?\d+,\d+", s):
        s = s.replace(".", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None


def parse_date(value: Any) -> str | None:
    s = clean(value)
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s) or None
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", s)
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else None


def contract_dedup_key(supplier_cnpj: Any, organ: Any, number: Any = None, signed: Any = None, value: Any = None) -> str:
    """Cross-module contract/operation key (FC5, proposed for P237): sha256('cnpj|organ|number|date|value')[:16]
    with the shared normalisation (CNPJ digits, normalised organ name, number without leading zeros, ISO date,
    value rounded to cents)."""
    amount = parse_amount(value)
    parts = [cnpj_normalize(supplier_cnpj) or "", namematch.normalized_name(clean(organ)), clean(number).lstrip("0"),
             parse_date(signed) or "", "" if amount is None else f"{amount:.2f}"]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


# ======================================================================================
# BNDES CKAN (FC1, FC4)
# ======================================================================================


def bndes_masked_cnpj(cnpj: Any) -> str | None:
    """'92816560000137' -> '**.*16.560/0001-**' (the mask of the automatic-operations resource)."""
    c = cnpj_normalize(cnpj)
    return f"**.*{c[3:5]}.{c[5:8]}/{c[8:12]}-**" if c else None


def bndes_query_url(resource: str, cnpj: str) -> str:
    """datastore_search for one CNPJ: full-text q (formatted CNPJ on the non-automatic resource, the masked form
    on the automatic one), limit 20; never 'filters=' (the BNDES front WAF answers a JSON filters parameter with an
    Apache 403 page)."""
    rid = BNDES_RESOURCES[resource]
    q = format_cnpj(cnpj) if resource == "naut" else bndes_masked_cnpj(cnpj)
    return f"{BNDES_DATASTORE}?resource_id={rid}&q={quote(q or '', safe='')}&limit={MAX_ROWS}"


def ckan_problem(data: Any) -> str:
    """CKAN envelope problems (error-in-200): success=false, a missing result, a non-object answer."""
    if not isinstance(data, dict):
        return "unexpected CKAN answer (not a JSON object)"
    if data.get("success") is False:
        err = data.get("error") if isinstance(data.get("error"), dict) else {}
        return f"CKAN error: {clean(err.get('__type') or err.get('message')) or 'unknown'}"
    if not isinstance(data.get("result"), dict) or not isinstance(data["result"].get("records", []), list):
        return "unexpected CKAN answer (no result.records)"
    return ""


def parse_bndes_datastore(data: Any, cnpj: str, resource: str) -> dict[str, Any]:
    """BNDES datastore_search -> ``{ok, total, records, dropped_persons, error}`` (FC1, FC4).

    Exact CNPJ post-filter on the full 'cnpj' field (the full-text q matches loosely); on the masked resource only
    rows whose masked 'cpf_cnpj' equals the masked CNPJ are kept, as 'masked_partial' (possible) matches. Masked-CPF
    rows (natural persons) are dropped and counted. Output per record: operation_id, organ, value, disbursed,
    date, product, status, match, url, dedup_key."""
    problem = ckan_problem(data)
    if problem:
        return {"ok": False, "total": None, "records": [], "dropped_persons": 0, "error": problem}
    result = data["result"]
    rid = BNDES_RESOURCES[resource]
    masked_q = bndes_masked_cnpj(cnpj)
    records: list[dict[str, Any]] = []
    dropped = 0
    for r in result.get("records") or ():
        if not isinstance(r, dict):
            continue
        full = cnpj_normalize(r.get("cnpj"))
        masked = clean(r.get("cpf_cnpj")) or None
        if masked and (_MASKED_CPF.match(masked) or ("/" not in masked and re.fullmatch(r"[*\d.]{3,}-\*\*", masked))):
            dropped += 1  # FC4: natural persons never enter the case
            continue
        if full:
            if full != cnpj:
                continue
            match = "exact"
        elif masked and masked == masked_q:
            match = "masked_partial"
        else:
            continue
        number = r.get("numero_do_contrato")
        op_id = str(int(number)) if isinstance(number, (int, float)) and not isinstance(number, bool) else (clean(number) or f"{rid}:{r.get('_id')}")
        agent = clean(r.get("instituicao_financeira_credenciada"))
        organ = "BNDES" + (f" via {agent}" if agent and not agent.startswith("---") else "")
        value = parse_amount(r.get("valor_contratado_reais", r.get("valor_da_operacao_em_reais")))
        date = parse_date(r.get("data_da_contratacao"))
        records.append({
            "source": "bndes", "operation_id": op_id, "organ": organ, "value": value,
            "disbursed": parse_amount(r.get("valor_desembolsado_reais")), "date": date, "product": clean(r.get("produto")) or None,
            "instrument": clean(r.get("instrumento_financeiro")) or None,
            "status": clean(r.get("situacao_do_contrato") or r.get("situacao_da_operacao")) or None, "match": match,
            "url": bndes_query_url(resource, cnpj), "dedup_key": contract_dedup_key(cnpj, "BNDES", op_id, date, value),
        })
        if len(records) >= MAX_ROWS:
            break
    total = result.get("total")
    return {"ok": True, "total": total if isinstance(total, int) else None, "records": records, "dropped_persons": dropped, "error": None}


# ======================================================================================
# SALIC (FC1, FC4)
# ======================================================================================


def salic_query_url(cnpj: str) -> str:
    """SALIC incentivadores by CNPJ only (FC4: never a name search, never a CPF)."""
    return f"{SALIC_BASE}incentivadores?cgccpf={cnpj}"


def salic_not_found(body: Any) -> bool:
    """The documented absence: HTTP 404 with ``message_code`` 11 ('No donator was found with your criteria')."""
    try:
        data = json.loads(body) if isinstance(body, (bytes, str)) else body
    except ValueError:
        return False
    return isinstance(data, dict) and data.get("message_code") == 11 and "_embedded" not in data


def parse_salic_incentivadores(data: Any, cnpj: str) -> dict[str, Any]:
    """SALIC HAL JSON -> ``{ok, rows, dropped_persons, error}``. Natural-person sponsors (tipo_pessoa 'fisica' or
    an 11-digit document) are dropped; 'responsavel' (a person) is never read; only the queried CNPJ is kept."""
    if not isinstance(data, dict):
        return {"ok": False, "rows": [], "dropped_persons": 0, "error": "unexpected SALIC answer (not a JSON object)"}
    if "_embedded" not in data and "message" in data:
        return {"ok": False, "rows": [], "dropped_persons": 0, "error": f"SALIC error: {clean(data.get('message'))[:120]}"}
    emb = data.get("_embedded") if isinstance(data.get("_embedded"), dict) else None
    items = emb.get("incentivadores") if emb else None
    if not isinstance(items, list):
        return {"ok": False, "rows": [], "dropped_persons": 0, "error": "unexpected SALIC answer (no _embedded.incentivadores)"}
    rows: list[dict[str, Any]] = []
    dropped = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        doc = re.sub(r"\D", "", clean(it.get("cgccpf")))
        kind = clean(it.get("tipo_pessoa")).casefold()
        if kind != "juridica" or len(doc) != 14:
            dropped += 1
            continue
        if doc != cnpj:
            continue
        links = it.get("_links") if isinstance(it.get("_links"), dict) else {}
        url = links.get("doacoes") or links.get("self")
        total = parse_amount(it.get("total_doado"))
        rows.append({"source": "salic", "operation_id": f"salic:{doc}", "organ": "Ministerio da Cultura (Lei Rouanet, SALIC)",
                     "value": round(total, 2) if total is not None else None, "disbursed": None, "date": None,
                     "product": "incentivador (sponsor)", "status": None, "match": "exact",
                     "url": url if isinstance(url, str) and url.startswith("https://") else salic_query_url(cnpj),
                     "dedup_key": contract_dedup_key(doc, "SALIC", f"salic:{doc}", None, total)})
        if len(rows) >= MAX_ROWS:
            break
    return {"ok": True, "rows": rows, "dropped_persons": dropped, "error": None}


# ======================================================================================
# Compras.gov.br SICAF (FC2-FC4)
# ======================================================================================


def compras_fornecedor_url(cnpj: str) -> str:
    """SICAF supplier query; ``ativo`` is REQUIRED (without it the API answers 404 'Resource not found', which the
    research misread as egress filtering). CNPJ only, never 'cpf' (FC4)."""
    return f"{COMPRAS_BASE}modulo-fornecedor/1_consultarFornecedor?pagina=1&tamanhoPagina=10&ativo=true&cnpj={cnpj}"


def compras_problem(data: Any) -> str:
    if not isinstance(data, dict):
        return "unexpected Compras.gov.br answer (not a JSON object)"
    if "resultado" not in data and ("statusCode" in data or "message" in data):
        msg = clean(data.get("message"))
        return ("Compras.gov.br 'Resource not found': a query error (missing parameter or moved route), never an absence"
                if "not found" in msg.lower() else f"Compras.gov.br error: {msg[:120]}")
    if not isinstance(data.get("resultado"), list):
        return "unexpected Compras.gov.br answer (no resultado list)"
    return ""


def parse_compras_fornecedor(data: Any, cnpj: str) -> dict[str, Any]:
    """GenericAPIResponseDTO -> ``{ok, rows, total, error}``. Partners (masked names), e-mail and phone are never
    kept; natural-person suppliers (cpf set) are dropped."""
    problem = compras_problem(data)
    if problem:
        return {"ok": False, "rows": [], "total": None, "error": problem}
    rows = []
    for r in data["resultado"]:
        if not isinstance(r, dict) or r.get("cpf"):
            continue
        c = cnpj_normalize(r.get("cnpj"))
        if c != cnpj:
            continue
        lines = [clean(x.get("descricao")) for x in (r.get("linhasFornecimento") or []) if isinstance(x, dict) and clean(x.get("descricao"))]
        rows.append({"active": r.get("ativo") is True, "qualified": clean(r.get("statusHabilitacaoGeral")).casefold() == "sim",
                     "name": clean(r.get("nomeRazaoSocialFornecedor")) or None, "uf": clean(r.get("ufSigla")) or None,
                     "city": clean(r.get("nomeMunicipio")) or None, "cnae": r.get("codigoCnae") if isinstance(r.get("codigoCnae"), int) else None,
                     "legal_nature": clean(r.get("naturezaJuridicaNome")) or None, "size": clean(r.get("porteEmpresaNome")) or None,
                     "supply_lines": lines[:10]})
    total = data.get("totalRegistros")
    return {"ok": True, "rows": rows[:MAX_ROWS], "total": total if isinstance(total, int) else None, "error": None}


# ======================================================================================
# per-provider calls (FC1, FC3): failures become a per-source status, never 'no contracts'
# ======================================================================================


class _Failure(Exception):
    def __init__(self, status: Status, code: str, reason: str) -> None:
        super().__init__(reason)
        self.status, self.code, self.reason = status, code, reason


def _call(ctx: Any, url: str, source: str, label: str) -> Any:
    """One GET; classified answers and transport failures become _Failure (rule 5: could not verify). The
    run-level deadline, request cap and cancellation propagate."""
    try:
        return ctx.http.get(url, source=source, timeout=PROVIDER_TIMEOUT, headers={"Accept": "application/json"})
    except RateLimited as exc:
        raise _Failure(Status.RATE_LIMITED, "rate_limited", f"{label}: rate limited ({exc}): could not verify") from None
    except QuotaExceeded as exc:
        raise _Failure(Status.QUOTA, "quota", f"{label}: quota exhausted ({exc}): could not verify") from None
    except Blocked as exc:
        code = str(getattr(exc, "reason_code", "") or "challenge")
        code = code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
        raise _Failure(Status.BLOCKED, code, f"{label}: blocked ({exc}): could not verify") from None
    except AuthRequired as exc:
        raise _Failure(Status.BLOCKED, "challenge", f"{label}: refused ({exc}): could not verify") from None
    except DeadlineExceeded:
        raise
    except NetworkError as exc:
        if getattr(exc, "reason_code", "") == "timeout":
            raise _Failure(Status.ERROR, "timeout", f"{label}: no answer in time: could not verify") from None
        if _EMPTY_REPLY.search(str(exc)) or _EMPTY_REPLY.search(str(getattr(exc, "kind", ""))):
            raise _Failure(Status.BLOCKED, "geo_block", f"{label}: empty reply / connection dropped (geo or WAF filtering; A9: needs the "
                                                        "team's Brazilian egress): could not verify") from None
        raise _Failure(Status.ERROR, "error", f"{label}: network error ({exc}): could not verify") from None
    except HttpError as exc:
        raise _Failure(Status.ERROR, "error", f"{label}: {exc}: could not verify") from None


def _json(ctx: Any, resp: Any, label: str) -> Any:
    """Classify (markers, challenge pages) and parse a 2xx JSON body; anything else is a _Failure."""
    try:
        ctx.http.check(resp)
    except Blocked as exc:
        code = str(getattr(exc, "reason_code", "") or "challenge")
        raise _Failure(Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall") else "challenge",
                       f"{label}: blocked ({exc}): could not verify") from None
    except RateLimited as exc:
        raise _Failure(Status.RATE_LIMITED, "rate_limited", f"{label}: rate limited ({exc}): could not verify") from None
    except QuotaExceeded as exc:
        raise _Failure(Status.QUOTA, "quota", f"{label}: quota exhausted ({exc}): could not verify") from None
    except AuthRequired as exc:
        raise _Failure(Status.BLOCKED, "challenge", f"{label}: refused ({exc}): could not verify") from None
    except HttpError as exc:
        raise _Failure(Status.ERROR, "error", f"{label}: {exc}: could not verify") from None
    if _HTML.match((resp.text or "")[:512]):
        raise _Failure(Status.ERROR, "error", f"{label}: an HTML page instead of JSON: could not verify")
    try:
        return json.loads(resp.text)
    except ValueError:
        raise _Failure(Status.ERROR, "error", f"{label}: malformed JSON: could not verify") from None


def _finish(res: ModuleResult, coverage: dict[str, dict[str, Any]], rows: list[dict[str, Any]], empty_text: str) -> ModuleResult:
    failures = [c for c in coverage.values() if c["state"] not in ("ok", "empty", "not_queried")]
    answered = [c for c in coverage.values() if c["state"] in ("ok", "empty")]
    if rows:
        res.attr("public_funding_coverage", coverage)
        return res
    if answered and not failures:
        return res.mark(Status.EMPTY, empty_text)
    if answered:
        res.attr("public_funding_coverage", coverage)
        return res.mark(Status.EMPTY, empty_text + "; could not verify: " + "; ".join(c["reason"] for c in failures))
    if not failures:
        return res.mark(Status.SKIPPED, "no provider queried", reason_code="not_applicable")
    order = [Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR]
    worst = min((Status(c["status"]) for c in failures), key=lambda s: order.index(s) if s in order else len(order))
    code = next(c["code"] for c in failures if c["status"] == worst.value)
    return res.mark(worst, "; ".join(c["reason"] for c in failures)[:500], reason_code=code)


def _record(res: ModuleResult, coverage: dict[str, dict[str, Any]], key: str, source: str, status: Status, *, code: str = "",
            reason: str = "") -> None:
    res.source_status(source, status, reason_code=code, reason=reason[:300])
    state = {Status.OK: "ok", Status.EMPTY: "empty", Status.BLOCKED: "blocked", Status.RATE_LIMITED: "rate_limited",
             Status.QUOTA: "quota", Status.SKIPPED: "not_queried"}.get(status, "error")
    coverage[key] = {"state": state, "status": status.value, "code": code, "reason": reason[:300]}


# ======================================================================================
# the modules
# ======================================================================================


@register
class BrPublicSpending(Module):
    name = "br_public_spending"
    title = "BR public financing and incentives by CNPJ (BNDES, SALIC)"
    description = (
        "BNDES financing operations (CKAN datastore, exact CNPJ) and Lei Rouanet sponsorship (SALIC incentivadores) of a CNPJ: "
        "operation id, organ, value, dates, status and URL, at most 20 rows per provider; companies only."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ}
    produces = frozenset()
    tags = {"brazil"}
    reference = "https://dadosabertos.bndes.gov.br/"
    notice = (
        "Sends the CNPJ to BNDES (CKAN datastore) and to the Ministerio da Cultura SALIC API. CNPJ-centric only: SALIC "
        "natural-person sponsors and BNDES masked-CPF rows are never matched, stored or pivoted. A blocked or failed provider "
        "reads 'could not verify', never 'no operations'."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("dadosabertos.bndes.gov.br", "api.salic.cultura.gov.br")
    provider = "bndes"
    sources = (SOURCE_BNDES, SOURCE_SALIC)
    access_model = "free_noauth_limited"
    max_requests = 3
    expected_latency = 4.0
    timeout = 75.0
    min_interval = 1.0
    cache_ttl = 86400
    daily_quota = 200
    max_pivots = 0
    default_enabled = False  # P246 cond 5: opt-in
    settings = {"br_public_spending_bndes_indirect": False}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        cnpj = str(entity.value)
        allowed = frozenset(getattr(ctx, "allowed_sources", None) or self.sources)
        coverage: dict[str, dict[str, Any]] = {}
        rows: list[dict[str, Any]] = []
        dropped = 0
        if SOURCE_BNDES in allowed:
            resources = ["naut"] + (["aut"] if ctx.setting("br_public_spending_bndes_indirect", False) else [])
            got: list[dict[str, Any]] = []
            failure: _Failure | None = None
            for resource in resources:
                try:
                    resp = _call(ctx, bndes_query_url(resource, cnpj), SOURCE_BNDES, "BNDES")
                    parsed = parse_bndes_datastore(_json(ctx, resp, "BNDES"), cnpj, resource)
                except _Failure as exc:
                    failure = failure or exc
                    continue
                if not parsed["ok"]:
                    failure = failure or _Failure(Status.ERROR, "error", f"BNDES: {parsed['error']}: could not verify")
                    continue
                got += parsed["records"]
                dropped += parsed["dropped_persons"]
            got = got[:MAX_ROWS]
            if got:
                _record(res, coverage, "bndes", SOURCE_BNDES, Status.OK, reason=f"{len(got)} operation(s)")
            elif failure is not None:
                _record(res, coverage, "bndes", SOURCE_BNDES, failure.status, code=failure.code, reason=failure.reason)
            else:
                _record(res, coverage, "bndes", SOURCE_BNDES, Status.EMPTY, reason="no BNDES operation with this exact CNPJ")
            rows += got
        else:
            _record(res, coverage, "bndes", SOURCE_BNDES, Status.SKIPPED, code="licence", reason="not allowed in this run")
        if SOURCE_SALIC in allowed:
            try:
                resp = _call(ctx, salic_query_url(cnpj), SOURCE_SALIC, "SALIC")
                if int(resp.status) == 404 and resp.classification is None and salic_not_found(resp.content):
                    _record(res, coverage, "salic", SOURCE_SALIC, Status.EMPTY, reason="SALIC: no sponsor with this CNPJ (message_code 11)")
                else:
                    parsed = parse_salic_incentivadores(_json(ctx, resp, "SALIC"), cnpj)
                    if not parsed["ok"]:
                        raise _Failure(Status.ERROR, "error", f"SALIC: {parsed['error']}: could not verify")
                    dropped += parsed["dropped_persons"]
                    rows += parsed["rows"]
                    _record(res, coverage, "salic", SOURCE_SALIC, Status.OK if parsed["rows"] else Status.EMPTY,
                            reason=f"{len(parsed['rows'])} sponsor record(s)")
            except _Failure as exc:
                _record(res, coverage, "salic", SOURCE_SALIC, exc.status, code=exc.code, reason=exc.reason)
        else:
            _record(res, coverage, "salic", SOURCE_SALIC, Status.SKIPPED, code="licence", reason="not allowed in this run")
        if rows:
            res.attr("public_funding", rows)
            res.raw = {"public_funding": rows, "dropped_persons": dropped}
            self._findings(res, cnpj, rows)
        return _finish(res, coverage, rows, "no BNDES operation and no SALIC sponsorship for this CNPJ")

    @staticmethod
    def _findings(res: ModuleResult, cnpj: str, rows: list[dict[str, Any]]) -> None:
        bndes = [r for r in rows if r["source"] == "bndes"]
        if bndes:
            exact = [r for r in bndes if r["match"] == "exact"]
            total = sum(r["value"] or 0.0 for r in bndes)
            res.finding(
                "BNDES financing operations", "info",
                f"{len(bndes)} BNDES operation(s) for {format_cnpj(cnpj)}, contracted total R$ {total:,.2f}; latest "
                f"{max((r['date'] or '' for r in bndes), default='') or '?'}"
                + ("" if exact else " (masked CNPJ in the source: possible match only)"),
                confidence="confirmed" if exact else "possible", source=SOURCE_BNDES, key="bndes",
                criterion="client CNPJ of BNDES operations " + ("equal to the query" if exact else "matching the masked form (**.*NN.NNN/NNNN-**)"),
                data={"operations": [r["operation_id"] for r in bndes], "count": len(bndes)},
            )
        salic = [r for r in rows if r["source"] == "salic"]
        if salic:
            res.finding(
                "Lei Rouanet cultural-incentive sponsor (SALIC)", "info",
                f"{format_cnpj(cnpj)} is a SALIC sponsor (incentivador): total donated R$ {salic[0]['value'] or 0:,.2f}",
                confidence="confirmed", source=SOURCE_SALIC, key="salic",
                criterion="SALIC incentivadores record with the queried CNPJ (company sponsor)",
                data={"total_donated": salic[0]["value"], "url": salic[0]["url"]},
            )


@register
class BrPublicSpendingBr(Module):
    name = "br_public_spending_br"
    title = "BR federal procurement by CNPJ (Compras.gov.br SICAF, PNCP; BR egress only)"
    description = (
        "Compras.gov.br SICAF supplier record of a CNPJ and the PNCP contract search, automated only from the team's Brazilian "
        "egress (A9); otherwise skipped with manual links. PNCP is a manual link until a Brazilian-egress capture exists."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ}
    produces = frozenset()
    tags = {"brazil"}
    reference = "https://dadosabertos.compras.gov.br/swagger-ui/index.html"
    notice = (
        "Needs the team's own Brazilian egress (requires_egress BR): never through a VPN, proxy exit or rotated IPs chosen to "
        "defeat a geo-block. A 403, challenge, geo-block or empty reply reads 'could not verify' with the manual link, never "
        "'no contracts'. Partners, e-mail and phone of the SICAF record are never kept."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("dadosabertos.compras.gov.br",)
    provider = "compras_gov"
    sources = (SOURCE_COMPRAS, SOURCE_PNCP)
    access_model = "free_noauth_limited"
    requires_egress = frozenset({"BR"})
    manual_link = PNCP_MANUAL
    max_requests = 1
    expected_latency = 2.0
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 86400
    daily_quota = 200
    max_pivots = 0
    default_enabled = False  # P246 cond 5: opt-in

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        cnpj = str(entity.value)
        res.link("PNCP - contracts and tenders search by CNPJ (manual)", f"https://pncp.gov.br/app/contratos?q={cnpj}")
        res.link("Compras.gov.br - SICAF supplier record (manual)", compras_fornecedor_url(cnpj))
        allowed = frozenset(getattr(ctx, "allowed_sources", None) or self.sources)
        coverage: dict[str, dict[str, Any]] = {}
        # PNCP (FC2): no automated request until a success fixture is captured from the team's Brazilian egress
        _record(res, coverage, "pncp", SOURCE_PNCP, Status.SKIPPED, code="config",
                reason="PNCP automation pending a success capture from the team's Brazilian egress: manual link emitted")
        rows: list[dict[str, Any]] = []
        if SOURCE_COMPRAS in allowed:
            try:
                resp = _call(ctx, compras_fornecedor_url(cnpj), SOURCE_COMPRAS, "Compras.gov.br")
                parsed = parse_compras_fornecedor(_json(ctx, resp, "Compras.gov.br"), cnpj)
                if not parsed["ok"]:
                    raise _Failure(Status.ERROR, "error", f"{parsed['error']}: could not verify")
                rows = parsed["rows"]
                _record(res, coverage, "compras", SOURCE_COMPRAS, Status.OK if rows else Status.EMPTY,
                        reason=f"{len(rows)} active SICAF supplier record(s)")
            except _Failure as exc:
                _record(res, coverage, "compras", SOURCE_COMPRAS, exc.status, code=exc.code, reason=exc.reason)
        else:
            _record(res, coverage, "compras", SOURCE_COMPRAS, Status.SKIPPED, code="licence", reason="not allowed in this run")
        if rows:
            sicaf = rows[0]
            res.attr("sicaf_supplier", sicaf)
            res.raw = {"sicaf_supplier": sicaf}
            res.finding(
                "Registered supplier in SICAF (Compras.gov.br)", "info",
                f"{sicaf.get('name') or format_cnpj(cnpj)}: active {sicaf['active']}, SICAF qualified {sicaf['qualified']}, "
                f"{len(sicaf['supply_lines'])} supply line(s)",
                confidence="confirmed", source=SOURCE_COMPRAS, key="sicaf",
                criterion="active SICAF supplier record returned for the exact CNPJ by the Compras.gov.br open-data API",
                data={"active": sicaf["active"], "qualified": sicaf["qualified"], "supply_lines": sicaf["supply_lines"]},
            )
        return _finish(res, coverage, rows, "no active SICAF supplier record for this CNPJ (PNCP: manual link)")


__all__ = [
    "BrPublicSpending", "BrPublicSpendingBr", "bndes_masked_cnpj", "bndes_query_url", "ckan_problem", "compras_fornecedor_url",
    "compras_problem", "contract_dedup_key", "parse_bndes_datastore", "parse_compras_fornecedor", "parse_salic_incentivadores",
    "salic_not_found", "salic_query_url",
]
