"""P237 ``portal_transparencia_api`` - Portal da Transparencia API (CGU, keyed): CNPJ-centric sanctions detail,
federal contracts, agreements and payments; PEP by name for a recorded due-diligence subject.

Council P237 final conditions, as implemented here:

1. ``requires_keys = ('transparencia',)`` (provider ``transparencia_api``, env V3LUM_TRANSPARENCIA_KEY /
   V3LUM_CGU_KEY): the key travels only in the ``chave-api-dados`` header, never in a URL or a log (the core
   registers it with the redactor; it is a credential header on redirects). Key plans: CGU open data,
   ``free_plan_business_use`` true in the registry.
2. Without a key the engine answers NEEDS_KEY before the run; :data:`NO_KEY_HINT` is the one-line hint (it is
   also the notice). A 401 'Chave de API nao informada' body maps to NEEDS_KEY.
3. Rule 4 floor: no CPF or NIS is ever sent. Only the CNPJ endpoints below and ``/peps?nome=`` exist here;
   :func:`build_request` refuses anything else and :func:`personal_param_violations` checks every URL
   (``/pessoa-fisica``, ``/ceaf``, ``/peps?cpf``, servidores by CPF and the benefit endpoints are not
   implemented).
4. Default endpoints are CNPJ-centric: the ``/pessoa-juridica`` summary, CEIS, CNEP, CEPIM, acordos de
   leniencia, contracts, convenios and payments by CNPJ. PEP is queried by name only for a person the analyst
   typed (seed, not a pivot or a text extract) with a recorded purpose; otherwise SKIPPED 'privacy'.
5. Sanctions are not parsed twice: when the P240 bulk list (dataset ``cgu_sanctions_bulk.<list>``) was
   fetched less than 48 h ago, its findings stand and this module only adds the API detail for a listing the
   summary flags (attribute ``cgu_api_sanctions``, no finding); when it is stale or absent the API rows go
   through P240's row normaliser (``cgu_sanctions_bulk._sanction_row``) and become the findings, with the
   shared ``data['dedup_key']`` '<list>|<cnpj>|<sanction id>' (rule ``g10_sanction_dedup``).
6. Ceos guard: a row that does not carry the queried CNPJ means the filter was ignored -> that endpoint is
   ERROR, never findings. Bodies declared ISO-8859-1 are decoded as such; ``{"Erro na API": ...}`` inside a
   200 is an error (rule 5).
7. Limits: the per-key 90 req/min (06:00-23:59) / 300 req/min (00:00-05:59) is the provider quota block
   (P334); 429 -> RATE_LIMITED; pagination capped at 3 pages of 15; ``max_requests = 10`` per entity (beyond
   it the run is partial, stop reason 'request_cap'). Contracts: count, total value and the 5 most recent.
8. API only: the portal's web pages answer 202 bot challenges and are never fetched (only
   api.portaldatransparencia.gov.br is declared).
9. Success fixtures captured with the team key are pending (no key in this environment): the offline tests use
   schema-derived synthetic answers plus the real keyless 401; see docs/backlog/p2-G10-1.md.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

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

try:  # P240's row normaliser and dedup key (batch p1-G10-2): one normaliser for API and bulk rows (cond 5)
    from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import LISTS as _BULK_LISTS
    from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import _sanction_row as _bulk_row
    from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import dedup_key as _bulk_dedup_key
    from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import sanction_status as _bulk_status
except ImportError:  # pragma: no cover - P240 moved: sanctions are reported as detail only (no second parser)
    _BULK_LISTS = {}
    _bulk_row = _bulk_dedup_key = _bulk_status = None

SOURCE = "transparencia_api.api_dados"
HOST = "api.portaldatransparencia.gov.br"
BASE = f"https://{HOST}/api-de-dados"
KEY_NAME = "transparencia"
KEY_HEADER = "chave-api-dados"
PAGE_SIZE = 15
PAGE_CAP = 3  # cond 7
MAX_REQUESTS = 10  # cond 7 (A3 BR2)
BULK_FRESH_H = 48  # cond 5
NO_KEY_HINT = ("add V3LUM_TRANSPARENCIA_KEY for contracts/leniency; sanctions already checked keyless by "
               "tcu_certidoes/cgu_sanctions_bulk")
PORTAL_LINK = "https://portaldatransparencia.gov.br/pessoa-juridica/{cnpj}"
BRT = timezone(timedelta(hours=-3))

#: cond 4: CNPJ-centric endpoints; the CNPJ parameter is always a valid CNPJ (cond 3 guard)
ENDPOINTS: dict[str, dict[str, Any]] = {
    "pessoa_juridica": {"path": "/pessoa-juridica", "param": "cnpj", "paged": False},
    "ceis": {"path": "/ceis", "param": "codigoSancionado", "paged": True, "list": "ceis", "flag": "sancionadoCEIS"},
    "cnep": {"path": "/cnep", "param": "codigoSancionado", "paged": True, "list": "cnep", "flag": "sancionadoCNEP"},
    "cepim": {"path": "/cepim", "param": "cnpjSancionado", "paged": True, "list": "cepim", "flag": "sancionadoCEPIM"},
    "acordos_leniencia": {"path": "/acordos-leniencia", "param": "cnpjSancionado", "paged": True, "list": "acordos_leniencia",
                          "flag": None},
    "contratos": {"path": "/contratos/cpf-cnpj", "param": "cpfCnpj", "paged": True, "flag": "possuiContratacao"},  # v3lum-lint: allow LINT-04 -- the CGU contract search by supplier; cond 3 guard: the parameter only ever carries a check-digit-valid CNPJ, never a CPF
    "convenios": {"path": "/convenios", "param": "convenente", "paged": True, "flag": "convenios"},
    "despesas": {"path": "/despesas/documentos-por-favorecido", "param": "codigoPessoa", "paged": True, "flag": "favorecidoDespesas",
                 "fixed": (("fase", "3"),), "year": True},
}
NAME_ENDPOINTS = {"peps": {"path": "/peps", "param": "nome"}}
SANCTION_ENDPOINTS = ("ceis", "cnep", "cepim", "acordos_leniencia")
#: cond 3: never built
FORBIDDEN_PARAMS = frozenset({"cpf", "nis", "cpfsancionado", "cpfportador", "cpfocupante", "codigobeneficiario",
                              "codigoresponsavelfamiliar"})
CNPJ_ONLY_PARAMS = frozenset({"cnpj", "codigosancionado", "cnpjsancionado", "cpfcnpj", "codigopessoa", "cpfcnpjfavorecido",
                              "codigofavorecido", "convenente"})
FORBIDDEN_PATH_PREFIXES = ("/pessoa-fisica", "/ceaf", "/viagens-por-cpf", "/servidores/remuneracao", "/permissionarios", "/cartoes",
                           "/auxilio-", "/bolsa-familia", "/novo-bolsa-familia", "/bpc-", "/peti-", "/safra-", "/seguro-defeso")
LATIN1 = frozenset({"iso-8859-1", "iso8859-1", "iso_8859-1", "latin-1", "latin1", "l1", "cp819"})


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _s(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", _s(text))
    return "".join(c for c in t if not unicodedata.combining(c)).upper()


def _cnpj_val(c: str) -> int:
    return ord(c) - 48


def normalize_cnpj(value: Any) -> str | None:
    c = re.sub(r"[\s./-]", "", _s(value)).upper()
    if not re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", c) or c == c[0] * 14:
        return None
    out = ""
    for weights in ((5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2), (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)):
        r = sum(_cnpj_val(ch) * weights[i] for i, ch in enumerate(c[:12] + out)) % 11
        out += "0" if r < 2 else str(11 - r)
    return c if out == c[12:] else None


def format_cnpj(value: Any) -> str:
    c = normalize_cnpj(value) or _s(value)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if len(c) == 14 else c


def eleven_digit_value(value: Any) -> bool:
    """CPF- or NIS-shaped value (11 digits after removing punctuation)."""
    return bool(re.fullmatch(r"\d{11}", re.sub(r"[\s./-]", "", _s(value))))


def mask_cpf(value: Any) -> str | None:
    """A published CPF is kept only masked (***.456.789-**), whatever form the API returns."""
    raw = _s(value)
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11:
        return f"***.{digits[3:6]}.{digits[6:9]}-**"
    if "*" in raw and len(re.sub(r"[^0-9*]", "", raw)) == 11:
        d = re.sub(r"[^0-9*]", "", raw)
        return f"***.{d[3:6]}.{d[6:9]}-**"
    return None


def iso_date(value: Any) -> str | None:
    s = _s(value)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", s)
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else None


def parse_money(value: Any) -> float | None:
    """150000.0 | '150.000,00' | 'R$ 1.234,56' | '1234.56' -> float; garbage -> None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    s = re.sub(r"[^\d,.-]", "", _s(value))
    if not s or not re.search(r"\d", s):
        return None
    if "," in s:
        s = s.replace(".", "").replace(",", ".")
    elif s.count(".") > 1:
        s = s.replace(".", "")
    try:
        return float(s)
    except ValueError:
        return None


# --------------------------------------------------------------------------------------
# request builders (cond 3, 4, 7)
# --------------------------------------------------------------------------------------


def personal_param_violations(url: str) -> list[str]:
    """cond 3: every reason a request would send a CPF/NIS or touch a person/benefit endpoint ([] = clean)."""
    parts = urlsplit(_s(url))
    path = parts.path
    if path.startswith("/api-de-dados"):
        path = path[len("/api-de-dados"):]
    out = [f"forbidden endpoint {pre}" for pre in FORBIDDEN_PATH_PREFIXES if path.startswith(pre)]
    if re.match(r"^/servidores(/|$)", path):
        out.append("servidores endpoints are not implemented")
    query = parse_qsl(parts.query, keep_blank_values=True)
    for k, v in query:
        kl = k.lower()
        if kl in FORBIDDEN_PARAMS or (kl == "codigo" and "cpf-ou-nis" in path):
            out.append(f"forbidden parameter {k}")
        if eleven_digit_value(v):
            out.append(f"CPF/NIS-shaped value in {k}")
        if kl in CNPJ_ONLY_PARAMS and not normalize_cnpj(v):
            out.append(f"{k} must carry a valid CNPJ")
    if path == "/peps" and not any(k.lower() == "nome" for k, _ in query):
        out.append("/peps only by name for a due-diligence subject")
    return out


def build_request(endpoint: str, cnpj: Any, *, page: int = 1, year: int | None = None) -> str:
    """URL of a CNPJ-centric endpoint. The key never goes into the URL. ValueError for an invalid CNPJ or a
    page beyond the cap; PermissionError for anything cond 3 forbids."""
    spec = ENDPOINTS.get(endpoint)
    if not spec:
        raise PermissionError(f"endpoint not implemented: {endpoint}")
    c = normalize_cnpj(cnpj)
    if not c:
        raise ValueError("a valid CNPJ is required (CPF/NIS are never sent)")
    params: list[tuple[str, str]] = [(spec["param"], c)]
    if spec.get("paged"):
        if page < 1 or page > PAGE_CAP:
            raise ValueError(f"page beyond the cap of {PAGE_CAP}")
        params += list(spec.get("fixed") or ())
        if spec.get("year"):
            if not year:
                raise ValueError("year required")
            params.append(("ano", str(int(year))))
        params.append(("pagina", str(page)))
    url = BASE + spec["path"] + "?" + urlencode(params)
    bad = personal_param_violations(url)
    if bad:
        raise PermissionError("; ".join(bad))
    return url


def build_name_request(endpoint: str, name: Any, *, page: int = 1) -> str:
    """cond 4: /peps?nome= for a recorded due-diligence subject (never by CPF)."""
    spec = NAME_ENDPOINTS.get(endpoint)
    n = re.sub(r"\s+", " ", _s(name))
    if not spec:
        raise PermissionError(f"endpoint not implemented: {endpoint}")
    if len(n) < 5 or re.search(r"\d", n):
        raise ValueError("a full name is required (no digits)")
    url = BASE + spec["path"] + "?" + urlencode([(spec["param"], n), ("pagina", str(page))])
    bad = personal_param_violations(url)
    if bad:
        raise PermissionError("; ".join(bad))
    return url


def plan(flags: dict[str, Any] | None, fresh: dict[str, bool], *, budget: int = MAX_REQUESTS - 1) -> list[str]:
    """cond 4/5/7: endpoints after the summary call. A list whose bulk copy is fresh is asked only for the
    detail of a listing the summary flags; a stale/absent list is asked unless the summary says 'no'.
    Contracts reserve their 3-page cap; payments come last; the total stays within ``budget``."""
    f = _d(flags)
    out: list[str] = []
    for ep in SANCTION_ENDPOINTS:
        flag = ENDPOINTS[ep].get("flag")
        if fresh.get(ep):
            if flag and f.get(flag) is True:
                out.append(ep)
            continue
        if flag and f.get(flag) is False:
            continue
        out.append(ep)
    if f.get("possuiContratacao") is not False:
        out += ["contratos"] * PAGE_CAP
    if f.get("convenios") is True:
        out.append("convenios")
    if f.get("favorecidoDespesas") is True:
        out.append("despesas")
    return out[: max(0, budget)]


# --------------------------------------------------------------------------------------
# parsers (cond 2, 5, 6, 7)
# --------------------------------------------------------------------------------------


def decode_body(content: bytes, content_type: str = "") -> str:
    """cond 6: bodies declared ISO-8859-1 are decoded as such; undeclared: UTF-8, then ISO-8859-1."""
    m = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_\-:.]+)", content_type or "", re.I)
    cs = m.group(1).lower() if m else ""
    raw = bytes(content or b"")
    if cs in LATIN1:
        return raw.decode("latin-1")
    if cs in ("windows-1252", "cp1252"):
        return raw.decode("cp1252", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_json(content: bytes, content_type: str = "") -> tuple[Any, str | None]:
    text = decode_body(content, content_type)
    if not text.strip():
        return None, "empty body"
    head = text.lstrip()[:1]
    if head not in ("{", "["):
        return None, "HTML or text where JSON was expected"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "invalid JSON (truncated or malformed)"


def key_error(obj: Any) -> str | None:
    """cond 2: the 401 body {'Erro na API': 'Chave de API nao informada! ...'} (or invalid/expired key)."""
    msg = _s(_d(obj).get("Erro na API"))
    f = fold(msg)
    if "CHAVE" in f and any(w in f for w in ("NAO INFORMADA", "INVALIDA", "EXPIRADA", "BLOQUEADA", "NAO ENCONTRADA")):
        return msg[:160]
    return None


def error_marker(obj: Any) -> str | None:
    """cond 6 rule 5: error JSON inside a response."""
    if not isinstance(obj, dict):
        return None
    for k in ("Erro na API", "erro", "error", "mensagem"):
        if obj.get(k):
            return f"error JSON ({k}: {_s(obj.get(k))[:100]})"
    return None


def _row_docs(endpoint: str, row: Any) -> set[str]:
    r = _d(row)
    vals: list[Any] = []
    if endpoint in ("ceis", "cnep"):
        vals += [_d(r.get("sancionado")).get("codigoFormatado"), _d(r.get("pessoa")).get("cnpjFormatado")]
    elif endpoint == "cepim":
        vals += [_d(r.get("pessoaJuridica")).get("cnpjFormatado")]
    elif endpoint == "acordos_leniencia":
        for s in _l(r.get("sancoes")):
            vals += [_d(s).get("cnpj"), _d(s).get("cnpjFormatado")]
    elif endpoint == "contratos":
        vals += [_d(r.get("fornecedor")).get("cnpjFormatado")]
    elif endpoint == "convenios":
        vals += [_d(r.get("convenente")).get("cnpjFormatado")]
    elif endpoint == "despesas":
        vals += [r.get("codigoFavorecido")]
    elif endpoint == "pessoa_juridica":
        vals += [r.get("cnpj")]
    return {c for c in (normalize_cnpj(v) for v in vals) if c}


def filter_guard(endpoint: str, rows: Any, cnpj: str) -> str | None:
    """cond 6 (Ceos guard): any row without the queried CNPJ means the filter was ignored -> reason."""
    rows = rows if isinstance(rows, list) else [rows]
    bad = sum(1 for r in rows if cnpj not in _row_docs(endpoint, r))
    if bad:
        return f"filter ignored: {bad} of {len(rows)} {endpoint} rows do not carry the queried CNPJ"
    return None


def parse_summary(obj: Any) -> dict[str, Any]:
    """/pessoa-juridica summary flags."""
    o = _d(obj)
    keys = ("sancionadoCEIS", "sancionadoCNEP", "sancionadoCEPIM", "possuiContratacao", "convenios", "favorecidoDespesas",
            "participanteLicitacao", "favorecidoTransferencias")
    return {k: (o.get(k) if isinstance(o.get(k), bool) else None) for k in keys}


def api_row_to_bulk_record(list_key: str, row: Any) -> list[dict[str, Any]]:
    """cond 5: one API row -> records keyed like P240's bulk columns, for P240's normaliser. A CPF is never
    carried (rule 4); leniency rows expand to one record per sanctioned company."""
    r = _d(row)
    if list_key in ("ceis", "cnep"):
        p, sanc, org = _d(r.get("pessoa")), _d(r.get("sancionado")), _d(r.get("orgaoSancionador"))
        doc = re.sub(r"\D", "", _s(sanc.get("codigoFormatado")) or _s(p.get("cnpjFormatado")))
        person_type = "J" if len(doc) == 14 or _s(p.get("cnpjFormatado")) else ("F" if doc else "")
        rec = {
            "sanction_id": _s(r.get("id")), "person_type": person_type, "doc": doc if person_type == "J" else "",
            "name": _s(sanc.get("nome")), "rfb_name": _s(p.get("razaoSocialReceita")), "process": _s(r.get("numeroProcesso")),
            "category": _s(_d(r.get("tipoSancao")).get("descricaoResumida")), "start": _s(r.get("dataInicioSancao")),
            "end": _s(r.get("dataFimSancao")), "published": _s(r.get("dataPublicacaoSancao")),
            "res_judicata": _s(r.get("dataTransitadoJulgado")), "scope": _s(r.get("abrangenciaDefinidaDecisaoJudicial")),
            "organ": _s(org.get("nome")), "organ_uf": _s(org.get("siglaUf")), "sphere": _s(org.get("esfera")).upper(),
            "legal_basis": "; ".join(x for x in (_s(_d(f).get("descricao")) for f in _l(r.get("fundamentacao"))) if x),
        }
        if list_key == "cnep":
            rec["fine"] = _s(r.get("valorMulta"))
        return [rec]
    if list_key == "cepim":
        pj = _d(r.get("pessoaJuridica"))
        agreement = _s(_d(r.get("convenio")).get("numero"))
        return [{"sanction_id": agreement, "person_type": "J", "doc": re.sub(r"\D", "", _s(pj.get("cnpjFormatado"))),
                 "name": _s(pj.get("razaoSocialReceita")) or _s(pj.get("nome")), "category": _s(r.get("motivo")),
                 "organ": _s(_d(r.get("orgaoSuperior")).get("nome"))}]
    if list_key == "acordos_leniencia":
        out = []
        for s in _l(r.get("sancoes")):
            sd = _d(s)
            out.append({"sanction_id": _s(r.get("id")), "person_type": "J",
                        "doc": re.sub(r"\D", "", _s(sd.get("cnpj")) or _s(sd.get("cnpjFormatado"))),
                        "name": _s(sd.get("razaoSocial")) or _s(sd.get("nomeInformadoOrgaoResponsavel")),
                        "category": "Acordo de leniência", "start": _s(r.get("dataInicioAcordo")), "end": _s(r.get("dataFimAcordo")),
                        "organ": _s(r.get("orgaoResponsavel")), "situation": _s(r.get("situacaoAcordo"))})
        return out
    return []


def normalise_sanction(list_key: str, rec: dict[str, Any], source_date: str) -> dict[str, Any]:
    """P240's normaliser for one bulk-shaped record (cond 5), plus the fields it keeps for leniency rows."""
    if _bulk_row is None:  # pragma: no cover - P240 missing
        return {"list": list_key, "sanction_id": rec.get("sanction_id"), "cnpj": normalize_cnpj(rec.get("doc"))}
    row = _bulk_row(list_key, rec, source_date)
    if rec.get("situation"):
        row["situation"] = rec["situation"]
    return row


def summarize_items(rows: list[Any], kind: str, *, pages: int, last_page_rows: int, top: int = 5) -> dict[str, Any]:
    """cond 7: count, total value and the 5 most recent (contracts / agreements / payments)."""
    items: list[dict[str, Any]] = []
    total = 0.0
    for row in rows:
        r = _d(row)
        if kind == "contratos":
            value = parse_money(r.get("valorFinalCompra"))
            if value is None:
                value = parse_money(r.get("valorInicialCompra"))
            date = next((iso_date(r.get(k)) for k in ("dataAssinatura", "dataInicioVigencia", "dataPublicacaoDOU") if iso_date(r.get(k))), None)
            item = {"number": _s(r.get("numero")) or None, "object": _s(r.get("objeto"))[:200] or None, "signed": date, "value": value,
                    "situation": _s(r.get("situacaoContrato")) or None, "organ": _s(_d(r.get("unidadeGestora")).get("nome")) or None}
        elif kind == "convenios":
            value = parse_money(r.get("valor"))
            dim = _d(r.get("dimConvenio"))
            item = {"number": _s(dim.get("numero")) or None, "object": _s(dim.get("objeto"))[:200] or None,
                    "signed": iso_date(r.get("dataPublicacao")) or iso_date(r.get("dataInicioVigencia")), "value": value,
                    "situation": _s(r.get("situacao")) or None, "organ": _s(_d(r.get("orgao")).get("nome")) or None}
        else:
            value = parse_money(r.get("valor"))
            item = {"number": _s(r.get("documentoResumido") or r.get("documento")) or None, "object": _s(r.get("observacao"))[:200] or None,
                    "signed": iso_date(r.get("data")), "value": value, "situation": _s(r.get("fase")) or None,
                    "organ": _s(r.get("orgao")) or None}
        total += value or 0.0
        items.append(item)
    items.sort(key=lambda x: x.get("signed") or "", reverse=True)
    capped = pages >= PAGE_CAP and last_page_rows >= PAGE_SIZE
    return {"count": len(items), "count_is_lower_bound": capped or last_page_rows >= PAGE_SIZE, "total_value": round(total, 2),
            "currency": "BRL", "most_recent": [{k: v for k, v in i.items() if v not in (None, "")} for i in items[:top]],
            "pages": pages, "partial": capped}


def bulk_fresh(ctx: Any, list_key: str) -> bool:
    """cond 5: the P240 bulk copy of this list was fetched less than 48 h ago."""
    spec = _BULK_LISTS.get(list_key)
    data = getattr(ctx, "data", None)
    if spec is None or data is None:
        return False
    try:
        info = data.info(spec.dataset)
    except Exception:
        return False
    if not getattr(info, "present", False):
        return False
    try:
        fetched = datetime.fromisoformat(str(getattr(info, "fetched_at", "") or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    return (ctx.now() - fetched) < timedelta(hours=BULK_FRESH_H)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


class _Failure(Exception):
    def __init__(self, status: Status, reason: str, code: str = "") -> None:
        super().__init__(reason)
        self.status, self.reason, self.code = status, reason, code


@register
class PortalTransparenciaApi(Module):
    name = "portal_transparencia_api"
    title = "Portal da Transparencia API (CGU)"
    description = (
        "CNPJ-centric CGU open data with the team key: the /pessoa-juridica summary, CEIS/CNEP/CEPIM/leniency detail "
        "(P240 bulk lists first), federal contracts, agreements and payments; PEP by name for a recorded due-diligence subject."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.PERSON}
    produces: set[Any] = set()
    tags = {"brazil"}
    reference = "https://api.portaldatransparencia.gov.br/swagger-ui/index.html"
    notice = (
        "Needs the team's institutional key (V3LUM_TRANSPARENCIA_KEY; never a personal or borrowed key): " + NO_KEY_HINT + ". "
        "No CPF or NIS is ever sent; PEP is searched by name only for an analyst-typed due-diligence subject with a recorded "
        "purpose. The portal's web pages (bot challenges) are never fetched."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = (HOST,)
    provider = "transparencia_api"
    sources = (SOURCE,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = MAX_REQUESTS  # cond 7
    expected_latency = 5.0  # summary + up to 9 drill-downs paced at 1 s (no keyed measurement yet)
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 0
    default_enabled = True  # A3: council P237 (a key-required trusted government source may be default)

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = _s(ctx.key(KEY_NAME)) if callable(getattr(ctx, "key", None)) else ""
        if not key:
            return res.mark(Status.NEEDS_KEY, NO_KEY_HINT, reason_code="needs_key")
        if entity.type is T.PERSON:
            return self._pep(res, ctx, key, str(entity.value), entity)
        cnpj = normalize_cnpj(entity.value)
        if not cnpj:
            return res.mark(Status.SKIPPED, "not a valid CNPJ (check digits)", reason_code="not_applicable")
        return self._cnpj(res, ctx, key, cnpj)

    # ------------------------------------------------------------------ HTTP
    def _get(self, ctx: Any, key: str, url: str) -> Any:
        """One request -> parsed JSON; raises _Failure for every could-not-verify answer (rule 5)."""
        try:
            resp = ctx.http.get(url, source=SOURCE, headers={KEY_HEADER: key, "Accept": "application/json"},
                                cache_if=lambda r: getattr(r, "status", 0) == 200 and _usable(r))
        except AuthRequired as exc:
            raise _Failure(Status.NEEDS_KEY, f"Portal da Transparencia refused the key (HTTP {getattr(exc, 'status', 401)}): "
                                             f"check V3LUM_TRANSPARENCIA_KEY", "needs_key") from None
        except RateLimited as exc:
            raise _Failure(Status.RATE_LIMITED, f"Portal da Transparencia: rate limited ({exc})", "rate_limited") from None
        except QuotaExceeded as exc:
            raise _Failure(Status.QUOTA, f"Portal da Transparencia: quota exhausted ({exc})", "quota") from None
        except Blocked as exc:
            code = str(getattr(exc, "reason_code", "") or "challenge")
            raise _Failure(Status.BLOCKED, f"Portal da Transparencia: blocked ({exc})",
                           code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge") from None
        except DeadlineExceeded:
            remaining = ctx.remaining() if callable(getattr(ctx, "remaining", None)) else None
            if remaining is not None and remaining <= 0:
                raise
            raise _Failure(Status.ERROR, "Portal da Transparencia: no answer in time", "timeout") from None
        except (HttpError, NetworkError) as exc:
            timeout = "timeout" in str(getattr(exc, "kind", "") or "").lower() or "timed out" in str(exc).lower()
            raise _Failure(Status.ERROR, f"Portal da Transparencia: {exc}", "timeout" if timeout else "error") from None
        obj, problem = parse_json(resp.content, str(resp.headers.get("content-type", "")))
        if problem is None and isinstance(obj, dict) and resp.status in (400, 401, 403) and key_error(obj):
            raise _Failure(Status.NEEDS_KEY, f"Portal da Transparencia: {key_error(obj)}", "needs_key")
        try:
            ctx.http.check(resp)
        except AuthRequired:
            raise _Failure(Status.NEEDS_KEY, "Portal da Transparencia refused the key: check V3LUM_TRANSPARENCIA_KEY", "needs_key") from None
        except RateLimited as exc:
            raise _Failure(Status.RATE_LIMITED, f"Portal da Transparencia: rate limited ({exc})", "rate_limited") from None
        except QuotaExceeded as exc:
            raise _Failure(Status.QUOTA, f"Portal da Transparencia: quota exhausted ({exc})", "quota") from None
        except Blocked as exc:
            raise _Failure(Status.BLOCKED, f"Portal da Transparencia: blocked ({exc})", "challenge") from None
        except (HttpError, NetworkError) as exc:
            raise _Failure(Status.ERROR, f"Portal da Transparencia: {exc}", "error") from None
        if problem:
            raise _Failure(Status.ERROR, f"Portal da Transparencia: {problem}: could not verify", "error")
        marker = error_marker(obj)
        if marker:
            raise _Failure(Status.ERROR, f"Portal da Transparencia: {marker} inside HTTP {resp.status}: could not verify", "error")
        return obj

    # ------------------------------------------------------------------ CNPJ
    def _cnpj(self, res: ModuleResult, ctx: Any, key: str, cnpj: str) -> ModuleResult:
        try:
            summary_obj = self._get(ctx, key, build_request("pessoa_juridica", cnpj))
        except _Failure as f:
            return res.mark(f.status, f.reason, reason_code=f.code)
        if not isinstance(summary_obj, dict):
            return res.mark(Status.ERROR, "Portal da Transparencia: /pessoa-juridica answered a non-object: could not verify", reason_code="error")
        guard = filter_guard("pessoa_juridica", summary_obj, cnpj) if summary_obj.get("cnpj") else None
        if guard:
            return res.mark(Status.ERROR, f"Portal da Transparencia /pessoa-juridica: {guard}: could not verify", reason_code="error")
        flags = parse_summary(summary_obj)
        res.attr("transparencia_summary", {
            "sanctioned_ceis": flags["sancionadoCEIS"], "sanctioned_cnep": flags["sancionadoCNEP"], "sanctioned_cepim": flags["sancionadoCEPIM"],
            "has_contracts": flags["possuiContratacao"], "has_agreements": flags["convenios"], "spending_payee": flags["favorecidoDespesas"],
            "bidder": flags["participanteLicitacao"], "transfers_payee": flags["favorecidoTransferencias"],
        })
        res.link("Portal da Transparencia (manual review)", PORTAL_LINK.format(cnpj=cnpj))
        fresh = {ep: bulk_fresh(ctx, ENDPOINTS[ep]["list"]) for ep in SANCTION_ENDPOINTS}
        steps = plan(flags, fresh)
        failures: list[_Failure] = []
        endpoint_states: dict[str, str] = {}
        api_sanctions: list[dict[str, Any]] = []
        today = ctx.now().astimezone(BRT).date()
        source_date = today.isoformat()
        seen: set[str] = set()
        collected: dict[str, list[Any]] = {"contratos": [], "convenios": [], "despesas": []}
        pages: dict[str, tuple[int, int]] = {}
        for ep in steps:
            if ep in seen and ep != "contratos":
                continue
            if ep == "contratos":
                page = pages.get("contratos", (0, PAGE_SIZE))[0] + 1
                last = pages.get("contratos", (0, PAGE_SIZE))[1]
                if page > 1 and last < PAGE_SIZE:
                    continue  # the previous page was not full: no more pages
            else:
                page = 1
            seen.add(ep)
            try:
                url = build_request(ep, cnpj, page=page, year=today.year if ENDPOINTS[ep].get("year") else None)
                rows = self._get(ctx, key, url)
            except _Failure as f:
                failures.append(f)
                endpoint_states[ep] = f"could not verify ({f.reason})"
                continue
            if not isinstance(rows, list):
                failures.append(_Failure(Status.ERROR, f"{ep}: expected a JSON list", "error"))
                endpoint_states[ep] = "could not verify (not a list)"
                continue
            guard = filter_guard(ep, rows, cnpj) if rows else None
            if guard:
                failures.append(_Failure(Status.ERROR, f"{ep}: {guard}", "error"))
                endpoint_states[ep] = f"could not verify ({guard})"
                continue
            if ep in SANCTION_ENDPOINTS:
                endpoint_states[ep] = f"{len(rows)} row(s)" if rows else "no rows"
                for row in rows[:PAGE_SIZE]:
                    for rec in api_row_to_bulk_record(ENDPOINTS[ep]["list"], row):
                        norm = normalise_sanction(ENDPOINTS[ep]["list"], rec, source_date)
                        if norm.get("cnpj") != cnpj:
                            continue  # a leniency agreement row of another signatory
                        api_sanctions.append(norm)
                        if not fresh[ep]:
                            self._sanction_finding(res, ENDPOINTS[ep]["list"], norm, today)
                continue
            collected[ep].extend(rows)
            prev_pages = pages.get(ep, (0, 0))[0]
            pages[ep] = (prev_pages + 1, len(rows))
            endpoint_states[ep] = f"{len(collected[ep])} row(s) in {pages[ep][0]} page(s)"
        if api_sanctions:
            res.attr("cgu_api_sanctions", [self._sanction_view(s, today) for s in api_sanctions])
        if "contratos" in pages:
            summary = summarize_items(collected["contratos"], "contratos", pages=pages["contratos"][0], last_page_rows=pages["contratos"][1])
            res.attr("federal_contracts", summary)
            if summary["partial"]:
                res.stop("request_cap")
        if "convenios" in pages:
            res.attr("federal_agreements", summarize_items(collected["convenios"], "convenios", pages=1, last_page_rows=pages["convenios"][1]))
        if "despesas" in pages:
            pay = summarize_items(collected["despesas"], "despesas", pages=1, last_page_rows=pages["despesas"][1])
            pay["year"] = today.year
            res.attr("federal_payments", pay)
        res.raw = {"summary": flags, "bulk_fresh": fresh, "plan": steps, "endpoints": endpoint_states}
        if failures:
            res.error = "; ".join(f.reason for f in failures)[:600]
            statuses = {f.status for f in failures}
            if Status.RATE_LIMITED in statuses:
                res.stop("rate_limited")
            elif Status.QUOTA in statuses:
                res.stop("quota")
        return res

    def _sanction_finding(self, res: ModuleResult, list_key: str, row: dict[str, Any], today: Any) -> None:
        """cond 5: stale/absent bulk list -> the API row is the finding (same titles and dedup key as P240)."""
        spec = _BULK_LISTS.get(list_key)
        label = getattr(spec, "label", list_key.upper())
        link = getattr(spec, "link", "") or ""
        status = _bulk_status(row, today) if _bulk_status else "in_force"
        in_force = status == "in_force"
        what = row.get("category") or label
        dates = f"start {row.get('start') or 'not stated'}, end {row.get('end') or 'none (indefinite)'}"
        state = "sanction in force" if in_force else f"formerly sanctioned ({row.get('end') or 'end date not stated'})"
        key = _bulk_dedup_key(list_key, row.get("cnpj"), row.get("sanction_id")) if _bulk_dedup_key else f"{list_key}|{row.get('cnpj')}|{row.get('sanction_id')}"
        desc = (f"{label} lists this CNPJ: {what}" + (f" by {row['organ']}" if row.get("organ") else "") + f" ({dates}); {state}. "
                "Source: Portal da Transparencia API (the CGU bulk file was not fresh).")
        if list_key == "acordos_leniencia":
            desc += f" Agreement situation: {row.get('situation') or 'not stated'} (a leniency agreement, not a penalty by itself)."
        res.finding(
            f"Listed in {label} (in force)" if in_force else f"Formerly listed in {label}",
            "high" if in_force else "info",
            desc,
            confidence="confirmed",
            criterion=f"exact 14-character CNPJ match in the CGU {label} via the Portal da Transparencia API (filter checked on "
                      f"every row); {state}",
            data={"list": list_key, "match_type": "exact_cnpj", "matched_cnpj": row.get("cnpj"), "sanction_id": row.get("sanction_id"),
                  "sanction_type": what, "organ": row.get("organ"), "start": row.get("start"), "end": row.get("end"), "status": status,
                  "file_date": row.get("file_date"), "dedup_key": key, "fine": row.get("fine"), "situation": row.get("situation"),
                  "via": "api"},
            tags=["sanctions"],
            references=[link] if link.startswith("https://") else [],
            source=SOURCE,
            observed_first=row.get("start"),
            key=f"{list_key}:{row.get('sanction_id') or ''}",
        )
        if in_force:
            res.attr("sanctioned", True)

    @staticmethod
    def _sanction_view(row: dict[str, Any], today: Any) -> dict[str, Any]:
        status = _bulk_status(row, today) if _bulk_status else None
        key = _bulk_dedup_key(row.get("list"), row.get("cnpj"), row.get("sanction_id")) if _bulk_dedup_key else None
        out = {"list": row.get("list"), "sanction_id": row.get("sanction_id"), "category": row.get("category"), "start": row.get("start"),
               "end": row.get("end"), "organ": row.get("organ"), "status": status, "dedup_key": key, "legal_basis": row.get("legal_basis")}
        return {k: v for k, v in out.items() if v not in (None, "")}

    # ------------------------------------------------------------------ PEP by name (cond 4)
    def _pep(self, res: ModuleResult, ctx: Any, key: str, name: str, entity: Entity) -> ModuleResult:
        options = getattr(ctx, "options", None)
        unconfirmed = set(getattr(options, "unconfirmed_seeds", ()) or ())
        purpose = _s(getattr(ctx, "purpose", "") or "")
        if not getattr(ctx, "is_seed", False) or int(getattr(ctx, "depth", 0) or 0) > 0 or entity.key in unconfirmed:
            return res.mark(Status.SKIPPED, "PEP is searched by name only for a person the analyst typed as a due-diligence subject",
                            reason_code="privacy")
        if not purpose:
            return res.mark(Status.SKIPPED, "PEP search by name needs a recorded purpose (--purpose, due diligence)", reason_code="privacy")
        try:
            url = build_name_request("peps", name)
        except ValueError:
            return res.mark(Status.SKIPPED, "a full name (no digits) is required for a PEP search", reason_code="not_applicable")
        try:
            rows = self._get(ctx, key, url)
        except _Failure as f:
            return res.mark(f.status, f.reason, reason_code=f.code)
        if not isinstance(rows, list):
            return res.mark(Status.ERROR, "Portal da Transparencia /peps: expected a JSON list: could not verify", reason_code="error")
        qn = " ".join(fold(name).split())
        hits = [r for r in rows if isinstance(r, dict) and " ".join(fold(r.get("nome")).split()) == qn]
        if not hits:
            return res.mark(Status.EMPTY, f"no PEP record with exactly this name in the Portal da Transparencia ({len(rows)} row(s) read)")
        for i, r in enumerate(hits[:5]):
            role = _s(r.get("descricao_funcao")) or "role not stated"
            organ = _s(r.get("nome_orgao")) or "organ not stated"
            res.finding(
                "PEP (possible match)", "info",
                f"The Portal da Transparencia PEP list has '{_s(r.get('nome'))}' ({role}, {organ}): a name-only possible match, context "
                f"only - never a risk by itself. CPF as published (masked): {mask_cpf(r.get('cpf')) or 'not stated'}.",
                confidence="possible",
                criterion="exact normalised name match in the Portal da Transparencia PEP list; no identifier compared",
                data={"match_type": "name_only", "role": role, "organ": organ, "start": iso_date(r.get("dt_inicio_exercicio")),
                      "end": iso_date(r.get("dt_fim_exercicio")), "grace_end": iso_date(r.get("dt_fim_carencia")),
                      "cpf_as_published": mask_cpf(r.get("cpf")), "purpose_recorded": True},
                tags=["pep", "name_only_match", "context_only", "privacy"],
                source=SOURCE,
                key=f"pep:{i}",
            )
        return res


def _usable(resp: Any) -> bool:
    obj, problem = parse_json(getattr(resp, "content", b""), str(getattr(resp, "headers", {}).get("content-type", "")))
    return problem is None and error_marker(obj) is None


__all__ = [
    "ENDPOINTS",
    "NO_KEY_HINT",
    "PortalTransparenciaApi",
    "api_row_to_bulk_record",
    "build_name_request",
    "build_request",
    "decode_body",
    "filter_guard",
    "key_error",
    "mask_cpf",
    "normalise_sanction",
    "parse_json",
    "personal_param_violations",
    "plan",
    "summarize_items",
]
