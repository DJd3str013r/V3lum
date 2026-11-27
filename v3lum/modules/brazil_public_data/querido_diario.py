"""querido_diario (P243): mentions of a CNPJ or company name in Brazilian municipal official gazettes.

Batch p2-G10-3. Source: the Querido Diario gazette search API of Open Knowledge Brasil (research C0554,
community tier, open data with attribution 'Fonte: Querido Diario (Open Knowledge Brasil)').

* **FC1 host and limits** - only ``api.queridodiario.org.br``. The old ``api.queridodiario.ok.org.br``
  fails the TLS handshake and is never declared, never a fallback (the Ceos port used it). At most one
  request per second (``min_interval`` 1 s, provider profile 1 s), 24 h cache (``cache_ttl``), a 20 s
  timeout per request (the CNPJ query answers in 2-7 s; a company-name phrase query passed 20 s live).
* **FC2 queries** - CNPJ seeds: the formatted CNPJ in quotes, then the exact razao social and nome
  fantasia of the CNPJ record (read from Querido Diario's own ``/company/info``, same host and provider;
  never for MEI/EI records, whose razao social is a person's name; generic trade names such as 'DIRECAO
  GERAL' are skipped). Company names: only analyst-typed seeds (or an explicit ``-M querido_diario``),
  never a legal name pivoted from a CNPJ record (that CNPJ is searched instead). Keywords: only on
  explicit request. Person names: only an analyst-typed seed of a case with a recorded ``--purpose``
  (due diligence), never QSA or other pivoted names (SKIPPED ``privacy``). Default window 2 years
  (setting ``querido_diario_window_years``).
* **FC3 bounded output** - ``size=10`` and one excerpt per gazette: at most 10 excerpts per query. The
  analyst sees the count per query plus the 5 hits ranked penalty terms first (penalidade, inidoneidade,
  rescisao, multa, sancao, suspensao; 'multa de transito' does not count), then most recent. Every
  mention is an INFO finding tagged ``context_only``: it never raises the score.
* **FC4 minimisation** - each hit keeps municipality, state, IBGE id, date, edition, the gazette URL (a
  link, never fetched) and an excerpt of at most 300 characters with CPFs masked. No gazette text is
  stored and no PERSON entity is extracted from excerpts.
* **FC5 derived pivots** - CNJ process numbers (shared P241 parser, mod-97 checked) pivot with
  ``expand=False`` (KEYWORD until the core ``cnj_process`` type exists; DataJud runs on them only on
  request, under its licence gate); other valid CNPJs of the excerpts pivot with ``expand=False`` as
  POSSIBLE hypotheses (relation ``co_mentioned_in_gazette``), never as confirmed links.
* **FC6 wording and rule 5** - an empty answer reads 'not found in covered gazettes (Querido Diario
  indexes only part of Brazil's municipalities)', never 'no mentions'. 401/403/429, challenges,
  timeouts, 5xx, 4xx and error-in-200 bodies (a FastAPI ``detail`` body, a missing or non-integer
  ``total_gazettes``, ``gazettes`` not a list, a positive total with no gazettes, malformed JSON) are
  'could not verify' (BLOCKED / RATE_LIMITED / QUOTA / ERROR) and are never cached (``cache_if`` veto).
  When a later name query fails after the CNPJ query answered, the hits are kept and the failed query is
  listed as 'could not verify' in ``gazette_mentions``; with no hit at all the failure decides the status.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlencode

from v3lum.config import SettingSpec
from v3lum.core import validators
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import gazette_excerpts as gx
from v3lum.modules.brazil_public_data.cnpj_lookup import parse_qd

SOURCE = "querido_diario.gazettes"
SOURCE_COMPANY = "querido_diario.company"
API = "https://api.queridodiario.org.br"
GAZETTES_URL = API + "/gazettes"
COMPANY_URL = API + "/company/info/{cnpj}"
QD_EMPTY_TEXT = "not found in covered gazettes (Querido Diario indexes only part of Brazil's municipalities)"
QD_ATTRIBUTION = "Fonte: Querido Diario (Open Knowledge Brasil), dados abertos"
QD_SITE = "https://queridodiario.ok.org.br/"
COVERAGE_NOTE = "Querido Diario indexes the official gazettes of only part of Brazil's municipalities"
REQUEST_TIMEOUT = 20.0
PAGE_SIZE = 10  # FC3: at most 10 excerpts per query (one excerpt per gazette)
MAX_EXCERPTS_PER_QUERY = 10
SHOWN = 5
MAX_CNPJ_PIVOTS = 10
MAX_CNJ_PIVOTS = 10
DEFAULT_WINDOW_YEARS = 2
#: nome fantasia values that are department labels, not names: searching them returns noise
GENERIC_TRADE_NAMES = frozenset({
    "direcao geral", "matriz", "sede", "sede social", "filial", "escritorio", "escritorio central", "loja", "unidade",
    "agencia", "administracao", "administracao central", "central", "deposito", "fabrica", "posto", "nao informado",
    "sem nome", "nao possui", "inexistente",
})
#: natureza juridica 213-5 Empresario (Individual): the razao social is a natural person's name
EI_NATUREZA = frozenset({"2135"})
QUERY_KINDS = ("cnpj", "razao_social", "nome_fantasia", "company_name", "keyword", "person_name")


def window(today: Any, years: int = DEFAULT_WINDOW_YEARS) -> tuple[str, str]:
    """FC2 date window -> (published_since, published_until) ISO dates."""
    return gx.years_back(today, max(1, int(years))).isoformat(), today.isoformat()


def gazettes_params(querystring: str, since: str, until: str) -> dict[str, str]:
    """FC1/FC3/FC4 query parameters: ``size=10`` with one excerpt of about 300 characters per gazette
    (the research used 3 excerpts of 500: up to 30 per query); sorted by descending date."""
    return {
        "querystring": querystring,
        "published_since": since,
        "published_until": until,
        "excerpt_size": str(gx.EXCERPT_MAX),
        "number_of_excerpts": "1",
        "size": str(PAGE_SIZE),
        "offset": "0",
        "sort_by": "descending_date",
    }


def gazettes_url(querystring: str, since: str, until: str) -> str:
    """The only gazette endpoint (FC1: host api.queridodiario.org.br)."""
    return GAZETTES_URL + "?" + urlencode(gazettes_params(querystring, since, until))


def quote_phrase(value: Any) -> str | None:
    """FC2: an exact phrase in quotes; inner quotes and backslashes are removed so the phrase cannot be
    broken, whitespace is collapsed."""
    t = gx.collapse_ws(gx.text(value).replace('"', " ").replace("\\", " "))
    return f'"{t}"' if t else None


def error_in_200(body: Any) -> str | None:
    """FC6 error-in-200 marker of a /gazettes answer (None when the body is usable)."""
    if not isinstance(body, dict):
        return "body is not a JSON object"
    if "detail" in body and ("total_gazettes" not in body or "gazettes" not in body):
        return f"API error detail {gx.text(body.get('detail'))[:120]!r}"
    total = body.get("total_gazettes")
    gazettes = body.get("gazettes")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        return "total_gazettes missing or not an integer"
    if not isinstance(gazettes, list):
        return "gazettes missing or not a list"
    if total > 0 and not gazettes:
        return f"inconsistent body (total_gazettes={total} but no gazettes)"
    return None


def _cacheable(resp: Any) -> bool:
    """``cache_if`` veto (FC6): only a well-formed /gazettes answer may enter the 24 h cache."""
    try:
        return error_in_200(json.loads(resp.content)) is None
    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
        return False


def parse_gazettes(body: Any, anchors: Iterable[str] = (), queried_cnpj: str | None = None,
                   max_excerpts: int = MAX_EXCERPTS_PER_QUERY) -> dict[str, Any]:
    """FC3-FC5: a /gazettes answer -> {ok, error, total, returned, hits}. Each hit: territory_id,
    municipality, state, date, edition, extra_edition, url, excerpts (<= 300 chars, CPFs masked),
    penalty_terms, cnj_numbers, other_cnpjs (found in the full excerpts before they are cut). At most
    ``max_excerpts`` excerpts per answer, every gazette's first excerpt before any second one."""
    err = error_in_200(body)
    if err:
        return {"ok": False, "error": err, "total": None, "returned": 0, "hits": []}
    exclude = [queried_cnpj] if queried_cnpj else []
    hits: list[dict[str, Any]] = []
    for g in body["gazettes"]:
        if not isinstance(g, dict):
            continue
        raw = [x for x in (g.get("excerpts") if isinstance(g.get("excerpts"), list) else []) if isinstance(x, str)]
        joined = "\n".join(raw)
        extra = g.get("is_extra_edition")
        hits.append({
            "territory_id": gx.text(g.get("territory_id")) or None,
            "municipality": gx.collapse_ws(g.get("territory_name")) or None,
            "state": gx.text(g.get("state_code")).strip() or None,
            "date": gx.iso_date(g.get("date")),
            "edition": gx.text(g.get("edition")).strip() or None,
            "extra_edition": extra if isinstance(extra, bool) else None,
            "url": gx.http_url(g.get("url")),
            "excerpts": [gx.clean_excerpt(x, anchors) for x in raw],
            "penalty_terms": sorted({t for x in raw for t in gx.penalty_terms(x)}),
            "cnj_numbers": [c["number"] for c in gx.extract_cnj(joined, limit=MAX_CNJ_PIVOTS)],
            "other_cnpjs": gx.extract_cnpjs(joined, exclude=exclude),
        })
    budget = max(0, int(max_excerpts))
    rounds = max((len(h["excerpts"]) for h in hits), default=0)
    kept: list[list[str]] = [[] for _ in hits]
    for k in range(rounds):
        for i, h in enumerate(hits):
            if k < len(h["excerpts"]) and budget > 0:
                kept[i].append(h["excerpts"][k])
                budget -= 1
    for h, ex in zip(hits, kept):
        h["excerpts"] = ex
    return {"ok": True, "error": None, "total": body["total_gazettes"], "returned": len(hits), "hits": hits}


def rank_hits(hits: Iterable[Mapping[str, Any]], top: int = SHOWN) -> list[dict[str, Any]]:
    """FC3: penalty-term hits first, then the most recent, then municipality."""
    def key(h: Mapping[str, Any]) -> tuple[Any, ...]:
        date = str(h.get("date") or "0000-00-00")
        return (0 if h.get("penalty_terms") else 1, tuple(-int(x) for x in date.split("-")), str(h.get("municipality") or ""))

    return [dict(h) for h in sorted(hits, key=key)[:top]]


def parse_cities(body: Any) -> list[dict[str, Any]]:
    """/cities answer -> [{territory_id, name, state, level, availability_date, covered}] (FC6 coverage
    caveat: a municipality without an availability date is not indexed)."""
    cities = body.get("cities") if isinstance(body, dict) else None
    out = []
    for c in cities if isinstance(cities, list) else []:
        if not isinstance(c, dict):
            continue
        avail = gx.iso_date(c.get("availability_date"))
        out.append({"territory_id": gx.text(c.get("territory_id")) or None, "name": gx.collapse_ws(c.get("territory_name")) or None,
                    "state": gx.text(c.get("state_code")) or None, "level": gx.text(c.get("level")) or None,
                    "availability_date": avail, "covered": bool(avail)})
    return out


def parse_themes(body: Any) -> list[str]:
    """/gazettes/by_theme themes list -> list of theme names."""
    themes = body.get("themes") if isinstance(body, dict) else None
    return [t for t in (themes if isinstance(themes, list) else []) if isinstance(t, str)]


def usable_trade_name(trade: Any, legal: Any) -> str | None:
    """A nome fantasia worth searching (FC2): not empty, not a department label, not the legal name."""
    t = gx.collapse_ws(trade)
    folded = gx.fold(t)
    if not folded or folded in GENERIC_TRADE_NAMES or len(folded.replace(" ", "")) < 4:
        return None
    if folded == gx.fold(legal):
        return None
    return t


def _natural_person_record(record: Mapping[str, Any]) -> bool:
    nat = record.get("natureza_juridica") if isinstance(record.get("natureza_juridica"), dict) else {}
    mei = record.get("mei") if isinstance(record.get("mei"), dict) else {}
    return str(nat.get("code") or "") in EI_NATUREZA or mei.get("optante") is True


def _failure_state(exc: BaseException) -> str:
    if isinstance(exc, RateLimited):
        return "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return "quota"
    if isinstance(exc, (Blocked, AuthRequired)):
        return "blocked"
    if isinstance(exc, DeadlineExceeded) or "timed out" in str(exc).lower() or "timeout" in str(exc).lower():
        return "timeout"
    return "error"


@register
class QueridoDiario(Module):
    name = "querido_diario"
    title = "Querido Diario municipal gazettes"
    description = (
        "Mentions of a CNPJ or company name in Brazilian municipal official gazettes indexed by Querido Diario "
        "(Open Knowledge Brasil): count per query, the 5 most relevant excerpts (penalty terms first), CNJ "
        "process numbers and co-mentioned CNPJs as non-expanding hypotheses."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.PERSON, T.KEYWORD}
    produces = {T.CNPJ, T.KEYWORD}
    tags = {"brazil", "free"}
    reference = "https://api.queridodiario.org.br/docs"
    notice = (
        "Open Knowledge Brasil open data (attribution: 'Fonte: Querido Diario (Open Knowledge Brasil)'). Covers only part of "
        "Brazil's municipalities: an empty answer is 'not found in covered gazettes', never 'no mentions'. Person names are "
        "searched only for an analyst-typed seed of a case with a recorded purpose (LGPD), never for QSA names."
    )
    # ---- declarations ------------------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Querido Diario receives the CNPJ / name
    hosts = ("api.queridodiario.org.br",)
    provider = "querido_diario"
    sources = (SOURCE, SOURCE_COMPANY)
    access_model = "free_noauth_limited"
    max_requests = 4  # formatted CNPJ, /company/info, razao social, nome fantasia
    expected_latency = 8.0
    timeout = 75.0
    min_interval = 1.0
    cache_ttl = 86400
    daily_quota = 300
    max_pivots = MAX_CNPJ_PIVOTS + MAX_CNJ_PIVOTS
    default_enabled = True
    error_markers = (
        {"id": "querido_diario_detail_in_200", "statuses": [200], "json_path": None, "equals": None,
         "regex": r"\A\s*\{\s*\"detail\"\s*:", "final_url_regex": None, "maps_to": "error", "reason_code": "error",
         "reason": "Querido Diario: API error 'detail' body in an HTTP 200 answer (could not verify)"},
    )
    settings = {
        "querido_diario_window_years": SettingSpec(DEFAULT_WINDOW_YEARS, "Querido Diario: years of gazettes searched back from today (P243 FC2, default 2)."),
    }

    # ------------------------------------------------------------------ planning (FC2)
    def _explicit(self, ctx: Any) -> bool:
        include = getattr(getattr(ctx, "options", None), "include", None) or ()
        return self.name in set(include)

    @staticmethod
    def _from_cnpj_record(ctx: Any) -> bool:
        prov = getattr(ctx, "provenance", ()) or ()
        if not prov:
            return False
        parent = prov[-1]
        parent_key = str(parent[0]) if isinstance(parent, (tuple, list)) and parent else ""
        relation = str(parent[1]) if isinstance(parent, (tuple, list)) and len(parent) > 1 else ""
        return parent_key.startswith("cnpj:") or relation in ("legal_name", "partner_of")

    def _skip(self, res: ModuleResult, code: str, why: str) -> ModuleResult:
        return res.mark(Status.SKIPPED, why, reason_code=code)

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        explicit = self._explicit(ctx)
        seed = bool(getattr(ctx, "is_seed", True))
        cnpj: str | None = None
        queries: list[tuple[str, str]] = []
        if entity.type is T.CNPJ:
            cnpj = gx.normalize_cnpj(entity.value)
            if not cnpj or not validators.cnpj_valid(cnpj):
                return self._skip(res, "not_applicable", "not a valid CNPJ")
            if not seed and not explicit:
                return self._skip(res, "not_applicable", "Querido Diario runs on CNPJ seeds by default (P243 FC2): select it with -M querido_diario for pivoted CNPJs")
            queries.append(("cnpj", f'"{gx.format_cnpj(cnpj)}"'))
        elif entity.type is T.ORG:
            if self._from_cnpj_record(ctx):
                return self._skip(res, "not_applicable", "a name taken from a CNPJ record is searched through that CNPJ's run (P243 FC2)")
            if not seed and not explicit:
                return self._skip(res, "not_applicable", "company names are searched only when typed by the analyst (P243 FC2)")
            q = quote_phrase(entity.value)
            if not q:
                return self._skip(res, "not_applicable", "empty company name")
            queries.append(("company_name", q))
        elif entity.type is T.KEYWORD:
            if not explicit:
                return self._skip(res, "not_default", "keyword search in gazettes runs only on explicit request (-M querido_diario, P243 FC2)")
            q = gx.collapse_ws(entity.value)
            if not q:
                return self._skip(res, "not_applicable", "empty keyword")
            queries.append(("keyword", q))
        elif entity.type is T.PERSON:
            purpose = gx.collapse_ws(getattr(ctx, "purpose", "") or getattr(getattr(ctx, "options", None), "purpose", "") or "")
            if not seed or not purpose or self._from_cnpj_record(ctx):
                return self._skip(res, "privacy", "person names are searched only for an analyst-typed seed of a due-diligence case with a recorded purpose, never QSA names (P243 FC2, LGPD)")
            q = quote_phrase(entity.value)
            if not q:
                return self._skip(res, "not_applicable", "empty name")
            queries.append(("person_name", q))
        else:  # pragma: no cover - accepts guards this
            return self._skip(res, "not_applicable", "unsupported input type")

        years = ctx.setting("querido_diario_window_years", DEFAULT_WINDOW_YEARS)
        try:
            years = max(1, min(int(years), 20))
        except (TypeError, ValueError):
            years = DEFAULT_WINDOW_YEARS
        since, until = window(ctx.now().date(), years)
        anchors: list[str] = [gx.format_cnpj(cnpj) or "", cnpj or ""] if cnpj else [entity.value]

        runs: list[dict[str, Any]] = []
        hits: dict[str, dict[str, Any]] = {}
        failure: BaseException | None = None
        stop: str | None = None
        names_done = False
        i = 0
        while i < len(queries):
            kind, q = queries[i]
            i += 1
            try:
                parsed = self._search(ctx, q, since, until, anchors, cnpj)
            except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
                if not runs:  # the primary query decides the status (rule 5)
                    raise
                runs.append({"kind": kind, "query": q, "state": "could_not_verify", "reason": _failure_state(exc), "total": None})
                failure = failure or exc
                if isinstance(exc, (RateLimited, QuotaExceeded, Blocked, AuthRequired, DeadlineExceeded)):
                    stop = "rate_limited" if isinstance(exc, RateLimited) else "quota" if isinstance(exc, QuotaExceeded) else None
                    break  # the provider is throttling or blocking: no further query
                continue
            runs.append({"kind": kind, "query": q, "state": "ok" if parsed["total"] else "empty", "total": parsed["total"],
                         "returned": parsed["returned"]})
            for h in parsed["hits"]:
                key = h.get("url") or f"{h.get('territory_id')}|{h.get('date')}|{h.get('edition')}"
                if key in hits:
                    seen = hits[key]
                    seen["queries"] = sorted(set(seen["queries"]) | {kind})
                    continue
                hits[key] = dict(h, queries=[kind])
            if kind == "cnpj" and not names_done and cnpj:
                names_done = True
                queries.extend(self._record_names(ctx, res, cnpj))

        return self._finish(entity, res, runs, list(hits.values()), cnpj, since, until, failure, stop)

    # ------------------------------------------------------------------ HTTP
    def _search(self, ctx: Any, querystring: str, since: str, until: str, anchors: list[str], cnpj: str | None) -> dict[str, Any]:
        resp = ctx.http.get(gazettes_url(querystring, since, until), source=SOURCE, timeout=REQUEST_TIMEOUT, cache_if=_cacheable,
                            headers={"Accept": "application/json"})
        ctx.http.check(resp)
        try:
            body = json.loads(resp.content)
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            ctx.http.evict(resp)
            raise HttpError("Querido Diario: malformed or truncated JSON answer: could not verify", getattr(resp, "status", 0) or 0,
                            getattr(resp, "url", "") or "") from exc
        parsed = parse_gazettes(body, anchors, cnpj)
        if not parsed["ok"]:
            ctx.http.evict(resp)
            raise HttpError(f"Querido Diario: error-in-200 ({parsed['error']}): could not verify", getattr(resp, "status", 0) or 0,
                            getattr(resp, "url", "") or "")
        return parsed

    def _record_names(self, ctx: Any, res: ModuleResult, cnpj: str) -> list[tuple[str, str]]:
        """FC2: razao social and nome fantasia of a CNPJ seed from Querido Diario's /company/info (numeric
        CNPJs only: QD answers 400 for the alphanumeric form). A failure only costs the name queries."""
        if not cnpj.isdigit():
            res.source_status(SOURCE_COMPANY, Status.SKIPPED, reason_code="not_applicable",
                              reason="alphanumeric CNPJ: Querido Diario /company/info supports numeric CNPJs only")
            return []
        try:
            body = ctx.http.get_json(COMPANY_URL.format(cnpj=cnpj), source=SOURCE_COMPANY, absent={404}, timeout=REQUEST_TIMEOUT)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
            state = _failure_state(exc)
            status = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED}.get(state, Status.ERROR)
            code = {"timeout": "timeout", "blocked": getattr(exc, "reason_code", "challenge") or "challenge"}.get(state, "")
            if status is Status.BLOCKED and code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                code = "challenge"
            res.source_status(SOURCE_COMPANY, status, reason_code=code, reason=f"could not read the CNPJ record for the name queries ({state})")
            return []
        if body is None:
            res.source_status(SOURCE_COMPANY, Status.EMPTY, reason="CNPJ not in Querido Diario's company records: names not searched")
            return []
        record = parse_qd(body)
        if not record:
            res.source_status(SOURCE_COMPANY, Status.ERROR, reason="unexpected /company/info answer: names not searched")
            return []
        res.source_status(SOURCE_COMPANY, Status.OK)
        if _natural_person_record(record):
            # MEI/EI: the razao social is a natural person's name - never searched by default (FC2, LGPD)
            return []
        legal = gx.collapse_ws(record.get("razao_social"))
        out: list[tuple[str, str]] = []
        q = quote_phrase(legal)
        if q:
            out.append(("razao_social", q))
        trade = usable_trade_name(record.get("nome_fantasia"), legal)
        tq = quote_phrase(trade) if trade else None
        if tq and tq != q:
            out.append(("nome_fantasia", tq))
        return out

    # ------------------------------------------------------------------ output
    def _finish(self, entity: Entity, res: ModuleResult, runs: list[dict[str, Any]], hits: list[dict[str, Any]], cnpj: str | None,
                since: str, until: str, failure: BaseException | None, stop: str | None) -> ModuleResult:
        failed = [r for r in runs if r["state"] == "could_not_verify"]
        if not hits:
            if failure is not None:
                raise failure  # rule 5: one query could not be verified and nothing was found elsewhere
            res.attr("gazette_mentions", {"count": 0, "queries": runs, "window": {"since": since, "until": until},
                                          "line": QD_EMPTY_TEXT, "coverage": COVERAGE_NOTE, "attribution": QD_ATTRIBUTION})
            return res.mark(Status.EMPTY, QD_EMPTY_TEXT)
        shown = rank_hits(hits)
        penalty = [h for h in hits if h.get("penalty_terms")]
        counts = {r["kind"]: r["total"] for r in runs if r.get("total") is not None}
        count = max(counts.values()) if counts else len(hits)
        label = gx.format_cnpj(cnpj) if cnpj else entity.value
        line = (f"{count} gazette(s) in Querido Diario mention {label} ({since} to {until}); showing {len(shown)} "
                f"(penalty terms first, then most recent)")
        if penalty:
            line += f"; {len(penalty)} of the {len(hits)} fetched excerpts carry penalty terms"
        if failed:
            line += "; could not verify: " + ", ".join(f"{r['kind']} query ({r['reason']})" for r in failed)
        top = [{k: h.get(k) for k in ("municipality", "state", "territory_id", "date", "edition", "extra_edition", "url", "excerpts",
                                      "penalty_terms", "queries")} for h in shown]
        res.attr("gazette_mentions", {"count": count, "counts": counts, "fetched": len(hits), "queries": runs,
                                      "window": {"since": since, "until": until}, "top": top, "line": line,
                                      "coverage": COVERAGE_NOTE, "attribution": QD_ATTRIBUTION})
        exact = any(k == "cnpj" for h in hits for k in h.get("queries", ()))
        res.finding(
            "Mentioned in municipal gazettes (Querido Diario)",
            "info",
            f"{line}. {QD_ATTRIBUTION}.",
            confidence="confirmed" if exact else "possible",
            criterion=("formatted CNPJ found verbatim in gazette excerpts" if exact else
                       "exact name phrase found in gazette excerpts (homonyms possible: confirm the CNPJ in the act)"),
            data={"count": count, "counts": counts, "top": top, "window": {"since": since, "until": until}},
            tags=["context_only"],
            references=[QD_SITE],
            source=SOURCE,
            observed_last=max((h["date"] for h in hits if h.get("date")), default=None),
        )
        if penalty:
            pen_top = rank_hits(penalty)
            terms = sorted({t for h in penalty for t in h["penalty_terms"]})
            res.finding(
                "Municipal gazette excerpts mention penalty terms",
                "info",
                f"{len(penalty)} excerpt(s) mentioning {label} carry penalty terms ({', '.join(terms)}): read the act - a keyword "
                f"match, not a confirmed sanction. {QD_ATTRIBUTION}.",
                confidence="possible",
                criterion="penalty term (penalidade, inidoneidade, rescisao, multa, sancao, suspensao) in an excerpt naming the subject",
                data={"terms": terms, "top": [{k: h.get(k) for k in ("municipality", "state", "date", "url", "excerpts", "penalty_terms")}
                                              for h in pen_top]},
                tags=["penalty_term"],
                references=[QD_SITE],
                source=SOURCE,
            )
        for h in shown:
            if h.get("url"):
                res.link(f"Gazette {h.get('municipality') or '?'}/{h.get('state') or '?'} {h.get('date') or ''}".strip(), h["url"])
        self._pivots(res, hits, cnpj)
        if stop:
            res.stop(stop)
        return res

    @staticmethod
    def _pivots(res: ModuleResult, hits: list[dict[str, Any]], cnpj: str | None) -> None:
        """FC5: CNJ numbers and co-mentioned CNPJs, expand=False, capped."""
        cnj_seen: list[str] = []
        cnpj_seen: list[str] = []
        for h in rank_hits(hits, top=len(hits)):
            for number in h.get("cnj_numbers") or ():
                if number not in cnj_seen and len(cnj_seen) < MAX_CNJ_PIVOTS:
                    cnj_seen.append(number)
                    res.pivot(T.KEYWORD, **gx.cnj_pivot_args(number))
            for other in h.get("other_cnpjs") or ():
                if other == cnpj or other in cnpj_seen or len(cnpj_seen) >= MAX_CNPJ_PIVOTS:
                    continue
                cnpj_seen.append(other)
                res.pivot(T.CNPJ, other, "co_mentioned_in_gazette", confidence="possible", expand=False,
                          note=f"hypothesis: CNPJ co-mentioned in a gazette excerpt ({h.get('municipality') or '?'} {h.get('date') or ''}), not a confirmed link")
