"""P241 ``datajud`` - DataJud (CNJ) court-process metadata by validated CNJ process number.

Council P241 final conditions, as implemented here:

1. terms 'noncommercial' (DataJud Termo de Uso v1.2, 27/11/2023: 3.3 'exclusivamente para fins legais, nao
   comerciais e autorizados', 3.8 no commercial exploitation), recorded on ``cnj.datajud``.
2. Off under the corporate licence profile until a licence_allow entry clears ``cnj.datajud`` (the policy
   gate skips it with reason_code 'licence' and coverage shows it).
3. The offline CNJ unified-number parser and router live in ``cnj_process.py`` (mod 97, the 91 DataJud
   aliases, e.g. 0700055-10.2018.8.01.0022 -> api_publica_tjac); a core-validators copy is a core request.
4. Inputs: a KEYWORD that is one CNJ number, or a text blob (at most 5 numbers queried, the rest counted).
   The core ``cnj_process`` type (P333) does not exist yet (backlog). The module runs only on analyst-typed
   seeds (``run_on='seeds'``) and numbers found by other modules are pivots with expand=False, so the slow
   API never runs automatically on them.
5. API key: the configured key ``datajud`` (``V3LUM_DATAJUD_KEY``), else the 'APIKey atual' CNJ publishes on
   datajud-wiki.cnj.jus.br/api-publica/acesso (a public key, read with a strict pattern, never cached or
   logged, registered with the redactor). On 401 the official page is read again, once per run.
6. Queries only by a validated number routed by J.TR (no party, name, CNPJ or CPF search, terms 3.11/4.2).
   Output is metadata only: court, class, subjects, filing date, last movements. Sealed or absent processes
   read 'not found in public DataJud', never 'no case'.
7. expected_latency 28 s, default_enabled False (A3), per-run deadline 60 s with ``ctx.cancelled()`` checks
   between numbers and attempts. HTTP 429 / es_rejected_execution_exception (also inside HTTP 200 as failed
   shards) -> one retry after a backoff when the deadline allows it, else RATE_LIMITED 'could not verify:
   DataJud overloaded'. Rate <= 120 req/min (provider quota 2 req/s, min_interval 1 s).
8. Every result carries ``export_restriction`` and its findings the tag ``no_export``: DataJud data is never
   shared with third parties or exported to STIX/MISP (terms 4.6). Never used to screen employees or
   candidates (module notice).
9. Offline tests over trimmed real captures (tests/modules/test_datajud.py).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import time
from html.parser import HTMLParser
from typing import Any

from v3lum.core import redact
from v3lum.core.clock import SystemClock
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import DeadlineExceeded, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data.cnj_process import cnj_format, extract_cnj_numbers, looks_like_cnj

API = "https://api-publica.datajud.cnj.jus.br"
KEY_PAGE = "https://datajud-wiki.cnj.jus.br/api-publica/acesso/"
SOURCE = "cnj.datajud"
KEY_SOURCE = "cnj.datajud_key_page"  # registry evidence of the key page terms (requests are charged to SOURCE)
KEY_NAME = "datajud"
NOT_FOUND_TEXT = "not found in public DataJud"
OVERLOADED_TEXT = "could not verify: DataJud overloaded"
#: P241 cond 7: per-run deadline and the overload retry
DEADLINE_S = 60.0
BACKOFF_S = 5.0
MIN_USEFUL_S = 10.0
MAX_MOVEMENTS = 5
SEARCH_SIZE = 10  # one number may exist in several graus (G1, G2, JE...) of the same index
EXPORT_RESTRICTION = {
    "source": SOURCE,
    "redistributable": False,
    "external_exports": "none: DataJud-derived data stays in the case (never shared with third parties, never in STIX/MISP exports)",
    "reason": "DataJud Termo de Uso v1.2 4.6 (P241 cond 8)",
}

_KEY_LOCK = threading.Lock()
_PUBLISHED_KEY: dict[str, str] = {}  # in-memory only: the key last read from the official page


# --------------------------------------------------------------------------------------
# key page (P241 cond 5)
# --------------------------------------------------------------------------------------


class _Text(HTMLParser):
    BLOCK = frozenset({"p", "br", "div", "tr", "td", "li", "h1", "h2", "h3", "h4", "h5", "table", "ul", "ol", "pre", "code"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(fragment: Any) -> str:
    """HTML -> plain text (block tags become line breaks, script/style dropped, entities decoded)."""
    p = _Text()
    p.feed(fragment if isinstance(fragment, str) else "")
    p.close()
    lines = (" ".join(line.split()) for line in "".join(p.parts).split("\n"))
    return "\n".join(line for line in lines if line)


def _is_es_api_key(key: str) -> bool:
    try:
        decoded = base64.b64decode(key, validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    if decoded.count(":") != 1:
        return False
    ident, secret = decoded.split(":")
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{8,64}", ident) and re.fullmatch(r"[A-Za-z0-9_-]{8,128}", secret))


def extract_datajud_key(page: Any) -> str | None:
    """The 'APIKey atual' CNJ publishes on its DataJud wiki access page, or None.

    Strict: the token must follow 'APIKey atual' as 'Authorization: APIKey <token>' and decode to an
    Elasticsearch API key (base64 of '<id>:<secret>'); the template text '[Chave Publica]' never matches.
    The caller never logs the value and registers it with the redactor (AR01).
    """
    if isinstance(page, (bytes, bytearray)):
        page = page.decode("utf-8", "replace")
    text = html_to_text(page)
    i = text.find("APIKey atual")
    if i < 0:
        return None
    m = re.search(r"Authorization:\s*APIKey\s+([A-Za-z0-9+/]{20,200}={0,2})(?![A-Za-z0-9+/=])", text[i : i + 400])
    if not m or not _is_es_api_key(m.group(1)):
        return None
    return m.group(1)


def forget_published_key() -> None:
    """Drop the in-memory copy of the published key (tests, rotation)."""
    with _KEY_LOCK:
        _PUBLISHED_KEY.clear()


# --------------------------------------------------------------------------------------
# answer parsing (P241 cond 6-8)
# --------------------------------------------------------------------------------------


def _digits(value: Any) -> str:
    return re.sub(r"\D", "", value if isinstance(value, str) else str(value or ""))


def _datajud_date(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if re.fullmatch(r"\d{14}", v):
        return f"{v[:4]}-{v[4:6]}-{v[6:8]}T{v[8:10]}:{v[10:12]}:{v[12:14]}"
    if re.fullmatch(r"\d{8}", v):
        return f"{v[:4]}-{v[4:6]}-{v[6:8]}"
    m = re.match(r"(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}:\d{2}))?", v)
    if m:
        return m.group(1) + (f"T{m.group(2)}" if m.group(2) else "")
    return None


def _flatten(value: Any) -> Any:
    if isinstance(value, list):
        for v in value:
            yield from _flatten(v)
    elif value is not None:
        yield value


def _code_name(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict) and (value.get("nome") or value.get("codigo") is not None):
        name = value.get("nome")
        return {"codigo": value.get("codigo"), "nome": str(name)[:200] if name is not None else None}
    return None


def _short(value: Any, limit: int = 200) -> str | None:
    return str(value)[:limit] if value not in (None, "") else None


def _hit(src: dict[str, Any], index: Any) -> dict[str, Any] | None:
    num = _digits(src.get("numeroProcesso"))
    if len(num) != 20:
        return None
    org = src.get("orgaoJulgador") if isinstance(src.get("orgaoJulgador"), dict) else {}
    movs = []
    raw_movs = src.get("movimentos") if isinstance(src.get("movimentos"), list) else []
    for m in raw_movs:
        if not isinstance(m, dict):
            continue
        comps = [str(c.get("nome"))[:120] for c in (m.get("complementosTabelados") or []) if isinstance(c, dict) and c.get("nome")]
        movs.append({"data": _datajud_date(m.get("dataHora")), "codigo": m.get("codigo"), "nome": _short(m.get("nome")), "complementos": comps[:5]})
    movs.sort(key=lambda m: m["data"] or "", reverse=True)  # the API does not sort them (prep H7)
    sigilo = src.get("nivelSigilo")
    return {
        "numero": cnj_format(num), "numero_digits": num, "tribunal": _short(src.get("tribunal"), 20), "grau": _short(src.get("grau"), 20),
        "index": index if isinstance(index, str) else None, "classe": _code_name(src.get("classe")),
        "assuntos": [a for a in (_code_name(x) for x in _flatten(src.get("assuntos"))) if a][:20],
        "orgao_julgador": {"codigo": org.get("codigo"), "nome": _short(org.get("nome")), "municipio_ibge": org.get("codigoMunicipioIBGE")},
        "data_ajuizamento": _datajud_date(src.get("dataAjuizamento")),
        "sistema": _code_name(src.get("sistema")), "formato": _code_name(src.get("formato")),
        "ultima_atualizacao": _datajud_date(src.get("dataHoraUltimaAtualizacao")),
        "movimentos_recentes": movs[:MAX_MOVEMENTS], "movimentos_total": len(movs),
        "sigilo": isinstance(sigilo, int) and not isinstance(sigilo, bool) and sigilo > 0,
    }


def _error_kind(obj: Any) -> str | None:
    err = obj.get("error") if isinstance(obj, dict) else None
    if err is None:
        return None
    blob = json.dumps(err)
    if "es_rejected_execution_exception" in blob:
        return "overloaded"
    if "security_exception" in blob:
        return "auth"
    return "error"


def parse_search(obj: Any, number: str | None = None) -> dict[str, Any]:
    """A DataJud _search answer -> {status, reason, hits, shards, took_ms}.

    status 'found' | 'not_found' (sealed or absent: never 'no case') | 'overloaded' (es_rejected_execution_exception,
    failed shards or timed_out without a hit: could not verify, never not found) | 'auth' | 'error'. Hits are
    filtered to the exact queried number (the cluster's total is not a per-number count) and sealed hits
    (nivelSigilo > 0) are dropped. Only whitelisted fields leave this function.
    """
    out: dict[str, Any] = {"status": "error", "reason": None, "hits": [], "shards": None, "took_ms": None}
    if isinstance(obj, (bytes, bytearray, str)):
        try:
            obj = json.loads(obj)
        except ValueError:
            out["reason"] = "unexpected DataJud answer (not JSON): could not verify"
            return out
    if not isinstance(obj, dict):
        out["reason"] = "unexpected DataJud answer (not a JSON object): could not verify"
        return out
    kind = _error_kind(obj)
    if kind == "overloaded":
        out.update(status="overloaded", reason=OVERLOADED_TEXT)
        return out
    if kind == "auth":
        out.update(status="auth", reason="DataJud refused the API key (security_exception)")
        return out
    if kind:
        out["reason"] = "DataJud answered an error object: could not verify"
        return out
    took = obj.get("took")
    out["took_ms"] = took if isinstance(took, int) and not isinstance(took, bool) else None
    sh = obj.get("_shards") if isinstance(obj.get("_shards"), dict) else {}
    shards = {k: sh[k] for k in ("total", "successful", "skipped", "failed") if isinstance(sh.get(k), int)}
    out["shards"] = shards or None
    failed = bool(shards.get("failed"))
    partial = failed or obj.get("timed_out") is True
    hits_obj = obj.get("hits") if isinstance(obj.get("hits"), dict) else None
    if hits_obj is None or not isinstance(hits_obj.get("hits"), list):
        out["reason"] = "DataJud answer format changed (no hits.hits): could not verify"
        return out
    want = _digits(number) if number else None
    hits = []
    for h in hits_obj["hits"]:
        src = h.get("_source") if isinstance(h, dict) else None
        if not isinstance(src, dict):
            continue
        rec = _hit(src, h.get("_index"))
        if rec is None or (want and rec["numero_digits"] != want) or rec["sigilo"]:
            continue
        hits.append(rec)
    out["hits"] = hits
    if hits:
        out.update(status="found", reason=("partial answer: some shards failed" if partial else None))
    elif partial:
        out.update(status="overloaded", reason=OVERLOADED_TEXT + (" (shards rejected)" if failed else " (search timed out)"))
    else:
        out.update(status="not_found", reason=NOT_FOUND_TEXT)
    return out


def _usable(resp: Any) -> bool:
    """Cache only clean answers: HTTP 200, a JSON object without error, failed shards or timeout."""
    if getattr(resp, "status", 0) != 200:
        return False
    try:
        obj = json.loads(getattr(resp, "content", b"") or b"")
    except ValueError:
        return False
    if not isinstance(obj, dict) or obj.get("error") is not None or obj.get("timed_out") is True:
        return False
    sh = obj.get("_shards") if isinstance(obj.get("_shards"), dict) else {}
    return not (isinstance(sh.get("failed"), int) and sh["failed"] > 0)


def _pause(ctx: Any, seconds: float) -> None:
    """Backoff wait that the kill switch cuts short (a test clock only advances)."""
    if seconds <= 0:
        return
    clock = getattr(getattr(ctx, "runtime", None), "clock", None)
    if clock is not None and not isinstance(clock, SystemClock):
        clock.sleep(seconds)
        return
    event = getattr(ctx, "cancel_event", None)
    if event is not None:
        event.wait(seconds)
    else:  # pragma: no cover - every Context has a cancel event
        time.sleep(seconds)


class _AuthFailed(Exception):
    """The configured and the published key were both refused."""


class _KeyPageFailed(Exception):
    """The official key page could not be read or no longer shows the key in the expected form."""


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class DataJud(Module):
    name = "datajud"
    title = "DataJud court process metadata (CNJ, by CNJ process number)"
    description = (
        "Court, class, subjects, filing date and latest movements of a Brazilian court process from the CNJ DataJud public "
        "API, queried only by a validated CNJ unified number (NNNNNNN-DD.AAAA.J.TR.OOOO) routed to its tribunal index; "
        "metadata only, no parties."
    )
    category = "brazil_public_data"
    accepts = {T.KEYWORD, T.TEXT}
    produces: set[Any] = set()
    run_on = "seeds"
    tags = {"brazil", "slow"}
    reference = "https://datajud-wiki.cnj.jus.br/api-publica/"
    notice = (
        "DataJud terms are noncommercial (Termo de Uso v1.2 3.3/3.8): off under the corporate licence profile until "
        "licence-cleared. Queries only by CNJ process number (never by party, name, CNPJ or CPF); metadata only; never "
        "shared with third parties or exported to STIX/MISP; never used to screen employees or job candidates. Answers "
        "take 25-30 s and the cluster is often overloaded ('could not verify', never 'no case')."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "cnj"
    sources = (SOURCE,)  # one noncommercial source: the licence gate skips the whole module (the key page is never read alone)
    hosts = ("api-publica.datajud.cnj.jus.br", "datajud-wiki.cnj.jus.br")
    access_model = "free_noauth_limited"  # the key is public, published by CNJ for everyone
    optional_keys = (KEY_NAME,)
    max_requests = 14  # 5 numbers x (query + overload retry) + one auth retry + two key-page reads
    expected_latency = 28.0
    timeout = DEADLINE_S
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 0
    default_enabled = False  # A3: p50 > 10 s and noncommercial terms (P241 cond 2, 7)
    settings = {"datajud_backoff_seconds": BACKOFF_S}

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.KEYWORD:
            return looks_like_cnj(entity.value)
        return bool(extract_cnj_numbers(str(entity.value or ""))["numbers"])

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        extracted = extract_cnj_numbers(str(entity.value or ""), limit=1 if entity.type is T.KEYWORD else 5)
        numbers = extracted["numbers"]
        res.attr("cnj_numbers", {
            "numbers": [{"number": p["formatted"], "court": p["court"], "index": p["index"], "reason": p["reason"]} for p in numbers],
            "invalid": extracted["invalid"], "over_limit": extracted["over_limit"],
        })
        if not numbers:
            return res.mark(Status.SKIPPED, "no valid CNJ process number in the input", reason_code="not_applicable")
        if SOURCE not in ctx.allowed_sources:  # P241 cond 2: never queried outside the licence profile
            return res.mark(Status.SKIPPED, "skipped: noncommercial terms (licence profile corporate)", reason_code="licence")
        statuses: dict[str, str] = {}
        for p in numbers:
            if not p["index"]:
                statuses[p["formatted"]] = str(p["reason"])
        queryable = [p for p in numbers if p["index"]]
        if not queryable:
            res.attr("datajud_status", statuses)
            return res.mark(Status.SKIPPED, "; ".join(sorted(set(statuses.values()))), reason_code="not_applicable")
        state = {"key": "", "origin": "", "refreshed": False}
        cases: list[dict[str, Any]] = []
        outcomes: dict[str, str] = {}
        raw: dict[str, Any] = {"queries": []}
        stop = ""
        try:
            for p in queryable:
                if ctx.cancelled():
                    stop = "cancelled"
                    break
                rem = ctx.remaining()
                if rem is not None and rem <= 1.0:
                    stop = "deadline"
                    break
                outcome = self._query(ctx, p, state)
                raw["queries"].append({"number": p["formatted"], "index": p["index"], "status": outcome["status"],
                                       "reason": outcome.get("reason"), "shards": outcome.get("shards"), "took_ms": outcome.get("took_ms"),
                                       "attempts": outcome.get("attempts", 1)})
                outcomes[p["formatted"]] = outcome["status"]
                if outcome["status"] == "found":
                    statuses[p["formatted"]] = f"found in public DataJud ({len(outcome['hits'])} record(s), {p['court']})"
                    cases.extend(outcome["hits"])
                elif outcome["status"] == "not_found":
                    statuses[p["formatted"]] = f"{NOT_FOUND_TEXT} ({p['court']}; sealed or absent, never 'no case')"
                else:
                    statuses[p["formatted"]] = str(outcome.get("reason") or "could not verify")
                if outcome.get("stop"):
                    stop = outcome["stop"]
                    break
        except _AuthFailed as exc:
            res.attr("datajud_status", statuses)
            res.raw = raw
            return res.mark(Status.NEEDS_KEY, str(exc), reason_code="needs_key")
        except _KeyPageFailed as exc:
            res.attr("datajud_status", statuses)
            res.raw = raw
            return res.mark(Status.ERROR, str(exc), reason_code="error")
        for p in queryable:
            if p["formatted"] not in outcomes:
                statuses[p["formatted"]] = "could not verify: " + ("run deadline reached" if stop == "deadline" else "run stopped")
        res.attr("datajud_status", statuses)
        res.raw = raw
        if state["origin"] == "published_after_rejection":
            ctx.log("the configured DataJud key was refused; the key CNJ publishes worked: update it (v3lum keys set datajud)", "warning")
        if cases:
            res.attr("court_cases", [{k: v for k, v in c.items() if k not in ("numero_digits", "sigilo")} for c in cases])
            res.attr("export_restriction", EXPORT_RESTRICTION)
            for c in cases:
                self._finding(res, c)
        return self._final_status(res, cases, outcomes, queryable, stop)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _final_status(res: ModuleResult, cases: list[dict[str, Any]], outcomes: dict[str, str], queryable: list[dict[str, Any]],
                      stop: str) -> ModuleResult:
        missing = [p for p in queryable if outcomes.get(p["formatted"]) not in ("found", "not_found")]
        overloaded = any(outcomes.get(p["formatted"]) == "overloaded" for p in queryable)
        if cases:
            if missing:
                res.stop(stop if stop in ("cancelled", "deadline", "quota") else "rate_limited")
            return res
        if not missing:
            return res.mark(Status.EMPTY, f"{NOT_FOUND_TEXT} (sealed or absent: never 'no case')")
        if stop == "quota":
            return res.mark(Status.QUOTA, "could not verify: DataJud request budget exhausted", reason_code="quota")
        if stop == "deadline":
            return res.mark(Status.ERROR, "could not verify: DataJud did not answer within the 60 s run deadline", reason_code="timeout")
        if stop == "cancelled":
            return res.mark(Status.ERROR, "could not verify: run cancelled", reason_code="error")
        if overloaded:
            return res.mark(Status.RATE_LIMITED, OVERLOADED_TEXT, reason_code="rate_limited")
        reasons = sorted({str(r) for r in (res.attributes.get("datajud_status") or {}).values()})
        return res.mark(Status.ERROR, "; ".join(reasons)[:300] or "could not verify", reason_code="error")

    @staticmethod
    def _finding(res: ModuleResult, case: dict[str, Any]) -> None:
        classe = (case.get("classe") or {}).get("nome") or "class not given"
        court = case.get("tribunal") or "?"
        grau = case.get("grau") or "?"
        last = (case.get("movimentos_recentes") or [{}])[0]
        desc = (
            f"{case.get('numero')} - {court} {grau}: {classe}; filed {case.get('data_ajuizamento') or '?'}; "
            f"last movement {last.get('data') or '?'} {last.get('nome') or ''}".strip()
        )
        res.finding(
            "Court process in public DataJud", "info", desc,
            confidence="confirmed", source=SOURCE, tags=["no_export"],
            data={k: case.get(k) for k in ("numero", "tribunal", "grau", "classe", "assuntos", "orgao_julgador", "data_ajuizamento",
                                           "ultima_atualizacao", "movimentos_recentes", "movimentos_total")},
            observed_last=case.get("ultima_atualizacao"), key=f"{case.get('numero')}|{court}|{grau}",
        )

    def _key(self, ctx: Any, state: dict[str, Any]) -> str:
        """The key to send: the configured one, else the published one (cached in memory, else read)."""
        if state["key"]:
            return state["key"]
        configured = str(ctx.key(KEY_NAME) or "")
        if configured:
            state.update(key=configured, origin="configured")
            return configured
        with _KEY_LOCK:
            cached = _PUBLISHED_KEY.get("value", "")
        if cached:
            state.update(key=cached, origin="published")
            return cached
        return self._refresh(ctx, state, first=True)

    def _refresh(self, ctx: Any, state: dict[str, Any], *, first: bool = False) -> str:
        """Read the official key page (at most once per run after a rejection, P241 cond 5)."""
        if not first:
            if state["refreshed"]:
                raise _AuthFailed("DataJud refused the API key and the key CNJ publishes was already re-read in this run: "
                                  "check datajud-wiki.cnj.jus.br/api-publica/acesso or set it (v3lum keys set datajud)")
            state["refreshed"] = True
        try:
            resp = ctx.http.get(KEY_PAGE, source=SOURCE, ttl=0, headers={"Accept": "text/html"}, cache_if=lambda r: False)
            ctx.http.check(resp)
        except NetworkError as exc:
            raise _KeyPageFailed(f"could not read the DataJud key page ({type(exc).__name__}): could not verify") from None
        except Exception as exc:  # noqa: BLE001 - HttpError and classified answers (blocked, 5xx) end the same way
            name = type(exc).__name__
            if name in ("Blocked", "RateLimited", "QuotaExceeded", "Cancelled", "DeadlineExceeded", "RequestCapReached"):
                raise
            raise _KeyPageFailed(f"could not read the DataJud key page ({name}): could not verify") from None
        key = extract_datajud_key(resp.text)
        if not key:
            raise _AuthFailed("the DataJud key page no longer shows 'APIKey atual' in the expected form: "
                              "set the current key (v3lum keys set datajud)")
        redact.register_secret(key, "datajud published key")
        previous = state.get("key") or ""
        with _KEY_LOCK:
            _PUBLISHED_KEY["value"] = key
        if not first and key == previous:
            raise _AuthFailed("DataJud refused the key CNJ publishes on its access page (unchanged): could not verify; "
                              "set the current key (v3lum keys set datajud)")
        origin = "published_after_rejection" if state.get("origin") == "configured" else "published"
        state.update(key=key, origin=origin)
        return key

    def _send(self, ctx: Any, p: dict[str, Any], key: str, timeout: float | None) -> Any:
        body = {"query": {"match": {"numeroProcesso": p["digits"]}}, "size": SEARCH_SIZE}
        kw: dict[str, Any] = {
            "json_body": body, "headers": {"Authorization": f"APIKey {key}", "Content-Type": "application/json"},
            "source": SOURCE, "ttl": self.cache_ttl, "cache_if": _usable, "retries": 0,
        }
        if timeout is not None:
            kw["timeout"] = timeout
        return ctx.http.request("POST", f"{API}/{p['index']}/_search", **kw)

    def _query(self, ctx: Any, p: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        """One number: query, one key refresh on 401, one overload retry inside the deadline."""
        attempts = 0
        retried = False
        while True:
            key = self._key(ctx, state)
            attempts += 1
            try:
                resp = self._send(ctx, p, key, None)
            except RateLimited:
                # the core client backs the provider off after a 429 without Retry-After (P334): no resend in this run
                return {"status": "overloaded", "reason": OVERLOADED_TEXT + " (provider backoff after HTTP 429)", "attempts": attempts}
            except QuotaExceeded:
                return {"status": "quota", "reason": "could not verify: DataJud request budget exhausted", "attempts": attempts, "stop": "quota"}
            except DeadlineExceeded:
                return {"status": "timeout", "reason": "could not verify: DataJud did not answer before the run deadline",
                        "attempts": attempts, "stop": "deadline"}
            except NetworkError as exc:
                text = str(exc).lower()
                kind = "timed out" if "timed out" in text or "timeout" in text else "network error"
                return {"status": "error", "reason": f"could not verify: DataJud {kind}", "attempts": attempts}
            status = int(getattr(resp, "status", 0) or 0)
            if status in (401, 403) or (status == 200 and b"security_exception" in (resp.content or b"")[:4096]):
                ctx.http.evict(resp)
                self._refresh(ctx, state)
                continue
            if status == 429 or (status >= 500 and b"es_rejected_execution_exception" in (resp.content or b"")):
                # HTTP 429 es_rejected_execution_exception: the core backs the provider off for the rest of the
                # run (no Retry-After), so the single retry of cond 7 applies to the failed-shards form in HTTP 200
                return {"status": "overloaded", "reason": OVERLOADED_TEXT, "attempts": attempts}
            if status >= 500:
                return {"status": "error", "reason": f"could not verify: DataJud server error (HTTP {status})", "attempts": attempts}
            if status != 200:
                return {"status": "error", "reason": f"could not verify: unexpected DataJud answer (HTTP {status})", "attempts": attempts}
            cls = getattr(resp, "classification", None)
            if cls is not None and getattr(cls, "status", "") == "blocked":
                ctx.http.check(resp)  # a challenge/geo-block page: Blocked propagates (BLOCKED, never empty)
            outcome = parse_search(resp.content, p["digits"])
            if outcome["status"] == "auth":
                ctx.http.evict(resp)
                self._refresh(ctx, state)
                continue
            outcome["attempts"] = attempts
            if outcome["status"] != "overloaded" or retried:
                return outcome
            backoff = float(ctx.setting("datajud_backoff_seconds", BACKOFF_S) or 0.0)
            rem = ctx.remaining()
            if rem is not None and rem - backoff < MIN_USEFUL_S:
                outcome["reason"] = OVERLOADED_TEXT + " (no time left for a retry before the 60 s deadline)"
                return outcome
            if ctx.cancelled():
                return outcome
            retried = True
            _pause(ctx, backoff)


__all__ = ["DataJud", "extract_datajud_key", "forget_published_key", "html_to_text", "parse_search"]
