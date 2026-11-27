"""P234 ``cep_lookup`` - CEP lookup: offline CEP -> UF table, BrasilAPI CEP v2 -> ViaCEP chain, IBGE codes.

Council P234 final conditions, as implemented here:

1-2. Offline first: the bundled ``v3lum/data/cep_lookup/cep_uf_ranges.json`` (the council's 5-digit prefix
   table, exactly as written) answers the UF of any CEP without a request (attribute ``cep_uf_hint``).
   78900-78999 is not assigned by that table: :func:`cep_uf` answers None there (backlog p2-G10-1).
3. Online chain, stop at the first success, 5 s per provider, no fan-out, per-provider status in coverage
   (``res.source_status`` + attribute ``provider_chain``): BrasilAPI CEP v2 -> ViaCEP (-> OpenCEP, see 4).
   AwesomeAPI is dropped. IBGE localidades normalises municipality codes: the bundled IBGE municipality
   table (or a newer ``cep_lookup.ibge_municipios`` dataset copy) answers offline; the per-code endpoint
   is asked only for a code missing from the table.
4. Tiers: BrasilAPI and ViaCEP community, IBGE trusted. OpenCEP (provider ``opencep``, tier unknown) is not a
   declared source: it receives no value and the chain ends at ViaCEP. Its parser and chain slot exist
   (:data:`CHAIN`); it joins once the registry reviewer records tier community and the source/host are
   added to this class (one-line change, backlog p2-G10-1).
5. ViaCEP's documented ``{"erro": true}`` inside HTTP 200 (sent live as the string "true") means EMPTY;
   every other error-in-200, HTML, 403/429, timeout or 5xx means could not verify. A provider record whose
   UF contradicts the range table, or that echoes another CEP, is 'inconsistent' (seen live: a bogus 200
   for 99999-999) and the chain goes on. BrasilAPI 404 ``CepPromiseError`` is a not-found vote, not an
   absence: only ViaCEP's marker ends the chain as EMPTY.
6. One normaliser to the shared vocabulary (address, city, region, country BR, ibge_code; ``cep_record``).
   BrasilAPI coordinates are labelled 'CEP centroid (approximate)', never a person's location; the
   coordinates pivot exists only when a provider supplied them and is never auto-expanded.
7. ViaCEP reverse address search (``ws/{UF}/{city}/{street}/json``, >= 3 characters per segment) only for an
   address the analyst typed (a keyword seed, not extracted from text); the company-address path needs the
   CNPJ record handed to the module (backlog). Never for addresses tied to natural persons.
8. :func:`uf_mismatch_attributes`: CEP UF vs DDD vs CNPJ UF mismatches are weak info attributes for
   correlation (``uf_mismatch``); they never raise a score on their own.
9. Cache TTL 30 days (``cache_ttl``), always capped by the provider profile ttl (BrasilAPI 72 h),
   ``cache_max_age_days`` and ``retention_days``; failures are never cached.
"""

from __future__ import annotations

import json
import re
import threading
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core.datasets import DataStore, register_dataset
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
from v3lum.core.module import HealthCheck, Module, register

SRC_BRASILAPI = "brasilapi.cep"
SRC_VIACEP = "viacep.cep"
SRC_OPENCEP = "opencep.cep"
SRC_IBGE = "ibge.localidades"
PROVIDERS: dict[str, dict[str, str]] = {
    "brasilapi": {"url": "https://brasilapi.com.br/api/cep/v2/{cep}", "source": SRC_BRASILAPI, "label": "BrasilAPI CEP v2"},
    "viacep": {"url": "https://viacep.com.br/ws/{cep}/json/", "source": SRC_VIACEP, "label": "ViaCEP"},
    "opencep": {"url": "https://opencep.com/v1/{cep}", "source": SRC_OPENCEP, "label": "OpenCEP"},
}
#: cond 3/4: the chain order; a provider runs only when its source is declared by the module
CHAIN = ("brasilapi", "viacep", "opencep")
IBGE_MUNICIPIO_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/municipios/{code}"
IBGE_DATASET = "cep_lookup.ibge_municipios"
IBGE_DATASET_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/municipios?view=nivelado"
BUNDLED_RANGES = "cep_lookup/cep_uf_ranges.json"
BUNDLED_MUNICIPIOS = "cep_lookup/ibge_municipios.json"
PROVIDER_TIMEOUT_S = 5.0  # cond 3
CACHE_TTL = 30 * 86400  # cond 9
COORD_LABEL = "CEP centroid (approximate)"  # cond 6
REVERSE_CAP = 50
REVERSE_PIVOTS = 10
MIN_MUNICIPIOS = 5000  # 5571 on 2026-11-26

UF_NAMES = {
    "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas", "BA": "Bahia", "CE": "Ceará", "DF": "Distrito Federal",
    "ES": "Espírito Santo", "GO": "Goiás", "MA": "Maranhão", "MT": "Mato Grosso", "MS": "Mato Grosso do Sul", "MG": "Minas Gerais",
    "PA": "Pará", "PB": "Paraíba", "PR": "Paraná", "PE": "Pernambuco", "PI": "Piauí", "RJ": "Rio de Janeiro",
    "RN": "Rio Grande do Norte", "RS": "Rio Grande do Sul", "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina",
    "SP": "São Paulo", "SE": "Sergipe", "TO": "Tocantins",
}
#: Anatel DDD -> UF (67 area codes); DDD 61 also serves the GO municipalities around Brasilia (Entorno)
_DDD_BY_UF = {
    "SP": (11, 12, 13, 14, 15, 16, 17, 18, 19), "RJ": (21, 22, 24), "ES": (27, 28), "MG": (31, 32, 33, 34, 35, 37, 38),
    "PR": (41, 42, 43, 44, 45, 46), "SC": (47, 48, 49), "RS": (51, 53, 54, 55), "DF": (61,), "GO": (62, 64), "TO": (63,),
    "MT": (65, 66), "MS": (67,), "AC": (68,), "RO": (69,), "BA": (71, 73, 74, 75, 77), "SE": (79,), "PE": (81, 87), "AL": (82,),
    "PB": (83,), "RN": (84,), "CE": (85, 88), "PI": (86, 89), "PA": (91, 93, 94), "AM": (92, 97), "RR": (95,), "AP": (96,),
    "MA": (98, 99),
}
DDD_UF = {d: uf for uf, ds in _DDD_BY_UF.items() for d in ds}
DDD_EXTRA_UF = {61: ("GO",)}


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


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", _s(text))
    return "".join(c for c in t if not unicodedata.combining(c)).upper()


def _digits(value: Any, n: int | None = None) -> str | None:
    d = re.sub(r"\D", "", _s(value))
    if n and len(d) != n:
        return None
    return d or None


# --------------------------------------------------------------------------------------
# offline: CEP -> UF (cond 1-2) and DDD -> UF (cond 8)
# --------------------------------------------------------------------------------------


def normalize_cep(value: Any) -> str | None:
    """8-digit CEP or None (invalid input never reaches a provider)."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = f"{value:08d}"
    d = re.sub(r"[\s.-]", "", _s(value))
    return d if re.fullmatch(r"\d{8}", d) else None


def format_cep(value: Any) -> str | None:
    c = normalize_cep(value)
    return f"{c[:5]}-{c[5:]}" if c else None


def cep_ranges() -> list[tuple[int, int, str]]:
    data = DataStore.bundled_json(BUNDLED_RANGES)
    return [(int(lo), int(hi), str(uf)) for lo, hi, uf in data["ranges"]]


def cep_uf(cep: Any) -> str | None:
    """cond 1-2: UF from the 5-digit prefix (no request). None outside every range."""
    c = normalize_cep(cep)
    if not c:
        return None
    n = int(c[:5])
    return next((uf for lo, hi, uf in cep_ranges() if lo <= n <= hi), None)


def ddd_uf(ddd: Any) -> str | None:
    return DDD_UF.get(_int(ddd) or -1)


def uf_mismatch_attributes(cep: Any = None, ddd: Any = None, cnpj_uf: Any = None) -> list[dict[str, Any]]:
    """cond 8: CEP UF vs DDD UF vs CNPJ UF mismatches -> weak info entries (score effect 0)."""
    cu = cep_uf(cep) if cep else None
    du = ddd_uf(ddd) if ddd else None
    nu = _s(cnpj_uf).upper() or None
    extra = DDD_EXTRA_UF.get(_int(ddd) or -1, ())
    out: list[dict[str, Any]] = []

    def add(check: str, a: str, b: str, la: str, lb: str) -> None:
        out.append({"check": check, "value": f"{la} {a} vs {lb} {b}", "weak": True, "score_effect": 0,
                    "note": "people and companies move: context for correlation only"})

    if cu and du and cu != du and cu not in extra:
        add("cep_ddd", cu, du, "CEP", "DDD")
    if cu and nu and cu != nu:
        add("cep_cnpj", cu, nu, "CEP", "CNPJ")
    if du and nu and du != nu and nu not in extra:
        add("ddd_cnpj", du, nu, "DDD", "CNPJ")
    return out


# --------------------------------------------------------------------------------------
# IBGE municipality table (cond 3): bundled, or a newer dataset copy
# --------------------------------------------------------------------------------------


def parse_ibge_municipios_flat(obj: Any) -> dict[str, list[str]]:
    """IBGE localidades ``view=nivelado`` list -> {code: [name, UF]}."""
    out: dict[str, list[str]] = {}
    for row in _l(obj):
        r = _d(row)
        code = _int(r.get("municipio-id"))
        name = _s(r.get("municipio-nome"))
        uf = _s(r.get("UF-sigla")).upper()
        if code and name and uf in UF_NAMES:
            out[str(code)] = [name, uf]
    return out


def _validate_municipios(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return len(parse_ibge_municipios_flat(json.load(fh))) >= MIN_MUNICIPIOS
    except (OSError, ValueError):
        return False


register_dataset(
    IBGE_DATASET, IBGE_DATASET_URL, ttl=30 * 86400,
    description="IBGE municipality list (code, name, UF) refreshing the bundled cep_lookup table (P234 cond 3)",
    licence="Brazilian open government data (IBGE, Decreto 8.777/2016)", terms_class="open",
    attribution="IBGE - API de Localidades (municipios)", provider="ibge", source=SRC_IBGE, validate=_validate_municipios,
    min_bytes=500_000, expect="json", max_bytes=10_000_000, large=False,
)

_MUN_LOCK = threading.Lock()
_MUN_MEMO: dict[str, dict[str, list[str]]] = {}


def municipios(data: Any = None) -> dict[str, list[str]]:
    """{ibge_code: [name, UF]}: a valid local dataset copy (never downloaded here), else the bundled table."""
    if data is not None:
        try:
            info = data.info(IBGE_DATASET)
            if getattr(info, "present", False):
                sha = str(getattr(info, "sha256", "") or "")
                with _MUN_LOCK:
                    if sha in _MUN_MEMO:
                        return _MUN_MEMO[sha]
                store = getattr(data, "store", data)
                parsed = parse_ibge_municipios_flat(json.loads(Path(store.path(IBGE_DATASET)).read_bytes().decode("utf-8")))
                if len(parsed) >= MIN_MUNICIPIOS:
                    with _MUN_LOCK:
                        _MUN_MEMO[sha] = parsed
                    return parsed
        except Exception:  # an unreadable local copy is ignored: the bundled table answers
            pass
    return dict(DataStore.bundled_json(BUNDLED_MUNICIPIOS)["municipios"])


def municipio_by_name(table: dict[str, list[str]], city: Any, uf: Any) -> str | None:
    """IBGE code for (city, UF) from the table (accent/case-insensitive), or None."""
    fc, fu = fold(city), _s(uf).upper()
    if not fc or not fu:
        return None
    hits = [code for code, (name, u) in table.items() if u == fu and fold(name) == fc]
    return hits[0] if len(hits) == 1 else None


def parse_ibge_municipio(obj: Any) -> dict[str, Any] | None:
    """IBGE localidades municipality (nested view) -> {ibge_code, city, uf, region}; ``[]`` -> None."""
    if isinstance(obj, list):
        if not obj:
            return None
        obj = obj[0]
    o = _d(obj)
    code = _int(o.get("id"))
    if not code:
        return None
    uf = _d(_d(_d(o.get("microrregiao")).get("mesorregiao")).get("UF")) or _d(
        _d(_d(o.get("regiao-imediata")).get("regiao-intermediaria")).get("UF"))
    return {"ibge_code": str(code), "city": _s(o.get("nome")) or None, "uf": _s(uf.get("sigla")).upper() or None,
            "region": _s(_d(uf.get("regiao")).get("nome")) or None}


# --------------------------------------------------------------------------------------
# provider parsers (cond 3, 5, 6)
# --------------------------------------------------------------------------------------


def _coord(value: Any) -> float | None:
    try:
        f = float(_s(value).replace(",", "."))
    except ValueError:
        return None
    return f if f == f else None


def _br_coords(lat: float | None, lon: float | None) -> dict[str, Any] | None:
    if lat is None or lon is None or not (-34.0 <= lat <= 6.0 and -74.5 <= lon <= -28.5):
        return None  # outside Brazil's bounding box: treated as missing
    return {"lat": lat, "lon": lon, "label": COORD_LABEL}


def parse_brasilapi_cep(obj: Any) -> dict[str, Any] | None:
    """BrasilAPI CEP v2 (also v1) -> normalised record; coordinates only when supplied."""
    o = _d(obj)
    cep = normalize_cep(o.get("cep"))
    if not cep:
        return None
    loc = _d(_d(o.get("location")).get("coordinates"))
    return {"provider": "brasilapi", "cep": cep, "uf": _s(o.get("state")).upper() or None, "city": _s(o.get("city")) or None,
            "district": _s(o.get("neighborhood")) or None, "street": _s(o.get("street")) or None,
            "ibge_code": _digits(_d(o.get("ibge")).get("city"), 7), "backend": _s(o.get("service")) or None,
            "coordinates": _br_coords(_coord(loc.get("latitude")), _coord(loc.get("longitude")))}


def _viacep_like(obj: Any, provider: str) -> dict[str, Any] | None:
    o = _d(obj)
    cep = normalize_cep(o.get("cep"))
    if not cep:
        return None
    rec = {"provider": provider, "cep": cep, "uf": _s(o.get("uf")).upper() or None, "city": _s(o.get("localidade")) or None,
           "district": _s(o.get("bairro")) or None, "street": _s(o.get("logradouro")) or None,
           "ibge_code": _digits(o.get("ibge"), 7), "complement": _s(o.get("complemento")) or None, "coordinates": None}
    if provider == "viacep":
        rec["ddd"] = _digits(o.get("ddd"), 2)
    return rec


def viacep_erro_marker(obj: Any) -> str | None:
    """cond 5: ViaCEP's documented not-found marker inside HTTP 200 (string 'true' live, boolean documented)."""
    if isinstance(obj, dict) and "erro" in obj:
        v = obj.get("erro")
        if v is True or _s(v).lower() == "true":
            return "ViaCEP: CEP not found (documented erro marker)"
    return None


def opencep_not_found_marker(obj: Any) -> str | None:
    if isinstance(obj, dict) and (obj.get("error") is True or _s(obj.get("error")).lower() == "true"):
        return "OpenCEP: CEP not found"
    return None


def brasilapi_cep_error(obj: Any) -> dict[str, Any] | None:
    """BrasilAPI CepPromiseError -> {type, not_found_votes, backend_errors} or None."""
    o = _d(obj)
    if _s(o.get("name")) != "CepPromiseError":
        return None
    errs = [_d(e) for e in _l(o.get("errors"))]
    nf = sum(1 for e in errs if "NAO ENCONTRADO" in fold(e.get("message")))
    return {"type": _s(o.get("type")) or None, "not_found_votes": nf, "backend_errors": len(errs) - nf}


def parse_provider_record(provider: str, obj: Any) -> dict[str, Any] | None:
    if provider == "brasilapi":
        return parse_brasilapi_cep(obj)
    if provider == "viacep":
        return None if viacep_erro_marker(obj) else _viacep_like(obj, "viacep")
    if provider == "opencep":
        return None if opencep_not_found_marker(obj) else _viacep_like(obj, "opencep")
    return None


def cep_consistency(cep: Any, record: dict[str, Any]) -> str | None:
    """Guard: the echoed CEP must be the one asked and the UF must agree with the range table."""
    q = normalize_cep(cep)
    if q and record.get("cep") and record["cep"] != q:
        return f"answered CEP {format_cep(record['cep'])} for {format_cep(q)}"
    off = cep_uf(q)
    uf = _s(record.get("uf")).upper()
    if off and uf and uf != off:
        return f"provider UF {uf} contradicts the CEP range table ({off})"
    return None


def normalise_cep_record(rec: dict[str, Any], table: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """cond 6: one normaliser to the shared vocabulary (IBGE code/name/UF win when the code is known)."""
    table = table or {}
    code = rec.get("ibge_code") or municipio_by_name(table, rec.get("city"), rec.get("uf"))
    known = table.get(code or "")
    uf = (known[1] if known else _s(rec.get("uf"))).upper() or None
    street, district = rec.get("street"), rec.get("district")
    out = {
        "postal_code": format_cep(rec.get("cep")), "address": ", ".join(x for x in (street, district) if x) or None,
        "district": district, "city": known[0] if known else rec.get("city"), "region": uf,
        "region_iso": f"BR-{uf}" if uf else None, "country": "BR", "ibge_code": code, "provider": rec.get("provider"),
        "coordinates": rec.get("coordinates"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


# --------------------------------------------------------------------------------------
# reverse address search (cond 7)
# --------------------------------------------------------------------------------------


def parse_typed_address(text: Any) -> tuple[str, str, str] | None:
    """An analyst-typed address -> (UF, city, street) or None.

    Accepts 'Praça da Sé, São Paulo - SP', 'Praça da Sé, 108, São Paulo/SP' and 'SP/São Paulo/Praça da Sé';
    house numbers are dropped (ViaCEP searches the street name)."""
    t = re.sub(r"\s+", " ", _s(text))
    m = re.match(r"^([A-Za-z]{2})\s*/\s*([^/]{3,}?)\s*/\s*([^/]{3,})$", t)
    if m and m.group(1).upper() in UF_NAMES:
        uf, city, street = m.group(1).upper(), m.group(2), m.group(3)
    else:
        m = re.match(r"^(.{3,}?)\s*,\s*([^,]{3,}?)\s*(?:-|/|,)\s*([A-Za-z]{2})$", t)
        if not m or m.group(3).upper() not in UF_NAMES:
            return None
        uf, city, street = m.group(3).upper(), m.group(2), m.group(1)
    street = re.sub(r"(,\s*|\s+)(n[ºo°.]?\s*)?\d+[A-Za-z]?$", "", street.strip(), flags=re.I).strip(" ,")
    city = city.strip(" ,")
    if len(street) < 3 or len(city) < 3 or re.search(r"\d{5}", street + city):
        return None
    return uf, city, street


def viacep_reverse_url(uf: str, city: str, street: str) -> str:
    """>= 3 characters per segment (ViaCEP rule); ValueError otherwise."""
    u = _s(uf).upper()
    c, s = re.sub(r"\s+", " ", _s(city)), re.sub(r"\s+", " ", _s(street))
    if u not in UF_NAMES or len(c) < 3 or len(s) < 3:
        raise ValueError("reverse search needs a UF and >= 3 characters per segment")
    return f"https://viacep.com.br/ws/{u}/{quote(c, safe='')}/{quote(s, safe='')}/json/"


def parse_viacep_reverse(obj: Any, cap: int = REVERSE_CAP) -> list[dict[str, Any]]:
    return [r for r in (_viacep_like(x, "viacep") for x in _l(obj)[:cap]) if r]


# --------------------------------------------------------------------------------------
# one provider call -> a chain step
# --------------------------------------------------------------------------------------


def _json_body(resp: Any) -> Any:
    try:
        raw = bytes(getattr(resp, "content", b"") or b"")
        if raw.lstrip()[:1] not in (b"{", b"["):
            return None
        return json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _cacheable(resp: Any) -> bool:
    """Only parseable JSON answers are cached (records, the documented ViaCEP marker, not-found votes)."""
    return int(getattr(resp, "status", 0) or 0) in (200, 404) and isinstance(_json_body(resp), (dict, list))


def _step(provider: str, state: str, reason: str = "", code: str = "", record: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"provider": provider, "source": PROVIDERS[provider]["source"] if provider in PROVIDERS else "", "state": state,
            "reason": reason, "reason_code": code, "record": record}


def _failure_step(ctx: Any, provider: str, exc: Exception) -> dict[str, Any]:
    label = PROVIDERS.get(provider, {}).get("label", provider)
    if isinstance(exc, RateLimited):
        return _step(provider, "rate_limited", f"{label}: rate limited ({exc})", "rate_limited")
    if isinstance(exc, QuotaExceeded):
        return _step(provider, "quota", f"{label}: quota exhausted ({exc})", "quota")
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return _step(provider, "blocked", f"{label}: blocked ({exc})",
                     code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge")
    if isinstance(exc, AuthRequired):
        return _step(provider, "blocked", f"{label}: HTTP {getattr(exc, 'status', '') or '401/403'} for a keyless API", "challenge")
    if isinstance(exc, DeadlineExceeded):
        remaining = ctx.remaining() if callable(getattr(ctx, "remaining", None)) else None
        if remaining is not None and remaining <= 0:
            raise exc
        return _step(provider, "error", f"{label}: no answer within {PROVIDER_TIMEOUT_S:.0f} s", "timeout")
    if isinstance(exc, NetworkError):
        kind = str(getattr(exc, "kind", "") or "").lower()
        timeout = "timeout" in kind or "timed out" in str(exc).lower()
        return _step(provider, "error", f"{label}: {exc}", "timeout" if timeout else "error")
    return _step(provider, "error", f"{label}: {exc}", "error")


def call_provider(ctx: Any, provider: str, cep: str) -> dict[str, Any]:
    """One chain step: ok | empty | not_found | inconsistent | error | blocked | rate_limited | quota."""
    spec = PROVIDERS[provider]
    label = spec["label"]
    try:
        resp = ctx.http.get(spec["url"].format(cep=cep), source=spec["source"], timeout=PROVIDER_TIMEOUT_S, retries=0,
                            headers={"Accept": "application/json"}, cache_if=_cacheable)
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
        return _failure_step(ctx, provider, exc)
    body = _json_body(resp)
    if getattr(resp, "status", 0) == 404 and resp.classification is None:
        if provider == "brasilapi" and brasilapi_cep_error(body):
            e = brasilapi_cep_error(body) or {}
            return _step(provider, "not_found", f"{label}: {e.get('type') or 'error'} ({e.get('not_found_votes')} not-found vote(s), "
                                                f"{e.get('backend_errors')} backend error(s)): a vote, not a documented absence")
        if provider == "opencep" and opencep_not_found_marker(body):
            return _step(provider, "not_found", f"{label}: CEP not found (a vote, not a documented absence)")
        return _step(provider, "error", f"{label}: HTTP 404 without the provider's not-found body: could not verify", "error")
    try:
        ctx.http.check(resp)
    except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError) as exc:
        return _failure_step(ctx, provider, exc)
    if body is None:
        return _step(provider, "error", f"{label}: HTML or invalid JSON in HTTP {resp.status}: could not verify", "error")
    if provider == "viacep" and viacep_erro_marker(body):
        return _step(provider, "empty", viacep_erro_marker(body) or "")
    record = parse_provider_record(provider, body)
    if not record:
        return _step(provider, "error", f"{label}: HTTP {resp.status} without a CEP record (error in 200): could not verify", "error")
    bad = cep_consistency(cep, record)
    if bad:
        return _step(provider, "inconsistent", f"{label}: {bad}: answer discarded", "error", record)
    return _step(provider, "ok", record=record)


_STATE_STATUS = {"ok": Status.OK, "empty": Status.EMPTY, "not_found": Status.EMPTY, "blocked": Status.BLOCKED,
                 "rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA}


def chain_verdict(steps: list[dict[str, Any]]) -> tuple[Status, str, str]:
    """(status, reason, reason_code): the first success wins; ViaCEP's marker is the only EMPTY; anything
    else is could not verify (BLOCKED > RATE_LIMITED > QUOTA > ERROR)."""
    if any(s["state"] == "ok" for s in steps):
        return Status.OK, "", ""
    if any(s["state"] == "empty" for s in steps):
        return Status.EMPTY, "CEP not found (ViaCEP documented marker)", ""
    detail = "; ".join(f"{s['provider']}: {s['state']}" + (f" - {s['reason'][:120]}" if s.get("reason") else "") for s in steps)
    detail = detail or "no provider asked"
    for state, status in (("blocked", Status.BLOCKED), ("rate_limited", Status.RATE_LIMITED), ("quota", Status.QUOTA)):
        hit = [s for s in steps if s["state"] == state]
        if hit:
            return status, f"could not verify ({detail})", hit[0]["reason_code"] or ""
    failed = [s for s in steps if s["state"] in ("error", "inconsistent")]
    timeout = bool(failed) and all(s.get("reason_code") == "timeout" for s in failed)
    return Status.ERROR, f"could not verify ({detail})", "timeout" if timeout else "error"


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class CepLookup(Module):
    name = "cep_lookup"
    title = "CEP lookup (offline UF + BrasilAPI/ViaCEP)"
    description = (
        "UF of a CEP from the offline range table, then street/district/city from BrasilAPI CEP v2 or ViaCEP (first "
        "success, IBGE municipality code normalised offline); reverse search of an analyst-typed address on ViaCEP."
    )
    category = "brazil_public_data"
    accepts = {T.CEP, T.KEYWORD}
    produces = {T.COORDINATES, T.CEP}
    tags = {"brazil", "free"}
    reference = "https://viacep.com.br/"
    notice = (
        "Coordinates are a CEP centroid (approximate), never a person's location, and are never expanded. Reverse address "
        "search runs only for an address the analyst typed, never for text extracts or addresses of natural persons. "
        "CEP/DDD/CNPJ UF mismatches are weak context only."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("brasilapi.com.br", "viacep.com.br", "servicodados.ibge.gov.br")
    provider = "brasilapi"
    sources = (SRC_BRASILAPI, SRC_VIACEP, SRC_IBGE)
    access_model = "free_noauth_limited"
    max_requests = 4  # BrasilAPI + ViaCEP + one IBGE code missing from the table (or one reverse search)
    expected_latency = 0.8  # BrasilAPI cache hit 0.3 s; miss + ViaCEP ~3 s (measured 2026-11-26)
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = 12
    default_enabled = True  # A3: council P234 (community providers, area-level data)

    @classmethod
    def health_check(cls) -> HealthCheck:
        # CEP 01001-000 (Praça da Sé, São Paulo): a public square, the reference CEP of the providers' docs
        return HealthCheck(etype=T.CEP, value="01001000")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.CEP:
            return normalize_cep(entity.value) is not None
        return parse_typed_address(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.KEYWORD:
            return self._reverse(res, ctx, entity)
        cep = normalize_cep(entity.value)
        if not cep:
            return res.mark(Status.SKIPPED, "not an 8-digit CEP", reason_code="not_applicable")
        offline_uf = cep_uf(cep)
        if offline_uf:
            res.attr("cep_uf_hint", offline_uf)
        steps: list[dict[str, Any]] = []
        for provider in self.chain():
            step = call_provider(ctx, provider, cep)
            steps.append(step)
            if step["state"] in ("ok", "empty"):
                break  # cond 3: first success (or ViaCEP's documented absence) ends the chain
        self._coverage(res, steps)
        res.attr("provider_chain", [{k: s[k] for k in ("provider", "source", "state", "reason") if s.get(k)} for s in steps])
        status, reason, code = chain_verdict(steps)
        if status is not Status.OK:
            res.raw = {"cep": cep, "uf_offline": offline_uf, "steps": [{k: v for k, v in s.items() if k != "record"} for s in steps]}
            return res.mark(status, reason, reason_code=code)
        record = next(s["record"] for s in steps if s["state"] == "ok")
        table = municipios(getattr(ctx, "data", None))
        if record.get("ibge_code") and record["ibge_code"] not in table:
            self._ibge_lookup(res, ctx, record, table)
        norm = normalise_cep_record(record, table)
        res.attr("cep_record", norm)
        for key in ("address", "city", "region", "country", "ibge_code"):
            res.attr(key, norm.get(key))
        if record.get("ddd"):
            res.attr("cep_ddd", record["ddd"])
            res.attr("uf_mismatch", [{"check": m["check"], "value": m["value"]} for m in uf_mismatch_attributes(cep=cep, ddd=record["ddd"])])
        coords = record.get("coordinates")
        if coords:
            res.pivot(T.COORDINATES, f"{coords['lat']},{coords['lon']}", "located_at", confidence="possible", expand=False,
                      note=f"{COORD_LABEL} from {PROVIDERS[record['provider']]['label']}: never a person's location")
        res.raw = {"cep": cep, "uf_offline": offline_uf, "record": norm, "steps": [s["provider"] + ":" + s["state"] for s in steps]}
        return res

    def chain(self) -> list[str]:
        """cond 3/4: providers in chain order whose source this class declares (OpenCEP waits for its tier)."""
        return [p for p in CHAIN if PROVIDERS[p]["source"] in self.sources]

    @staticmethod
    def _coverage(res: ModuleResult, steps: list[dict[str, Any]]) -> None:
        for s in steps:
            status = _STATE_STATUS.get(s["state"], Status.ERROR)
            code = s["reason_code"] if status in (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR) else ""
            res.source_status(s["source"], status, reason_code=code or "", reason=(s.get("reason") or "")[:300])

    @staticmethod
    def _ibge_lookup(res: ModuleResult, ctx: Any, record: dict[str, Any], table: dict[str, list[str]]) -> None:
        """A municipality code missing from the offline table: one IBGE localidades request."""
        code = record["ibge_code"]
        try:
            resp = ctx.http.get(IBGE_MUNICIPIO_URL.format(code=code), source=SRC_IBGE, timeout=PROVIDER_TIMEOUT_S, retries=0,
                                headers={"Accept": "application/json"}, cache_if=_cacheable)
            ctx.http.check(resp)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            step = _failure_step(ctx, "ibge", exc)
            status = _STATE_STATUS.get(step["state"], Status.ERROR)
            res.source_status(SRC_IBGE, status, reason_code=step["reason_code"] or "", reason=f"IBGE municipality {code}: {exc}"[:300])
            return
        parsed = parse_ibge_municipio(_json_body(resp))
        if parsed and parsed.get("city") and parsed.get("uf"):
            table[code] = [parsed["city"], parsed["uf"]]
            res.source_status(SRC_IBGE, Status.OK)
        else:
            res.source_status(SRC_IBGE, Status.EMPTY, reason=f"IBGE: unknown municipality code {code} (empty answer)")

    def _reverse(self, res: ModuleResult, ctx: Any, entity: Entity) -> ModuleResult:
        """cond 7: only an analyst-typed address (a keyword seed that was not extracted from text)."""
        options = getattr(ctx, "options", None)
        unconfirmed = set(getattr(options, "unconfirmed_seeds", ()) or ())
        if not getattr(ctx, "is_seed", False) or int(getattr(ctx, "depth", 0) or 0) > 0 or entity.key in unconfirmed:
            return res.mark(Status.SKIPPED, "reverse address search runs only for an address the analyst typed (never for text "
                            "extracts, pivots or addresses of natural persons)", reason_code="privacy")
        parsed = parse_typed_address(entity.value)
        if not parsed:
            return res.mark(Status.SKIPPED, "not an address ('street, city - UF' or 'UF/city/street')", reason_code="not_applicable")
        uf, city, street = parsed
        url = viacep_reverse_url(uf, city, street)
        try:
            resp = ctx.http.get(url, source=SRC_VIACEP, timeout=PROVIDER_TIMEOUT_S, retries=0, headers={"Accept": "application/json"},
                                cache_if=_cacheable)
            ctx.http.check(resp)
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            step = _failure_step(ctx, "viacep", exc)
            status = _STATE_STATUS.get(step["state"], Status.ERROR)
            return res.mark(status, f"could not verify ({step['reason']})", reason_code=step["reason_code"] or "")
        body = _json_body(resp)
        if viacep_erro_marker(body) or body == []:
            res.attr("cep_uf_hint", uf)
            return res.mark(Status.EMPTY, f"ViaCEP lists no CEP for '{street}', {city}/{uf}")
        if not isinstance(body, list):
            return res.mark(Status.ERROR, "ViaCEP reverse search: unexpected answer (not a list): could not verify", reason_code="error")
        rows = parse_viacep_reverse(body)
        if not rows:
            return res.mark(Status.ERROR, "ViaCEP reverse search: no parseable CEP rows: could not verify", reason_code="error")
        matches = [{"postal_code": format_cep(r["cep"]), "street": r.get("street"), "district": r.get("district"),
                    "complement": r.get("complement"), "city": r.get("city"), "uf": r.get("uf")} for r in rows]
        res.attr("cep_reverse_matches", [{k: v for k, v in m.items() if v} for m in matches])
        for r in rows[:REVERSE_PIVOTS]:
            res.pivot(T.CEP, r["cep"], "located_at", confidence="possible", expand=False,
                      note="candidate CEP of the typed address (ViaCEP reverse search): a street can span several CEPs")
        res.source_status(SRC_VIACEP, Status.OK, reason=f"{len(rows)} CEP(s) for the typed address")
        res.raw = {"query": {"uf": uf, "city": city, "street": street}, "count": len(rows)}
        return res


__all__ = [
    "CHAIN",
    "CepLookup",
    "call_provider",
    "cep_consistency",
    "cep_uf",
    "chain_verdict",
    "ddd_uf",
    "format_cep",
    "municipios",
    "normalise_cep_record",
    "normalize_cep",
    "parse_brasilapi_cep",
    "parse_ibge_municipio",
    "parse_ibge_municipios_flat",
    "parse_typed_address",
    "parse_viacep_reverse",
    "uf_mismatch_attributes",
    "viacep_erro_marker",
    "viacep_reverse_url",
]
