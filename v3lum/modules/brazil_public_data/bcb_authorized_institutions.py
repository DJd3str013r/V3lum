"""bcb_authorized_institutions (P360): authorised financial institutions and their verified domains.

Batch p1-G10-3. Offline matching (disclosure 'none'): the investigated value never leaves the
machine. Sources: BCB Olinda 'Instituicoes_em_funcionamento' v1 (DominiosVerificados and the Sedes*
head-office sets, C0745) and the CVM cadastral registries (C0744) through the shared loader
:mod:`v3lum.modules.brazil_public_data.cvm_registries`.

* **FC1 datasets** - dataset manager only, never during a scan: DominiosVerificados (~630 KB) is
  downloaded daily in full and matched locally (server-side ``$filter``/``$count`` are broken), the slow
  Sedes* sets and the CVM registries are refreshed by ``v3lum data update``. Every registration is
  ``large=True`` and the module reads the local copies only (no refresh, no download); a missing copy
  is UNAVAILABLE 'dataset' ('not screened against BCB/CVM registries - run v3lum data update ...').
* **FC2 validation** - each copy is validated before it replaces the previous one (floors, OData error
  bodies, row count within -10%/+25% of the previous copy, at least 400 verified domains); the dataset
  date goes into the evidence, the ``dataset_age`` attribute and the coverage rows (``source_status``).
* **FC3** - OData comment-wrapped error bodies (``/*{"codigo": 500, ...}*/``) are errors, never an
  empty list: provider marker ``bcb_authorized_institutions_odata_comment_error`` (any status) and
  :func:`odata_error` in every parser and validator.
* **FC4 matching** - exact host or a label-wise subdomain of a verified domain, walking only up to the
  PSL registrable domain (``v3lum.core.psl``); never substrings, lookalikes or string suffixes. A match
  sets ``known_good`` plus an INFO finding with legal name, CNPJ root, segment and conglomerate.
* **FC5** - known_good annotates, never suppresses: the module never touches other findings; the
  correlation rule ``bcb_verified_domain_flagged`` (``v3lum/correlations/p1_g10_3.py``) surfaces a
  flagged verified domain as 'possible compromise - verified institution domain, review URL'.
  Domain-reputation weighting belongs to the scorer (P302): :func:`reputation_adjustment` is the
  helper it should apply.
* **FC6** - a URL on a verified domain whose query or fragment names a redirect target on another host
  is not known_good and is tagged ``redirect_via_verified_domain`` (the target pivots as an IOC).
* **FC7** - absence produces no finding (status EMPTY); an authorised institution without a verified
  domain gets at most the INFO line 'no verified domain registered with BCB'.
* **FC8** - protected-brand feed for P012/P028: :func:`protected_brands`, :func:`protected_brand_for`
  and :func:`classify_lookalike` (HIGH only when registered and active, otherwise a MEDIUM watch item,
  suppressed when the registro.br registrant CNPJ root is the institution's or a conglomerate
  member's); the graph rule ``bcb_lookalike_activity`` applies it to typosquat reverse matches.
* **FC9** - CNPJ-root or company-name queries answer in one line 'authorised by BCB/CVM: yes
  (<segment>)' / '... not found as of <date>' (exact normalised names only, at most 5 hypotheses, no
  auto-chaining unless the legal name matches one active entity exactly). Natural-person registries are
  never read here (``cvm_person_registry``, explicit due diligence only); a CPF is never a lookup key.
* **FC10** - BCB and CVM are trusted government providers; attribution 'Banco Central do Brasil
  (Olinda, dados abertos); Comissao de Valores Mobiliarios (dados.cvm.gov.br, ODbL)'; the ODbL
  share-alike applies only if a derived database is redistributed (the index is never exported).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from v3lum.core import psl
from v3lum.core.datasets import DataStore, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import cvm_registries as cvm
from v3lum.modules.brazil_public_data.cvm_registries import clean, cnpj_root, fold, head_office_cnpj, normalize_host

SOURCE = "bcb.olinda_institutions"
SOURCE_CVM = cvm.SOURCE
OLINDA = "https://olinda.bcb.gov.br/olinda/servico/Instituicoes_em_funcionamento/versao/v1/odata/"
LICENCE = "BCB dados abertos (open government data of the Banco Central do Brasil, Decreto 8.777/2016)"
ATTRIBUTION = "Banco Central do Brasil (Olinda, dados abertos)"
REPORT_ATTRIBUTION = "Fonte: Banco Central do Brasil (Olinda, dados abertos); Comissao de Valores Mobiliarios (dados.cvm.gov.br, ODbL)"
DATASET_MAX_BYTES = 10_000_000
MIN_UNIQUE_DOMAINS = 400

LINE_NO_DOMAIN = "no verified domain registered with BCB"  # FC7
TITLE_COMPROMISE = "possible compromise - verified institution domain, review URL"  # FC5
SEGMENT_NOT_INFORMED = "BCB: segment not informed"
KNOWN_GOOD_DOMAIN_REPUTATION_FACTOR = 0.5  # FC5: domain-reputation signals only
MALICIOUS_VERDICTS = frozenset({"malicious", "phishing", "malware", "c2", "suspicious", "compromised"})
#: caps (P360 notes s.6): CNPJ pivots of a matched domain, name hypotheses, domain pivots
MAX_DOMAIN_CNPJ_PIVOTS = 3
MAX_NAME_HYPOTHESES = 5
MAX_DOMAIN_PIVOTS = 10
MAX_REDIRECT_PIVOTS = 10
MAX_INSTITUTIONS_SHOWN = 20
DERIVED_NOTE = "head-office CNPJ derived from the BCB CNPJ root (order /0001)"


@dataclass(frozen=True)
class OlindaSet:
    """One Olinda entity set downloaded in full as a dataset (FC1)."""

    dataset: str
    entity_set: str
    min_rows: int
    min_bytes: int
    observed_rows: int
    observed_bytes: int

    @property
    def url(self) -> str:
        return f"{OLINDA}{self.entity_set}?$format=json"


#: observed 2026-11-26 05:23Z (datacenter egress); floors are about 60-80% of the observed sizes
DOMINIOS = OlindaSet("bcb_dominios_verificados.json", "DominiosVerificados", 1500, 400_000, 1873, 631_533)
SEDES: tuple[OlindaSet, ...] = (
    OlindaSet("bcb_sedes_bancos.json", "SedesBancoComMultCE", 120, 40_000, 153, 65_525),
    OlindaSet("bcb_sedes_sociedades.json", "SedesSociedades", 550, 200_000, 705, 300_300),
    OlindaSet("bcb_sedes_consorcios.json", "SedesConsorcios", 100, 30_000, 130, 49_067),
    OlindaSet("bcb_sedes_cooperativas.json", "SedesCooperativas", 600, 250_000, 735, 415_591),
)
#: segment of the Sedes sets that carry no SEGMENTO column (FC9 one-line answer)
SEDES_DEFAULT_SEGMENT = {"SedesConsorcios": "Administradora de Consorcio", "SedesCooperativas": "Cooperativa de Credito"}

# ======================================================================================
# OData parsing (FC1, FC3)
# ======================================================================================

_COMMENT_WRAPPED = re.compile(r"^\s*/\*(.*)\*/\s*$", re.S)
_HTML = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml\b)", re.I)


def _text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray, memoryview)):
        data = bytes(body)
        return data.decode("utf-8-sig", errors="replace")
    return body.lstrip("﻿") if isinstance(body, str) else str(body)


def odata_error(body: Any, status: int | None = None) -> str:
    """FC3: why an Olinda body is not a usable entity set ('' = usable).

    Olinda wraps errors in a JS comment ('/*{"codigo":500,"mensagem":"Erro desconhecido"}*/', HTTP 500
    on $filter, 400 on bad property names) with no JSON content-type, so the body decides; standard
    OData ``{"error": ...}``, HTML pages, non-JSON text and JSON without a 'value' list are errors too,
    also inside HTTP 200. Never an empty list."""
    st = f" (HTTP {status})" if status else ""
    if isinstance(body, (dict, list)):
        obj: Any = body
    else:
        text = _text(body).strip()
        if not text:
            return "empty body" + st
        m = _COMMENT_WRAPPED.match(text)
        if m:
            try:
                inner = json.loads(m.group(1))
            except (ValueError, RecursionError):
                inner = None
            if isinstance(inner, dict):
                return f"Olinda error {clean(inner.get('codigo')) or status or '?'}: {clean(inner.get('mensagem')) or 'no message'} (comment-wrapped body)"
            return "Olinda error (comment-wrapped body, unparsable)" + st
        if _HTML.match(text[:2048]):
            return "an HTML page came back instead of JSON" + st
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return "not JSON" + st
    if isinstance(obj, dict):
        err = obj.get("error")
        if err:
            if isinstance(err, dict):
                return f"OData error {clean(err.get('code')) or status or '?'}: {clean(err.get('message')) or 'no message'}"
            return f"OData error: {clean(err)}"
        if "codigo" in obj and "mensagem" in obj and "value" not in obj:
            return f"Olinda error {clean(obj.get('codigo'))}: {clean(obj.get('mensagem'))}"
        if not isinstance(obj.get("value"), list):
            return "OData body without a 'value' list" + st
        if status and status >= 400:
            return f"HTTP {status}"
        return ""
    return f"unexpected JSON type {type(obj).__name__}"


def parse_odata(body: Any) -> tuple[list[dict[str, Any]], str, str]:
    """(rows, entity set from @odata.context, error) of an Olinda body; error set = never usable."""
    why = odata_error(body)
    if why:
        return [], "", why
    obj = body if isinstance(body, dict) else json.loads(_text(body).strip())
    context = clean(obj.get("@odata.context"))
    return [r for r in obj["value"] if isinstance(r, dict)], (context.rsplit("#", 1)[1] if "#" in context else ""), ""


@dataclass
class ParsedSet:
    rows: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    entity_set: str = ""
    error: str = ""


def classify_domain_type(tipo: Any, has_domain: bool = True) -> str:
    """TIPO_DE_DOMINIO -> own | conglomerate_member | none | unknown. The source spells
    'Dominio de intregrante do conglomerado' (sic): folded keywords, never the exact text."""
    t = fold(tipo)
    if t.startswith("SEM DOMINIO") or not has_domain:
        return "none"
    if "CONGLOMERADO" in t:
        return "conglomerate_member"
    if "PROPRIO" in t:
        return "own"
    return "unknown"


_DOMINIOS_REQUIRED = ("CNPJ", "INSTITUICAO_FINANCEIRA", "DOMINIO", "TIPO_DE_DOMINIO")


def parse_dominios(body: Any) -> ParsedSet:
    """DominiosVerificados -> rows {cnpj_root, institution, domain (normalised host or None), domain_raw,
    domain_type, conglomerate_code (None for independents), conglomerate, independent, domain_owner,
    registrant_cnpj_root} plus stats (FC1, FC3, FC4)."""
    out = ParsedSet(entity_set=DOMINIOS.entity_set)
    raw, _es, out.error = parse_odata(body)
    if out.error:
        return out
    if raw and not any(all(k in r for k in _DOMINIOS_REQUIRED) for r in raw):
        out.error = f"schema drift: field(s) {', '.join(_DOMINIOS_REQUIRED)} missing"
        return out
    skipped = 0
    invalid: list[str] = []
    for r in raw:
        root = cnpj_root(r.get("CNPJ"))
        if not root:
            skipped += 1
            continue
        dom_raw = clean(r.get("DOMINIO"))
        dom = normalize_host(dom_raw) if dom_raw else None
        if dom and "." not in dom:
            dom = None
        if dom_raw and not dom:
            invalid.append(dom_raw[:80])
        code = clean(r.get("CODIGO_DO_CONGLOMERADO")) or None
        congl = clean(r.get("CONGLOMERADO"))
        independent = not code or fold(congl).startswith("INSTITUICAO INDEPENDENTE")
        out.rows.append({
            "cnpj_root": root,
            "institution": clean(r.get("INSTITUICAO_FINANCEIRA")),
            "domain": dom,
            "domain_raw": dom_raw or None,
            "domain_type": classify_domain_type(r.get("TIPO_DE_DOMINIO"), has_domain=bool(dom)),
            "conglomerate_code": code,
            "conglomerate": None if independent else (congl or None),
            "independent": independent,
            "domain_owner": clean(r.get("PROPRIETARIO_DO_DOMINIO")) or None,
            "registrant_cnpj_root": cnpj_root(r.get("CNPJ_NO_REGISTRO_DO_DOMINIO")) if clean(r.get("CNPJ_NO_REGISTRO_DO_DOMINIO")) else None,
        })
    roots = {r["cnpj_root"] for r in out.rows}
    with_domain = {r["cnpj_root"] for r in out.rows if r["domain"]}
    out.stats = {
        "rows": len(out.rows),
        "skipped_rows": skipped,
        "institutions": len(roots),
        "domain_rows": sum(1 for r in out.rows if r["domain"]),
        "unique_domains": len({r["domain"] for r in out.rows if r["domain"]}),
        "institutions_without_domain": len(roots - with_domain),
        "invalid_domains": invalid[:20],
    }
    return out


def sedes_segment(entity_set: str, row: Mapping[str, Any]) -> str:
    """Segment label (FC9): SEGMENTO when present, else the set's default (+ CLASSE for cooperatives)."""
    seg = clean(row.get("SEGMENTO"))
    if seg:
        return seg
    base = SEDES_DEFAULT_SEGMENT.get(entity_set, "Instituicao autorizada pelo BCB")
    classe = clean(row.get("CLASSE"))
    return f"{base} - {classe}" if classe and entity_set == "SedesCooperativas" else base


def parse_sedes(body: Any, entity_set: str = "") -> ParsedSet:
    """Sedes* -> rows {cnpj_root, name, segment, entity_set, uf, municipality, declared_hosts, central}.
    Contacts (E_MAIL, DDD/TELEFONE, addresses) are dropped; exact duplicate rows are collapsed."""
    out = ParsedSet(entity_set=entity_set)
    raw, es, out.error = parse_odata(body)
    if out.error:
        return out
    out.entity_set = es = entity_set or es
    if raw and not any("CNPJ" in r and "NOME_INSTITUICAO" in r for r in raw):
        out.error = "schema drift: CNPJ/NOME_INSTITUICAO missing"
        return out
    seen: set[str] = set()
    dup = skipped = 0
    for r in raw:
        root = cnpj_root(r.get("CNPJ"))
        if not root:
            skipped += 1
            continue
        item = {
            "cnpj_root": root,
            "name": clean(r.get("NOME_INSTITUICAO")),
            "segment": sedes_segment(es, r),
            "entity_set": es,
            "uf": clean(r.get("UF")) or None,
            "municipality": clean(r.get("MUNICIPIO")) or None,
            "declared_hosts": cvm.declared_hosts(r.get("SITIO_NA_INTERNET"))[:5],
            "central": clean(r.get("FILIACAO")) or None,
        }
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        out.rows.append(item)
    out.stats = {"rows": len(out.rows), "duplicates_collapsed": dup, "skipped_rows": skipped}
    return out


def _count(parse: Any) -> Any:
    def count(data: bytes) -> tuple[int, str]:
        parsed = parse(data)
        return len(parsed.rows), parsed.error

    return count


def _unique_domain_floor(data: bytes) -> str:
    unique = parse_dominios(data).stats.get("unique_domains", 0)
    return "" if unique >= MIN_UNIQUE_DOMAINS else f"{DOMINIOS.dataset}: {unique} unique verified domains is below the floor of {MIN_UNIQUE_DOMAINS}"


def _register(spec: OlindaSet, count: Any, extra: Any = None) -> None:
    register_dataset(
        spec.dataset, spec.url, ttl=86400,
        description=f"BCB Olinda Instituicoes_em_funcionamento {spec.entity_set} (full set, matched locally; refreshed daily by v3lum data update, never during a scan)",
        licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, source=SOURCE,
        validate=cvm.copy_validator(spec.dataset, count, min_rows=spec.min_rows, min_bytes=spec.min_bytes, extra=extra),
        min_bytes=spec.min_bytes, expect="json", max_bytes=DATASET_MAX_BYTES, large=True, essential=True,
    )


_register(DOMINIOS, _count(parse_dominios), _unique_domain_floor)
for _spec in SEDES:
    _register(_spec, _count(lambda data, es=_spec.entity_set: parse_sedes(data, es)))


# ======================================================================================
# indexes
# ======================================================================================


def build_domain_index(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """verified domain -> {domain, institutions (own first), registrant_cnpj_roots, owners,
    conglomerate_codes} (FC4)."""
    idx: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = r.get("domain")
        if not d:
            continue
        e = idx.setdefault(d, {"domain": d, "institutions": [], "registrant_cnpj_roots": set(), "owners": set(), "conglomerate_codes": set()})
        e["institutions"].append({k: r.get(k) for k in ("cnpj_root", "institution", "domain_type", "conglomerate_code", "conglomerate")})
        if r.get("registrant_cnpj_root"):
            e["registrant_cnpj_roots"].add(r["registrant_cnpj_root"])
        if r.get("domain_owner"):
            e["owners"].add(r["domain_owner"])
        if r.get("conglomerate_code"):
            e["conglomerate_codes"].add(r["conglomerate_code"])
    order = {"own": 0, "conglomerate_member": 1, "unknown": 2, "none": 3}
    for e in idx.values():
        e["institutions"].sort(key=lambda i: (order.get(i["domain_type"], 9), i["cnpj_root"]))
        for k in ("registrant_cnpj_roots", "owners", "conglomerate_codes"):
            e[k] = sorted(e[k])
    return idx


def build_institution_index(dominios: Iterable[Mapping[str, Any]], sedes: Iterable[Mapping[str, Any]] = ()) -> dict[str, dict[str, Any]]:
    """cnpj_root -> {cnpj_root, name, segments, sources, verified_domains, has_verified_domain,
    conglomerate_code, conglomerate, declared_hosts, uf} (FC7, FC9)."""
    inst: dict[str, dict[str, Any]] = {}

    def entry(root: str) -> dict[str, Any]:
        return inst.setdefault(root, {"cnpj_root": root, "name": None, "segments": [], "sources": [], "verified_domains": [],
                                      "conglomerate_code": None, "conglomerate": None, "declared_hosts": [], "uf": None})

    for r in dominios:
        e = entry(r["cnpj_root"])
        e["name"] = e["name"] or r.get("institution") or None
        if DOMINIOS.entity_set not in e["sources"]:
            e["sources"].append(DOMINIOS.entity_set)
        if r.get("domain") and r["domain"] not in e["verified_domains"]:
            e["verified_domains"].append(r["domain"])
        e["conglomerate_code"] = e["conglomerate_code"] or r.get("conglomerate_code")
        e["conglomerate"] = e["conglomerate"] or r.get("conglomerate")
    for s in sedes:
        e = entry(s["cnpj_root"])
        e["name"] = e["name"] or s.get("name") or None
        if s.get("segment") and s["segment"] not in e["segments"]:
            e["segments"].append(s["segment"])
        if s.get("entity_set") and s["entity_set"] not in e["sources"]:
            e["sources"].append(s["entity_set"])
        for h in s.get("declared_hosts") or ():
            if h not in e["declared_hosts"]:
                e["declared_hosts"].append(h)
        e["uf"] = e["uf"] or s.get("uf")
    for e in inst.values():
        e["verified_domains"].sort()
        e["has_verified_domain"] = bool(e["verified_domains"])
    return inst


@dataclass(frozen=True)
class BcbIndex:
    """The BCB registry built from the local copies (FC1): verified domains, institutions, exact-name
    keys and conglomerate membership, with the dataset metas used for dates and evidence."""

    domains: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    institutions: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    names: cvm.NameIndex = field(default_factory=cvm.NameIndex)
    conglomerates: Mapping[str, frozenset[str]] = field(default_factory=dict)
    datasets: tuple[dict[str, Any], ...] = ()
    missing: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    dominios: bool = False  # DominiosVerificados installed and parsed
    sedes: bool = False  # every Sedes* set installed and parsed

    def dataset(self, name: str) -> dict[str, Any]:
        return next((m for m in self.datasets if m.get("name") == name), {})

    @property
    def as_of(self) -> str:
        return str(self.dataset(DOMINIOS.dataset).get("date") or "")


def build_index(dominios: ParsedSet, sedes: Iterable[ParsedSet] = (), *, datasets: Iterable[dict[str, Any]] = (),
                missing: Iterable[str] = (), errors: Iterable[str] = (), sedes_complete: bool = False) -> BcbIndex:
    sedes_rows = [r for p in sedes for r in p.rows]
    institutions = build_institution_index(dominios.rows, sedes_rows)
    names = cvm.NameIndex()
    for root, e in institutions.items():
        names.add(e.get("name"), root)
    for r in dominios.rows:
        names.add(r.get("institution"), r["cnpj_root"])
    for s in sedes_rows:
        names.add(s.get("name"), s["cnpj_root"])
    congl: dict[str, set[str]] = {}
    for r in dominios.rows:
        if r.get("conglomerate_code"):
            congl.setdefault(r["conglomerate_code"], set()).add(r["cnpj_root"])
            if r.get("registrant_cnpj_root"):
                congl[r["conglomerate_code"]].add(r["registrant_cnpj_root"])
    return BcbIndex(build_domain_index(dominios.rows), institutions, names, {k: frozenset(v) for k, v in congl.items()},
                    tuple(datasets), tuple(missing), tuple(errors), not dominios.error and bool(dominios.rows), sedes_complete)


_LOCK = threading.Lock()
_PARSED: dict[str, tuple[str, ParsedSet]] = {}
_INDEXES: dict[tuple[tuple[str, str], ...], BcbIndex] = {}


def _parsed(data: Any, spec: OlindaSet, parse: Any) -> tuple[ParsedSet, dict[str, Any]]:
    path = cvm.local_path(data, spec.dataset)
    meta = cvm.dataset_meta(data, spec.dataset)
    sha = meta["sha256"]
    with _LOCK:
        hit = _PARSED.get(spec.dataset)
    if hit is not None and sha and hit[0] == sha:
        parsed = hit[1]
    else:
        try:
            parsed = parse(path.read_bytes())
        except OSError as exc:
            parsed = ParsedSet(entity_set=spec.entity_set, error=f"cannot read the local copy: {exc}")
        with _LOCK:
            _PARSED[spec.dataset] = (sha, parsed)
    meta["rows"] = len(parsed.rows)
    return parsed, meta


def load_bcb(data: Any, *, sedes: bool = True) -> BcbIndex:
    """The BCB registry from the local copies only (FC1: never downloads). ``data`` is ``ctx.data``
    (reads are cited in ``res.datasets``) or ``DataStore(None)``. ``dominios`` is False when
    DominiosVerificados is missing or no longer parses (never read as 'not verified')."""
    metas: list[dict[str, Any]] = []
    missing: list[str] = []
    errors: list[str] = []
    try:
        dom, meta = _parsed(data, DOMINIOS, parse_dominios)
        if dom.error:
            errors.append(f"{DOMINIOS.dataset}: the local copy does not parse ({dom.error}): run v3lum data update {DOMINIOS.dataset}")
            dom = ParsedSet(entity_set=DOMINIOS.entity_set, error=dom.error)
        else:
            metas.append(meta)
    except DatasetUnavailable:
        missing.append(DOMINIOS.dataset)
        dom = ParsedSet(entity_set=DOMINIOS.entity_set, error="missing")
    parsed_sedes: list[ParsedSet] = []
    for spec in SEDES if sedes else ():
        try:
            p, meta = _parsed(data, spec, lambda b, es=spec.entity_set: parse_sedes(b, es))
        except DatasetUnavailable:
            missing.append(spec.dataset)
            continue
        if p.error:
            errors.append(f"{spec.dataset}: the local copy does not parse ({p.error}): run v3lum data update {spec.dataset}")
            continue
        parsed_sedes.append(p)
        metas.append(meta)
    complete = sedes and len(parsed_sedes) == len(SEDES)
    signature = tuple((m["name"], m["sha256"]) for m in metas)
    with _LOCK:
        hit = _INDEXES.get(signature)
    if hit is not None and signature:
        return BcbIndex(hit.domains, hit.institutions, hit.names, hit.conglomerates, tuple(metas), tuple(missing), tuple(errors),
                        hit.dominios, complete)
    index = build_index(dom, parsed_sedes, datasets=metas, missing=missing, errors=errors, sedes_complete=complete)
    if signature:
        with _LOCK:
            _INDEXES.clear()  # one version at a time
            _INDEXES[signature] = index
    return index


def local_index(*, sedes: bool = True) -> BcbIndex:
    """The BCB registry from the local copies, for consumers outside a module run (correlation rules,
    typosquat, boleto_pix, apk_triage...): never downloads; check ``.dominios`` before using it."""
    return load_bcb(DataStore(None), sedes=sedes)


# ======================================================================================
# matching (FC4, FC6)
# ======================================================================================


def registrable_domain(host: str) -> str | None:
    """PSL registrable domain of a normalised host (bundled PSL, ICANN and private sections)."""
    try:
        return psl.registrable_domain(host)
    except Exception:  # noqa: BLE001 - a broken PSL file must not break matching: no match
        return None


def match_host(host: Any, domains: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """FC4: exact host or a subdomain of a verified domain, walking labels from the host up to its PSL
    registrable domain (never past it, never substrings or string suffixes). Matches come most
    specific first: {verified_domain, match exact|subdomain, host, registrable_domain, institutions,
    registrant_cnpj_roots, conglomerate_codes}."""
    h = normalize_host(host) if isinstance(host, str) else None
    if not h or not domains:
        return []
    reg = registrable_domain(h)
    if not reg:
        return []
    labels = h.split(".")
    stop = len(labels) - len(reg.split("."))
    out: list[dict[str, Any]] = []
    for i in range(stop + 1):
        cand = ".".join(labels[i:])
        e = domains.get(cand)
        if e:
            out.append({"verified_domain": cand, "match": "exact" if i == 0 else "subdomain", "host": h, "registrable_domain": reg,
                        "institutions": e["institutions"], "registrant_cnpj_roots": e["registrant_cnpj_roots"],
                        "conglomerate_codes": e["conglomerate_codes"]})
    return out


REDIRECT_PARAMS = frozenset({
    "url", "uri", "u", "r", "redirect", "redirect_uri", "redirect_url", "redirecturl", "redirect_to", "redirectto", "redir",
    "next", "next_url", "nexturl", "return", "returnurl", "return_url", "returnto", "return_to", "continue", "continueurl",
    "dest", "destination", "target", "goto", "go", "link", "out", "to", "forward", "fwd", "jump", "callback", "callback_url",
    "cb", "site", "location", "checkout_url", "success_url", "failure_url",
})
_ABS_URL = re.compile(r"(?i)(?:https?|ftp)\s*:\s*[\\/]+\s*([^\\/?#\s&\"'<>]+)")
_PROTO_REL = re.compile(r"^\s*(?:[\\/]{2,}|/\\|\\/)\s*([^\\/?#\s&\"'<>]+)")
_BARE_HOST = re.compile(r"(?i)^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?=$|[/:?#])")
#: 'next=home.html' / 'goto=login.do' are relative files, not hosts (bare-host form only)
_FILE_EXT = frozenset({
    "html", "htm", "shtml", "xhtml", "php", "asp", "aspx", "jsp", "jspx", "do", "action", "cgi", "pl", "py", "js", "css", "json",
    "xml", "txt", "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico", "csv", "zip",
})
_MAX_URL = 8192


def _authority_host(authority: str) -> str | None:
    a = authority.rsplit("@", 1)[-1]
    a = re.sub(r":\d*$", "", a)
    return normalize_host(a)


def _decodings(value: str) -> list[str]:
    seen: list[str] = []
    cur = value
    for _ in range(3):
        if cur in seen:
            break
        seen.append(cur)
        cur = unquote(cur)
    if cur not in seen:
        seen.append(cur)
    return seen


def _b64_url(value: str) -> str | None:
    v = value.strip()
    if len(v) < 12 or len(v) > 2048 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", v):
        return None
    try:
        decoded = base64.urlsafe_b64decode(v.replace("+", "-").replace("/", "_") + "=" * (-len(v) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if re.match(r"(?i)^\s*(https?:|//)", decoded) else None


def _bare_host(value: str) -> str | None:
    m = _BARE_HOST.match(value.strip())
    if not m:
        return None
    h = normalize_host(m.group(0))
    if not h:
        return None
    labels = h.split(".")
    if len(labels) == 2 and labels[-1] in _FILE_EXT:
        return None
    return h if psl.is_known_tld(labels[-1]) else None


def _targets_in_value(name: str, value: str, depth: int = 0) -> list[str]:
    hosts: list[str | None] = []
    for v in _decodings(value):
        hosts.extend(_authority_host(m.group(1)) for m in _ABS_URL.finditer(v))
        m = _PROTO_REL.match(v)
        if m:
            hosts.append(_authority_host(m.group(1)))
        if name.lower() in REDIRECT_PARAMS:
            hosts.append(_bare_host(v))
            decoded = _b64_url(v) if depth == 0 else None
            if decoded:
                hosts.extend(_targets_in_value("", decoded, depth + 1))
    return [h for h in hosts if h]


def redirect_targets(url: Any) -> list[str]:
    """FC6: hosts of redirect targets carried in the query or fragment: absolute URLs, scheme-relative
    '//host', backslash tricks, %-encoding up to three rounds, base64 and bare hosts in redirect-named
    parameters (a bare host needs an IANA TLD and no file extension: 'next=home.html' is not a host).
    The path is not inspected (FC6 names query and fragment)."""
    text = clean(url)[:_MAX_URL]
    try:
        parts = urlsplit(text)
    except ValueError:
        return []
    found: list[str] = []
    for kind, section in (("query", parts.query), ("fragment", parts.fragment)):
        if not section:
            continue
        q = section.split("?", 1)[1] if kind == "fragment" and "?" in section else section
        for name, value in parse_qsl(q, keep_blank_values=True)[:100]:
            found.extend(_targets_in_value(name, value))
        if kind == "fragment":
            found.extend(_targets_in_value("", section))
    out: list[str] = []
    for h in found:
        if h not in out:
            out.append(h)
    return out


def assess_url(url: Any, domains: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    """FC4 + FC6 for a URL: {url, host, matches, known_good, redirect_targets (external only),
    userinfo_domain, error}. A verified host whose query/fragment redirects to another host is not
    known_good; a verified domain used as userinfo ('https://bb.com.br@evil.example/') never matches
    and is reported as ``userinfo_domain``."""
    u = clean(url)[:_MAX_URL]
    out: dict[str, Any] = {"url": u, "host": None, "matches": [], "known_good": False, "redirect_targets": [], "userinfo_domain": None, "error": ""}
    try:
        parts = urlsplit(u if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", u) else "http://" + u)
        host = parts.hostname
        userinfo = parts.username
    except ValueError:
        out["error"] = "unparsable URL"
        return out
    h = normalize_host(host or "")
    out["host"] = h
    matches = match_host(h, domains) if h else []
    out["matches"] = matches
    own = {m["verified_domain"] for m in matches}
    external: list[str] = []
    for target in redirect_targets(u):
        if target == h:
            continue
        if own and own & {m["verified_domain"] for m in match_host(target, domains)}:
            continue  # same verified domain: an internal redirect
        external.append(target)
    out["redirect_targets"] = external if matches else []
    out["known_good"] = bool(matches) and not external
    ui = normalize_host(unquote(userinfo)) if userinfo else None
    if ui and not matches:
        ui_matches = match_host(ui, domains)
        if ui_matches:
            out["userinfo_domain"] = ui_matches[0]["verified_domain"]
    return out


# ======================================================================================
# answers (FC4, FC5, FC7, FC9)
# ======================================================================================


def institution_view(inst: Mapping[str, Any], *, domains: int = 10) -> dict[str, Any]:
    """Public fields of an institution entry (attributes and evidence)."""
    return {
        "cnpj_root": inst.get("cnpj_root"),
        "legal_name": inst.get("name"),
        "segments": list(inst.get("segments") or []) or [SEGMENT_NOT_INFORMED],
        "conglomerate": inst.get("conglomerate"),
        "verified_domains": list(inst.get("verified_domains") or [])[:domains],
        "has_verified_domain": bool(inst.get("has_verified_domain")),
    }


def reputation_adjustment(known_good: bool, verdicts: Iterable[Any]) -> dict[str, Any]:
    """FC5 helper for the scorer (P302/P171): known_good annotates, never suppresses.

    ``verdicts``: dicts {'source', 'verdict', 'level': 'domain'|'url', 'kind'} from other modules.
    Domain-level reputation signals (kind reputation/domain_reputation/age/popularity) get
    KNOWN_GOOD_DOMAIN_REPUTATION_FACTOR; malicious verdicts keep weight 1.0 and raise
    TITLE_COMPROMISE; URL-level hits stay untouched. Nothing is ever suppressed."""
    out: list[dict[str, Any]] = []
    flag = None
    for v in verdicts or ():
        if not isinstance(v, Mapping):
            continue
        verdict = clean(v.get("verdict")).lower()
        level = clean(v.get("level")).lower() or "domain"
        factor = 1.0
        if known_good and level == "domain":
            if verdict in MALICIOUS_VERDICTS:
                flag = TITLE_COMPROMISE
            elif clean(v.get("kind")).lower() in ("reputation", "domain_reputation", "age", "popularity"):
                factor = KNOWN_GOOD_DOMAIN_REPUTATION_FACTOR
        out.append(dict(v, weight_factor=factor, suppressed=False))
    return {"known_good": bool(known_good), "verdicts": out, "flag": flag}


def _active_root(root: str, bcb: BcbIndex, regs: Iterable[Mapping[str, Any]]) -> bool:
    return root in bcb.institutions or any(r.get("status") == "active" for r in regs)


def authorisation_answer(roots: list[str], bcb: BcbIndex, companies: cvm.CvmIndex, *, as_of: str, match: str = "cnpj_root") -> dict[str, Any]:
    """FC9: the one-line answer 'authorised by BCB/CVM: yes (<segments>)' or 'authorised by BCB/CVM:
    not found as of <date>' (+ inactive CVM registrations as context, + which side was not screened).
    Returns {line, authorised, segments, context, roots, match}."""
    parts: list[str] = []
    context: list[str] = []
    for root in roots:
        inst = bcb.institutions.get(root)
        if inst:
            parts.extend(inst.get("segments") or [SEGMENT_NOT_INFORMED])
        regs = companies.by_root.get(root, ())
        active = sorted({str(g.get("segment")) for g in regs if g.get("status") == "active"})
        if active:
            parts.append("CVM: " + ", ".join(active))
        for g in regs:
            if g.get("status") != "active":
                context.append(f"CVM {g.get('segment')} {g.get('status')} since {g.get('status_since') or '?'}")
    segments: list[str] = []
    for p in parts:
        if p not in segments:
            segments.append(p)
    unscreened = [label for label, present in (("BCB", bcb.dominios), ("CVM", companies.present)) if not present]
    note = f"; {' and '.join(unscreened)} not screened (dataset missing: run v3lum data update)" if unscreened else ""
    if segments:
        line = f"authorised by BCB/CVM: yes ({'; '.join(segments)})"
        if len(roots) > 1:
            line += f" [{len(roots)} institutions match the name]"
        return {"line": line + note, "authorised": True, "segments": segments, "context": sorted(set(context)), "roots": roots, "match": match}
    line = f"authorised by BCB/CVM: not found as of {as_of or 'the last update'}"
    ctx = sorted(set(context))
    if ctx:
        line += f" ({'; '.join(ctx[:3])})"
    return {"line": line + note, "authorised": False, "segments": [], "context": ctx, "roots": roots, "match": match}


# ======================================================================================
# protected-brand feed (FC8) for typosquat (P012) and the correlation packs (P028)
# ======================================================================================


def protected_brands(index: BcbIndex) -> list[dict[str, Any]]:
    """FC8 feed: one entry per registrable domain of the verified domains, with the CNPJ roots that make
    a lookalike registration defensive (institutions, domain registrants, conglomerate members).
    ``short_label`` flags labels of 3 characters or fewer ('bb', 'cf') that need stricter rules."""
    brands: dict[str, dict[str, Any]] = {}
    for dom, e in index.domains.items():
        reg = registrable_domain(dom)
        if not reg:
            continue
        suffix = reg.split(".", 1)[1] if "." in reg else ""
        b = brands.setdefault(reg, {"registrable_domain": reg, "verified_domains": [], "public_suffix": suffix, "brand_label": reg.split(".", 1)[0],
                                    "institution_cnpj_roots": set(), "registrant_cnpj_roots": set(), "conglomerate_codes": set(), "names": set()})
        b["verified_domains"].append(dom)
        for i in e["institutions"]:
            b["institution_cnpj_roots"].add(i["cnpj_root"])
            if i.get("institution"):
                b["names"].add(i["institution"])
        b["registrant_cnpj_roots"].update(e["registrant_cnpj_roots"])
        b["conglomerate_codes"].update(e["conglomerate_codes"])
    out: list[dict[str, Any]] = []
    for reg in sorted(brands):
        b = brands[reg]
        members: set[str] = set()
        for code in b["conglomerate_codes"]:
            members |= set(index.conglomerates.get(code, ()))
        own = b["institution_cnpj_roots"] | b["registrant_cnpj_roots"]
        out.append({
            "registrable_domain": reg,
            "verified_domains": sorted(b["verified_domains"]),
            "public_suffix": b["public_suffix"],
            "brand_label": b["brand_label"],
            "short_label": len(b["brand_label"].replace("-", "")) <= 3,
            "institution_cnpj_roots": sorted(b["institution_cnpj_roots"]),
            "registrant_cnpj_roots": sorted(b["registrant_cnpj_roots"]),
            "conglomerate_codes": sorted(b["conglomerate_codes"]),
            "conglomerate_member_roots": sorted(members - own),
            "names": sorted(b["names"]),
        })
    return out


def protected_brand_for(domain: Any, index: BcbIndex) -> dict[str, Any] | None:
    """The protected-brand entry of a verified domain or of its registrable domain (None when the
    domain is not BCB-verified)."""
    h = normalize_host(domain) if isinstance(domain, str) else None
    reg = registrable_domain(h) if h else None
    if not reg or not index.domains:
        return None
    return _brands_by_domain(index).get(reg)


_BRANDS: dict[tuple[tuple[str, str], ...], dict[str, dict[str, Any]]] = {}


def _brands_by_domain(index: BcbIndex) -> dict[str, dict[str, Any]]:
    signature = tuple((str(m.get("name")), str(m.get("sha256"))) for m in index.datasets)
    with _LOCK:
        hit = _BRANDS.get(signature) if signature else None
    if hit is not None:
        return hit
    brands = {b["registrable_domain"]: b for b in protected_brands(index)}
    if signature:
        with _LOCK:
            _BRANDS.clear()
            _BRANDS[signature] = brands
    return brands


def classify_lookalike(brand: Mapping[str, Any], *, registered: bool, resolves: bool = False, mx: bool = False, fresh_cert: bool = False,
                       live_page: bool = False, registrant_cnpj: Any = None, parked: bool = False) -> dict[str, Any] | None:
    """FC8: severity of a lookalike of a verified institution domain.

    SUPPRESSED when the registro.br registrant CNPJ root is the institution's, the verified domain's
    registrant or a member of the same conglomerate (defensive registration; conglomerate registrants
    may legitimately differ); HIGH only when registered and active (resolves, MX, fresh certificate or
    live page; a parked or sinkholed name does not count as resolving); a MEDIUM watch item when
    registered but inactive; None when not registered (nothing to watch)."""
    root = cnpj_root(registrant_cnpj) if registrant_cnpj not in (None, "") else None  # a CPF (11 digits) is never a root (rule 4)
    if root and root in set(brand.get("institution_cnpj_roots", ())) | set(brand.get("registrant_cnpj_roots", ())):
        return {"severity": "suppressed", "reason": f"defensive registration: the registrant CNPJ root {root} is the institution's", "signals": []}
    if root and root in set(brand.get("conglomerate_member_roots", ())):
        return {"severity": "suppressed", "reason": f"defensive registration: the registrant CNPJ root {root} belongs to the same conglomerate", "signals": []}
    if not registered:
        return None
    signals = [name for name, on in (("resolves", resolves and not parked), ("mx", mx), ("fresh_certificate", fresh_cert), ("live_page", live_page)) if on]
    target = brand.get("registrable_domain")
    if signals:
        return {"severity": "high", "reason": f"registered and active lookalike of {target} ({', '.join(signals)})", "signals": signals}
    return {"severity": "medium", "reason": f"registered lookalike of {target}, no activity seen: watch item", "signals": []}


def verified_domain_match(host: Any, index: BcbIndex | None = None) -> dict[str, Any] | None:
    """The most specific BCB verified-domain match of a host (consumers: boleto_pix, apk_triage,
    correlation packs), from the given index or the local copies; None when not verified or when the
    list is not installed."""
    idx = index if index is not None else local_index(sedes=False)
    matches = match_host(host, idx.domains) if idx.dominios else []
    return matches[0] if matches else None


# ======================================================================================
# the module
# ======================================================================================


def _age_text(hours: Any) -> str:
    try:
        h = float(hours)
    except (TypeError, ValueError):
        return "age unknown"
    return "<1 h" if h < 1 else f"{h:.0f} h" if h < 48 else f"{h / 24:.0f} d"


def _dataset_lines(metas: Iterable[Mapping[str, Any]]) -> list[str]:
    lines = []
    for m in metas:
        line = f"{m.get('name')}, fetched {m.get('date') or '?'} ({_age_text(m.get('age_hours'))})"
        if m.get("stale"):
            line += f" - stale: run v3lum data update {m.get('name')}"
        lines.append(line)
    return lines


def _citations(metas: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{k: m.get(k) for k in ("name", "sha256", "date", "rows", "stale")} for m in metas]


def _oldest_date(metas: Iterable[Mapping[str, Any]]) -> str:
    dates = sorted(str(m.get("date")) for m in metas if m.get("date"))
    return dates[0] if dates else ""


_NUMERIC_ID = re.compile(r"[\d.\-/\s]+")


@register
class BcbAuthorizedInstitutions(Module):
    name = "bcb_authorized_institutions"
    title = "BCB/CVM authorised institutions and verified domains"
    description = (
        "Offline check against the Banco Central do Brasil list of authorised institutions and their BCB-verified domains "
        "(Olinda DominiosVerificados and Sedes*) and the CVM cadastral registries: known-good annotation of verified bank, "
        "fintech and broker domains (never a suppression), open-redirect and userinfo tricks on them, and a one-line "
        "'authorised by BCB/CVM' answer for a CNPJ or company name."
    )
    category = "brazil_public_data"
    accepts = {T.DOMAIN, T.URL, T.CNPJ, T.ORG}
    produces = {T.CNPJ, T.DOMAIN}
    tags = {"offline", "free", "brazil"}
    reference = "https://olinda.bcb.gov.br/olinda/servico/Instituicoes_em_funcionamento/versao/v1/aplicacao"
    notice = (
        "Official BCB/CVM open data matched offline from local copies (v3lum data update): attribution Banco Central do Brasil "
        "(Olinda, dados abertos) and CVM (dados.cvm.gov.br, ODbL; share-alike only if a derived database is redistributed). "
        "A verified domain annotates (known_good), never suppresses other findings; absence from the list is never a fraud "
        "signal (most institutions have no verified domain)."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the investigated value never leaves the machine; only the dataset manager downloads
    hosts = ()
    sources = (SOURCE, SOURCE_CVM)
    run_on = "any"  # known_good also for pivots (URLs and hosts found during a scan)
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    max_pivots = 30
    default_enabled = True  # A3: default-on by decision (BCB authorised institutions and DominiosVerificados)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            try:
                parts = urlsplit(entity.value)
            except ValueError:
                return False
            return bool(parts.hostname)
        return bool(clean(entity.value))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        declared = getattr(ctx, "allowed_sources", None)
        allowed = frozenset(self.sources if declared is None else declared)
        if entity.type in (T.DOMAIN, T.URL):
            if SOURCE not in allowed:
                return res.mark(Status.SKIPPED, "the BCB verified-domain list is not allowed in this run (licence profile)", reason_code="licence")
            bcb = load_bcb(ctx.data)
            if not bcb.dominios:
                return self._unavailable(res, bcb.errors or (f"run v3lum data update {DOMINIOS.dataset}",))
            return self._domain_or_url(entity, res, bcb)
        bcb = load_bcb(ctx.data) if SOURCE in allowed else BcbIndex()
        companies = cvm.load_companies(ctx.data) if SOURCE_CVM in allowed else cvm.CvmIndex()
        if not bcb.dominios and not companies.present:
            return self._unavailable(res, tuple(bcb.errors) + tuple(companies.errors) or ("run v3lum data update bcb_authorized_institutions datasets",))
        return self._company(entity, res, bcb, companies, allowed)

    @staticmethod
    def _unavailable(res: ModuleResult, why: Iterable[str]) -> ModuleResult:
        detail = "; ".join(why)
        return res.mark(Status.UNAVAILABLE, f"not screened against BCB/CVM registries - {detail}", reason_code="dataset")

    # ---- domain / URL (FC4-FC7) -------------------------------------------------------------
    def _domain_or_url(self, entity: Entity, res: ModuleResult, bcb: BcbIndex) -> ModuleResult:
        if entity.type is T.URL:
            a = assess_url(entity.value, bcb.domains)
        else:
            matches = match_host(entity.value, bcb.domains)
            a = {"url": None, "host": normalize_host(entity.value), "matches": matches, "known_good": bool(matches), "redirect_targets": [],
                 "userinfo_domain": None, "error": ""}
        metas = list(bcb.datasets)
        as_of = bcb.as_of
        res.raw = {
            "input": {"type": entity.type.value, "host": a["host"]},
            "matches": [{"verified_domain": m["verified_domain"], "match": m["match"]} for m in a["matches"]],
            "redirect_targets": a["redirect_targets"],
            "userinfo_domain": a["userinfo_domain"],
            "datasets": _citations(metas),
            "attribution": REPORT_ATTRIBUTION,
        }
        if a["userinfo_domain"]:
            self._userinfo_finding(entity, res, a)
        if not a["matches"]:
            res.source_status(SOURCE, Status.EMPTY, reason=f"not a BCB-verified domain (DominiosVerificados as of {as_of or '?'})")
            if res.findings:
                res.attr("dataset_age", _dataset_lines(metas))
                return res
            return res.mark(Status.EMPTY)  # FC7: absence produces no finding and is never a fraud signal
        top = a["matches"][0]
        institutions = [self._institution_in_match(i, bcb) for i in top["institutions"][:MAX_INSTITUTIONS_SHOWN]]
        lead = institutions[0] if institutions else {}
        members = sorted({root for code in top["conglomerate_codes"] for root in bcb.conglomerates.get(code, ())})
        res.attr("bcb_verified_domain", {
            "domain": top["verified_domain"],
            "match": top["match"],
            "host": top["host"],
            "registrable_domain": top["registrable_domain"],
            "matched_domains": [m["verified_domain"] for m in a["matches"]],
            "institutions": institutions,
            "institutions_sharing_domain": len(top["institutions"]),
            "registrant_cnpj_roots": top["registrant_cnpj_roots"],
            "conglomerate_member_roots": members[:50],
            "as_of": as_of,
        })
        res.attr("dataset_age", _dataset_lines(metas))
        data = {
            "verified_domain": top["verified_domain"],
            "match": top["match"],
            "legal_name": lead.get("legal_name"),
            "cnpj_root": lead.get("cnpj_root"),
            "segment": (lead.get("segments") or [None])[0],
            "conglomerate": lead.get("conglomerate"),
            "conglomerate_code": lead.get("conglomerate_code"),
            "domain_type": lead.get("domain_type"),
            "institutions_sharing_domain": len(top["institutions"]),
            "datasets": _citations(metas),
            "attribution": REPORT_ATTRIBUTION,
        }
        if a["redirect_targets"]:
            self._redirect(entity, res, a, top, data)
        else:
            res.attr("legal_name", lead.get("legal_name"))
            res.attr("known_good", True)
            where = "is" if top["match"] == "exact" else "is a subdomain of"
            segment = data["segment"] if bcb.sedes or data["segment"] != SEGMENT_NOT_INFORMED else "segment unknown (Sedes* sets not installed)"
            res.finding(
                "Verified domain of a BCB-authorised institution",
                "info",
                f"{a['host']} {where} the BCB-verified domain {top['verified_domain']} of {lead.get('legal_name')} (CNPJ root "
                f"{lead.get('cnpj_root')}; {segment}; conglomerate {lead.get('conglomerate') or 'independent institution'}"
                + (f"; shared by {len(top['institutions'])} institutions" if len(top["institutions"]) > 1 else "")
                + f"). BCB DominiosVerificados as of {as_of or '?'}. Known-good annotates only: it never suppresses other sources' "
                "findings, and URL-level hits stay.",
                confidence="confirmed",
                criterion="exact host or label-wise subdomain (below the PSL registrable domain) of a domain in BCB Olinda DominiosVerificados",
                data=data,
                tags=["verified_fi", "known_good", "info"],
                source=SOURCE,
            )
        self._institution_pivots(res, top)
        res.source_status(SOURCE, Status.OK, reason=f"BCB DominiosVerificados as of {as_of or '?'}")
        return res

    @staticmethod
    def _institution_in_match(i: Mapping[str, Any], bcb: BcbIndex) -> dict[str, Any]:
        inst = bcb.institutions.get(i.get("cnpj_root") or "", {})
        return {
            "cnpj_root": i.get("cnpj_root"),
            "legal_name": i.get("institution") or inst.get("name"),
            "domain_type": i.get("domain_type"),
            "segments": list(inst.get("segments") or []) or [SEGMENT_NOT_INFORMED],
            "conglomerate": i.get("conglomerate"),
            "conglomerate_code": i.get("conglomerate_code"),
        }

    @staticmethod
    def _institution_pivots(res: ModuleResult, top: Mapping[str, Any]) -> None:
        roots: list[str] = []
        for i in top["institutions"]:
            if i.get("cnpj_root") and i["cnpj_root"] not in roots:
                roots.append(i["cnpj_root"])
        for root in top["registrant_cnpj_roots"]:
            if root not in roots:
                roots.append(root)
        for root in roots[:MAX_DOMAIN_CNPJ_PIVOTS]:
            value = head_office_cnpj(root)
            if value:
                res.pivot(T.CNPJ, value, "bcb_verified_domain_of", confidence="probable", expand=False,
                          note=f"{DERIVED_NOTE}: the institution the domain is verified for (analyst selection)")

    def _redirect(self, entity: Entity, res: ModuleResult, a: Mapping[str, Any], top: Mapping[str, Any], data: dict[str, Any]) -> None:
        """FC6: a redirect target on another host - not known_good, tagged, targets pivoted as IOCs."""
        targets = list(a["redirect_targets"])
        res.attr("known_good", False)
        res.attr("redirect_targets", targets[:MAX_REDIRECT_PIVOTS])
        res.finding(
            "Redirect via verified domain",
            "medium",
            f"The URL is on the BCB-verified domain {top['verified_domain']} but its query or fragment names a redirect target on "
            f"another host ({', '.join(targets[:5])}): the open-redirect pattern used to lend a bank or fintech domain to a phishing "
            "or malware link. Not known-good; review the target.",
            confidence="possible",
            criterion="URL on a BCB-verified institution domain whose query or fragment names a redirect target on another host (open-redirect pattern)",
            data={**data, "redirect_targets": targets[:MAX_REDIRECT_PIVOTS]},
            tags=["redirect_via_verified_domain"],
            source=SOURCE,
            attack=["T1566.002"],
        )
        for target in targets[:MAX_REDIRECT_PIVOTS]:
            res.pivot(T.DOMAIN, target, "redirect_target", confidence="probable", expand=True,
                      note="redirect target named in the query or fragment of a URL on a verified institution domain")

    @staticmethod
    def _userinfo_finding(entity: Entity, res: ModuleResult, a: Mapping[str, Any]) -> None:
        res.finding(
            "Verified institution domain in URL userinfo",
            "medium",
            f"The URL shows the BCB-verified domain {a['userinfo_domain']} before '@' (userinfo) while its real host is {a['host']}: "
            "a deceptive URL; the verified domain is never matched this way.",
            confidence="probable",
            criterion="URL userinfo equal to (or under) a BCB-verified institution domain while the host is not",
            data={"userinfo_domain": a["userinfo_domain"], "host": a["host"], "attribution": REPORT_ATTRIBUTION},
            tags=["verified_domain_in_userinfo"],
            source=SOURCE,
            attack=["T1566.002"],
        )

    # ---- CNPJ / company name (FC7, FC9) ----------------------------------------------------------
    def _company(self, entity: Entity, res: ModuleResult, bcb: BcbIndex, companies: cvm.CvmIndex, allowed: frozenset[str]) -> ModuleResult:
        if entity.type is T.CNPJ:
            roots, match = [entity.value[:8]], "cnpj_root"
        else:
            text = clean(entity.value)
            digits = re.sub(r"\D", "", text)
            if _NUMERIC_ID.fullmatch(text) and len(digits) == 11:
                return res.mark(Status.SKIPPED, "a CPF-shaped value is never a lookup key (rule 4): only company names and CNPJs are answered",
                                reason_code="not_applicable")
            if _NUMERIC_ID.fullmatch(text) and len(digits) in (8, 14) and cnpj_root(digits):
                roots, match = [cnpj_root(digits) or ""], "cnpj_root"
            else:
                roots, match = bcb.names.find(text, companies.names)
        metas = list(bcb.datasets) + list(companies.datasets)
        as_of = _oldest_date(metas)
        shown = roots[:MAX_NAME_HYPOTHESES]
        answer = authorisation_answer(shown, bcb, companies, as_of=as_of, match=match or "none")
        if len(roots) > MAX_NAME_HYPOTHESES:
            answer["line"] += f" (showing {MAX_NAME_HYPOTHESES} of {len(roots)} matches)"
        institutions = [institution_view(bcb.institutions[r]) for r in shown if r in bcb.institutions]
        registrations = [dict(g, cnpj_root=r) for r in shown for g in companies.by_root.get(r, ())][:20]
        res.raw = {
            "input": {"type": entity.type.value, "match": match or "none"},
            "roots": shown,
            "institutions": institutions,
            "cvm_registrations": registrations,
            "missing_datasets": list(bcb.missing) + list(companies.missing),
            "datasets": _citations(metas),
            "attribution": REPORT_ATTRIBUTION,
        }
        res.attr("bcb_cvm_authorisation", answer["line"])
        res.attr("bcb_institutions", institutions)
        res.attr("cvm_registrations", [{k: g.get(k) for k in ("registry", "segment", "category", "status", "status_since", "cnpj")} for g in registrations])
        res.attr("dataset_age", _dataset_lines(metas))
        if len(shown) == 1:
            res.attr("legal_name", (institutions[0]["legal_name"] if institutions else None)
                     or next((g.get("name") for g in registrations if g.get("name")), None))
        self._coverage(res, bcb, companies, allowed)
        if answer["authorised"]:
            self._authorised_finding(entity, res, answer, institutions, match, shown, metas)
        self._company_pivots(entity, res, bcb, companies, shown, match)
        return res

    @staticmethod
    def _coverage(res: ModuleResult, bcb: BcbIndex, companies: cvm.CvmIndex, allowed: frozenset[str]) -> None:
        if SOURCE in allowed:
            if bcb.dominios:
                res.source_status(SOURCE, Status.OK, reason=f"BCB Instituicoes_em_funcionamento as of {bcb.as_of or '?'}"
                                  + ("" if bcb.sedes else " (Sedes* segments incomplete)"))
            else:
                res.source_status(SOURCE, Status.UNAVAILABLE, reason_code="dataset",
                                  reason="; ".join(bcb.errors) or f"not screened: run v3lum data update {DOMINIOS.dataset}")
        else:
            res.source_status(SOURCE, Status.SKIPPED, reason_code="licence", reason="not allowed in this run (licence profile)")
        if SOURCE_CVM in allowed:
            if companies.present:
                note = f" ({len(companies.missing)} registry file(s) missing)" if companies.missing else ""
                res.source_status(SOURCE_CVM, Status.OK, reason=f"CVM cadastral registries as of {_oldest_date(companies.datasets) or '?'}{note}")
            else:
                why = "; ".join(companies.errors) or "not screened: run v3lum data update " + " ".join(companies.missing)
                res.source_status(SOURCE_CVM, Status.UNAVAILABLE, reason_code="dataset", reason=why)
        else:
            res.source_status(SOURCE_CVM, Status.SKIPPED, reason_code="licence", reason="not allowed in this run (licence profile)")

    @staticmethod
    def _authorised_finding(entity: Entity, res: ModuleResult, answer: Mapping[str, Any], institutions: list[dict[str, Any]], match: str,
                            roots: list[str], metas: list[dict[str, Any]]) -> None:
        no_domain = [i["cnpj_root"] for i in institutions if not i["has_verified_domain"]]
        if match == "cnpj_root":
            confidence = "confirmed"
        elif match == "exact_name" and len(roots) == 1:
            confidence = "probable"
        else:
            confidence = "possible"
        description = answer["line"] + "."
        if no_domain and len(institutions) == 1:
            description += f" {LINE_NO_DOMAIN[0].upper()}{LINE_NO_DOMAIN[1:]} (absence is not a fraud signal: most institutions have none)."
        if match not in ("cnpj_root",):
            description += f" Matched by {match.replace('_', ' ')}: same name is not the same company - confirm the CNPJ."
        res.finding(
            "Authorised by BCB/CVM",
            "info",
            description,
            confidence=confidence,
            criterion="CNPJ root listed by BCB Olinda Instituicoes_em_funcionamento or with an active ('EM FUNCIONAMENTO NORMAL') CVM cadastral registration",
            data={
                "line": answer["line"],
                "segments": answer["segments"],
                "roots": roots,
                "match": match,
                "no_verified_domain": LINE_NO_DOMAIN if no_domain else None,
                "inactive_cvm_registrations": answer["context"][:10],
                "datasets": _citations(metas),
                "attribution": REPORT_ATTRIBUTION,
            },
            tags=["verified_fi", "info"] if institutions else ["info"],
            source=SOURCE if institutions else SOURCE_CVM,
        )

    @staticmethod
    def _company_pivots(entity: Entity, res: ModuleResult, bcb: BcbIndex, companies: cvm.CvmIndex, roots: list[str], match: str) -> None:
        unique = len(roots) == 1
        if entity.type is T.ORG:
            for root in roots:
                regs = companies.by_root.get(root, ())
                if root in bcb.institutions:
                    value, note = head_office_cnpj(root), DERIVED_NOTE
                else:
                    cnpjs = [str(g.get("cnpj")) for g in regs if g.get("cnpj")]
                    value = next((c for c in cnpjs if c[11:15] == "0001"), cnpjs[0] if cnpjs else None)
                    note = "CNPJ of the CVM registration"
                if not value:
                    continue
                active = _active_root(root, bcb, regs)
                chain = unique and match == "exact_name" and active
                res.pivot(T.CNPJ, value, "registry_name_match", confidence="probable" if chain else "possible", expand=chain,
                          note=note + ("" if chain else ": name match only - analyst confirmation required (homonyms, trade names)"))
        expand_domains = unique and (entity.type is T.CNPJ or match == "exact_name")
        domains = 0
        for root in roots:
            inst = bcb.institutions.get(root)
            if not inst:
                continue
            for dom in inst.get("verified_domains") or ():
                if domains >= MAX_DOMAIN_PIVOTS:
                    break
                if res.pivot(T.DOMAIN, dom, "bcb_verified_domain", confidence="confirmed", expand=expand_domains,
                             note="" if expand_domains else "verified domain of one of several name matches: analyst selection") is not None:
                    domains += 1
        declared = 0
        for root in roots:
            inst = bcb.institutions.get(root) or {}
            verified = {d: {"institutions": [{"cnpj_root": root}], "registrant_cnpj_roots": [], "conglomerate_codes": []}
                        for d in inst.get("verified_domains") or ()}
            hosts = list(inst.get("declared_hosts") or [])
            for g in companies.by_root.get(root, ()):
                hosts.extend(g.get("declared_hosts") or [])
            for host in hosts:
                if declared >= MAX_DOMAIN_PIVOTS:
                    break
                if verified and match_host(host, verified):
                    continue  # already pivoted as a verified domain of the same institution
                if res.pivot(T.DOMAIN, host, "declared_website", confidence="possible", expand=False,
                             note="website the company declared to a regulator (BCB Sedes/CVM cadastre): self-declared, never verified or known-good") is not None:
                    declared += 1

