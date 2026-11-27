"""P235 ``cnae_tables`` - CNAE and Receita code tables (reference data, not a collector).

Council P235 final conditions, as implemented here:

1. Bundled reference data under ``v3lum/data/cnae_tables/`` (the batch's own data directory; the council
   text names ``v3lum/data/br/``): ``cnae.json`` (IBGE CNAE 2.3 tree + the RFB-only legacy codes still
   found in CNPJ records), ``natureza_juridica.json`` (the official RFB table), ``rfb_codes.json`` (porte,
   situacao cadastral, matriz/filial from the RFB layout) and ``sensitive_divisions.json``, each with
   source, version and retrieval date. The helpers below (``cnae_describe``, ``sector_tags``,
   ``cnae_attributes``, ``cnpj_card_labels``, ``natureza_label``, ``porte_label``, ``situacao_label``...)
   are the shared helper for ``cnpj_lookup`` and correlation rules. The module makes no network call
   (disclosure 'none').
2. The IBGE CNAE API is only the ``v3lum data update cnae`` refresher of the full tree (dataset ``cnae``,
   validated by :func:`validate_cnae_tree` before it replaces anything); never called per CNPJ. A valid
   local copy wins over the bundled tree; an invalid one is ignored.
3. :func:`cnpj_card_labels` renders human-readable CNAE, legal nature, size and situation labels from codes
   only (fallback providers) or keeps the provider labels when present.
4. The sensitive-division map covers business-risk sectors only (64-66 financial and insurance, payment
   and crypto subclasses, 80 private security, 92 gambling and betting); its tags are info context
   (``risk_signal False``, ``score_effect 0``) and never raise risk on their own.
5. LGPD floor: division 94 (unions 9420-1/00, religious 9491-0/00, political 9492-8/00 and the rest) never
   gets a tag, is never a risk signal and :func:`cnae_attributes` returns nothing for natural persons (QSA
   partners, MEI owners...) - no company activity is ever copied onto a person. The same floor applies to
   the legal natures that reveal those affiliations (``natureza_juridica.json`` ``lgpd_sensitive``).
6. Tests map sample subclasses to descriptions and divisions and assert that division-94 classes produce
   no risk tag and no partner attribute.

Module input: an analyst-typed keyword that is a CNAE code (``6422-1/00``, ``6422100``, ``cnae 9492800``),
a description search (``cnae: apostas``) or a legal-nature code (``natureza 2062``).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import unicodedata
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DataStore, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

DATASET = "cnae"  # FC2: `v3lum data update cnae`
SOURCE = "ibge.cnae"
IBGE_CNAE_SUBCLASSES_URL = "https://servicodados.ibge.gov.br/api/v2/cnae/subclasses"
CNAE_MIN_SUBCLASSES = 1300  # 1332 on 2026-11-26
CNAE_VERSION = "CNAE 2.3 (subclasses)"
CNAE_ATTRIBUTION = "CNAE: IBGE/CONCLA via servicodados.ibge.gov.br (open government data)"
BUNDLED_CNAE = "cnae_tables/cnae.json"
BUNDLED_NATUREZA = "cnae_tables/natureza_juridica.json"
BUNDLED_CODES = "cnae_tables/rfb_codes.json"
BUNDLED_SENSITIVE = "cnae_tables/sensitive_divisions.json"
MAX_MATCHES = 10
#: subject kinds that are natural persons: CNAE classes are never copied onto them (cond 5)
NATURAL_PERSON_KINDS = frozenset({"person", "natural_person", "qsa_partner", "partner", "mei_owner", "person_name", "cpf"})


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _s(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", _s(text))
    return "".join(c for c in t if not unicodedata.combining(c)).upper()


def normalize_cnae(code: Any) -> str | None:
    """'6422-1/00' | '6422100' | 6422100 | 111301 (an int that lost its leading zero) -> 7 digits."""
    if isinstance(code, int) and not isinstance(code, bool):
        code = f"{code:07d}" if 0 < code < 10**7 else ""
    d = re.sub(r"[\s./-]", "", _s(code))
    if re.fullmatch(r"\d{6}", d):
        d = "0" + d
    return d if re.fullmatch(r"\d{7}", d) and d != "0000000" else None


def format_cnae(code: Any) -> str | None:
    """NNNN-N/NN as shown on CNPJ cards."""
    c = normalize_cnae(code)
    return f"{c[:4]}-{c[4]}/{c[5:]}" if c else None


def _code(value: Any, width: int) -> str | None:
    d = re.sub(r"\D", "", _s(value))
    return d.zfill(width) if d and len(d) <= width else None


# --------------------------------------------------------------------------------------
# the IBGE refresher (cond 2)
# --------------------------------------------------------------------------------------


def validate_cnae_tree(obj: Any, min_subclasses: int = CNAE_MIN_SUBCLASSES) -> str | None:
    """Refresher validation before the previous copy is replaced -> problem or None."""
    if not isinstance(obj, list):
        return f"cnae refresh: expected a list of subclasses, got {type(obj).__name__}"
    good = 0
    for s in obj:
        sd = _d(s)
        dv = _d(_d(_d(sd.get("classe")).get("grupo")).get("divisao"))
        if normalize_cnae(sd.get("id")) and _s(sd.get("descricao")) and _s(dv.get("id")) and _s(_d(dv.get("secao")).get("id")):
            good += 1
    if good < min_subclasses:
        return f"cnae refresh: only {good} valid subclasses (< {min_subclasses}) - keeping the bundled table"
    return None


def build_cnae_table(subclasses: Any, retrieved: str, *, source_url: str = IBGE_CNAE_SUBCLASSES_URL) -> dict[str, Any]:
    """Full IBGE tree -> compact table with source, version and retrieval date (the bundled layout)."""
    t: dict[str, Any] = {"source": source_url, "version": CNAE_VERSION, "retrieved": retrieved, "attribution": CNAE_ATTRIBUTION,
                         "subclasses": {}, "classes": {}, "groups": {}, "divisions": {}, "sections": {}, "rfb_only": {}}
    for s in subclasses if isinstance(subclasses, list) else []:
        sd = _d(s)
        code = normalize_cnae(sd.get("id"))
        c = _d(sd.get("classe"))
        g = _d(c.get("grupo"))
        dv = _d(g.get("divisao"))
        sc = _d(dv.get("secao"))
        if not code or not _s(sd.get("descricao")):
            continue
        t["subclasses"][code] = {"label": _s(sd.get("descricao")), "class": _s(c.get("id")) or None, "group": _s(g.get("id")) or None,
                                 "division": _s(dv.get("id")) or code[:2], "section": _s(sc.get("id")) or None}
        for key, node in (("classes", c), ("groups", g), ("divisions", dv), ("sections", sc)):
            nid = _s(node.get("id"))
            if nid and _s(node.get("descricao")):
                t[key][nid] = _s(node.get("descricao"))
    t["counts"] = {k: len(t[k]) for k in ("subclasses", "classes", "groups", "divisions", "sections")}
    return t


def _validate_file(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return validate_cnae_tree(json.load(fh)) is None
    except (OSError, ValueError):
        return False


register_dataset(
    DATASET, IBGE_CNAE_SUBCLASSES_URL, ttl=30 * 86400,
    description="IBGE CNAE 2.3 subclasses tree (refresher of the bundled cnae_tables/cnae.json; never fetched per CNPJ, P235 cond 2)",
    licence="Brazilian open government data (IBGE, Decreto 8.777/2016)", terms_class="open", attribution=CNAE_ATTRIBUTION,
    provider="ibge", source=SOURCE, validate=_validate_file, min_bytes=1_000_000, expect="json", max_bytes=20_000_000, large=False,
)


# --------------------------------------------------------------------------------------
# tables (bundled, or a valid local refresh of the CNAE tree)
# --------------------------------------------------------------------------------------

_LOCK = threading.Lock()
_LOCAL_MEMO: dict[str, dict[str, Any]] = {}


class Tables:
    """The loaded reference tables (immutable view)."""

    def __init__(self, cnae: dict[str, Any], natureza: dict[str, Any], codes: dict[str, Any], sensitive: dict[str, Any]) -> None:
        self.cnae = cnae
        self.natureza = natureza
        self.codes = codes
        self.sensitive = sensitive

    @property
    def cnae_version(self) -> str:
        return f"{self.cnae.get('version')} retrieved {self.cnae.get('retrieved')}"

    def subclass(self, code: str) -> dict[str, Any] | None:
        sub = _d(self.cnae.get("subclasses")).get(code)
        if sub:
            return dict(sub, known="ibge")
        legacy = _d(self.cnae.get("rfb_only")).get(code)
        if legacy:
            return {"label": legacy.get("label"), "class": None, "group": None, "division": code[:2], "section": None, "known": "rfb_only"}
        return None


def _bundled() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (DataStore.bundled_json(BUNDLED_CNAE), DataStore.bundled_json(BUNDLED_NATUREZA), DataStore.bundled_json(BUNDLED_CODES),
            DataStore.bundled_json(BUNDLED_SENSITIVE))


def _local_tree(data: Any) -> dict[str, Any] | None:
    """A valid local refresh of the IBGE tree (dataset 'cnae'), never downloaded here."""
    if data is None:
        return None
    try:
        info = data.info(DATASET)
        if not getattr(info, "present", False):
            return None
        sha = str(getattr(info, "sha256", "") or "")
        with _LOCK:
            if sha and sha in _LOCAL_MEMO:
                return _LOCAL_MEMO[sha]
        store = getattr(data, "store", data)
        path = Path(store.path(DATASET))
        raw = path.read_bytes()
        tree = json.loads(raw.decode("utf-8"))
    except Exception:  # an unreadable local copy is ignored: the bundled table answers (cond 2)
        return None
    if validate_cnae_tree(tree):
        return None
    fetched = str(getattr(info, "fetched_at", "") or "")[:10] or "unknown date"
    table = build_cnae_table(tree, fetched)
    table["rfb_only"] = _d(DataStore.bundled_json(BUNDLED_CNAE).get("rfb_only"))
    with _LOCK:
        _LOCAL_MEMO[sha or hashlib.sha256(raw).hexdigest()] = table
    used = getattr(data, "used", None)
    if isinstance(used, list) and not any(isinstance(c, dict) and c.get("name") == DATASET for c in used):
        used.append({"name": DATASET, "sha256": sha, "fetched_at": getattr(info, "fetched_at", ""), "licence": getattr(info, "licence", "")})
    return table


def load_tables(data: Any = None) -> Tables:
    """The reference tables: the bundled files, with the CNAE tree replaced by a valid local refresh when
    ``data`` (``ctx.data``) holds one. Never touches the network."""
    cnae, natureza, codes, sensitive = _bundled()
    local = _local_tree(data)
    return Tables(local or cnae, natureza, codes, sensitive)


# --------------------------------------------------------------------------------------
# CNAE helpers (cond 3-6)
# --------------------------------------------------------------------------------------


def cnae_division(code: Any) -> str | None:
    c = normalize_cnae(code)
    return c[:2] if c else None


def is_lgpd_protected_cnae(code: Any, tables: Tables | None = None) -> bool:
    """cond 5: every subclass of division 94 (associations: unions, religious, political...)."""
    t = tables or load_tables()
    return cnae_division(code) in set(t.sensitive.get("lgpd_protected_divisions") or ["94"])


def sector_tags(code: Any, tables: Tables | None = None) -> list[dict[str, Any]]:
    """cond 4: info-context sector tags (never risk on their own); division 94 never gets one."""
    t = tables or load_tables()
    c = normalize_cnae(code)
    if not c or is_lgpd_protected_cnae(c, t):
        return []
    out = []
    for tag, spec in _d(t.sensitive.get("sectors")).items():
        if c[:2] in (spec.get("divisions") or []) or c in (spec.get("subclasses") or []):
            out.append({"tag": tag, "label": spec.get("label"), "kind": "info", "risk_signal": False, "score_effect": 0,
                        "map_version": t.sensitive.get("version")})
    return out


def cnae_describe(code: Any, tables: Tables | None = None) -> dict[str, Any] | None:
    """cond 3: human-readable CNAE (code -> labels of subclass, class, group, division and section)."""
    t = tables or load_tables()
    c = normalize_cnae(code)
    if not c:
        return None
    sub = t.subclass(c) or {}
    cnae = t.cnae
    return {
        "code": c, "code_formatted": format_cnae(c), "label": sub.get("label"),
        "class": sub.get("class"), "class_label": _d(cnae.get("classes")).get(sub.get("class") or ""),
        "group": sub.get("group"), "group_label": _d(cnae.get("groups")).get(sub.get("group") or ""),
        "division": c[:2], "division_label": _d(cnae.get("divisions")).get(c[:2]),
        "section": sub.get("section"), "section_label": _d(cnae.get("sections")).get(sub.get("section") or ""),
        "sector_tags": [x["tag"] for x in sector_tags(c, t)], "lgpd_protected": is_lgpd_protected_cnae(c, t),
        "known": sub.get("known") or False, "table_version": t.cnae_version,
    }


def cnae_attributes(code: Any, subject_kind: str = "company", tables: Tables | None = None) -> list[dict[str, Any]]:
    """cond 4/5: attributes an entity may carry for a CNAE code.

    company: the label + info sector tags (none for division 94, flagged ``lgpd_protected``).
    natural persons (QSA partners, MEI owners...): nothing - company activity is never copied onto a
    person, and a division-94 class (union, religious, political affiliation) least of all."""
    if subject_kind in NATURAL_PERSON_KINDS:
        return []
    t = tables or load_tables()
    d = cnae_describe(code, t)
    if not d:
        return []
    label = f"{d['code_formatted']} {d['label'] or '(label not in table)'}"
    attrs: list[dict[str, Any]] = [{"name": "cnae", "value": label, "kind": "info", "risk_signal": False, "lgpd_protected": d["lgpd_protected"]}]
    if not d["lgpd_protected"]:
        attrs += [{"name": "sector", "value": s["tag"], "label": s["label"], "kind": "info", "risk_signal": False, "score_effect": 0}
                  for s in sector_tags(code, t)]
    return attrs


def search_cnae(term: Any, tables: Tables | None = None, limit: int = MAX_MATCHES) -> tuple[list[dict[str, Any]], int]:
    """Analyst search over subclass descriptions (accent-insensitive, every word must match)."""
    t = tables or load_tables()
    words = [w for w in re.split(r"\s+", fold(term)) if len(w) >= 3]
    if not words:
        return [], 0
    hits = []
    for code, sub in sorted(_d(t.cnae.get("subclasses")).items()):
        label = fold(sub.get("label"))
        if all(w in label for w in words):
            hits.append({"code_formatted": format_cnae(code), "label": sub.get("label"), "division": code[:2]})
    return hits[:limit], len(hits)


# --------------------------------------------------------------------------------------
# Receita code tables (cond 1, 3)
# --------------------------------------------------------------------------------------


def natureza_label(code: Any, tables: Tables | None = None) -> str | None:
    """natureza juridica code (2038, '203-8') -> label from the official RFB table."""
    t = tables or load_tables()
    c = _code(code, 4)
    return _d(t.natureza.get("codes")).get(c or "")


def is_lgpd_sensitive_natureza(code: Any, tables: Tables | None = None) -> bool:
    """Legal natures revealing union, religious or political affiliation (cond 5 floor, applied to the
    legal nature as well): never a risk signal, never copied onto persons."""
    t = tables or load_tables()
    return (_code(code, 4) or "") in set(_d(t.natureza.get("lgpd_sensitive")).get("codes") or [])


def situacao_label(code: Any, tables: Tables | None = None) -> str | None:
    """situacao cadastral code (2, '02') or word ('ATIVA') -> label."""
    t = tables or load_tables()
    table = _d(t.codes.get("situacao_cadastral"))
    c = _code(code, 2)
    if c in table:
        return table[c]
    w = fold(code)
    return next((v for v in table.values() if fold(v) == w), None)


_PORTE_WORDS = {"ME": "01", "MICRO EMPRESA": "01", "MICROEMPRESA": "01", "EPP": "03", "EMPRESA DE PEQUENO PORTE": "03",
                "DEMAIS": "05", "NAO INFORMADO": "00"}


def porte_label(code: Any, tables: Tables | None = None) -> str | None:
    """porte code (5, '05') or word ('DEMAIS', 'ME', 'EPP') -> label."""
    t = tables or load_tables()
    table = _d(t.codes.get("porte"))
    c = _code(code, 2)
    if c in table:
        return table[c]
    return table.get(_PORTE_WORDS.get(fold(code).replace(".", "").strip(), ""))


def _first(record: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = record.get(k)
        if v not in (None, "", {}, []):
            return v
    return None


def cnpj_card_labels(record: Any, tables: Tables | None = None) -> dict[str, Any]:
    """cond 3: human-readable CNAE, legal nature, size and situation for a CNPJ card, also when a fallback
    provider returns codes only (provider labels win when present). Accepts raw provider records
    (BrasilAPI/Minha Receita field names) and the ``cnpj_lookup`` attribute shapes ({code, label})."""
    t = tables or load_tables()
    r = _d(record)
    out: dict[str, Any] = {"cnae": None, "natureza": None, "porte": None, "situacao": None, "sector_tags": [], "lgpd_sensitive": False}
    cnae = _first(r, "cnae_fiscal", "cnae", "cnae_principal", "codigo_cnae")
    cnae_label = r.get("cnae_fiscal_descricao")
    if isinstance(cnae, dict):
        cnae_label, cnae = cnae.get("label") or cnae_label, cnae.get("code")
    d = cnae_describe(cnae, t) if cnae is not None else None
    if d:
        out["cnae"] = f"{d['code_formatted']} {cnae_label or d['label'] or '(label not in table)'}"
        out["sector_tags"] = d["sector_tags"]
        out["lgpd_sensitive"] = d["lgpd_protected"]
    nat = _first(r, "codigo_natureza_juridica", "natureza_juridica_codigo", "natureza_juridica", "legal_nature")
    nat_label = None
    if isinstance(nat, dict):
        nat_label, nat = nat.get("label"), nat.get("code")
    nat_code = _code(nat, 4) if nat is not None and re.fullmatch(r"[\d\s.-]+", _s(nat)) else None
    if nat_code:
        out["natureza"] = f"{nat_code} {nat_label or natureza_label(nat_code, t) or '(code not in table)'}"
        out["lgpd_sensitive"] = out["lgpd_sensitive"] or is_lgpd_sensitive_natureza(nat_code, t)
    else:
        out["natureza"] = _s(nat_label or nat) or None
    porte = _first(r, "codigo_porte", "porte", "company_size")
    out["porte"] = porte_label(porte, t) or (_s(porte) or None)
    sit = _first(r, "situacao_cadastral", "codigo_situacao_cadastral", "descricao_situacao_cadastral", "situacao", "status")
    out["situacao"] = situacao_label(sit, t) or (_s(sit) or None)
    return out


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------

_CODE_RE = re.compile(r"^(?:cnae\s*:?\s*)?(\d{4}\s*-?\s*\d\s*/?\s*\d{2}|\d{6,7})$", re.I)
_SEARCH_RE = re.compile(r"^cnae\s*:\s*(.{3,})$", re.I)
_NATUREZA_RE = re.compile(r"^natureza(?:\s+jur[ií]dica)?\s*:?\s*(\d{3}-?\d)$", re.I)


def parse_query(value: Any) -> tuple[str, str] | None:
    """('cnae', code) | ('search', term) | ('natureza', code) | None for any other keyword."""
    v = re.sub(r"\s+", " ", _s(value))
    m = _CODE_RE.match(v)
    if m and normalize_cnae(m.group(1)):
        return "cnae", normalize_cnae(m.group(1)) or ""
    m = _NATUREZA_RE.match(v)
    if m:
        return "natureza", _code(m.group(1), 4) or ""
    m = _SEARCH_RE.match(v)
    if m:
        return "search", m.group(1).strip()
    return None


@register
class CnaeTables(Module):
    name = "cnae_tables"
    title = "CNAE and Receita code tables (offline)"
    description = (
        "Offline lookup of a CNAE subclass (description, class, division, section, info sector tags), a CNAE "
        "description search or a legal-nature code, from bundled IBGE/RFB tables refreshed by `v3lum data update cnae`."
    )
    category = "brazil_public_data"
    accepts = {T.KEYWORD}
    produces: set[Any] = set()
    tags = {"brazil", "offline", "free"}
    reference = "https://concla.ibge.gov.br/busca-online-cnae.html"
    notice = (
        "Reference data only (IBGE CNAE 2.3, RFB code tables): nothing is sent anywhere. Sector tags are info context "
        "and never a risk signal on their own; division 94 (unions, religious and political organisations) never gets a "
        "tag and is never attached to a person (LGPD art. 5 II and 11)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 0.05
    timeout = 10.0
    max_pivots = 0
    default_enabled = True  # A3: council P235 (offline open government data)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return parse_query(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        query = parse_query(entity.value)
        if query is None:
            return res.mark(Status.SKIPPED, "not a CNAE code, CNAE search or legal-nature code", reason_code="not_applicable")
        tables = load_tables(getattr(ctx, "data", None))
        kind, value = query
        if kind == "cnae":
            return self._cnae(res, value, tables)
        if kind == "natureza":
            label = natureza_label(value, tables)
            if not label:
                return res.mark(Status.EMPTY, f"legal-nature code {value} is not in the RFB table ({tables.natureza.get('version')})")
            res.attr("legal_nature", {"code": value, "label": label, "lgpd_sensitive": is_lgpd_sensitive_natureza(value, tables)})
            res.attr("data_attribution", tables.natureza.get("attribution"))
            return res
        matches, total = search_cnae(value, tables)
        if not matches:
            return res.mark(Status.EMPTY, f"no CNAE subclass description contains '{value}' ({tables.cnae_version})")
        res.attr("cnae_matches", matches)
        if total > len(matches):
            res.error = f"{total} subclasses match; the first {len(matches)} are listed"
        res.attr("data_attribution", tables.cnae.get("attribution"))
        return res

    @staticmethod
    def _cnae(res: ModuleResult, code: str, tables: Tables) -> ModuleResult:
        d = cnae_describe(code, tables)
        if not d or not d["known"]:
            return res.mark(Status.EMPTY, f"CNAE {format_cnae(code)} is not in the CNAE table ({tables.cnae_version})")
        res.attr("cnae_detail", d)
        tags = sector_tags(code, tables)
        if tags:
            res.attr("sector_tags", [{k: v for k, v in t.items() if k != "map_version"} for t in tags])
        res.attr("cnae_lgpd_protected", d["lgpd_protected"])
        res.attr("data_attribution", tables.cnae.get("attribution"))
        return res


__all__ = [
    "DATASET",
    "NATURAL_PERSON_KINDS",
    "CnaeTables",
    "Tables",
    "build_cnae_table",
    "cnae_attributes",
    "cnae_describe",
    "cnae_division",
    "cnpj_card_labels",
    "format_cnae",
    "is_lgpd_protected_cnae",
    "is_lgpd_sensitive_natureza",
    "load_tables",
    "natureza_label",
    "normalize_cnae",
    "parse_query",
    "porte_label",
    "search_cnae",
    "sector_tags",
    "situacao_label",
    "validate_cnae_tree",
]
