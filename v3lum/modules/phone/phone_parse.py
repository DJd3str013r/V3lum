"""Offline phone parsing (P126): libphonenumber facts plus the bundled Brazilian DDD -> UF table.

Disclosure ``none``: nothing leaves the machine and ``ctx.http`` refuses every request.

* **phone** entities (the core's canonical E.164; FC1: no second normalisation - every helper here only
  reads the core value): validity, line type, E.164/international/national formats, region, the
  geodescription (a bare state name for mobiles, 'City - UF' for landlines), time zones (libphonenumber's
  prefix-based list plus the zones of the DDD's state, with a caveat when their UTC offsets differ),
  the DDD -> UF(s)/main city from the bundled ``v3lum/data/phone_parse/br_ddd.json`` and the carrier,
  always labelled 'original carrier (portability not reflected)' (FC2). The current operator after
  portability is only available manually (ABR Telecom page with a CAPTCHA, emitted by ``pivots_phone``).
* **text_blob / file** inputs (FC4, the text/file extraction path): ``PhoneNumberMatcher`` with the
  ``default_region`` setting runs over candidate windows (runs of >= 8 digits; the whole-text matcher
  silently stops after 65,535 failed candidates) with a cap of 100 distinct numbers. Phones are
  PERSONAL_TYPES: they pivot with ``expand=False`` for analyst selection (AR07). Bare 11-digit strings
  that pass the CPF check digits are never turned into phones (team rule 4).
* The city list of a DDD comes from the ``brasilapi_ddd`` dataset (P127) only when that dataset is
  registered and already downloaded (it is never fetched here); otherwise the DDD facts say
  'city list unavailable (run v3lum data update brasilapi_ddd)'.

The python package ``phonenumbers`` (Apache-2.0) is an optional extra (core extra ``full``): without it
the module is UNAVAILABLE ``package``.

Maintainer data script (FC3): ``br_ddd.json`` is generated from Anatel's Cadastro Nacional de
Localidades (CNL, public download of the AreaArea system: one ``LoPubCNL`` file per UF) by
:func:`build_br_ddd_table`; run :func:`main` (see its docstring). Main city = the state capital when
it is a municipality of the DDD, otherwise the reviewed :data:`MAIN_CITY_OVERRIDES` entry, which must
be an Anatel tariff-area centre of that DDD. The table is registered in the notices registry
(``v3lum/data/notices/phone_parse_br_ddd.json``).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import sys
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from v3lum.core import datasets as _datasets
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.validators import cpf_valid

# ----------------------------------------------------------------------------------------------------------
# constants
# ----------------------------------------------------------------------------------------------------------

DDD_TABLE = "phone_parse/br_ddd.json"  # bundled data (v3lum/data/...)
BRASILAPI_DDD_DATASET = "brasilapi_ddd"  # P127 dataset, read only when registered and present
CITY_LIST_UNAVAILABLE = "city list unavailable (run v3lum data update brasilapi_ddd)"
ORIGINAL_CARRIER_LABEL = "original carrier (portability not reflected)"
TIME_ZONES_SOURCE = "libphonenumber (prefix-based, approximate)"
PERSONAL_NOTE = "personal identifier from text: analyst selection required"
MATCH_CAP = 100  # FC4: distinct phones kept per text/file
WINDOW_CAP = 5000  # candidate windows per text (bounds the matcher work on pathological input)
MAX_WINDOW_CHARS = 512  # longer digit runs are cut into overlapping chunks
WINDOW_OVERLAP = 64  # chunk overlap (>= 2 x the longest formatted phone)
MAX_READ = 20 * 1024 * 1024  # text files read for extraction (as ioc_extract)
TEXT_EXT = frozenset({".txt", ".log", ".csv", ".json", ".md", ".eml", ".msg", ".html", ".htm", ".xml", ".yaml", ".yml", ".ini", ".conf", ".ioc", ".tsv", ""})

E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")

UF_NAMES: dict[str, str] = {
    "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas", "BA": "Bahia", "CE": "Ceará",
    "DF": "Distrito Federal", "ES": "Espírito Santo", "GO": "Goiás", "MA": "Maranhão", "MT": "Mato Grosso",
    "MS": "Mato Grosso do Sul", "MG": "Minas Gerais", "PA": "Pará", "PB": "Paraíba", "PR": "Paraná",
    "PE": "Pernambuco", "PI": "Piauí", "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte",
    "RS": "Rio Grande do Sul", "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina", "SP": "São Paulo",
    "SE": "Sergipe", "TO": "Tocantins",
}

#: IANA zone.tab zones per UF (first = main zone). libphonenumber's BR zones are prefix-based and coarse
#: (9.0.44: DDD 81 -> America/Noronha UTC-2 for Recife UTC-3; DDD 91/93/94 -> America/Manaus UTC-4 for Pará).
UF_TIME_ZONES: dict[str, tuple[str, ...]] = {
    "AC": ("America/Rio_Branco",), "AL": ("America/Maceio",), "AP": ("America/Belem",),
    "AM": ("America/Manaus", "America/Eirunepe"), "BA": ("America/Bahia",), "CE": ("America/Fortaleza",),
    "DF": ("America/Sao_Paulo",), "ES": ("America/Sao_Paulo",), "GO": ("America/Sao_Paulo",),
    "MA": ("America/Fortaleza",), "MT": ("America/Cuiaba",), "MS": ("America/Campo_Grande",),
    "MG": ("America/Sao_Paulo",), "PA": ("America/Belem", "America/Santarem"), "PB": ("America/Fortaleza",),
    "PR": ("America/Sao_Paulo",), "PE": ("America/Recife", "America/Noronha"), "PI": ("America/Fortaleza",),
    "RJ": ("America/Sao_Paulo",), "RN": ("America/Fortaleza",), "RS": ("America/Sao_Paulo",),
    "RO": ("America/Porto_Velho",), "RR": ("America/Boa_Vista",), "SC": ("America/Sao_Paulo",),
    "SP": ("America/Sao_Paulo",), "SE": ("America/Maceio",), "TO": ("America/Araguaina",),
}
#: Fixed UTC offsets of the Brazilian zones (no DST since 2019).
BR_ZONE_UTC_OFFSET: dict[str, int] = {
    "America/Noronha": -2, "America/Belem": -3, "America/Fortaleza": -3, "America/Recife": -3,
    "America/Araguaina": -3, "America/Maceio": -3, "America/Bahia": -3, "America/Sao_Paulo": -3,
    "America/Santarem": -3, "America/Campo_Grande": -4, "America/Cuiaba": -4, "America/Porto_Velho": -4,
    "America/Boa_Vista": -4, "America/Manaus": -4, "America/Eirunepe": -5, "America/Rio_Branco": -5,
}

#: The 67 allocated DDDs (Anatel CNL 2026-11-26 = libphonenumber 9.0.44's BR area-code group).
BR_DDD_CODES: frozenset[str] = frozenset(
    [str(d) for d in range(11, 20)] + ["21", "22", "24", "27", "28"] + ["31", "32", "33", "34", "35", "37", "38"]
    + [str(d) for d in range(41, 50)] + ["51", "53", "54", "55"] + [str(d) for d in range(61, 70)]
    + ["71", "73", "74", "75", "77", "79"] + [str(d) for d in range(81, 90)] + [str(d) for d in range(91, 100)]
)

#: Non-geographic BR numbers (national-number prefix without the trunk '0'; libphonenumber type in brackets).
BR_NON_GEOGRAPHIC: tuple[tuple[str, str, str], ...] = (
    ("800", "toll_free", "0800: free for the caller [TOLL_FREE]"),
    ("303", "telemarketing", "0303: Anatel telemarketing code [SHARED_COST in libphonenumber]"),
    ("300", "shared_cost", "0300: non-geographic shared cost [SHARED_COST]"),
    ("500", "donation", "0500: donation/charity lines [PREMIUM_RATE in libphonenumber]"),
    ("900", "premium_rate", "0900: premium rate [PREMIUM_RATE]"),
)
#: 8-digit national single numbers 400x-xxxx (4004, 4003...), 4020, 4370, 4864 [SHARED_COST].
BR_SINGLE_NUMBER_RE = re.compile(r"^(?:400\d|4020|4370|4864)\d{4}$")

#: libphonenumber PhoneNumberType name -> line_type attribute value (core vocabulary 'mobile|fixed|...').
LINE_TYPES: dict[str, str] = {
    "FIXED_LINE": "fixed", "MOBILE": "mobile", "FIXED_LINE_OR_MOBILE": "fixed_or_mobile", "TOLL_FREE": "toll_free",
    "PREMIUM_RATE": "premium_rate", "SHARED_COST": "shared_cost", "VOIP": "voip", "PERSONAL_NUMBER": "personal_number",
    "PAGER": "pager", "UAN": "uan", "VOICEMAIL": "voicemail", "UNKNOWN": "unknown",
}
#: phonenumbers ValidationResult (is_possible_number_with_reason).
POSSIBLE_REASONS: dict[int, str] = {0: "is_possible", 1: "invalid_country_code", 2: "too_short", 3: "too_long", 4: "is_possible_local_only", 5: "invalid_length"}
#: phonenumbers NumberParseException.error_type.
PARSE_ERRORS: dict[int, str] = {0: "invalid_country_code", 1: "not_a_number", 2: "too_short_after_idd", 3: "too_short_nsn", 4: "too_long"}

# ---- maintainer data script (FC3) --------------------------------------------------------------------

#: State capitals: the main city of the DDD that contains them.
UF_CAPITALS: dict[str, str] = {
    "AC": "Rio Branco", "AL": "Maceió", "AP": "Macapá", "AM": "Manaus", "BA": "Salvador", "CE": "Fortaleza",
    "DF": "Brasília", "ES": "Vitória", "GO": "Goiânia", "MA": "São Luís", "MT": "Cuiabá", "MS": "Campo Grande",
    "MG": "Belo Horizonte", "PA": "Belém", "PB": "João Pessoa", "PR": "Curitiba", "PE": "Recife", "PI": "Teresina",
    "RJ": "Rio de Janeiro", "RN": "Natal", "RS": "Porto Alegre", "RO": "Porto Velho", "RR": "Boa Vista",
    "SC": "Florianópolis", "SP": "São Paulo", "SE": "Aracaju", "TO": "Palmas",
}
#: Reviewed main city of the 40 DDDs without a state capital: the most populous Anatel tariff-area centre
#: of the DDD (IBGE Censo 2022, table 4709, reviewed 2026-11-26). The generator refuses an entry that is
#: not an area centre of its DDD in the CNL files.
MAIN_CITY_OVERRIDES: dict[str, tuple[str, str]] = {
    "12": ("SP", "São José dos Campos"), "13": ("SP", "Santos"), "14": ("SP", "Bauru"), "15": ("SP", "Sorocaba"),
    "16": ("SP", "Ribeirão Preto"), "17": ("SP", "São José do Rio Preto"), "18": ("SP", "Presidente Prudente"),
    "19": ("SP", "Campinas"), "22": ("RJ", "Campos dos Goytacazes"), "24": ("RJ", "Petrópolis"),
    "28": ("ES", "Cachoeiro de Itapemirim"), "32": ("MG", "Juiz de Fora"), "33": ("MG", "Governador Valadares"),
    "34": ("MG", "Uberlândia"), "35": ("MG", "Poços de Caldas"), "37": ("MG", "Divinópolis"), "38": ("MG", "Montes Claros"),
    "42": ("PR", "Ponta Grossa"), "43": ("PR", "Londrina"), "44": ("PR", "Maringá"), "45": ("PR", "Cascavel"),
    "46": ("PR", "Francisco Beltrão"), "47": ("SC", "Joinville"), "49": ("SC", "Chapecó"), "53": ("RS", "Pelotas"),
    "54": ("RS", "Caxias do Sul"), "55": ("RS", "Santa Maria"), "64": ("GO", "Rio Verde"), "66": ("MT", "Rondonópolis"),
    "73": ("BA", "Itabuna"), "74": ("BA", "Juazeiro"), "75": ("BA", "Feira de Santana"), "77": ("BA", "Vitória da Conquista"),
    "87": ("PE", "Petrolina"), "88": ("CE", "Juazeiro do Norte"), "89": ("PI", "Picos"), "93": ("PA", "Santarém"),
    "94": ("PA", "Parauapebas"), "97": ("AM", "Tefé"), "99": ("MA", "Imperatriz"),
}
#: Land borders between UFs: a DDD lists a second UF only when it borders the DDD's main UF (border towns
#: such as Rio Negro/PR in DDD 47); a locality of a non-bordering UF is a CNL anomaly and is reported.
UF_NEIGHBOURS: dict[str, frozenset[str]] = {k: frozenset(v.split()) for k, v in {
    "AC": "AM RO", "AL": "BA PE SE", "AP": "PA", "AM": "AC MT PA RO RR", "BA": "AL ES GO MG PE PI SE TO",
    "CE": "PB PE PI RN", "DF": "GO MG", "ES": "BA MG RJ", "GO": "BA DF MG MS MT TO", "MA": "PA PI TO",
    "MT": "AM GO MS PA RO TO", "MS": "GO MG MT PR SP", "MG": "BA DF ES GO MS RJ SP", "PA": "AM AP MA MT RR TO",
    "PB": "CE PE RN", "PR": "MS SC SP", "PE": "AL BA CE PB PI", "PI": "BA CE MA PE TO", "RJ": "ES MG SP",
    "RN": "CE PB", "RS": "SC", "RO": "AC AM MT", "RR": "AM PA", "SC": "PR RS", "SP": "MG MS PR RJ", "SE": "AL BA",
    "TO": "BA GO MA MT PA PI",
}.items()}

#: Anatel CNL public download, layout LoPubCNL (field, width): one fixed-width ISO-8859-1 line per locality.
CNL_LAYOUT: tuple[tuple[str, int], ...] = (
    ("uf", 2), ("sigla_cnl", 4), ("codigo_cnl", 5), ("localidade", 50), ("municipio", 50), ("area_tarifacao", 5),
    ("atendido_stfc", 3), ("centro_area", 3), ("cn_mesa_informacao", 16), ("cn_mesa_iu", 16),
    ("latitude", 8), ("hemisferio", 5), ("longitude", 8),
)
CNL_SOURCE = "Anatel - Cadastro Nacional de Localidades (CNL), public download of the AreaArea system (LoPubCNL layout, one file per UF)"
CNL_SOURCE_URL = "https://sistemas.anatel.gov.br/areaarea/N_Download/Tela.asp?varMod=Publico&SISQSmodulo=7179"
CNL_LICENCE = "Brazilian open government data (Anatel public information, Lei 12.527/2011)"
DDD_TABLE_REQUIRED = ("name", "source", "source_url", "generated_at", "licence", "ddd")
MAX_CNL_MEMBER = 50 * 1024 * 1024


# ----------------------------------------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------------------------------------


def fold(value: Any) -> str:
    """Accent-fold + casefold + collapse spaces ('SÃO PAULO' == 'Sao Paulo')."""
    s = unicodedata.normalize("NFKD", value if isinstance(value, str) else str(value or ""))
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", s).strip().casefold()


UF_BY_FOLDED_NAME: dict[str, str] = {fold(name): uf for uf, name in UF_NAMES.items()}
UF_BY_FOLDED_NAME[fold("Federal District")] = "DF"


def is_e164(value: Any) -> bool:
    return isinstance(value, str) and bool(E164_RE.match(value))


def _str(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# ----------------------------------------------------------------------------------------------------------
# FC1/FC2: facts from libphonenumber
# ----------------------------------------------------------------------------------------------------------


def collect_phone_facts(value: str, region: str = "BR") -> dict[str, Any]:
    """The plain values libphonenumber gives for ``value`` (the core's E.164; ``region`` only matters for a
    national form). Raises ImportError without the optional 'phonenumbers' package."""
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    rec: dict[str, Any] = {"input": value}
    try:
        n = phonenumbers.parse(value, None if value.startswith("+") else region)
    except phonenumbers.NumberParseException as exc:
        rec["parse_error"] = {"error_type": int(exc.error_type), "msg": str(exc)[:200]}
        return rec
    type_names = {v: k for k, v in vars(phonenumbers.PhoneNumberType).items() if k.isupper()}
    fmt = phonenumbers.PhoneNumberFormat
    rec.update({
        "valid": phonenumbers.is_valid_number(n),
        "possible": phonenumbers.is_possible_number(n),
        "possible_reason": int(phonenumbers.is_possible_number_with_reason(n)),
        "region": phonenumbers.region_code_for_number(n),
        "type": type_names.get(phonenumbers.number_type(n), "UNKNOWN"),
        "e164": phonenumbers.format_number(n, fmt.E164),
        "international": phonenumbers.format_number(n, fmt.INTERNATIONAL),
        "national": phonenumbers.format_number(n, fmt.NATIONAL),
        "geo_pt": geocoder.description_for_number(n, "pt"),
        # never carrier.safe_display_name: it is always '' for a portable region such as BR
        "carrier_pt": carrier.name_for_number(n, "pt"),
        "timezones": list(timezone.time_zones_for_number(n)),
    })
    return rec


def br_number_facts(e164: Any) -> dict[str, Any]:
    """Read-only BR facts from the core's canonical E.164 (+55...): DDD, a digit-based line hint and the
    non-geographic class. Hint: 9 digits starting with 9 = mobile; 8 digits starting 2-5 = landline; 8-digit
    7xxx = legacy SME/trunking; 8-digit 6/8/9xxx = pre-2016 mobile missing the ninth digit (invalid today).
    """
    if not is_e164(e164):
        return {"ok": False, "reason": "not an E.164 string (normalise with the core first)"}
    if not e164.startswith("+55"):
        return {"ok": False, "reason": "not a Brazilian number"}
    nsn = e164[3:]
    facts: dict[str, Any] = {"ok": True, "ddd": None, "ddd_allocated": None, "subscriber_digits": None,
                             "line_hint": "unknown", "non_geographic": None}
    for prefix, cls, label in BR_NON_GEOGRAPHIC:
        if nsn.startswith(prefix) and len(nsn) in (9, 10, 11):
            facts.update(line_hint="non_geographic", non_geographic={"prefix": "0" + prefix, "class": cls, "label": label})
            return facts
    if BR_SINGLE_NUMBER_RE.match(nsn):
        label = f"{nsn[:4]}: national single number (same number in every DDD) [SHARED_COST]"
        facts.update(line_hint="non_geographic", non_geographic={"prefix": nsn[:4], "class": "national_single_number", "label": label})
        return facts
    if len(nsn) not in (10, 11):
        facts["line_hint"] = "invalid_length"
        return facts
    ddd, sub = nsn[:2], nsn[2:]
    facts.update(ddd=ddd, ddd_allocated=ddd in BR_DDD_CODES, subscriber_digits=len(sub))
    if len(sub) == 9 and sub[0] == "9":
        hint = "mobile"
    elif len(sub) == 8 and sub[0] in "2345":
        hint = "landline"
    elif len(sub) == 8 and sub[0] == "7":
        hint = "mobile_sme_8digit"
    elif len(sub) == 8 and sub[0] in "689":
        hint = "pre2016_mobile_missing_ninth_digit"
    else:
        hint = "unknown"
    facts["line_hint"] = hint
    return facts


def split_geodescription(text: Any) -> dict[str, Any] | None:
    """libphonenumber's geocoder text -> {text, level, country, city, uf, state}. 9.0.44 (pt): landlines with
    prefix data give 'City - UF'; mobiles and unknown prefixes give the STATE name only (a bare 'São Paulo'
    is the state); non-geographic numbers give 'Brasil'; foreign numbers a locality ('San Francisco, CA')."""
    t = re.sub(r"\s+", " ", text).strip() if isinstance(text, str) else ""
    if not t:
        return None
    if fold(t) in ("brasil", "brazil"):
        return {"text": t, "level": "country", "country": "BR", "city": None, "uf": None, "state": None}
    m = re.match(r"^(.*\S)\s+-\s+([A-Z]{2})$", t)
    if m and m.group(2) in UF_NAMES:
        return {"text": t, "level": "city", "country": "BR", "city": m.group(1), "uf": m.group(2), "state": UF_NAMES[m.group(2)]}
    uf = UF_BY_FOLDED_NAME.get(fold(t))
    if uf:
        return {"text": t, "level": "state", "country": "BR", "city": None, "uf": uf, "state": UF_NAMES[uf]}
    return {"text": t, "level": "locality", "country": None, "city": None, "uf": None, "state": None}


def uf_time_zones(uf: Any) -> list[str]:
    """IANA zone(s) of a UF (zone.tab): the cross-check of libphonenumber's prefix-based BR zones."""
    return list(UF_TIME_ZONES.get(uf, ())) if isinstance(uf, str) else []


def time_zone_caveat(lib_zones: Iterable[str], uf: Any) -> str | None:
    """A caveat when no libphonenumber zone has the UTC offset of the UF's main zone; None otherwise."""
    zones = uf_time_zones(uf)
    lib = [z for z in lib_zones or () if isinstance(z, str)]
    if not zones or not lib:
        return None
    main_off = BR_ZONE_UTC_OFFSET.get(zones[0])
    if main_off is None or main_off in {BR_ZONE_UTC_OFFSET.get(z) for z in lib}:
        return None

    def _fmt(off: int | None) -> str:
        return "UTC" + (f"{off:+d}" if off is not None else "?")

    lib_txt = ", ".join(f"{z} ({_fmt(BR_ZONE_UTC_OFFSET.get(z))})" for z in lib)
    return f"libphonenumber zone {lib_txt} has another offset than {zones[0]} ({_fmt(main_off)}), the main zone of {uf}: prefer the state zone"


def parse_brasilapi_ddd(payload: Any) -> dict[str, Any]:
    """One brasilapi_ddd record (P127: BrasilAPI /api/ddd/v1/{ddd} answer) -> {ok, state, cities, reason}.
    {'state': 'SP', 'cities': [...]} -> ok; {'name': 'DDD_NOT_FOUND', ...} -> not_found; anything else is
    ok False with a reason (never an empty success). Cities are de-duplicated and sorted by folded name."""
    data = payload
    if isinstance(payload, (bytes, bytearray)):
        payload = bytes(payload).decode("utf-8", errors="replace")
    if isinstance(payload, str):
        head = payload[:2048].lstrip().lower()
        if head.startswith(("<!doctype html", "<html")) or "<body" in head:
            return {"ok": False, "reason": "HTML page instead of JSON", "state": None, "cities": []}
        try:
            data = json.loads(payload)
        except ValueError:
            return {"ok": False, "reason": "malformed JSON", "state": None, "cities": []}
    if not isinstance(data, dict):
        return {"ok": False, "reason": "unexpected JSON shape", "state": None, "cities": []}
    if data.get("name") == "DDD_NOT_FOUND" or data.get("type") == "ddd_error":
        return {"ok": False, "reason": "not_found", "state": None, "cities": []}
    state, cities = data.get("state"), data.get("cities")
    if state not in UF_NAMES or not isinstance(cities, list):
        return {"ok": False, "reason": "missing state/cities", "state": None, "cities": []}
    seen: set[str] = set()
    clean: list[str] = []
    for c in cities:
        if isinstance(c, str) and c.strip() and fold(c) not in seen:
            seen.add(fold(c))
            clean.append(re.sub(r"\s+", " ", c.strip()))
    clean.sort(key=fold)
    return {"ok": True, "reason": None, "state": state, "cities": clean}


def parse_ddd_dataset(data: Any) -> dict[str, dict[str, Any]]:
    """The brasilapi_ddd dataset (P127): {"<ddd>": {"state", "cities"}} or a list of {"ddd", "state",
    "cities"} -> {ddd: parse_brasilapi_ddd(record)} (only well-formed records; anything else -> {})."""
    items: Iterable[tuple[Any, Any]]
    if isinstance(data, Mapping):
        items = data.items()
    elif isinstance(data, list):
        items = ((r.get("ddd"), r) for r in data if isinstance(r, Mapping))
    else:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for code, record in items:
        code = str(code or "").strip()
        if code in BR_DDD_CODES:
            parsed = parse_brasilapi_ddd(record)
            if parsed["ok"]:
                out[code] = parsed
    return out


def ddd_info(ddd: Any, ddd_table: Any = None, dataset_record: Any = None) -> dict[str, Any]:
    """DDD -> UF(s), main city (bundled table) and the full city list only from a brasilapi_ddd record."""
    code = str(ddd or "").strip()
    info: dict[str, Any] = {"code": code, "allocated": code in BR_DDD_CODES, "uf": None, "ufs": [], "main_city": None,
                            "cities": None, "cities_source": None, "coverage": None, "table": None}
    entries = ddd_table.get("ddd") if isinstance(ddd_table, Mapping) else None
    entry = entries.get(code) if isinstance(entries, Mapping) else None
    if isinstance(entry, Mapping):
        uf = entry.get("uf") if entry.get("uf") in UF_NAMES else None
        ufs = [u for u in entry.get("ufs") or [] if u in UF_NAMES] if isinstance(entry.get("ufs"), list) else []
        info.update(uf=uf, ufs=ufs or ([uf] if uf else []), main_city=_str(entry.get("main_city")),
                    table={"source": "Anatel CNL (bundled br_ddd.json)", "generated_at": ddd_table.get("generated_at")})
    if isinstance(dataset_record, Mapping) and dataset_record.get("ok") and dataset_record.get("cities"):
        info.update(cities=list(dataset_record["cities"]), cities_source=BRASILAPI_DDD_DATASET)
        if not info["uf"] and dataset_record.get("state") in UF_NAMES:
            info["uf"] = dataset_record["state"]
            info["ufs"] = [info["uf"]]
    elif info["allocated"]:
        info["coverage"] = CITY_LIST_UNAVAILABLE
    return info


def normalise_phone_facts(raw: Any, ddd_table: Any = None, ddd_dataset: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """FC1-FC3: the plain libphonenumber values (:func:`collect_phone_facts`) -> V3LUM facts.

    Output keys: ok, reason, e164, valid, possible, possible_reason, invalid_reason, region, line_type,
    formats{e164,international,national}, geodescription, br, ddd, time_zones, time_zones_source,
    uf_time_zones, time_zone_caveat, carrier{name,label}|None. The carrier is ONLY the original
    allocation and always carries ORIGINAL_CARRIER_LABEL (FC2).
    """
    out: dict[str, Any] = {"ok": False, "reason": None, "e164": None, "valid": False, "possible": False,
                           "possible_reason": None, "invalid_reason": None, "region": None, "line_type": "unknown",
                           "formats": {}, "geodescription": None, "br": None, "ddd": None, "time_zones": [],
                           "time_zones_source": TIME_ZONES_SOURCE, "uf_time_zones": [], "time_zone_caveat": None,
                           "carrier": None}
    if not isinstance(raw, Mapping):
        out["reason"] = "facts must be an object"
        return out
    perr = raw.get("parse_error")
    if perr:
        code = _int(perr.get("error_type")) if isinstance(perr, Mapping) else None
        out["reason"] = f"could not parse as a phone number ({PARSE_ERRORS.get(code, 'parse_error') if code is not None else 'parse_error'})"
        return out
    e164 = raw.get("e164")
    if not is_e164(e164):
        out["reason"] = "no E.164 value in the facts"
        return out
    out.update(ok=True, e164=e164, valid=_bool(raw.get("valid")) is True, possible=_bool(raw.get("possible")) is True,
               region=_str(raw.get("region")))
    pr = _int(raw.get("possible_reason"))
    out["possible_reason"] = POSSIBLE_REASONS.get(pr) if pr is not None else None
    out["line_type"] = LINE_TYPES.get(_str(raw.get("type")) or "UNKNOWN", "unknown")
    out["formats"] = {"e164": e164, "international": _str(raw.get("international")), "national": _str(raw.get("national"))}
    out["geodescription"] = split_geodescription(raw.get("geo_pt"))
    tzs = raw.get("timezones")
    out["time_zones"] = [z for z in tzs if isinstance(z, str) and z and z != "Etc/Unknown"] if isinstance(tzs, (list, tuple)) else []
    name = _str(raw.get("carrier_pt"))
    if name:
        out["carrier"] = {"name": name, "label": ORIGINAL_CARRIER_LABEL}
    if e164.startswith("+55"):
        br = br_number_facts(e164)
        out["br"] = br
        if br.get("ddd"):
            out["ddd"] = ddd_info(br["ddd"], ddd_table, (ddd_dataset or {}).get(br["ddd"]))
            uf = out["ddd"].get("uf")
            if uf:
                out["uf_time_zones"] = uf_time_zones(uf)
                out["time_zone_caveat"] = time_zone_caveat(out["time_zones"], uf)
        if not out["valid"]:
            out["invalid_reason"] = _br_invalid_reason(br, out["possible_reason"])
    elif not out["valid"]:
        out["invalid_reason"] = out["possible_reason"] if out["possible_reason"] not in (None, "is_possible") else "not valid for its region"
    return out


def _br_invalid_reason(br: Mapping[str, Any], possible_reason: str | None) -> str:
    if possible_reason in ("too_short", "too_long", "invalid_length"):
        return str(possible_reason)
    if br.get("ddd") and br.get("ddd_allocated") is False:
        return f"unallocated DDD {br['ddd']}"
    if br.get("line_hint") == "pre2016_mobile_missing_ninth_digit":
        return "8-digit mobile without the ninth digit (pre-2016 format)"
    if br.get("line_hint") == "invalid_length":
        return "invalid length"
    return "not a valid Brazilian number"


def validate_br_ddd_table(obj: Any, *, require_anatel: bool = True) -> list[str]:
    """Problems of a br_ddd.json candidate ([] = OK): header fields with an Anatel source and an ISO date,
    the 67 allocated two-digit DDDs, a valid uf, a non-empty main_city and a ufs list containing uf."""
    if not isinstance(obj, Mapping):
        return ["table is not a JSON object"]
    problems = [f"missing {key}" for key in DDD_TABLE_REQUIRED if obj.get(key) in (None, "")]
    if isinstance(obj.get("generated_at"), str) and not re.match(r"^\d{4}-\d{2}-\d{2}", obj["generated_at"]):
        problems.append("generated_at is not an ISO date")
    if require_anatel:
        src, url = str(obj.get("source") or ""), str(obj.get("source_url") or "")
        host = re.sub(r"^https://([^/?#:]+).*$", r"\1", url).lower() if url.startswith("https://") else ""
        if "anatel" not in fold(src) or "draft" in fold(src):
            problems.append("source is not Anatel's numbering data (draft table: regenerate before bundling)")
        if not (host == "anatel.gov.br" or host.endswith(".anatel.gov.br") or (host == "www.gov.br" and "/anatel/" in url)):
            problems.append("source_url is not an Anatel https URL")
    entries = obj.get("ddd")
    if not isinstance(entries, Mapping):
        return problems + ["ddd is not an object"]
    for code, entry in entries.items():
        if not re.fullmatch(r"[1-9][1-9]", str(code)):
            problems.append(f"bad DDD key {code!r}")
            continue
        if code not in BR_DDD_CODES:
            problems.append(f"DDD {code} is not allocated")
        if not isinstance(entry, Mapping):
            problems.append(f"DDD {code}: entry is not an object")
            continue
        if entry.get("uf") not in UF_NAMES:
            problems.append(f"DDD {code}: bad uf {entry.get('uf')!r}")
        if not _str(entry.get("main_city")):
            problems.append(f"DDD {code}: empty main_city")
        ufs = entry.get("ufs")
        if ufs is not None and (not isinstance(ufs, list) or entry.get("uf") not in ufs or any(u not in UF_NAMES for u in ufs)):
            problems.append(f"DDD {code}: ufs must list valid UFs including uf")
    missing = sorted(BR_DDD_CODES - {str(k) for k in entries})
    if missing:
        problems.append(f"missing DDDs: {', '.join(missing)}")
    return problems


# ----------------------------------------------------------------------------------------------------------
# FC4: extraction from text/file (PhoneNumberMatcher over candidate windows, match cap)
# ----------------------------------------------------------------------------------------------------------

# Separators and digits are disjoint classes, so the repetition cannot backtrack catastrophically.
_CANDIDATE_RE = re.compile(r"\d(?:[ \t ().\-/]{0,3}\d){7,}")
# Whole runs that are dates, CPFs or CNPJs are never phones: skipping them keeps prose cheap.
_NOT_PHONE_RUN_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}|\d{2}[/.-]\d{2}[/.-]\d{4}|\d{3}\.\d{3}\.\d{3}-\d{2}|\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})$")
_WINDOW_BREAK_RE = re.compile(r"[ \t /](?=\d|[(+])")


def phone_candidate_windows(text: str, *, pad: int = 6, max_windows: int = WINDOW_CAP) -> dict[str, Any]:
    """Padded windows around every run of >= 8 digits separated by at most 3 of ' ().-/' (NBSP included),
    skipping runs that are exactly a date, CPF or CNPJ shape; runs longer than MAX_WINDOW_CHARS become
    overlapping chunks. -> {'windows': [(start, end)], 'capped': bool}. PhoneNumberMatcher runs per window
    (a whole-text run gives up after max_tries failed candidates and misses later phones)."""
    t = text if isinstance(text, str) else ""
    wins: list[tuple[int, int]] = []
    capped = False

    def emit(a: int, b: int) -> bool:
        nonlocal capped
        if len(wins) >= max_windows:
            capped = True
            return False
        wins.append((a, b))
        return True

    for m in _CANDIDATE_RE.finditer(t):
        if _NOT_PHONE_RUN_RE.match(m.group(0)):
            continue
        a, b = max(0, m.start() - pad), min(len(t), m.end() + pad)
        if b - a > MAX_WINDOW_CHARS:
            s = a
            while True:
                e = min(b, s + MAX_WINDOW_CHARS)
                if not emit(s, e) or e >= b:
                    break
                nxt = e - WINDOW_OVERLAP
                ws = _WINDOW_BREAK_RE.search(t, nxt, nxt + 32)
                s = ws.end() if ws else nxt
            if capped:
                break
            continue
        if wins and a <= wins[-1][1] and max(b, wins[-1][1]) - wins[-1][0] <= MAX_WINDOW_CHARS:
            wins[-1] = (wins[-1][0], max(wins[-1][1], b))
            continue
        if not emit(a, b):
            break
    return {"windows": wins, "capped": capped}


def cpf_shaped(raw: Any) -> bool:
    """A bare 11-digit string with valid CPF check digits: ambiguous with a phone, never turned into one."""
    s = raw.strip() if isinstance(raw, str) else ""
    return len(s) == 11 and s.isdigit() and cpf_valid(s)


def build_extracted_phone_pivots(matches: Any, *, cap: int = MATCH_CAP) -> dict[str, Any]:
    """Matcher results ({'start', 'end', 'raw_string', 'e164'}) -> distinct phones in order of appearance,
    de-duplicated by E.164, at most ``cap``; ``cap_hit`` as soon as a (cap+1)-th distinct number is seen."""
    cap = cap if isinstance(cap, int) and not isinstance(cap, bool) and cap > 0 else MATCH_CAP
    phones: dict[str, dict[str, Any]] = {}
    cap_hit = False
    skipped = 0
    for m in matches if isinstance(matches, (list, tuple)) else []:
        if not isinstance(m, Mapping) or not is_e164(m.get("e164")):
            skipped += 1
            continue
        e164 = m["e164"]
        if e164 not in phones:
            if len(phones) >= cap:
                cap_hit = True
                break
            phones[e164] = {"e164": e164, "spans": [], "raw": []}
        start, end = _int(m.get("start")), _int(m.get("end"))
        spans = phones[e164]["spans"]
        if start is not None and end is not None and 0 <= start <= end and [start, end] not in spans:
            spans.append([start, end])  # overlapping windows can report the same span twice
        raw = m.get("raw_string")
        if isinstance(raw, str) and raw not in phones[e164]["raw"]:
            phones[e164]["raw"].append(raw)
    return {"phones": list(phones.values()), "distinct": len(phones), "cap": cap, "cap_hit": cap_hit, "skipped_bad": skipped}


def extract_phones(text: str, *, region: str = "BR", cap: int = MATCH_CAP, window_cap: int = WINDOW_CAP,
                   cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    """FC4: PhoneNumberMatcher(window, region) over :func:`phone_candidate_windows`, stopping once cap+1
    distinct numbers were seen. -> :func:`build_extracted_phone_pivots` output plus 'windows',
    'windows_capped', 'withheld_cpf_shaped' and 'cancelled'. Raises ImportError without 'phonenumbers'.
    (The P172 extraction engine can call this; offsets are relative to the whole text.)"""
    import phonenumbers

    e164_fmt = phonenumbers.PhoneNumberFormat.E164
    found = phone_candidate_windows(text, max_windows=window_cap)
    matches: list[dict[str, Any]] = []
    distinct: set[str] = set()
    withheld = 0
    stopped = False
    for a, b in found["windows"]:
        if cancelled is not None and cancelled():
            stopped = True
            break
        for m in phonenumbers.PhoneNumberMatcher(text[a:b], region):
            if cpf_shaped(m.raw_string):
                withheld += 1
                continue
            e164 = phonenumbers.format_number(m.number, e164_fmt)
            matches.append({"start": a + m.start, "end": a + m.end, "raw_string": m.raw_string, "e164": e164})
            distinct.add(e164)
            if len(distinct) > cap:
                break
        if len(distinct) > cap:
            break
    out = build_extracted_phone_pivots(matches, cap=cap)
    out.update(windows=len(found["windows"]), windows_capped=found["capped"], withheld_cpf_shaped=withheld, cancelled=stopped)
    return out


# ----------------------------------------------------------------------------------------------------------
# FC3: maintainer data script (Anatel CNL -> br_ddd.json)
# ----------------------------------------------------------------------------------------------------------


def parse_cnl_localities(text: str) -> list[dict[str, str]]:
    """One LoPubCNL file (decoded text) -> locality records; 'cn' = the national code (DDD) read from the
    first two digits of 'Cod.Nacional/Mesa Informação' (else 'Mesa IU'). Short or blank lines are skipped."""
    width = sum(w for _, w in CNL_LAYOUT)
    out: list[dict[str, str]] = []
    for line in str(text or "").splitlines():
        if len(line.rstrip()) < width - 32 or not line.strip():
            continue
        line = line.ljust(width)
        rec: dict[str, str] = {}
        pos = 0
        for key, w in CNL_LAYOUT:
            rec[key] = line[pos:pos + w].strip()
            pos += w
        cn = ""
        for key in ("cn_mesa_informacao", "cn_mesa_iu"):
            if re.match(r"^\d{2}", rec[key]):
                cn = rec[key][:2]
                break
        rec["cn"] = cn
        out.append(rec)
    return out


def read_cnl_inputs(paths: Iterable[str | Path]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Records and per-file digests of LoPubCNL inputs: .TXT files or the .ZIP the public form returns
    (only its .TXT members are read, at most 50 MB each, never extracted to disk). ISO-8859-1 text."""
    records: list[dict[str, str]] = []
    digests: list[dict[str, Any]] = []
    for path in paths:
        p = Path(path)
        blobs: list[tuple[str, bytes]] = []
        if p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as zf:
                for info in zf.infolist():
                    if info.filename.upper().endswith(".TXT") and not info.is_dir() and info.file_size <= MAX_CNL_MEMBER:
                        blobs.append((f"{p.name}:{info.filename}", zf.read(info)))
        else:
            data = p.read_bytes()
            if len(data) <= MAX_CNL_MEMBER:
                blobs.append((p.name, data))
        for name, data in blobs:
            recs = parse_cnl_localities(data.decode("iso-8859-1"))
            digests.append({"file": name, "sha256": hashlib.sha256(data).hexdigest(), "localities": len(recs)})
            records.extend(recs)
    return records, digests


def build_br_ddd_table(records: Iterable[Mapping[str, str]], *, generated_at: str, inputs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """FC3: the bundled table from CNL locality records. Per allocated DDD: ``uf`` (the main city's UF),
    ``ufs`` (main UF first, then bordering UFs by municipality count), ``main_city`` and its basis (state
    capital, else the reviewed :data:`MAIN_CITY_OVERRIDES` entry, which must be an area centre of the
    DDD). Records of a UF that does not border the DDD's main UF are CNL anomalies: excluded and listed.
    Raises ValueError when a DDD is missing or has no acceptable main city (the maintainer reviews it)."""
    munis: dict[str, dict[str, set[str]]] = {}
    centres: dict[str, set[tuple[str, str]]] = {}
    names: dict[tuple[str, str], str] = {}
    for r in records:
        cn, uf, muni = r.get("cn", ""), r.get("uf", ""), (r.get("municipio") or "").strip()
        if cn not in BR_DDD_CODES or uf not in UF_NAMES or not muni or "?" in muni:
            continue
        munis.setdefault(cn, {}).setdefault(uf, set()).add(fold(muni))
        names.setdefault((uf, fold(muni)), muni)
        if r.get("centro_area") == "SIM":
            centres.setdefault(cn, set()).add((uf, fold(muni)))
    table: dict[str, Any] = {}
    anomalies: list[dict[str, Any]] = []
    problems: list[str] = []
    for cn in sorted(BR_DDD_CODES):
        by_uf = munis.get(cn) or {}
        if not by_uf:
            problems.append(f"DDD {cn}: no locality in the CNL files")
            continue
        capital = [(uf, fold(UF_CAPITALS[uf])) for uf in by_uf if fold(UF_CAPITALS[uf]) in by_uf[uf] and (uf, fold(UF_CAPITALS[uf])) in centres.get(cn, set())]
        if capital:
            main_uf, main_key = capital[0]
            basis = "state capital"
        elif cn in MAIN_CITY_OVERRIDES:
            main_uf, city = MAIN_CITY_OVERRIDES[cn]
            main_key = fold(city)
            if (main_uf, main_key) not in centres.get(cn, set()):
                problems.append(f"DDD {cn}: override {city}/{main_uf} is not an Anatel area centre of the DDD")
                continue
            basis = "reviewed override: most populous area centre (IBGE Censo 2022)"
        else:
            problems.append(f"DDD {cn}: no state capital and no reviewed override")
            continue
        ufs = [main_uf]
        for uf in sorted(by_uf, key=lambda u: (-len(by_uf[u]), u)):
            if uf == main_uf:
                continue
            if uf in UF_NEIGHBOURS.get(main_uf, frozenset()):
                ufs.append(uf)
            else:
                anomalies.extend({"ddd": cn, "uf": uf, "municipio": names[(uf, m)], "reason": f"{uf} does not border {main_uf}"} for m in sorted(by_uf[uf]))
        table[cn] = {"uf": main_uf, "ufs": ufs, "main_city": names[(main_uf, main_key)], "main_city_basis": basis}
    if problems:
        raise ValueError("; ".join(problems))
    digest = hashlib.sha256("\n".join(sorted(d["sha256"] for d in inputs or [])).encode()).hexdigest() if inputs else ""
    return {
        "name": "br_ddd",
        "description": "Brazilian DDD (national code, CN) -> UF(s) and main city",
        "source": CNL_SOURCE,
        "source_url": CNL_SOURCE_URL,
        "generated_at": generated_at,
        "licence": CNL_LICENCE,
        "attribution": "Fonte: Anatel (Cadastro Nacional de Localidades). Main cities of DDDs without a state capital: IBGE Censo 2022 (table 4709).",
        "generator": "v3lum.modules.phone.phone_parse.main (build_br_ddd_table)",
        "inputs": {"files": len(inputs or []), "localities": sum(int(d.get("localities", 0)) for d in inputs or []), "sha256": digest},
        "rules": "uf = UF of the main city; ufs = main UF + bordering UFs with municipalities in the DDD; main_city = state capital when it is an area centre of the DDD, else MAIN_CITY_OVERRIDES",
        "anomalies": anomalies,
        "ddd": table,
    }


def main(argv: list[str] | None = None) -> int:
    """Maintainer script: regenerate ``v3lum/data/phone_parse/br_ddd.json`` from Anatel's CNL files.

    1. In a browser, open the public form (``CNL_SOURCE_URL``: AreaArea > Download CNL > Gerar Arquivo
       Para Download (Publico)), choose TIPO ARQUIVO 'Localidade CNL' and download the file of each of the
       27 UFs (ZIP files containing LOPUBxxxxxx.TXT). No login or CAPTCHA is involved.
    2. ``python -c "import sys; from v3lum.modules.phone.phone_parse import main; sys.exit(main(sys.argv[1:]))" \\
       OUT.json LOPUB_*.ZIP`` (``--date YYYY-MM-DD`` sets generated_at, default today).
    3. Review the anomalies list, update the notice ``v3lum/data/notices/phone_parse_br_ddd.json`` (sha256,
       version) and run the phone_parse tests.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    date = _dt.date.today().isoformat()
    if "--date" in args:
        i = args.index("--date")
        date = args[i + 1] if i + 1 < len(args) else date
        del args[i:i + 2]
    if len(args) < 2:
        print(main.__doc__)
        return 2
    out, inputs = Path(args[0]), args[1:]
    records, digests = read_cnl_inputs(inputs)
    table = build_br_ddd_table(records, generated_at=date, inputs=digests)
    problems = validate_br_ddd_table(table)
    if problems:
        print("invalid table: " + "; ".join(problems), file=sys.stderr)
        return 1
    out.write_text(json.dumps(table, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{out}: {len(table['ddd'])} DDDs from {table['inputs']['localities']} localities; {len(table['anomalies'])} anomalies excluded")
    return 0


# ----------------------------------------------------------------------------------------------------------
# the module
# ----------------------------------------------------------------------------------------------------------


@register
class PhoneParse(Module):
    name = "phone_parse"
    title = "Phone parsing (offline, libphonenumber)"
    description = (
        "Validity, line type, E.164/national formats, DDD -> UF and main city (bundled Anatel table), "
        "geodescription, time zones and the original carrier (portability not reflected) of a phone number, "
        "offline; extracts phone numbers from text and files for analyst selection."
    )
    category = "phone"
    accepts = {T.PHONE, T.TEXT, T.FILE}
    produces = {T.PHONE}
    reference = "https://github.com/daviddrysdale/python-phonenumbers"
    tags = {"offline", "brazil"}
    notice = (
        "Carrier = ORIGINAL carrier of the number block (portability not reflected): the current operator is "
        "only available manually (ABR Telecom page, CAPTCHA). A DDD that differs from a CPF fiscal region, CEP "
        "or address UF is a weak consistency signal (people move), never a fraud verdict."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # nothing leaves the machine
    hosts = ()
    # No registry source: the P127 dataset brasilapi_ddd (source brasilapi.ddd, terms open) is optional
    # enrichment read only when already downloaded; declaring it would make the policy gate (POL-14)
    # report the whole module UNAVAILABLE offline whenever that dataset is missing.
    access_model = "offline"
    requires_packages = ("phonenumbers",)
    max_requests = 0
    expected_latency = 0.05
    timeout = 30.0
    max_pivots = MATCH_CAP
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            path = Path(entity.value)
            try:  # regular text files only: a FIFO or device would block or never end
                return path.suffix.lower() in TEXT_EXT and path.is_file() and path.stat().st_size <= MAX_READ
            except OSError:
                return False
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            import phonenumbers
        except ImportError:
            return res.mark(Status.UNAVAILABLE, "python package 'phonenumbers' is missing: pip install 'v3lum[full]'", reason_code="package")
        if entity.type is T.PHONE:
            return self._phone(entity, ctx, res, getattr(phonenumbers, "__version__", ""))
        return self._extract(entity, ctx, res)

    # ---- phone entities -------------------------------------------------------------------------------
    def _phone(self, entity: Entity, ctx: Any, res: ModuleResult, version: str) -> ModuleResult:
        raw = collect_phone_facts(entity.value, _region(ctx))
        brazilian = entity.value.startswith("+55")  # the DDD table and dataset are cited only when used
        facts = normalise_phone_facts(raw, _ddd_table(ctx) if brazilian else None, _ddd_dataset(ctx) if brazilian else None)
        res.raw = {"libphonenumber": version, "facts": facts}
        if not facts["ok"]:
            res.attr("valid", False)
            res.attr("phone_invalid_reason", facts["reason"])
            res.finding("Phone number could not be parsed", "info", str(facts["reason"]), confidence="confirmed", tags=["info"])
            return res
        res.attr("valid", facts["valid"])
        res.attr("phone_formats", facts["formats"])
        if facts["line_type"] != "unknown":
            res.attr("line_type", facts["line_type"])
        res.attr("country", facts["region"])
        geo = facts["geodescription"]
        if geo:
            res.attr("phone_geodescription", geo)
            if geo.get("level") == "city":
                res.attr("city", geo.get("city"))
        res.attr("timezone", facts["time_zones"])
        if facts["carrier"]:
            res.attr("original_carrier", facts["carrier"])
        br, ddd = facts["br"], facts["ddd"]
        if isinstance(br, dict) and br.get("ok"):
            res.attr("phone_br", {k: br[k] for k in ("ddd", "ddd_allocated", "line_hint", "subscriber_digits", "non_geographic")})
        if isinstance(ddd, dict):
            res.attr("region", ddd.get("uf"))
            res.attr("phone_ddd", {**ddd, "uf_time_zones": facts["uf_time_zones"]})
        if not facts["valid"]:
            res.attr("phone_invalid_reason", facts["invalid_reason"])
            res.finding(
                "Phone number is not valid",
                "info",
                f"libphonenumber does not consider {entity.display} a valid number: {facts['invalid_reason']}.",
                confidence="probable",
                data={"reason": facts["invalid_reason"], "possible": facts["possible"]},
                tags=["info"],
            )
        ng = (br or {}).get("non_geographic") if isinstance(br, dict) else None
        if ng:
            res.finding("Non-geographic Brazilian number", "info", ng["label"], confidence="confirmed", data=ng, tags=["info"], key=ng["class"])
        if facts["time_zone_caveat"]:
            res.finding(
                "libphonenumber time zone differs from the DDD state",
                "info",
                facts["time_zone_caveat"],
                confidence="probable",
                data={"libphonenumber": facts["time_zones"], "state": facts["uf_time_zones"]},
                tags=["info"],
            )
        return res

    # ---- text / file extraction (FC4) -----------------------------------------------------------------
    def _extract(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        if entity.type is T.FILE:
            try:
                with open(entity.value, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(MAX_READ)
            except OSError as exc:
                return res.mark(Status.ERROR, f"cannot read the file: {exc.strerror or type(exc).__name__}")
        else:
            text = entity.value
        region = _region(ctx)
        out = extract_phones(text, region=region, cap=MATCH_CAP, window_cap=WINDOW_CAP, cancelled=ctx.cancelled)
        for phone in out["phones"]:
            res.pivot(T.PHONE, phone["e164"], "mentions", confidence=0.85, expand=False, note=PERSONAL_NOTE)
        summary = {"distinct": out["distinct"], "cap": out["cap"], "cap_hit": out["cap_hit"], "windows": out["windows"],
                   "windows_capped": out["windows_capped"], "withheld_cpf_shaped": out["withheld_cpf_shaped"], "region": region}
        res.raw = {**summary, "spans": {p["e164"]: p["spans"] for p in out["phones"]}}
        if out["phones"]:
            capped = f" Phone extraction capped at {out['cap']} distinct numbers." if out["cap_hit"] else ""
            res.finding(
                "Phone numbers extracted from text",
                "info",
                f"{out['distinct']} distinct phone number(s) (default region {region}), listed for analyst selection.{capped}",
                confidence="probable",
                data=summary,
                tags=["info"],
            )
        if out["windows_capped"] or out["withheld_cpf_shaped"]:
            res.finding(
                "Phone extraction incomplete",
                "info",
                "Candidate windows capped (pathological input): later numbers were not read." if out["windows_capped"]
                else "Bare 11-digit numbers with valid CPF check digits were not read as phones (ambiguous; CPF is never pivoted).",
                confidence="confirmed",
                data=summary,
                tags=["info"],
            )
        if out["cancelled"]:
            res.stop("cancelled")
        return res


# ----------------------------------------------------------------------------------------------------------
# context helpers
# ----------------------------------------------------------------------------------------------------------


def _region(ctx: Any) -> str:
    """The core 'default_region' setting (ISO alpha-2, default BR)."""
    value = str(ctx.setting("default_region", "BR") or "BR").strip().upper()
    return value if re.fullmatch(r"[A-Z]{2}", value) else "BR"


def _ddd_table(ctx: Any) -> dict[str, Any] | None:
    """The bundled DDD table, or None when it is missing or fails validation (never raises)."""
    try:
        table = ctx.data.bundled_json(DDD_TABLE)
    except (OSError, ValueError):
        return None
    return table if not validate_br_ddd_table(table) else None


def _ddd_dataset(ctx: Any) -> dict[str, dict[str, Any]]:
    """P127 brasilapi_ddd records when that dataset is registered AND already downloaded; it is never
    fetched here (a present copy is served as is, whatever its age: `v3lum data update` refreshes it)."""
    if BRASILAPI_DDD_DATASET not in _datasets.DATASETS:
        return {}
    try:
        if not ctx.data.info(BRASILAPI_DDD_DATASET).present:
            return {}
        data = ctx.data.fetch_json(BRASILAPI_DDD_DATASET, ttl=10 * 365 * 86400)
    except (_datasets.DatasetError, OSError, ValueError):
        return {}
    return parse_ddd_dataset(data)
