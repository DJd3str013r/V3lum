"""P236 ``cnpj_lookup`` - CNPJ resolver over RFB open-data relays with a fallback chain.

Council P236 final conditions, as implemented here:

1. Sources at release (class open, tier community): BrasilAPI and Minha Receita (one shared parser),
   Querido Diario company/partners and the publica.cnpj.ws public API (only free source of state IE).
   Only a CNPJ entity is ever looked up (a CPF never is).
2. OpenCNPJ, CNPJa open and ReceitaWS are coded behind the same normaliser (``parse_opencnpj``,
   ``parse_cnpja``, ``parse_receitaws``) but are not registered or called until legal records their
   terms and a tier: the result lists them in ``providers_pending_review`` ('pending terms review').
3. Chain BrasilAPI -> Minha Receita -> Querido Diario -> publica.cnpj.ws (3/min, last resort): it stops
   at the first full record, 8 s per provider and a 25 s chain budget, with the per-provider outcome in
   coverage (``res.source_status``) and in ``provider_chain``. publica.cnpj.ws is called only when its
   registry token bucket and its x-ratelimit-remaining/reset headers allow it within 2 s; an empty
   bucket skips to the next provider instead of sleeping. Requests never wait for a Retry-After.
4. One normaliser, one schema (names, status and date, opening date, CNAEs with provider labels until
   P235 lands, legal nature, size, capital, Simples/MEI, address + IBGE code, phones, e-mails, QSA,
   state IE).
5. Every field keeps its provider and the provider's freshness (``field_sources``); when several
   providers answered, conflicts are listed with their source and the freshest wins
   (``field_conflicts``). BrasilAPI/Minha Receita rank by the dump month of minhareceita.org/updated
   (their data_situacao_cadastral is a status date, kept as displayed field).
6. Not found: 'not in RFB open data as of <snapshot>' only after not_found from two different ingestion
   pipelines (BrasilAPI relays Minha Receita: one pipeline); a dump-based not_found triggers at most one
   fallback. Anything else is 'could not verify'.
7. A ReceitaWS-style ``{"status": "ERROR"}`` inside HTTP 200 is an error (module error marker); the
   alphanumeric CNPJ is accepted (Querido Diario rejects it with 400: skipped as not applicable). The
   HTTP cache keeps answers 72 h (only records and documented not-found bodies are cached).
8. Registry e-mails/phones: attributes ``rfb_emails``/``rfb_phones`` and pivots (relation
   ``rfb_contact``, ``expand=False``, confidence 0.5 so correlation rules never link two companies
   through them) labelled 'registry contact (often the accounting firm)'.
9. Contact domains: free/BR webmail never pivots; other domains pivot with ``expand=False`` unless
   registro.br RDAP shows a registrant CNPJ with the same root (then ``expand=True``).
10. QSA: natural persons -> ``person_name`` pivots (relation ``partner_of``, expand False, name only);
    masked CPFs exactly as given and age bands only in the ``qsa`` table of the card.
11. PJ partners -> ``cnpj`` pivots, at most 20, expanded only while the depth is below setting
    ``cnpj_lookup_partner_depth`` (1 by default, 2 at most); third parties, passive modules only. The
    module never recurses.
12. MEI/EI: CPF digits inside names are masked at parse time, before display, evidence and indexes;
    their contacts are personal data (domain pivots only for non-webmail domains).
13. Status other than ATIVA -> MEDIUM finding with date and meaning; opening date and age are
    attributes (no age finding); ``cnpj_card`` holds the header. The legal-name pivot never expands.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.context import StateError
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
from v3lum.core.validators import cnpj_check_digits

# --------------------------------------------------------------------------------------
# registry sources and the provider chain
# --------------------------------------------------------------------------------------

SRC_BRASILAPI = "brasilapi.cnpj"
SRC_MINHARECEITA = "minhareceita.cnpj"
SRC_QD = "querido_diario.company"
SRC_CNPJWS = "cnpjws.public"
SRC_RDAP = "registrobr.rdap"

SNAPSHOT_URL = "https://minhareceita.org/updated"
RDAP_URL = "https://rdap.registro.br/domain/{domain}"

#: P236 cond 3: 8 s per provider, 25 s for the whole chain, never a wait above 2 s.
PROVIDER_TIMEOUT_S = 8.0
CHAIN_BUDGET_S = 25.0
MAX_WAIT_S = 2.0
#: P236 cond 7: 72 h for records and documented not-found answers.
CACHE_TTL_S = 72 * 3600
SNAPSHOT_TTL_S = 24 * 3600
RDAP_TIMEOUT_S = 6.0
MAX_RDAP_LOOKUPS = 2
#: P236 cond 11: at most 20 partner companies per seed.
PJ_PARTNER_CAP = 20
#: P236 cond 8: label of every registry-contact pivot.
REGISTRY_CONTACT_LABEL = "registry contact (often the accounting firm)"
#: P236 cond 8 / P238: contacts on more than this many CNPJs are tagged shared_contact.
SHARED_CONTACT_THRESHOLD = 20
#: confidence of weak edges (registry contacts, partner names, CEP): below MIN_LINK_CONFIDENCE (0.6)
#: of the generic correlation rules, so a shared accountant e-mail or a homonym never links two seeds.
WEAK_EDGE = 0.5


@dataclass(frozen=True)
class ChainProvider:
    """One provider of the chain. ``pipeline`` names the ingestion pipeline of the RFB dump used by the
    two-upstream not-found rule (BrasilAPI relays Minha Receita: one pipeline, prep H8)."""

    key: str
    label: str
    source: str
    url: str
    pipeline: str
    alnum: bool = True
    dump_based: bool = True
    budgeted: bool = False


PROVIDERS: dict[str, ChainProvider] = {
    "brasilapi": ChainProvider("brasilapi", "BrasilAPI", SRC_BRASILAPI, "https://brasilapi.com.br/api/cnpj/v1/{cnpj}", "minhareceita"),
    "minhareceita": ChainProvider("minhareceita", "Minha Receita", SRC_MINHARECEITA, "https://minhareceita.org/{cnpj}", "minhareceita"),
    "qd": ChainProvider("qd", "Querido Diario", SRC_QD, "https://api.queridodiario.org.br/company/info/{cnpj}", "querido_diario", alnum=False),
    "cnpjws": ChainProvider("cnpjws", "CNPJ.ws", SRC_CNPJWS, "https://publica.cnpj.ws/cnpj/{cnpj}", "cnpjws", budgeted=True),
}
QD_PARTNERS_URL = "https://api.queridodiario.org.br/company/partners/{cnpj}"
#: P236 cond 3: 3/min providers only as the last resort.
RELEASE_CHAIN = ("brasilapi", "minhareceita", "qd", "cnpjws")
#: P236 cond 2: coded, never called until legal records their terms (A1) and a tier (A8).
PENDING_TERMS_REVIEW: dict[str, dict[str, str]] = {
    "opencnpj": {"provider": "OpenCNPJ", "host": "api.opencnpj.org", "url": "https://api.opencnpj.org/{cnpj}"},
    "cnpja": {"provider": "CNPJa open", "host": "open.cnpja.com", "url": "https://open.cnpja.com/office/{cnpj}"},
    "receitaws": {"provider": "ReceitaWS", "host": "receitaws.com.br", "url": "https://receitaws.com.br/v1/cnpj/{cnpj}"},
}
PENDING_REASON = "pending terms review"
#: provider registry id of each chain provider (quota blocks)
REGISTRY_ID = {"brasilapi": "brasilapi", "minhareceita": "minhareceita", "qd": "querido_diario", "cnpjws": "cnpjws"}
BUCKET_STATE_KEY = "rate_buckets"

#: P236 cond 7 / P321: ReceitaWS answers {"status": "ERROR", "message": ...} with HTTP 200.
RECEITAWS_ERROR_MARKER: dict[str, Any] = {
    "id": "cnpj_lookup_status_error",
    "statuses": [200],
    "json_path": "status",
    "equals": "ERROR",
    "maps_to": "error",
    "reason_code": "error",
    "reason": "CNPJ provider answered status ERROR inside HTTP 200 (ReceitaWS-style error body): could not verify",
}

# --------------------------------------------------------------------------------------
# small helpers (untrusted provider data: never raise on odd types)
# --------------------------------------------------------------------------------------


def _s(v: Any) -> str:
    """str(v).strip() for scalars; '' for None, bools and containers."""
    if v is None or isinstance(v, (bool, dict, list, tuple, set)):
        return ""
    return str(v).strip()


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(_s(v))
    except ValueError:
        return None


def fold(text: Any) -> str:
    """Upper-case, accents stripped, dashes mapped to '-', whitespace collapsed."""
    t = _s(text).replace("–", "-").replace("—", "-")
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t).strip().upper()


def as_json(body: Any) -> Any:
    """Body (dict/list/bytes/str) -> parsed JSON, or None for HTML, empty or truncated bodies."""
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", "replace")
    t = body.strip() if isinstance(body, str) else ""
    if not t or t[0] not in "[{":
        return None
    try:
        return json.loads(t)
    except ValueError:
        return None


def iso_date(value: Any) -> str | None:
    """'2005-11-03' | '03/11/2005' | '20070701' | ISO datetime -> 'YYYY-MM-DD' or None."""
    v = _s(value)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", v)
    if m:
        y, mo, d = m.groups()
    else:
        m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", v)
        if m:
            d, mo, y = m.groups()
        else:
            m = re.match(r"^(\d{4})(\d{2})(\d{2})$", v)
            if not m:
                return None
            y, mo, d = m.groups()
    try:
        return date(int(y), int(mo), int(d)).isoformat()
    except ValueError:
        return None


def to_datetime(value: Any) -> datetime | None:
    """ISO datetime/date/month ('2026-11') -> aware datetime (UTC when no offset) or None."""
    v = _s(value)
    if not v:
        return None
    if re.fullmatch(r"\d{4}-\d{2}", v):
        v += "-01"
    v = re.sub(r"(\.\d{6})\d+", r"\1", v).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        d = iso_date(v)
        if not d:
            return None
        dt = datetime.fromisoformat(d)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    f = fold(v)
    if f in ("S", "SIM", "TRUE", "1", "Y", "YES"):
        return True
    if f in ("N", "NAO", "FALSE", "0", "NO"):
        return False
    return None


def _money(v: Any) -> float | None:
    """120000000000 | '120000000000,00' | '120000000000.00' | '1.234,56' -> float or None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    t = _s(v).replace("R$", "").replace(" ", "")
    if not t:
        return None
    if "," in t:
        t = t.replace(".", "").replace(",", ".")
    try:
        return float(t)
    except ValueError:
        return None


def _strip_code(v: Any) -> str | None:
    """'02 - ATIVA' -> 'ATIVA', '10-Diretor' -> 'Diretor', {'descricao': x} -> x."""
    if isinstance(v, dict):
        v = v.get("descricao") or v.get("text") or v.get("description") or ""
    t = _s(v)
    m = re.match(r"^\d+\s*-\s*(.+)$", t)
    return (m.group(1) if m else t).strip() or None


# --------------------------------------------------------------------------------------
# CNPJ / CPF helpers (P236 cond 7, 10, 12; rule 4)
# --------------------------------------------------------------------------------------

_CNPJ_RE = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")


def normalize_cnpj(value: Any) -> str | None:
    """Any CNPJ spelling (numeric or the 2026 alphanumeric format) -> 14 characters with valid check
    digits, else None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value).zfill(14)
    s = re.sub(r"[\s./\-]", "", _s(value)).upper()
    if not _CNPJ_RE.fullmatch(s) or len(set(s)) == 1:
        return None
    try:
        return s if cnpj_check_digits(s[:12]) == s[12:] else None
    except ValueError:
        return None


def format_cnpj(cnpj: Any) -> str | None:
    c = normalize_cnpj(cnpj)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if c else None


def cnpj_root(cnpj: Any) -> str | None:
    c = normalize_cnpj(cnpj)
    return c[:8] if c else None


_MASKED_CPF_RE = re.compile(r"^\*{3}\.?\d{3}\.?\d{3}-?\*{2}$")
_CPF_IN_TEXT = re.compile(r"(?<![\d*])(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})(?![\d*])")
_MASKED_IN_TEXT = re.compile(r"\*{3}\.?\d{3}\.?\d{3}-?\*{2}|\*{3}\d{6}\*{2}")


def mask_cpf(value: Any) -> str | None:
    """A full CPF -> the government pattern ***.456.789-** (AR24); a value already masked by its
    publisher is returned exactly as given (never re-derived, completed or unmasked); else None."""
    v = _s(value)
    if _MASKED_CPF_RE.fullmatch(v):
        return v
    d = re.sub(r"\D", "", v)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else None


def mask_cpfs_in_text(text: Any) -> str:
    """Mask every CPF-shaped 11-digit run inside free text (the MEI/EI razao social 'FULANO DE TAL
    12345678909'). 14-digit CNPJs and the 8-digit 'NN.NNN.NNN NAME' MEI prefix are untouched."""
    return _CPF_IN_TEXT.sub(lambda m: f"***.{m.group(2)}.{m.group(3)}-**", _s(text))


def strip_cpf_fragments(text: Any) -> str:
    """A name with every CPF run and masked CPF removed: pivots carry no CPF fragment (P236 cond 10)."""
    t = _MASKED_IN_TEXT.sub(" ", mask_cpfs_in_text(text))
    return re.sub(r"\s+", " ", t).strip(" -")


NAME_KEYS = frozenset({
    "razao_social", "nome_fantasia", "fantasia", "nome", "name", "alias", "nome_socio", "nome_representante_legal",
    "nome_representante", "nome_empresarial", "rep_name", "legal_rep",
})


def mask_for_evidence(obj: Any) -> Any:
    """Deep copy of a provider answer with CPF runs masked in name fields (evidence keeps the response
    only in this masked form, P236 cond 12, A10)."""
    if isinstance(obj, dict):
        return {k: (mask_cpfs_in_text(v) if k in NAME_KEYS and isinstance(v, str) else mask_for_evidence(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_for_evidence(x) for x in obj]
    return obj


def normalize_phone(raw: Any = None, ddd: Any = None, number: Any = None, fax: bool = False) -> dict[str, Any] | None:
    """Brazilian phone -> {ddd, number, e164, key, fax, mobile} or None. key = DDD + last 8 digits, so
    '61 9xxxx-xxxx' and BrasilAPI's 8-digit form (it drops the mobile 9) merge (P236 cond 4)."""
    digits = re.sub(r"\D", "", _s(raw)) if raw is not None else re.sub(r"\D", "", _s(ddd)) + re.sub(r"\D", "", _s(number))
    if digits.startswith("55") and len(digits) in (12, 13):
        digits = digits[2:]
    if digits.startswith("0") and len(digits) in (11, 12):
        digits = digits[1:]
    if len(digits) not in (10, 11) or digits[0] == "0":
        return None
    area, num = digits[:2], digits[2:]
    return {"ddd": area, "number": num, "e164": "+55" + area + num, "key": area + num[-8:], "fax": bool(fax),
            "mobile": len(num) == 9 and num[0] == "9"}


def _phones(pairs: list[tuple[Any, bool]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw, fax in pairs:
        for part in re.split(r"\s*/\s*", _s(raw)) if _s(raw) else []:
            p = normalize_phone(part, fax=fax)
            if p and p["key"] not in seen:
                seen.add(p["key"])
                out.append(p)
    return out


_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$")


def _emails(values: list[Any]) -> list[str]:
    out: list[str] = []
    for v in values:
        e = _s(v).lower().rstrip(".")
        if _EMAIL_RE.match(e) and e not in out:
            out.append(e)
    return out


def email_domain(email: Any) -> str | None:
    m = _EMAIL_RE.match(_s(email).lower().rstrip("."))
    return m.group(1) if m else None


# --------------------------------------------------------------------------------------
# one record schema (P236 cond 4) and the parsers
# --------------------------------------------------------------------------------------

SITUACAO_CODES = {1: "NULA", 2: "ATIVA", 3: "SUSPENSA", 4: "INAPTA", 8: "BAIXADA"}
PORTE_CODES = {0: "NAO INFORMADO", 1: "MICRO EMPRESA", 3: "EMPRESA DE PEQUENO PORTE", 5: "DEMAIS"}
PORTE_ACRONYMS = {"ME": "MICRO EMPRESA", "EPP": "EMPRESA DE PEQUENO PORTE", "DEMAIS": "DEMAIS"}
#: natureza juridica 213-5 Empresario (Individual)
EI_NATUREZA = frozenset({"2135"})
NAME_PARTICLES = frozenset({"DA", "DE", "DO", "DAS", "DOS", "E", "D"})


def _situacao(v: Any) -> str | None:
    if isinstance(v, int) and not isinstance(v, bool):
        return SITUACAO_CODES.get(v)
    f = fold(_strip_code(v) if re.match(r"^\d+\s*-", _s(v)) else v)
    if f.isdigit():
        return SITUACAO_CODES.get(int(f))
    return f or None


def _porte(v: Any) -> str | None:
    if isinstance(v, dict):
        a = fold(v.get("acronym"))
        if a in PORTE_ACRONYMS:
            return PORTE_ACRONYMS[a]
        v = v.get("descricao") or v.get("text")
    if isinstance(v, int) and not isinstance(v, bool):
        return PORTE_CODES.get(v)
    return fold(_strip_code(v)) or None


def _cnae(code: Any, label: Any = None) -> dict[str, Any] | None:
    d = re.sub(r"\D", "", _s(code))
    if not d or int(d) == 0:
        return None
    return {"code": d.zfill(7), "label": _s(label) or None}


def _natureza(code: Any, label: Any = None) -> dict[str, Any] | None:
    """{'code': '2038', 'label': ...}; ReceitaWS '203-8 - X' and QD '2038 - X' accepted."""
    c, lab = _s(code), _s(label)
    if not c and lab:
        m = re.match(r"^([\d-]+)\s+-\s+(.+)$", lab)
        if m:
            c, lab = m.group(1), m.group(2)
    d = re.sub(r"\D", "", c)
    if not d and not lab:
        return None
    return {"code": d or None, "label": lab or None}


def _matriz(v: Any) -> str | None:
    if isinstance(v, int) and not isinstance(v, bool):
        return {1: "MATRIZ", 2: "FILIAL"}.get(v)
    f = fold(_strip_code(v))
    return {"1": "MATRIZ", "2": "FILIAL"}.get(f, f or None)


def _age_band(v: Any) -> str | None:
    """'Entre 41 a 50 anos' | '6 - 51 a 60 anos' | '41-50' -> '41-50'; 'Maiores de 80 anos' -> '80+'."""
    t = fold(_strip_code(v) if re.match(r"^\d+\s*-\s*\D", _s(v)) else v)
    m = re.search(r"(\d+)\s*(?:A|-)\s*(\d+)", t)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    m = re.search(r"(?:MAIORES? DE|ACIMA DE|\+)\s*(\d+)", t)
    return m.group(1) + "+" if m else None


def _kind(v: Any) -> str:
    if isinstance(v, int) and not isinstance(v, bool):
        return {1: "PJ", 2: "PF", 3: "EXT"}.get(v, "UNKNOWN")
    f = fold(v)
    if f[:1].isdigit():
        return {"1": "PJ", "2": "PF", "3": "EXT"}.get(f[:1], "UNKNOWN")
    if "FISICA" in f or f == "NATURAL":
        return "PF"
    if "JURIDICA" in f or f in ("LEGAL", "COMPANY"):
        return "PJ"
    if "ESTRANG" in f or "FOREIGN" in f or "EXTERIOR" in f:
        return "EXT"
    return "UNKNOWN"


def _partner(name: Any, kind: str, doc: Any, role: Any, since: Any, age_band: Any, country: Any = None,
             rep_name: Any = None, rep_doc: Any = None, rep_role: Any = None) -> dict[str, Any] | None:
    """Common QSA row. The partner document is kept exactly as published (the RFB masks CPFs as
    ***XXXXXX**); a full CPF a provider leaks is masked here (P236 cond 10). PJ partners keep their full
    CNPJ for the cnpj pivot (cond 11)."""
    nm = mask_cpfs_in_text(name)
    if not nm:
        return None
    raw_doc = _s(doc)
    digits = re.sub(r"\D", "", raw_doc)
    cnpj = normalize_cnpj(raw_doc) if kind in ("PJ", "UNKNOWN") and "*" not in raw_doc else None
    if kind == "UNKNOWN" and cnpj:
        kind = "PJ"
    if kind != "PJ" and len(digits) == 11 and "*" not in raw_doc:
        raw_doc = mask_cpf(digits) or ""
    p: dict[str, Any] = {
        "name": nm, "kind": kind, "doc_as_given": raw_doc or None, "cnpj": cnpj if kind == "PJ" else None,
        "role": _strip_code(role), "since": iso_date(since), "age_band": _age_band(age_band), "country": _strip_code(country),
    }
    rn = mask_cpfs_in_text(rep_name)
    if rn:
        rd = _s(rep_doc)
        if len(re.sub(r"\D", "", rd)) == 11 and "*" not in rd:
            rd = mask_cpf(rd) or ""
        p["legal_rep"] = {"name": rn, "doc_as_given": rd or None, "role": _strip_code(rep_role)}
    return p


def _address(street_type: Any = None, street: Any = None, number: Any = None, complement: Any = None, district: Any = None,
             city: Any = None, uf: Any = None, cep: Any = None, ibge: Any = None, siafi: Any = None) -> dict[str, Any]:
    c = re.sub(r"\D", "", _s(cep))
    ib = re.sub(r"\D", "", _s(ibge))
    return {
        "street_type": _s(street_type) or None, "street": _s(street) or None, "number": _s(number) or None,
        "complement": re.sub(r"\s+", " ", _s(complement)) or None, "district": _s(district) or None, "city": _s(city) or None,
        "uf": _s(uf).upper() or None, "cep": c if len(c) == 8 else None, "ibge_code": ib if len(ib) == 7 else None,
        "siafi_code": re.sub(r"\D", "", _s(siafi)) or None,
    }


def _empty_record(provider: str) -> dict[str, Any]:
    return {
        "provider": provider, "cnpj": None, "razao_social": None, "nome_fantasia": None, "situacao": None, "situacao_date": None,
        "situacao_motivo": None, "situacao_especial": None, "situacao_especial_date": None, "opening_date": None,
        "matriz_filial": None, "cnae_principal": None, "cnaes_secundarios": [], "natureza_juridica": None, "porte": None,
        "capital_social": None, "simples": None, "mei": None, "is_mei": False, "is_individual": False, "address": {}, "phones": [],
        "emails": [], "qsa": [], "qsa_count": 0, "qsa_total_reported": None, "qsa_former": [], "state_registrations": [],
        "ente_federativo": None, "freshness": {"field": None, "value": None},
    }


def _finish(r: dict[str, Any]) -> dict[str, Any]:
    r["qsa_count"] = len(r["qsa"])
    nat = _dict(r.get("natureza_juridica")).get("code")
    r["is_mei"] = _dict(r.get("mei")).get("optante") is True
    r["is_individual"] = r["is_mei"] or nat in EI_NATUREZA
    return r


def parse_brasilapi(obj: Any, provider: str = "brasilapi") -> dict[str, Any] | None:
    """BrasilAPI CNPJ v1 and Minha Receita (same schema, one parser; P236 cond 1, 4)."""
    o = as_json(obj)
    if not isinstance(o, dict) or not (o.get("cnpj") and "razao_social" in o):
        return None
    r = _empty_record(provider)
    r["cnpj"] = normalize_cnpj(o.get("cnpj"))
    r["razao_social"] = mask_cpfs_in_text(o.get("razao_social")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(o.get("nome_fantasia")) or None
    r["situacao"] = _situacao(o.get("descricao_situacao_cadastral") or o.get("situacao_cadastral"))
    r["situacao_date"] = iso_date(o.get("data_situacao_cadastral"))
    r["situacao_motivo"] = _s(o.get("descricao_motivo_situacao_cadastral")) or None
    r["situacao_especial"] = _s(o.get("situacao_especial")) or None
    r["situacao_especial_date"] = iso_date(o.get("data_situacao_especial"))
    r["opening_date"] = iso_date(o.get("data_inicio_atividade"))
    r["matriz_filial"] = _matriz(o.get("descricao_identificador_matriz_filial") or o.get("identificador_matriz_filial"))
    r["cnae_principal"] = _cnae(o.get("cnae_fiscal"), o.get("cnae_fiscal_descricao"))
    r["cnaes_secundarios"] = [c for c in (_cnae(_dict(x).get("codigo"), _dict(x).get("descricao")) for x in _list(o.get("cnaes_secundarios"))) if c]
    r["natureza_juridica"] = _natureza(o.get("codigo_natureza_juridica"), o.get("natureza_juridica"))
    r["porte"] = _porte(o.get("porte") or o.get("codigo_porte"))
    r["capital_social"] = _money(o.get("capital_social"))
    r["simples"] = {"optante": _bool(o.get("opcao_pelo_simples")), "since": iso_date(o.get("data_opcao_pelo_simples")),
                    "excluded": iso_date(o.get("data_exclusao_do_simples"))}
    r["mei"] = {"optante": _bool(o.get("opcao_pelo_mei")), "since": iso_date(o.get("data_opcao_pelo_mei")),
                "excluded": iso_date(o.get("data_exclusao_do_mei"))}
    r["address"] = _address(o.get("descricao_tipo_de_logradouro"), o.get("logradouro"), o.get("numero"), o.get("complemento"),
                            o.get("bairro"), o.get("municipio"), o.get("uf"), o.get("cep"), o.get("codigo_municipio_ibge"),
                            o.get("codigo_municipio"))
    r["phones"] = _phones([(o.get("ddd_telefone_1"), False), (o.get("ddd_telefone_2"), False), (o.get("ddd_fax"), True)])
    r["emails"] = _emails([o.get("email")])
    for x in _list(o.get("qsa")):
        x = _dict(x)
        p = _partner(x.get("nome_socio"), _kind(x.get("identificador_de_socio")), x.get("cnpj_cpf_do_socio"),
                     x.get("qualificacao_socio"), x.get("data_entrada_sociedade"), x.get("faixa_etaria"), x.get("pais"),
                     x.get("nome_representante_legal"), x.get("cpf_representante_legal"), x.get("qualificacao_representante_legal"))
        if p:
            r["qsa"].append(p)
    r["ente_federativo"] = _s(o.get("ente_federativo_responsavel")) or None
    r["freshness"] = {"field": "data_situacao_cadastral", "value": r["situacao_date"]}
    return _finish(r)


def parse_minhareceita(obj: Any) -> dict[str, Any] | None:
    return parse_brasilapi(obj, "minhareceita")


def parse_cnpjws(obj: Any) -> dict[str, Any] | None:
    """publica.cnpj.ws (only free source of state IE; P236 cond 1, 4). cnpj.ws keeps partners of
    earlier dumps: only the latest refresh month is the current QSA, older rows go to qsa_former
    (history, never pivots; prep H10)."""
    o = as_json(obj)
    if not isinstance(o, dict) or not isinstance(o.get("estabelecimento"), dict):
        return None
    e = o["estabelecimento"]
    r = _empty_record("cnpjws")
    r["cnpj"] = normalize_cnpj(e.get("cnpj"))
    r["razao_social"] = mask_cpfs_in_text(o.get("razao_social")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(e.get("nome_fantasia")) or None
    r["situacao"] = _situacao(e.get("situacao_cadastral"))
    r["situacao_date"] = iso_date(e.get("data_situacao_cadastral"))
    r["situacao_motivo"] = _strip_code(e.get("motivo_situacao_cadastral")) if e.get("motivo_situacao_cadastral") else None
    r["situacao_especial"] = _s(e.get("situacao_especial")) or None
    r["situacao_especial_date"] = iso_date(e.get("data_situacao_especial"))
    r["opening_date"] = iso_date(e.get("data_inicio_atividade"))
    r["matriz_filial"] = _matriz(e.get("tipo"))
    ap = _dict(e.get("atividade_principal"))
    r["cnae_principal"] = _cnae(ap.get("id"), ap.get("descricao"))
    r["cnaes_secundarios"] = [c for c in (_cnae(_dict(x).get("id"), _dict(x).get("descricao")) for x in _list(e.get("atividades_secundarias"))) if c]
    nj = _dict(o.get("natureza_juridica"))
    r["natureza_juridica"] = _natureza(nj.get("id"), nj.get("descricao"))
    r["porte"] = _porte(o.get("porte"))
    r["capital_social"] = _money(o.get("capital_social"))
    si = _dict(o.get("simples"))
    r["simples"] = {"optante": _bool(si.get("simples")), "since": iso_date(si.get("data_opcao_simples")),
                    "excluded": iso_date(si.get("data_exclusao_simples"))}
    r["mei"] = {"optante": _bool(si.get("mei")), "since": iso_date(si.get("data_opcao_mei")), "excluded": iso_date(si.get("data_exclusao_mei"))}
    cid, est = _dict(e.get("cidade")), _dict(e.get("estado"))
    r["address"] = _address(e.get("tipo_logradouro"), e.get("logradouro"), e.get("numero"), e.get("complemento"), e.get("bairro"),
                            cid.get("nome"), est.get("sigla"), e.get("cep"), cid.get("ibge_id"), cid.get("siafi_id"))
    r["phones"] = _phones([(_s(e.get("ddd1")) + _s(e.get("telefone1")), False), (_s(e.get("ddd2")) + _s(e.get("telefone2")), False),
                           (_s(e.get("ddd_fax")) + _s(e.get("fax")), True)])
    r["emails"] = _emails([e.get("email")])
    socios: list[tuple[dict[str, Any], str]] = []
    for x in _list(o.get("socios")):
        x = _dict(x)
        p = _partner(x.get("nome"), _kind(x.get("tipo")), x.get("cpf_cnpj_socio"), x.get("qualificacao_socio"), x.get("data_entrada"),
                     x.get("faixa_etaria"), _dict(x.get("pais")).get("nome"), x.get("nome_representante"),
                     x.get("cpf_representante_legal"), x.get("qualificacao_representante"))
        if p:
            socios.append((p, _s(x.get("atualizado_em"))))
    months = [u[:7] for _, u in socios if re.match(r"^\d{4}-\d{2}", u)]
    latest = max(months) if months else None
    for p, u in socios:
        if latest is None or not re.match(r"^\d{4}-\d{2}", u) or u[:7] == latest:
            r["qsa"].append(p)
        else:
            p["last_seen"] = iso_date(u)
            r["qsa_former"].append(p)
    for ie in _list(e.get("inscricoes_estaduais")):
        ie = _dict(ie)
        if _s(ie.get("inscricao_estadual")):
            r["state_registrations"].append({
                "ie": _s(ie.get("inscricao_estadual")), "uf": _s(_dict(ie.get("estado")).get("sigla")) or None,
                "active": ie.get("ativo") if isinstance(ie.get("ativo"), bool) else None, "updated": _s(ie.get("atualizado_em")) or None,
            })
    r["ente_federativo"] = _s(o.get("responsavel_federativo")) or None
    r["freshness"] = {"field": "atualizado_em", "value": _s(e.get("atualizado_em") or o.get("atualizado_em")) or None}
    return _finish(r)


def parse_qd_partners(obj: Any) -> tuple[list[dict[str, Any]], int | None]:
    """Querido Diario /company/partners -> (partners, total_partners)."""
    o = as_json(obj)
    if not isinstance(o, dict):
        return [], None
    out: list[dict[str, Any]] = []
    for x in _list(o.get("partners")):
        x = _dict(x)
        p = _partner(x.get("razao_social"), _kind(x.get("identificador_socio")), x.get("cnpj_cpf_socio"), x.get("qualificacao_socio"),
                     x.get("data_entrada_sociedade"), x.get("faixa_etaria"), x.get("pais_socio_estrangeiro"),
                     x.get("nome_representante_legal"), x.get("numero_cpf_representante_legal"), x.get("qualificacao_representante_legal"))
        if p:
            out.append(p)
    return out, _int(o.get("total_partners"))


def parse_qd(info_obj: Any, partners_obj: Any = None) -> dict[str, Any] | None:
    """Querido Diario /company/info + /company/partners (P236 cond 1, 4). QD exposes no freshness
    field (its capital can be years old): it ranks after dated providers (cond 5)."""
    o = as_json(info_obj)
    ci = _dict(o.get("cnpj_info")) if isinstance(o, dict) else {}
    if not ci:
        return None
    r = _empty_record("qd")
    r["cnpj"] = normalize_cnpj(ci.get("cnpj_completo_apenas_numeros") or ci.get("cnpj_completo"))
    r["razao_social"] = mask_cpfs_in_text(ci.get("razao_social")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(ci.get("nome_fantasia")) or None
    r["situacao"] = _situacao(ci.get("situacao_cadastral"))
    r["situacao_date"] = iso_date(ci.get("data_situacao_cadastral"))
    r["situacao_motivo"] = _strip_code(ci.get("motivo_situacao_cadastral"))
    r["situacao_especial"] = _s(ci.get("situacao_especial")) or None
    r["situacao_especial_date"] = iso_date(ci.get("data_situacao_especial"))
    r["opening_date"] = iso_date(ci.get("data_inicio_atividade"))
    r["matriz_filial"] = _matriz(ci.get("identificador_matriz_filial"))
    m = re.match(r"^\s*(\d{7})\s*-\s*(.*)$", _s(ci.get("cnae")))
    r["cnae_principal"] = _cnae(m.group(1), m.group(2)) if m else _cnae(ci.get("cnae"))
    sec = _s(ci.get("cnae_fiscal_secundario"))
    r["cnaes_secundarios"] = [c for c in (_cnae(a, b.strip().rstrip(",")) for a, b in re.findall(r"(\d{7})\s*-\s*(.*?)(?=,\s*\d{7}\s*-|$)", sec)) if c]
    r["natureza_juridica"] = _natureza(None, ci.get("natureza_juridica"))
    r["porte"] = _porte(ci.get("porte"))
    r["capital_social"] = _money(ci.get("capital_social"))
    r["simples"] = {"optante": _bool(ci.get("opcao_pelo_simples")), "since": iso_date(ci.get("data_opcao_pelo_simples")),
                    "excluded": iso_date(ci.get("data_exclusao_pelo_simples"))}
    r["mei"] = {"optante": _bool(ci.get("opcao_pelo_mei")), "since": iso_date(ci.get("data_opcao_pelo_mei")),
                "excluded": iso_date(ci.get("data_exclusao_pelo_mei"))}
    mun = _s(ci.get("municipio"))
    mm = re.match(r"^(\d+)\s*-\s*(.*)$", mun)
    r["address"] = _address(ci.get("tipo_logradouro"), ci.get("logradouro"), ci.get("numero"), ci.get("complemento"), ci.get("bairro"),
                            mm.group(2) if mm else mun, ci.get("uf"), ci.get("cep"), None, mm.group(1) if mm else None)
    t1 = _s(ci.get("ddd_telefone_1"))
    fax = re.sub(r"\D", "", _s(ci.get("ddd_telefone_fax")))
    if len(fax) in (8, 9) and len(re.sub(r"\D", "", t1)) >= 10:
        fax = re.sub(r"\D", "", t1)[:2] + fax
    r["phones"] = _phones([(t1, False), (ci.get("ddd_telefone_2"), False), (fax, True)])
    r["emails"] = _emails([ci.get("correio_eletronico")])
    r["ente_federativo"] = _s(ci.get("ente_federativo_responsavel")) or None
    if partners_obj is not None:
        r["qsa"], r["qsa_total_reported"] = parse_qd_partners(partners_obj)
    r["freshness"] = {"field": None, "value": None}
    return _finish(r)


# ---- providers pending terms review (P236 cond 2): coded, never called --------------------------


def parse_opencnpj(obj: Any) -> dict[str, Any] | None:
    """OpenCNPJ (pending terms review: coded behind the same normaliser, not registered, not called)."""
    o = as_json(obj)
    if not isinstance(o, dict) or not (o.get("cnpj") and "razao_social" in o):
        return None
    r = _empty_record("opencnpj")
    r["cnpj"] = normalize_cnpj(o.get("cnpj"))
    r["razao_social"] = mask_cpfs_in_text(o.get("razao_social")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(o.get("nome_fantasia")) or None
    r["situacao"] = _situacao(o.get("situacao_cadastral"))
    r["situacao_date"] = iso_date(o.get("data_situacao_cadastral"))
    r["situacao_motivo"] = _strip_code(o.get("motivo_situacao_cadastral"))
    r["situacao_especial"] = _s(o.get("situacao_especial")) or None
    r["situacao_especial_date"] = iso_date(o.get("data_situacao_especial"))
    r["opening_date"] = iso_date(o.get("data_inicio_atividade"))
    r["matriz_filial"] = _matriz(o.get("matriz_filial"))
    cn = [_dict(c) for c in _list(o.get("cnaes"))]
    main = [c for c in cn if c.get("is_principal") is True]
    r["cnae_principal"] = _cnae(main[0].get("codigo"), main[0].get("descricao")) if main else _cnae(o.get("cnae_principal"))
    sec = [_cnae(c.get("codigo"), c.get("descricao")) for c in cn if c.get("is_principal") is not True]
    if not cn:
        sec = [_cnae(c) for c in _list(o.get("cnaes_secundarios"))]
    r["cnaes_secundarios"] = [c for c in sec if c]
    r["natureza_juridica"] = _natureza(o.get("codigo_natureza_juridica"), o.get("natureza_juridica"))
    r["porte"] = _porte(o.get("porte_empresa"))
    r["capital_social"] = _money(o.get("capital_social"))
    r["simples"] = {"optante": _bool(o.get("opcao_simples")), "since": iso_date(o.get("data_opcao_simples")),
                    "excluded": iso_date(o.get("data_exclusao_simples"))}
    r["mei"] = {"optante": _bool(o.get("opcao_mei")), "since": iso_date(o.get("data_opcao_mei")), "excluded": iso_date(o.get("data_exclusao_mei"))}
    r["address"] = _address(o.get("tipo_logradouro"), o.get("logradouro"), o.get("numero"), o.get("complemento"), o.get("bairro"),
                            o.get("municipio"), o.get("uf"), o.get("cep"), None, o.get("codigo_municipio"))
    r["phones"] = _phones([(_s(_dict(t).get("ddd")) + _s(_dict(t).get("numero")), _dict(t).get("is_fax") is True) for t in _list(o.get("telefones"))])
    r["emails"] = _emails([o.get("email")])
    for x in _list(o.get("QSA") or o.get("qsa")):
        x = _dict(x)
        p = _partner(x.get("nome_socio"), _kind(x.get("identificador_socio")), x.get("cnpj_cpf_socio"), x.get("qualificacao_socio"),
                     x.get("data_entrada_sociedade"), x.get("faixa_etaria"), _dict(x.get("pais")).get("descricao"),
                     x.get("nome_representante"), x.get("representante_legal"), x.get("qualificacao_representante"))
        if p:
            r["qsa"].append(p)
    r["ente_federativo"] = _s(o.get("ente_federativo")) or None
    r["freshness"] = {"field": "updated_at", "value": _s(o.get("updated_at")) or None}
    return _finish(r)


def parse_cnpja(obj: Any) -> dict[str, Any] | None:
    """CNPJa open office record (pending terms review: coded, not registered, not called)."""
    o = as_json(obj)
    if not isinstance(o, dict) or not o.get("taxId"):
        return None
    co = _dict(o.get("company"))
    r = _empty_record("cnpja")
    r["cnpj"] = normalize_cnpj(o.get("taxId"))
    r["razao_social"] = mask_cpfs_in_text(co.get("name")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(o.get("alias")) or None
    st = _dict(o.get("status"))
    r["situacao"] = _situacao(st.get("text") or st.get("id"))
    r["situacao_date"] = iso_date(o.get("statusDate"))
    r["situacao_motivo"] = _strip_code(o.get("reason")) if isinstance(o.get("reason"), dict) else None
    if isinstance(o.get("special"), dict):
        r["situacao_especial"] = _strip_code(o.get("special"))
        r["situacao_especial_date"] = iso_date(o.get("specialDate"))
    r["opening_date"] = iso_date(o.get("founded"))
    r["matriz_filial"] = "MATRIZ" if o.get("head") is True else "FILIAL" if o.get("head") is False else None
    ma = _dict(o.get("mainActivity"))
    r["cnae_principal"] = _cnae(ma.get("id"), ma.get("text"))
    r["cnaes_secundarios"] = [c for c in (_cnae(_dict(x).get("id"), _dict(x).get("text")) for x in _list(o.get("sideActivities"))) if c]
    na = _dict(co.get("nature"))
    r["natureza_juridica"] = _natureza(na.get("id"), na.get("text"))
    r["porte"] = _porte(co.get("size"))
    r["capital_social"] = _money(co.get("equity"))
    si, sm = _dict(co.get("simples")), _dict(co.get("simei"))
    r["simples"] = {"optante": _bool(si.get("optant")), "since": iso_date(si.get("since")), "excluded": None}
    r["mei"] = {"optante": _bool(sm.get("optant")), "since": iso_date(sm.get("since")), "excluded": None}
    ad = _dict(o.get("address"))
    r["address"] = _address(None, ad.get("street"), ad.get("number"), ad.get("details"), ad.get("district"), ad.get("city"),
                            ad.get("state"), ad.get("zip"), ad.get("municipality"), None)
    r["phones"] = _phones([(_s(_dict(p).get("area")) + _s(_dict(p).get("number")), fold(_dict(p).get("type")) == "FAX") for p in _list(o.get("phones"))])
    r["emails"] = _emails([_dict(e).get("address") for e in _list(o.get("emails"))])
    for m in _list(co.get("members")):
        m = _dict(m)
        per = _dict(m.get("person"))
        p = _partner(per.get("name"), _kind(per.get("type")), per.get("taxId"), _dict(m.get("role")).get("text"), m.get("since"),
                     per.get("age"), _dict(per.get("country")).get("name"))
        if p:
            r["qsa"].append(p)
    for reg in _list(o.get("registrations")):
        reg = _dict(reg)
        if _s(reg.get("number")):
            r["state_registrations"].append({
                "ie": _s(reg.get("number")), "uf": _s(reg.get("state")) or None,
                "active": reg.get("enabled") if isinstance(reg.get("enabled"), bool) else None, "updated": _s(reg.get("statusDate")) or None,
            })
    r["freshness"] = {"field": "updated", "value": _s(o.get("updated")) or None}
    return _finish(r)


def receitaws_error(obj: Any) -> str | None:
    """P236 cond 7 / P321: ReceitaWS {'status': 'ERROR', 'message': ...} - also inside HTTP 200 - is
    an ERROR, never a not-found vote. Returns the reason or None."""
    o = as_json(obj)
    if isinstance(o, dict) and fold(o.get("status")) == "ERROR":
        return "ReceitaWS status ERROR: %s" % (_s(o.get("message"))[:120] or "no message")
    return None


def parse_receitaws(obj: Any) -> dict[str, Any] | None:
    """ReceitaWS v1 (pending terms review: coded, not registered, not called). QSA rows carry no partner
    type or document, so partners are kind UNKNOWN."""
    o = as_json(obj)
    if not isinstance(o, dict) or receitaws_error(o) or not o.get("cnpj") or "nome" not in o:
        return None
    r = _empty_record("receitaws")
    r["cnpj"] = normalize_cnpj(o.get("cnpj"))
    r["razao_social"] = mask_cpfs_in_text(o.get("nome")) or None
    r["nome_fantasia"] = mask_cpfs_in_text(o.get("fantasia")) or None
    r["situacao"] = _situacao(o.get("situacao"))
    r["situacao_date"] = iso_date(o.get("data_situacao"))
    r["situacao_motivo"] = _s(o.get("motivo_situacao")) or None
    r["situacao_especial"] = _s(o.get("situacao_especial")) or None
    r["situacao_especial_date"] = iso_date(o.get("data_situacao_especial"))
    r["opening_date"] = iso_date(o.get("abertura"))
    r["matriz_filial"] = _matriz(o.get("tipo"))
    ap = [_dict(a) for a in _list(o.get("atividade_principal"))]
    r["cnae_principal"] = _cnae(ap[0].get("code"), ap[0].get("text")) if ap else None
    r["cnaes_secundarios"] = [c for c in (_cnae(_dict(a).get("code"), _dict(a).get("text")) for a in _list(o.get("atividades_secundarias"))) if c]
    r["natureza_juridica"] = _natureza(None, o.get("natureza_juridica"))
    r["porte"] = _porte(o.get("porte"))
    r["capital_social"] = _money(o.get("capital_social"))
    si, sm = _dict(o.get("simples")), _dict(o.get("simei"))
    r["simples"] = {"optante": _bool(si.get("optante")), "since": iso_date(si.get("data_opcao")), "excluded": iso_date(si.get("data_exclusao"))}
    r["mei"] = {"optante": _bool(sm.get("optante")), "since": iso_date(sm.get("data_opcao")), "excluded": iso_date(sm.get("data_exclusao"))}
    r["address"] = _address(None, o.get("logradouro"), o.get("numero"), o.get("complemento"), o.get("bairro"), o.get("municipio"),
                            o.get("uf"), o.get("cep"))
    r["phones"] = _phones([(o.get("telefone"), False)])
    r["emails"] = _emails([o.get("email")])
    for q in _list(o.get("qsa")):
        q = _dict(q)
        p = _partner(q.get("nome"), _kind(q.get("tipo")) if q.get("tipo") else "UNKNOWN", None, q.get("qual"), None, None,
                     q.get("pais_origem"), q.get("nome_rep_legal"), None, q.get("qual_rep_legal"))
        if p:
            r["qsa"].append(p)
    r["ente_federativo"] = _s(o.get("efr")) or None
    r["freshness"] = {"field": "ultima_atualizacao", "value": _s(o.get("ultima_atualizacao")) or None}
    return _finish(r)


PARSERS = {
    "brasilapi": parse_brasilapi, "minhareceita": parse_minhareceita, "cnpjws": parse_cnpjws,
    "opencnpj": parse_opencnpj, "cnpja": parse_cnpja, "receitaws": parse_receitaws,
}


def parse_snapshot(obj: Any) -> str | None:
    """minhareceita.org/updated -> RFB dump month 'YYYY-MM' (or a date) or None."""
    o = as_json(obj)
    if not isinstance(o, dict):
        return None
    m = re.search(r"(\d{4})-(\d{2})(?:-(\d{2}))?", _s(o.get("message")))
    return m.group(0) if m else None


def is_full(record: dict[str, Any] | None) -> bool:
    """P236 cond 3 'first full record': names, status and opening date present."""
    return bool(record and record.get("razao_social") and record.get("situacao") and record.get("opening_date"))


# --------------------------------------------------------------------------------------
# answer classification (P236 cond 6-7)
# --------------------------------------------------------------------------------------


def _not_found_body(js: Any) -> bool:
    if not isinstance(js, dict):
        return False
    if _s(js.get("type")).lower() == "not_found":
        return True
    if _int(js.get("code")) == 404 or _int(js.get("status")) == 404:
        return True
    msg = fold(" ".join(_s(js.get(k)) for k in ("message", "error", "titulo", "detail")))
    return "NAO ENCONTRADO" in msg or "NOT FOUND" in msg or "NOT REGISTERED" in msg


def _has_record(provider: str, js: Any) -> bool:
    if not isinstance(js, dict):
        return False
    if provider in ("brasilapi", "minhareceita", "opencnpj"):
        return bool(js.get("cnpj")) and "razao_social" in js
    if provider == "cnpjws":
        return isinstance(js.get("estabelecimento"), dict)
    if provider == "qd":
        return isinstance(js.get("cnpj_info"), dict)
    if provider == "qd_partners":
        return isinstance(js.get("partners"), list)
    if provider == "cnpja":
        return bool(js.get("taxId"))
    if provider == "receitaws":
        return fold(js.get("status")) == "OK" and bool(js.get("cnpj"))
    return False


#: classification status of the core (P321) -> chain state
_CLASS_STATE = {"blocked": "blocked", "rate_limited": "rate_limited", "quota": "quota", "error": "error"}


def answer_state(provider: str, status: int, body: Any, *, cnpj: str = "", classification: Any = None) -> tuple[str, str]:
    """One provider answer -> (state, reason). state: ok | not_found | unsupported | invalid |
    rate_limited | blocked | quota | error. Only a 404 carrying the provider's own not-found body is a
    not_found vote; a 200 with an unexpected shape (error-in-200) is an error; Querido Diario's 400 for
    an alphanumeric CNPJ is 'unsupported' (not applicable)."""
    label = PROVIDERS[provider].label if provider in PROVIDERS else provider
    if classification is not None:
        state = _CLASS_STATE.get(str(getattr(classification, "status", "") or ""), "error")
        return state, f"{label}: {getattr(classification, 'reason', '') or state}"
    js = as_json(body)
    if status == 429:
        return "rate_limited", f"{label}: rate limited (HTTP 429)"
    if status == 200:
        err = receitaws_error(js)
        if err:
            return "error", f"{label}: {err}"
        kind = "qd_partners" if provider == "qd_partners" else provider
        if _has_record(kind, js):
            return "ok", ""
        return "error", f"{label}: HTTP 200 without a usable record (unexpected shape or error body)"
    if status == 404:
        if _not_found_body(js):
            return "not_found", f"{label}: no record for this CNPJ (HTTP 404)"
        return "error", f"{label}: HTTP 404 without its documented not-found body"
    if status == 400:
        if provider in ("qd", "qd_partners") and cnpj and not cnpj.isdigit():
            return "unsupported", f"{label} rejects alphanumeric CNPJs (HTTP 400)"
        return "invalid", f"{label} rejected the CNPJ (HTTP 400)"
    if status in (401, 403, 430, 451):
        return "blocked", f"{label}: HTTP {status}"
    if status >= 500:
        return "error", f"{label}: HTTP {status}"
    return "error", f"{label}: unexpected HTTP {status}"


#: chain state -> (Status, reason_code) of the per-provider coverage row
STATE_STATUS: dict[str, tuple[Status, str]] = {
    "ok": (Status.OK, ""),
    "not_found": (Status.EMPTY, ""),
    "unsupported": (Status.SKIPPED, "not_applicable"),
    "skipped": (Status.RATE_LIMITED, "rate_limited"),
    "deadline": (Status.SKIPPED, "deadline"),
    "rate_limited": (Status.RATE_LIMITED, "rate_limited"),
    "blocked": (Status.BLOCKED, "challenge"),
    "quota": (Status.QUOTA, "quota"),
    "timeout": (Status.ERROR, "timeout"),
    "invalid": (Status.ERROR, "error"),
    "error": (Status.ERROR, "error"),
}


def not_found_verdict(attempts: list[dict[str, Any]], snapshot: str | None = None) -> dict[str, Any]:
    """P236 cond 6 (rule 5): 'not_found' only after not_found from two different ingestion pipelines;
    anything else without an 'ok' is 'could not verify'."""
    if any(a.get("state") == "ok" for a in attempts):
        return {"verdict": "found", "message": None, "pipelines": []}
    pipes = sorted({PROVIDERS[a["provider"]].pipeline for a in attempts if a.get("state") == "not_found" and a.get("provider") in PROVIDERS})
    if len(pipes) >= 2:
        return {
            "verdict": "not_found", "pipelines": pipes,
            "message": "not in RFB open data as of %s (companies opened after the last dump may be missing)" % (snapshot or "the last dump"),
        }
    detail = ", ".join(f"{a.get('provider')} {a.get('state')}" for a in attempts if a.get("state") not in (None, "")) or "no provider answered"
    return {"verdict": "could_not_verify", "pipelines": pipes, "message": f"could not verify ({detail})"}


# --------------------------------------------------------------------------------------
# merge with provenance (P236 cond 5)
# --------------------------------------------------------------------------------------

CHAIN_ORDER = RELEASE_CHAIN + tuple(PENDING_TERMS_REVIEW)
MERGE_FIELDS = (
    "razao_social", "nome_fantasia", "situacao", "situacao_date", "situacao_motivo", "situacao_especial", "situacao_especial_date",
    "opening_date", "matriz_filial", "cnae_principal",
    "cnaes_secundarios", "natureza_juridica", "porte", "capital_social", "simples", "mei", "address", "phones", "emails", "qsa",
    "state_registrations", "ente_federativo",
)


def _cmp(field: str, v: Any) -> Any:
    if v is None or v == [] or v == {}:
        return None
    if field in ("razao_social", "nome_fantasia", "situacao_motivo", "porte", "matriz_filial", "ente_federativo", "situacao", "situacao_especial"):
        return fold(v) or None
    if field in ("cnae_principal", "natureza_juridica"):
        return _dict(v).get("code")
    if field == "cnaes_secundarios":
        return tuple(sorted(_dict(c).get("code") or "" for c in v))
    if field == "capital_social":
        try:
            return round(float(v), 2)
        except (TypeError, ValueError):
            return None
    if field == "address":
        return (v.get("cep"), fold(v.get("number"))) if isinstance(v, dict) and v.get("cep") else None
    if field == "phones":
        return tuple(sorted(_dict(p).get("key") or "" for p in v))
    if field == "emails":
        return tuple(sorted(v))
    if field == "qsa":
        return len(v)
    if field in ("simples", "mei"):
        return _dict(v).get("optante")
    if field == "state_registrations":
        return tuple(sorted(_dict(x).get("ie") or "" for x in v))
    return v


def provider_as_of(record: dict[str, Any], snapshot: str | None = None) -> str | None:
    """Freshness used to rank providers (P236 cond 5): BrasilAPI and Minha Receita use the dump month
    of minhareceita.org/updated (their data_situacao_cadastral is a status date); other providers
    their own updated / atualizado_em / ultima_atualizacao field; Querido Diario has none."""
    p = record.get("provider")
    fr = _dict(record.get("freshness"))
    if p in ("brasilapi", "minhareceita"):
        return snapshot
    if fr.get("field") and fr.get("field") != "data_situacao_cadastral":
        return fr.get("value")
    return None


def merge_records(records: list[dict[str, Any]], snapshot: str | None = None) -> dict[str, Any]:
    """One schema; every field keeps its provider and as-of; when providers disagree the freshest wins
    and the others are listed as alternatives. Unknown freshness ranks after dated providers, then by
    chain order."""
    recs = [r for r in records if isinstance(r, dict) and r.get("provider")]
    order = {p: i for i, p in enumerate(CHAIN_ORDER)}

    def key(r: dict[str, Any]) -> tuple[int, float, int]:
        dt = to_datetime(provider_as_of(r, snapshot))
        return (0 if dt else 1, -(dt.timestamp()) if dt else 0.0, order.get(r["provider"], 99))

    ranked = sorted(recs, key=key)
    fields: dict[str, dict[str, Any]] = {}
    for f in MERGE_FIELDS:
        vals = [(r["provider"], r.get(f), provider_as_of(r, snapshot)) for r in ranked if _cmp(f, r.get(f)) is not None]
        if not vals:
            fields[f] = {"value": None, "provider": None, "as_of": None, "conflict": False, "alternatives": []}
            continue
        win = vals[0]
        wk = _cmp(f, win[1])
        fields[f] = {
            "value": win[1], "provider": win[0], "as_of": win[2],
            "conflict": len({_cmp(f, v) for _, v, _ in vals}) > 1,
            "alternatives": [{"provider": p, "value": v, "as_of": a} for p, v, a in vals[1:] if _cmp(f, v) != wk],
        }
    cnpjs = [r.get("cnpj") for r in ranked if r.get("cnpj")]
    return {
        "cnpj": cnpjs[0] if cnpjs else None,
        "providers": [r["provider"] for r in ranked],
        "is_mei": any(r.get("is_mei") for r in ranked),
        "is_individual": any(r.get("is_individual") for r in ranked),
        "qsa_former": next((r.get("qsa_former") for r in ranked if r.get("qsa_former")), []),
        "qsa_total_reported": next((r.get("qsa_total_reported") for r in ranked if r.get("qsa_total_reported") is not None), None),
        "freshness": {r["provider"]: {"field": _dict(r.get("freshness")).get("field"), "value": _dict(r.get("freshness")).get("value"),
                                      "as_of": provider_as_of(r, snapshot)} for r in ranked},
        "fields": fields,
        "conflicts": [f for f in MERGE_FIELDS if fields[f]["conflict"]],
    }


def field(merged: dict[str, Any], name: str) -> Any:
    return _dict(_dict(merged.get("fields")).get(name)).get("value")


# --------------------------------------------------------------------------------------
# contacts, QSA and company pivots (P236 cond 8-12)
# --------------------------------------------------------------------------------------

#: P236 cond 9: free and Brazilian webmail domains never become domain pivots.
WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.com.br", "outlook.com", "outlook.com.br", "live.com", "live.com.br", "msn.com",
    "yahoo.com", "yahoo.com.br", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com",
    "proton.me", "pm.me", "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com", "bol.com.br", "uol.com.br", "terra.com.br",
    "ig.com.br", "igmail.com.br", "superig.com.br", "globo.com", "globomail.com", "r7.com", "zipmail.com.br", "pop.com.br",
    "oi.com.br", "brturbo.com.br", "click21.com.br", "ibest.com.br", "itelefonica.com.br", "veloxmail.com.br", "bol.com",
    "outlook.pt",
})
_CORP_WORDS = frozenset({
    "LTDA", "EIRELI", "LLC", "INC", "CORP", "CORPORATION", "LTD", "LIMITED", "GMBH", "BV", "NV", "SAS", "SRL", "PLC", "SPA", "HOLDING",
    "HOLDINGS", "PARTICIPACOES", "FUNDO", "FUND", "S/A", "COMPANY", "CIA", "AG",
})


def is_webmail(domain: Any) -> bool:
    d = _s(domain).lower().rstrip(".")
    return d in WEBMAIL_DOMAINS or any(d.endswith("." + w) for w in WEBMAIL_DOMAINS)


def looks_corporate(name: Any) -> bool:
    """Partners without a type: company suffixes; a final 'SA' counts only when not preceded by a
    particle, so the surname Sa ('JOAO DE SA') stays a person."""
    toks = re.sub(r"[^A-Z0-9/ ]", " ", fold(name).replace(".", "")).split()
    if not toks:
        return False
    if _CORP_WORDS & set(toks):
        return True
    return toks[-1] == "SA" and len(toks) >= 2 and toks[-2] not in NAME_PARTICLES


def rdap_registrant_cnpjs(rdap: Any) -> list[str]:
    """registro.br RDAP domain answer -> registrant CNPJs (publicIds of type cnpj, or a CNPJ handle)."""
    o = as_json(rdap)
    out: list[str] = []

    def walk(entities: Any) -> None:
        for e in _list(entities):
            e = _dict(e)
            roles = [_s(x).lower() for x in _list(e.get("roles"))]
            if "registrant" in roles:
                for pid in _list(e.get("publicIds")):
                    pid = _dict(pid)
                    c = normalize_cnpj(pid.get("identifier")) if _s(pid.get("type")).lower() == "cnpj" else None
                    if c and c not in out:
                        out.append(c)
                h = normalize_cnpj(e.get("handle"))
                if h and h not in out:
                    out.append(h)
            walk(e.get("entities"))

    walk(_dict(o).get("entities"))
    return out


STATUS_MEANINGS = {
    "BAIXADA": "closed: the registration was cancelled (baixa) at the Receita Federal",
    "INAPTA": "unfit (inapta): the Receita Federal flagged missing tax filings or an address that could not be found",
    "SUSPENSA": "suspended: the Receita Federal suspended the registration while an irregularity is reviewed",
    "NULA": "null: the registration was annulled (e.g. fraud or a duplicate registration)",
}
STATUS_PLAIN = {"ATIVA": "active", "BAIXADA": "closed", "INAPTA": "unfit (inapta)", "SUSPENSA": "suspended", "NULA": "null (annulled)"}


def company_age_years(opening_date: Any, today: date) -> float | None:
    o = to_datetime(opening_date)
    if not o:
        return None
    days = (today - o.date()).days
    return None if days < 0 else int(days / 365.25 * 10) / 10.0


def address_text(addr: dict[str, Any]) -> str:
    a = _dict(addr)
    street = " ".join(x for x in (a.get("street_type"), a.get("street")) if x)
    if street and a.get("street_type") and _s(a.get("street")).upper().startswith(_s(a.get("street_type")).upper()):
        street = _s(a.get("street"))
    parts = [", ".join(x for x in (street, a.get("number")) if x), a.get("complement"), a.get("district")]
    city = "/".join(x for x in (a.get("city"), a.get("uf")) if x)
    parts.append(city)
    if a.get("cep"):
        parts.append(f"CEP {a['cep'][:5]}-{a['cep'][5:]}")
    return " - ".join(p for p in parts if p)


# --------------------------------------------------------------------------------------
# per-provider rate budget (P236 cond 3, P334): token bucket from the registry + headers
# --------------------------------------------------------------------------------------


def _quota_block(provider_key: str) -> Any:
    try:
        from v3lum.core import providers

        prov = providers.registry().get(REGISTRY_ID.get(provider_key, provider_key))
    except Exception:  # noqa: BLE001 - a missing registry means 'no budget known'
        return None
    return getattr(prov, "quota", None) if prov is not None else None


def _bucket_params(provider_key: str) -> tuple[float, float] | None:
    """(interval seconds, tolerance seconds) of the provider's token bucket (rate x safety margin)."""
    spec = _quota_block(provider_key)
    rate = getattr(spec, "rate_per_second", None) if spec is not None else None
    if not rate:
        return None
    margin = float(getattr(spec, "safety_margin", 0.8) or 0.8)
    interval = 1.0 / (float(rate) * margin)
    tolerance = max(0, int(getattr(spec, "burst", 1) or 1) - 1) * interval
    return interval, tolerance


def _buckets(ctx: Any) -> dict[str, Any]:
    try:
        value = ctx.state.get(BUCKET_STATE_KEY, {})
    except (StateError, OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def bucket_wait(ctx: Any, provider_key: str, now_s: float) -> float:
    """Seconds before ``provider_key`` may be called: its registry token bucket (GCRA) and the last
    x-ratelimit-remaining / reset (or Retry-After) it sent. 0.0 when free."""
    b = _dict(_buckets(ctx).get(provider_key))
    wait = 0.0
    params = _bucket_params(provider_key)
    tat = b.get("tat")
    if params is not None and isinstance(tat, (int, float)):
        interval, tolerance = params
        wait = max(wait, float(tat) - tolerance - now_s)
    remaining, reset_at = b.get("remaining"), b.get("reset_at")
    if isinstance(remaining, (int, float)) and remaining <= 0 and isinstance(reset_at, (int, float)):
        wait = max(wait, float(reset_at) - now_s)
    return max(0.0, wait)


def bucket_charge(ctx: Any, provider_key: str, now_s: float, *, headers: dict[str, str] | None = None, status: int = 0) -> None:
    """Record one call (token bucket) and the provider's rate headers. Best effort: ctx.state problems
    never break the lookup."""
    state = _buckets(ctx)
    b = dict(_dict(state.get(provider_key)))
    params = _bucket_params(provider_key)
    if params is not None:
        interval, _tolerance = params
        tat = b.get("tat") if isinstance(b.get("tat"), (int, float)) else now_s
        b["tat"] = round(max(float(tat), now_s) + interval, 3)
    h = {str(k).lower(): _s(v) for k, v in (headers or {}).items()}

    def num(name: str) -> float | None:
        try:
            return float(h[name])
        except (KeyError, ValueError):
            return None

    remaining = num("x-ratelimit-remaining")
    reset = num("x-ratelimit-reset")
    retry_after = num("retry-after")
    if status == 429:
        remaining = 0.0
        reset = retry_after if retry_after is not None else (reset if reset is not None else 60.0)
    if remaining is not None:
        b["remaining"] = remaining
        # publica.cnpj.ws sends the window length (60) as x-ratelimit-reset (prep H13)
        b["reset_at"] = round(now_s + (reset if reset is not None else 60.0), 3)
    state[provider_key] = b
    try:
        ctx.state.set(BUCKET_STATE_KEY, state)
    except (StateError, OSError, ValueError):
        pass


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


def _clock(ctx: Any) -> Any:
    clock = getattr(getattr(ctx, "http", None), "clock", None)
    if clock is None:
        clock = getattr(getattr(ctx, "runtime", None), "clock", None)
    return clock


def _mono(ctx: Any) -> float:
    clock = _clock(ctx)
    if clock is not None:
        return float(clock.monotonic())
    import time

    return time.monotonic()


@register
class CnpjLookup(Module):
    name = "cnpj_lookup"
    title = "CNPJ registry lookup (RFB open data)"
    description = (
        "Resolves a CNPJ through a fallback chain of RFB open-data relays (BrasilAPI, Minha Receita, Querido Diario, "
        "publica.cnpj.ws as last resort): names, status, CNAEs, legal nature, size, capital, Simples/MEI, address, registry "
        "contacts, QSA and state registrations, with per-field provenance."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ}
    produces = {T.CNPJ, T.ORG, T.PERSON, T.EMAIL, T.PHONE, T.CEP, T.DOMAIN}
    tags = {"brazil", "free"}
    reference = "https://brasilapi.com.br/docs#tag/CNPJ"
    notice = (
        "Official RFB open data (Decreto 8.777/2016). QSA partner CPFs appear only as masked by the RFB and are never "
        "unmasked, completed or joined; a CPF is never looked up. Registry e-mails/phones are often the accounting firm's. "
        "OpenCNPJ, CNPJa open and ReceitaWS are coded but not called until legal records their terms (pending terms review)."
    )
    # ---- declarations --------------------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("brasilapi.com.br", "minhareceita.org", "api.queridodiario.org.br", "publica.cnpj.ws", "rdap.registro.br")
    provider = "brasilapi"
    sources = (SRC_BRASILAPI, SRC_MINHARECEITA, SRC_QD, SRC_CNPJWS, SRC_RDAP)
    access_model = "free_noauth_limited"
    # chain 1-5 (BrasilAPI, Minha Receita, QD info + partners, cnpj.ws) + dump month 1 + RDAP <= 2
    max_requests = 9
    expected_latency = 1.5
    timeout = 45.0
    cache_ttl = CACHE_TTL_S
    max_pivots = 100
    error_markers = (RECEITAWS_ERROR_MARKER,)
    manual_link = "https://brasilapi.com.br/api/cnpj/v1/{cnpj_digits}"
    default_enabled = True  # A3: the BR CNPJ/QSA official open-data chain is default-on by decision
    settings = {
        "cnpj_lookup_partner_depth": SettingSpec(
            1, "levels of partner companies (QSA PJ partners) the engine may expand from a seed CNPJ (P236 cond 11)", choices=(1, 2)
        ),
        "cnpj_lookup_state_registrations": SettingSpec(
            False, "also query publica.cnpj.ws (3/min, last resort) for state registrations (IE) after another provider answered, when its budget allows"
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        # Banco do Brasil's public registration: the golden-path CNPJ of the acceptance tests
        return HealthCheck(etype=T.CNPJ, value="00000000000191")

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        cnpj = str(entity.value).upper()
        start = _mono(ctx)
        attempts: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        raw: dict[str, Any] = {}
        nf_pipelines: set[str] = set()
        calls_after_nf: int | None = None  # P236 cond 6: at most one fallback after a dump-based not_found

        for key in RELEASE_CHAIN:
            spec = PROVIDERS[key]
            if any(is_full(r) for r in records):
                break
            if calls_after_nf is not None and calls_after_nf >= 1:
                break
            if nf_pipelines and spec.pipeline in nf_pipelines:
                continue  # same ingestion pipeline as a not_found: not an independent answer
            if not spec.alnum and not cnpj.isdigit():
                attempts.append({"provider": key, "state": "unsupported", "reason": f"{spec.label} rejects alphanumeric CNPJs"})
                continue
            left = CHAIN_BUDGET_S - (_mono(ctx) - start)
            if left <= 0.5:
                attempts.append({"provider": key, "state": "deadline", "reason": "chain budget (25 s) spent: not called"})
                continue
            if spec.budgeted:
                wait = bucket_wait(ctx, key, ctx.now().timestamp())
                if wait > MAX_WAIT_S:
                    attempts.append({"provider": key, "state": "skipped",
                                     "reason": f"{spec.label}: rate budget empty (3/min), next slot in {wait:.0f} s - skipped instead of waiting"})
                    continue
            attempt, record, body = self._call(ctx, key, cnpj, min(PROVIDER_TIMEOUT_S, left))
            attempts.append(attempt)
            if body is not None:
                raw[key] = mask_for_evidence(body)
            if calls_after_nf is not None:
                calls_after_nf += 1
            if attempt["state"] == "ok" and record is not None:
                records.append(record)
            elif attempt["state"] == "not_found":
                nf_pipelines.add(spec.pipeline)
                if calls_after_nf is None and spec.dump_based:
                    calls_after_nf = 0

        # optional supplement: state registrations (IE) from cnpj.ws when another provider answered
        if (records and "cnpjws" not in {a["provider"] for a in attempts} and bool(ctx.setting("cnpj_lookup_state_registrations", False))
                and bucket_wait(ctx, "cnpjws", ctx.now().timestamp()) <= MAX_WAIT_S):
            left = CHAIN_BUDGET_S - (_mono(ctx) - start)
            if left > 0.5:
                attempt, record, body = self._call(ctx, "cnpjws", cnpj, min(PROVIDER_TIMEOUT_S, left))
                attempt["supplement"] = True
                attempts.append(attempt)
                if body is not None:
                    raw["cnpjws"] = mask_for_evidence(body)
                if record is not None and attempt["state"] == "ok":
                    records.append(record)

        snapshot = None
        if any(r["provider"] in ("brasilapi", "minhareceita") for r in records) or (not records and nf_pipelines):
            snapshot = self._snapshot(ctx)
        self._coverage(res, attempts)
        res.attr("provider_chain", [{"provider": PROVIDERS[a["provider"]].label, "source": PROVIDERS[a["provider"]].source,
                                     "state": a["state"], "reason": a.get("reason", "")} for a in attempts])
        res.attr("providers_pending_review", [{"provider": v["provider"], "host": v["host"], "reason": PENDING_REASON}
                                              for v in PENDING_TERMS_REVIEW.values()])
        res.raw = {"cnpj": cnpj, "responses": raw, "chain": attempts, "rfb_snapshot": snapshot}

        if not records:
            return self._no_record(res, ctx, attempts, snapshot, cnpj)
        merged = merge_records(records, snapshot)
        self._emit(res, ctx, merged, snapshot, cnpj)
        return res

    # ------------------------------------------------------------------ one provider
    def _call(self, ctx: Any, key: str, cnpj: str, budget: float) -> tuple[dict[str, Any], dict[str, Any] | None, Any]:
        spec = PROVIDERS[key]
        attempt: dict[str, Any] = {"provider": key, "state": "error", "reason": ""}
        url = spec.url.format(cnpj=cnpj)
        try:
            resp = self._get(ctx, url, spec.source, budget, key)
        except _Failure as exc:
            if spec.budgeted and exc.state not in ("quota", "rate_limited"):
                bucket_charge(ctx, key, ctx.now().timestamp())  # a request that may have reached the provider counts
            attempt.update(state=exc.state, reason=exc.reason, reason_code=exc.code)
            return attempt, None, None
        if spec.budgeted:
            bucket_charge(ctx, key, ctx.now().timestamp(), headers=resp.headers, status=resp.status)
        body = as_json(resp.content)
        state, reason = answer_state(key, resp.status, resp.content, cnpj=cnpj, classification=resp.classification)
        attempt.update(state=state, reason=reason, http_status=resp.status)
        if resp.classification is not None:
            attempt["reason_code"] = str(getattr(resp.classification, "reason_code", "") or "")
        if state != "ok":
            return attempt, None, body
        if key == "qd":
            partners_body = None
            try:
                presp = self._get(ctx, QD_PARTNERS_URL.format(cnpj=cnpj), spec.source, max(1.0, budget), "qd_partners")
                pstate, preason = answer_state("qd_partners", presp.status, presp.content, cnpj=cnpj, classification=presp.classification)
                if pstate == "ok":
                    partners_body = as_json(presp.content)
                else:
                    attempt["partners"] = preason
            except _Failure as exc:
                attempt["partners"] = exc.reason
            record = parse_qd(body, partners_body)
            if partners_body is not None:
                body = {"info": body, "partners": partners_body}
        else:
            record = PARSERS[key](body)
        if record is None or (record.get("cnpj") and record["cnpj"] != cnpj):
            attempt.update(state="error", reason=f"{spec.label}: answer is not the record of this CNPJ (unexpected shape)")
            return attempt, None, body
        return attempt, record, body

    def _get(self, ctx: Any, url: str, source: str, budget: float, kind: str) -> Any:
        """One GET with the per-provider timeout, no retry (never a Retry-After wait) and caching of
        records / documented not-found answers only. Failures raise _Failure (a chain state)."""
        deadline = _mono(ctx) + max(0.5, budget)
        try:
            return ctx.http.get(url, source=source, timeout=max(0.5, budget), deadline=deadline, retries=0, cache_if=_cacheable(kind),
                                headers={"Accept": "application/json"})
        except RateLimited as exc:
            raise _Failure("rate_limited", f"{_label(kind)}: {exc}", "rate_limited") from None
        except QuotaExceeded as exc:
            raise _Failure("quota", f"{_label(kind)}: {exc}", "quota") from None
        except Blocked as exc:
            raise _Failure("blocked", f"{_label(kind)}: {exc}", str(getattr(exc, "reason_code", "") or "challenge")) from None
        except AuthRequired as exc:
            raise _Failure("blocked", f"{_label(kind)}: {exc}", "challenge") from None
        except HttpError as exc:
            raise _Failure("error", f"{_label(kind)}: {exc}", "error") from None
        except DeadlineExceeded as exc:
            if ctx.remaining() is not None and ctx.remaining() <= 0:
                raise  # the run deadline itself: stop (the engine maps it to ERROR timeout)
            raise _Failure("timeout", f"{_label(kind)}: no answer within {budget:.0f} s ({exc})", "timeout") from None
        except NetworkError as exc:
            state = "timeout" if "timeout" in str(getattr(exc, "kind", "")).lower() else "error"
            raise _Failure(state, f"{_label(kind)}: {exc}", "timeout" if state == "timeout" else "error") from None

    def _snapshot(self, ctx: Any) -> str | None:
        """Dump month of minhareceita.org/updated (cached 24 h); None when it cannot be read."""
        try:
            resp = ctx.http.get(SNAPSHOT_URL, source=SRC_MINHARECEITA, ttl=SNAPSHOT_TTL_S, timeout=4.0, retries=0,
                                headers={"Accept": "application/json"}, cache_if=lambda r: r.status == 200 and parse_snapshot(r.content) is not None)
        except (HttpError, NetworkError):
            return None
        if resp.status != 200 or resp.classification is not None:
            return None
        return parse_snapshot(resp.content)

    # ------------------------------------------------------------------ outcomes
    def _coverage(self, res: ModuleResult, attempts: list[dict[str, Any]]) -> None:
        rows: dict[str, tuple[Status, str, str]] = {}
        for a in attempts:
            src = PROVIDERS[a["provider"]].source
            status, code = STATE_STATUS.get(a["state"], (Status.ERROR, "error"))
            if status is Status.BLOCKED and a.get("reason_code") in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                code = a["reason_code"]
            prev = rows.get(src)
            if prev is not None and prev[0] in (Status.OK, Status.EMPTY):
                continue  # an answer of the same source wins over a supplement failure
            rows[src] = (status, code, str(a.get("reason") or ""))
        for src, (status, code, reason) in rows.items():
            res.source_status(src, status, reason_code=code, reason=reason[:300])

    def _no_record(self, res: ModuleResult, ctx: Any, attempts: list[dict[str, Any]], snapshot: str | None, cnpj: str) -> ModuleResult:
        verdict = not_found_verdict(attempts, snapshot)
        if verdict["verdict"] == "not_found":
            text = str(verdict["message"])
            res.presence("absent", marker=f"HTTP 404 not_found from independent pipelines {', '.join(verdict['pipelines'])}",
                         checked_at=ctx.now(), source=SRC_BRASILAPI)
            if snapshot:
                res.attr("rfb_snapshot", snapshot)
            res.finding(
                "CNPJ not found in RFB open data",
                "info",
                f"{format_cnpj(cnpj)} is {text}. The check digits are valid; a CNPJ that the RFB does not list may be fictitious or "
                "newly opened - confirm it in the official Receita Federal registry before relying on it.",
                confidence="probable",
                criterion=f"not_found from two independent ingestion pipelines of the RFB dump ({', '.join(verdict['pipelines'])})",
                data={"snapshot": snapshot, "pipelines": verdict["pipelines"]},
                source=SRC_BRASILAPI,
            )
            return res
        return self._could_not_verify(res, attempts, str(verdict["message"]))

    def _could_not_verify(self, res: ModuleResult, attempts: list[dict[str, Any]], message: str) -> ModuleResult:
        states = [a["state"] for a in attempts if a["state"] not in ("unsupported",)]
        if states and all(s in ("rate_limited", "skipped") for s in states):
            return res.mark(Status.RATE_LIMITED, message)
        blocked = [a for a in attempts if a["state"] == "blocked"]
        if blocked:
            code = blocked[0].get("reason_code") if blocked[0].get("reason_code") in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
            return res.mark(Status.BLOCKED, message, reason_code=str(code))
        if any(s == "quota" for s in states):
            return res.mark(Status.QUOTA, message)
        if any(s in ("rate_limited", "skipped") for s in states):
            return res.mark(Status.RATE_LIMITED, message)
        if states and all(s == "timeout" for s in states):
            return res.mark(Status.ERROR, message, reason_code="timeout")
        return res.mark(Status.ERROR, message)

    def _emit(self, res: ModuleResult, ctx: Any, merged: dict[str, Any], snapshot: str | None, cnpj: str) -> None:
        fields = merged["fields"]
        individual = bool(merged.get("is_individual"))
        provider = fields["razao_social"]["provider"] or (merged["providers"][0] if merged["providers"] else "")
        label = PROVIDERS[provider].label if provider in PROVIDERS else provider
        source = PROVIDERS[provider].source if provider in PROVIDERS else SRC_BRASILAPI
        data_date = snapshot if provider in ("brasilapi", "minhareceita") else iso_date(_dict(merged["freshness"].get(provider)).get("as_of"))
        situacao = fold(field(merged, "situacao")) or None
        opening = field(merged, "opening_date")
        today = ctx.now().date()
        age = company_age_years(opening, today)

        # ---- attributes (P236 cond 4-5, 13) ------------------------------------------------
        res.attr("legal_name", field(merged, "razao_social"))
        res.attr("trade_name", field(merged, "nome_fantasia"))
        res.attr("status", situacao)
        res.attr("status_date", field(merged, "situacao_date"))
        res.attr("status_reason", field(merged, "situacao_motivo"))
        special = field(merged, "situacao_especial")
        if special:
            res.attr("special_status", {"status": special, "date": field(merged, "situacao_especial_date")})
        res.attr("opened", opening)
        res.attr("company_age_years", age)
        res.attr("branch_type", field(merged, "matriz_filial"))
        res.attr("cnae", field(merged, "cnae_principal"))
        res.attr("cnaes_secondary", field(merged, "cnaes_secundarios"))
        res.attr("legal_nature", field(merged, "natureza_juridica"))
        res.attr("company_size", field(merged, "porte"))
        res.attr("capital", field(merged, "capital_social"))
        res.attr("simples_nacional", field(merged, "simples"))
        res.attr("mei", field(merged, "mei"))
        res.attr("individual_entrepreneur", individual)
        res.attr("federative_entity", field(merged, "ente_federativo"))
        addr = _dict(field(merged, "address"))
        res.attr("address", address_text(addr))
        res.attr("address_details", {k: v for k, v in addr.items() if k != "siafi_code" and v})
        res.attr("rfb_snapshot", snapshot)
        emails = list(field(merged, "emails") or [])
        phones = [p for p in field(merged, "phones") or [] if isinstance(p, dict)]
        res.attr("rfb_emails", emails)
        res.attr("rfb_phones", [p["e164"] for p in phones if p.get("e164")])
        qsa = [p for p in field(merged, "qsa") or [] if isinstance(p, dict)]
        res.attr("partners", [p["name"] for p in qsa if p.get("name")])
        res.attr("qsa", qsa)
        res.attr("qsa_former", merged.get("qsa_former") or [])
        res.attr("state_registrations", field(merged, "state_registrations"))
        res.attr("field_sources", {f: {"provider": PROVIDERS[v["provider"]].label if v["provider"] in PROVIDERS else v["provider"],
                                       "as_of": v["as_of"]} for f, v in fields.items() if v.get("provider")})
        res.attr("field_conflicts", [
            {"field": f, "chosen": {"provider": fields[f]["provider"], "value": fields[f]["value"], "as_of": fields[f]["as_of"]},
             "alternatives": fields[f]["alternatives"]} for f in merged["conflicts"]
        ])
        res.attr("cnpj_card", {
            "provider": label, "data_date": data_date, "status": situacao, "status_plain": STATUS_PLAIN.get(situacao or "", "unknown"),
            "opening_date": opening, "age_years": age,
        })

        # ---- findings (P236 cond 13): no age-only finding -------------------------------------
        if situacao and situacao != "ATIVA":
            when = field(merged, "situacao_date")
            motive = field(merged, "situacao_motivo")
            res.finding(
                f"CNPJ registration status {situacao}",
                "medium",
                f"The Receita Federal lists {format_cnpj(cnpj)} as {situacao} since {when or 'an unknown date'}: "
                f"{STATUS_MEANINGS.get(situacao, 'registration not active')}" + (f" (reason: {motive})." if motive else "."),
                confidence="confirmed",
                criterion=f"RFB situacao cadastral {situacao} since {when or 'unknown date'} as published by {label} (RFB open data)",
                data={"status": situacao, "since": when, "reason": motive, "meaning": STATUS_MEANINGS.get(situacao), "provider": label,
                      "data_date": data_date},
                tags=["company_status"],
                source=source,
                observed_first=when,
            )

        # ---- pivots (P236 cond 8-13) ----------------------------------------------------------
        legal = strip_cpf_fragments(field(merged, "razao_social"))
        if legal and not individual:
            res.pivot(T.ORG, legal, "legal_name", confidence="confirmed", expand=False,
                      note="registered legal name (RFB): listed for the analyst, never sent to a name-to-CNPJ resolver automatically")
        if addr.get("cep") and not individual:
            res.pivot(T.CEP, addr["cep"], "located_at", confidence=WEAK_EDGE, expand=False,
                      note="registered address CEP (RFB): shared by unrelated companies, never same-owner evidence")
        self._contacts(res, ctx, emails, phones, cnpj, individual)
        self._partners(res, ctx, qsa)

    def _contacts(self, res: ModuleResult, ctx: Any, emails: list[str], phones: list[dict[str, Any]], cnpj: str, individual: bool) -> None:
        note = REGISTRY_CONTACT_LABEL + ("; MEI/EI registration: personal data" if individual else "") + \
            "; never expanded into breach, infostealer, username or phone-reputation lookups"
        for e in emails:
            res.pivot(T.EMAIL, e, "rfb_contact", confidence=WEAK_EDGE, expand=False, note=note)
        for p in phones:
            if p.get("e164"):
                res.pivot(T.PHONE, p["e164"], "rfb_contact", confidence=WEAK_EDGE, expand=False, note=note)
        root = cnpj[:8]
        rdap_left = MAX_RDAP_LOOKUPS
        seen: set[str] = set()
        for e in emails:
            dom = email_domain(e)
            if not dom or is_webmail(dom):
                continue
            reg = psl.registrable_domain(dom) or dom
            if reg in seen or is_webmail(reg):
                continue
            seen.add(reg)
            tied: bool | None = None
            if reg.endswith(".br") and rdap_left > 0:
                rdap_left -= 1
                tied = self._rdap_tie(res, ctx, reg, root)
            if tied:
                res.pivot(T.DOMAIN, reg, "rfb_contact_domain", confidence="confirmed", expand=True,
                          note="domain of the RFB registry e-mail; registro.br RDAP lists a registrant CNPJ with the same root")
            else:
                why = ("registro.br RDAP could not verify the registrant" if tied is None and reg.endswith(".br")
                       else "registrant is another company" if tied is False else "no registro.br RDAP for this TLD")
                res.pivot(T.DOMAIN, reg, "rfb_contact_domain", confidence=WEAK_EDGE, expand=False,
                          note=f"{REGISTRY_CONTACT_LABEL}: third-party domain until confirmed ({why}); passive modules only")

    def _rdap_tie(self, res: ModuleResult, ctx: Any, domain: str, root: str) -> bool | None:
        """True when registro.br RDAP lists a registrant CNPJ with the same 8-character root, False when
        it lists another or none, None when it could not be verified."""
        remaining = ctx.remaining()
        if remaining is not None and remaining < 2.0:
            return None
        budget = RDAP_TIMEOUT_S if remaining is None else min(RDAP_TIMEOUT_S, max(1.0, remaining - 1.0))
        try:
            data = ctx.http.get_json(RDAP_URL.format(domain=domain), source=SRC_RDAP, absent={404}, timeout=budget,
                                     deadline=_mono(ctx) + budget, retries=0)
        except (Blocked, AuthRequired) as exc:
            code = str(getattr(exc, "reason_code", "") or "challenge")
            res.source_status(SRC_RDAP, Status.BLOCKED, reason_code=code if code in ("challenge", "geo_block", "login_wall", "circuit") else "challenge",
                              reason=f"registro.br RDAP {domain}: {exc}"[:300])
            return None
        except RateLimited as exc:
            res.source_status(SRC_RDAP, Status.RATE_LIMITED, reason=f"registro.br RDAP {domain}: {exc}"[:300])
            return None
        except QuotaExceeded as exc:
            res.source_status(SRC_RDAP, Status.QUOTA, reason=f"registro.br RDAP {domain}: {exc}"[:300])
            return None
        except DeadlineExceeded as exc:
            res.source_status(SRC_RDAP, Status.ERROR, reason_code="timeout", reason=f"registro.br RDAP {domain}: {exc}"[:300])
            return None
        except (HttpError, NetworkError) as exc:
            res.source_status(SRC_RDAP, Status.ERROR, reason=f"registro.br RDAP {domain}: {exc}"[:300])
            return None
        if data is None:
            res.source_status(SRC_RDAP, Status.EMPTY, reason=f"{domain}: not registered at registro.br (HTTP 404)")
            return False
        roots = {c[:8] for c in rdap_registrant_cnpjs(data)}
        res.source_status(SRC_RDAP, Status.OK)
        return root in roots

    def _partners(self, res: ModuleResult, ctx: Any, qsa: list[dict[str, Any]]) -> None:
        try:
            depth_limit = int(ctx.setting("cnpj_lookup_partner_depth", 1) or 1)
        except (TypeError, ValueError):
            depth_limit = 1
        depth_limit = min(2, max(1, depth_limit))
        expand_pj = int(getattr(ctx, "depth", 0) or 0) + 1 <= depth_limit
        n_pj = 0
        for p in qsa:
            name = strip_cpf_fragments(p.get("name"))
            if p.get("kind") == "PJ" and p.get("cnpj"):
                if n_pj >= PJ_PARTNER_CAP:
                    continue
                n_pj += 1
                res.pivot(T.CNPJ, p["cnpj"], "partner_of", confidence="confirmed", expand=expand_pj,
                          note="partner company (QSA, RFB): third party - passive modules only, never a LIGHT/ACTIVE seed, "
                               "an org-profile entry or a scope target")
            elif not name:
                continue
            elif p.get("kind") == "PF" or not looks_corporate(name):
                res.pivot(T.PERSON, name, "partner_of", confidence=WEAK_EDGE, expand=False,
                          note="QSA partner as published by the RFB: name only, identity not established; the masked CPF and the "
                               "age band stay in the CNPJ card")
            else:
                res.pivot(T.ORG, name, "partner_of", confidence="probable", expand=False,
                          note="corporate partner without a CNPJ in the QSA (foreign or untyped): listed for the analyst")


class _Failure(Exception):
    """A provider request that did not produce an answer (a chain state)."""

    def __init__(self, state: str, reason: str, code: str) -> None:
        super().__init__(reason)
        self.state = state
        self.reason = reason
        self.code = code


def _label(kind: str) -> str:
    if kind == "qd_partners":
        return "Querido Diario partners"
    return PROVIDERS[kind].label if kind in PROVIDERS else kind


def _cacheable(kind: str) -> Any:
    """cache_if hook: only records and documented not-found answers enter the HTTP cache (P236 cond 7)."""

    def ok(resp: Any) -> bool:
        js = as_json(resp.content)
        if resp.status == 200:
            return _has_record("qd_partners" if kind == "qd_partners" else kind, js) and receitaws_error(js) is None
        if resp.status == 404:
            return _not_found_body(js)
        return False

    return ok


__all__ = [
    "CHAIN_BUDGET_S",
    "PENDING_TERMS_REVIEW",
    "PROVIDERS",
    "PROVIDER_TIMEOUT_S",
    "RELEASE_CHAIN",
    "CnpjLookup",
    "answer_state",
    "bucket_charge",
    "bucket_wait",
    "format_cnpj",
    "is_webmail",
    "mask_cpf",
    "mask_cpfs_in_text",
    "mask_for_evidence",
    "merge_records",
    "normalize_cnpj",
    "not_found_verdict",
    "parse_brasilapi",
    "parse_cnpja",
    "parse_cnpjws",
    "parse_opencnpj",
    "parse_qd",
    "parse_receitaws",
    "rdap_registrant_cnpjs",
    "receitaws_error",
]
