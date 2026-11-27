"""Domain ownership verifier (P013 ``domain_ownership``, port of the Ceos ``dominios.Verificador``).

"Is this domain really the company's?" - answered before attack-surface or typosquat conclusions,
for the organisation profile (A11) and for a company the analyst queried (a typed CNPJ or company
name seed). P013 is a **correlation rule over facts already in the graph** (final condition 1, the
architect's floor): no client, no host, no key, **no network call**. The Ceos verifier's own homepage
visit, crt.sh and RDAP calls are not ported.

Facts read (FC1) and their producers:

* registry - ``rdap`` (P003/P001): ``registered``, ``cnpj_roots`` (registro.br publicIds), ``registrant``
  (organisation), ``registrant_kind``, ``created`` / ``domain_age_days``; a BLOCKED / RATE_LIMITED /
  ERROR rdap run is 'RDAP could not be verified' (never a contradiction).
* certificates - attribute ``cert_organizations`` (``[{o, validation EV|OV|IV, names, source,
  given_name, surname}]``, declared by this batch for Cert Spotter ``cert_der`` / Censys / tls_inspect
  producers) and the LIGHT ``tls_certificate`` handshake fact (subject ``O=`` of a chain-verified,
  hostname-matching, not self-signed certificate: CA/B Forum rules allow ``O=`` only in OV/EV).
  crt.sh JSON carries no subject DN, so ``ct_logs`` alone never gives an ``O=`` (noted in the verdict).
* DNS tenancy - ``mx``, ``spf``, ``spf_includes`` (dns_records / email_security_posture) and
  ``m365_tenant_id`` (m365_tenant / m365_tenant_azmap). Shared providers (Microsoft 365, Google
  Workspace MX/SPF) alone are never evidence (AR06).
* homepage - ``homepage_indicators`` / ``site_contacts`` (``cnpjs``, optional ``invalid_cnpjs``,
  ``commercial`` / ``commerce_markers``, ``marker``, ``status``) and CNPJ pivots written by the homepage producers in
  :data:`HOMEPAGE_SOURCES`: live ``web_fingerprint`` / ``site_contacts`` (LIGHT, analyst-typed seeds
  only) or archived snapshots (``web_archives`` P059, ``web_fingerprint_archive``...). Candidates from
  typosquat / NRD / CT are never fetched by this rule (FC7).
* subjects - the org profile (``cnpj_roots``, ``domains``, ``app_ids`` kind ``m365_tenant``, ``name``)
  plus ``legal_name`` facts of its CNPJ roots (cnpj_lookup); a queried company is an analyst-typed
  ``cnpj`` seed (root + ``legal_name``) or ``company_name`` seed.

Final conditions and where they live:

1. Rule only (this file, ``v3lum/correlations/``); facts above; nothing imported from the HTTP/DNS stack.
2. CONFIRMED only from authoritative data (:func:`assess_domain_ownership`): the RDAP registrant CNPJ
   root equals a subject root, or the domain is an org-profile own domain (PSL + label-wise
   membership, ``OrgProfile.domain_entry``). Only CONFIRMED carries the ``own_asset`` / ``known_good``
   marks (tags of the verdict; the engine never gets them from a weaker level).
3. PROBABLE at most from an OV/EV certificate ``O=`` match (0.60; 0.75 with a tenancy signal: same
   M365 tenant id, MX hosted on / SPF include of a subject domain) or an RDAP registrant organisation
   name vetted by the registry (registro.br, no CNPJ: Ceos rule kept). A self-declared registrant
   organisation (gTLDs: anyone can type a victim's name) and a CNPJ printed on the site are at most
   POSSIBLE, worded 'unconfirmed link'; a tenancy signal alone is POSSIBLE too. An RDAP registrant
   naming another CNPJ root caps everything at POSSIBLE and voids the site CNPJ.
4. ``domain_ownership_cnpj_mismatch`` (MEDIUM, tags fraud + clone_indicator): a valid site CNPJ root
   differs from the RDAP registrant root (probable), or a valid site CNPJ on a domain <= 90 days old
   without a registry CNPJ (possible). Site CNPJs are re-validated offline by check digits
   (``validators.cnpj_valid``, P232, alphanumeric included); ``domain_ownership_invalid_cnpj`` (LOW,
   suspicious) when a CNPJ failing them is shown on a commercial page (a note otherwise).
5. Every verdict lists evidence bullets with evidence ids (``ev:`` + the producing run's evidence
   SHA-256 prefix, or a deterministic hash of the fact). In passive mode only RDAP/CT/DNS facts are
   used (setting ``ownership_archive_in_passive``, default False, admits archived snapshots) and the
   verdict says when no homepage evidence was available.
6. ``domain_ownership_person``: only for a person the analyst typed as a seed, in a case with a
   recorded purpose (``--purpose``), from public registrant data already in the graph
   (``registrant_person`` {name, cpf_masked} when the RDAP producer keeps it, IV certificate subjects).
   POSSIBLE/PROBABLE only, tagged privacy, never a pivot; the seed CPF is compared on the visible
   registry digits only and never appears in any output (only the registry's masked form).
7. Homepage facts only from :data:`HOMEPAGE_SOURCES` (live ones only on analyst-typed seeds). CONFIRMED /
   PROBABLE results for the org become ``org seed`` proposals (tag ``org_seed_candidate``, analyst
   confirmation required); nothing here touches the scope or schedules anything.
8. Unit tests on synthetic graphs (tests/modules/test_domain_ownership.py and
   tests/fixtures/rules/domain_ownership*/): one per level, the copied footer and the RDAP-contradicted
   footer.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from v3lum.core import psl
from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType, mask_cpf
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Opsec, Severity, Status
from v3lum.core.validators import cnpj_valid

__all__ = [
    "HOMEPAGE_ATTRIBUTES",
    "HOMEPAGE_SOURCES",
    "LABELS",
    "LABEL_UNVERIFIED",
    "LEVEL_CONFIDENCE",
    "RULE_INVALID",
    "RULE_MISMATCH",
    "RULE_PERSON",
    "RULE_VERDICT",
    "GraphIndex",
    "Subject",
    "assess_domain_ownership",
    "assess_person_ownership",
    "build_index",
    "cnpj_normalize",
    "cnpj_root",
    "cpf_mask_compatible",
    "domain_facts",
    "domain_findings",
    "evaluate",
    "evidence_id",
    "org_name_key",
    "org_names_match",
    "org_seed_proposal",
    "parse_dn",
    "registry_verifies_holder",
    "site_cnpj_facts",
    "subjects",
]

RULE_VERDICT = "domain_ownership"
RULE_MISMATCH = "domain_ownership_cnpj_mismatch"
RULE_INVALID = "domain_ownership_invalid_cnpj"
RULE_PERSON = "domain_ownership_person"

#: Confidence per level (P322 bands: >= .85 confirmed, >= .55 probable, else possible).
LEVEL_CONFIDENCE = {"CONFIRMED": 0.95, "PROBABLE": 0.6, "POSSIBLE": 0.4}
LABELS = {"CONFIRMED": "confirmed owner", "PROBABLE": "probable owner", "POSSIBLE": "unconfirmed link"}
#: Homepage producers: 'live' (LIGHT fetch of an analyst-typed seed) or 'archive' (archived snapshot).
HOMEPAGE_SOURCES: dict[str, str] = {
    "web_fingerprint": "live",
    "site_contacts": "live",
    "web_fingerprint_archive": "archive",
    "site_contacts_archive": "archive",
    "web_archives": "archive",
    "web_archives_deep": "archive",
    "web_archives_ukwa": "archive",
}
#: Homepage fact attributes carrying the CNPJs printed on a page (P059 archives, P077 site contacts).
HOMEPAGE_ATTRIBUTES = ("homepage_indicators", "site_contacts")
#: Producers of registry facts (registrant CNPJ roots, organisation, creation date).
REGISTRY_SOURCES = frozenset({"rdap"})
CT_SOURCES = frozenset({"ct_logs", "ct_logs_extra"})
#: Setting that admits archived homepage snapshots in passive mode (FC5 strict reading by default).
ARCHIVE_IN_PASSIVE_SETTING = "ownership_archive_in_passive"
#: Run statuses that mean 'could not verify' (403 / 429 / quota / timeouts and errors): never 'no evidence'.
_UNVERIFIED_STATUSES = frozenset({"blocked", "rate_limited", "quota", "error"})
COULD_NOT_VERIFY = "could_not_verify"
LABEL_UNVERIFIED = "could not verify (registry unavailable)"
NEW_DOMAIN_DAYS = 90
MAX_DOMAINS = 300
MAX_COMPANY_SUBJECTS = 5
MAX_PERSON_DOMAINS = 25
MAX_SITE_CNPJS = 20
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CNPJ_RE = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")
#: Shared mail providers: never evidence on their own (AR06), only named in a note.
_SHARED_MX = (("microsoft 365", re.compile(r"\.mail\.protection\.(?:outlook\.com|partner\.outlook\.cn)$")),
              ("google workspace", re.compile(r"(?:^|\.)(?:google\.com|googlemail\.com)$")))
_SHARED_SPF = (("microsoft 365", re.compile(r"^spf\.protection\.(?:outlook\.com|partner\.outlook\.cn)$")),
               ("google workspace", re.compile(r"^_spf\.google\.com$")))


# ======================================================================================
# identifiers, names, dates
# ======================================================================================


def cnpj_normalize(value: Any) -> str | None:
    """'12.abc.345/01de-35' -> '12ABC34501DE35'; None unless 14 characters of the P232 alphabet."""
    if not isinstance(value, str):
        return None
    v = re.sub(r"[\s./\-]", "", value.strip()).upper()
    return v if _CNPJ_RE.match(v) else None


def cnpj_root(value: Any) -> str | None:
    """8-character root of a CNPJ or of a root (numeric roots that lost leading zeros are padded)."""
    if not isinstance(value, str):
        return None
    v = re.sub(r"[\s./\-]", "", value.strip()).upper()
    if len(v) == 14 and _CNPJ_RE.match(v):
        return v[:8]
    if re.fullmatch(r"[0-9A-Z]{8}", v):
        return v
    if re.fullmatch(r"\d{1,7}", v):
        return v.zfill(8)
    return None


def _cnpj_display(norm: str) -> str:
    return f"{norm[:2]}.{norm[2:5]}.{norm[5:8]}/{norm[8:12]}-{norm[12:]}" if len(norm) == 14 else norm


def _fold(text: Any) -> str:
    """Accent-folded upper-case ASCII; anything but letters and digits becomes a space."""
    t = unicodedata.normalize("NFKD", str(text or "")).encode("ascii", "ignore").decode()
    t = re.sub(r"[^A-Za-z0-9 ]", " ", t)
    return re.sub(r"\s+", " ", t).strip().upper()


_CORP_TOKENS = frozenset({
    "LTDA", "LIMITADA", "ME", "EPP", "EIRELI", "SA", "S", "A", "CIA", "COMPANHIA", "SOCIEDADE", "ANONIMA",
    "UNIPESSOAL", "SLU", "SS", "INC", "LLC", "LTD", "LIMITED", "CORP", "CORPORATION", "GMBH", "PLC", "CO",
    "DE", "DA", "DO", "DOS", "DAS", "E", "THE", "AND", "OF",
})
_PARTICLES = frozenset({"DE", "DA", "DO", "DOS", "DAS", "E"})


def org_name_key(name: Any) -> str:
    """Comparable organisation key: folded, corporate forms and particles removed
    ('Exemplo Comercio Ltda' and 'EXEMPLO COMÉRCIO LTDA.' -> 'EXEMPLO COMERCIO')."""
    return " ".join(t for t in _fold(name).split() if t not in _CORP_TOKENS)


def org_names_match(a: Any, b: Any) -> bool:
    """Exact match of the organisation keys (>= 4 characters). Containment is NOT a match: group
    companies ('EXEMPLO' vs 'EXEMPLO PAGAMENTOS') are distinct legal entities."""
    ka, kb = org_name_key(a), org_name_key(b)
    return bool(ka) and len(ka.replace(" ", "")) >= 4 and ka == kb


def _person_tokens(name: Any) -> list[str]:
    return [t for t in _fold(name).split() if t not in _PARTICLES and not t.isdigit()]


def person_names_equal(a: Any, b: Any) -> bool:
    ta, tb = _person_tokens(a), _person_tokens(b)
    return len(ta) >= 2 and ta == tb


def person_name_contained(seed: Any, record: Any) -> bool:
    """Ceos nome_compativel: the seed name inside the record name, same first and last token, in order."""
    a, b = _person_tokens(seed), _person_tokens(record)
    if len(a) < 2 or a == b or len(b) <= len(a) or a[0] != b[0] or a[-1] != b[-1]:
        return False
    it = iter(b)
    return all(t in it for t in a)


def cpf_mask_compatible(registry_value: Any, seed_cpf: Any) -> bool:
    """FC6: an analyst-typed CPF against a registry CPF (masked or not) on the digits the registry
    shows (>= 5 visible digits, all equal). Only a boolean leaves this function; nothing is completed
    or revealed."""
    a = re.sub(r"[^\d*]", "", str(registry_value or ""))
    b = re.sub(r"\D", "", str(seed_cpf or ""))
    if len(a) != 11 or len(b) != 11:
        return False
    common = [(x, y) for x, y in zip(a, b) if x != "*"]
    return len(common) >= 5 and all(x == y for x, y in common)


def _registry_cpf_display(value: Any) -> str | None:
    """The registry CPF as it may be shown: its own mask, or the AR24 mask when it came unmasked."""
    text = re.sub(r"[^\d*]", "", str(value or ""))
    if len(text) != 11:
        return None
    if "*" in text:
        return f"{text[:3]}.{text[3:6]}.{text[6:9]}-{text[9:]}"
    return mask_cpf(text)


def _host(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    h = value.strip().lower().rstrip(".")
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h).split("/")[0].split("?")[0].split("#")[0]
    h = h.rsplit("@", 1)[-1].split(":")[0]
    if h.startswith("*."):
        h = h[2:]
    if h and not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return h if re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+", h or "") else ""


def host_in(host: Any, domains: Iterable[str]) -> bool:
    """Label-boundary membership (A11: never a plain string-suffix match)."""
    h = _host(host)
    if not h:
        return False
    for d in domains:
        dn = _host(d)
        if dn and (h == dn or h.endswith("." + dn)):
            return True
    return False


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        try:
            when = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _now(rctx: Any) -> datetime:
    now = getattr(rctx, "now", None)
    if not isinstance(now, datetime):
        now = datetime.now(timezone.utc)
    return now if now.tzinfo else now.replace(tzinfo=timezone.utc)


def registry_verifies_holder(registrable: Any, rdap_server: Any = "") -> bool:
    """Does the registry vet the registrant organisation? registro.br ties every .br holder to a
    Receita Federal CNPJ/CPF; gTLD and most ccTLD registrant organisations are self-declared at the
    registrar (anyone can type a victim's company name), so they are never more than an unconfirmed link."""
    reg, server = _host(registrable), _host(rdap_server)
    return reg.endswith(".br") or server == "registro.br" or server.endswith(".registro.br")


def evidence_id(domain: str, kind: str, value: Any) -> str:
    """Deterministic evidence id of a fact (used when the producing run saved no evidence file)."""
    return "ev:" + hashlib.sha256(f"{_host(domain) or domain}|{kind}|{value}".encode()).hexdigest()[:12]


# ======================================================================================
# certificates (DN parsing for the tls_certificate subject)
# ======================================================================================

_DN_ALIASES = {
    "cn": "CN", "commonname": "CN", "2.5.4.3": "CN",
    "o": "O", "organizationname": "O", "2.5.4.10": "O",
    "ou": "OU", "organizationalunitname": "OU", "2.5.4.11": "OU",
    "c": "C", "countryname": "C", "2.5.4.6": "C",
    "serialnumber": "serialNumber", "2.5.4.5": "serialNumber",
    "businesscategory": "businessCategory", "2.5.4.15": "businessCategory",
    "jurisdictionc": "jurisdictionC", "jurisdictioncountryname": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
    "gn": "GN", "givenname": "GN", "2.5.4.42": "GN",
    "sn": "SN", "surname": "SN", "2.5.4.4": "SN",
}


def _dn_key(key: str) -> str:
    k = key.strip()
    return _DN_ALIASES.get(k.lower(), k)


def _clean(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    return re.sub(r"\s+", " ", value).strip()[:limit]


def parse_dn(dn: Any) -> list[tuple[str, str]]:
    """[(key, value)] from a one-line DN ('C=BR, O=Exemplo Ltda, CN=...' or RFC 4514 with escapes and
    quotes), a {key: value} mapping or the ssl.getpeercert() tuple form; keys normalised (O, CN, C,
    OU, GN, SN, serialNumber, businessCategory, jurisdictionC)."""
    out: list[tuple[str, str]] = []
    if isinstance(dn, dict):
        for k, v in list(dn.items())[:50]:
            for item in v if isinstance(v, list) else [v]:
                if isinstance(k, str) and isinstance(item, str):
                    out.append((_dn_key(k), _clean(item)))
        return out
    if isinstance(dn, (list, tuple)):
        for rdn in list(dn)[:50]:
            for pair in rdn if isinstance(rdn, (list, tuple)) else []:
                if isinstance(pair, (list, tuple)) and len(pair) == 2 and isinstance(pair[0], str):
                    out.append((_dn_key(pair[0]), _clean(str(pair[1]))))
        return out
    if not isinstance(dn, str):
        return out
    parts: list[str] = []
    buf: list[str] = []
    quoted = escaped = False
    for ch in dn[:4096]:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch in ",;+" and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out.append((_dn_key(k), _clean(v.strip().strip('"'))))
    return out


def _dn_get(attrs: list[tuple[str, str]], key: str) -> str:
    return next((v for k, v in attrs if k == key and v), "")


def _cert_facts(node: Node) -> list[dict[str, Any]]:
    """Certificate subject facts of a domain node: ``cert_organizations`` items and the subject of a
    trusted live handshake (``tls_certificate``)."""
    out: list[dict[str, Any]] = []
    for value, source in node.attributes.get("cert_organizations", []) or []:
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, dict):
                continue
            level = str(item.get("validation") or "").upper()
            names = [n for n in (_host(x) for x in (item.get("names") or [])[:200] if isinstance(x, str)) if n]
            out.append({
                "o": _clean(item.get("o") or item.get("organization"), 200),
                "validation": level if level in ("EV", "OV", "IV", "DV") else "unknown",
                "names": names,
                "given_name": _clean(item.get("given_name"), 100),
                "surname": _clean(item.get("surname"), 100),
                "source": _clean(item.get("source"), 60) or source,
                "module": source,
            })
    for value, source in node.attributes.get("tls_certificate", []) or []:
        if not isinstance(value, dict):
            continue
        if value.get("chain_verified") is not True or value.get("self_signed") is True or value.get("hostname_match") is False:
            continue  # only a publicly trusted certificate presented for this name says anything about O=
        attrs = parse_dn(value.get("subject"))
        org, gn, sn = _dn_get(attrs, "O"), _dn_get(attrs, "GN"), _dn_get(attrs, "SN")
        if org:
            level = "EV" if _dn_get(attrs, "jurisdictionC") and _dn_get(attrs, "businessCategory") else "OV"
        elif gn or sn:
            level = "IV"
        else:
            level = "DV"
        out.append({"o": org, "validation": level, "names": [], "given_name": gn, "surname": sn,
                    "source": "tls handshake (subject shape)", "module": source})
    return out


# ======================================================================================
# subjects
# ======================================================================================


@dataclass
class Subject:
    """Whose ownership is assessed: the org profile or a company the analyst queried."""

    scope: str  # 'org' | 'company'
    key: str  # 'org' | 'cnpj:<root>' | 'company_name:<hash>'
    roots: set[str] = field(default_factory=set)
    names: list[str] = field(default_factory=list)
    profile_domains: list[tuple[str, str]] = field(default_factory=list)  # (name, verification), org only
    anchors: set[str] = field(default_factory=set)  # registrable domains known to be the subject's
    tenant_ids: set[str] = field(default_factory=set)
    entity: Entity | None = None
    node_key: str = ""

    @property
    def label(self) -> str:
        return "org" if self.scope == "org" else "queried company"


def _options(rctx: Any) -> Any:
    return getattr(rctx, "options", None)


def analyst_seed(node: Node | None, rctx: Any) -> bool:
    """An analyst-typed seed: a seed at depth 0 that the analyst did not leave unconfirmed (AR07)."""
    if node is None or not node.seed or node.depth != 0:
        return False
    unconfirmed = getattr(_options(rctx), "unconfirmed_seeds", None) or set()
    return node.key not in unconfirmed


def _flat(values: Iterable[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        for item in value if isinstance(value, (list, tuple, set)) else [value]:
            if item not in out:
                out.append(item)
    return out


def _vals(node: Node | None, key: str, sources: Iterable[str] | None = None) -> list[Any]:
    if node is None:
        return []
    allowed = set(sources) if sources is not None else None
    return _flat(v for v, s in node.attributes.get(key, []) or [] if allowed is None or s in allowed)


def _legal_names(graph: Graph, roots: set[str]) -> list[str]:
    names: list[str] = []
    for node in graph.of_type(EntityType.CNPJ):
        if cnpj_root(str(node.entity.value)) in roots:
            for name in _vals(node, "legal_name"):
                if isinstance(name, str) and name.strip() and name not in names:
                    names.append(name.strip())
    return names


def _registry_roots(node: Node | None) -> set[str]:
    return {r for r in (cnpj_root(x) for x in _vals(node, "cnpj_roots", REGISTRY_SOURCES) if isinstance(x, str)) if r}


def _tenant_ids(node: Node | None) -> set[str]:
    return {str(t).strip().lower() for t in _vals(node, "m365_tenant_id") if isinstance(t, str) and _GUID.match(t.strip().lower())}


def subjects(graph: Graph, rctx: Any) -> list[Subject]:
    """The org-profile subject (when a profile is loaded) and up to five queried companies."""
    out: list[Subject] = []
    org = getattr(rctx, "org", None)
    org_roots: set[str] = set()
    if org is not None and not getattr(org, "is_empty", True):
        org_roots = {r for r in (cnpj_root(str(x)) for x in getattr(org, "cnpj_roots", []) or []) if r}
        names = [n for n in [getattr(org, "name", "")] if isinstance(n, str) and n.strip()]
        names += [n for n in _legal_names(graph, org_roots) if n not in names]
        profile_domains = [(e.name, e.verification) for e in getattr(org, "domains", []) or [] if getattr(e, "name", "")]
        tenants = {str(a.value).strip().lower() for a in getattr(org, "app_ids", []) or []
                   if getattr(a, "kind", "") == "m365_tenant" and _GUID.match(str(a.value).strip().lower())}
        out.append(Subject("org", "org", org_roots, names, profile_domains, {d for d, _v in profile_domains}, tenants))
    companies = 0
    for node in sorted(graph.seeds(), key=lambda n: n.key):
        if companies >= MAX_COMPANY_SUBJECTS:
            break
        if not analyst_seed(node, rctx):
            continue
        if node.entity.type is EntityType.CNPJ:
            root = cnpj_root(str(node.entity.value))
            if not root or root in org_roots or any(s.key == f"cnpj:{root}" for s in out):
                continue
            out.append(Subject("company", f"cnpj:{root}", {root}, _legal_names(graph, {root}), entity=node.entity, node_key=node.key))
            companies += 1
        elif node.entity.type is EntityType.ORG:
            name = str(node.entity.value or "").strip()
            if not org_name_key(name):
                continue
            key = "company_name:" + hashlib.sha256(org_name_key(name).encode()).hexdigest()[:12]
            if any(s.key == key for s in out):
                continue
            out.append(Subject("company", key, set(), [name], entity=node.entity, node_key=node.key))
            companies += 1
    # registry-confirmed domains of each subject anchor the tenancy signals (MX / SPF / M365 tenant)
    for node in graph.of_type(EntityType.DOMAIN):
        roots = _registry_roots(node)
        reg = psl.registrable_domain(str(node.entity.value))
        for subject in out:
            if reg and roots & subject.roots:
                subject.anchors.add(reg)
    for subject in out:
        for node in graph.of_type(EntityType.DOMAIN):
            if host_in(str(node.entity.value), subject.anchors):
                subject.tenant_ids |= _tenant_ids(node)
    return out


# ======================================================================================
# facts of a domain
# ======================================================================================


_HOMEPAGE_URL = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]+)/?(?:#.*)?$", re.I)


@dataclass
class GraphIndex:
    """Per-run lookups: module results by (module, entity key), out-edges by source key and the
    homepage URL nodes (``https://<host>/``, no path or query) by host."""

    results: dict[tuple[str, str], ModuleResult] = field(default_factory=dict)
    out_edges: dict[str, list[Any]] = field(default_factory=dict)
    homepages: dict[str, list[Node]] = field(default_factory=dict)

    def adjacent(self, a: str, b: str) -> bool:
        return any(e.dst == b for e in self.out_edges.get(a, ())) or any(e.dst == a for e in self.out_edges.get(b, ()))


def build_index(graph: Graph, results: Iterable[ModuleResult] | None) -> GraphIndex:
    index = GraphIndex()
    for res in results or []:
        entity = getattr(res, "entity", None)
        module = getattr(res, "module", "")
        if isinstance(entity, Entity) and module:
            index.results.setdefault((module, entity.key), res)
    for edge in graph.edges:
        index.out_edges.setdefault(edge.src, []).append(edge)
    for node in graph.of_type(EntityType.URL):
        m = _HOMEPAGE_URL.match(str(node.entity.value))
        host = _host(m.group(1)) if m else ""
        if host:
            index.homepages.setdefault(host, []).append(node)
    return index


def _evidence_ref(index: GraphIndex, modules: Iterable[str], keys: Iterable[str]) -> str | None:
    keys = list(keys)
    for module in modules:
        for key in keys:
            res = index.results.get((module, key))
            sha = getattr(res, "evidence_sha256", "") if res is not None else ""
            if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{12,64}", sha):
                return "ev:" + sha[:12]
    return None


def _run_status(index: GraphIndex, modules: Iterable[str], keys: Iterable[str]) -> str | None:
    keys = list(keys)
    for module in modules:
        for key in keys:
            res = index.results.get((module, key))
            if res is None:
                continue
            status = getattr(res, "status", None)
            if status in (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA):
                return str(status.value)
            if status in (Status.ERROR, Status.UNAVAILABLE, Status.NEEDS_KEY):
                return "error"
            if status is Status.SKIPPED:
                return "skipped"
            return "ok"
    return None


def site_cnpj_facts(value: Any) -> dict[str, Any]:
    """CNPJs of one homepage fact (``homepage_indicators``-shaped mapping), re-validated offline by
    check digits (P232): {valid: {norm}, invalid: {norm}, commercial, marker}."""
    out: dict[str, Any] = {"valid": set(), "invalid": set(), "commercial": False, "marker": None}
    if not isinstance(value, dict):
        return out
    items = value.get("cnpjs") if isinstance(value.get("cnpjs"), list) else []
    extra = value.get("invalid_cnpjs") if isinstance(value.get("invalid_cnpjs"), list) else []
    for item in (items + extra)[: MAX_SITE_CNPJS * 2]:
        raw = item.get("value") or item.get("cnpj") if isinstance(item, dict) else item
        norm = cnpj_normalize(raw) if isinstance(raw, str) else None
        if not norm:
            continue
        (out["valid"] if cnpj_valid(norm) else out["invalid"]).add(norm)
    markers = value.get("commerce_markers") if isinstance(value.get("commerce_markers"), list) else []
    out["commercial"] = value.get("commercial") is True or len(markers) >= 2
    marker = value.get("marker")
    status = value.get("status")
    if isinstance(marker, str) and marker.strip():
        out["marker"] = _clean(marker, 80)
    elif isinstance(status, int) and not isinstance(status, bool) and status >= 400:
        out["marker"] = f"http_{status}"
    return out


def _homepage(graph: Graph, index: GraphIndex, nodes: list[Node], rctx: Any, mode: Opsec, allow_archive: bool) -> dict[str, Any]:
    """Usable homepage facts of a domain (FC5/FC7) and the homepage-evidence state."""
    states: list[str] = []
    valid: dict[str, str] = {}  # norm -> 'live' | 'archive'
    invalid: set[str] = set()
    commercial = False
    captured: list[str] = []

    def gate(kind: str | None, holder: Node) -> str:
        if kind is None:
            return "ignored_source"
        if kind == "live" and not analyst_seed(holder, rctx):
            return "ignored_not_seed"
        if mode is Opsec.PASSIVE and (kind == "live" or not allow_archive):
            return "excluded_passive_mode"
        return "used"

    for holder in nodes:
        pairs = [pair for attr in HOMEPAGE_ATTRIBUTES for pair in holder.attributes.get(attr, []) or []]
        for value, source in pairs:
            kind = HOMEPAGE_SOURCES.get(source)
            state = gate(kind, holder)
            facts = site_cnpj_facts(value)
            if state == "used" and facts["marker"]:
                state = f"unusable:{facts['marker']}"
            states.append(state)
            if state != "used":
                continue
            for norm in facts["valid"]:
                valid.setdefault(norm, kind or "archive")
            invalid |= facts["invalid"]
            commercial = commercial or facts["commercial"]
            when = value.get("captured_at") if isinstance(value, dict) else None
            if isinstance(when, str) and when[:10] not in captured:
                captured.append(when[:10])
        for edge in index.out_edges.get(holder.key, ()):
            kind = HOMEPAGE_SOURCES.get(edge.module)
            dst = graph.get(edge.dst)
            if kind is None or dst is None or dst.entity.type is not EntityType.CNPJ or edge.relation == "registrant":
                continue
            state = gate(kind, holder)
            states.append(state)
            norm = cnpj_normalize(str(dst.entity.value))
            if state == "used" and norm:
                if cnpj_valid(norm):
                    valid.setdefault(norm, kind)
                else:
                    invalid.add(norm)
    if "used" in states:
        hp_state = "used"
    elif not states:
        hp_state = "none_available"
        # a homepage producer that was refused / rate limited / failed is 'could not verify', never 'nothing there'
        keys = [h.key for h in nodes]
        statuses = {s for s in (_run_status(index, [m], keys) for m in sorted(HOMEPAGE_SOURCES)) if s}
        failed = sorted(statuses & _UNVERIFIED_STATUSES)
        if failed and "ok" not in statuses:
            hp_state = f"{COULD_NOT_VERIFY}:{failed[0]}"
    else:
        order = ("excluded_passive_mode", "ignored_not_seed", "unusable", "ignored_source")
        hp_state = next((s for prefix in order for s in states if s.startswith(prefix)), states[0])
    sorted_valid = sorted(valid)[:MAX_SITE_CNPJS]
    return {
        "state": hp_state,
        "valid": sorted_valid,
        "valid_roots": sorted({n[:8] for n in sorted_valid}),
        "kinds": {n: valid[n] for n in sorted_valid},
        "invalid": sorted(invalid)[:MAX_SITE_CNPJS],
        "commercial": commercial,
        "captured": captured,
    }


def _mail_facts(nodes: list[Node]) -> dict[str, Any]:
    mx = [h for h in (_host(x) for x in _flat(_vals(n, "mx") for n in nodes) if isinstance(x, str)) if h]
    spf = next((s for n in nodes for s in _vals(n, "spf") if isinstance(s, str) and s.lower().startswith("v=spf1")), None)
    targets: list[str] = []
    for m in re.finditer(r"(?:^|\s)[+?~-]?(?:include:|redirect=)(\S+)", spf or "", re.I):
        h = _host(m.group(1))
        if h and h not in targets:
            targets.append(h)
    for item in _flat(_vals(n, "spf_includes") for n in nodes):
        h = _host(item.get("domain")) if isinstance(item, dict) else ""
        if h and h not in targets:
            targets.append(h)
    return {"mx": mx[:50], "spf_targets": targets[:100]}


def domain_facts(graph: Graph, node: Node, results: Iterable[ModuleResult] | None, rctx: Any, *,
                 index: GraphIndex | None = None) -> dict[str, Any]:
    """Normalised facts of one domain (graph -> the input of :func:`assess_domain_ownership`)."""
    index = index if index is not None else build_index(graph, results)
    domain = str(node.entity.value)
    reg = psl.registrable_domain(domain) or domain
    apex = graph.get(f"domain:{reg}") if reg != domain else node
    nodes = [n for n in (node, apex) if n is not None]
    nodes = list({n.key: n for n in nodes}.values())
    keys = [n.key for n in nodes]
    reg_node = apex or node
    options = _options(rctx)
    mode = getattr(options, "mode", Opsec.PASSIVE)
    if not isinstance(mode, Opsec):
        try:
            mode = Opsec.parse(mode)
        except (KeyError, ValueError):
            mode = Opsec.PASSIVE
    allow_archive = bool(_setting(rctx, ARCHIVE_IN_PASSIVE_SETTING))
    now = _now(rctx)

    # ---- registry (rdap)
    registered = _vals(reg_node, "registered", REGISTRY_SOURCES)
    roots = _registry_roots(reg_node)
    kind = next((k for k in _vals(reg_node, "registrant_kind", REGISTRY_SOURCES) if isinstance(k, str)), None)
    registrant = next((o for o in _vals(reg_node, "registrant", REGISTRY_SOURCES) if isinstance(o, str) and o.strip()), None)
    age = next((int(a) for a in _vals(reg_node, "domain_age_days", REGISTRY_SOURCES)
                if isinstance(a, (int, float)) and not isinstance(a, bool) and a >= 0), None)
    created = next((c for c in _vals(reg_node, "created", REGISTRY_SOURCES) if isinstance(c, str)), None)
    if age is None and created:
        when = _parse_time(created)
        age = max(0, (now - when).days) if when else None
    reg_keys = [reg_node.key]
    if False in registered and True not in registered:
        rstatus = "not_registered"
    elif True in registered or roots or kind or registrant:
        rstatus = "ok"
    else:
        rstatus = _run_status(index, sorted(REGISTRY_SOURCES), reg_keys) or "missing"
        if rstatus == "ok":
            rstatus = "no_data"
    person = next((p for p in _vals(reg_node, "registrant_person", REGISTRY_SOURCES) if isinstance(p, dict)), None)
    server = next((_host(s) for s in _vals(reg_node, "rdap_server", REGISTRY_SOURCES) if isinstance(s, str) and _host(s)), "")
    rdap = {
        "status": rstatus, "cnpj_roots": sorted(roots), "registrant_kind": kind, "registrant_org": registrant,
        "server": server or None, "registry_verified": registry_verifies_holder(reg, server),
        "privacy_proxy": True in _vals(reg_node, "privacy_proxy", REGISTRY_SOURCES), "created": created, "age_days": age,
        "evidence_ref": _evidence_ref(index, sorted(REGISTRY_SOURCES), reg_keys),
        "registrant_person": {"name": _clean(person.get("name"), 200), "cpf_masked": person.get("cpf_masked")} if person else None,
    }
    # ---- certificates, CT status
    certs: list[dict[str, Any]] = []
    for n in nodes:
        for cert in _cert_facts(n):
            cert["evidence_ref"] = _evidence_ref(index, [cert["module"]], [n.key])
            certs.append(cert)
    ct = _run_status(index, sorted(CT_SOURCES), [reg_node.key])
    # ---- DNS / M365 tenancy
    mail = _mail_facts(nodes)
    mail["evidence_ref"] = _evidence_ref(index, ["dns_records", "email_security_posture"], keys)
    tenants = set().union(*(_tenant_ids(n) for n in nodes)) if nodes else set()
    # ---- homepage
    holders = list(nodes)
    for n in nodes:
        for host in (str(n.entity.value), "www." + str(n.entity.value)):
            holders += [u for u in index.homepages.get(host, ()) if u.key not in {h.key for h in holders}]
    homepage = _homepage(graph, index, holders, rctx, mode, allow_archive)
    homepage["evidence_ref"] = _evidence_ref(index, sorted(HOMEPAGE_SOURCES), [h.key for h in holders])
    return {
        "domain": domain,
        "registrable_domain": reg,
        "mode": mode.label,
        "is_seed": analyst_seed(node, rctx),
        "rdap": rdap,
        "certs": certs,
        "ct_status": COULD_NOT_VERIFY if ct in _UNVERIFIED_STATUSES else ct,
        "dns": mail,
        "m365": {"tenant_ids": sorted(tenants), "evidence_ref": _evidence_ref(index, ["m365_tenant", "m365_tenant_azmap"], keys)},
        "homepage": homepage,
    }


def _setting(rctx: Any, name: str) -> Any:
    meta = getattr(rctx, "meta", None)
    if isinstance(meta, dict) and name in meta:
        return meta[name]
    getter = getattr(rctx, "setting", None)
    if callable(getter):
        try:
            return getter(name, False)
        except Exception:  # pragma: no cover - defensive: a broken config never breaks the rule
            return False
    return False


# ======================================================================================
# the verdict (FC2-FC5, FC7)
# ======================================================================================


def _ev(domain: str, kind: str, value: Any, text: str, source: str, ref: str | None = None) -> dict[str, str]:
    return {"id": ref or evidence_id(domain, kind, value), "kind": kind, "text": text, "source": source}


def _shared_provider(mx: list[str], targets: list[str]) -> list[str]:
    found = [name for name, rx in _SHARED_MX if any(rx.search(h) for h in mx)]
    found += [name for name, rx in _SHARED_SPF if any(rx.match(t) for t in targets) and name not in found]
    return found


def assess_domain_ownership(facts: dict[str, Any], subject: Subject, *, profile_entry: Any = None) -> dict[str, Any]:
    """Company ownership verdict of one domain for one subject.

    ``facts``: :func:`domain_facts` output. ``profile_entry``: the org-profile DomainEntry covering the
    domain (org subject only). Returns {domain, subject, level (CONFIRMED|PROBABLE|POSSIBLE|None),
    label, confidence, evidence, contra, notes, marks, homepage_evidence, org_seed_proposal, criterion}.
    """
    domain = str(facts.get("domain") or "")
    reg = str(facts.get("registrable_domain") or domain)
    who = subject.label
    evidence: list[dict[str, str]] = []
    contra: list[dict[str, str]] = []
    notes: list[str] = []
    confirmed = o_match = rdap_name = rdap_self = False
    tenancy: list[dict[str, str]] = []
    site: list[dict[str, str]] = []

    # FC2: org-profile own domain (PSL + label-wise membership)
    if subject.scope == "org" and profile_entry is not None:
        state = str(getattr(profile_entry, "verification", "") or "")
        evidence.append(_ev(domain, "own_domain", profile_entry.name,
                            f"Domain is an org_profile own domain ({profile_entry.name}{', ' + state if state else ''})", "org_profile"))
        confirmed = True

    # FC2: RDAP registrant CNPJ root
    rd = facts.get("rdap") if isinstance(facts.get("rdap"), dict) else {}
    rstatus = rd.get("status") or "missing"
    registrant_roots = {r for r in (cnpj_root(x) for x in rd.get("cnpj_roots") or []) if r}
    rdap_other = False
    ref = rd.get("evidence_ref")
    if rstatus == "ok":
        hit = sorted(registrant_roots & subject.roots)
        if hit:
            evidence.append(_ev(domain, "rdap_cnpj_root", hit[0], f"RDAP CNPJ = {who} CNPJ root ({hit[0]})", "rdap", ref))
            confirmed = True
        elif registrant_roots:
            rdap_other = True
            contra.append(_ev(domain, "rdap_cnpj_other", ",".join(sorted(registrant_roots)),
                              f"RDAP registrant CNPJ root {', '.join(sorted(registrant_roots))} is not the {who}'s", "rdap", ref))
        elif rd.get("registrant_kind") == "org" and rd.get("registrant_org") and not rd.get("privacy_proxy") \
                and any(org_names_match(rd["registrant_org"], n) for n in subject.names):
            org_txt = _clean(rd["registrant_org"], 120)
            if rd.get("registry_verified"):
                evidence.append(_ev(domain, "rdap_org_name", org_name_key(rd["registrant_org"]),
                                    f"RDAP registrant organisation = {who} name ({org_txt}; holder vetted by the registry)", "rdap", ref))
                rdap_name = True
            else:  # self-declared at the registrar: a fraudster can type the victim's name (like a copied footer)
                evidence.append(_ev(domain, "rdap_org_name_self_declared", org_name_key(rd["registrant_org"]),
                                    f"RDAP registrant organisation = {who} name ({org_txt}; self-declared at the registrar, "
                                    "not vetted by the registry: unconfirmed link)", "rdap", ref))
                rdap_self = True
        elif rd.get("registrant_kind") == "individual":
            notes.append("RDAP registrant is a natural person: company ownership cannot be confirmed from the registry")
        elif rd.get("registrant_kind") == "redacted" or rd.get("privacy_proxy"):
            notes.append("RDAP registrant hidden by a privacy/proxy service")
        elif not rd.get("registrant_kind"):
            notes.append("The registry publishes no registrant (thin registry; the registrar's RDAP is not read by this rule)")
    elif rstatus == "not_registered":
        contra.append(_ev(domain, "rdap_not_registered", reg, "Domain is not registered (authoritative RDAP 404)", "rdap", ref))
    elif rstatus in _UNVERIFIED_STATUSES:
        notes.append(f"RDAP could not be verified ({rstatus}): registry ownership not checked")
    elif rstatus == "skipped":
        notes.append("RDAP did not run for this domain: registry ownership not checked")
    else:
        notes.append("No RDAP facts in the graph for this domain")

    # FC3: certificate O= (OV/EV only)
    seen_o = False
    for cert in facts.get("certs") or []:
        names = cert.get("names") or []
        if names and reg and not any(psl.registrable_domain(n) == reg for n in names):
            continue
        if cert.get("validation") not in ("OV", "EV") or not cert.get("o"):
            continue
        seen_o = True
        if any(org_names_match(cert["o"], n) for n in subject.names):
            if not o_match:
                evidence.append(_ev(domain, "cert_o", org_name_key(cert["o"]),
                                    f"CT O= matches ({cert['validation']} certificate, O={cert['o']}; {cert.get('source') or cert.get('module')})",
                                    str(cert.get("module") or "ct_logs"), cert.get("evidence_ref")))
            o_match = True
        else:
            notes.append(f"{cert['validation']} certificate names another organisation (O={_clean(cert['o'], 120)})")
    if not seen_o and not confirmed:
        notes.append("No OV/EV certificate subject O= in the graph (crt.sh JSON has no subject DN; needs Cert Spotter cert_der, "
                     "Censys or a tls_inspect handshake)")
    if facts.get("ct_status") == COULD_NOT_VERIFY:
        notes.append("Certificate Transparency could not be verified (source unavailable)")

    # FC3: DNS / M365 tenancy (a strengthener; alone at most POSSIBLE)
    anchors = {a for a in subject.anchors if a != reg}
    m365 = facts.get("m365") if isinstance(facts.get("m365"), dict) else {}
    for tid in m365.get("tenant_ids") or []:
        if tid in subject.tenant_ids:
            tenancy.append(_ev(domain, "m365_tenant", tid, f"MX in the same M365 tenant as the {who} ({tid})", "m365_tenant",
                               m365.get("evidence_ref")))
            break
    dns = facts.get("dns") if isinstance(facts.get("dns"), dict) else {}
    org_mx = [h for h in dns.get("mx") or [] if host_in(h, anchors)]
    org_spf = [t for t in dns.get("spf_targets") or [] if host_in(t, anchors)]
    for h in org_mx[:3]:
        tenancy.append(_ev(domain, "mx_org", h, f"MX hosted on a domain of the {who} ({h})", "dns_records", dns.get("evidence_ref")))
    for t in org_spf[:3]:
        tenancy.append(_ev(domain, "spf_org", t, f"SPF includes a domain of the {who} ({t})", "email_security_posture", dns.get("evidence_ref")))
    shared = _shared_provider(dns.get("mx") or [], dns.get("spf_targets") or [])
    if shared and not tenancy:
        notes.append(f"MX/SPF on a shared provider ({', '.join(shared)}): not evidence by itself")
    evidence.extend(tenancy)

    # FC3/FC4/FC5/FC7: homepage (site CNPJ = at most an unconfirmed link)
    hp = facts.get("homepage") if isinstance(facts.get("homepage"), dict) else {"state": "none_available"}
    hp_state = str(hp.get("state") or "none_available")
    if hp_state == "used":
        hit = sorted(set(hp.get("valid_roots") or []) & subject.roots)
        if hit:
            kinds = hp.get("kinds") or {}
            kind = next((kinds[n] for n in hp.get("valid") or [] if n[:8] == hit[0]), "archive")
            source = "web_fingerprint" if kind == "live" else "web_archives"
            site.append(_ev(domain, "site_cnpj", hit[0], f"Site displays the {who} CNPJ root {hit[0]} (unconfirmed link: a displayed "
                                                         "CNPJ never confirms ownership)", source, hp.get("evidence_ref")))
            if rdap_other:
                contra.append(_ev(domain, "site_cnpj_contradicted", hit[0], "Site CNPJ contradicted by the RDAP registrant", source))
                site = []
    evidence.extend(site)

    # level
    if confirmed:
        level, conf = "CONFIRMED", LEVEL_CONFIDENCE["CONFIRMED"]
    elif o_match or rdap_name:
        level = "PROBABLE"
        conf = 0.75 if tenancy or (o_match and (rdap_name or rdap_self)) else 0.6
    elif tenancy or site or rdap_self:
        level = "POSSIBLE"
        signals = sum(1 for s in (tenancy, site, rdap_self) if s)
        conf = 0.45 if signals >= 2 else 0.4 if (tenancy or rdap_self) else 0.35
    else:
        level, conf = None, 0.0
    if rdap_other and level in ("PROBABLE", "POSSIBLE"):
        notes.append("Conflicting evidence: the registry names another company; capped at POSSIBLE")
        level, conf = "POSSIBLE", min(conf, 0.45)
    if rstatus == "not_registered" and level != "CONFIRMED":
        level, conf = None, 0.0

    # wording, marks, proposals
    if hp_state == "excluded_passive_mode":
        notes.append("No homepage evidence used (passive mode: RDAP/CT/DNS facts only)")
    elif hp_state.startswith(COULD_NOT_VERIFY + ":"):
        notes.append(f"Homepage evidence could not be verified ({hp_state.split(':', 1)[1]}): no site facts used")
    elif hp_state != "used":
        notes.append("No homepage evidence was available" + ("" if hp_state == "none_available" else f" ({hp_state})"))
    if level:
        label = LABELS[level]
    elif rdap_other:
        label = "registered to another company"
    elif rstatus == "not_registered":
        label = "not registered"
    elif rstatus in _UNVERIFIED_STATUSES:
        label = LABEL_UNVERIFIED  # 403/429/timeouts: never read as 'no evidence'
    else:
        label = "no ownership evidence"
    marks: list[str] = []
    if level == "CONFIRMED":
        marks = ["own_asset", "known_good"] if subject.scope == "org" else ["known_good"]
    verdict: dict[str, Any] = {
        "rule": RULE_VERDICT, "domain": domain, "subject": who, "subject_key": subject.key, "level": level, "label": label,
        "confidence": round(conf, 2), "evidence": evidence, "contra": contra, "notes": list(dict.fromkeys(notes)),
        "marks": marks, "homepage_evidence": hp_state, "active_scope": False,
        "criterion": "; ".join(f"[{e['id']}] {e['text']}" for e in evidence) or "no ownership evidence",
    }
    verdict["org_seed_proposal"] = org_seed_proposal(verdict, subject, in_profile=profile_entry is not None)
    return verdict


def org_seed_proposal(verdict: dict[str, Any], subject: Subject, *, in_profile: bool = False) -> dict[str, Any] | None:
    """FC7: a CONFIRMED/PROBABLE org verdict for a domain the profile does not list becomes an
    ``org seed`` proposal: analyst confirmation required, never an ACTIVE scope entry."""
    if not verdict or verdict.get("level") not in ("CONFIRMED", "PROBABLE") or subject.scope != "org" or in_profile:
        return None
    return {"entry": "domains", "value": psl.registrable_domain(str(verdict.get("domain") or "")) or verdict.get("domain"),
            "level": verdict.get("level"), "evidence_ids": [e["id"] for e in verdict.get("evidence") or []],
            "requires_analyst_confirmation": True, "scope_effect": None, "proposed_by": RULE_VERDICT}


def domain_findings(facts: dict[str, Any], *, own_roots: Iterable[str] = ()) -> list[dict[str, Any]]:
    """FC4 findings of one domain (independent of the subject): CNPJ displayed vs registrant, invalid
    CNPJ on a commercial page. Returns dicts {rule, title, severity, tags, confidence, criterion,
    evidence_ids, cnpjs}. ``own_roots``: the org CNPJ roots when the domain is an org-profile own
    domain (FC2 authoritative): the org's own site showing only the org's CNPJ is never a clone."""
    out: list[dict[str, Any]] = []
    domain = str(facts.get("domain") or "")
    hp = facts.get("homepage") if isinstance(facts.get("homepage"), dict) else {}
    if hp.get("state") != "used":
        return out
    rd = facts.get("rdap") if isinstance(facts.get("rdap"), dict) else {}
    valid_roots = set(hp.get("valid_roots") or [])
    registrant_roots = {r for r in (cnpj_root(x) for x in rd.get("cnpj_roots") or []) if r} if rd.get("status") == "ok" else set()
    age = rd.get("age_days") if isinstance(rd.get("age_days"), int) else None
    site_id = evidence_id(domain, "site_cnpj", ",".join(sorted(valid_roots)))
    own = {r for r in (cnpj_root(x) for x in own_roots) if r}
    if valid_roots and not (own and valid_roots <= own):
        reason = None
        if registrant_roots and not (valid_roots & registrant_roots):
            reason = (f"site CNPJ root(s) {', '.join(sorted(valid_roots))} differ from the RDAP registrant root(s) "
                      f"{', '.join(sorted(registrant_roots))}", "probable")
        elif rd.get("status") == "ok" and not registrant_roots and age is not None and age <= NEW_DOMAIN_DAYS:
            reason = (f"site CNPJ root(s) {', '.join(sorted(valid_roots))} on a domain registered {age} day(s) ago without a "
                      "registry CNPJ match", "possible")
        if reason:
            ids = [site_id] + ([rd["evidence_ref"]] if rd.get("evidence_ref") else [])
            out.append({"rule": RULE_MISMATCH, "title": "CNPJ displayed does not match registrant", "severity": "medium",
                        "tags": ["fraud", "clone_indicator"], "confidence": reason[1], "criterion": reason[0],
                        "evidence_ids": ids, "cnpjs": list(hp.get("valid") or [])[:3]})
    invalid = list(hp.get("invalid") or [])
    if invalid and hp.get("commercial"):
        shown = ", ".join(_cnpj_display(n) for n in invalid[:3])
        out.append({"rule": RULE_INVALID, "title": "Invalid CNPJ displayed on a commercial site", "severity": "low",
                    "tags": ["suspicious"], "confidence": "possible",
                    "criterion": f"check digits fail for {shown} (P232, offline format check) on a page with commerce markers",
                    "evidence_ids": [evidence_id(domain, "site_cnpj_invalid", invalid[0])], "cnpjs": []})
    return out


# ======================================================================================
# person ownership (FC6)
# ======================================================================================


def assess_person_ownership(facts: dict[str, Any], person_name: str, *, seed_cpfs: Iterable[str] = (), purpose: str = "") -> dict[str, Any]:
    """Ownership of a domain by an analyst-typed person (the caller checks the seed); only from public
    registrant data already in the graph. Never CONFIRMED; the seed CPFs are compared, never returned."""
    domain = str(facts.get("domain") or "")
    base: dict[str, Any] = {"rule": RULE_PERSON, "domain": domain, "tags": ["privacy"], "expand": False, "retention": "case", "pivots": []}
    if not _clean(purpose):
        return {**base, "status": "skipped", "reason_code": "privacy", "reason": "person ownership needs a case with a recorded purpose"}
    if not _person_tokens(person_name):
        return {**base, "status": "skipped", "reason_code": "privacy", "reason": "no analyst-typed person name"}
    rd = facts.get("rdap") if isinstance(facts.get("rdap"), dict) else {}
    rp = rd.get("registrant_person") if isinstance(rd.get("registrant_person"), dict) else None
    evidence: list[dict[str, str]] = []
    contra: list[dict[str, str]] = []
    notes: list[str] = []
    level: str | None = None
    masked = _registry_cpf_display(rp.get("cpf_masked")) if rp else None
    cpfs = [c for c in seed_cpfs if isinstance(c, str)]
    if rp:
        name_eq = person_names_equal(person_name, rp.get("name"))
        name_in = person_name_contained(person_name, rp.get("name"))
        cpf_ok: bool | None = None
        if masked and cpfs:
            cpf_ok = any(cpf_mask_compatible(rp.get("cpf_masked"), c) for c in cpfs)
        if cpf_ok is False:
            contra.append(_ev(domain, "rdap_cpf_incompatible", masked, f"Registrant CPF {masked} is incompatible with the seed (homonym)", "rdap"))
        elif name_eq and cpf_ok:
            evidence.append(_ev(domain, "rdap_person", masked, f"RDAP registrant name = seed and CPF {masked} compatible", "rdap",
                                rd.get("evidence_ref")))
            level = "PROBABLE"
        elif name_eq or name_in:
            evidence.append(_ev(domain, "rdap_person_name", _fold(rp.get("name")),
                                "RDAP registrant name " + ("equals" if name_eq else "contains") + " the seed name"
                                + ("" if cpf_ok is None else " (CPF compatible)"), "rdap", rd.get("evidence_ref")))
            level = "POSSIBLE"
        elif cpf_ok:
            evidence.append(_ev(domain, "rdap_person_cpf", masked, f"Registrant CPF {masked} compatible but the name differs: check", "rdap"))
            level = "POSSIBLE"
    elif rd.get("registrant_kind") == "individual":
        notes.append("RDAP shows a natural-person registrant but its data was minimised at ingestion (P001): no person comparison possible")
    if not contra:
        reg = str(facts.get("registrable_domain") or psl.registrable_domain(domain) or domain)
        for cert in facts.get("certs") or []:
            names = cert.get("names") or []
            if names and not any(psl.registrable_domain(n) == reg for n in names):
                continue  # an IV certificate issued for another domain says nothing about this one
            if cert.get("validation") == "IV" and (cert.get("given_name") or cert.get("surname")):
                full = f"{cert.get('given_name') or ''} {cert.get('surname') or ''}"
                if person_names_equal(person_name, full):
                    evidence.append(_ev(domain, "cert_iv_name", _fold(full), "IV certificate names the seed person",
                                        str(cert.get("module") or "ct_logs"), cert.get("evidence_ref")))
                    level = level or "POSSIBLE"
                    break
    if contra:
        level = None
    return {**base, "status": "ok", "level": level,
            "label": {"PROBABLE": "probable owner (person)", "POSSIBLE": "unconfirmed link (person)"}.get(level or "", "no link"),
            "confidence": {"PROBABLE": 0.6, "POSSIBLE": 0.35}.get(level or "", 0.0),
            "evidence": evidence, "contra": contra, "notes": notes, "registrant_cpf_display": masked}


# ======================================================================================
# graph evaluation and the rules
# ======================================================================================


def _candidates(graph: Graph, rctx: Any) -> list[Node]:
    out = []
    for node in sorted(graph.of_type(EntityType.DOMAIN), key=lambda n: (not n.seed, n.depth, n.key)):
        value = str(node.entity.value)
        reg = psl.registrable_domain(value)
        if reg is None:
            continue
        seed = analyst_seed(node, rctx)
        if (value != reg or node.noise) and not seed:
            continue
        out.append(node)
        if len(out) >= MAX_DOMAINS:
            break
    return out


def evaluate(graph: Graph, results: list[ModuleResult] | None, rctx: Any, *, with_subjects: bool = True,
             index: GraphIndex | None = None) -> Iterator[tuple[Node, Subject | None, dict[str, Any]]]:
    """(domain node, subject, verdict) for every evaluated pair, then (node, None, facts) once per
    domain (the subject-independent part used by the FC4 rules)."""
    index = index if index is not None else build_index(graph, results)
    subs = subjects(graph, rctx) if with_subjects else []
    org = getattr(rctx, "org", None)
    for node in _candidates(graph, rctx):
        facts = domain_facts(graph, node, results, rctx, index=index)
        for subject in subs:
            entry = org.domain_entry(str(node.entity.value)) if subject.scope == "org" and org is not None else None
            yield node, subject, assess_domain_ownership(facts, subject, profile_entry=entry)
        yield node, None, facts


def _emit_verdict(index: GraphIndex, node: Node, subject: Subject, verdict: dict[str, Any], rctx: Any) -> bool:
    if subject.scope == "org" and any(e.get("kind") == "own_domain" for e in verdict.get("evidence") or []):
        return analyst_seed(node, rctx)  # the profile already says so: repeat it only when the analyst asked about the domain
    if verdict.get("level"):
        return True
    if subject.scope != "company":
        return False  # 'no evidence' against the org would be noise on every investigated domain
    return analyst_seed(node, rctx) or bool(subject.node_key and index.adjacent(node.key, subject.node_key))


def _bullets(items: list[dict[str, str]]) -> str:
    return "; ".join(f"[{e['id']}] {e['text']}" for e in items)


def _verdict_correlation(node: Node, subject: Subject, verdict: dict[str, Any]) -> Correlation:
    level = verdict.get("level")
    label = verdict["label"]
    who = subject.label
    domain = node.entity.value
    if level:
        confidence: float = verdict["confidence"]
    else:
        confidence = {"registered to another company": 0.6, "not registered": 0.9}.get(label, 0.3)
    parts = [f"{domain}: {label} for the {who}" + (f" ({level})." if level else ".")]
    if verdict["evidence"]:
        parts.append("Evidence: " + _bullets(verdict["evidence"]) + ".")
    if verdict["contra"]:
        parts.append("Against: " + _bullets(verdict["contra"]) + ".")
    if verdict["notes"]:
        parts.append("Notes: " + "; ".join(verdict["notes"]) + ".")
    if level == "POSSIBLE":
        parts.append("An unconfirmed link is never ownership: confirm with registry data (RDAP CNPJ) before relying on it.")
    tags = ["ownership", *verdict["marks"]]
    proposal = verdict.get("org_seed_proposal")
    if proposal:
        tags.append("org_seed_candidate")
        recommendation = (f"Propose {proposal['value']} to the organisation profile with `v3lum org seed` (analyst confirmation "
                          "required); it never becomes an ACTIVE scope entry.")
    elif level == "CONFIRMED":
        recommendation = "Treat as the subject's asset (registry or profile evidence)."
    elif level == "PROBABLE":
        recommendation = "Confirm with registry data (registro.br RDAP CNPJ) or the org profile before treating it as an own asset."
    elif level == "POSSIBLE":
        recommendation = "Unconfirmed link: verify ownership before any conclusion; never an own asset on this evidence."
    elif label == LABEL_UNVERIFIED:
        recommendation = ("The registry could not be queried (refused, rate limited or failed): re-run rdap later or check the "
                          "registro.br web whois before drawing any conclusion.")
    else:
        recommendation = "Do not attribute this domain to the queried company without registry evidence."
    entities = [node.entity] + ([subject.entity] if subject.scope == "company" and subject.entity is not None else [])
    return Correlation(
        rule=RULE_VERDICT,
        title=f"Domain ownership ({who}): {domain} - {label}",
        severity=Severity.INFO,
        description=" ".join(parts),
        entities=entities,
        confidence=confidence,
        evidence=[f"[{e['id']}] {e['text']}" for e in verdict["evidence"]][:20],
        recommendation=recommendation,
        tags=tags,
        criterion=verdict["criterion"] if verdict["evidence"] else (_bullets(verdict["contra"]) or "no ownership evidence"),
        why=(f"org seed proposal: domains += {proposal['value']} (requires analyst confirmation, no scope effect)" if proposal
             else f"homepage evidence: {verdict['homepage_evidence']}"),
        key=subject.key,
    )


@rule(
    RULE_VERDICT,
    "Domain ownership verdict",
    "Is this domain really the organisation's (org profile) or the queried company's (typed CNPJ / company name seed)? "
    "CONFIRMED only from authoritative data (RDAP registrant CNPJ root, org-profile own domain); PROBABLE at most from an "
    "OV/EV certificate O= match (stronger with a DNS/M365 tenancy signal) or a registry-vetted (registro.br) registrant "
    "organisation name; a self-declared registrant organisation or a CNPJ printed on the site is at most POSSIBLE "
    "('unconfirmed link'). Facts already in the graph only: no network call (P013).",
    version="1",
    code="P013",
    severity="info",
    criterion="RDAP registrant CNPJ root / org-profile membership (CONFIRMED); OV/EV O= match +/- tenancy or a registro.br "
              "registrant organisation name (PROBABLE); tenancy, self-declared registrant name or site CNPJ (POSSIBLE); "
              "registry contradiction caps at POSSIBLE",
    false_positives="Group companies with several CNPJ roots look 'registered to another company'; certificate O= of a "
                    "reseller or hosting company; a tenancy signal from a shared mail gateway of the subject.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_confirmed_rdap_org_root.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_confirmed_own_domain.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_probable_cert_o.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_probable_cert_o_and_tenant.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_possible_tenancy_only.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_possible_archived_footer_light.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_possible_self_declared_registrant.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/positive_queried_company_registered_to_other.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/negative_no_evidence.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/negative_shared_mail_provider_only.json",
        f"tests/fixtures/rules/{RULE_VERDICT}/negative_passive_footer_excluded.json",
    ),
)
def domain_ownership(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    index = build_index(graph, results)
    for node, subject, verdict in evaluate(graph, results, rctx, index=index):
        if subject is None or not _emit_verdict(index, node, subject, verdict, rctx):
            continue
        yield _verdict_correlation(node, subject, verdict)


def _own_roots(rctx: Any, domain: str) -> list[str]:
    """The org CNPJ roots when ``domain`` is an org-profile own domain (else nothing)."""
    org = getattr(rctx, "org", None)
    finder = getattr(org, "domain_entry", None)
    if org is None or not callable(finder) or finder(domain) is None:
        return []
    return [str(r) for r in getattr(org, "cnpj_roots", []) or []]


def _finding_correlations(graph: Graph, results: list[ModuleResult], rctx: Any, rule_id: str) -> Iterator[Correlation]:
    for node, subject, facts in evaluate(graph, results, rctx, with_subjects=False):
        if subject is not None:
            continue
        for item in domain_findings(facts, own_roots=_own_roots(rctx, str(node.entity.value))):
            if item["rule"] != rule_id:
                continue
            description = (f"{node.entity.value}: {item['title']} - {item['criterion']}. A CNPJ printed on a site never confirms "
                           "ownership (fake stores copy real companies' CNPJs).")
            if rule_id == RULE_MISMATCH:
                # the displayed CNPJ is usually the victim's: named in the text, never an entity of a fraud correlation
                shown = ", ".join(_cnpj_display(n) for n in item["cnpjs"])
                description += (f" CNPJ displayed: {shown} (likely copied from a legitimate company, which is not the suspect)."
                                if shown else "")
                description += " Clone indicator: compare with the registrant's legitimate site before any takedown."
            yield Correlation(
                rule=rule_id,
                title=f"{item['title']}: {node.entity.value}",
                severity=Severity.parse(item["severity"]),
                description=description,
                entities=[node.entity],
                confidence=item["confidence"],
                evidence=list(item["evidence_ids"]),
                recommendation=("Treat the site as a possible clone or fake store: check the registrant, the domain age and the "
                                "legitimate company's official domains." if rule_id == RULE_MISMATCH
                                else "Check the company behind the site: an invalid CNPJ on a store is a fraud warning sign."),
                tags=list(item["tags"]),
                criterion=item["criterion"],
                key=str(node.entity.value),
            )


@rule(
    RULE_MISMATCH,
    "CNPJ displayed does not match registrant",
    "A valid CNPJ printed on the homepage (live LIGHT fetch of an analyst-typed seed, or an archived snapshot) whose root "
    "differs from the RDAP registrant CNPJ root, or that sits on a domain registered at most 90 days ago without a "
    "registry match: clone / fake-store indicator (P013 cond 4). Facts already in the graph only.",
    version="1",
    code="P013",
    severity="medium",
    criterion="valid site CNPJ root != RDAP registrant CNPJ root (probable), or site CNPJ on a domain <= 90 days old without "
              "a registry CNPJ (possible); site CNPJs re-validated by check digits (P232); an org-profile own domain showing "
              "only the org's CNPJ is never flagged",
    false_positives="A site that prints only a marketplace's or payment provider's CNPJ while RDAP names its owner; group "
                    "companies registering domains under another root.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_MISMATCH}/positive_copied_footer_new_domain.json",
        f"tests/fixtures/rules/{RULE_MISMATCH}/positive_rdap_contradicts_footer.json",
        f"tests/fixtures/rules/{RULE_MISMATCH}/negative_footer_matches_registrant.json",
        f"tests/fixtures/rules/{RULE_MISMATCH}/negative_old_domain_or_passive.json",
        f"tests/fixtures/rules/{RULE_MISMATCH}/negative_passive_mode.json",
        f"tests/fixtures/rules/{RULE_MISMATCH}/negative_own_profile_domain_own_cnpj.json",
    ),
)
def cnpj_mismatch(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    yield from _finding_correlations(graph, results, rctx, RULE_MISMATCH)


@rule(
    RULE_INVALID,
    "Invalid CNPJ displayed on a commercial site",
    "A CNPJ that fails the P232 check digits (offline format check, numeric or alphanumeric) is printed on a homepage "
    "with commerce markers: suspicious (P013 cond 4). On a non-commercial page it is only a note of the ownership verdict.",
    version="1",
    code="P013",
    severity="low",
    criterion="site CNPJ failing the check digits on a page with commerce markers (homepage facts of a usable source)",
    false_positives="Typos in a legitimate footer; OCR-like copies of the CNPJ in archived pages.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_INVALID}/positive_invalid_cnpj_commercial.json",
        f"tests/fixtures/rules/{RULE_INVALID}/negative_invalid_cnpj_not_commercial.json",
    ),
)
def invalid_site_cnpj(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    yield from _finding_correlations(graph, results, rctx, RULE_INVALID)


@rule(
    RULE_PERSON,
    "Domain ownership by an analyst-typed person",
    "Whether a person the analyst typed as a seed holds a domain, from public registrant data already in the graph "
    "(minimised RDAP registrant data, IV certificate subjects). Only inside a case with a recorded purpose; POSSIBLE or "
    "PROBABLE, tagged privacy, never pivoted; the CPF is never unmasked (P013 cond 6, A10 retention of the case).",
    version="1",
    code="P013",
    severity="info",
    criterion="registrant name equal to the seed (+ compatible masked CPF: PROBABLE; name only: POSSIBLE) or an IV certificate "
              "naming the seed (POSSIBLE)",
    false_positives="Homonyms: the same name without a compatible CPF stays an unconfirmed link.",
    person=True,
    fixtures=(
        f"tests/fixtures/rules/{RULE_PERSON}/positive_registrant_name_possible.json",
        f"tests/fixtures/rules/{RULE_PERSON}/negative_no_purpose_or_not_seed.json",
    ),
)
def person_ownership(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    purpose = str(getattr(_options(rctx), "purpose", "") or "")
    if not purpose.strip():
        return  # privacy floor: no recorded purpose, no person comparison at all
    persons = [n for n in graph.seeds() if n.entity.type is EntityType.PERSON and analyst_seed(n, rctx)]
    if not persons:
        return
    cpfs = [str(n.entity.value) for n in graph.seeds() if n.entity.type is EntityType.CPF and analyst_seed(n, rctx)]
    index = build_index(graph, results)
    for person in persons[:5]:
        domains = [n for n in graph.of_type(EntityType.DOMAIN)
                   if analyst_seed(n, rctx) or index.adjacent(n.key, person.key)][:MAX_PERSON_DOMAINS]
        for node in sorted(domains, key=lambda n: n.key):
            facts = domain_facts(graph, node, results, rctx, index=index)
            verdict = assess_person_ownership(facts, str(person.entity.value), seed_cpfs=cpfs, purpose=purpose)
            if verdict.get("status") != "ok" or not verdict.get("level"):
                continue
            notes = verdict["notes"]
            yield Correlation(
                rule=RULE_PERSON,
                title=f"Domain ownership (person seed): {node.entity.value} - {verdict['label']}",
                severity=Severity.INFO,
                description=(f"{node.entity.value}: {verdict['label']} for the analyst-typed person seed. Evidence: "
                             f"{_bullets(verdict['evidence'])}." + (f" Notes: {'; '.join(notes)}." if notes else "")
                             + " Personal data: case retention, never pivoted; the CPF is shown masked only."),
                entities=[node.entity, person.entity],
                confidence=verdict["confidence"],
                evidence=[f"[{e['id']}] {e['text']}" for e in verdict["evidence"]],
                recommendation="Use only for the recorded case purpose; confirm with the registrant's documents before any conclusion.",
                tags=["privacy", "ownership", "natural_person"],
                criterion=_bullets(verdict["evidence"]),
                key="person:" + hashlib.sha256(person.key.encode()).hexdigest()[:12],
            )
