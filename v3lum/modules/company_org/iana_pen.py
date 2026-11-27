"""P228 ``iana_pen`` - IANA Private Enterprise Numbers (PEN) registry, matched offline.

Batch p3-G10-2. Council P228 final conditions, as implemented here:

1. **Dataset** - ``enterprise-numbers.txt`` from www.iana.org is a registered dataset
   (``iana_enterprise_numbers.txt``, monthly TTL, > 5 MB so it is never downloaded during a scan) fetched by
   ``v3lum data update``; the module reads only the local copy (disclosure 'none'). Records are 4-line blocks
   (number / organisation / contact / e-mail with '&' for '@'); :func:`validate_pen_registry` rejects an HTML
   page, a truncated download or a copy with too few records before it replaces the previous one.
2. **Legal floor** - :func:`parse_pen_registry` keeps only the PEN number, the organisation name and the
   contact e-mail DOMAIN. Contact person names and full e-mail addresses are read only to compute flags and
   are dropped at parse time: they never reach the index, evidence or reports. When the organisation equals
   the contact (an individual registrant) the "organisation" is a person's name and is withheld too. The module
   produces DOMAIN pivots (never e-mail) with ``expand=False``, never for webmail domains, placeholders,
   individual registrants or iana.org.
3. **Forward lookup** - company name or domain -> PEN number(s). Organisation names are matched through the
   shared name matcher (``v3lum.modules.company_org.namematch``, the stand-in for core/namematch.py): an equal
   normalised name is an exact match, a score >= 0.90 is worded 'possible match'.
4. **Reverse lookup** - :func:`pen_lookup` (number -> organisation) and :func:`pen_reverse_lookup` (OIDs
   ``1.3.6.1.4.1.<n>`` found in certificate extensions, SNMP or syslog text -> organisations) are offline
   helpers for other parsers (a core home ``v3lum/core/pen.py`` is a core request); the module also accepts a
   KEYWORD (``pen:<n>`` or an OID) or a TEXT blob and resolves the enterprise OIDs it carries.
5. **Opt-in** - ``default_enabled = False``; IANA public registry, terms open, tier trusted.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import noise
from v3lum.core.datasets import DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.company_org import namematch

SOURCE = "iana.iana_pen_enterprise_numbers"
DATASET = "iana_enterprise_numbers.txt"
PEN_URL = "https://www.iana.org/assignments/enterprise-numbers.txt"
PEN_PREFIX = "1.3.6.1.4.1"
LICENCE = "IANA public registry (Private Enterprise Numbers; public data, runtime download only)"
ATTRIBUTION = "IANA Private Enterprise Numbers registry (www.iana.org/assignments/enterprise-numbers)"
#: the production registry holds ~67,800 records; a much smaller download is a partial or broken copy
MIN_RECORDS = 50_000
#: the local copy is served whatever its age: the module never triggers a download (FC1)
SERVE_LOCAL_TTL = 100 * 365 * 86400.0
#: a copy older than this is reported stale (monthly refresh + grace)
STALE_DAYS = 62
MAX_HITS = 25
MAX_POSSIBLE = 5
MAX_OIDS = 50

PLACEHOLDER_ORGS = frozenset({"reserved", "unassigned", "---none---", "returned", "reclaimed", "none"})
#: webmail providers (the core noise list is consulted as well): a contact domain there is personal mail
WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "outlook.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.com.br", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "gmx.de", "gmx.net", "gmx.com", "web.de", "mail.ru", "yandex.ru", "yandex.com", "qq.com", "163.com",
    "126.com", "139.com", "sina.com", "sohu.com", "foxmail.com", "aliyun.com", "protonmail.com", "proton.me", "pm.me",
    "tutanota.com", "fastmail.com", "hey.com", "zoho.com", "mail.com", "t-online.de", "free.fr", "orange.fr", "wanadoo.fr",
    "laposte.net", "libero.it", "seznam.cz", "wp.pl", "o2.pl", "interia.pl", "naver.com", "daum.net", "hanmail.net",
    "rediffmail.com", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "comcast.net", "verizon.net",
    "earthlink.net", "compuserve.com", "att.net", "sbcglobal.net", "bellsouth.net", "cox.net", "charter.net",
    "optonline.net", "btinternet.com", "ntlworld.com", "263.net",
})

_PEN_DOMAIN_RX = re.compile(r"[&@]+([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*"
                            r"[A-Za-z0-9])?)*\.[A-Za-z]{2,63})(?![A-Za-z0-9-])")
_NUMBER_LINE = re.compile(r"\d{1,10}")
_URL_IN_NAME = re.compile(r"\(?\s*(?:https?://|www\.)\S*\s*\)?", re.I)
_OID_RXES = (
    ("numeric", re.compile(r"(?<![\w.])\.?(?:1|iso)\.3\.6\.1\.4\.1\.(\d{1,10})(?!\d)")),
    ("textual", re.compile(r"(?i)(?<![\w.])iso\.org\.dod\.internet\.private\.enterprises?\.(\d{1,10})(?!\d)")),
    ("snmp_mib", re.compile(r"(?<![\w.-])(?:SNMPv2-SMI::)?enterprises\.(\d{1,10})(?!\d)")),
)
_PEN_KEYWORD = re.compile(r"(?i)^\s*(?:pen|iana[-_ ]?pen|enterprise)\s*[:#=]\s*(\d{1,10})\s*$")


# ======================================================================================
# parsing (FC1, FC2)
# ======================================================================================


def _text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        text = body
    elif isinstance(body, (bytes, bytearray, memoryview)):
        raw = bytes(body)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    else:
        return ""
    return text[1:] if text.startswith("﻿") else text


def _looks_like_html(text: str) -> bool:
    return bool(re.match(r"\s*(<!doctype\s+html|<html|<head|<body|<\?xml)", text[:2048], re.I))


def is_webmail_domain(domain: Any) -> bool:
    d = str(domain or "").lower().strip().rstrip(".")
    if not d:
        return False
    if d in WEBMAIL_DOMAINS or any(d.endswith("." + w) for w in WEBMAIL_DOMAINS):
        return True
    ent = Entity.try_make(T.DOMAIN, d)
    try:
        return ent is not None and noise.noise_kind(ent) == "webmail"
    except Exception:  # noqa: BLE001 - the core list is advisory here
        return False


def pen_email_domains(email_line: Any) -> list[str]:
    """Domains of a contact e-mail line ('&' stands for '@'), lower case, de-duplicated. The local part is
    never returned (FC2). Several addresses, 'mailto:', '&&', a leading '&', phone numbers and '---none---'
    are handled; a domain without a dot gives nothing."""
    out: list[str] = []
    for m in _PEN_DOMAIN_RX.finditer(str(email_line or "")):
        d = m.group(1).lower().rstrip(".")
        if d not in out:
            out.append(d)
    return out


def registry_problem(body: Any, *, min_records: int = MIN_RECORDS) -> str:
    """Why a downloaded copy must not replace the installed one ('' = acceptable)."""
    text = _text(body)
    if not text.strip():
        return "empty file"
    if _looks_like_html(text):
        return "an HTML page came back instead of the registry"
    if "PRIVATE ENTERPRISE NUMBERS" not in text[:400] or f"({PEN_PREFIX})" not in text[:1200]:
        return "missing registry header"
    if not text.rstrip().endswith("End of Document"):
        return "truncated (no 'End of Document' trailer)"
    records = len(re.findall(r"(?m)^\d{1,10}\r?$", text))
    if records < min_records:
        return f"too few records ({records} < {min_records})"
    return ""


def validate_pen_registry(path: Path) -> bool:
    """``validate(path)`` of the dataset (FC1): raises ValueError with the reason (the previous copy stays)."""
    problem = registry_problem(Path(path).read_bytes())
    if problem:
        raise ValueError(f"{DATASET}: {problem}")
    return True


def _clean_org(org: str) -> str:
    return re.sub(r"\s+", " ", org).strip()


def parse_pen_registry(body: Any) -> dict[str, Any]:
    """enterprise-numbers.txt -> organisation-level records (FC1, FC2).

    Returns ``{updated, records: [{number, organization, email_domains, webmail_only, placeholder,
    individual}], complete, errors}``. Contact names and full e-mail addresses are read only to compute the
    flags and are never stored (FC2); an individual registrant (organisation == contact) gets
    ``organization=None``. Header-agnostic (starts at the first number line), tolerant of CRLF and of an
    incomplete last block (reported in ``errors``, never raised)."""
    text = _text(body)
    out: dict[str, Any] = {"updated": None, "records": [], "complete": False, "errors": []}
    m = re.search(r"\(last updated (\d{4}-\d{2}-\d{2})\)", text[:800])
    out["updated"] = m.group(1) if m else None
    lines = text.split("\n")
    i = 0
    while i < len(lines) and not _NUMBER_LINE.fullmatch(lines[i].rstrip("\r")):
        i += 1
    records: list[dict[str, Any]] = out["records"]
    while i < len(lines):
        line = lines[i].rstrip("\r")
        if line.strip() == "End of Document":
            out["complete"] = True
            break
        if not _NUMBER_LINE.fullmatch(line):
            i += 1
            continue
        number = int(line)
        block: list[str] = []
        j = i + 1
        while j < len(lines) and len(block) < 3:
            cur = lines[j].rstrip("\r")
            if _NUMBER_LINE.fullmatch(cur) or cur.strip() == "End of Document":
                break
            if cur.startswith("  "):
                block.append(cur)
            j += 1
        i = j
        if len(block) < 3:
            out["errors"].append(f"record {number} incomplete")
            continue
        org = _clean_org(block[0])
        contact = block[1].strip()
        domains = pen_email_domains(block[2])
        placeholder = org.casefold() in PLACEHOLDER_ORGS or org.startswith("---") or not org
        individual = not placeholder and org.casefold() == contact.casefold()
        webmail = [d for d in domains if is_webmail_domain(d)]
        records.append({
            "number": number,
            "organization": None if individual else (org or None),
            "email_domains": [d for d in domains if not is_webmail_domain(d)],
            "webmail_only": bool(domains) and len(webmail) == len(domains),
            "placeholder": placeholder,
            "individual": individual,
        })
        # FC2: the contact name and the full address (block[1], block[2]) are not kept anywhere
        del contact, block
    return out


# ======================================================================================
# index and offline lookups (FC3, FC4)
# ======================================================================================


def _name_aliases(org: str) -> list[str]:
    """Matching aliases of a registry organisation: URLs removed, '|'-separated alternatives split."""
    base = _URL_IN_NAME.sub(" ", org)
    parts = [re.sub(r"\s+", " ", p).strip(" -,;") for p in base.split("|")]
    return [p for p in parts if p]


@dataclass
class PenIndex:
    updated: str | None = None
    by_number: dict[int, dict[str, Any]] = field(default_factory=dict)
    by_domain: dict[str, list[int]] = field(default_factory=dict)
    by_name: dict[str, list[int]] = field(default_factory=dict)
    names: dict[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    complete: bool = False

    @property
    def records(self) -> int:
        return len(self.by_number)


def build_pen_index(parsed: dict[str, Any]) -> PenIndex:
    idx = PenIndex(updated=parsed.get("updated"), errors=tuple(parsed.get("errors") or ()), complete=bool(parsed.get("complete")))
    name_records: list[dict[str, Any]] = []
    for rec in parsed.get("records") or ():
        if not isinstance(rec, dict) or not isinstance(rec.get("number"), int):
            continue
        n = rec["number"]
        idx.by_number[n] = rec
        for d in rec.get("email_domains") or ():
            idx.by_domain.setdefault(d, []).append(n)
        org = rec.get("organization")
        if org and not rec.get("placeholder"):
            for alias in _name_aliases(org):
                key = namematch.normalized_name(alias)
                if key:
                    idx.by_name.setdefault(key, []).append(n)
                name_records.append({"entry_id": n, "name": alias, "kind": "entity"})
    idx.names = namematch.build_name_index(name_records)
    return idx


def record_status(rec: dict[str, Any] | None) -> str:
    if rec is None:
        return "unassigned"
    if rec.get("placeholder"):
        return "placeholder"
    if rec.get("individual"):
        return "individual"
    return "assigned"


def _public(n: int, rec: dict[str, Any] | None, match: str, **extra: Any) -> dict[str, Any]:
    rec = rec or {}
    out = {
        "number": n,
        "oid": f"{PEN_PREFIX}.{n}",
        "organization": rec.get("organization") if not rec.get("individual") else None,
        "status": record_status(rec if rec else None),
        "match": match,
        "email_domains": list(rec.get("email_domains") or ()),
    }
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def extract_enterprise_oids(text: Any) -> list[dict[str, Any]]:
    """Private-enterprise OIDs in certificate, SNMP or syslog text (FC4): ``1.3.6.1.4.1.<n>``,
    ``iso.3.6.1.4.1.<n>``, ``SNMPv2-SMI::enterprises.<n>`` and ``iso.org.dod.internet.private.enterprise.<n>``.
    Returns ``[{number, match, form}]`` in order of appearance, de-duplicated by number. A bare
    ``enterprise=<n>`` token is not an OID and is ignored (too ambiguous)."""
    s = _text(text)
    found: list[tuple[int, int, str, str]] = []
    for form, rx in _OID_RXES:
        for m in rx.finditer(s):
            found.append((m.start(), int(m.group(1)), m.group(0).lstrip("."), form))
    found.sort()
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for _pos, n, match, form in found:
        if n in seen:
            continue
        seen.add(n)
        out.append({"number": n, "match": match, "form": form})
    return out


def lookup_number(index: PenIndex, number: Any) -> dict[str, Any] | None:
    try:
        n = int(number)
    except (TypeError, ValueError):
        return None
    if n < 0:
        return None
    rec = index.by_number.get(n)
    return _public(n, rec, "number") if rec is not None else None


def reverse_lookup(index: PenIndex, text: Any) -> list[dict[str, Any]]:
    out = []
    for hit in extract_enterprise_oids(text)[:MAX_OIDS]:
        rec = index.by_number.get(hit["number"])
        out.append(_public(hit["number"], rec, "oid", form=hit["form"], text_match=hit["match"]))
    return out


def forward_by_domain(index: PenIndex, domain: Any) -> list[dict[str, Any]]:
    """Exact contact-domain matches ('domain') and subdomains of the query ('domain_suffix'); webmail
    queries are refused (empty)."""
    q = str(domain or "").lower().strip().rstrip(".")
    if not q or is_webmail_domain(q):
        return []
    hits: dict[int, str] = {}
    for n in index.by_domain.get(q, ()):
        hits[n] = "domain"
    suffix = "." + q
    for d, nums in index.by_domain.items():
        if d.endswith(suffix):
            for n in nums:
                hits.setdefault(n, "domain_suffix")
    rank = {"domain": 0, "domain_suffix": 1}
    return [_public(n, index.by_number.get(n), level) for n, level in sorted(hits.items(), key=lambda kv: (rank[kv[1]], kv[0]))]


def forward_by_name(index: PenIndex, name: Any) -> list[dict[str, Any]]:
    """Organisation name -> PEN numbers through the shared matcher (FC3): 'exact' for an equal normalised
    name, 'possible' for a score >= namematch.NAME_MATCH_THRESHOLD (at most MAX_POSSIBLE)."""
    key = namematch.normalized_name(name)
    if not key:
        return []
    hits: dict[int, tuple[str, float]] = {}
    for n in index.by_name.get(key, ()):
        hits[n] = ("exact", 1.0)
    for cand in namematch.match_name(str(name), index.names, kind="entity", limit=MAX_POSSIBLE + len(hits)):
        n = cand.get("entry_id")
        if isinstance(n, int) and n not in hits:
            hits[n] = ("possible", float(cand.get("score") or 0.0))
    exact = [n for n, (lvl, _s) in hits.items() if lvl == "exact"]
    possible = sorted((n for n, (lvl, _s) in hits.items() if lvl == "possible"), key=lambda n: (-hits[n][1], n))[:MAX_POSSIBLE]
    out = [_public(n, index.by_number.get(n), "exact") for n in sorted(exact)]
    out += [_public(n, index.by_number.get(n), "possible", score=round(hits[n][1], 4)) for n in possible]
    return out


# ======================================================================================
# local copy (never downloads: FC1) and the public helpers for other parsers (FC4)
# ======================================================================================

_LOCK = threading.Lock()
_MEMO: dict[str, PenIndex] = {}


def _local_copy(data: Any) -> tuple[Path, Any]:
    try:
        info = data.info(DATASET)
        present = bool(info.present)
    except (ValueError, OSError):
        present, info = False, None
    if not present:
        raise DatasetUnavailable(DATASET, f"IANA PEN registry not downloaded: run v3lum data update {DATASET}")
    return Path(data.fetch(DATASET, ttl=SERVE_LOCAL_TTL)), data.info(DATASET)


def load_index(data: Any = None) -> tuple[PenIndex, dict[str, Any]]:
    """The parsed local registry (parsed once per copy) and its citation meta. ``data`` is ``ctx.data``
    (the read is cited in ``res.datasets``) or None for a plain DataStore. Raises DatasetUnavailable when no
    copy is installed; never downloads."""
    if data is None:
        from v3lum.core.datasets import DataStore

        data = DataStore(None)
    path, info = _local_copy(data)
    sha = str(getattr(info, "sha256", "") or "")
    with _LOCK:
        idx = _MEMO.get(sha) if sha else None
    if idx is None:
        idx = build_pen_index(parse_pen_registry(path.read_bytes()))
        if sha:
            with _LOCK:
                _MEMO.clear()
                _MEMO[sha] = idx
    fetched = str(getattr(info, "fetched_at", "") or "")
    meta = {"dataset": DATASET, "updated": idx.updated, "records": idx.records, "fetched_at": fetched,
            "stale": bool(getattr(info, "age_hours", 0) and float(info.age_hours) > STALE_DAYS * 24)}
    return idx, meta


def pen_lookup(number: Any, data: Any = None) -> dict[str, Any] | None:
    """Core-style helper (FC4): PEN number -> ``{number, oid, organization, status, email_domains}`` from the
    local registry copy, offline; None when the number is not in the registry or no copy is installed.
    ``organization`` is None for individual registrants (withheld, FC2)."""
    try:
        idx, _meta = load_index(data)
    except DatasetUnavailable:
        return None
    return lookup_number(idx, number)


def pen_reverse_lookup(text: Any, data: Any = None) -> list[dict[str, Any]]:
    """Core-style helper (FC4): enterprise OIDs found in ``text`` -> organisations (status 'unassigned' for
    numbers absent from the registry). Empty when no copy is installed (callers say 'not resolved')."""
    try:
        idx, _meta = load_index(data)
    except DatasetUnavailable:
        return []
    return reverse_lookup(idx, text)


def domain_pivots(hit: dict[str, Any]) -> list[str]:
    """Contact domains of one hit that may be pivoted (FC2): assigned records only, never webmail or iana.org."""
    if hit.get("status") != "assigned":
        return []
    return [d for d in hit.get("email_domains") or () if not is_webmail_domain(d) and d != "iana.org" and not d.endswith(".iana.org")]


register_dataset(
    DATASET, PEN_URL, ttl=30 * 86400,
    description="IANA Private Enterprise Numbers registry (enterprise-numbers.txt, ~5 MB, monthly; refreshed by v3lum data update, "
                "never during a scan); parsed offline keeping only PEN, organisation and contact e-mail domain",
    licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, source=SOURCE, validate=validate_pen_registry,
    min_bytes=1_000_000, expect="text", max_bytes=20_000_000, large=True,
)


# ======================================================================================
# the module
# ======================================================================================


def _keyword_number(value: str) -> int | None:
    m = _PEN_KEYWORD.match(value or "")
    return int(m.group(1)) if m else None


@register
class IanaPen(Module):
    name = "iana_pen"
    title = "IANA Private Enterprise Numbers (offline)"
    description = (
        "Offline lookups in the IANA Private Enterprise Numbers registry: company name or domain -> PEN number(s), and "
        "enterprise OIDs (1.3.6.1.4.1.<n>) in certificate/SNMP/syslog text -> organisation. Organisation-level data only."
    )
    category = "company_org"
    accepts = {T.ORG, T.DOMAIN, T.KEYWORD, T.TEXT}
    produces = {T.DOMAIN}
    tags = {"offline"}
    reference = "https://www.iana.org/assignments/enterprise-numbers/"
    notice = (
        "IANA public registry, downloaded monthly by `v3lum data update iana_enterprise_numbers.txt` and matched locally. "
        "Only the PEN number, the organisation name and the contact e-mail DOMAIN are kept: contact names and full addresses "
        "are dropped at parse time, and an individual registrant's name is withheld."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 60.0
    max_pivots = 50
    default_enabled = False  # P228 cond 5: opt-in

    def applies(self, entity: Entity, ctx: Any) -> bool:
        value = str(entity.value)
        if entity.type is T.DOMAIN:
            return not is_webmail_domain(value)  # FC2: never for webmail domains
        if entity.type is T.KEYWORD:
            return _keyword_number(value) is not None or bool(extract_enterprise_oids(value))
        if entity.type is T.TEXT:
            return bool(extract_enterprise_oids(value))
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            index, meta = load_index(ctx.data)
        except DatasetUnavailable as exc:
            return res.mark(Status.UNAVAILABLE, f"{exc}; never read as 'no PEN'", reason_code="dataset")
        except OSError as exc:
            return res.mark(Status.ERROR, f"local IANA PEN copy unreadable ({type(exc).__name__}): could not verify")
        if index.records == 0:
            return res.mark(Status.ERROR, f"local IANA PEN copy holds no record (run v3lum data update {DATASET}): could not verify")
        res.attr("iana_pen_registry", meta)
        as_of = meta.get("updated") or str(meta.get("fetched_at") or "")[:10] or "unknown date"
        value = str(entity.value)
        if entity.type is T.ORG:
            hits = forward_by_name(index, value)
            kind = "name"
        elif entity.type is T.DOMAIN:
            hits = forward_by_domain(index, value)
            kind = "domain"
        else:
            number = _keyword_number(value) if entity.type is T.KEYWORD else None
            if number is not None:
                one = lookup_number(index, number)
                hits = [one] if one else [_public(number, None, "number")]
            else:
                hits = reverse_lookup(index, value)
            kind = "oid"
        hits = hits[:MAX_HITS]
        res.raw = {"query_kind": kind, "registry_updated": index.updated, "hits": hits}
        known = [h for h in hits if h.get("status") != "unassigned"]
        if not known:
            what = {"name": "organisation name", "domain": "contact domain", "oid": "enterprise number"}[kind]
            return res.mark(Status.EMPTY, f"no IANA PEN registration matches this {what} (registry as of {as_of})")
        res.attr("iana_pen", hits)
        if meta.get("stale"):
            res.attr("dataset_age", [f"{DATASET}, registry as of {as_of} (older than {STALE_DAYS} days: run v3lum data update)"])
        for hit in known:
            self._finding(res, hit, kind, as_of)
            confidence = "possible" if hit.get("match") == "possible" else "probable"
            for d in domain_pivots(hit):
                res.pivot(T.DOMAIN, d, "iana_pen_contact_domain", confidence=confidence, expand=False,
                          note=f"contact e-mail domain of IANA PEN {hit['number']} ({hit.get('organization') or 'organisation'}); "
                               "organisation-level contact, analyst selection required")
        return res

    def _finding(self, res: ModuleResult, hit: dict[str, Any], kind: str, as_of: str) -> None:
        n = hit["number"]
        org = hit.get("organization")
        status = hit.get("status")
        label = org or ("individual registrant (name withheld)" if status == "individual" else status or "unknown")
        data = {k: hit.get(k) for k in ("number", "oid", "organization", "status", "match", "email_domains", "form") if hit.get(k) is not None}
        if hit.get("match") == "possible":
            res.finding(
                "Possible IANA Private Enterprise Number match", "info",
                f"PEN {n} ({hit['oid']}) is registered to '{label}': possible name match - verify before attributing (registry as of {as_of})",
                confidence="possible", source=SOURCE, key=str(n), tags=["name_only_match"], data=data,
                criterion=f"organisation name similar to the query (token-set score {hit.get('score')}, threshold "
                          f"{namematch.NAME_MATCH_THRESHOLD}) in the IANA PEN registry: a possible match, not an exact one",
            )
            return
        if kind == "oid":
            title, crit = ("Enterprise OID resolved to its IANA PEN registrant",
                           f"OID {hit['oid']} ({hit.get('form') or 'pen'}) belongs to PEN {n} in the IANA registry")
        elif kind == "domain":
            title, crit = ("IANA Private Enterprise Number registered with this contact domain",
                           f"the PEN {n} contact e-mail domain {'equals' if hit.get('match') == 'domain' else 'is a subdomain of'} the query")
        else:
            title, crit = ("IANA Private Enterprise Number assigned to this organisation",
                           f"organisation name equal to the query after normalisation (PEN {n})")
        res.finding(
            title, "info", f"PEN {n} ({hit['oid']}): {label} (registry as of {as_of})",
            confidence="probable" if status == "assigned" else "possible", source=SOURCE, key=str(n), criterion=crit, data=data,
        )


__all__ = [
    "DATASET", "IanaPen", "PenIndex", "build_pen_index", "domain_pivots", "extract_enterprise_oids", "forward_by_domain",
    "forward_by_name", "is_webmail_domain", "load_index", "lookup_number", "parse_pen_registry", "pen_email_domains", "pen_lookup",
    "pen_reverse_lookup", "registry_problem", "reverse_lookup", "validate_pen_registry",
]
