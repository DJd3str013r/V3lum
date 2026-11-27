"""Typosquat / brand-impersonation engine (P012): offline reverse match plus a DoH forward scan.

Reverse mode (default, offline, < 1 s, P012 c4): is the INPUT domain a lookalike of a protected
domain or brand - org_profile domains/brands and suppliers (P378), the BCB DominiosVerificados list
(P360, when its dataset is installed)? A match gives one finding and ``lookalike_of`` pivots
(expand=False). Own assets and protected domains themselves are never reported as lookalikes.

Forward scan (P012 c5-c9) only on analyst-typed seeds that are org_profile domains/brands, or when the
analyst selected the module explicitly (``-M typosquat``); never on pivots, subdomains or arbitrary
hostile domains (``run_on='seeds'``):

* candidates come from the shared permutation helper (``typosquat_permutations``: dnstwist fuzzers,
  pt-BR combo-squats from ``v3lum/data/typosquat/brand_lures_pt.json``, accent/IDN homoglyphs, TLD
  swaps), validated with IDNA/UTS-46 before any query, ranked and capped (150; 500 with --preset deep);
* registration is checked only through the core DoH resolver (``ctx.dns``, hostile=True: ECS-free
  Cloudflare first, Google always with ``edns_client_subnet=0.0.0.0/0``), never the system resolver
  and never registro.br availability calls; staged: NS (then A) for every candidate, MX/AAAA only for
  registered names; budget 300 queries per run (setting), <= 10 q/s, 45 s module budget,
  ``ctx.cancelled()`` honoured, a cap hit reported in coverage (rule 5: SERVFAIL, REFUSED and timeouts
  are 'could not verify', only an NXDOMAIN counts as unregistered - confirmed by a second resolver
  within the budget, P029 c10);
* RDAP for registered .br candidates through registro.br (at most 10 per run), minimised at ingestion
  (P003 c4-c6: registrar, organisation, CNPJ roots, events, nameservers; natural persons and CPF are
  never kept); RDAP for other TLDs waits for the P003 helper (backlog p1-G01-2);
* severity ladder (P012 c8/c9): registered only = INFO (one table); one activity signal (MX, NRD
  <= 30 d, non-parking A record) = MEDIUM; HIGH needs >= 2 signals AND evidence the name is not
  brand-owned; parking/sinkhole caps at LOW; own and defensive registrations go to the own-asset
  section, never into typosquat findings.

No LIGHT contact: candidates are hostile by default (P012 c10); HTTP, page similarity and SMTP checks
belong to the later ``typosquat_live_checks`` module behind the P376 guard.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import datasets as _datasets
from v3lum.core import noise, psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns import typosquat_permutations as perm

SOURCE_DOH = "core_doh.resolvers"
SOURCE_RDAP_BR = "registrobr.rdap"
SOURCE_BCB = "bcb.olinda_institutions"
RDAP_BR = "https://rdap.registro.br/domain/{domain}"
LURES_FILE = "typosquat/brand_lures_pt.json"

#: first lure words reused by the dnstwist dictionary fuzzer (the combo fuzzer uses all of them)
DICTIONARY_WORDS = 10
#: seconds kept free before the run deadline (the engine marks an overdue run ERROR 'timeout')
_DEADLINE_MARGIN = 4.0
_TOP_N = 10
_MAX_REVERSE_PIVOTS = 5
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_STRONG_TECHNIQUES = frozenset({"homoglyph", "homoglyph+tld-swap", "tld-swap", "combo", "hyphenation", "subdomain", "brand-label"})

#: Brand-protection / corporate registrars (own work, P012 c9: MarkMonitor, CSC, Com Laude...):
#: lower-case substring of the registrar name -> label.
BRAND_PROTECTION_REGISTRARS: tuple[tuple[str, str], ...] = (
    ("markmonitor", "MarkMonitor"),
    ("csc corporate domains", "CSC"),
    ("corporation service company", "CSC"),
    ("cscglobal", "CSC"),
    ("com laude", "Com Laude"),
    ("nom-iq", "Com Laude"),
    ("safenames", "Safenames"),
    ("brandsight", "GoDaddy Corporate Domains"),
    ("godaddy corporate domains", "GoDaddy Corporate Domains"),
    ("lexsynergy", "Lexsynergy"),
    ("ip twins", "IP Twins"),
    ("nameshield", "Nameshield"),
    ("mailclub", "Mailclub"),
    ("authentic web", "Authentic Web"),
    ("brandit", "BRANDIT"),
    ("valideus", "Valideus"),
    ("demys", "Demys"),
    ("ebrand", "EBRAND"),
    ("instra corporation", "Instra"),
    ("ascio technologies", "Ascio"),
    ("netnames", "CSC (NetNames)"),
)

_PRIVACY_MARKERS = (
    "redacted", "privacy", "withheld", "domains by proxy", "whoisguard", "contact privacy", "data protected",
    "statutory masking", "not disclosed", "gdpr masked", "proxy protection", "perfect privacy", "identity protect",
    "private registration", "registrant of ",
)
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _clean(value: Any, limit: int = 160) -> str:
    """Untrusted string -> one line without control characters, capped."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", _CTRL.sub(" ", value)).strip()[:limit]


def _setting(ctx: Any, name: str, default: Any) -> Any:
    try:
        value = ctx.setting(name, default)
    except Exception:  # a broken setting never stops the run
        return default
    return default if value is None else value


def _int_setting(ctx: Any, name: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(_setting(ctx, name, default))))
    except (TypeError, ValueError):
        return default


def _norm_host(value: Any) -> str:
    return value.strip().rstrip(".").lower() if isinstance(value, str) else ""


def _host_under(host: str, domains: Iterable[str]) -> str | None:
    h = _norm_host(host)
    for d in domains:
        d = _norm_host(d)
        if d and (h == d or h.endswith("." + d)):
            return d
    return None


def _digits(value: Any) -> str:
    return re.sub(r"\D", "", value) if isinstance(value, str) else ""


def cnpj_root(value: Any) -> str | None:
    """8-digit CNPJ root from a full CNPJ (14 digits) or a root (8 digits; BCB rows may lose leading zeros)."""
    d = _digits(value if isinstance(value, str) else str(value or ""))
    if len(d) in (8, 14):
        return d[:8]
    if 1 <= len(d) < 8:
        return d.zfill(8)
    return None


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def is_registrable(domain: str) -> bool:
    """True when ``domain`` is a registrable domain (eTLD+1), not a subdomain or a public suffix."""
    try:
        return psl.registrable_domain(domain) == domain.strip(".").lower()
    except Exception:
        return False


def brand_protection_registrar(name: Any) -> str | None:
    """Label of a brand-protection/corporate registrar (P012 c9), else None."""
    n = _clean(name, 200).lower()
    if not n:
        return None
    for needle, label in BRAND_PROTECTION_REGISTRARS:
        if needle in n:
            return label
    return None


# --------------------------------------------------------------------------------------
# RDAP minimisation (P003 c4-c6 applied to lookalike registrants, P012 c6)
# --------------------------------------------------------------------------------------


def _vcard(entity: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    v = entity.get("vcardArray") if isinstance(entity, Mapping) else None
    if isinstance(v, list) and len(v) > 1 and isinstance(v[1], list):
        for item in v[1]:
            if isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str):
                val = item[3]
                if isinstance(val, list):
                    val = " ".join(x for x in val if isinstance(x, str))
                if isinstance(val, str):
                    out.setdefault(item[0].lower(), val)
    return out


def _walk_entities(entities: Any, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    if depth > 4 or not isinstance(entities, list):
        return
    for e in entities:
        if isinstance(e, Mapping):
            yield e
            yield from _walk_entities(e.get("entities"), depth + 1)


def parse_rdap(data: Any, now: datetime | None = None) -> dict[str, Any]:
    """Minimised facts from one RDAP domain answer (RFC 9083): registrar + IANA id, registrant kind
    ('org' | 'individual' | 'redacted' | None), the registrant organisation only when it is an
    organisation, CNPJ roots (publicIds type cnpj), nameservers, status, created/expires/updated and
    age_days. Natural-person names, e-mails, phones, addresses and CPF publicIds are never returned
    (``cpf_seen`` only says one was present). ``error`` is set for answers that are not RDAP domains."""
    out: dict[str, Any] = {
        "registrar": None, "registrar_iana_id": None, "registrant_kind": None, "registrant_org": None,
        "cnpj_roots": [], "cpf_seen": False, "nameservers": [], "status": [], "created": None, "expires": None,
        "updated": None, "age_days": None, "error": None,
    }
    if not isinstance(data, Mapping) or data.get("objectClassName") not in ("domain", None):
        out["error"] = "not an RDAP domain object"
        return out
    if data.get("errorCode") is not None:
        out["error"] = f"RDAP error {_clean(str(data.get('errorCode')), 8)}"
        return out
    out["status"] = [_clean(s, 60) for s in data.get("status") or [] if isinstance(s, str)][:12]
    roots: list[str] = []
    for e in _walk_entities(data.get("entities")):
        roles = [r for r in e.get("roles") or [] if isinstance(r, str)]
        card = _vcard(e)
        pids = [p for p in e.get("publicIds") or [] if isinstance(p, Mapping)]
        if "registrar" in roles and out["registrar"] is None:
            out["registrar"] = _clean(card.get("fn") or card.get("org") or "", 120) or None
            for p in pids:
                if str(p.get("type", "")).lower().startswith("iana registrar"):
                    out["registrar_iana_id"] = _clean(str(p.get("identifier", "")), 12) or None
            handle = e.get("handle")
            if out["registrar_iana_id"] is None and isinstance(handle, str) and handle.isdigit() and len(handle) <= 8:
                out["registrar_iana_id"] = handle
        if "registrant" not in roles:
            continue
        kind = (card.get("kind") or "").lower()
        text = " ".join([card.get("fn", ""), card.get("org", "")]).lower()
        has_cnpj = False
        for p in pids:
            ptype = str(p.get("type", "")).lower()
            if ptype == "cnpj":
                root = cnpj_root(str(p.get("identifier", "")))
                if root and root not in roots:
                    roots.append(root)
                    has_cnpj = True
            elif ptype == "cpf":
                out["cpf_seen"] = True  # never stored, never pivoted (rule 4, P003 c6)
        if any(m in text for m in _PRIVACY_MARKERS):
            out["registrant_kind"] = "redacted"
        elif kind == "org" or has_cnpj:
            out["registrant_kind"] = "org"
            out["registrant_org"] = _clean(card.get("org") or card.get("fn") or "", 160) or None
        elif kind == "individual" or out["cpf_seen"]:
            out["registrant_kind"] = "individual"  # a natural person: no name is kept
        elif out["registrant_kind"] is None and not text.strip():
            out["registrant_kind"] = "redacted"
    out["cnpj_roots"] = roots
    for ev in data.get("events") or []:
        if not isinstance(ev, Mapping):
            continue
        action = str(ev.get("eventAction", "")).lower()
        dt = _parse_dt(ev.get("eventDate"))
        if action == "registration":
            out["created"] = _iso(dt)
        elif action == "expiration":
            out["expires"] = _iso(dt)
        elif action == "last changed":
            out["updated"] = _iso(dt)
    for ns in data.get("nameservers") or []:
        if isinstance(ns, Mapping):
            h = _norm_host(ns.get("ldhName"))
            if h and h not in out["nameservers"]:
                out["nameservers"].append(h)
    created = _parse_dt(out["created"])
    if created:
        ref = now or datetime.now(timezone.utc)
        out["age_days"] = max(0, (ref - created).days)
    return out


# --------------------------------------------------------------------------------------
# ownership and the severity ladder (P012 c8, c9)
# --------------------------------------------------------------------------------------


def brand_ownership(candidate: Mapping[str, Any], owner: Mapping[str, Any]) -> dict[str, Any]:
    """Is a registered lookalike brand-owned? (P012 c9, P028 c5).

    ``candidate``: {domain, ns, mx, registrar, cnpj_roots, registrant_kind}. ``owner``: {domains,
    cnpj_roots} of the protected party (org_profile, or the institution of a BCB row). Shared providers
    (Cloudflare NS, Google MX) prove nothing: only NS/MX hosts under an owner domain count.

    Verdicts: ``own_asset`` (owner domain, owner CNPJ root, or NS/MX under an owner domain),
    ``defensive_probable`` (brand-protection registrar), ``not_brand_owned`` (registrar known and not a
    brand-protection one, or - for .br, where registro.br publishes no registrar - a different
    registrant CNPJ root; and NS known and not the owner's) or ``unknown`` (not enough facts: the ladder
    cannot reach HIGH). Returns {verdict, evidence, registrant_checked}.
    """
    cand = candidate or {}
    own = owner or {}
    dom = _norm_host(cand.get("domain"))
    own_domains = [_norm_host(d) for d in own.get("domains") or [] if d]
    own_roots = {r for r in (cnpj_root(x) for x in own.get("cnpj_roots") or []) if r}
    if dom and _host_under(dom, own_domains):
        return {"verdict": "own_asset", "evidence": ["protected domain itself"], "registrant_checked": False}
    roots = {r for r in (cnpj_root(x) for x in cand.get("cnpj_roots") or []) if r}
    if roots & own_roots:
        return {"verdict": "own_asset", "evidence": ["registrant CNPJ root equals the owner's"], "registrant_checked": True}
    for kind, hosts in (("NS", cand.get("ns") or []), ("MX", cand.get("mx") or [])):
        for h in hosts:
            if _host_under(h, own_domains):
                return {"verdict": "own_asset", "evidence": [f"{kind} {_norm_host(h)} is under an owner domain"], "registrant_checked": bool(roots)}
    bp = brand_protection_registrar(cand.get("registrar"))
    if bp:
        return {"verdict": "defensive_probable", "evidence": [f"brand-protection registrar ({bp})"], "registrant_checked": bool(roots)}
    evidence: list[str] = []
    registrar_known = bool(_clean(cand.get("registrar") or ""))
    ns_known = bool(cand.get("ns"))
    if registrar_known:
        evidence.append("registrar is not a brand-protection registrar")
    if ns_known:
        evidence.append("NS not under an owner domain")
    if cand.get("mx"):
        evidence.append("MX not under an owner domain")
    registrant_checked = False
    if roots and own_roots:
        evidence.append("registrant CNPJ root differs from the owner's")
        registrant_checked = True
    elif cand.get("registrant_kind") in ("redacted", None, "individual"):
        evidence.append("registrant unverified (redacted, individual or unavailable)")
    if registrar_known and ns_known:
        return {"verdict": "not_brand_owned", "evidence": evidence, "registrant_checked": registrant_checked}
    if ns_known and registrant_checked:  # .br: registro.br RDAP has no registrar, the CNPJ comparison stands in
        return {"verdict": "not_brand_owned", "evidence": evidence, "registrant_checked": True}
    return {"verdict": "unknown", "evidence": evidence or ["no RDAP/NS facts"], "registrant_checked": registrant_checked}


def severity_ladder(signals: Mapping[str, Any], ownership: str, *, parked: bool = False, sinkhole: bool = False) -> dict[str, Any]:
    """The P012 c8 ladder with the c9 caps and own-asset suppression (unit-tested).

    ``signals`` (missing = absent): ``mx`` (non-null MX present), ``ct_cert_days`` (age of the FIRST
    CT certificate), ``nrd_days`` (RDAP created or an NRD feed), ``a_non_parking`` (A record not on a
    parking/sinkhole list), ``phishing_list`` and ``page_similarity`` (LIGHT, typosquat_live_checks).
    registered only = INFO (info table); one signal = MEDIUM; HIGH needs >= 2 signals AND
    ``ownership == 'not_brand_owned'``; parked/sinkhole caps at LOW; own_asset/defensive_probable ->
    own-asset section, never a typosquat finding. The same ladder applies to BCB/gov.br protected
    domains. Returns {severity: 'info'|'low'|'medium'|'high'|None, section, signals, capped}.
    """
    s = signals or {}
    if ownership in ("own_asset", "defensive_probable"):
        return {"severity": None, "section": "own_assets", "signals": [], "capped": None}
    hit: list[str] = []
    if s.get("mx"):
        hit.append("mx")
    ct = s.get("ct_cert_days")
    if isinstance(ct, int) and not isinstance(ct, bool) and 0 <= ct <= 30:
        hit.append("ct_cert<=30d")
    nrd = s.get("nrd_days")
    if isinstance(nrd, int) and not isinstance(nrd, bool) and 0 <= nrd <= 30:
        hit.append("nrd<=30d")
    if s.get("a_non_parking") and not (parked or sinkhole):
        hit.append("a_non_parking")
    if s.get("phishing_list"):
        hit.append("phishing_list")
    if s.get("page_similarity"):
        hit.append("page_similarity")
    if not hit:
        sev, section = "info", "info_table"
    elif len(hit) >= 2 and ownership == "not_brand_owned":
        sev, section = "high", "findings"
    else:
        sev, section = "medium", "findings"
    capped = None
    if (parked or sinkhole) and _SEVERITY_RANK[sev] > _SEVERITY_RANK["low"]:
        capped = "sinkhole" if sinkhole else "parked"
        sev = "low"
    return {"severity": sev, "section": section, "signals": hit, "capped": capped}


# --------------------------------------------------------------------------------------
# protected entries (reverse mode, ownership)
# --------------------------------------------------------------------------------------


def parse_bcb_rows(data: Any) -> list[dict[str, Any]]:
    """BCB DominiosVerificados OData rows -> protected entries {domain, source 'bcb', institution,
    cnpj_root, owner_cnpj_root}. Rows without DOMINIO are skipped; junk is ignored."""
    rows = data.get("value") if isinstance(data, Mapping) else None
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, Mapping):
            continue
        dom = _norm_host(r.get("DOMINIO"))
        if not dom or "." not in dom or len(dom) > 253:
            continue
        key = (dom, cnpj_root(str(r.get("CNPJ") or "")))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "domain": dom, "source": "bcb", "institution": _clean(str(r.get("INSTITUICAO_FINANCEIRA") or ""), 160) or None,
            "cnpj_root": key[1], "owner_cnpj_root": cnpj_root(str(r.get("CNPJ_NO_REGISTRO_DO_DOMINIO") or "")),
        })
    return out


def _bcb_dataset(ctx: Any) -> tuple[list[dict[str, Any]], str]:
    """Protected rows of the P360 BCB DominiosVerificados dataset when it is registered and installed.

    The dataset belongs to bcb_authorized_institutions (P360): it is found by its registry source and
    URL, read from the local copy and never registered or forced to download here."""
    for name, reg in sorted(_datasets.DATASETS.items()):
        if not isinstance(reg, Mapping) or reg.get("source") != SOURCE_BCB:
            continue
        if "dominiosverificados" not in str(reg.get("url", "")).lower():
            continue
        try:
            info = ctx.data.info(name)
            if not getattr(info, "present", False):
                return [], f"BCB DominiosVerificados ({name}) not downloaded: run v3lum data update {name}"
            return parse_bcb_rows(ctx.data.fetch_json(name)), ""
        except Exception as exc:  # DatasetError/DatasetUnavailable or a broken copy: list not applied
            return [], f"BCB DominiosVerificados ({name}) unavailable: {_clean(str(exc), 120)}"
    return [], "BCB DominiosVerificados list not installed (P360 bcb_authorized_institutions)"


def _org_entries(org: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(domains, brands) protected by the org profile: own entries ('org_profile') and suppliers."""
    domains: list[dict[str, Any]] = []
    brands: list[dict[str, Any]] = []
    if org is None:
        return domains, brands
    for d in getattr(org, "domains", None) or []:
        name = getattr(d, "name", "")
        if name:
            domains.append({"domain": name, "source": "org_profile"})
    for b in getattr(org, "brands", None) or []:
        for kw in (getattr(b, "keyword", ""), *(getattr(b, "variants", ()) or ())):
            if kw:
                brands.append({"keyword": kw, "source": "org_profile"})
    for s in getattr(org, "suppliers", None) or []:
        for name in getattr(s, "domains", ()) or ():
            domains.append({"domain": name, "source": "supplier"})
        for kw in getattr(s, "brands", ()) or ():
            brands.append({"keyword": kw, "source": "supplier"})
    return domains, brands


def load_lures(ctx: Any) -> list[str]:
    """The bundled pt-BR/EN lure dictionary (P012 c2), [] when unreadable."""
    try:
        doc = ctx.data.bundled_json(LURES_FILE)
    except Exception:
        return []
    words = doc.get("words") if isinstance(doc, Mapping) else None
    return [w for w in words if isinstance(w, str) and re.fullmatch(r"[a-z0-9-]{1,30}", w)] if isinstance(words, list) else []


# --------------------------------------------------------------------------------------
# the forward scan pipeline (shared with typosquat_dnstwister)
# --------------------------------------------------------------------------------------


class _Pacer:
    """<= ``qps`` DoH queries per second on the runtime clock (fake clocks never block)."""

    def __init__(self, ctx: Any, qps: float) -> None:
        self.clock = getattr(getattr(ctx, "runtime", None), "clock", None)
        self.interval = 1.0 / qps if qps and qps > 0 else 0.0
        self.last: float | None = None

    def wait(self) -> None:
        clock = self.clock
        if clock is None or not self.interval:
            return
        now = clock.monotonic()
        if self.last is not None:
            delay = self.last + self.interval - now
            if delay > 0:
                clock.sleep(min(delay, 1.0))
                now = clock.monotonic()
        self.last = now


class _Stop(Exception):
    """End of the forward scan: budget, deadline or kill switch (``reason`` is a STOP_REASON)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ForwardScan:
    """Staged DoH registration checks, RDAP (.br), ownership and the ladder for ranked candidates.

    ``owner`` = {domains, cnpj_roots} of the protected party. Results are written into ``res`` by
    :meth:`report`. Used by ``typosquat`` and ``typosquat_dnstwister``.
    """

    def __init__(self, ctx: Any, res: ModuleResult, *, seed: str, owner: Mapping[str, Any], deep: bool, rdap_cap: int, max_pivots: int = 100) -> None:
        self.ctx = ctx
        self.res = res
        self.seed = seed
        self.owner = owner
        self.deep = deep
        self.budget = _int_setting(ctx, "typosquat_doh_budget", 300, 1, 5000)
        self.confirm = bool(_setting(ctx, "typosquat_confirm_nxdomain", True))
        qps = _setting(ctx, "typosquat_doh_qps", 10.0)
        try:
            qps = max(0.5, min(10.0, float(qps)))
        except (TypeError, ValueError):
            qps = 10.0
        self.pacer = _Pacer(ctx, qps)
        self.rdap_cap = max(0, rdap_cap)
        self.queries = 0
        self.stop_reason = ""
        self.rows: dict[str, dict[str, Any]] = {}
        self.unchecked: list[str] = []
        self.rdap_used = 0
        self.rdap_status: tuple[Status, str, str] | None = None
        self.wildcards: dict[str, set[str]] = {}
        self.confirm_note = ""
        self.max_pivots = max_pivots

    # ---- DoH ---------------------------------------------------------------------------------
    def _guard(self, cost: int = 1) -> None:
        if self.ctx.cancelled():
            raise _Stop("cancelled")
        remaining = self.ctx.remaining()
        if remaining is not None and remaining < _DEADLINE_MARGIN:
            raise _Stop("deadline")
        if self.queries + cost > self.budget:
            raise _Stop("request_cap")

    def _ask(self, name: str, rtype: str) -> Any:
        self._guard()
        self.pacer.wait()
        self.queries += 1
        return self.ctx.dns.query(name, rtype, hostile=True)

    def _confirm(self, name: str) -> bool | None:
        """A second, different resolver must also answer NXDOMAIN (P029 c10). The repeated first query
        is served by the core DoH cache, so one query is charged."""
        self._guard()
        self.pacer.wait()
        self.queries += 1
        return self.ctx.dns.confirm_nxdomain(name, "NS", hostile=True)

    def _wildcard_records(self, suffix: str) -> set[str]:
        """Records a random name under ``suffix`` gets (empty when the TLD has no wildcard or the probe
        could not be verified); one probe per suffix and run."""
        if suffix not in self.wildcards:
            self._guard(2)
            self.queries += 2
            try:
                info = self.ctx.dns.wildcard_info(suffix, hostile=True)
                self.wildcards[suffix] = set(info.records) if getattr(info, "wildcard", None) else set()
            except (Cancelled, DeadlineExceeded):
                raise
            except Exception:  # a probe failure never decides registration
                self.wildcards[suffix] = set()
        return self.wildcards[suffix]

    @staticmethod
    def _status(ans: Any) -> str:
        status = str(getattr(ans, "status", "") or "")
        if getattr(ans, "error", ""):
            return status if status not in ("NOERROR", "NXDOMAIN") else "ERROR"
        return status or "ERROR"

    def _stage1(self, cand: Mapping[str, Any]) -> None:
        name = str(cand["domain"])
        self._guard()  # before the row exists: a stop here leaves the candidate unchecked
        row: dict[str, Any] = {
            "domain": name, "domain_unicode": cand.get("domain_unicode") or name, "fuzzer": cand.get("fuzzer"),
            "score": cand.get("score"), "state": "could_not_verify", "doh": {}, "ns": [], "a": [], "mx": [], "aaaa": [],
        }
        self.rows[name] = row
        ns = self._ask(name, "NS")
        row["doh"]["NS"] = self._status(ns)
        if ns.nxdomain:
            row["state"] = "nxdomain"
            return
        if not ns.ok:
            row["reason"] = _clean(getattr(ns, "error", "") or ns.status, 160)
            return
        row["ns"] = [h for h in (_norm_host(r) for r in ns.records) if h][:8]
        if row["ns"]:
            row["state"] = "registered"  # delegated: registered whatever the A answer says
        else:
            row["reason"] = "NS NOERROR without records: A decides"
        a = self._ask(name, "A")
        row["doh"]["A"] = self._status(a)
        if a.ok:
            row["a"] = [r for r in a.records if isinstance(r, str) and r.count(".") == 3][:8]
        if row["ns"]:
            return
        # NOERROR/NODATA on NS: the name exists unless a wildcard TLD answers for every name
        if a.nxdomain:
            row["reason"] = "NS NODATA but A NXDOMAIN (inconsistent answers)"
            return
        if not a.ok:
            row["reason"] = _clean(getattr(a, "error", "") or a.status, 160)
            return
        if row["a"]:
            wild = self._wildcard_records(psl.public_suffix(name) or name.split(".", 1)[-1])
            if wild and set(row["a"]) <= wild:
                row["reason"] = "wildcard TLD answers for any name"
                return
        row.pop("reason", None)
        row["state"] = "registered"

    def _stage2(self, row: dict[str, Any]) -> None:
        name = row["domain"]
        mx = self._ask(name, "MX")
        row["doh"]["MX"] = self._status(mx)
        if mx.ok:
            hosts = []
            for r in mx.records:
                parts = str(r).split()
                host = parts[-1] if parts else ""
                hosts.append("" if host in (".", "") else _norm_host(host))
            row["mx"] = [h for h in hosts if h][:8]
            row["null_mx"] = bool(hosts) and all(h == "" for h in hosts)
        if not row["a"]:
            aaaa = self._ask(name, "AAAA")
            row["doh"]["AAAA"] = self._status(aaaa)
            if aaaa.ok:
                row["aaaa"] = [r for r in aaaa.records if isinstance(r, str) and ":" in r][:8]

    def check(self, ranked: list[dict[str, Any]]) -> None:
        """NS/A for every candidate in rank order, then MX/AAAA for registered names, then NXDOMAIN
        confirmation by a second resolver within the remaining budget. Stops on budget, deadline or
        kill switch (``stop_reason``); confirmations are best effort: names left unconfirmed are
        counted as 'NXDOMAIN not confirmed', never as unregistered."""
        names = [c for c in ranked if isinstance(c, Mapping) and c.get("domain")]
        try:
            for i, cand in enumerate(names):
                try:
                    self._stage1(cand)
                except _Stop:
                    self.unchecked = [c["domain"] for c in names[i:] if c["domain"] not in self.rows]
                    raise
            for row in self._ordered("registered"):
                self._stage2(row)
        except _Stop as stop:
            self.stop_reason = stop.reason
            return
        except (Cancelled, DeadlineExceeded) as exc:  # raised by the DoH scope itself
            self.stop_reason = "cancelled" if isinstance(exc, Cancelled) else "deadline"
            return
        if not self.confirm:
            self.confirm_note = "NXDOMAIN confirmation disabled (typosquat_confirm_nxdomain)"
            return
        try:
            for row in self._ordered("nxdomain"):
                verdict = self._confirm(row["domain"])
                row["nxdomain_confirmed"] = verdict
                if verdict is True:
                    row["state"] = "unregistered"
                elif verdict is False:  # the second resolver says the name exists
                    row["state"] = "could_not_verify"
                    row["reason"] = "resolvers disagree (NXDOMAIN vs NOERROR)"
        except _Stop as stop:
            if stop.reason != "request_cap":  # an exhausted budget only leaves negatives unconfirmed
                self.stop_reason = stop.reason
            else:
                self.confirm_note = "DoH budget used up before every NXDOMAIN was confirmed"
        except (Cancelled, DeadlineExceeded) as exc:
            self.stop_reason = "cancelled" if isinstance(exc, Cancelled) else "deadline"

    def _ordered(self, state: str) -> list[dict[str, Any]]:
        rows = [r for r in self.rows.values() if r.get("state") == state]
        rows.sort(key=lambda r: (-int(r.get("score") or 0), r["domain"]))
        return rows

    # ---- RDAP (.br) --------------------------------------------------------------------------
    def rdap(self) -> None:
        """RDAP for registered .br candidates through registro.br (best scores first, capped)."""
        if self.stop_reason in ("cancelled", "deadline"):
            return
        for row in self._ordered("registered"):
            if self.rdap_used >= self.rdap_cap:
                break
            suffix = psl.public_suffix(row["domain"]) or ""
            if not perm.is_br(suffix):
                row["rdap"] = "not_available"  # gTLD RDAP waits for the P003 helper
                continue
            remaining = self.ctx.remaining()
            if self.ctx.cancelled() or (remaining is not None and remaining < _DEADLINE_MARGIN):
                break
            self.rdap_used += 1
            try:
                data = self.ctx.http.get_json(RDAP_BR.format(domain=row["domain"]), source=SOURCE_RDAP_BR, absent={404})
            except RequestCapReached:
                break
            except (RateLimited, QuotaExceeded) as exc:
                self.rdap_status = (Status.RATE_LIMITED if isinstance(exc, RateLimited) else Status.QUOTA, "", _clean(str(exc), 160))
                row["rdap"] = "could_not_verify"
                break
            except (Blocked, AuthRequired) as exc:
                self.rdap_status = (Status.BLOCKED, str(getattr(exc, "reason_code", "") or "challenge"), _clean(str(exc), 160))
                row["rdap"] = "could_not_verify"
                break
            except (Cancelled, DeadlineExceeded):
                break
            except (HttpError, NetworkError, PolicyError, ValueError) as exc:
                row["rdap"] = "could_not_verify"
                self.rdap_status = (Status.ERROR, "error", _clean(str(exc), 160))
                continue
            if data is None:
                row["rdap"] = "not_found"  # registro.br 404 for a name the DNS answered: kept as a fact
                continue
            facts = parse_rdap(data, now=self.ctx.now())
            if facts.get("error"):
                row["rdap"] = "could_not_verify"
                continue
            row["rdap"] = "ok"
            for key in ("registrar", "registrar_iana_id", "registrant_kind", "registrant_org", "cnpj_roots", "created", "age_days"):
                if facts.get(key) not in (None, [], ""):
                    row[key] = facts[key]

    # ---- verdicts ----------------------------------------------------------------------------
    def judge(self) -> None:
        for row in self.rows.values():
            if row.get("state") != "registered":
                continue
            parked = [h for h in row["ns"] if _flag(T.DOMAIN, h, noise.is_parked)]
            parked += [ip for ip in row["a"] if _flag(T.IPV4, ip, noise.is_parked)]
            sinkhole = [ip for ip in row["a"] if _flag(T.IPV4, ip, noise.is_sinkhole)]
            row["parked"] = bool(parked)
            row["sinkhole"] = bool(sinkhole)
            if parked or sinkhole:
                row["parking_evidence"] = (parked + sinkhole)[:4]
            own = brand_ownership(
                {"domain": row["domain"], "ns": row["ns"], "mx": row["mx"], "registrar": row.get("registrar"),
                 "cnpj_roots": row.get("cnpj_roots") or [], "registrant_kind": row.get("registrant_kind")},
                self.owner,
            )
            row["ownership"] = own["verdict"]
            row["ownership_evidence"] = own["evidence"]
            signals = {"mx": bool(row["mx"]), "nrd_days": row.get("age_days"), "a_non_parking": bool(row["a"])}
            ladder = severity_ladder(signals, own["verdict"], parked=row["parked"], sinkhole=row["sinkhole"])
            row["severity"] = ladder["severity"]
            row["section"] = ladder["section"]
            row["signals"] = ladder["signals"]
            row["capped"] = ladder["capped"]

    # ---- output ------------------------------------------------------------------------------
    def report(self, *, coverage: dict[str, Any], seed_label: str) -> None:
        res = self.res
        registered = [r for r in self.rows.values() if r.get("state") == "registered"]
        own = [r for r in registered if r.get("section") == "own_assets"]
        hits = [r for r in registered if r.get("section") != "own_assets"]
        hits.sort(key=lambda r: (-_SEVERITY_RANK.get(str(r.get("severity")), 0), -int(r.get("score") or 0), r["domain"]))
        table = [_public_row(r) for r in hits]
        cnv = [r["domain"] for r in self.rows.values() if r.get("state") == "could_not_verify"]
        coverage.update({
            "candidates_checked": len(self.rows),
            "registered": len(registered),
            "own_or_defensive": len(own),
            "unregistered": sum(1 for r in self.rows.values() if r.get("state") == "unregistered"),
            "nxdomain_unconfirmed": sum(1 for r in self.rows.values() if r.get("state") == "nxdomain"),
            "could_not_verify": len(cnv),
            "unchecked": len(self.unchecked),
            "doh_queries": self.queries,
            "doh_budget": self.budget,
            "doh_cap_hit": self.stop_reason == "request_cap" or "budget" in self.confirm_note,
            "rdap_lookups": self.rdap_used,
            "rdap_cap": self.rdap_cap,
        })
        if self.stop_reason:
            coverage["stopped"] = {"request_cap": "DoH budget reached", "deadline": "module time budget reached",
                                   "cancelled": "cancelled"}.get(self.stop_reason, self.stop_reason)
        if self.confirm_note:
            coverage["nxdomain_confirmation"] = self.confirm_note
        if cnv:
            coverage["could_not_verify_sample"] = sorted(cnv)[:20]
        if self.unchecked:
            coverage["unchecked_sample"] = self.unchecked[:20]
        res.attr("typosquat_coverage", coverage)
        res.attr("typosquat_lookalikes", table)
        res.attr("typosquat_top", [{"domain": r["domain"], "severity": r.get("severity"), "signals": r.get("signals") or []} for r in table[:_TOP_N]])
        if own:
            res.attr("typosquat_own_registrations", [
                {"domain": r["domain"], "ownership": r.get("ownership"), "evidence": r.get("ownership_evidence") or []} for r in own
            ])
            res.finding(
                "Own or defensive registrations among lookalike candidates",
                "info",
                f"{len(own)} lookalike candidate(s) of {seed_label} belong to the organisation or carry a brand-protection "
                "registrar: listed here, never reported as typosquats.",
                confidence="probable",
                data={"domains": [r["domain"] for r in own][:100]},
                tags=["own_asset", "info"],
                source=SOURCE_DOH,
            )
        info_rows = [r for r in hits if r.get("section") == "info_table"]
        if info_rows:
            res.finding(
                "Registered lookalike domains without activity signals",
                "info",
                f"{len(info_rows)} registered lookalike(s) of {seed_label} show no activity signal (no MX, no non-parking "
                "A record, not registered in the last 30 days): kept as one table for monitoring.",
                confidence="probable",
                data={"domains": [r["domain"] for r in info_rows][:200], "count": len(info_rows)},
                tags=["typosquat", "info"],
                source=SOURCE_DOH,
            )
        for row in hits:
            if row.get("section") != "findings":
                continue
            self._finding(row, seed_label)
        for row in hits[: max(0, self.max_pivots)]:
            res.pivot(
                T.DOMAIN, row["domain"], "lookalike", confidence="probable", expand=False,
                note=f"registered lookalike ({row.get('fuzzer')}) of {seed_label}; candidates are hostile: passive checks only",
            )
        res.raw = {
            "mode": "forward", "seed": self.seed, "doh_queries": self.queries,
            "candidates": [
                {k: v for k, v in r.items() if k in ("domain", "fuzzer", "score", "state", "doh", "reason", "nxdomain_confirmed", "rdap")}
                for r in self.rows.values()
            ][:600],
            "registered": table[:300],
        }

    def _finding(self, row: dict[str, Any], seed_label: str) -> None:
        sev = str(row.get("severity") or "info")
        signals = row.get("signals") or []
        words = {"mx": "MX present", "nrd<=30d": f"registered {row.get('age_days')} day(s) ago", "a_non_parking": "non-parking A record",
                 "ct_cert<=30d": "fresh CT certificate", "phishing_list": "on a phishing list", "page_similarity": "page similar to the brand"}
        sig_text = ", ".join(words.get(s, s) for s in signals) or "none"
        criterion = f"P012 ladder: registered lookalike with {len(signals)} activity signal(s) ({sig_text})"
        if sev == "high":
            criterion += "; >= 2 signals and not brand-owned (" + "; ".join(row.get("ownership_evidence") or []) + ")"
        elif row.get("ownership") != "not_brand_owned" and len(signals) >= 2:
            criterion += "; ownership not established, so not HIGH"
        if row.get("capped"):
            criterion += f"; capped at LOW ({row['capped']})"
        tags = ["typosquat"]
        if row.get("parked"):
            tags.append("parked")
        if row.get("sinkhole"):
            tags.append("sinkhole")
        if sev == "high":
            tags.append("suspicious")
        self.res.finding(
            "Registered lookalike domain",
            sev,
            f"{row['domain_unicode']} ({row.get('fuzzer')}) imitates {seed_label} and is registered; activity: {sig_text}; "
            f"ownership: {row.get('ownership')}. Lookalike / phishing-capable indicator: no contact was made with it.",
            confidence="probable" if sev in ("medium", "high") else "possible",
            criterion=criterion,
            data={k: row.get(k) for k in ("domain", "fuzzer", "signals", "ownership", "ownership_evidence", "ns", "mx", "a",
                                            "created", "age_days", "registrar", "cnpj_roots", "parked", "sinkhole", "capped")},
            tags=tags,
            source=SOURCE_DOH,
            observed_first=row.get("created"),
            attack=["T1583.001"],
            key=row["domain"],
        )


def _flag(etype: T, value: str, test: Any) -> bool:
    """``test(entity)`` for a parsed value; False for junk or a failing list."""
    ent = Entity.try_make(etype, value)
    try:
        return bool(ent is not None and test(ent))
    except Exception:
        return False


def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("domain", "domain_unicode", "fuzzer", "score", "state", "ns", "a", "mx", "parked", "sinkhole", "registrar",
            "registrar_iana_id", "registrant_kind", "registrant_org", "cnpj_roots", "created", "age_days", "rdap", "ownership",
            "ownership_evidence", "severity", "signals", "capped")
    out = {k: row.get(k) for k in keys if row.get(k) not in (None, [], "")}
    out["mx_present"] = bool(row.get("mx"))
    return out


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class Typosquat(Module):
    name = "typosquat"
    title = "Typosquat and brand impersonation"
    description = (
        "Offline lookalike check of a domain against the organisation's protected domains/brands and the BCB verified list; "
        "for org-profile domains/brands (or -M typosquat) a dnstwist-style permutation scan checked through the core DoH resolver."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.KEYWORD}
    produces = {T.DOMAIN}
    run_on = "seeds"
    tags = {"brazil"}
    reference = "https://github.com/elceef/dnstwist"
    notice = (
        "Fuzzer algorithms adapted from dnstwist (Apache-2.0, v3lum/data/notices/dnstwist.json). Candidates are hostile: "
        "registration is checked only through DoH (ECS disabled) and .br RDAP, never by contacting them. "
        "The public DoH resolver operator sees every permutation: configure doh_internal for brand monitoring at scale."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "core_doh"
    sources = (SOURCE_DOH, SOURCE_RDAP_BR, SOURCE_BCB)
    hosts = ("rdap.registro.br",)
    access_model = "free_noauth_limited"
    max_requests = 10  # RDAP lookups (DoH is not counted)
    expected_latency = 2.0  # p50: most runs are the offline reverse mode; a forward scan takes 15-40 s
    timeout = 45.0
    cache_ttl = 86400  # RDAP 24 h (DoH answers are cached by the core resolver)
    max_pivots = 100
    default_enabled = True
    settings = {
        "typosquat_doh_budget": SettingSpec(300, "typosquat: DoH queries per forward scan (P012 c5)"),
        "typosquat_doh_qps": SettingSpec(10.0, "typosquat: maximum DoH queries per second (<= 10)"),
        "typosquat_candidates": SettingSpec(150, "typosquat: top-ranked candidates checked in a default scan"),
        "typosquat_candidates_deep": SettingSpec(500, "typosquat: candidates checked with --preset deep"),
        "typosquat_rdap_lookups": SettingSpec(10, "typosquat: RDAP lookups of registered .br candidates per run (<= max_requests)"),
        "typosquat_confirm_nxdomain": SettingSpec(True, "typosquat: confirm NXDOMAIN with a second resolver before 'unregistered' (P029 c10)"),
    }

    # ---- applicability -----------------------------------------------------------------------
    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.KEYWORD:
            return self._forward_reason(entity, ctx)[0]
        return True

    def _explicit(self, ctx: Any) -> bool:
        include = getattr(getattr(ctx, "options", None), "include", None) or set()
        return self.name in include

    def _forward_reason(self, entity: Entity, ctx: Any) -> tuple[bool, str]:
        """(run the forward scan?, why/why not) - P012 c4: analyst-typed org_profile domains/brands or
        an explicit -M; never pivots, subdomains or arbitrary hostile domains."""
        if not getattr(ctx, "is_seed", True):
            return False, "not an analyst-typed seed (forward scans never run on pivots)"
        org = getattr(ctx, "org", None)
        if entity.type is T.DOMAIN:
            if not is_registrable(entity.value):
                return False, "subdomain or public suffix (forward scans run on registrable domains only)"
            owned = False
            try:
                owned = bool(org is not None and org.owns(entity).own)
            except Exception:
                owned = False
            if owned:
                return True, "org_profile domain"
            if self._explicit(ctx):
                return True, f"explicit -M {self.name}"
            return False, f"not an org_profile domain (select -M {self.name} to scan its lookalikes)"
        folded = perm.fold(re.sub(r"\s+", "", entity.value))
        try:
            terms = set(org.brand_terms()) if org is not None else set()
        except Exception:
            terms = set()
        if folded in {perm.fold(re.sub(r"\s+", "", t)) for t in terms}:
            return True, "org_profile brand"
        if self._explicit(ctx):
            return True, f"explicit -M {self.name}"
        return False, f"not an org_profile brand (select -M {self.name} to scan its lookalikes)"

    # ---- run -----------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        lures = load_lures(ctx)
        org = getattr(ctx, "org", None)
        org_domains, org_brands = _org_entries(org)
        bcb_rows, bcb_note = _bcb_dataset(ctx)
        index = perm.build_protected_index(org_domains + bcb_rows, org_brands)
        protected_lists = {"org_profile": len(org_domains) + len(org_brands), "bcb": len(bcb_rows)}
        reverse: dict[str, Any] = {"protected_entries": len(index)}
        if bcb_note:
            reverse["bcb"] = bcb_note
        if entity.type is T.DOMAIN:
            self._reverse(entity, res, index, lures, reverse)
        run_forward, why = self._forward_reason(entity, ctx)
        if not run_forward:
            if res.findings:
                res.attr("typosquat_coverage", {"mode": "reverse", "forward": f"not run: {why}", **reverse, "protected_lists": protected_lists})
                return res
            if not index:
                return res.mark("skipped", "no protected domains or brands to compare with (org profile empty, BCB list not installed)",
                                reason_code="not_applicable")
            return res  # no lookalike of a protected entry: empty
        return self._forward(entity, ctx, res, lures, org, org_domains, bcb_rows, why, reverse, protected_lists)

    def _reverse(self, entity: Entity, res: ModuleResult, index: list[dict[str, Any]], lures: list[str], cov: dict[str, Any]) -> None:
        if not index:
            return
        match = perm.reverse_match(entity.value, index, lures=lures)
        if match["own_asset"] is not None:
            cov["input"] = f"protected domain ({match['own_asset'].get('source')}): never reported as its own lookalike"
            return
        matches = match["matches"]
        if not matches:
            return
        public = [{k: m.get(k) for k in ("protected", "source", "technique", "score", "lure")} for m in matches[:10]]
        res.attr("lookalike_matches", public)
        top = matches[0]
        strong = top["technique"] in _STRONG_TECHNIQUES or top["score"] >= 80
        lines = "; ".join(
            f"{m['protected']} ({m['source']}, {m['technique']}" + (f", lure '{m['lure']}'" if m.get("lure") else "") + ")" for m in matches[:5]
        )
        res.finding(
            "Lookalike of a protected domain or brand",
            "info",
            f"{entity.display} imitates {lines}. Offline match only: registration and activity come from DNS/RDAP/CT modules, and "
            "the typosquat severity ladder applies to them (a lookalike of a BCB-verified institution is not HIGH by itself).",
            confidence="probable" if strong else "possible",
            criterion=f"offline reverse match: {top['technique']} of {top['protected']} ({top['source']})",
            data={"matches": public},
            tags=["typosquat"],
            source=SOURCE_BCB if top.get("source") == "bcb" else "",
            attack=["T1583.001"],
        )
        seen: set[str] = set()
        for m in matches:
            if len(seen) >= _MAX_REVERSE_PIVOTS:
                break
            target = str(m.get("protected") or "")
            if not target or target in seen:
                continue
            seen.add(target)
            note = f"protected {'domain' if '.' in target else 'brand'} this input imitates ({m.get('source')}, {m.get('technique')})"
            if "." in target:
                res.pivot(T.DOMAIN, target, "lookalike_of", confidence="probable" if strong else "possible", expand=False, note=note)
            else:
                res.pivot(T.KEYWORD, target, "lookalike_of", confidence="probable" if strong else "possible", expand=False, note=note)

    def _forward(self, entity: Entity, ctx: Any, res: ModuleResult, lures: list[str], org: Any, org_domains: list[dict[str, Any]],
                 bcb_rows: list[dict[str, Any]], why: str, reverse: dict[str, Any], protected_lists: dict[str, int]) -> ModuleResult:
        deep = str(getattr(getattr(ctx, "options", None), "preset", "") or "") == "deep"
        limit = _int_setting(ctx, "typosquat_candidates_deep" if deep else "typosquat_candidates", 500 if deep else 150, 1, 2000)
        rdap_cap = min(_int_setting(ctx, "typosquat_rdap_lookups", 10, 0, 100), int(self.max_requests))
        candidates = perm.generate(entity.value, lures=lures, dictionary=lures[:DICTIONARY_WORDS])
        own_names = [d["domain"] for d in org_domains if d.get("source") == "org_profile"]
        owner = owner_facts(entity, org, own_names, bcb_rows)
        own_rows, scan = [], []
        for c in candidates:
            if c.get("fuzzer") == "*original":
                continue
            if _host_under(c["domain"], owner["domains"]):
                own_rows.append(c)  # an own domain needs no query: own-asset section
            else:
                scan.append(c)
        ranked, cap_hit = perm.rank(scan, limit)
        coverage: dict[str, Any] = {
            "mode": "forward" + (" (deep)" if deep else ""), "why": why, "seed": entity.value,
            "candidates_generated": len(candidates) - 1 if candidates else 0, "candidates_ranked": len(ranked),
            "candidate_cap": limit, "candidate_cap_hit": cap_hit, "protected_lists": protected_lists, **reverse,
        }
        scanner = ForwardScan(ctx, res, seed=entity.value, owner=owner, deep=deep, rdap_cap=rdap_cap, max_pivots=int(self.max_pivots))
        return run_forward_scan(scanner, ranked, coverage, own_rows, seed_label=entity.display, no_candidates=not candidates)


def owner_facts(entity: Entity, org: Any, own_names: list[str], bcb_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """{domains, cnpj_roots} of the protected party of a forward scan: the seed domain, the org
    profile domains and CNPJ roots when the seed belongs to the organisation, and the institution's
    CNPJ roots when the seed is a BCB-verified domain."""
    domains: list[str] = []
    roots: list[str] = []
    org_related = False
    if entity.type is T.DOMAIN:
        domains.append(entity.value)
        try:
            org_related = bool(org is not None and org.owns(entity).own)
        except Exception:
            org_related = False
        for row in bcb_rows:
            if _host_under(entity.value, [row["domain"]]) or _host_under(row["domain"], [entity.value]):
                roots += [r for r in (row.get("cnpj_root"), row.get("owner_cnpj_root")) if r]
    else:
        try:
            org_related = perm.fold(entity.value) in set(org.brand_terms()) if org is not None else False
        except Exception:
            org_related = False
    if org_related:
        domains += own_names
        roots += [r for r in (cnpj_root(x) for x in (getattr(org, "cnpj_roots", None) or [])) if r]
    return {"domains": sorted(set(domains)), "cnpj_roots": sorted(set(roots))}


def run_forward_scan(scanner: ForwardScan, ranked: list[dict[str, Any]], coverage: dict[str, Any], own_rows: list[dict[str, Any]], *,
                     seed_label: str, no_candidates: bool = False) -> ModuleResult:
    """Run the staged checks, RDAP, verdicts and reporting; map the outcome to a status (rule 5)."""
    res = scanner.res
    if not ranked:
        coverage["candidates_checked"] = 0
        res.attr("typosquat_coverage", coverage)
        if no_candidates:
            return res.mark("error", "no valid candidate could be generated for this seed (IDNA/UTS-46 validation)")
        return res
    scanner.check(ranked)
    scanner.rdap()
    scanner.judge()
    for c in own_rows:
        scanner.rows.setdefault(c["domain"], {"domain": c["domain"], "domain_unicode": c.get("domain_unicode"), "fuzzer": c.get("fuzzer"),
                                              "score": c.get("score"), "state": "registered", "doh": {}, "ns": [], "a": [], "mx": [],
                                              "section": "own_assets", "ownership": "own_asset",
                                              "ownership_evidence": ["organisation domain (org profile)"]})
    scanner.report(coverage=coverage, seed_label=seed_label)
    if scanner.rdap_status is not None:
        status, code, reason = scanner.rdap_status
        res.source_status(SOURCE_RDAP_BR, status, reason_code=code, reason=reason or "registro.br RDAP: could not verify")
    checked = [r for r in scanner.rows.values() if r.get("doh")]
    failed = [r for r in checked if r.get("state") == "could_not_verify"]
    if checked and len(failed) == len(checked):  # rule 5: nothing verified is 'could not verify', never 'no lookalikes'
        res.source_status(SOURCE_DOH, Status.ERROR, reason_code="error", reason="DoH could not verify any candidate (SERVFAIL/REFUSED/timeouts)")
        return res.mark("error", f"could not verify: DoH failed for all {len(checked)} candidate(s) checked")
    if scanner.stop_reason:
        res.stop(scanner.stop_reason)
    return res
