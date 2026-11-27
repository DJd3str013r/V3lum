"""registro.br domain availability and release-process status (P021): registro.br avail API, BrasilAPI fallback.

Final conditions (council #1, P021) and where they live:

1. :meth:`RegistrobrDomainStatus.applies`: individual registrable .br names in a case only - own .br
   domains (``ctx.org.owns``), .br lookalikes found by P012 (provenance relation ``lookalike`` from the
   ``typosquat`` / ``typosquat_dnstwister`` modules) and the analyst's own typed seed (one explicit
   name, never a generated one). At most 20 names per run (:data:`RUN_CAP`, counted per case/scan); a
   name reached through any other path - typosquat permutations included - is not applicable, so this
   module is never a bulk registration checker (DoH/RDAP do that; registro.br anti-abuse terms).
2. Primary ``registro.br/v2/ajax/avail/raw/{name}`` (source ``registrobr.avail``, trusted); fallback
   BrasilAPI ``/api/registrobr/v1/{name}`` (``brasilapi.registrobr``, community: it discloses the name to
   a third party) only when registro.br could not answer, each with its own status
   (``res.source_statuses``). The BrasilAPI body is validated for error-in-200 (its
   ``{message, type, name}`` error schema, a status label that disagrees with ``status_code``).
3. Only availability and release-process status (``registrobr_status``, ``registrobr_availability``)
   plus the expiry as a separate fallback attribute (``registrobr_expires_at``; rdap's ``expires`` stays
   authoritative). Registration dates, NS hosts as entities and the CNPJ stay with rdap (P003): this
   module never pivots and is never a CNPJ source.
4. min_interval 5 s (module; politeness = max(module, provider profile)), cache 24 h. 403 (keyless:
   BLOCKED challenge), 429 (RATE_LIMITED), timeouts (ERROR timeout) are 'could not verify'.
   'available' or 'in release' is claimed only from a normal API answer: a documented status code, an
   answer whose ``fqdn``/``fqdnace`` equals the query (the service rewrites 'example.com' to
   'example.com.br' and answers 'www.x.com.br' for its parent) and a code other than 8 (erro) / 10
   (desconhecido).
5. Tests with the recorded registro.br avail and BrasilAPI answers plus 403 cases
   (tests/modules/test_registrobr_domain_status.py).
"""

from __future__ import annotations

import json
import re
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import HealthCheck, HealthResult, Module, register

__all__ = [
    "LOOKALIKE_MODULES",
    "REGISTROBR_STATUS",
    "RUN_CAP",
    "Answer",
    "RegistrobrDomainStatus",
    "name_origin",
    "parse_answer",
]

SRC_AVAIL = "registrobr.avail"
SRC_BRASILAPI = "brasilapi.registrobr"
AVAIL_URL = "https://registro.br/v2/ajax/avail/raw/{name}"
BRASILAPI_URL = "https://brasilapi.com.br/api/registrobr/v1/{name}"
LABELS = {SRC_AVAIL: "registro.br", SRC_BRASILAPI: "BrasilAPI"}

RUN_CAP = 20  # P021 cond 1
CACHE_TTL = 86400  # P021 cond 4
#: P012 modules whose 'lookalike' pivots are registered lookalikes found by the typosquat pipeline
LOOKALIKE_MODULES = frozenset({"typosquat", "typosquat_dnstwister"})

#: code -> (BrasilAPI label, normalised status, release phase). Documented in the BrasilAPI OpenAPI schema
#: REGISTROBR (read 2026-11-26); codes 2 and 3 observed live on both endpoints.
REGISTROBR_STATUS: dict[int, tuple[str, str, str | None]] = {
    0: ("AVAILABLE", "available", None),
    1: ("AVAILABLE_WITH_TICKET", "available", None),
    2: ("REGISTERED", "registered", None),
    3: ("UNAVAILABLE", "unavailable", None),
    4: ("INVALID_QUERY", "invalid", None),
    5: ("RELEASE_WAITING", "in_release", "waiting"),
    6: ("RELEASE_IN_PROGRESS", "in_release", "open"),
    7: ("RELEASE_IN_PROGRESS_WITH_TICKETS", "in_release", "open"),
    8: ("ERROR", "error", None),
    9: ("DOMAIN_PROCESS_RELEASE", "in_release", "competitive"),
    10: ("UNKNOW", "unknown", None),
}
_LABEL_ALIASES = {"UNKNOW": ("UNKNOW", "UNKNOWN")}
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?$")


def _short(value: Any, limit: int = 160) -> str:
    text = _CTRL.sub(" ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _norm(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    ent = Entity.try_make(T.DOMAIN, value.strip().lower().rstrip("."))
    return str(ent.value) if ent is not None else None


def to_utc_iso(value: Any) -> str | None:
    """'2027-05-18T00:00:00-03:00' -> '2027-05-18T03:00:00Z'; None when absent or invalid."""
    if not isinstance(value, str):
        return None
    m = _ISO.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0))
    except ValueError:
        return None
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt -= timedelta(minutes=sign * (int(digits[:2]) * 60 + int(digits[2:4])))
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_registrable_br(name: str) -> bool:
    """A registrable .br name (eTLD+1 under .br): subdomains are answered for their parent, never sent."""
    name = str(name or "").strip().lower().rstrip(".")
    if not name.endswith(".br") or "." not in name:
        return False
    try:
        return psl.registrable_domain(name) == name
    except Exception:  # noqa: BLE001 - an odd value is simply not applicable
        return False


def name_origin(entity: Entity, ctx: Any) -> str | None:
    """P021 cond 1: 'own_asset' | 'p012_lookalike' | 'seed' | None (not applicable)."""
    try:
        if ctx.org.owns(entity).own:
            return "own_asset"
    except Exception:  # noqa: BLE001 - no profile: not owned
        pass
    prov = tuple(getattr(ctx, "provenance", ()) or ())
    if prov:
        last = prov[-1]
        if len(last) >= 3 and last[1] == "lookalike" and last[2] in LOOKALIKE_MODULES:
            return "p012_lookalike"
        return None
    if bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0:
        return "seed"  # the analyst typed this one name
    return None


# ======================================================================================
# per-run cap (cond 1)
# ======================================================================================

_RUN_LOCK = threading.Lock()
_RUN_NAMES: OrderedDict[str, set[str]] = OrderedDict()
_RUN_KEYS_KEPT = 64


def _run_key(ctx: Any) -> str:
    case = str(getattr(ctx, "case_id", "") or "")
    if case:
        return "case:" + case
    return f"opts:{id(getattr(ctx, 'options', None))}"


def claim_slot(ctx: Any, name: str, cap: int = RUN_CAP) -> bool:
    """Count ``name`` against the per-run cap; False when ``cap`` other names already ran in this run."""
    key = _run_key(ctx)
    with _RUN_LOCK:
        names = _RUN_NAMES.get(key)
        if names is None:
            names = _RUN_NAMES[key] = set()
            while len(_RUN_NAMES) > _RUN_KEYS_KEPT:
                _RUN_NAMES.popitem(last=False)
        else:
            _RUN_NAMES.move_to_end(key)
        if name in names:
            return True
        if len(names) >= cap:
            return False
        names.add(name)
        return True


# ======================================================================================
# parsing (cond 2-4)
# ======================================================================================


@dataclass
class Answer:
    """One source's outcome: ``outcome`` ok | blocked | rate_limited | quota | error (could not verify)."""

    source: str
    outcome: str = "error"
    reason_code: str = "error"
    reason: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.outcome == "ok"


def _load(raw: Any) -> tuple[Any, str]:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8", "replace")
    else:
        text = str(raw or "")
    text = text.lstrip("﻿").strip()
    if not text:
        return None, "empty body"
    if text[:1] == "<":
        return None, "HTML page instead of JSON (error-in-200)"
    try:
        return json.loads(text), ""
    except (ValueError, RecursionError):
        return None, "malformed JSON"


def parse_answer(source: str, raw: Any, queried: str) -> dict[str, Any]:
    """Normalise a registro.br avail or BrasilAPI body -> ``{valid, problem, status, ...}``.

    ``valid`` (a claim is allowed, cond 4) only for well-formed JSON with a documented status code (and,
    for BrasilAPI, a matching status label), an answer for the queried name and a code other than 8/10."""
    out: dict[str, Any] = {"valid": False, "problem": "", "answered_for": None, "fqdn": None, "status_code": None,
                           "status_label": None, "status": None, "release_phase": None, "concurrent_tickets": False,
                           "exempt": None, "publication_status": None, "expires_at": None, "hosts": [], "reasons": []}
    obj, problem = _load(raw)
    if problem:
        out["problem"] = problem
        return out
    if not isinstance(obj, Mapping):
        out["problem"] = "unexpected answer shape"
        return out
    if source == SRC_BRASILAPI:
        if "status_code" not in obj and any(k in obj for k in ("message", "type", "name")):
            out["problem"] = f"BrasilAPI error body in an HTTP 200 ({_short(obj.get('message'), 100)})"
            return out
        code, label = obj.get("status_code"), obj.get("status")
    else:
        code, label = obj.get("status"), None
    if not isinstance(code, int) or isinstance(code, bool) or code not in REGISTROBR_STATUS:
        out["problem"] = f"undocumented status code {_short(code, 20)!s}"
        return out
    ref_label, status, phase = REGISTROBR_STATUS[code]
    if source == SRC_BRASILAPI and (not isinstance(label, str) or label.strip().upper() not in _LABEL_ALIASES.get(ref_label, (ref_label,))):
        out["problem"] = f"status label {_short(label, 40)!r} disagrees with status_code {code}"
        return out
    out.update({"status_code": code, "status_label": ref_label, "status": status, "release_phase": phase,
                "concurrent_tickets": code in (1, 7)})
    fqdn = _norm(obj.get("fqdnace")) or _norm(obj.get("fqdn"))
    out["fqdn"] = fqdn
    ex = obj.get("exempt")
    out["exempt"] = ex if isinstance(ex, bool) else None
    ps = obj.get("publication-status")
    out["publication_status"] = _short(ps, 40) if isinstance(ps, str) and ps.strip() else None
    out["expires_at"] = to_utc_iso(obj.get("expires-at"))
    hosts = obj.get("hosts")
    out["hosts"] = [h for h in (_norm(x) for x in hosts if isinstance(x, str)) if h][:13] if isinstance(hosts, list) else []
    reasons = obj.get("reasons")
    out["reasons"] = [_short(r, 200) for r in reasons if isinstance(r, str)][:10] if isinstance(reasons, list) else []
    candidates = {n for n in (_norm(obj.get("fqdnace")), _norm(obj.get("fqdn"))) if n}
    q = _norm(queried)
    if not candidates or q is None:
        out["problem"] = "answer without fqdn"
    elif q not in candidates:
        out["answered_for"] = "parent" if fqdn and q.endswith("." + fqdn) else "other"
        out["problem"] = f"answer for another name ({out['answered_for']}: {fqdn})"
    elif status in ("error", "unknown"):
        out["problem"] = f"registry status {status} (code {code})"
    else:
        out["valid"] = True
    return out


# ======================================================================================
# the module
# ======================================================================================


@register
class RegistrobrDomainStatus(Module):
    name = "registrobr_domain_status"
    title = "registro.br availability and release status (.br)"
    description = (
        "Availability and release-process status (registered, available, in release process) of individual .br names in a "
        "case - own .br domains and lookalikes found by typosquat - from the registro.br availability API, with BrasilAPI "
        "as fallback; never a bulk registration checker, never a CNPJ source."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces: frozenset[T] = frozenset()  # attributes only: registration data and the CNPJ pivot belong to rdap (P003)
    tags = {"brazil", "free"}
    reference = "https://registro.br/"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # registro.br (registry) and, on fallback, BrasilAPI receive the name
    provider = "registrobr"
    sources = (SRC_AVAIL, SRC_BRASILAPI)
    hosts = ("registro.br", "brasilapi.com.br")
    access_model = "free_noauth_limited"
    max_requests = 2  # primary + fallback
    expected_latency = 1.5
    timeout = 120.0  # the 5 s per-host spacing can queue names of one scan behind each other
    min_interval = 5.0  # P021 cond 4: registro.br anti-abuse spacing (also applied to the fallback)
    cache_ttl = CACHE_TTL
    daily_quota = 100  # registro.br publishes no limit and shares per-IP limits with rdap.registro.br
    max_pivots = 0
    manual_link = "https://registro.br/tecnologia/ferramentas/whois/?search={domain}"
    default_enabled = False  # opt-in (P021 chair decision)
    notice = (
        "Individual .br names only (own domains, typosquat lookalikes, an analyst-typed seed), at most 20 per run and one "
        "request every 5 s: registro.br anti-abuse terms forbid bulk availability checks (typosquat permutations go "
        "through DoH/RDAP). BrasilAPI, a community relay, receives the name only when registro.br could not answer."
    )

    @classmethod
    def health_check(cls) -> HealthCheck:
        """A passive self-test on registro.br's own name (the central benign value example.com is not a .br name,
        so a probe on it would only ever be 'not applicable')."""
        return HealthCheck(offline=False, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """P021 cond 1: individual registrable .br names that are own assets, P012 lookalikes or the typed seed."""
        return is_registrable_br(str(entity.value)) and name_origin(entity, ctx) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = str(entity.value).strip().lower().rstrip(".")
        origin = name_origin(entity, ctx) or "seed"
        if not claim_slot(ctx, name):
            return res.mark("skipped", f"per-run cap of {RUN_CAP} .br names reached (registro.br anti-abuse terms): not queried",
                            reason_code="policy")
        allowed = ctx.allowed_sources
        answers: list[Answer] = []
        if SRC_AVAIL in allowed:
            answers.append(self._query(ctx, SRC_AVAIL, AVAIL_URL, name))
        primary = answers[0] if answers else None
        # fallback only when registro.br could not answer - never after an answer for another name (BrasilAPI relays
        # the same upstream answer and would repeat it)
        needs_fallback = primary is None or (not primary.valid and primary.parsed.get("answered_for") is None)
        if needs_fallback and SRC_BRASILAPI in allowed:
            answers.append(self._query(ctx, SRC_BRASILAPI, BRASILAPI_URL, name))
        for ans in answers:
            self._record(res, ans)
        res.raw = {"queried": name, "origin": origin,
                   "sources": [{"source": a.source, "outcome": a.outcome, "reason": a.reason,
                                "answer": {k: v for k, v in a.parsed.items() if k != "valid"} if a.parsed else None} for a in answers]}
        final = next((a for a in answers if a.valid), None)
        if final is None:
            return self._could_not_verify(res, answers)
        self._facts(res, final, name, origin)
        return res

    # ---- requests --------------------------------------------------------------------------------
    @staticmethod
    def _query(ctx: Any, source: str, template: str, name: str) -> Answer:
        label = LABELS[source]
        ans = Answer(source)
        url = template.format(name=quote(name, safe=".-"))
        try:
            resp = ctx.http.get(url, headers={"Accept": "application/json"}, source=source, ttl=CACHE_TTL, allow_redirects=False)
            ctx.http.check(resp)  # keyless 403 / challenge -> Blocked, 429 -> RateLimited, 4xx/5xx/3xx -> HttpError
        except RateLimited as exc:
            ans.outcome, ans.reason_code, ans.reason = "rate_limited", "rate_limited", f"{label}: rate limited ({_short(exc)}): could not verify"
            return ans
        except QuotaExceeded as exc:
            ans.outcome, ans.reason_code, ans.reason = "quota", "quota", f"{label}: budget exhausted ({_short(exc)}): could not verify"
            return ans
        except (Blocked, AuthRequired) as exc:
            code = str(getattr(exc, "reason_code", "") or "challenge")
            code = code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
            ans.outcome, ans.reason_code, ans.reason = "blocked", code, f"{label}: refused ({_short(exc)}): could not verify"
            return ans
        except DeadlineExceeded as exc:
            ans.outcome, ans.reason_code, ans.reason = "error", "timeout", f"{label}: no answer in time ({_short(exc)}): could not verify"
            return ans
        except (PolicyError, ConfigError):
            raise
        except NetworkError as exc:
            timed_out = "timeout" in str(getattr(exc, "kind", "") or "").lower() or "timed out" in str(exc).lower()
            ans.outcome, ans.reason_code = "error", "timeout" if timed_out else "error"
            ans.reason = f"{label}: {_short(exc)}: could not verify"
            return ans
        except HttpError as exc:
            code = str(getattr(exc, "reason_code", "") or "error")
            ans.outcome, ans.reason_code = "error", code if code in ("timeout", "error") else "error"
            ans.reason = f"{label}: {_short(exc)}: could not verify"
            return ans
        parsed = parse_answer(source, resp.content, name)
        ans.parsed = parsed
        if parsed["valid"]:
            ans.outcome, ans.reason_code, ans.reason = "ok", "", ""
        else:
            ctx.http.evict(resp)  # never serve an unusable answer from the cache
            ans.outcome, ans.reason_code, ans.reason = "error", "error", f"{label}: {parsed['problem']}: could not verify"
        return ans

    @staticmethod
    def _record(res: ModuleResult, ans: Answer) -> None:
        if ans.valid:
            res.source_status(ans.source, Status.OK)
            return
        status = {"blocked": Status.BLOCKED, "rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA}.get(ans.outcome, Status.ERROR)
        code = ans.reason_code if valid_reason(status, ans.reason_code) else ""
        res.source_status(ans.source, status, reason_code=code, reason=ans.reason)

    @staticmethod
    def _could_not_verify(res: ModuleResult, answers: list[Answer]) -> ModuleResult:
        """Rule 5 / cond 4: no normal answer - never 'available' or 'in release', never EMPTY."""
        if not answers:
            return res.mark("skipped", "no registro.br source is allowed for this run (licence profile or policy)", reason_code="licence")
        reasons = "; ".join(a.reason for a in answers if a.reason) or "no source answered"
        for wanted, status in (("rate_limited", Status.RATE_LIMITED), ("quota", Status.QUOTA), ("blocked", Status.BLOCKED)):
            hit = next((a for a in answers if a.outcome == wanted), None)
            if hit is not None:
                code = hit.reason_code if valid_reason(status, hit.reason_code) else ""
                return res.mark(status, f"could not verify: {reasons}", reason_code=code)
        code = "timeout" if any(a.reason_code == "timeout" for a in answers) else "error"
        return res.mark("error", f"could not verify: {reasons}", reason_code=code)

    # ---- output (cond 3) ----------------------------------------------------------------------------
    @staticmethod
    def _facts(res: ModuleResult, final: Answer, name: str, origin: str) -> None:
        p = final.parsed
        status = str(p["status"])
        res.attr("registrobr_status", status)
        res.attr("registrobr_availability", {
            "status": status, "status_code": p["status_code"], "status_label": p["status_label"], "release_phase": p["release_phase"],
            "concurrent_tickets": p["concurrent_tickets"], "exempt": p["exempt"], "publication_status": p["publication_status"],
            "checked_name": p["fqdn"], "source": final.source,
        })
        if p.get("expires_at"):
            res.attr("registrobr_expires_at", p["expires_at"])  # fallback only: rdap 'expires' is authoritative
        if status not in ("available", "in_release"):
            return
        label = LABELS[final.source]
        criterion = f"{label} availability API status code {p['status_code']} ({p['status_label']}) in a normal answer for this exact name"
        data = {"name": name, "status": status, "status_code": p["status_code"], "release_phase": p["release_phase"],
                "concurrent_tickets": p["concurrent_tickets"], "source": final.source}
        if origin == "own_asset":
            if status == "available":
                title, desc = ("Own .br domain is available for registration",
                               f"{name} is listed in the organisation profile but registro.br reports it as available: the "
                               "registration lapsed or was never made, and anyone may register it.")
            else:
                title, desc = ("Own .br domain is in the registro.br release process",
                               f"{name} is listed in the organisation profile but registro.br reports it in the release process "
                               f"(phase {p['release_phase']}): it can be lost to another registrant.")
            res.finding(title, "high", desc, confidence="confirmed", criterion=criterion, data=data,
                        tags=["own_asset"] + (["in_release"] if status == "in_release" else []), source=final.source,
                        references=["https://registro.br/dominio/regras/"])
            return
        if origin == "p012_lookalike":
            title = "Lookalike .br name is not registered" if status == "available" else "Lookalike .br name is in the release process"
            res.finding(title, "info",
                        f"{name} (a lookalike found by typosquat) is {status.replace('_', ' ')} at registro.br: a defensive "
                        "registration is possible; no one holds it today.",
                        confidence="confirmed", criterion=criterion, data=data, tags=["typosquat", "info"], source=final.source)
            return
        title = ".br name is available for registration" if status == "available" else ".br name is in the release process"
        res.finding(title, "info", f"registro.br reports {name} as {status.replace('_', ' ')}.", confidence="confirmed",
                    criterion=criterion, data=data, tags=["info"], source=final.source)


def _selftest(ctx: Any) -> HealthResult:
    """doctor: one availability query for registro.br itself (benign; the registry's own exempt name)."""
    ans = RegistrobrDomainStatus._query(ctx, SRC_AVAIL, AVAIL_URL, "registro.br")
    if ans.valid and ans.parsed.get("status") == "registered":
        return HealthResult("ok", "registro.br availability API answered for registro.br")
    if ans.outcome in ("blocked", "rate_limited"):
        return HealthResult("blocked", ans.reason)
    if ans.outcome == "quota":
        return HealthResult("quota", ans.reason)
    return HealthResult("dead", ans.reason or "unexpected answer")
