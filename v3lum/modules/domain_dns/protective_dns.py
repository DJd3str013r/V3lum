"""Protective-DNS block check (P020): Cloudflare 1.1.1.2 / 1.1.1.3 (JSON DoH) and Quad9 (RFC 8484
wire format) in this default module; the shared engine of ``protective_dns_extra`` (AdGuard, OpenDNS,
CleanBrowsing).

Final conditions (council #1, P020) and where they live:

1. Cloudflare security.cloudflare-dns.com (1.1.1.2) and family.cloudflare-dns.com (1.1.1.3) through
   JSON DoH and Quad9 dns.quad9.net through RFC 8484; registry terms open, tier trusted
   (``cloudflare_dns__p2-G01-3.json``, ``quad9__p2-G01-3.json``).
2. The opt-in ``protective_dns_extra`` module holds AdGuard, OpenDNS and CleanBrowsing.
3. Wire format only through dnspython (optional extra ``full``): it builds the query (id 0, RD, no
   EDNS - so no ECS) and decodes the answer; without it the wire resolvers report UNAVAILABLE
   'package'. No hand-rolled DNS wire parser. One A query per resolver per name; answers are cached
   only for the record TTL (``ttl_from``), errors never. Quad9 answers HTTP 505 (HTTP Version Not
   Supported) to the HTTP/1.1 core client - its DoH needs HTTP/2 (verified live 2026-11-26): that is
   UNAVAILABLE 'package' (could not verify), remembered in ``ctx.state`` so Quad9 is asked again only
   after ``HTTP2_RECHECK_DAYS`` days instead of on every run.
4. Each resolver declares a category (security / family / ads); only security blocks are
   maliciousness signals.
5. Blocked = the filtered answer matches the bundled per-resolver block signature
   (``v3lum/data/protective_dns/block_signatures.json``: sink/block-page addresses, the NXDOMAIN rule,
   RFC 8914 Extended DNS Errors 15-17) AND the unfiltered core DoH reference (``ctx.dns``, ECS-free
   Cloudflare first for possibly hostile names) resolves the name.
6. A block only by family/ads resolvers gives an info 'Content filter (adult/ads)' finding tagged
   ``content_filter`` and ``context_only`` (zero risk), never a maliciousness signal.
7. One security resolver blocking = LOW 'Blocked by <resolver>'; two or more = MEDIUM naming them.
   Every protective-DNS source belongs to ONE upstream family ('protective_dns') for consensus, so
   HIGH comes only with another independent family (P171).
8. No answer, SERVFAIL, REFUSED or a timeout = 'could not verify <resolver>'; a pass reads 'not
   blocked by N security resolvers at <time>', never 'clean'.
9. Tests: recorded Cloudflare security/family and AdGuard family answers plus synthetic block-page,
   NXDOMAIN-with-reference and timeout cases (tests/modules/test_protective_dns*.py).

Behaviour reimplemented from the research records (web-check api/block-lists.js, MIT, was read for
the 'blocked only when the reference resolves' rule; no code copied).
"""

from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import Module, register

__all__ = [
    "DEFAULT_RESOLVERS",
    "SIGNATURES_FILE",
    "Answer",
    "ProtectiveDns",
    "ProtectiveRun",
    "ResolverSpec",
    "build_wire_query",
    "decode_wire",
    "load_signatures",
    "match_signature",
    "parse_json_answer",
    "query_name",
    "summarise",
    "verdict_for",
]

SIGNATURES_FILE = "protective_dns/block_signatures.json"
UPSTREAM_FAMILY = "protective_dns"
QUERY_TIMEOUT = 5.0  # seconds per resolver query (timeout = could not verify)
DEFAULT_BUDGET = 12.0
TTL_CAP = 3600  # DoH answers never outlive the provider profile ttl (<= 3600)
HTTP2_STATE_KEY = "http2_required"  # ctx.state: {resolver id: 'YYYY-MM-DD' of the last HTTP 505}
HTTP2_RECHECK_DAYS = 7
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_EDE_RE = re.compile(r"EDE\((\d{1,5})\)\s*:?\s*([^;,\]]*)")
_TYPE_A, _TYPE_CNAME, _TYPE_SOA, _TYPE_AAAA = 1, 5, 6, 28


@dataclass(frozen=True)
class ResolverSpec:
    """One filtering resolver endpoint (P020 cond 1, 2, 4)."""

    id: str  # key of the block-signature table
    label: str  # shown in findings and coverage ('Cloudflare 1.1.1.2')
    source: str  # registry source id
    url: str
    protocol: str  # 'json' | 'wire'
    category: str  # 'security' | 'family' | 'ads'


DEFAULT_RESOLVERS: tuple[ResolverSpec, ...] = (
    ResolverSpec("cloudflare_security", "Cloudflare 1.1.1.2", "cloudflare_dns.protective_dns_security",
                 "https://security.cloudflare-dns.com/dns-query", "json", "security"),
    ResolverSpec("cloudflare_family", "Cloudflare 1.1.1.3", "cloudflare_dns.protective_dns_family",
                 "https://family.cloudflare-dns.com/dns-query", "json", "family"),
    ResolverSpec("quad9", "Quad9", "quad9.protective_dns_security", "https://dns.quad9.net/dns-query", "wire", "security"),
)


class UnexpectedAnswer(Exception):
    """A resolver answered something that is not a DNS answer: could not verify."""


# ======================================================================================
# the bundled block-signature table (P020 cond 5)
# ======================================================================================


def load_signatures() -> dict[str, Any]:
    """The bundled table {'ede_block_codes': [...], 'resolvers': {id: {...}}}; an unreadable table
    gives no resolvers (every resolver then reads 'could not verify', never 'not blocked')."""
    try:
        data = DataStore.bundled_json(SIGNATURES_FILE)
    except (OSError, ValueError):
        return {"ede_block_codes": [], "resolvers": {}}
    if not isinstance(data, dict) or not isinstance(data.get("resolvers"), dict):
        return {"ede_block_codes": [], "resolvers": {}}
    return data


def _norm_ip(value: Any) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip)


# ======================================================================================
# answers: JSON DoH and RFC 8484 (dnspython)
# ======================================================================================


@dataclass
class Answer:
    """A filtered resolver's answer for one A query, protocol-independent."""

    rcode: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    has_soa: bool = False
    ede: list[tuple[int, str]] = field(default_factory=list)
    ttl: int = 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rcode": self.rcode}
        if self.addresses:
            out["addresses"] = list(self.addresses)[:8]
        if self.cnames:
            out["cnames"] = list(self.cnames)[:4]
        if self.has_soa:
            out["soa"] = True
        if self.ede:
            out["ede"] = [f"{code} {text}".strip() for code, text in self.ede][:4]
        return out


def _ttl_of(values: Iterable[Any]) -> int:
    ttls = [int(v) for v in values if isinstance(v, int) and not isinstance(v, bool) and v >= 0]
    return min(ttls) if ttls else 0


def parse_json_answer(raw: Any) -> Answer:
    """JSON DoH body (Cloudflare ``/dns-query``, AdGuard ``/resolve``) -> Answer. HTML, malformed JSON
    or a body without an integer Status raise UnexpectedAnswer. AdGuard sends ``Answer: null`` and
    never an Authority section; names may carry a trailing dot."""
    text = bytes(raw).decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray, memoryview)) else str(raw or "")
    text = text.strip()
    if not text:
        raise UnexpectedAnswer("empty body instead of a DoH answer")
    if text.startswith("<"):
        raise UnexpectedAnswer("HTML instead of a DoH answer")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise UnexpectedAnswer("malformed DoH JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Status"), int) or isinstance(data.get("Status"), bool):
        raise UnexpectedAnswer("DoH answer without an integer Status")
    status = data["Status"]
    ans = Answer(_RCODES.get(status, f"RCODE{status}"))
    ttls: list[Any] = []
    for rr in data.get("Answer") or []:
        if not isinstance(rr, dict):
            continue
        rtype, value = rr.get("type"), rr.get("data")
        if rtype in (_TYPE_A, _TYPE_AAAA):
            ip = _norm_ip(value)
            if ip and ip not in ans.addresses:
                ans.addresses.append(ip)
                ttls.append(rr.get("TTL"))
        elif rtype == _TYPE_CNAME and isinstance(value, str):
            ans.cnames.append(value.strip().rstrip(".").lower())
            ttls.append(rr.get("TTL"))
    negative: list[Any] = []
    for rr in data.get("Authority") or []:
        if isinstance(rr, dict) and rr.get("type") == _TYPE_SOA:
            ans.has_soa = True
            negative.append(rr.get("TTL"))
            parts = str(rr.get("data") or "").split()
            if parts and parts[-1].isdigit():
                negative.append(int(parts[-1]))
    comment = data.get("Comment")
    text_comment = " ".join(str(c) for c in comment) if isinstance(comment, list) else str(comment or "")
    for code, label in _EDE_RE.findall(text_comment):
        ans.ede.append((int(code), label.strip()[:60]))
    ans.ttl = _ttl_of(ttls) if ans.addresses or ans.cnames else _ttl_of(negative)
    return ans


def _load_dns() -> Any:
    """dnspython (optional extra 'full'), or None when it is not installed (P020 cond 3)."""
    try:
        import dns.edns
        import dns.flags
        import dns.message
        import dns.rcode
        import dns.rdatatype
    except ImportError:
        return None
    return dns


def build_wire_query(name: str, dns_mod: Any) -> str:
    """RFC 8484 GET parameter: an A query built by dnspython with id 0 (cache friendly), RD and NO
    EDNS (so never an ECS option), base64url without padding."""
    query = dns_mod.message.make_query(name, dns_mod.rdatatype.A)
    query.id = 0
    return base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")


def decode_wire(raw: Any, dns_mod: Any) -> Answer:
    """RFC 8484 answer decoded by dnspython (never by hand) -> Answer; undecodable data raises
    UnexpectedAnswer. Extended DNS Errors (RFC 8914) are read from the OPT record when present."""
    try:
        msg = dns_mod.message.from_wire(bytes(raw or b""))
    except Exception as exc:  # noqa: BLE001 - dnspython raises many types for bad wire data
        raise UnexpectedAnswer(f"not a DNS message ({type(exc).__name__})") from exc
    ans = Answer(_RCODES.get(msg.rcode(), str(dns_mod.rcode.to_text(msg.rcode()))))
    ttls: list[Any] = []
    for rrset in msg.answer:
        if rrset.rdtype in (_TYPE_A, _TYPE_AAAA):
            for rd in rrset:
                ip = _norm_ip(rd.to_text())
                if ip and ip not in ans.addresses:
                    ans.addresses.append(ip)
            ttls.append(int(rrset.ttl))
        elif rrset.rdtype == _TYPE_CNAME:
            ans.cnames.extend(rd.to_text().rstrip(".").lower() for rd in rrset)
            ttls.append(int(rrset.ttl))
    negative: list[Any] = []
    for rrset in msg.authority:
        if rrset.rdtype == _TYPE_SOA:
            ans.has_soa = True
            negative.append(int(rrset.ttl))
            for rd in rrset:
                minimum = getattr(rd, "minimum", None)
                if isinstance(minimum, int):
                    negative.append(minimum)
    for opt in getattr(msg, "options", None) or []:
        if int(getattr(opt, "otype", 0) or 0) == 15:  # EDE (RFC 8914)
            try:
                code = int(getattr(opt, "code", 0))
            except (TypeError, ValueError):
                continue
            ans.ede.append((code, str(getattr(opt, "text", "") or "")[:60]))
    ans.ttl = _ttl_of(ttls) if ans.addresses or ans.cnames else _ttl_of(negative)
    return ans


def _json_cacheable(resp: Any) -> bool:
    try:
        return getattr(resp, "status", 0) == 200 and parse_json_answer(getattr(resp, "content", b"")).rcode in ("NOERROR", "NXDOMAIN")
    except UnexpectedAnswer:
        return False


def _json_ttl(resp: Any) -> float:
    try:
        return float(min(parse_json_answer(getattr(resp, "content", b"")).ttl, TTL_CAP))
    except UnexpectedAnswer:
        return 0.0


def _wire_cacheable(resp: Any) -> bool:
    dns_mod = _load_dns()
    if dns_mod is None or getattr(resp, "status", 0) != 200:
        return False
    try:
        return decode_wire(getattr(resp, "content", b""), dns_mod).rcode in ("NOERROR", "NXDOMAIN")
    except UnexpectedAnswer:
        return False


def _wire_ttl(resp: Any) -> float:
    dns_mod = _load_dns()
    if dns_mod is None:
        return 0.0
    try:
        return float(min(decode_wire(getattr(resp, "content", b""), dns_mod).ttl, TTL_CAP))
    except UnexpectedAnswer:
        return 0.0


# ======================================================================================
# verdicts (P020 cond 5, 8) and the summary (cond 6, 7, 8)
# ======================================================================================


def match_signature(signature: Mapping[str, Any] | None, answer: Answer, ede_codes: Iterable[int] = ()) -> str | None:
    """The matched block signature of a filtered answer, or None. Every address must be a sink/block
    page address; the NXDOMAIN rule is 'any' or 'no_soa'; an EDE code of the table matches always."""
    if not signature:
        return None
    for code, text in answer.ede:
        if code in set(ede_codes):
            return f"Extended DNS Error {code}" + (f" ({text})" if text else "")
    sinks = {ip for ip in (_norm_ip(x) for x in signature.get("sinks") or []) if ip}
    if answer.addresses and all(a in sinks for a in answer.addresses):
        return "block answer " + ", ".join(sorted(set(answer.addresses)))
    rule = signature.get("nxdomain")
    if answer.rcode == "NXDOMAIN" and not answer.addresses:
        if rule == "any":
            return "NXDOMAIN"
        if rule == "no_soa" and not answer.has_soa:
            return "NXDOMAIN without an SOA"
    return None


def reference_state(reference: Any) -> str:
    """'resolves' | 'nxdomain' | 'nodata' | 'failed' of the unfiltered core DoH answer (sink-like
    addresses never count as resolving)."""
    if reference is None:
        return "failed"
    if getattr(reference, "nxdomain", False):
        return "nxdomain"
    if not getattr(reference, "ok", False):
        return "failed"
    real = []
    for record in getattr(reference, "records", []) or []:
        try:
            ip = ipaddress.ip_address(str(record))
        except ValueError:
            continue
        if not (ip.is_unspecified or ip.is_loopback):
            real.append(str(ip))
    return "resolves" if real else "nodata"


def verdict_for(spec: ResolverSpec, signature: Mapping[str, Any] | None, answer: Answer | None, problem: str, reference: Any,
                ede_codes: Iterable[int] = ()) -> dict[str, Any]:
    """One resolver's verdict: blocked | not_blocked | could_not_verify | not_applicable (the name
    does not resolve at the unfiltered reference: nothing to block)."""
    base = {"resolver": spec.id, "label": spec.label, "category": spec.category, "source": spec.source}
    if problem or answer is None:
        return {**base, "verdict": "could_not_verify", "reason": problem or "no answer"}
    base["answer"] = answer.to_dict()
    if answer.rcode not in ("NOERROR", "NXDOMAIN"):
        return {**base, "verdict": "could_not_verify", "reason": f"{answer.rcode} from {spec.label}"}
    if signature is None:
        return {**base, "verdict": "could_not_verify", "reason": f"no block signature for {spec.label} in the bundled table"}
    ref = reference_state(reference)
    matched = match_signature(signature, answer, ede_codes)
    if matched:
        if ref == "resolves":
            return {**base, "verdict": "blocked", "signature": matched, "reason": f"{matched} while the unfiltered reference resolves the name"}
        if ref in ("nxdomain", "nodata"):
            return {**base, "verdict": "not_applicable", "signature": matched,
                    "reason": f"{matched}, but the unfiltered reference does not resolve the name either"}
        return {**base, "verdict": "could_not_verify", "signature": matched,
                "reason": f"{matched}, but the unfiltered reference could not be verified"}
    if answer.addresses:
        return {**base, "verdict": "not_blocked", "reason": "resolves normally"}
    if ref in ("nxdomain", "nodata"):
        return {**base, "verdict": "not_applicable", "reason": f"{answer.rcode} and the unfiltered reference does not resolve the name"}
    if ref == "resolves":
        return {**base, "verdict": "could_not_verify",
                "reason": f"{answer.rcode} without an address outside the block signature while the reference resolves the name"}
    return {**base, "verdict": "could_not_verify", "reason": f"{answer.rcode}; the unfiltered reference could not be verified"}


def summarise(verdicts: list[Mapping[str, Any]], checked_at: str) -> dict[str, Any]:
    """P020 cond 6-8: security blocks, content-filter blocks, could-not-verify lines and the pass line."""
    blocked_sec = [v for v in verdicts if v.get("verdict") == "blocked" and v.get("category") == "security"]
    blocked_content = [v for v in verdicts if v.get("verdict") == "blocked" and v.get("category") in ("family", "ads")]
    passed_sec = [v for v in verdicts if v.get("verdict") == "not_blocked" and v.get("category") == "security"]
    cnv = [v for v in verdicts if v.get("verdict") == "could_not_verify"]
    na = [v for v in verdicts if v.get("verdict") == "not_applicable"]
    lines: list[str] = []
    if blocked_sec:
        lines.append(f"blocked by {', '.join(v['label'] for v in blocked_sec)} at {checked_at}")
    elif passed_sec:
        lines.append(f"not blocked by {len(passed_sec)} security resolver(s) at {checked_at}")
    if blocked_content and not blocked_sec:
        lines.append(f"content filter (adult/ads): {', '.join(v['label'] for v in blocked_content)}")
    if na and not blocked_sec and not passed_sec:
        lines.append("not applicable: the name does not resolve at the unfiltered reference")
    lines.extend(f"could not verify {v['label']}" for v in cnv)
    return {
        "security_blocked": [v["label"] for v in blocked_sec],
        "content_filtered": [v["label"] for v in blocked_content],
        "not_blocked_security": len(passed_sec),
        "could_not_verify": [v["label"] for v in cnv],
        "not_applicable": [v["label"] for v in na],
        "lines": lines,
    }


# ======================================================================================
# the shared run
# ======================================================================================


def query_name(entity: Entity) -> str | None:
    """Domain or URL -> the DNS name to check; None for IP-literal URLs and junk (not applicable)."""
    if entity.type is T.DOMAIN:
        name = str(entity.value).strip().lower().rstrip(".")
    elif entity.type is T.URL:
        try:
            host = urlsplit(str(entity.value)).hostname or ""
        except ValueError:
            return None
        name = host.strip().lower().rstrip(".")
    else:
        return None
    if not name or "." not in name:
        return None
    try:
        ipaddress.ip_address(name.strip("[]"))
        return None
    except ValueError:
        pass
    ent = Entity.try_make(T.DOMAIN, name)
    return str(ent.value) if ent is not None else None


_FAILURE_STATUS = {
    "rate_limited": (Status.RATE_LIMITED, "rate_limited"),
    "quota": (Status.QUOTA, "quota"),
    "blocked": (Status.BLOCKED, "challenge"),
    "package": (Status.UNAVAILABLE, "package"),
    "http2": (Status.UNAVAILABLE, "package"),  # the core HTTP client speaks HTTP/1.1 only
    "timeout": (Status.ERROR, "timeout"),
    "error": (Status.ERROR, "error"),
}


def _http2_state(ctx: Any) -> dict[str, str]:
    try:
        value = ctx.state.get(HTTP2_STATE_KEY, {})
    except Exception:  # noqa: BLE001 - unreadable state: every resolver is asked
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v)}


def _recent(day: str | None, today: str) -> bool:
    """True while the last HTTP 505 of a resolver is younger than HTTP2_RECHECK_DAYS."""
    if not day:
        return False
    try:
        age = (datetime.strptime(today, "%Y-%m-%d") - datetime.strptime(day, "%Y-%m-%d")).days
    except ValueError:
        return False
    return 0 <= age < HTTP2_RECHECK_DAYS


def _save_http2_state(ctx: Any, before: Mapping[str, str], asked: Mapping[str, tuple[Any, str, str]], today: str) -> None:
    after = dict(before)
    for sid, (answer, _problem, kind) in asked.items():
        if kind == "http2":
            after[sid] = today
        elif answer is not None:
            after.pop(sid, None)  # it answered over HTTP/1.1: forget the old 505
    if after != dict(before):
        try:
            ctx.state.set(HTTP2_STATE_KEY, after)
        except Exception:  # noqa: BLE001 - state is best effort; never fail the run for it
            pass


def _mono(ctx: Any) -> float:
    clock = getattr(getattr(ctx, "http", None), "clock", None)
    try:
        return float(clock.monotonic()) if clock is not None else time.monotonic()
    except Exception:  # noqa: BLE001
        return time.monotonic()


def _checked_at(ctx: Any) -> str:
    try:
        now = ctx.now()
    except Exception:  # noqa: BLE001
        now = None
    now = now if isinstance(now, datetime) else datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProtectiveRun:
    """One protective-DNS check of one name against a set of resolvers."""

    def __init__(self, module: Any, res: ModuleResult, ctx: Any, name: str, resolvers: Iterable[ResolverSpec]) -> None:
        self.module, self.res, self.ctx, self.name = module, res, ctx, name
        self.resolvers = list(resolvers)
        self.table = load_signatures()
        self.ede_codes = [int(c) for c in self.table.get("ede_block_codes") or [] if isinstance(c, int)]
        self.deadline = _mono(ctx) + DEFAULT_BUDGET
        self.stop: BaseException | None = None
        self._last_verdicts: list[dict[str, Any]] = []

    def _query(self, spec: ResolverSpec) -> tuple[Answer | None, str, str]:
        """(answer, problem text, failure kind) - every failure is 'could not verify' (rule 5)."""
        try:
            left = self.deadline - _mono(self.ctx)
            if left <= 0.5:
                return None, f"{spec.label}: time budget used up", "timeout"
            timeout = min(QUERY_TIMEOUT, left)
            if spec.protocol == "wire":
                dns_mod = _load_dns()
                if dns_mod is None:
                    return None, f"{spec.label}: needs dnspython for RFC 8484 (pip install 'v3lum[full]')", "package"
                resp = self.ctx.http.get(
                    spec.url, params={"dns": build_wire_query(self.name, dns_mod)}, headers={"Accept": "application/dns-message"},
                    source=spec.source, timeout=timeout, ttl=TTL_CAP, ttl_from=_wire_ttl, cache_if=_wire_cacheable, retries=0,
                )
                self.ctx.http.check(resp)
                return decode_wire(resp.content, dns_mod), "", ""
            resp = self.ctx.http.get(
                spec.url, params={"name": self.name, "type": "A"}, headers={"Accept": "application/dns-json"},
                source=spec.source, timeout=timeout, ttl=TTL_CAP, ttl_from=_json_ttl, cache_if=_json_cacheable, retries=0,
            )
            self.ctx.http.check(resp)
            return parse_json_answer(resp.content), "", ""
        except Cancelled as exc:
            self.stop = exc
            return None, f"{spec.label}: stopped (kill switch or scan deadline)", "error"
        except RequestCapReached as exc:
            return None, f"{spec.label}: request cap reached ({exc})", "error"
        except RateLimited as exc:
            return None, f"{spec.label}: rate limited ({str(exc)[:100]})", "rate_limited"
        except QuotaExceeded as exc:
            return None, f"{spec.label}: quota exhausted ({str(exc)[:100]})", "quota"
        except (Blocked, AuthRequired) as exc:
            return None, f"{spec.label}: refused ({str(exc)[:100]})", "blocked"
        except DeadlineExceeded as exc:
            return None, f"{spec.label}: no answer in time ({str(exc)[:100]})", "timeout"
        except (PolicyError, ConfigError):
            raise
        except NetworkError as exc:
            timed_out = "timeout" in str(getattr(exc, "kind", "") or "").lower() or "timed out" in str(exc).lower()
            return None, f"{spec.label}: {str(exc)[:120]}", "timeout" if timed_out else "error"
        except HttpError as exc:
            if int(getattr(exc, "status", 0) or 0) == 505:
                return None, f"{spec.label}: needs HTTP/2 (HTTP 505 HTTP Version Not Supported; the core HTTP client speaks HTTP/1.1)", "http2"
            return None, f"{spec.label}: {str(exc)[:120]}", "error"
        except UnexpectedAnswer as exc:
            return None, f"{spec.label}: {exc}", "error"
        except Exception as exc:  # noqa: BLE001 - untrusted answer: a surprise is 'could not verify', never a crash
            return None, f"{spec.label}: unexpected answer ({type(exc).__name__})", "error"

    def _reference(self) -> Any:
        try:
            return self.ctx.dns.query(self.name, "A", hostile=True)
        except Cancelled as exc:
            self.stop = exc
            return None
        except Exception:  # noqa: BLE001 - the reference could not be verified
            return None

    def execute(self) -> ModuleResult:
        res = self.res
        allowed = self.ctx.allowed_sources
        specs = [s for s in self.resolvers if s.source in allowed]
        if not specs:
            return res.mark("skipped", "no protective-DNS resolver is allowed for this run", reason_code="config")
        http2 = _http2_state(self.ctx)
        today = _checked_at(self.ctx)[:10]
        known = {spec.id: http2[spec.id] for spec in specs if _recent(http2.get(spec.id), today)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(specs) + 1, thread_name_prefix="protective_dns") as pool:
            ref_future = pool.submit(self._reference)
            futures = {spec.id: pool.submit(self._query, spec) for spec in specs if spec.id not in known}
            reference = ref_future.result()
            outcomes = {sid: fut.result() for sid, fut in futures.items()}
        for spec in specs:
            if spec.id in known:
                outcomes[spec.id] = (None, f"{spec.label}: needs HTTP/2 (HTTP 505 on {known[spec.id]}; the core HTTP client speaks "
                                           f"HTTP/1.1; asked again {HTTP2_RECHECK_DAYS} days later)", "http2")
        _save_http2_state(self.ctx, http2, {sid: out for sid, out in outcomes.items() if sid not in known}, today)
        checked_at = _checked_at(self.ctx)
        verdicts: list[dict[str, Any]] = []
        failures: dict[str, str] = {}
        for spec in specs:
            answer, problem, kind = outcomes[spec.id]
            signature = (self.table.get("resolvers") or {}).get(spec.id)
            verdict = verdict_for(spec, signature, answer, problem, reference, self.ede_codes)
            verdicts.append(verdict)
            if verdict["verdict"] == "could_not_verify":
                failures[spec.id] = kind or "error"
            self._source_status(spec, verdict, kind)
        self._last_verdicts = verdicts
        summary = summarise(verdicts, checked_at)
        ref_view = {
            "status": getattr(reference, "status", "FAILED") if reference is not None else "FAILED",
            "records": list(getattr(reference, "records", []) or [])[:8] if reference is not None else [],
            "resolver": getattr(reference, "resolver", "") if reference is not None else "",
            "error": str(getattr(reference, "error", "") or "")[:160] if reference is not None else "unavailable",
        }
        res.attr("protective_dns", {
            "name": self.name, "checked_at": checked_at, "summary": "; ".join(summary["lines"]), "lines": summary["lines"],
            "verdicts": verdicts, "reference": ref_view, "security_blocked": summary["security_blocked"],
            "content_filtered": summary["content_filtered"], "could_not_verify": summary["could_not_verify"],
            "upstream_family": UPSTREAM_FAMILY,
        })
        self._findings(verdicts, summary, checked_at, ref_view)
        res.raw = {"name": self.name, "checked_at": checked_at, "verdicts": verdicts, "reference": ref_view, "summary": summary}
        if len(failures) == len(specs):
            self._mark_all_failed(failures, summary)
        elif failures:
            res.partial = True
            res.error = "partial: " + "; ".join(f"could not verify {v['label']} ({v['reason']})" for v in verdicts if v["verdict"] == "could_not_verify")
            if set(failures.values()) == {"rate_limited"}:
                res.stop("rate_limited")
        if self.stop is not None:
            raise self.stop
        return res

    def _source_status(self, spec: ResolverSpec, verdict: Mapping[str, Any], kind: str) -> None:
        if verdict["verdict"] != "could_not_verify":
            self.res.source_status(spec.source, Status.OK, reason=f"{verdict['verdict']}: {verdict.get('reason', '')}"[:200])
            return
        status, code = _FAILURE_STATUS.get(kind or "error", (Status.ERROR, "error"))
        if not valid_reason(status, code):
            status, code = Status.ERROR, "error"
        self.res.source_status(spec.source, status, reason_code=code, reason=f"could not verify {spec.label}: {verdict.get('reason', '')}"[:200])

    def _mark_all_failed(self, failures: Mapping[str, str], summary: Mapping[str, Any]) -> None:
        kinds = set(failures.values())
        text = "could not verify any protective-DNS resolver: " + "; ".join(
            str(v.get("reason") or v.get("label")) for v in self._last_verdicts if v.get("verdict") == "could_not_verify")
        mapped = {_FAILURE_STATUS.get(kind, (Status.ERROR, "error")) for kind in kinds}
        if len(mapped) == 1:  # one kind of failure everywhere: its own status (UNAVAILABLE, RATE_LIMITED...)
            status, code = next(iter(mapped))
            self.res.mark(status, text, reason_code=code)
            return
        self.res.mark("error", text, reason_code="error")

    def _findings(self, verdicts: list[Mapping[str, Any]], summary: Mapping[str, Any], checked_at: str, ref_view: Mapping[str, Any]) -> None:
        blocked = [v for v in verdicts if v["verdict"] == "blocked" and v["category"] == "security"]
        content = [v for v in verdicts if v["verdict"] == "blocked" and v["category"] in ("family", "ads")]
        if blocked:
            labels = [v["label"] for v in blocked]
            many = len(blocked) >= 2
            self.res.finding(
                "Blocked by " + ", ".join(labels),
                "medium" if many else "low",
                f"{self.name} is blocked by {len(blocked)} security-category protective DNS resolver(s) ({', '.join(labels)}) at "
                f"{checked_at} while the unfiltered reference resolves it: the vendors classify it as malware/phishing. All "
                "protective-DNS votes are one upstream family (their feeds overlap), so this never reaches HIGH on its own.",
                confidence="probable" if many else "possible",
                criterion="filtered answer matches the bundled block signature of the resolver (sink/block-page address, NXDOMAIN "
                          "rule or Extended DNS Error) AND the unfiltered core DoH reference resolves the name (P020 cond 5)",
                data={"resolvers": labels, "signatures": {v["label"]: v.get("signature") for v in blocked},
                      "reference": dict(ref_view), "checked_at": checked_at, "upstream_family": UPSTREAM_FAMILY, "consensus_votes": 1},
                tags=["suspicious", "protective_dns_block"],
                source=blocked[0]["source"],
                observed_last=checked_at,
            )
        elif content:
            labels = [v["label"] for v in content]
            self.res.finding(
                "Content filter (adult/ads)",
                "info",
                f"{self.name} is blocked only by family/ads filtering resolver(s) ({', '.join(labels)}) at {checked_at}; no "
                "security resolver blocks it. A content category, never a maliciousness signal (zero risk).",
                confidence="probable",
                data={"resolvers": labels, "checked_at": checked_at, "categories": sorted({v["category"] for v in content})},
                tags=["content_filter", "context_only"],
                source=content[0]["source"],
                observed_last=checked_at,
            )


# ======================================================================================
# the default module
# ======================================================================================


@register
class ProtectiveDns(Module):
    name = "protective_dns"
    title = "Protective-DNS block check (Cloudflare 1.1.1.2/1.1.1.3, Quad9)"
    description = (
        "Asks the threat-blocking resolvers Cloudflare 1.1.1.2 (security), 1.1.1.3 (family) and Quad9 for a domain or URL host "
        "and compares their answers with the bundled block signatures and the unfiltered core DoH reference."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.URL}
    produces = set()
    tags = {"reputation", "free"}
    reference = "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families"
    terms = "open"  # Cloudflare and Quad9 = open (P020 cond 1)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the resolver operators receive the name, never the target
    provider = "cloudflare_dns"
    sources = ("cloudflare_dns.protective_dns_security", "cloudflare_dns.protective_dns_family", "quad9.protective_dns_security")
    hosts = ("security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net")
    access_model = "free_noauth_unlimited"
    max_requests = 3  # one A query per resolver per name (P020 cond 3)
    expected_latency = 1.0
    timeout = 20.0
    cache_ttl = TTL_CAP  # capped per answer by its own record TTL (ttl_from)
    default_enabled = True
    notice = (
        "The resolver operators (Cloudflare, Quad9) see the queried name. A block is reported only when the bundled signature "
        "matches and the unfiltered reference resolves the name; family/ads blocks are content categories, never maliciousness; "
        "Quad9 needs dnspython (pip install 'v3lum[full]')."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_name(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = query_name(entity)
        if name is None:
            return res.mark("skipped", "no DNS name to check (IP-literal URL or invalid host)", reason_code="not_applicable")
        return ProtectiveRun(self, res, ctx, name, DEFAULT_RESOLVERS).execute()
