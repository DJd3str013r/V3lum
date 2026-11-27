"""E-mail security posture of a mail domain over DNS-over-HTTPS (P002 email_security_posture).

Behavioural reference: checkdmarc 6.0.4 (https://github.com/domainaware/checkdmarc, Apache-2.0,
Copyright Sean Whalen): the SPF limits, DMARC discovery and record checks below are re-implemented
over the core DoH resolver; no checkdmarc code is copied and dnspython is not used (notice fragment
v3lum/data/notices/checkdmarc.json). recon-ng (GPL) was an idea only.

Final conditions (council #1, P002) and where they live:

1. DNS only through ``ctx.dns`` (core DoH): SPF, DMARC (p, pct, sp, rua, ruf), DKIM over the bundled
   common-selector list (v3lum/data/email_security_posture/dkim_selectors.json, 30 names), MTA-STS TXT,
   TLS-RPT, BIMI, CAA and the DNSSEC AD flag. No SMTP/STARTTLS connection to MX hosts; the MTA-STS
   policy file belongs to wellknown_files (P065).
2. :func:`evaluate_spf`: RFC 7208 limits - 10 DNS-mechanism lookups, 2 void lookups, include/redirect
   loop detection, recursion depth 10 and a hard cap of 40 DoH queries per run -> ``spf_lookups`` and
   ``spf_void_lookups`` (P027 CR02).
3. :func:`dmarc_discovery`: ``_dmarc.<name>``, then the organisational domain (PSL) with its sp= tag;
   at most 5 external rua/ruf destinations are checked through ``<domain>._report._dmarc.<dest>``
   (``dmarc_rua_external``).
4. Rule 5: a DoH error, SERVFAIL, REFUSED or timeout on TXT, _dmarc or MX is 'could not verify'; no
   'missing SPF/DMARC' finding is ever raised on missing data (dead-DoH test).
5. CIDRs reached through include:/a:/mx: of SaaS/ESP mail providers (bundled vendor table + the core
   noise list) are ``third_party_mail``: listed in ``third_party_mail_cidrs`` only - never a pivot, so
   they never reach reputation/attack-surface rules, correlation or an ACTIVE scope.
6. Only direct ip4/ip6 mechanisms of the domain's own record become candidate CIDR/IP pivots
   (``spf_authorized``, expand=False) until RDAP/NIC.br confirms ownership.
7. Severity by ownership (org_profile own domains): missing DMARC or p=none -> MEDIUM, SPF +all -> HIGH,
   SPF permerror -> MEDIUM. Every domain gets ONE info 'posture summary' finding; absent BIMI/MTA-STS/
   TLS-RPT are never above info (P027 CR01 escalates third-party domains when warranted).
8. DKIM: no key under the common selectors is 'not determined (N common selectors checked)', never
   'DKIM missing'; selectors are probed on registrable domains and e-mail domains only, once per scan.
9. New attribute names live in v3lum/data/vocab/p1-G01-1.json (core vocab request).
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from v3lum.core import noise, psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "core_doh.resolvers"
DKIM_SELECTORS_FILE = "email_security_posture/dkim_selectors.json"
MAIL_PROVIDERS_FILE = "email_security_posture/mail_providers.json"
FALLBACK_SELECTORS = ("google", "selector1", "selector2", "k1", "s1", "s2", "default", "dkim", "mail", "smtp")
MAX_SELECTORS = 30
SPF_MAX_LOOKUPS = 10
SPF_MAX_VOID = 2
SPF_MAX_DEPTH = 10
SPF_MAX_QUERIES = 40
MAX_REPORT_DESTINATIONS = 5
CIDR_PIVOT_CAP = 25
INCLUDE_PIVOT_CAP = 15
WORKERS = 8
OK_STATUSES = ("NOERROR", "NXDOMAIN")
THIRD_PARTY_NOISE = frozenset({"saas", "cloud", "hosting", "cdn", "webmail"})
SPOOFING_ATTACK = ("T1566", "T1684.001")

_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.I)
_DMARC_RE = re.compile(r"^v\s*=\s*DMARC1\s*(;|$)", re.I)
_MECHS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists")
_MOD_RE = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.I)


# ======================================================================================
# DNS access (one cache per run; every query goes through ctx.dns, the core DoH resolver)
# ======================================================================================


@dataclass
class Answer:
    """What the evaluators need from a DnsAnswer: status, records, AD flag and the error text."""

    status: str
    records: list[str] = field(default_factory=list)
    ad: bool = False
    error: str = ""

    @property
    def verified(self) -> bool:
        return self.status in OK_STATUSES

    @property
    def void(self) -> bool:
        """RFC 7208 4.6.4 void lookup: NXDOMAIN or NOERROR without records."""
        return self.status == "NXDOMAIN" or (self.status == "NOERROR" and not self.records)


class Lookup:
    """Memoised, thread-safe ``ctx.dns.query`` wrapper. ``spf_budget`` counts only the SPF
    evaluator's queries (P002 cond 2: hard cap 40 per run)."""

    def __init__(self, dns: Any) -> None:
        self.dns = dns
        self._cache: dict[tuple[str, str], Answer] = {}
        self._lock = threading.Lock()
        self.queries = 0

    def __call__(self, name: str, rtype: str) -> Answer:
        key = (name.lower().rstrip("."), rtype.upper())
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        try:
            ans = self.dns.query(key[0], key[1])
            status = str(getattr(ans, "status", "") or "SERVFAIL").upper()
            error = str(getattr(ans, "error", "") or "")
            if error and status in OK_STATUSES:
                status = "SERVFAIL"  # an answer carrying an error is never read as NOERROR/NXDOMAIN
            records = [r for r in (getattr(ans, "records", None) or []) if isinstance(r, str)]
            answer = Answer(status, records if status == "NOERROR" else [], bool(getattr(ans, "authenticated", False)), error)
        except Exception as exc:  # noqa: BLE001 - a resolver failure is 'could not verify' (rule 5)
            answer = Answer("SERVFAIL", [], False, f"{type(exc).__name__}: could not verify")
        with self._lock:
            self._cache[key] = answer
            self.queries += 1
        return answer

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {f"{n} {t}": {"status": a.status, "records": a.records[:10], "ad": a.ad, "error": a.error[:160]} for (n, t), a in self._cache.items()}


# ======================================================================================
# SPF (RFC 7208), bounded evaluator without a sender IP
# ======================================================================================


def select_spf(txts: list[str]) -> tuple[str | None, str | None]:
    """RFC 7208 4.5: exactly one 'v=spf1' record -> ``(record, None)``; several -> ``(None, permerror)``."""
    recs = [t.strip() for t in txts if isinstance(t, str) and _SPF_RE.match(t.strip())]
    if not recs:
        return None, None
    if len(recs) > 1:
        return None, "permerror: multiple SPF records"
    return recs[0], None


def parse_spf(record: str) -> dict[str, Any]:
    """SPF record -> ``{mechanisms: [{qualifier, mechanism, value}], redirect, exp, errors}``."""
    out: dict[str, Any] = {"mechanisms": [], "redirect": None, "exp": None, "errors": []}
    if not isinstance(record, str) or not _SPF_RE.match(record.strip()):
        out["errors"].append("permerror: not an SPF record")
        return out
    for term in record.split()[1:]:
        mod = _MOD_RE.match(term)
        if mod and mod.group(1).lower() not in _MECHS:
            name, val = mod.group(1).lower(), mod.group(2)
            if name in ("redirect", "exp"):
                if out[name] is not None:
                    out["errors"].append(f"permerror: duplicate {name} modifier")
                out[name] = val
            continue
        qualifier, body = "+", term
        if body[:1] in "+-~?":
            qualifier, body = body[0], body[1:]
        m = re.match(r"^([a-z0-9]+)(.*)$", body, re.I)
        if not m or m.group(1).lower() not in _MECHS:
            out["errors"].append(f"permerror: unknown mechanism {term[:40]!r}")
            continue
        mech, rest = m.group(1).lower(), m.group(2)
        item: dict[str, Any] = {"qualifier": qualifier, "mechanism": mech, "value": None}
        if mech == "all":
            if rest:
                out["errors"].append(f"permerror: bad all term {term[:40]!r}")
                continue
        elif mech in ("include", "exists"):
            if not rest.startswith(":") or len(rest) < 2:
                out["errors"].append(f"permerror: {mech} needs a domain")
                continue
            item["value"] = rest[1:].lower().rstrip(".")
        elif mech in ("ip4", "ip6"):
            if not rest.startswith(":"):
                out["errors"].append(f"permerror: {mech} needs an address")
                continue
            try:
                net = ipaddress.ip_network(rest[1:], strict=False)
            except ValueError:
                out["errors"].append(f"permerror: bad {mech} {rest[1:][:50]!r}")
                continue
            if (mech == "ip4") != (net.version == 4):
                out["errors"].append(f"permerror: {mech} with the wrong address family")
                continue
            item["value"] = str(net)
        else:  # a, mx, ptr with an optional ':domain' and '/cidr'
            spec = rest
            if spec.startswith(":"):
                dom, _, cidr = spec[1:].partition("/")
                item["value"] = dom.lower().rstrip(".") or None
                spec = ("/" + cidr) if cidr else ""
            if spec and not re.match(r"^(?:/\d{1,2})?(?://\d{1,3})?$", spec):
                out["errors"].append(f"permerror: bad cidr in {term[:40]!r}")
                continue
        out["mechanisms"].append(item)
    return out


def load_vendor_table(ctx: Any) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """(spf vendor suffixes, mx vendor suffixes) from the bundled table (empty on a broken file)."""
    try:
        data = ctx.data.bundled_json(MAIL_PROVIDERS_FILE)
    except (OSError, ValueError):
        return (), ()

    def pairs(key: str) -> tuple[tuple[str, str], ...]:
        items = data.get(key) if isinstance(data, dict) else None
        return tuple((str(p[0]).lower(), str(p[1])) for p in items or () if isinstance(p, list) and len(p) == 2)

    return pairs("spf"), pairs("mx")


def vendor_for(domain: str, table: tuple[tuple[str, str], ...]) -> str | None:
    """Mail SaaS/ESP vendor of an SPF include/redirect/a/mx target: the bundled table first, then the
    core noise list (saas/cloud/hosting/cdn/webmail kinds) - P002 cond 5."""
    d = (domain or "").lower().rstrip(".")
    if not d:
        return None
    for suffix, vendor in table:
        if d == suffix or d.endswith("." + suffix):
            return vendor
    ent = Entity.try_make(T.DOMAIN, d)
    if ent is not None:
        try:
            kind = noise.noise_kind(ent)
        except Exception:  # noqa: BLE001 - the noise list never breaks a run
            kind = None
        if kind in THIRD_PARTY_NOISE:
            return f"{registrable_or(d)} ({kind})"
    return None


def registrable_or(name: str) -> str:
    try:
        return psl.registrable_domain(name) or name
    except Exception:  # noqa: BLE001
        return name


def evaluate_spf(domain: str, resolve: Callable[[str, str], Answer], vendors: tuple[tuple[str, str], ...] = (), *,
                 max_queries: int = SPF_MAX_QUERIES, resolve_targets: bool = True) -> dict[str, Any]:
    """Bounded RFC 7208 SPF evaluation of ``domain`` (P002 cond 2, 5, 6); no sender IP.

    Counts DNS-mechanism terms (include, a, mx, ptr, exists, redirect; > 10 -> permerror) and void
    lookups (NXDOMAIN/no records; > 2 -> permerror), detects include/redirect loops, bounds recursion
    depth (10) and the DoH queries of the evaluation (40; reaching it -> partial). a:/mx: targets are
    resolved inside the cap for void counting only (their addresses are never pivots: cond 6).
    """
    domain = (domain or "").strip().lower().rstrip(".")
    st: dict[str, Any] = {"lookups": 0, "void": 0, "queries": 0, "errors": [], "warnings": [], "temperror": False, "partial": False,
                          "tree": [], "includes": [], "cidrs": [], "top_all": None, "asked": {}}

    def query(name: str, rtype: str) -> Answer | None:
        key = (name, rtype)
        if key in st["asked"]:
            return st["asked"][key]
        if st["queries"] >= max_queries:
            st["partial"] = True
            note = f"DoH query cap reached ({max_queries} queries)"
            if note not in st["warnings"]:
                st["warnings"].append(note)
            return None
        st["queries"] += 1
        ans = resolve(name, rtype)
        st["asked"][key] = ans
        return ans

    def walk(name: str, depth: int, path: frozenset[str], via: str, vendor: str | None, top: bool) -> str:
        if depth > SPF_MAX_DEPTH:
            st["errors"].append(f"permerror: recursion depth above {SPF_MAX_DEPTH} at {name}")
            return "permerror"
        ans = query(name, "TXT")
        if ans is None:
            return "partial"
        if not ans.verified:
            st["temperror"] = True
            st["errors"].append(f"temperror: {name} TXT {ans.status}")
            return "temperror"
        record, err = select_spf(ans.records) if ans.status == "NOERROR" else (None, None)
        if err:
            st["errors"].append(f"{err} at {name}")
            return "permerror"
        if record is None:
            if depth == 0:
                return "nxdomain" if ans.status == "NXDOMAIN" else "none"
            if ans.void:
                st["void"] += 1
            st["errors"].append(f"permerror: {via} target {name} has no SPF record")
            return "permerror"
        parsed = parse_spf(record)
        st["tree"].append({"domain": name, "depth": depth, "via": via, "record": record[:512], "vendor": vendor})
        st["errors"].extend(f"{e} at {name}" for e in parsed["errors"])
        has_all = False
        for m in parsed["mechanisms"]:
            mech = m["mechanism"]
            if mech in _LOOKUP_MECHS:
                st["lookups"] += 1
            if mech == "all":
                has_all = True
                if top and st["top_all"] is None:
                    st["top_all"] = m["qualifier"] + "all"
            elif mech in ("ip4", "ip6"):
                origin = "direct" if depth == 0 else ("third_party_mail" if vendor else "included")
                st["cidrs"].append({"cidr": m["value"], "origin": origin, "vendor": vendor, "via": name, "qualifier": m["qualifier"]})
            elif mech == "include":
                target = m["value"]
                tv = vendor or vendor_for(target, vendors)
                st["includes"].append({"domain": target, "depth": depth + 1, "vendor": tv, "via": name})
                if "%" in target:
                    st["warnings"].append(f"macro include not expanded: {target}")
                elif target in path:
                    st["errors"].append(f"permerror: include loop {name} -> {target}")
                else:
                    walk(target, depth + 1, path | {target}, "include", tv, False)
            elif mech in ("a", "mx"):
                target = m["value"] or name
                if "%" in target:
                    st["warnings"].append(f"macro {mech} not expanded: {target}")
                elif resolve_targets:
                    res = query(target, "A" if mech == "a" else "MX")
                    if res is not None and res.verified:
                        if res.void:
                            st["void"] += 1
                        if mech == "mx" and len(res.records) > 10:
                            st["errors"].append(f"permerror: more than 10 MX records for {target}")
                    elif res is not None:
                        st["temperror"] = True
                        st["errors"].append(f"temperror: {target} {'A' if mech == 'a' else 'MX'} {res.status}")
            elif mech == "ptr":
                st["warnings"].append(f"ptr mechanism (deprecated, RFC 7208 5.5) at {name}")
        if parsed["redirect"] and not has_all:
            target = parsed["redirect"].lower().rstrip(".")
            st["lookups"] += 1
            tv = vendor or vendor_for(target, vendors)
            if target in path:
                st["errors"].append(f"permerror: redirect loop {name} -> {target}")
            elif "%" in target:
                st["warnings"].append(f"macro redirect not expanded: {target}")
            else:
                st["includes"].append({"domain": target, "depth": depth + 1, "vendor": tv, "via": name})
                outcome = walk(target, depth + 1, path | {target}, "redirect", tv, top)
                if outcome in ("none", "nxdomain"):
                    st["errors"].append(f"permerror: redirect target {target} has no SPF record")
        return "ok"

    top = walk(domain, 0, frozenset({domain}), "self", None, True)
    if st["lookups"] > SPF_MAX_LOOKUPS:
        st["errors"].append(f"permerror: too many DNS lookups ({st['lookups']} > {SPF_MAX_LOOKUPS})")
    if st["void"] > SPF_MAX_VOID:
        st["errors"].append(f"permerror: too many void lookups ({st['void']} > {SPF_MAX_VOID})")
    if top in ("temperror", "partial") and not st["tree"]:
        status = "could_not_verify"
    elif top in ("none", "nxdomain"):
        status = "none"
    elif any(e.startswith("permerror") for e in st["errors"]):
        status = "permerror"
    elif st["temperror"]:
        status = "temperror"
    else:
        status = "ok"
    if (st["temperror"] or top == "partial") and status != "could_not_verify":
        st["partial"] = True
    return {
        "domain": domain,
        "status": status,
        "record": st["tree"][0]["record"] if st["tree"] else None,
        "all": st["top_all"],
        "spf_lookups": st["lookups"],
        "spf_void_lookups": st["void"],
        "doh_queries": st["queries"],
        "errors": st["errors"],
        "warnings": st["warnings"],
        "partial": st["partial"],
        "tree": st["tree"],
        "includes": st["includes"],
        "vendors": sorted({i["vendor"] for i in st["includes"] if i["vendor"]}),
        "cidrs": st["cidrs"],
        "candidate_cidrs": [c["cidr"] for c in st["cidrs"] if c["origin"] == "direct"],
        "third_party_mail_cidrs": [c for c in st["cidrs"] if c["origin"] == "third_party_mail"],
    }


# ======================================================================================
# DMARC (RFC 7489), DKIM, MTA-STS, TLS-RPT, BIMI, CAA
# ======================================================================================


def select_dmarc(txts: list[str]) -> tuple[str | None, str | None]:
    """RFC 7489 6.6.3: exactly one 'v=DMARC1' record (several = no policy)."""
    recs = [t.strip() for t in txts if isinstance(t, str) and _DMARC_RE.match(t.strip())]
    if len(recs) == 1:
        return recs[0], None
    if len(recs) > 1:
        return None, "multiple DMARC records (treated as no policy)"
    return None, None


def _mailto_list(value: str | None) -> list[dict[str, Any]]:
    out = []
    for uri in (value or "").split(","):
        uri = uri.strip()
        if not uri:
            continue
        m = re.match(r"^mailto:([^!]+)(?:!(\d+[kmgt]?))?$", uri, re.I)
        if m:
            addr = m.group(1).strip()
            out.append({"scheme": "mailto", "domain": addr.rsplit("@", 1)[1].lower().rstrip(".") if "@" in addr else None})
        else:
            out.append({"scheme": uri.split(":", 1)[0].lower() if ":" in uri else None, "domain": None})
    return out


def parse_dmarc(record: str) -> dict[str, Any]:
    """DMARC record -> ``{valid, p, sp, pct, rua, ruf, adkim, aspf, errors}`` (mailboxes reduced to domains)."""
    out: dict[str, Any] = {"valid": False, "p": None, "sp": None, "pct": 100, "rua": [], "ruf": [], "adkim": "r", "aspf": "r", "errors": []}
    if not isinstance(record, str) or not _DMARC_RE.match(record.strip()):
        out["errors"].append("not a DMARC record")
        return out
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "").lower()
    if p in ("none", "quarantine", "reject"):
        out["p"] = p
    else:
        out["errors"].append("missing or invalid p= tag")
    sp = tags.get("sp", "").lower()
    out["sp"] = sp if sp in ("none", "quarantine", "reject") else out["p"]
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if not 0 <= pct <= 100:
                raise ValueError(pct)
            out["pct"] = pct
        except ValueError:
            out["errors"].append("invalid pct= tag")
    out["rua"] = _mailto_list(tags.get("rua"))
    out["ruf"] = _mailto_list(tags.get("ruf"))
    for k in ("adkim", "aspf"):
        if tags.get(k, "").lower() in ("r", "s"):
            out[k] = tags[k].lower()
    out["valid"] = out["p"] is not None
    return out


def dmarc_discovery(name: str, resolve: Callable[[str, str], Answer]) -> dict[str, Any]:
    """P002 cond 3-4: ``_dmarc.<name>``, then the organisational domain (PSL) with its sp= tag.

    status: ok | none (verified absent) | invalid | could_not_verify (SERVFAIL/timeout at any step:
    never 'missing DMARC', rule 5)."""
    name = (name or "").strip().lower().rstrip(".")
    org = registrable_or(name)
    out: dict[str, Any] = {"status": "none", "policy_domain": None, "record": None, "parsed": None, "applied_policy": None, "queried": [], "reason": ""}
    for cand in [name] + ([org] if org and org != name else []):
        qname = "_dmarc." + cand
        out["queried"].append(qname)
        ans = resolve(qname, "TXT")
        if not ans.verified:
            out.update(status="could_not_verify", reason=f"{qname} TXT {ans.status}")
            return out
        rec, err = select_dmarc(ans.records) if ans.status == "NOERROR" else (None, None)
        if err:
            out.update(status="invalid", reason=err, policy_domain=cand)
            return out
        if rec:
            parsed = parse_dmarc(rec)
            out.update(status="ok" if parsed["valid"] else "invalid", policy_domain=cand, record=rec, parsed=parsed,
                       reason="" if parsed["valid"] else "; ".join(parsed["errors"]))
            out["applied_policy"] = parsed["p"] if cand == name else parsed["sp"]
            return out
    return out


def dmarc_external_destinations(policy_domain: str, parsed: dict[str, Any]) -> list[dict[str, str]]:
    """P002 cond 3: rua/ruf destinations outside the policy domain's organisational domain, with the
    authorization record name ``<policy_domain>._report._dmarc.<dest>`` (RFC 7489 7.1); at most 5."""
    pol = (policy_domain or "").lower().rstrip(".")
    pol_org = registrable_or(pol)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for uri in list(parsed.get("rua") or []) + list(parsed.get("ruf") or []):
        dom = uri.get("domain") if isinstance(uri, dict) else None
        if not dom or dom in seen or registrable_or(dom) == pol_org:
            continue
        if Entity.try_make(T.DOMAIN, dom) is None:
            continue
        seen.add(dom)
        out.append({"dest_domain": dom, "auth_name": f"{pol}._report._dmarc.{dom}"})
        if len(out) >= MAX_REPORT_DESTINATIONS:
            break
    return out


def dmarc_report_authorized(ans: Answer) -> bool | None:
    """True/False for an external-report authorization lookup, None when it could not be verified."""
    if ans.status == "NXDOMAIN":
        return False
    if ans.status != "NOERROR":
        return None
    return any(_DMARC_RE.match(t.strip()) for t in ans.records)


def parse_dkim(record: str) -> dict[str, Any]:
    """DKIM key record -> ``{valid, revoked (empty p=), key_type, testing}``."""
    out: dict[str, Any] = {"valid": False, "revoked": False, "key_type": "rsa", "testing": False}
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    if ("v" in tags and tags["v"] != "DKIM1") or "p" not in tags:
        return out
    out.update(valid=True, revoked=tags["p"] == "", key_type=(tags.get("k") or "rsa").lower(), testing="y" in tags.get("t", "").split(":"))
    return out


def dkim_summary(results: dict[str, Answer], checked: int) -> dict[str, Any]:
    """P002 cond 8: 'not determined (N common selectors checked)' when no usable key is found - never
    'DKIM missing'. Null keys (p=) are revoked, not keys; identical answers for every selector suggest a
    wildcard (example.com answers a null key under any selector) and are not counted as found."""
    found: list[str] = []
    revoked: list[str] = []
    unverified: list[str] = []
    records: list[str] = []
    for sel, ans in results.items():
        if not ans.verified:
            unverified.append(sel)
            continue
        for rec in ans.records:
            parsed = parse_dkim(rec)
            if parsed["valid"]:
                records.append(rec)
                (revoked if parsed["revoked"] else found).append(sel)
                break
    answered = checked - len(unverified)
    wildcard = len(records) >= 3 and len(set(records)) == 1 and len(records) == answered
    if found and not wildcard:
        wording = "DKIM keys found for selectors: " + ", ".join(sorted(found))
    elif revoked and not found:
        wording = f"only null/revoked DKIM keys published ({checked} common selectors checked)"
    else:
        wording = f"not determined ({checked} common selectors checked)"
    if unverified:
        wording += f"; {len(unverified)} selector lookup(s) could not be verified"
    return {"dkim_selectors": [] if wildcard else sorted(found), "revoked_selectors": sorted(revoked), "checked": checked,
            "could_not_verify": sorted(unverified), "wildcard_suspected": wildcard, "wording": wording}


def _tag_record(record: str, version: str) -> dict[str, str] | None:
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags if tags.get("v", "").lower() == version.lower() else None


def txt_feature(ans: Answer, version: str) -> dict[str, Any] | None:
    """MTA-STS / TLS-RPT / BIMI TXT: the tag dict of the record with this version, {} when verified
    absent, None when it could not be verified."""
    if not ans.verified:
        return None
    for rec in ans.records:
        tags = _tag_record(rec, version)
        if tags is not None:
            return tags
    return {}


def caa_issuers(records: list[str]) -> list[str]:
    """CA domains of issue/issuewild CAA records ('0 issue "pki.goog"')."""
    out = set()
    for rec in records:
        m = re.match(r'^\s*\d+\s+(issue|issuewild)\s+"?([^";\s]*)', rec or "", re.I)
        if m and m.group(2):
            out.add(m.group(2).lower())
    return sorted(out)


def mx_hosts(records: list[str]) -> tuple[list[str], bool]:
    """MX records ('10 host') -> (hosts, null MX per RFC 7505)."""
    hosts: list[str] = []
    null = False
    for rec in records:
        bits = (rec or "").split()
        if len(bits) != 2:
            continue
        host = bits[1].rstrip(".").lower()
        if host in ("", "."):
            null = True
        elif host not in hosts:
            hosts.append(host)
    return hosts, null


# ======================================================================================
# Findings (P002 cond 4, 7)
# ======================================================================================


def posture_table(p: dict[str, Any]) -> dict[str, Any]:
    """The summary table of the single info finding (could-not-verify data stays 'could not verify')."""
    spf = p["spf"]
    dmarc = p["dmarc"]
    spf_state = {"ok": "valid", "none": "absent", "permerror": "permerror", "temperror": "present; include chain could not be verified",
                 "could_not_verify": "could not verify"}.get(spf["status"], "could not verify")
    if spf.get("all"):
        spf_state += f" ({spf['all']})"
    if dmarc["status"] == "ok":
        dmarc_state = f"p={dmarc['applied_policy']}" + (f" pct={dmarc['parsed']['pct']}" if dmarc["parsed"]["pct"] != 100 else "")
        if dmarc["policy_domain"] and dmarc["policy_domain"] != p["domain"]:
            dmarc_state += f" (organisational domain {dmarc['policy_domain']})"
    else:
        dmarc_state = {"none": "absent", "invalid": "invalid"}.get(dmarc["status"], "could not verify")

    def feature(value: dict[str, Any] | None) -> str:
        if value is None:
            return "could not verify"
        return "present" if value else "absent"

    caa = p["caa"]
    mx = p["mx"]
    return {
        "spf": spf_state,
        "spf_lookups": spf["spf_lookups"] if spf["status"] != "could_not_verify" else None,
        "spf_void_lookups": spf["spf_void_lookups"] if spf["status"] != "could_not_verify" else None,
        "dmarc": dmarc_state,
        "dkim": p["dkim"]["wording"] if p["dkim"] else "not checked (subdomain: selectors are probed on registrable and e-mail domains)",
        "mta_sts": feature(p["mta_sts"]),
        "tls_rpt": feature(p["tls_rpt"]),
        "bimi": feature(p["bimi"]),
        "caa": ("could not verify" if caa is None else (", ".join(caa) if caa else "absent")),
        "dnssec": p["dnssec"],
        "mx": ("could not verify" if mx is None else "NXDOMAIN" if mx.get("nxdomain") else "null MX (no mail)" if mx["null"]
               else (", ".join(mx["hosts"][:5]) or "none (implicit MX)")),
    }


def own_domain_findings(p: dict[str, Any]) -> list[dict[str, Any]]:
    """P002 cond 7: severities for org_profile own domains only (verified DNS data only, rule 5)."""
    spf = p["spf"]
    dmarc = p["dmarc"]
    out: list[dict[str, Any]] = []
    if dmarc["status"] == "none":
        out.append({"title": "DMARC record missing on an own domain", "severity": "medium", "spoof": True,
                    "criterion": "no v=DMARC1 record at _dmarc.<domain> nor at the organisational domain (verified DNS answers)",
                    "description": "Receivers apply no DMARC policy: mail spoofing this domain is not blocked."})
    elif dmarc["status"] == "invalid":
        out.append({"title": "DMARC record invalid on an own domain", "severity": "medium", "spoof": True,
                    "criterion": f"DMARC record unusable ({dmarc['reason'] or 'no valid p= tag'}): receivers treat it as missing",
                    "description": "An invalid DMARC record is ignored by receivers."})
    elif dmarc["status"] == "ok" and dmarc["applied_policy"] == "none":
        out.append({"title": "DMARC policy p=none on an own domain (monitoring only)", "severity": "medium", "spoof": True,
                    "criterion": "applied DMARC policy is none (p= or sp= for subdomains)",
                    "description": "p=none only monitors: spoofed mail is still delivered."})
    if spf["status"] in ("ok", "permerror", "temperror") and spf.get("all") == "+all":
        out.append({"title": "SPF allows any sender (+all) on an own domain", "severity": "high", "spoof": True,
                    "criterion": "the effective SPF 'all' mechanism has the + qualifier",
                    "description": "+all authorises every host on the internet to send mail for the domain."})
    if spf["status"] == "permerror":
        why = next((e for e in spf["errors"] if e.startswith("permerror")), "permerror")
        out.append({"title": "SPF permerror on an own domain", "severity": "medium", "spoof": False,
                    "criterion": f"RFC 7208 permanent error: {why.replace('permerror: ', '')}",
                    "description": f"Receivers treat the SPF record as broken ({spf['spf_lookups']} DNS lookups, {spf['spf_void_lookups']} void)."})
    return out


# ======================================================================================
# Per-scan memo (once per domain and scan, P002 cond 8)
# ======================================================================================

_MEMO_LOCK = threading.Lock()
_DONE: dict[str, set[str]] = {}


def claim_once(case_id: str, domain: str) -> bool:
    """True the first time ``domain`` is evaluated in scan ``case_id`` (no case id: always True)."""
    if not case_id:
        return True
    with _MEMO_LOCK:
        if case_id not in _DONE and len(_DONE) >= 64:
            _DONE.pop(next(iter(_DONE)))
        done = _DONE.setdefault(case_id, set())
        if domain in done:
            return False
        done.add(domain)
        return True


def target_domain(entity: Entity) -> str:
    value = str(entity.value)
    return value.rsplit("@", 1)[-1].lower() if entity.type is T.EMAIL else value.lower()


# ======================================================================================
# The module
# ======================================================================================


@register
class EmailSecurityPosture(Module):
    name = "email_security_posture"
    title = "E-mail security posture"
    description = "SPF tree with RFC 7208 limits, DMARC, common DKIM selectors, MTA-STS, TLS-RPT, BIMI, CAA and DNSSEC of a mail domain, over DNS-over-HTTPS."
    category = "domain_dns"
    accepts = {T.DOMAIN, T.EMAIL}
    produces = {T.DOMAIN, T.CIDR, T.IPV4, T.IPV6}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the DoH resolver operator sees the names, never the target
    provider = "core_doh"
    sources = (SOURCE,)
    hosts = ()
    access_model = "free_noauth_unlimited"
    max_requests = 0  # DoH only: ctx.dns is not counted
    expected_latency = 3.0
    timeout = 60.0
    max_pivots = CIDR_PIVOT_CAP + INCLUDE_PIVOT_CAP
    default_enabled = True
    reference = "https://www.rfc-editor.org/rfc/rfc7489"
    tags = {"free"}

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Registrable domains, their subdomains and e-mail domains; free-webmail domains of an e-mail
        address are not the sender's posture (the core noise list classes them 'webmail')."""
        domain = target_domain(entity)
        if not domain or psl.registrable_domain(domain) is None:
            return False
        if entity.type is T.EMAIL:
            ent = Entity.try_make(T.DOMAIN, domain)
            try:
                return ent is not None and noise.noise_kind(ent) != "webmail"
            except Exception:  # noqa: BLE001
                return ent is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = target_domain(entity)
        if not claim_once(str(ctx.case_id or ""), domain):
            return res.mark("skipped", f"e-mail security posture of {domain} already evaluated in this scan", reason_code="not_applicable")
        lookup = Lookup(ctx.dns)
        spf_vendors, mx_vendors = load_vendor_table(ctx)
        probe_dkim = entity.type is T.EMAIL or psl.registrable_domain(domain) == domain  # P002 cond 8
        selectors = self._selectors(ctx) if probe_dkim else []
        jobs: dict[str, Callable[[], Any]] = {
            "spf": lambda: evaluate_spf(domain, lookup, spf_vendors),
            "dmarc": lambda: dmarc_discovery(domain, lookup),
            "mx": lambda: lookup(domain, "MX"),
            "caa": lambda: lookup(domain, "CAA"),
            "ds": lambda: lookup(domain, "DS"),
            "mta_sts": lambda: lookup("_mta-sts." + domain, "TXT"),
            "tls_rpt": lambda: lookup("_smtp._tls." + domain, "TXT"),
            "bimi": lambda: lookup("default._bimi." + domain, "TXT"),
        }
        for sel in selectors:
            jobs["dkim:" + sel] = lambda s=sel: lookup(f"{s}._domainkey.{domain}", "TXT")
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="email_posture") as pool:
            futures = {name: pool.submit(fn) for name, fn in jobs.items()}
            done = {name: fut.result() for name, fut in futures.items()}
        spf: dict[str, Any] = done["spf"]
        dmarc: dict[str, Any] = done["dmarc"]
        external = self._external_reports(dmarc, lookup)
        mx_ans: Answer = done["mx"]
        txt_top = lookup(domain, "TXT")
        res.raw = {"domain": domain, "spf": {k: spf[k] for k in ("status", "record", "all", "spf_lookups", "spf_void_lookups", "errors", "warnings", "partial", "tree", "includes")},
                   "dmarc": {k: dmarc[k] for k in ("status", "policy_domain", "record", "applied_policy", "queried", "reason")}, "queries": lookup.snapshot()}
        unverified = [label for label, ok in (("TXT", txt_top.verified), ("_dmarc", dmarc["status"] != "could_not_verify"), ("MX", mx_ans.verified)) if not ok]
        if len(unverified) == 3:  # rule 5: nothing verified - no posture, no absence claim
            reason = txt_top.error or mx_ans.error or dmarc["reason"] or "DoH answers could not be verified"
            return res.mark("error", f"could not verify the e-mail security posture of {domain}: {reason}", reason_code=self._code(txt_top, mx_ans))
        posture = {
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim_summary({s: done["dkim:" + s] for s in selectors}, len(selectors)) if selectors else None,
            "mta_sts": txt_feature(done["mta_sts"], "STSv1"),
            "tls_rpt": txt_feature(done["tls_rpt"], "TLSRPTv1"),
            "bimi": txt_feature(done["bimi"], "BIMI1"),
            "caa": caa_issuers(done["caa"].records) if done["caa"].verified else None,
            "caa_records": list(done["caa"].records) if done["caa"].verified else None,
            "dnssec": self._dnssec(done["ds"], txt_top, mx_ans),
            "mx": {**dict(zip(("hosts", "null"), mx_hosts(mx_ans.records))), "nxdomain": mx_ans.status == "NXDOMAIN"} if mx_ans.verified else None,
            "external": external,
        }
        self._attributes(res, posture, mx_vendors)
        self._pivots(res, spf)
        own = self._own(ctx, domain)
        res.raw["own_domain"] = own
        for f in own_domain_findings(posture) if own else []:
            res.finding(
                f["title"], f["severity"], f["description"], confidence="confirmed", criterion=f["criterion"],
                data={"domain": domain, "spf_lookups": spf["spf_lookups"], "spf_void_lookups": spf["spf_void_lookups"],
                      "dmarc": posture_table(posture)["dmarc"]},
                tags=["weak_email_security"], source=SOURCE, attack=list(SPOOFING_ATTACK) if f["spoof"] else [],
            )
        table = posture_table(posture)
        res.attr("email_posture", table)
        res.finding(
            "E-mail security posture summary",
            "info",
            "; ".join(f"{k}: {v}" for k, v in table.items()),
            confidence="confirmed",
            criterion="DNS answers through the core DoH resolvers (could-not-verify entries are never absences)",
            data=table,
            tags=["info"],
            source=SOURCE,
        )
        if unverified or spf["partial"] or (posture["dkim"] or {}).get("could_not_verify"):
            missing = ", ".join(unverified) or "part of the SPF/DKIM lookups"
            res.error = f"could not verify: {missing} (DoH error, SERVFAIL, REFUSED or timeout)"
            res.source_status(SOURCE, Status.ERROR, reason_code=self._code(txt_top, mx_ans), reason=res.error)
        return res

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _selectors(ctx: Any) -> list[str]:
        try:
            data = ctx.data.bundled_json(DKIM_SELECTORS_FILE)
            items = data.get("selectors") if isinstance(data, dict) else None
            names = [s.strip().lower() for s in items or [] if isinstance(s, str) and re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", s.strip().lower())]
        except (OSError, ValueError):
            names = []
        return list(dict.fromkeys(names or FALLBACK_SELECTORS))[:MAX_SELECTORS]

    @staticmethod
    def _external_reports(dmarc: dict[str, Any], lookup: Lookup) -> list[dict[str, Any]]:
        if dmarc["status"] != "ok" or not dmarc["parsed"]:
            return []
        out = []
        for dest in dmarc_external_destinations(dmarc["policy_domain"], dmarc["parsed"]):
            out.append({"dest_domain": dest["dest_domain"], "authorized": dmarc_report_authorized(lookup(dest["auth_name"], "TXT"))})
        return out

    @staticmethod
    def _dnssec(ds: Answer, *others: Answer) -> str:
        """DS presence and the resolver AD flag: 'validated by resolver', never proof (P029)."""
        answers = [a for a in (ds, *others) if a.verified]
        if not answers:
            return "could not verify"
        ad = any(a.ad for a in answers)
        ds_state = ("DS present" if ds.records else "no DS") if ds.verified else "DS could not be verified"
        return f"{ds_state}; {'validated by resolver (AD flag)' if ad else 'not validated by resolver'}"

    @staticmethod
    def _code(*answers: Answer) -> str:
        return "timeout" if any(a.status == "TIMEOUT" for a in answers) else "error"

    @staticmethod
    def _own(ctx: Any, domain: str) -> bool:
        ent = Entity.try_make(T.DOMAIN, domain)
        if ent is None:
            return False
        try:
            own = ctx.org.owns(ent)
        except Exception:  # noqa: BLE001 - a profile problem never breaks a run
            return False
        return bool(getattr(own, "own", False)) and getattr(own, "kind", "") == "domain"

    @staticmethod
    def _attributes(res: ModuleResult, p: dict[str, Any], mx_vendors: tuple[tuple[str, str], ...]) -> None:
        spf, dmarc = p["spf"], p["dmarc"]
        res.attr("spf_status", spf["status"])
        if spf["status"] != "could_not_verify":
            res.attr("spf", spf["record"])
            res.attr("spf_lookups", spf["spf_lookups"])
            res.attr("spf_void_lookups", spf["spf_void_lookups"])
            res.attr("spf_includes", [{"domain": i["domain"], "vendor": i["vendor"], "depth": i["depth"], "via": i["via"]} for i in spf["includes"][:50]])
            res.attr("third_party_mail_cidrs", [{"cidr": c["cidr"], "vendor": c["vendor"], "via": c["via"]} for c in spf["third_party_mail_cidrs"][:200]])
        if dmarc["status"] == "ok":
            res.attr("dmarc", dmarc["record"])
            res.attr("dmarc_policy", dmarc["applied_policy"])
            res.attr("dmarc_pct", dmarc["parsed"]["pct"])
            res.attr("dmarc_sp", dmarc["parsed"]["sp"])
        res.attr("dmarc_rua_external", p["external"])
        if p["dkim"] is not None:
            res.attr("dkim_selectors", p["dkim"]["dkim_selectors"])
        for key in ("mta_sts", "tls_rpt", "bimi"):
            value = p[key]
            if value is None:
                continue
            if key == "mta_sts":
                res.attr(key, {"present": bool(value), "id": value.get("id")} if value else {"present": False})
            elif key == "tls_rpt":
                rua = [u.strip() for u in (value.get("rua") or "").split(",") if u.strip()] if value else []
                res.attr(key, {"present": bool(value), "rua": rua} if value else {"present": False})
            else:
                logo, auth = (value.get("l") or None, value.get("a") or None) if value else (None, None)
                res.attr(key, {"present": bool(value), "logo": logo, "authority": auth, "declined": bool(value) and not logo and not auth})
        if p["caa_records"]:
            res.attr("caa", p["caa_records"])  # raw records, as dns_records writes them (issuers are in the summary table)
        if p["mx"] is not None:
            res.attr("mx", p["mx"]["hosts"])
        vendors = set(spf["vendors"])
        for host in (p["mx"] or {}).get("hosts", []):
            vendors.update(v for s, v in mx_vendors if host == s or host.endswith("." + s))
        res.attr("mail_providers", sorted(vendors))

    @staticmethod
    def _pivots(res: ModuleResult, spf: dict[str, Any]) -> None:
        """Direct ip4/ip6 -> candidate pivots (cond 6); non-vendor include domains -> spf_include.
        Third-party mail netblocks and SaaS includes are never pivots (cond 5)."""
        for cidr in spf["candidate_cidrs"][:CIDR_PIVOT_CAP]:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            note = "candidate netblock (direct SPF ip4/ip6 mechanism): ownership unconfirmed until RDAP/NIC.br"
            if net.num_addresses == 1:
                etype = T.IPV4 if net.version == 4 else T.IPV6
                res.pivot(etype, str(net.network_address), "spf_authorized", confidence="possible", expand=False, note=note)
            else:
                res.pivot(T.CIDR, str(net), "spf_authorized", confidence="possible", expand=False, note=note)
        includes = [i for i in spf["includes"] if not i["vendor"] and "%" not in i["domain"]]
        for inc in includes[:INCLUDE_PIVOT_CAP]:
            res.pivot(T.DOMAIN, inc["domain"], "spf_include", confidence="probable", expand=False,
                      note=f"SPF include/redirect of {inc['via']} (not a known mail SaaS)")
