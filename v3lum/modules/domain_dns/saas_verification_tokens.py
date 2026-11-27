"""SaaS footprint from DNS TXT domain-verification tokens (P342 saas_verification_tokens).

Vendors ask their customers to publish a TXT record such as ``atlassian-domain-verification=...``,
``MS=ms12345678`` or ``docusign=...`` at the domain to prove they control it. Mapping those prefixes
to vendors gives a cheap, passive inventory of the SaaS tenants an organisation verified: which
identity provider, helpdesk and e-signature brands attackers would imitate in phishing, and which
services belong in the attack-surface inventory.

Final conditions (council #1, P342) and where they live:

1. One TXT lookup through ``ctx.dns`` (the core DoH resolvers): the answer email_security_posture and
   dns_records already fetched for the same name is a DoH cache hit, so the module normally sends
   nothing; otherwise exactly one query. A DoH error (SERVFAIL, REFUSED, timeout, 429, challenge) is
   'could not verify' (ERROR / RATE_LIMITED / BLOCKED), never 'no SaaS'. :func:`footprint_from_doh`
   also reads replayed DoH JSON: a research ``json_extract`` summary without records is could not
   verify.
2. Prefixes map to vendors through the bundled own-work table
   ``v3lum/data/saas_verification_tokens/txt_verification_prefixes.json`` (:func:`load_prefix_table`
   validates it): case-insensitive, longest prefix wins, policy records (SPF, DMARC, DKIM, MTA-STS,
   TLS-RPT, BIMI) never count as tokens.
3. Output: attribute ``saas_vendors`` (vendor names), attribute ``saas_unknown_prefixes`` (prefixes
   the table does not know, listed raw without values or embedded ids) and ONE info finding per
   domain carrying the phishing-simulation/ASM hints (IdP, helpdesk, e-signature, security-awareness
   vendors, other lure brands) and per-category hints. The vocabulary names live in
   ``v3lum/data/vocab/p2-G01-4.json`` (module batches never edit core/vocab.py).
4. Wording is always 'verification record present' (a past verification, not current use). Token
   values are never pivoted (``max_pivots = 0``) and never reach attributes, findings or reports:
   the raw TXT strings stay in ``res.raw`` (sanitized evidence) only.
5. Tests replay the recorded research request ``gaps__saas_tenants`` (atlassian.com via Cloudflare
   DoH): its stored summary (Status 0, 98 answers) and the same request re-recorded with the 98
   records (token values scrubbed).

Subdomain records (``zendeskverification.<domain>``, ``_oktaverification.<host>``,
``_github-challenge-<org>.<domain>``) are not queried: one TXT query per name (FC1). SPF includes
that reveal mail vendors belong to email_security_posture.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register

SOURCE = "core_doh.resolvers"
TABLE_FILE = "saas_verification_tokens/txt_verification_prefixes.json"
TABLE_SCHEMA = "v3lum.txt_verification_prefixes/1"
WORDING = "verification record present"
WORDING_FULL = "verification record present (proves a past domain verification, not current use)"
FINDING_TITLE = "SaaS verification records present"
MAX_RECORDS = 500  # TXT strings examined per name (atlassian.com: 98)
UNKNOWN_CAP = 50
PREFIX_CAP = 64
DEFAULT_POLICY_PREFIXES = ("v=spf1", "v=dmarc1", "v=dkim1", "v=stsv1", "v=tlsrptv1", "v=bimi1", "spf2.0/")
GROUP_ORDER = ("idp", "helpdesk", "e_signature", "security_awareness", "other_lures")
GROUP_TEXT = {
    "idp": "IdP/SSO",
    "helpdesk": "helpdesk",
    "e_signature": "e-signature",
    "security_awareness": "security awareness (coordinate simulations)",
    "other_lures": "other lure brands",
}

_KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\-]{1,127})\s*([=:])\s*(\S.*)$", re.S)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_+/=.\-]{8,}$")
_HEX_RE = re.compile(r"[0-9a-f]{8,}", re.I)


# ======================================================================================
# the bundled prefix table (FC2)
# ======================================================================================


@dataclass(frozen=True)
class PrefixEntry:
    prefix: str  # lower case, separator included where the vendor uses one
    vendor: str
    product: str
    category: str
    seen: str


@dataclass(frozen=True)
class PrefixTable:
    entries: tuple[PrefixEntry, ...]  # longest prefix first
    categories: dict[str, dict[str, str]]
    groups: dict[str, tuple[str, ...]]  # phishing group -> categories
    group_labels: dict[str, str]
    policy_prefixes: tuple[str, ...]
    version: str = ""

    def lookup(self, record: str) -> PrefixEntry | None:
        low = record.lower()
        for entry in self.entries:
            if low.startswith(entry.prefix):
                return entry
        return None


def load_prefix_table(obj: Any) -> PrefixTable:
    """Validate the bundled table -> :class:`PrefixTable`. ValueError on a missing field, an unknown
    category, a duplicate prefix or a phishing group naming an unknown category."""
    if not isinstance(obj, dict):
        raise ValueError("prefix table is not a JSON object")
    if obj.get("schema") != TABLE_SCHEMA:
        raise ValueError(f"prefix table schema must be {TABLE_SCHEMA!r}")
    cats = obj.get("categories")
    entries_in = obj.get("entries")
    if not isinstance(cats, dict) or not cats or not isinstance(entries_in, list) or not entries_in:
        raise ValueError("prefix table needs non-empty 'categories' and 'entries'")
    categories: dict[str, dict[str, str]] = {}
    for name, meta in cats.items():
        if not isinstance(name, str) or not isinstance(meta, dict) or not isinstance(meta.get("label"), str) or not isinstance(meta.get("hint"), str):
            raise ValueError(f"category {name!r} needs a label and a hint")
        categories[name] = {"label": meta["label"], "hint": meta["hint"]}
    seen: set[str] = set()
    entries: list[PrefixEntry] = []
    for item in entries_in:
        if not isinstance(item, dict):
            raise ValueError("prefix entry is not an object")
        for field in ("prefix", "vendor", "category", "seen"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"prefix entry lacks {field}: {item!r}")
        prefix = item["prefix"].strip().lower()
        if len(prefix) < 3:
            raise ValueError(f"prefix {prefix!r} is too short to identify a vendor")
        if prefix in seen:
            raise ValueError(f"duplicate prefix {prefix!r}")
        if item["category"] not in categories:
            raise ValueError(f"unknown category {item['category']!r} for {prefix!r}")
        if item["seen"] not in ("live", "council", "doc"):
            raise ValueError(f"'seen' of {prefix!r} must be live, council or doc")
        seen.add(prefix)
        product = item.get("product") if isinstance(item.get("product"), str) else ""
        entries.append(PrefixEntry(prefix, item["vendor"].strip(), product.strip(), item["category"], item["seen"]))
    entries.sort(key=lambda e: (-len(e.prefix), e.prefix))
    groups: dict[str, tuple[str, ...]] = {}
    labels: dict[str, str] = {}
    for gname, gmeta in (obj.get("phishing_groups") or {}).items():
        members = gmeta.get("categories") if isinstance(gmeta, dict) else None
        if not isinstance(members, list) or any(m not in categories for m in members):
            raise ValueError(f"phishing group {gname!r} names unknown categories")
        groups[gname] = tuple(members)
        labels[gname] = str(gmeta.get("label") or gname)
    missing = [g for g in GROUP_ORDER if g not in groups]
    if missing:
        raise ValueError(f"phishing groups missing: {', '.join(missing)}")
    policy = obj.get("policy_prefixes") or list(DEFAULT_POLICY_PREFIXES)
    if not isinstance(policy, list) or not all(isinstance(p, str) and p for p in policy):
        raise ValueError("policy_prefixes must be a list of strings")
    return PrefixTable(tuple(entries), categories, groups, labels, tuple(p.lower() for p in policy), str(obj.get("version") or ""))


_TABLES: dict[int, tuple[Any, PrefixTable]] = {}
_TABLES_LOCK = threading.Lock()


def prefix_table(ctx: Any = None) -> PrefixTable:
    """The bundled table through ``ctx.data`` (cited in res.datasets) or the package data directly,
    parsed once per loaded object. ValueError when the bundled file is unusable."""
    if ctx is not None:
        data = ctx.data.bundled_json(TABLE_FILE)
    else:
        from v3lum.core.datasets import DataStore

        data = DataStore.bundled_json(TABLE_FILE)
    key = id(data)
    with _TABLES_LOCK:
        hit = _TABLES.get(key)
    if hit is not None and hit[0] is data:
        return hit[1]
    table = load_prefix_table(data)
    with _TABLES_LOCK:
        if len(_TABLES) > 8:
            _TABLES.clear()
        _TABLES[key] = (data, table)
    return table


# ======================================================================================
# classification (FC2-FC4)
# ======================================================================================


def split_txt_key(record: Any) -> tuple[str | None, str | None, str]:
    """'key=value' / 'key: value' -> (key, separator, value); (None, None, record) without a key.
    A ':' followed by '//' is a URL, not a key; a value made only of '=' is base64 padding."""
    if not isinstance(record, str):
        return None, None, ""
    m = _KEY_RE.match(record.strip())
    if not m:
        return None, None, record
    key, sep, value = m.group(1), m.group(2), m.group(3)
    if (sep == ":" and value.startswith("//")) or not value.strip("= "):
        return None, None, record
    return key, sep, value


def _idlike(segment: str) -> bool:
    return (len(segment) >= 5 and any(c.isdigit() for c in segment)) or bool(_HEX_RE.fullmatch(segment))


def normalise_unknown_prefix(key: str) -> str:
    """An unknown key -> the prefix listed raw, without embedded ids (FC3/FC4): first dot label only
    ('_saml-domain-challenge.<uuid>.<uuid>.example.com' -> '_saml-domain-challenge'), trailing
    id-like dash segments trimmed ('databank-domain-verification-abc123' ->
    'databank-domain-verification'), at most 64 characters."""
    first = key.split(".", 1)[0] or key
    parts = first.split("-")
    while len(parts) > 1 and _idlike(parts[-1]):
        parts.pop()
    out = "-".join(parts)[:PREFIX_CAP]
    return out if not _idlike(out.lstrip("_")) else ""


def classify_txt(record: Any, table: PrefixTable) -> dict[str, Any]:
    """One TXT string -> {'kind': vendor | policy | unknown_prefix | opaque | text, ...}."""
    rec = record.strip() if isinstance(record, str) else ""
    if not rec:
        return {"kind": "text"}
    low = rec.lower()
    if low.startswith(table.policy_prefixes):
        return {"kind": "policy"}
    entry = table.lookup(rec)
    if entry is not None:
        return {"kind": "vendor", "vendor": entry.vendor, "product": entry.product, "category": entry.category, "prefix": entry.prefix, "seen": entry.seen}
    key, _sep, _value = split_txt_key(rec)
    if key:
        prefix = normalise_unknown_prefix(key)
        return {"kind": "unknown_prefix", "prefix": prefix} if prefix else {"kind": "opaque"}
    if _TOKEN_RE.match(rec):
        return {"kind": "opaque"}
    return {"kind": "text"}


def vendor_text(vendor: str, products: list[str] | tuple[str, ...] = ()) -> str:
    """FC4 wording for reports: the vendor name (products), never a token value."""
    prod = f" ({', '.join(products)})" if products else ""
    return f"{vendor}{prod}: {WORDING_FULL}"


def saas_footprint(records: Any, table: PrefixTable) -> dict[str, Any]:
    """TXT strings of one name -> the normalised SaaS footprint (FC2-FC4). No token value appears
    in the output: vendors, categories, products, prefixes and counts only."""
    recs = [r for r in (records if isinstance(records, (list, tuple)) else []) if isinstance(r, str)][:MAX_RECORDS]
    counts = {"txt_records": len(recs), "vendor_records": 0, "policy": 0, "unknown_prefix": 0, "opaque": 0, "text": 0}
    vendors: dict[str, dict[str, Any]] = {}
    unknown: dict[str, str] = {}
    for rec in recs:
        c = classify_txt(rec, table)
        kind = c["kind"]
        if kind == "vendor":
            counts["vendor_records"] += 1
            v = vendors.setdefault(c["vendor"], {"categories": set(), "products": set(), "prefixes": set(), "records": 0, "seen": set()})
            v["categories"].add(c["category"])
            if c["product"]:
                v["products"].add(c["product"])
            v["prefixes"].add(c["prefix"])
            v["seen"].add(c["seen"])
            v["records"] += 1
            continue
        counts[kind] += 1
        if kind == "unknown_prefix" and len(unknown) < UNKNOWN_CAP:
            unknown.setdefault(c["prefix"].lower(), c["prefix"])
    rows: list[dict[str, Any]] = []
    for name in sorted(vendors, key=str.lower):
        v = vendors[name]
        products = sorted(v["products"])
        rows.append({
            "vendor": name, "categories": sorted(v["categories"]), "products": products, "prefixes": sorted(v["prefixes"]),
            "records": v["records"], "seen": sorted(v["seen"]), "text": vendor_text(name, products),
        })
    by_cat: dict[str, list[str]] = {}
    for row in rows:
        for cat in row["categories"]:
            by_cat.setdefault(cat, []).append(row["vendor"])
    groups = {g: sorted({n for cat in table.groups.get(g, ()) for n in by_cat.get(cat, [])}, key=str.lower) for g in GROUP_ORDER}
    order = list(table.categories)
    hints = [
        {"category": cat, "label": table.categories[cat]["label"], "vendors": by_cat[cat], "hint": f"{WORDING}: {table.categories[cat]['hint']}"}
        for cat in sorted(by_cat, key=lambda k: order.index(k) if k in order else len(order))
    ]
    return {
        "wording": WORDING,
        "saas_vendors": [row["vendor"] for row in rows],
        "vendors": rows,
        "phishing_simulation": groups,
        "hints": hints,
        # sorted: resolvers return the same RRset in different orders (live: Cloudflare vs Google)
        "unknown_prefixes": sorted(unknown.values(), key=str.lower),
        "counts": counts,
        "table_version": table.version,
    }


def footprint_from_doh(obj: Any, table: PrefixTable) -> dict[str, Any]:
    """FC1/FC5 adapter for replayed DoH JSON (evidence, research samples): {'outcome': answer |
    nodata | nxdomain | could_not_verify, 'reason', 'footprint'}. A json_extract summary
    ('Answer.len' without 'Answer'), SERVFAIL/REFUSED, TC=1 or a body that is not a DoH answer is
    could_not_verify - never 'no SaaS'."""
    if not isinstance(obj, dict) or not isinstance(obj.get("Status"), int) or isinstance(obj.get("Status"), bool):
        return {"outcome": "could_not_verify", "reason": "not a DoH JSON answer", "footprint": None}
    if "Answer" not in obj and any(str(k).startswith("Answer.") for k in obj):
        return {"outcome": "could_not_verify", "reason": "summary without records (json_extract)", "footprint": None}
    status = obj["Status"]
    if status == 3:
        return {"outcome": "nxdomain", "reason": "NXDOMAIN", "footprint": saas_footprint([], table)}
    if status != 0:
        return {"outcome": "could_not_verify", "reason": f"DNS rcode {status}", "footprint": None}
    if obj.get("TC") is True:
        return {"outcome": "could_not_verify", "reason": "truncated answer (TC=1)", "footprint": None}
    records = [_unquote(a["data"]) for a in obj.get("Answer") or [] if isinstance(a, dict) and a.get("type") == 16 and isinstance(a.get("data"), str)]
    if not records:
        return {"outcome": "nodata", "reason": "no TXT records", "footprint": saas_footprint([], table)}
    return {"outcome": "answer", "reason": "", "footprint": saas_footprint(records, table)}


_PART_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _unquote(data: str) -> str:
    """Cloudflare-style quoted TXT data -> text (Google's unquoted data is returned as is)."""
    s = data.strip()
    if not s.startswith('"'):
        return s
    parts = _PART_RE.findall(s)
    return "".join(re.sub(r"\\(.)", r"\1", p) for p in parts) if parts else s


def dns_failure(answer: Any) -> tuple[str, str]:
    """(status, reason code) of a TXT answer that could not be verified (rule 5)."""
    status = str(getattr(answer, "status", "") or "")
    error = str(getattr(answer, "error", "") or "").lower()
    if status == "TIMEOUT":
        return "error", "timeout"
    if "429" in error or "rate limit" in error:
        return "rate_limited", "rate_limited"
    if "challenge" in error or "anti-bot" in error or "http 403" in error:
        return "blocked", "challenge"
    return "error", "error"


# ======================================================================================
# the module
# ======================================================================================


@register
class SaasVerificationTokens(Module):
    name = "saas_verification_tokens"
    title = "SaaS verification tokens (DNS TXT)"
    description = (
        "SaaS vendors with a domain-verification TXT record at the name (IdP, helpdesk, e-signature...), mapped by a bundled "
        "vendor-prefix table, with phishing-simulation/ASM hints; token values stay in evidence only."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = frozenset()
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the DoH resolver operators see the name, never the target
    provider = "core_doh"
    sources = (SOURCE,)
    hosts = ()  # DoH hosts are core, not declared
    access_model = "free_noauth_unlimited"
    max_requests = 0  # DoH only: ctx.dns is not counted
    expected_latency = 0.5  # usually a DoH cache hit left by dns_records/email_security_posture
    max_pivots = 0  # FC4: token values are never pivoted
    default_enabled = True  # DoH-based DNS modules are default-on (A3 BR10)
    reference = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/"
    tags = {"free"}
    notice = (
        "A verification record proves a past domain verification, not current use of the service. Token values are never "
        "pivoted or shown in reports: vendor names only; the raw TXT strings stay in the evidence."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(etype=T.DOMAIN, value="example.com", expect="empty")  # SPF + one opaque token: no vendor

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = str(entity.value)
        try:
            table = prefix_table(ctx)
        except (OSError, ValueError) as exc:
            return res.mark("error", f"bundled vendor-prefix table unusable ({str(exc)[:160]}): could not verify", reason_code="error")
        answer = ctx.dns.query(name, "TXT")
        res.raw = {
            "txt_answer": {
                "status": answer.status,
                "resolver": getattr(answer, "resolver", ""),
                "validated_by_resolver": bool(answer.authenticated),
                "error": answer.error,
                "records": list(answer.records),  # FC4: raw values live in the evidence only
            },
            "table_version": table.version,
        }
        if answer.could_not_verify:
            status, code = dns_failure(answer)
            return res.mark(status, f"TXT lookup could not be verified ({answer.error or answer.status}): no claim about SaaS verification records", reason_code=code)
        if answer.nxdomain:
            return res.mark("empty", "the name does not exist (NXDOMAIN): no TXT records")
        footprint = saas_footprint(answer.records, table)
        counts = footprint["counts"]
        res.raw["counts"] = counts
        if not footprint["saas_vendors"] and not footprint["unknown_prefixes"]:
            if not answer.records:
                return res.mark("empty", "no TXT records at the name (NOERROR/NODATA)")
            return res.mark("empty", f"no SaaS verification records among {counts['txt_records']} TXT record(s) ({counts['opaque']} opaque token(s) without a vendor prefix)")
        res.attr("saas_vendors", footprint["saas_vendors"])
        res.attr("saas_unknown_prefixes", footprint["unknown_prefixes"])
        res.finding(
            FINDING_TITLE,
            "info",
            _description(name, footprint),
            confidence="probable",
            criterion=(
                "TXT record at the name whose prefix matches the vendor's domain-verification prefix (bundled own-work table, "
                f"longest prefix wins); {WORDING_FULL}"
            ),
            data={k: footprint[k] for k in ("wording", "vendors", "phishing_simulation", "hints", "unknown_prefixes", "counts", "table_version")},
            tags=["info", "saas_footprint"],
            source=SOURCE,
        )
        return res


def _description(name: str, fp: dict[str, Any]) -> str:
    vendors = fp["saas_vendors"]
    parts = []
    if vendors:
        parts.append(f"{len(vendors)} SaaS vendor(s) with a {WORDING} at {name}: {', '.join(vendors)} ({WORDING_FULL}).")
    groups = fp["phishing_simulation"]
    lures = [f"{GROUP_TEXT[g]}: {', '.join(groups[g])}" for g in GROUP_ORDER if groups.get(g)]
    if lures:
        parts.append("Phishing-simulation / ASM hints (brands attackers would imitate) - " + "; ".join(lures) + ".")
    if fp["unknown_prefixes"]:
        parts.append(f"{len(fp['unknown_prefixes'])} verification prefix(es) not in V3LUM's vendor table (listed raw): {', '.join(fp['unknown_prefixes'])}.")
    return " ".join(parts)
