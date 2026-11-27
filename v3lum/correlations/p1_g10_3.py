"""Correlation rules of batch p1-G10-3 (P360 bcb_authorized_institutions): BCB-verified domains.

* ``bcb_verified_domain_flagged`` (FC5): known_good annotates, never suppresses. A BCB-verified
  institution domain (or a URL on it) that another source flags surfaces as 'possible compromise -
  verified institution domain, review URL'; every listing keeps its own severity and confidence (the
  rule only reads the graph, it never changes a finding).
* ``bcb_lookalike_activity`` (FC8): a lookalike of a BCB-verified institution domain (typosquat
  reverse match, source 'bcb') is HIGH only when registered and active - resolves (not parked or
  sinkholed), MX, or a first certificate at most 30 days old (a live-page signal arrives with the LIGHT
  modules) - otherwise a MEDIUM watch item. A lookalike whose registro.br registrant CNPJ root is the
  institution's, the verified domain's registrant or a conglomerate member's is a defensive
  registration and is suppressed; own assets and verified domains themselves are never flagged.
  Wording stays 'lookalike / phishing-capable indicator', never 'malicious' (P028 cond 9 spirit).

The protected-brand facts come from the graph when ``bcb_authorized_institutions`` ran on the imitated
domain, else from the local DominiosVerificados copy (read-only, never downloaded); without them the
rule stays silent rather than risk flagging a defensive registration as HIGH.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, Finding, ModuleResult, Severity
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as bcb

MODULE = "bcb_authorized_institutions"
RULE_FLAGGED = "bcb_verified_domain_flagged"
RULE_LOOKALIKE = "bcb_lookalike_activity"
#: finding tags of a listing or verdict by another source (FC5)
FLAG_TAGS = frozenset({
    "malicious", "phishing", "malware", "c2", "suspicious", "compromised", "botnet", "spam", "blocklisted", "phishing_kit_exfil",
    "crypto_scam", "fraud",
})
#: context markers: never a 'possible compromise' signal by themselves
CONTEXT_TAGS = frozenset({"context_only", "false_positive", "warninglist", "ads_tracking"})
FRESH_CERT_DAYS = 30
_NOISE_KINDS = frozenset({"parked", "sinkhole"})


def _listings(findings: Iterable[Finding]) -> list[Finding]:
    out = []
    for f in findings:
        tags = set(f.tags or ())
        if f.module != MODULE and f.severity >= Severity.LOW and tags & FLAG_TAGS and not tags & CONTEXT_TAGS:
            out.append(f)
    return out


def _verified(node: Node) -> dict[str, Any] | None:
    for value in node.attr_values("bcb_verified_domain"):
        if isinstance(value, Mapping) and value.get("domain"):
            return dict(value)
    return None


@rule(
    RULE_FLAGGED,
    "Verified institution domain flagged by another source",
    "A BCB-verified financial-institution domain (or a URL on it) that another source lists as malicious, phishing, malware or "
    "suspicious: a possible compromise of the institution's domain (a hacked page, an abused open redirect) or a false positive "
    "of the listing. known_good never suppresses the listing (P360 FC5).",
    version="1",
    severity="medium",
    criterion="attribute bcb_verified_domain (BCB DominiosVerificados match) and a finding of severity >= low from another module "
    "tagged as a listing (malicious, phishing, malware, c2, suspicious, compromised...)",
    false_positives="Stale or over-broad blocklist entries for big bank domains; URL-level listings of a page the institution already removed.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_FLAGGED}/positive_phishing_url_on_verified_domain.json",
        f"tests/fixtures/rules/{RULE_FLAGGED}/negative_info_only.json",
    ),
)
def verified_domain_flagged(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        if node.entity.type not in (EntityType.DOMAIN, EntityType.URL):
            continue
        verified = _verified(node)
        if verified is None:
            continue
        listings = _listings(node.findings)
        if node.entity.type is EntityType.DOMAIN:  # URL-level hits on the same host stay URL-level, but they surface here too
            for edge in graph.out_edges(node.key, "hosts_url"):
                target = graph.get(edge.dst)
                if target is not None:
                    listings.extend(_listings(target.findings))
        if not listings:
            continue
        modules = sorted({f.module or "?" for f in listings})
        worst = max(f.severity for f in listings)
        institutions = verified.get("institutions") or []
        lead = institutions[0] if institutions and isinstance(institutions[0], Mapping) else {}
        yield Correlation(
            rule=RULE_FLAGGED,
            title=bcb.TITLE_COMPROMISE,
            severity=Severity.MEDIUM,
            description=(
                f"{node.entity.display} is on the BCB-verified domain {verified.get('domain')} of {lead.get('legal_name') or 'an authorised institution'} "
                f"(CNPJ root {lead.get('cnpj_root') or '?'}), yet {', '.join(modules)} flag it (highest listing severity: {worst.label}). "
                "known_good annotates only: every listing keeps its severity. Review the flagged URL(s): a compromised page or an abused "
                "redirect on an institution's domain, or a false positive of the listing."
            ),
            entities=[node.entity],
            confidence="possible",
            evidence=[f.id for f in listings if f.id],
            recommendation="Review the exact URL(s) listed on the verified domain; notify the institution through its official channel if confirmed.",
            tags=["conflict", "verified_fi"],
            criterion="BCB-verified domain (DominiosVerificados) plus a listing by another source on the same host or URL",
        )


# ---- FC8 ------------------------------------------------------------------------------


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}", text):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00")) if len(text) > 10 else datetime.fromisoformat(text[:10])
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _brand_from_graph(graph: Graph, protected: str) -> dict[str, Any] | None:
    """Protected-brand facts from the imitated domain's node when bcb_authorized_institutions ran on it."""
    node = graph.get(f"domain:{protected}")
    verified = _verified(node) if node is not None else None
    if not verified:
        return None
    institutions = [i for i in verified.get("institutions") or [] if isinstance(i, Mapping)]
    return {
        "registrable_domain": verified.get("registrable_domain") or verified.get("domain"),
        "verified_domains": [verified.get("domain")],
        "institution_cnpj_roots": sorted({str(i.get("cnpj_root")) for i in institutions if i.get("cnpj_root")}),
        "registrant_cnpj_roots": sorted({str(r) for r in verified.get("registrant_cnpj_roots") or []}),
        "conglomerate_member_roots": sorted({str(r) for r in verified.get("conglomerate_member_roots") or []}),
        "names": sorted({str(i.get("legal_name")) for i in institutions if i.get("legal_name")}),
    }


def _ips_noise(graph: Graph, values: Iterable[Any]) -> bool:
    """True when every resolved address is a parked or sinkhole address of the graph."""
    seen = False
    for value in values:
        seen = True
        ip = str(value)
        node = graph.get(f"{'ipv6' if ':' in ip else 'ipv4'}:{ip}")
        if node is None or (node.noise_kind not in _NOISE_KINDS and not node.tagged("parked", "sinkhole")):
            return False
    return seen


def _signals(graph: Graph, node: Node, now: datetime) -> dict[str, Any]:
    a = node.attr_values("a_records") + node.attr_values("aaaa_records")
    mx = [m for m in node.attr_values("mx") if str(m).strip(". ")]
    ns = node.attr_values("nameservers")
    registered_flags = [v for v in node.attr_values("registered") if isinstance(v, bool)]
    created = next((d for d in (_parse_date(v) for v in node.attr_values("created")) if d), None)
    first_cert = next((d for d in (_parse_date(v) for v in node.attr_values("first_cert_seen")) if d), None)
    parked = node.tagged("parked", "sinkhole") or node.noise_kind in _NOISE_KINDS or (bool(a) and _ips_noise(graph, a))
    if registered_flags:
        registered = any(registered_flags)
    else:
        registered = bool(a or mx or ns or created)
    fresh = first_cert is not None and 0 <= (now - first_cert).days <= FRESH_CERT_DAYS
    roots = [str(r) for r in node.attr_values("cnpj_roots") if re.fullmatch(r"[0-9A-Z]{8}", str(r))]
    return {"registered": registered, "resolves": bool(a), "parked": parked, "mx": bool(mx), "fresh_cert": fresh,
            "created": created.date().isoformat() if created else "", "first_cert": first_cert.date().isoformat() if first_cert else "",
            "registrant_roots": roots}


@rule(
    RULE_LOOKALIKE,
    "Lookalike of a BCB-verified institution domain",
    "A typosquat reverse match of a BCB-verified financial-institution domain: HIGH when registered and active (resolves, MX or a fresh "
    "first certificate), otherwise a MEDIUM watch item; defensive registrations by the institution or its conglomerate are suppressed "
    "(P360 FC8).",
    version="1",
    severity="high",
    criterion="attribute lookalike_matches with source 'bcb' plus registration/activity facts (RDAP, DNS, CT) and the registrant CNPJ "
    "root compared with the institution's, its domain registrant's and its conglomerate members'",
    attack=("T1583.001",),
    false_positives="A conglomerate member registered under a CNPJ root that the BCB list does not show; a legitimate partner or "
    "fintech whose name resembles a bank brand.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_LOOKALIKE}/positive_active_lookalike.json",
        f"tests/fixtures/rules/{RULE_LOOKALIKE}/positive_registered_inactive_watch.json",
        f"tests/fixtures/rules/{RULE_LOOKALIKE}/negative_defensive_registration.json",
        f"tests/fixtures/rules/{RULE_LOOKALIKE}/negative_org_profile_lookalike.json",
    ),
)
def lookalike_activity(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = getattr(rctx, "now", None) or datetime.now(timezone.utc)
    index: bcb.BcbIndex | None = None
    for node in graph.nodes.values():
        if node.entity.type is not EntityType.DOMAIN or node.noise:
            continue
        if node.ownership == "own_asset" or node.tagged("verified_fi", "own_asset") or _verified(node) is not None:
            continue  # own assets and verified domains are never their own lookalikes
        matches = [m for m in node.attr_values("lookalike_matches") if isinstance(m, Mapping) and m.get("source") == "bcb" and m.get("protected")]
        if not matches:
            continue
        protected = str(matches[0]["protected"]).lower()
        brand = _brand_from_graph(graph, protected)
        if brand is None:
            if index is None:
                index = bcb.local_index(sedes=False)
            brand = bcb.protected_brand_for(protected, index) if index.dominios else None
        if brand is None:
            continue  # cannot rule out a defensive registration: stay silent (the typosquat INFO finding stands)
        sig = _signals(graph, node, now)
        verdicts = [bcb.classify_lookalike(brand, registered=sig["registered"], resolves=sig["resolves"], mx=sig["mx"], fresh_cert=sig["fresh_cert"],
                                           parked=sig["parked"], registrant_cnpj=root) for root in sig["registrant_roots"] or [None]]
        if any(v and v["severity"] == "suppressed" for v in verdicts):
            continue
        verdict = next((v for v in verdicts if v), None)
        if verdict is None:
            continue
        names = ", ".join(brand.get("names") or []) or "an authorised institution"
        chain = (f"registered{' ' + sig['created'] if sig['created'] else ''}, resolves {'yes (parked)' if sig['resolves'] and sig['parked'] else 'yes' if sig['resolves'] else 'no'}, "
                 f"MX {'yes' if sig['mx'] else 'no'}, first certificate {sig['first_cert'] or 'unknown'}")
        high = verdict["severity"] == "high"
        yield Correlation(
            rule=RULE_LOOKALIKE,
            title="Active lookalike of a BCB-verified institution domain" if high else "Registered lookalike of a BCB-verified institution domain (watch item)",
            severity=Severity.HIGH if high else Severity.MEDIUM,
            description=(
                f"{node.entity.display} imitates {protected} ({names}): {chain}. "
                + ("A phishing-capable lookalike indicator: registered and active." if high else "Registered but no activity seen: keep it on watch.")
                + " Not a verdict of maliciousness; the registrant is not judged."
            ),
            entities=[node.entity],
            confidence="probable" if high else "possible",
            evidence=[f.id for f in node.findings if f.id and "typosquat" in (f.tags or ())],
            recommendation=("Block or monitor the lookalike, and report it to the institution through its official channel."
                            if high else "Watch the name for MX, A records or a first certificate (v3lum watch); no action on registration alone."),
            tags=["typosquat", "verified_fi"],
            criterion=verdict["reason"],
            attack=["T1583.001"],
        )
