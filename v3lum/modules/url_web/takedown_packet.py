"""takedown_packet: takedown / abuse packet for hostile URLs and hosts (P345, batch p2-G03-1).

A report exporter over the case graph, not a source module (architect floor, cond 1): it reads the
registrar and abuse contacts that rdap (P003), ripestat (P031) and abusix_contacts (P041) already put in
the case, plus the IANA registrar-ID registry (weekly dataset ``iana.registrar_ids``, read from the local
copy only). No network at report time and no HTTP client here. Entry points:

* :func:`build_takedown_packet` (a stored case dict, schema ``v3lum.case/2``) and
  :func:`packet_from_graph` (a live Graph + results) -> the packet dict;
* :func:`render_packet_markdown` -> the text the analyst copies (the ``-f takedown`` report format and the
  ``v3lum takedown <case>`` command are core wiring: see the batch backlog);
* the correlation rule ``g03_takedown_packet_ready`` (v3lum/correlations/p2_g03_1.py) announces a packet
  automatically when the gate below passes.

Final conditions implemented (P345):

* c2 - :func:`takedown_gate`: automatic only with a hostile finding >= HIGH backed by consensus (>= 2
  independent upstream families, P171) or an analyst confirmation (override verdict); never from a
  single-source hit. Otherwise only on request (``requested=True``).
* c3 - :func:`rank_contacts`: registrar abuse (RDAP, IANA registrar id) > hosting abuse-c (RIR) > Abusix >
  CDN abuse portal (with origin hints when a CDN fronts the site), each with its reason, source and
  retrieval date; a compromised legitimate site adds the security.txt owner contact when the case has
  one. Person contacts are never included.
* c4 - .br domains and BR-hosted IPs add the CERT.br guidance (notify the source network, cert@cert.br in
  Cc); manual report links: Google Safe Browsing report_phish, Netcraft and the platforms abused in BR
  scams (WhatsApp, Instagram/Meta, Telegram, Google Forms/Sites) when the case holds such entities.
* c5 - V3LUM never sends e-mails or submits forms: the packet says that submitting shares the URL with the
  provider and that the analyst records the disclosure decision in the case audit.
* c6 - minimisation: only the hostile URL/host, timestamps, evidence SHA-256 hashes and screenshots;
  victims' e-mails, tokens and other personal data are redacted (phishstats' shared URL redaction),
  internal notes are dropped; the packet carries the case TLP.
* c7 - every evidence item lists its SHA-256 with UTC and America/Sao_Paulo timestamps; ready-to-copy
  templates in pt-BR and English cite the hashes.
"""

from __future__ import annotations

import csv
import io
import json
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.core import psl
from v3lum.core.datasets import register_dataset
from v3lum.modules.url_web.google_safe_browsing import minimise_lookup_url, parse_iso
from v3lum.modules.url_web.phishstats import EMAIL_RE, defang_url, redact_victim_url

REGISTRAR_DATASET = "iana.registrar_ids"
REGISTRAR_URL = "https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv"
REGISTRAR_SOURCE = "iana.takedown_packet_registrar_ids"
CONTACT_AUTHORITY = {"registrar_abuse": 1, "rir_abuse_c": 2, "abusix": 3, "cdn_portal": 4, "security_txt": 5}
CONTACT_REASON = {
    "registrar_abuse": "registrar abuse contact (RDAP of the sponsoring registrar, IANA registrar id)",
    "rir_abuse_c": "hosting network abuse-c from the authoritative RIR",
    "abusix": "Abusix Abuse Contact DB (DNS)",
    "cdn_portal": "CDN abuse portal (the CDN fronts the site; origin hints attached)",
    "security_txt": "site owner contact from security.txt (compromised legitimate site)",
}
#: finding tags that make an entity hostile for the takedown gate (the P376 guard's hostile set + malware)
HOSTILE_TAGS = frozenset({"phishing", "malicious", "malware", "c2", "crypto_scam", "fraud", "phishing_kit_exfil"})
CONFIRMED_VERDICTS = frozenset({"true_positive", "confirmed", "malicious", "phishing", "positive", "c2", "fraud"})
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TARGET_TYPES = ("url", "domain", "ipv4", "ipv6")
GSB_REPORT_URL = "https://safebrowsing.google.com/safebrowsing/report_phish/"
NETCRAFT_REPORT_URL = "https://report.netcraft.com/report"
CERT_BR_CC = "cert@cert.br"
CERT_BR_GUIDE = "https://cert.br/docs/whitepapers/notificacoes/"
#: verified 2026-11-26 (HTTP 200, or the provider's anti-bot wall for abuse.cloudflare.com from a datacenter)
PLATFORM_REPORTS = {
    "whatsapp": {"name": "WhatsApp: report the number (in-app) - help page", "url": "https://faq.whatsapp.com/1142481766359885"},
    "instagram_meta": {"name": "Instagram / Meta: report the profile or post (in-app) - help centre", "url": "https://help.instagram.com/"},
    "telegram": {"name": "Telegram: illegal content takedown (abuse@telegram.org)", "url": "https://telegram.org/faq#q-there-39s-illegal-content-on-telegram-how-do-i-take-it-down"},
    "google_forms": {"name": "Google Forms: report a violation", "url": "https://support.google.com/docs/answer/2463296"},
    "google_sites": {"name": "Google Sites: 'Report abuse' link in the site footer, or Safe Browsing report_phish", "url": GSB_REPORT_URL},
}
PLATFORM_HOSTS = {
    "whatsapp": ("wa.me", "whatsapp.com", "chat.whatsapp.com", "api.whatsapp.com"),
    "instagram_meta": ("instagram.com", "facebook.com", "fb.com", "fb.me", "m.me", "threads.net"),
    "telegram": ("t.me", "telegram.me", "telegram.org", "telegram.dog"),
    "google_forms": ("forms.gle",),
    "google_sites": ("sites.google.com",),
}
PLATFORM_ENTITY_TYPES = {"telegram_handle": "telegram", "telegram_invite": "telegram"}
#: CDN abuse portals by ASN (origin hints: the hosting abuse-c of a non-CDN address of the same host)
CDN_PORTALS = {
    13335: ("Cloudflare", "https://abuse.cloudflare.com/"),
    16509: ("Amazon CloudFront / AWS", "https://support.aws.amazon.com/#/contacts/report-abuse"),
    14618: ("Amazon CloudFront / AWS", "https://support.aws.amazon.com/#/contacts/report-abuse"),
    15169: ("Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"),
    396982: ("Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"),
}
DISCLOSURE_NOTE = ("V3LUM never sends e-mails or submits forms. Submitting a report shares the URL with the provider (and its partners): "
                   "the analyst decides per case and records the disclosure decision in the case audit.")


# ============================================================================================ IANA registrar ids
def parse_iana_registrar_csv(raw: Any) -> dict[str, Any]:
    """c1: IANA registrar-ids CSV ('ID',Registrar Name,Status,RDAP Base URL) -> {"registrars": {id: {name, status, rdap}}, "error"}."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    if text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return {"registrars": {}, "error": "html instead of csv"}
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or [c.strip().strip('"').lower() for c in rows[0][:2]] != ["id", "registrar name"]:
        return {"registrars": {}, "error": "unexpected header"}
    regs: dict[str, dict[str, Any]] = {}
    for r in rows[1:]:
        if len(r) < 3 or not r[0].strip().isdigit():
            continue
        rdap = r[3].strip() if len(r) > 3 and r[3].strip().startswith("https://") else None
        regs[r[0].strip()] = {"name": r[1].strip()[:200], "status": r[2].strip()[:40], "rdap": rdap}
    return {"registrars": regs, "error": None if regs else "no rows"}


def _validate_registrars(path: Path) -> bool:
    try:
        out = parse_iana_registrar_csv(Path(path).read_bytes())
    except OSError:
        return False
    return out["error"] is None and len(out["registrars"]) >= 1000


register_dataset(
    REGISTRAR_DATASET,
    REGISTRAR_URL,
    ttl=7 * 86400,
    description="IANA Registrar IDs registry (id -> registrar name, status, RDAP base URL) for takedown packets (P345)",
    licence="IANA registry (public data)",
    terms_class="open",
    attribution="IANA Registrar IDs registry, https://www.iana.org/assignments/registrar-ids/",
    provider="iana",
    source=REGISTRAR_SOURCE,
    validate=_validate_registrars,
    min_bytes=50_000,
    expect="csv",
    max_bytes=5 * 1024 * 1024,
    large=False,
)

_REG_LOCK = threading.Lock()
_REG_MEMO: dict[str, Any] = {"stamp": None, "regs": {}}


def local_registrars() -> dict[str, dict[str, Any]]:
    """The local copy of the IANA registrar registry ({} when absent). Never downloads (c1: no network at report time)."""
    try:
        from v3lum import paths

        path = paths.datasets_dir() / REGISTRAR_DATASET
        if not path.is_file():
            return {}
        st = path.stat()
        stamp = (st.st_mtime_ns, st.st_size)
        with _REG_LOCK:
            if _REG_MEMO["stamp"] != stamp:
                _REG_MEMO["regs"] = parse_iana_registrar_csv(path.read_bytes())["registrars"]
                _REG_MEMO["stamp"] = stamp
            return dict(_REG_MEMO["regs"])
    except Exception:  # noqa: BLE001 - the registry only enriches the registrar contact
        return {}


# ============================================================================================ case view
@dataclass
class _Node:
    key: str
    type: str
    value: str
    attributes: dict[str, list[tuple[Any, str]]] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    noise_kind: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    def values(self, name: str) -> list[Any]:
        out: list[Any] = []
        for value, _src in self.attributes.get(name, []):
            for item in value if isinstance(value, list) else [value]:
                if item not in out:
                    out.append(item)
        return out

    def first(self, name: str) -> Any:
        vals = self.values(name)
        return vals[0] if vals else None


@dataclass
class CaseView:
    """What the packet needs from a case: nodes, edges, results' evidence, TLP and times."""

    nodes: dict[str, _Node] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    case_id: str = ""
    tlp: str = "amber"
    created: str = ""

    def out(self, key: str, relation: str | None = None) -> list[_Node]:
        return [self.nodes[d] for s, d, r in self.edges if s == key and (relation is None or r == relation) and d in self.nodes]

    def into(self, key: str, relation: str | None = None) -> list[_Node]:
        return [self.nodes[s] for s, d, r in self.edges if d == key and (relation is None or r == relation) and s in self.nodes]


def view_from_case(case: dict[str, Any]) -> CaseView:
    """A stored case dict (``v3lum.case/2``) -> CaseView."""
    view = CaseView(case_id=str(case.get("case_id") or ""), tlp=str(case.get("tlp") or "amber"), created=str(case.get("created") or ""))
    for ent in case.get("entities") or []:
        if not isinstance(ent, dict) or not ent.get("key"):
            continue
        attrs = {k: [(v.get("value"), str(v.get("source") or "")) for v in vals if isinstance(v, dict)]
                 for k, vals in (ent.get("attributes") or {}).items() if isinstance(vals, list)}
        view.nodes[ent["key"]] = _Node(ent["key"], str(ent.get("type") or ent["key"].split(":", 1)[0]), str(ent.get("value") or ent["key"].split(":", 1)[-1]),
                                       attrs, set(ent.get("tags") or []), str(ent.get("noise_kind") or ""))
    for f in case.get("findings") or []:
        if isinstance(f, dict) and f.get("entity") in view.nodes:
            view.nodes[f["entity"]].findings.append(f)
    view.edges = [(str(e.get("src")), str(e.get("dst")), str(e.get("relation"))) for e in case.get("edges") or [] if isinstance(e, dict)]
    for r in case.get("modules") or []:
        if isinstance(r, dict) and r.get("evidence_sha256"):
            view.evidence.append({"entity": r.get("entity"), "kind": r.get("module"), "sha256": r.get("evidence_sha256"), "path": r.get("evidence"),
                                  "captured_at": None})
    return view


def view_from_graph(graph: Any, results: Any = (), *, now: Any = None, tlp: str = "amber", case_id: str = "") -> CaseView:
    """A live Graph (+ ModuleResults) -> CaseView (for the correlation rule)."""
    created = (now.isoformat() if isinstance(now, datetime) else str(now or ""))
    view = CaseView(case_id=case_id, tlp=tlp, created=created)
    for key, node in getattr(graph, "nodes", {}).items():
        ent = node.entity
        findings = []
        for f in node.findings:
            d = f.to_dict()
            d["entity"] = key
            findings.append(d)
        view.nodes[key] = _Node(key, ent.type.value, str(ent.value), dict(node.attributes), set(node.tags), node.noise_kind or "", findings)
    view.edges = [(e.src, e.dst, e.relation) for e in getattr(graph, "edges", [])]
    for r in results or ():
        if getattr(r, "evidence_sha256", ""):
            view.evidence.append({"entity": r.entity.key, "kind": r.module, "sha256": r.evidence_sha256, "path": r.evidence, "captured_at": None})
    return view


# ============================================================================================ gate (c2)
def finding_family(f: dict[str, Any]) -> str:
    """The upstream family of a finding: its registry source's upstream_family, else the module's."""
    source = str(f.get("source") or "")
    if source:
        try:
            from v3lum.core import providers

            src = providers.registry().source(source)
            if src is not None and getattr(src, "upstream_family", ""):
                return str(src.upstream_family)
        except Exception:  # noqa: BLE001
            pass
    module = str(f.get("module") or "")
    try:
        from v3lum.core.module import REGISTRY

        fams = sorted(getattr(REGISTRY.get(module), "upstream_families", ()) or ())
        if fams:
            return fams[0]
    except Exception:  # noqa: BLE001
        pass
    return module or source or "unknown"


def _verdict(f: dict[str, Any]) -> str:
    ov = f.get("override") if isinstance(f.get("override"), dict) else {}
    return str(ov.get("verdict") or "").strip().lower()


def evidence_hostile(f: dict[str, Any]) -> bool:
    """A finding that can back a takedown: hostile tag, not context-only, not downgraded by a SUP-* rule,
    not marked false positive by the analyst."""
    tags = set(f.get("tags") or [])
    if not (tags & HOSTILE_TAGS) or "context_only" in tags:
        return False
    if _verdict(f) in FALSE_POSITIVE_VERDICTS:
        return False
    suppressed = any(str(s.get("rule", "")).startswith("SUP-") for s in f.get("suppressed_by") or [] if isinstance(s, dict))
    return not suppressed or bool(_verdict(f))


def takedown_gate(findings: list[dict[str, Any]], *, requested: bool = False) -> dict[str, Any]:
    """c2: automatic generation only with a hostile finding >= HIGH backed by consensus (>= 2 independent
    upstream families, P171) or an analyst confirmation; never from a single-source hit; otherwise only on
    request. Returns ``{"generate", "automatic", "reason", "families"}``."""
    hostile = [f for f in findings or () if isinstance(f, dict) and evidence_hostile(f)]
    high = [f for f in hostile if SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0) >= SEVERITY_RANK["high"]]
    families = sorted({finding_family(f) for f in high})
    confirmed = any(_verdict(f) in CONFIRMED_VERDICTS for f in high)
    if high and (len(families) >= 2 or confirmed):
        why = f"consensus of {len(families)} independent families ({', '.join(families)})" if len(families) >= 2 else "analyst confirmation"
        return {"generate": True, "automatic": True, "reason": why, "families": families}
    why = (f"single-source hit ({', '.join(families)}): not generated automatically" if high
           else "no hostile finding >= HIGH: not generated automatically")
    if requested:
        return {"generate": True, "automatic": False, "reason": f"on analyst request ({why})", "families": families}
    return {"generate": False, "automatic": False, "reason": why, "families": families}


# ============================================================================================ contacts (c3)
def rank_contacts(contacts: list[dict[str, Any]], compromised_legit_site: bool = False) -> list[dict[str, Any]]:
    """c3: rank by authority (registrar abuse > RIR abuse-c > Abusix > CDN portal; security.txt only for a
    compromised legitimate site) with reason, sources and retrieval date; duplicates merged keeping the most
    authoritative entry; invalid addresses dropped."""
    ranked: list[dict[str, Any]] = []
    by_addr: dict[str, dict[str, Any]] = {}
    for c in contacts or ():
        if not isinstance(c, dict) or c.get("kind") not in CONTACT_AUTHORITY:
            continue
        kind = c["kind"]
        if kind == "security_txt" and not compromised_legit_site:
            continue
        email = c.get("email") if isinstance(c.get("email"), str) and EMAIL_RE.fullmatch(c["email"]) else None
        url = c.get("url") if isinstance(c.get("url"), str) and c["url"].startswith("https://") else None
        if not (email or url):
            continue
        addr = (email or url or "").lower()
        entry = {"rank": CONTACT_AUTHORITY[kind], "kind": kind, "email": email, "url": url, "phone": c.get("phone"), "reason": CONTACT_REASON[kind],
                 "sources": [s for s in [c.get("source")] if s], "retrieved_at": c.get("retrieved_at"), "entity": c.get("entity")}
        for extra in ("registrar", "iana_id", "registrar_rdap", "rir", "cdn", "origin_hints"):
            if c.get(extra):
                entry[extra] = c[extra]
        prev = by_addr.get(addr)
        if prev is not None:
            if entry["rank"] < prev["rank"]:
                entry["sources"] = entry["sources"] + [s for s in prev["sources"] if s not in entry["sources"]]
                ranked[ranked.index(prev)] = entry
                by_addr[addr] = entry
            else:
                prev["sources"] += [s for s in entry["sources"] if s not in prev["sources"]]
            continue
        by_addr[addr] = entry
        ranked.append(entry)
    ranked.sort(key=lambda e: (e["rank"], e.get("email") or e.get("url") or ""))
    for i, e in enumerate(ranked, 1):
        e["order"] = i
    return ranked


def _host_of(node: _Node) -> str | None:
    if node.type == "url":
        try:
            return (urllib.parse.urlsplit(node.value).hostname or "").lower() or None
        except ValueError:
            return None
    return node.value.lower() if node.type in TARGET_TYPES else None


def _asn(value: Any) -> int | None:
    m = re.fullmatch(r"(?i)\s*(?:AS)?(\d{1,10})\s*", str(value)) if value is not None else None
    return int(m.group(1)) if m else None


def collect_contacts(view: CaseView, target: _Node, registrars: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """c3: contacts already in the case for the target: registrar abuse from the host's (and its registrable
    domain's) RDAP facts, abuse-c / Abusix records of the addresses it resolves to, a CDN portal when an
    address is a CDN edge (with the other addresses as origin hints), security.txt owner contacts."""
    host = _host_of(target)
    reg_domain = psl.registrable_domain(host) if host and target.type != "ipv4" and target.type != "ipv6" else None
    domain_nodes = [view.nodes[k] for k in dict.fromkeys(f"domain:{d}" for d in (host, reg_domain) if d) if k in view.nodes]
    ip_nodes: list[_Node] = [target] if target.type in ("ipv4", "ipv6") else []
    for dn in domain_nodes + ([target] if target.type == "url" else []):
        ip_nodes += [n for n in view.out(dn.key, "resolves_to") if n.type in ("ipv4", "ipv6") and n not in ip_nodes]
    contacts: list[dict[str, Any]] = []
    for dn in domain_nodes:
        email = next((v for v, s in dn.attributes.get("abuse_contact", []) if isinstance(v, str)), None)
        iana = dn.first("registrar_iana_id")
        reg = (registrars or {}).get(str(iana)) if iana is not None else None
        rdap = str((reg or {}).get("rdap") or "")
        contacts.append({"kind": "registrar_abuse", "email": email, "phone": dn.first("abuse_phone"), "registrar": dn.first("registrar"),
                         "iana_id": str(iana) if iana is not None else None, "registrar_rdap": rdap or None,
                         "source": "rdap", "retrieved_at": dn.first("rdap_retrieved_at") or view.created or None, "entity": dn.key,
                         "url": None if email else (rdap if rdap.startswith("https://") else None)})
        for sec in dn.values("security_txt_contacts"):
            if isinstance(sec, str):
                contacts.append({"kind": "security_txt", "email": sec if EMAIL_RE.fullmatch(sec) else None,
                                 "url": sec if sec.startswith("https://") else None, "source": "security_txt", "entity": dn.key})
    cdn_nodes = []
    for ip in ip_nodes:
        for rec in ip.values("abuse_contacts"):
            if not isinstance(rec, dict):
                continue
            kind = {"hosting_abuse_c": "rir_abuse_c", "abusix_contact": "abusix"}.get(str(rec.get("kind")))
            if kind:
                contacts.append({"kind": kind, "email": rec.get("email"), "source": rec.get("source"), "retrieved_at": rec.get("retrieved_at"),
                                 "rir": rec.get("authority"), "entity": ip.key})
        if ip.noise_kind == "cdn" or "cdn" in ip.tags:
            cdn_nodes.append(ip)
    origin_hints = [ip.value for ip in ip_nodes if ip not in cdn_nodes][:5]
    for ip in cdn_nodes:
        asn = next((_asn(v) for v in ip.values("asn") if _asn(v) is not None), None)
        name, portal = CDN_PORTALS.get(asn or -1, (None, None))
        if portal:
            contacts.append({"kind": "cdn_portal", "url": portal, "cdn": name, "origin_hints": origin_hints, "source": "case graph (CDN edge address)",
                             "entity": ip.key})
    compromised = any(t in ("compromised", "abused_legit_service") for n in [target, *domain_nodes] for t in n.tags) or any(
        "compromised" in (f.get("tags") or []) for n in [target, *domain_nodes] for f in n.findings)
    countries = {str(v).upper() for ip in ip_nodes for k in ("country", "as_country", "registration_country") for v in ip.values(k) if isinstance(v, str)}
    return {"contacts": rank_contacts(contacts, compromised), "compromised": compromised, "countries": sorted(countries),
            "host": host, "addresses": [ip.value for ip in ip_nodes], "cdn": bool(cdn_nodes)}


# ============================================================================================ BR guidance, links (c4)
def _under(host: str | None, suffix: str) -> bool:
    return bool(host) and (host == suffix or host.endswith("." + suffix))  # type: ignore[union-attr]


def platforms_in_case(view: CaseView) -> list[str]:
    """c4: abused platforms (WhatsApp, Instagram/Meta, Telegram, Google Forms/Sites) present in the case."""
    found: list[str] = []
    for node in view.nodes.values():
        plat = PLATFORM_ENTITY_TYPES.get(node.type)
        if not plat and node.type in ("url", "domain"):
            try:
                parts = urllib.parse.urlsplit(node.value if node.type == "url" else "https://" + node.value)
            except ValueError:
                continue
            host = (parts.hostname or "").lower()
            if host == "docs.google.com" and parts.path.startswith("/forms"):
                plat = "google_forms"
            else:
                plat = next((name for name, hosts in PLATFORM_HOSTS.items() if any(_under(host, h) for h in hosts)), None)
        if plat and plat not in found:
            found.append(plat)
    return found


def manual_report_links(report_url: str | None, platforms: list[str]) -> list[dict[str, Any]]:
    """c4/c5: manual links only, never submitted by V3LUM."""
    links = []
    if report_url:
        links.append({"name": "Google Safe Browsing report_phish", "url": GSB_REPORT_URL + "?" + urllib.parse.urlencode({"url": report_url})})
    links.append({"name": "Netcraft report", "url": NETCRAFT_REPORT_URL})
    for p in platforms:
        if p in PLATFORM_REPORTS:
            links.append(dict(PLATFORM_REPORTS[p], platform=p))
    return links


def dual_timestamps(value: Any) -> dict[str, str | None]:
    """c7: one instant in UTC and in America/Sao_Paulo (zoneinfo; fixed -03:00 fallback, no DST since 2019)."""
    dt = parse_iso(value) if not isinstance(value, datetime) else (value if value.tzinfo else value.replace(tzinfo=timezone.utc))
    if not dt:
        return {"utc": None, "sao_paulo": None}
    try:
        from zoneinfo import ZoneInfo

        sp = dt.astimezone(ZoneInfo("America/Sao_Paulo"))
    except Exception:  # noqa: BLE001 - zoneinfo/tzdata missing
        sp = dt.astimezone(timezone(timedelta(hours=-3)))
    return {"utc": dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "sao_paulo": sp.isoformat(timespec="seconds")}


def _evidence_time(item: dict[str, Any], fallback: str) -> str:
    path = item.get("path")
    if isinstance(path, str) and path.endswith(".json"):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("collected_at"), str):
                return data["collected_at"]
        except (OSError, ValueError):
            pass
    return str(item.get("captured_at") or fallback)


# ============================================================================================ packet
def hostile_targets(view: CaseView) -> list[tuple[_Node, list[dict[str, Any]]]]:
    """Entities (url, domain, ip) carrying hostile findings, most specific first (URLs before hosts)."""
    out = []
    for node in view.nodes.values():
        if node.type in TARGET_TYPES:
            hostile = [f for f in node.findings if evidence_hostile(f)]
            if hostile:
                out.append((node, hostile))
    out.sort(key=lambda t: (TARGET_TYPES.index(t[0].type), t[0].key))
    return out


def _related_findings(view: CaseView, target: _Node) -> list[dict[str, Any]]:
    """Findings that speak about the target: its own, plus those of the URLs it hosts (URL-level verdicts
    of the same host count for a host target, never the reverse)."""
    findings = list(target.findings)
    if target.type == "domain":
        for node in view.nodes.values():
            if node.type == "url" and _host_of(node) == target.value.lower():
                findings += node.findings
    return findings


def build_packet(view: CaseView, *, requested: bool = False, now: Any = None, registrars: dict[str, dict[str, Any]] | None = None,
                 target_key: str | None = None) -> dict[str, Any]:
    """c1-c8 over a CaseView: the packet for the target (``target_key`` or the first hostile entity)."""
    targets = hostile_targets(view)
    target = view.nodes.get(target_key) if target_key else (targets[0][0] if targets else None)
    if target is None:
        gate = takedown_gate([], requested=requested)
        return {"generated": False, "gate": dict(gate, reason="no hostile URL, domain or IP in the case"), "case_id": view.case_id,
                "tlp": "TLP:" + view.tlp.upper()}
    gate = takedown_gate(_related_findings(view, target), requested=requested)
    if not gate["generate"]:
        return {"generated": False, "gate": gate, "case_id": view.case_id, "tlp": "TLP:" + view.tlp.upper(), "target": target.key}
    raw_url = target.value if target.type == "url" else None
    red_url, kinds = redact_victim_url(raw_url) if raw_url else (None, [])
    report_url = minimise_lookup_url(raw_url)["url"] if raw_url else None
    info = collect_contacts(view, target, registrars if registrars is not None else local_registrars())
    host = info["host"]
    br = bool(host and _under(host, "br")) or "BR" in info["countries"]
    created = dual_timestamps(now or datetime.now(timezone.utc))
    keys = {target.key, *(f"domain:{d}" for d in (host, psl.registrable_domain(host) if host else None) if d)}
    evidence, rejected = [], 0
    for item in view.evidence:
        if item.get("entity") not in keys:
            continue
        sha = str(item.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            rejected += 1
            continue
        ts = dual_timestamps(_evidence_time(item, view.created))
        evidence.append({"kind": str(item.get("kind") or "evidence"), "sha256": sha, "captured_at_utc": ts["utc"], "captured_at_sao_paulo": ts["sao_paulo"]})
    packet = {
        "generated": True, "gate": gate, "case_id": view.case_id, "tlp": "TLP:" + view.tlp.upper(),
        "created_utc": created["utc"], "created_sao_paulo": created["sao_paulo"],
        "target": {"entity": target.type, "url": red_url, "url_defanged": defang_url(red_url) if red_url else None, "host": host,
                   "host_defanged": host.replace(".", "[.]") if host else None, "report_url": report_url, "redacted_parts": kinds,
                   "addresses": info["addresses"][:10], "behind_cdn": info["cdn"], "compromised_legit_site": info["compromised"]},
        "contacts": info["contacts"],
        "cert_br": ({"cc": CERT_BR_CC, "guide": CERT_BR_GUIDE,
                     "guidance_pt": "Notifique os contatos de abuso da rede de origem e coloque cert@cert.br em Cc.",
                     "guidance_en": "Notify the abuse contacts of the source network with cert@cert.br in Cc."} if br else None),
        "manual_links": manual_report_links(report_url, platforms_in_case(view)),
        "evidence": evidence,
        "evidence_rejected": rejected,
        "disclosure_note": DISCLOSURE_NOTE,
    }
    packet["templates"] = takedown_templates(packet)
    return packet


def build_takedown_packet(case: dict[str, Any], *, requested: bool = False, now: Any = None, registrars: dict[str, dict[str, Any]] | None = None,
                          target_key: str | None = None) -> dict[str, Any]:
    """The packet of a stored case (``v3lum.case/2`` dict): the exporter entry point (no network)."""
    return build_packet(view_from_case(case if isinstance(case, dict) else {}), requested=requested, now=now, registrars=registrars, target_key=target_key)


def packet_from_graph(graph: Any, results: Any = (), *, now: Any = None, tlp: str = "amber", case_id: str = "", requested: bool = False,
                      target_key: str | None = None) -> dict[str, Any]:
    """The packet of a live investigation graph (correlation rule / report time)."""
    return build_packet(view_from_graph(graph, results, now=now, tlp=tlp, case_id=case_id), requested=requested, now=now, target_key=target_key)


def takedown_templates(packet: dict[str, Any]) -> dict[str, str]:
    """c7: ready-to-copy messages in pt-BR and English citing every evidence SHA-256 with both timestamps."""
    target = packet["target"]
    what = target.get("url_defanged") or target.get("host_defanged") or "-"
    host = target.get("host_defanged") or "-"
    lines_pt = [f"- {e['kind']} SHA-256 {e['sha256']} (UTC {e['captured_at_utc']} / Brasília {e['captured_at_sao_paulo']})" for e in packet["evidence"]]
    lines_en = [f"- {e['kind']} SHA-256 {e['sha256']} (UTC {e['captured_at_utc']} / America/Sao_Paulo {e['captured_at_sao_paulo']})" for e in packet["evidence"]]
    cc = f"\nCc: {CERT_BR_CC}" if packet.get("cert_br") else ""
    pt = (f"[{packet['tlp']}]\nAssunto: Solicitação de remoção - conteúdo malicioso (phishing) em {host}{cc}\n\n"
          f"Prezados,\n\nIdentificamos conteúdo malicioso hospedado em sua infraestrutura:\n{what}\n\n"
          f"Evidências (hashes SHA-256):\n{chr(10).join(lines_pt) or '- (sem evidências salvas)'}\n\n"
          "Solicitamos a remoção ou suspensão do conteúdo. (URL desarmada: substitua hxxp e [.] para acessar.)\n")
    en = (f"[{packet['tlp']}]\nSubject: Takedown request - malicious content (phishing) on {host}{cc}\n\n"
          f"Hello,\n\nWe identified malicious content hosted on your infrastructure:\n{what}\n\n"
          f"Evidence (SHA-256 hashes):\n{chr(10).join(lines_en) or '- (no saved evidence)'}\n\n"
          "Please remove or suspend this content. (Defanged URL: replace hxxp and [.] to access it.)\n")
    return {"pt-BR": pt, "en": en}


def render_packet_markdown(packet: dict[str, Any]) -> str:
    """The packet as text for the analyst (report format / command output). Never sent anywhere."""
    if not packet.get("generated"):
        return f"{packet.get('tlp', 'TLP:AMBER')}\nTakedown packet not generated: {packet.get('gate', {}).get('reason', 'gate refused')}\n"
    t = packet["target"]
    out = [f"{packet['tlp']}", f"# Takedown packet - case {packet.get('case_id') or '-'}", "",
           f"Created: {packet['created_utc']} (America/Sao_Paulo {packet['created_sao_paulo']})",
           f"Why: {packet['gate']['reason']}", "", "## Target",
           f"- {t.get('url_defanged') or t.get('host_defanged')}" + (f" (redacted: {', '.join(t['redacted_parts'])})" if t.get("redacted_parts") else ""),
           ]
    if t.get("behind_cdn"):
        out.append("- behind a CDN: report to the CDN portal and to the origin network (origin hints below)")
    out += ["", "## Contacts (most authoritative first)"]
    for c in packet["contacts"]:
        who = c.get("email") or c.get("url")
        extra = ", ".join(f"{k} {c[k]}" for k in ("registrar", "iana_id", "rir", "cdn") if c.get(k))
        out.append(f"{c['order']}. {who} - {c['reason']}" + (f" ({extra})" if extra else "")
                   + f"; source {', '.join(str(s) for s in c['sources']) or '-'}; retrieved {c.get('retrieved_at') or '-'}"
                   + (f"; origin hints {', '.join(c['origin_hints'])}" if c.get("origin_hints") else ""))
    if not packet["contacts"]:
        out.append("- no abuse contact in the case: run rdap / ripestat / abusix_contacts on the host and its addresses")
    if packet.get("cert_br"):
        out += ["", "## CERT.br", f"- {packet['cert_br']['guidance_pt']}", f"- {packet['cert_br']['guidance_en']}", f"- {packet['cert_br']['guide']}"]
    out += ["", "## Manual report links (never submitted by V3LUM)"] + [f"- {lk['name']}: {lk['url']}" for lk in packet["manual_links"]]
    out += ["", "## Evidence (SHA-256)"] + [f"- {e['kind']}: {e['sha256']} (UTC {e['captured_at_utc']} / America/Sao_Paulo {e['captured_at_sao_paulo']})"
                                            for e in packet["evidence"]]
    if not packet["evidence"]:
        out.append("- no saved evidence for the target")
    out += ["", "## Disclosure", packet["disclosure_note"], "", "## Template (pt-BR)", packet["templates"]["pt-BR"], "## Template (English)", packet["templates"]["en"]]
    return "\n".join(out)
