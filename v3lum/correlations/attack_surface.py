"""Correlation pack: attack-surface exposure (P291: CR07, CR08, CR13-CR16, CR25, CR26, CR31).

Every rule is ``fn(graph, results, rctx)`` and only reads facts already in the graph (vocab
attributes ``open_ports``, ``services``, ``cpes``, ``vulns``, ``vulns_verified``, ``kev``, ``epss``,
``cvss``, CNAME/NXDOMAIN facts...) plus the local CISA KEV / FIRST EPSS copies through
``core/datasets`` when a CVE node lacks the fact. No rule makes a network call, schedules a module
or touches the scope: findings outside the org profile are labelled ``third_party`` and never
trigger ACTIVE verification; SAN affiliates (CR31) and co-hosted names never join the scope.

Ownership (cond 5): CR13-CR16, CR25 and CR26 keep their severity only for org-profile own assets
(an address an own domain resolves to counts, unless shared or the domain entry is
``third_party_hosted``) or targets of the run's ACTIVE scope (:func:`threat_intel.in_scope`); any
other host gets INFO context; on entities tagged malicious/phishing/c2 the same facts are INFO
pivots for infrastructure fingerprinting.

* CR07 ``subdomain_takeover_candidate``: a CNAME to a service the pinned, attributed list
  ``v3lum/data/takeover_fingerprints.json`` (can-i-take-over-xyz, CC BY 4.0) marks vulnerable AND
  dangling evidence (a confirmed NXDOMAIN of the CNAME target, or the provider's unclaimed-resource
  fingerprint). Worded 'candidate'; the resource is never claimed or registered.
* CR08 ``dangling_cloud_ip``: a domain resolving to a cloud address whose indexed names (TLS
  certificate, hostnames, co-hosted domains) belong to someone else: POSSIBLE unless the evidence
  is strong; addresses are never re-acquired.
* CR13 ``exposed_remote_admin`` / CR14 ``exposed_database_or_cache``: risky ports with the
  observation date; data older than :data:`STALE_OBSERVATION_DAYS` (or undated) lowers confidence
  one level.
* CR15 ``known_exploited_vuln_on_asset``: CRITICAL only when (KEV or EPSS >= 0.5) AND verified AND
  own/in-scope; CVSS >= 9 alone is at most HIGH. Verified = the source marks it verified
  (``vulns_verified``), CVE-specific evidence beyond a version string, or an authorized ACTIVE check.
* CR16 ``outdated_version_disclosed``: version-inferred matches, ONE finding per host+product,
  POSSIBLE, capped HIGH with KEV and MEDIUM otherwise, labelled :data:`VERSION_LABEL`.
* CR25 ``stale_host``: >= :data:`STALE_HOST_MIN_SIGNALS` bad signals (a missing security.txt is not one).
* CR26 ``shadow_it_outlier``: an own asset whose hosting/registrar/DNS/certificate attribute is
  shared by <= 10 % of the org assets, only with >= setting ``attack_surface_min_assets`` (20).
* CR31 ``certificate_san_affiliate`` (INFO): other registrable domains named by the certificates of
  an own or analyst-typed domain.
* ``exploitable_exposure``: the legacy id, kept as an alias summary per host that applies the
  CR15/CR16 caps (it is never CRITICAL without verification on an own/in-scope asset).
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import re
import threading
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import psl
from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, ModuleResult, Severity
from v3lum.correlations.threat_intel import (
    adjacent,
    age_days,
    day,
    edges_out,
    evidence_findings,
    hostile,
    in_scope,
    now_of,
    own_asset,
    owned,
    parse_when,
    setting,
    shared_kind,
)

# ----------------------------------------------------------------------------------------
# Thresholds (P291) - one block, named constants only
# ----------------------------------------------------------------------------------------

#: CR13/CR14: observations older than this many days lower the confidence one level (cond 8).
STALE_OBSERVATION_DAYS = 30
#: CR15/CR16/alias: EPSS probability that counts as 'likely exploited' (cond 3).
EPSS_THRESHOLD = 0.5
#: CR15: CVSS at or above this is at most HIGH without KEV/EPSS (cond 3: never CRITICAL alone).
CVSS_HIGH = 9.0
#: CR16: CVSS at or above this makes a version-inferred product MEDIUM (else LOW).
CVSS_MEDIUM = 7.0
#: CR25: bad signals needed for a stale host (cond 8).
STALE_HOST_MIN_SIGNALS = 3
#: CR25: a registration expiring within this many days is a bad signal.
EXPIRY_WINDOW_DAYS = 30
#: CR25: a last web-archive capture older than this many days is a bad signal.
ARCHIVE_STALE_DAYS = 730
#: CR25: missing recommended security headers that count as one bad signal.
MISSING_HEADERS_MIN = 3
#: CR26: outlier share, share of the dominant value, minimum assets with the attribute (cond 9).
OUTLIER_MAX_SHARE = 0.10
DOMINANT_MIN_SHARE = 0.5
OUTLIER_MIN_VALUES = 5
#: CR26: setting holding the minimum number of org assets (config default 20).
MIN_ASSETS_SETTING = "attack_surface_min_assets"
DEFAULT_MIN_ASSETS = 20
#: CR31: a certificate naming more registrable domains than this is shared (CDN/hosting): skipped.
SAN_SHARED_CERT_DOMAINS = 50
#: Items listed in one correlation (CVEs, names, ports).
MAX_LISTED = 20
#: Per-CVE items read from one finding's data['vulns'] (shodan_api writes at most 100).
MAX_VULN_ITEMS = 200
#: CR16 label (cond 4).
VERSION_LABEL = "version-inferred, distro backports not considered: confirm on the host"
#: CR07 severity by whose name dangles (cond 10: outside the org profile = third_party, lower).
TAKEOVER_SEVERITY: dict[str, Severity] = {
    "own": Severity.HIGH, "in_scope": Severity.HIGH, "seed": Severity.MEDIUM, "third_party": Severity.LOW, "hostile": Severity.INFO,
}
#: CR08 severity with strong / single passive evidence (own or in-scope names; seeds LOW, others INFO).
DANGLING_IP_STRONG_SEVERITY = Severity.HIGH
DANGLING_IP_SEVERITY = Severity.MEDIUM
#: CR08: passive signals that make the evidence 'strong' (else POSSIBLE).
DANGLING_IP_STRONG_SIGNALS = 2
#: CR07: the bundled fingerprint list (pinned, attributed: v3lum/data/notices/can_i_take_over_xyz.json).
TAKEOVER_FILE = Path(__file__).resolve().parent.parent / "data" / "takeover_fingerprints.json"
TAKEOVER_SCHEMA = "v3lum.takeover_fingerprints/1"
#: Local datasets consulted for CVEs without graph facts (never downloaded by a rule).
KEV_DATASET = "cisa_kev"
EPSS_DATASET = "epss_scores"

S = Severity
#: CR13: remote administration / remote access services -> (label, severity for own assets).
REMOTE_ADMIN_PORTS: dict[int, tuple[str, Severity]] = {
    22: ("SSH", S.LOW), 23: ("Telnet", S.HIGH), 135: ("MS-RPC", S.MEDIUM), 161: ("SNMP", S.MEDIUM), 445: ("SMB", S.HIGH),
    623: ("IPMI", S.HIGH), 2082: ("cPanel", S.MEDIUM), 2083: ("cPanel (TLS)", S.MEDIUM), 2086: ("WHM", S.MEDIUM),
    2087: ("WHM (TLS)", S.MEDIUM), 2375: ("Docker API (plain)", S.HIGH), 2376: ("Docker API (TLS)", S.MEDIUM),
    3389: ("RDP", S.HIGH), 5900: ("VNC", S.HIGH), 5901: ("VNC", S.HIGH), 5902: ("VNC", S.HIGH),
    5985: ("WinRM (HTTP)", S.HIGH), 5986: ("WinRM (HTTPS)", S.MEDIUM), 6443: ("Kubernetes API", S.MEDIUM),
    8291: ("MikroTik Winbox", S.HIGH), 10000: ("Webmin", S.MEDIUM), 10250: ("kubelet", S.HIGH),
}
#: CR14: databases, caches and search indexes -> (label, severity for own assets).
DATABASE_PORTS: dict[int, tuple[str, Severity]] = {
    1433: ("Microsoft SQL Server", S.MEDIUM), 1521: ("Oracle Database", S.MEDIUM), 2379: ("etcd", S.HIGH),
    3306: ("MySQL/MariaDB", S.MEDIUM), 5432: ("PostgreSQL", S.MEDIUM), 5601: ("Kibana", S.MEDIUM), 5984: ("CouchDB", S.HIGH),
    6379: ("Redis", S.HIGH), 7474: ("Neo4j", S.MEDIUM), 8086: ("InfluxDB", S.MEDIUM), 8529: ("ArangoDB", S.MEDIUM),
    9042: ("Cassandra", S.MEDIUM), 9200: ("Elasticsearch", S.HIGH), 9300: ("Elasticsearch transport", S.HIGH),
    11211: ("Memcached", S.HIGH), 27017: ("MongoDB", S.HIGH), 27018: ("MongoDB", S.HIGH), 28015: ("RethinkDB", S.MEDIUM),
    50070: ("Hadoop NameNode", S.MEDIUM),
}
#: CR25: cleartext legacy services.
CLEARTEXT_PORTS: dict[int, str] = {21: "FTP", 23: "Telnet"}

CR07 = "subdomain_takeover_candidate"
CR08 = "dangling_cloud_ip"
CR13 = "exposed_remote_admin"
CR14 = "exposed_database_or_cache"
CR15 = "known_exploited_vuln_on_asset"
CR16 = "outdated_version_disclosed"
CR25 = "stale_host"
CR26 = "shadow_it_outlier"
CR31 = "certificate_san_affiliate"
ALIAS = "exploitable_exposure"

_HOST_TYPES = (EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN)
_IP_TYPES = (EntityType.IPV4, EntityType.IPV6)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_PORT_IN_TEXT = re.compile(r"^\s*(\d{1,5})(?:/(?:tcp|udp))?\b", re.I)
_REFS_TAKEOVER = ("https://github.com/EdOverflow/can-i-take-over-xyz", "https://attack.mitre.org/techniques/T1584/001/")
_REFS_EXPOSURE = ("https://attack.mitre.org/techniques/T1133/",)
_REFS_DATABASE = ("https://attack.mitre.org/techniques/T1190/",)
_REFS_KEV = ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://www.first.org/epss/")
_REFS_SURFACE = ("https://github.com/smicallef/spiderfoot",)
_REFS_CT = ("https://attack.mitre.org/techniques/T1596/003/",)


def _fixtures(rule_id: str, *names: str) -> tuple[str, ...]:
    """Graph-fixture paths of a rule (tests/fixtures/rules/<rule_id>/<name>.json)."""
    return tuple(f"tests/fixtures/rules/{rule_id}/{name}.json" for name in names)


# ----------------------------------------------------------------------------------------
# Ownership scoping (cond 5, 10)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Subject:
    """Whose asset a node is: 'own' | 'in_scope' | 'third_party' | 'hostile', with the reason."""

    kind: str
    reason: str

    @property
    def keeps_severity(self) -> bool:
        return self.kind in ("own", "in_scope")


def _third_party_hosted(own: Any) -> bool:
    return bool(getattr(own, "third_party_hosted", False))


def host_subject(graph: Graph, node: Node, rctx: Any) -> Subject:
    """Ownership class of a host for CR13-CR16/CR25/CR26 (cond 5).

    Own and in-scope assets come first: an own host a feed lists as malicious is a possibly
    compromised asset of the organisation, never 'hostile infrastructure' (its exposures keep their
    severity). Hostile is for everything else tagged malicious/phishing/c2."""
    flagged = " (listed as malicious: possibly compromised)" if hostile(node) else ""
    if own_asset(node, rctx):
        if _third_party_hosted(owned(node.entity, rctx)):
            return Subject("third_party", "own entry flagged third_party_hosted: the host belongs to its provider")
        return Subject("own", "org-profile own asset" + flagged)
    if in_scope(node, rctx):
        return Subject("in_scope", "target of the ACTIVE scope of the run" + flagged)
    if node.entity.type in _IP_TYPES and not node.noise and not shared_kind(node):
        for dom in sorted(adjacent(graph, node.key, "resolves_to", direction="in"), key=lambda n: n.key):
            if dom.entity.type is not EntityType.DOMAIN or edges_out(graph, dom.key, "cname_to"):
                continue  # a CNAME'd name resolves to its provider's address
            if own_asset(dom, rctx) and not _third_party_hosted(owned(dom.entity, rctx)):
                return Subject("own", f"address of the own domain {dom.entity.display}" + flagged)
    if flagged:
        return Subject("hostile", "entity tagged malicious/phishing/c2: infrastructure fingerprint only")
    return Subject("third_party", "not an org-profile asset nor an ACTIVE-scope target")


def scoped_severity(severity: Severity, subject: Subject) -> Severity:
    """Severity kept for own/in-scope assets; INFO for third-party and hostile hosts (cond 5)."""
    return severity if subject.keeps_severity else Severity.INFO


def _scope_tags(subject: Subject) -> list[str]:
    if subject.kind == "own":
        return ["own_asset"]
    if subject.kind == "hostile":
        return ["infrastructure", "third_party"]  # outside the org profile: never verified automatically (cond 10)
    if subject.kind == "third_party":
        return ["third_party"]
    return []


def _scope_note(subject: Subject) -> str:
    if subject.kind == "hostile":
        return " Hostile infrastructure: an INFO pivot for fingerprinting - never probe or verify it."
    if subject.kind == "third_party":
        return f" Third-party host ({subject.reason}): context only, never verified automatically."
    return ""


# ----------------------------------------------------------------------------------------
# Facts
# ----------------------------------------------------------------------------------------


def _floats(values: Iterable[Any]) -> list[float]:
    out = []
    for v in values:
        if isinstance(v, bool):
            continue
        if isinstance(v, Mapping):
            v = v.get("score")
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            continue
    return out


def _flag(node: Node, name: str) -> bool:
    return any(v is True for v in node.attr_values(name))


def _source_dates(node: Node) -> dict[str, _dt.datetime]:
    """Latest observation date per source module (evidence findings and ``last_seen`` attributes)."""
    dates: dict[str, _dt.datetime] = {}

    def keep(module: str, when: _dt.datetime | None) -> None:
        if when is not None and (module not in dates or when > dates[module]):
            dates[module] = when

    for f in evidence_findings(node):
        keep(f.module, parse_when(f.observed_last) or parse_when(f.observed_first))
    for value, src in node.attributes.get("last_seen", []):
        keep(src, parse_when(value))
    return dates


def host_ports(graph: Graph, node: Node) -> dict[int, set[str]]:
    """Open ports of a host -> reporting sources (``open_ports``, ``services`` and port_service nodes)."""
    ports: dict[int, set[str]] = {}

    def add(port: Any, src: str) -> None:
        try:
            num = int(port)
        except (TypeError, ValueError):
            return
        if 0 < num < 65536:
            ports.setdefault(num, set()).add(src or "?")

    for value, src in node.attributes.get("open_ports", []):
        for item in value if isinstance(value, (list, tuple, set)) else [value]:
            add(item, src)
    for value, src in node.attributes.get("services", []):
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, Mapping):
                add(item.get("port"), src)
            elif isinstance(item, str):
                m = _PORT_IN_TEXT.match(item)
                if m:
                    add(m.group(1), src)
    host = str(node.entity.value)
    for other in adjacent(graph, node.key, direction="both"):
        if other.entity.type is EntityType.PORT_SERVICE:
            hostpart, _, rest = str(other.entity.value).rpartition(":")
            if hostpart.strip("[]") == host:
                add(rest.split("/", 1)[0], next(iter(sorted(other.sources)), "port_service"))
    return ports


def _active_module(module: str) -> bool:
    """True for a registered module with opsec ACTIVE (an authorized check under the gate)."""
    try:
        from v3lum.core.module import REGISTRY
        from v3lum.core.models import Opsec
    except ImportError:  # pragma: no cover - defensive
        return False
    cls = REGISTRY.get(module)
    return cls is not None and getattr(cls, "opsec", None) == Opsec.ACTIVE


# ---- CVE facts ------------------------------------------------------------------------


@dataclass
class Vuln:
    """What the graph (and the local KEV/EPSS copies) say about one CVE on one host."""

    cve: str
    kev: bool = False
    epss: float | None = None
    cvss: float | None = None
    verified: str = ""  # '' | 'source verified' | 'CVE-specific evidence' | 'authorized ACTIVE check'
    products: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    @property
    def hot(self) -> bool:
        """Known or likely exploited: KEV or EPSS >= 0.5."""
        return self.kev or (self.epss is not None and self.epss >= EPSS_THRESHOLD)

    def describe(self) -> str:
        bits = [self.cve]
        if self.kev:
            bits.append("KEV")
        if self.epss is not None:
            bits.append(f"EPSS {self.epss:.2f}")
        if self.cvss is not None:
            bits.append(f"CVSS {self.cvss:.1f}")
        if self.verified:
            bits.append(self.verified)
        return " ".join(bits)


def _cve_id(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if _CVE_RE.match(text) else ""


def _product_key(vendor: Any, product: Any) -> str:
    v = str(vendor or "").strip().lower()
    p = str(product or "").strip().lower()
    if not p or p in ("*", "-"):
        return ""
    return f"{v}:{p}" if v and v not in ("*", "-") else p


def parse_cpe(cpe: Any) -> tuple[str, str]:
    """'cpe:/a:nginx:nginx:1.18.0' or 'cpe:2.3:a:nginx:nginx:1.18.0:...' -> ('nginx:nginx', '1.18.0')."""
    text = str(cpe or "").strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")[3:]
    elif text.startswith("cpe:/"):
        parts = text[5:].split(":")[1:]
    else:
        return "", ""
    vendor = parts[0] if parts else ""
    product = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 and parts[2] not in ("*", "-") else ""
    return _product_key(vendor, product), version


def _host_products(node: Node) -> dict[str, str]:
    """product key -> version from the host's ``cpes``."""
    out: dict[str, str] = {}
    for cpe in node.attr_values("cpes"):
        key, version = parse_cpe(cpe)
        if key:
            out.setdefault(key, version)
    return out


def _cve_products(cve_node: Node | None) -> set[str]:
    if cve_node is None:
        return set()
    out: set[str] = set()
    for item in cve_node.attr_values("affected") + cve_node.attr_values("cpe_matches"):
        if isinstance(item, Mapping):
            key = _product_key(item.get("vendor"), item.get("product"))
            if not key and item.get("criteria"):
                key = parse_cpe(item.get("criteria"))[0]
            if key:
                out.add(key)
    for cpe in cve_node.attr_values("cpes"):
        key = parse_cpe(cpe)[0]
        if key:
            out.add(key)
    return out


def _vuln_items(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Per-CVE items of a finding's ``data['vulns']`` (e.g. shodan_api: ``{cve, cvss, verified_by_shodan}``)."""
    items = data.get("vulns")
    return [i for i in items[:MAX_VULN_ITEMS] if isinstance(i, Mapping)] if isinstance(items, list) else []


def _mentions(f: Any, cve: str) -> bool:
    data = f.data if isinstance(f.data, Mapping) else {}
    if _cve_id(data.get("cve")) == cve:
        return True
    listed = data.get("cves")
    if isinstance(listed, (list, tuple)) and any(_cve_id(x) == cve for x in listed):
        return True
    return any(_cve_id(i.get("cve")) == cve for i in _vuln_items(data))


def _graph_cves(graph: Graph) -> set[str]:
    """Every CVE id the graph names (CVE nodes, host ``vulns``/``vulns_verified``, finding data)."""
    out: set[str] = set()
    for node in graph.nodes.values():
        if node.entity.type is EntityType.CVE:
            out.add(_cve_id(node.entity.value))
            continue
        for name in ("vulns", "vulns_verified"):
            out.update(_cve_id(v) for v in node.attr_values(name))
        for f in node.findings:
            data = f.data if isinstance(f.data, Mapping) else {}
            out.update(_cve_id(v) for v in [data.get("cve")] + list(data.get("cves") or []) if isinstance(v, str))
            out.update(_cve_id(i.get("cve")) for i in _vuln_items(data))
    out.discard("")
    return out


def prime_local_scores(graph: Graph) -> None:
    """Look every CVE of the graph up in the local EPSS copy in ONE pass over the file (a rule
    calls this before :func:`host_vulns` per host, which would otherwise re-read it per host)."""
    cves = _graph_cves(graph)
    if cves:
        local_epss(cves)


def host_vulns(graph: Graph, node: Node) -> dict[str, Vuln]:
    """CVEs of a host (has_vuln edges, ``vulns``/``vulns_verified`` attributes, finding data) with
    KEV/EPSS/CVSS from the CVE nodes, then from the local datasets, and the verification state.

    *Source verified* (P291 cond 3): ``vulns_verified``, or a per-CVE ``verified``/``verified_by_shodan``
    flag in a finding's ``data['vulns']`` items - even inside a finding tagged ``version_inferred``."""
    vulns: dict[str, Vuln] = {}

    def entry(cve: str, src: str) -> Vuln:
        v = vulns.setdefault(cve, Vuln(cve))
        v.sources.add(src or "?")
        return v

    for edge in edges_out(graph, node.key, "has_vuln"):
        dst = graph.nodes.get(edge.dst)
        cve = _cve_id(dst.entity.value) if dst is not None and dst.entity.type is EntityType.CVE else ""
        if cve:
            entry(cve, edge.module)
    for value, src in node.attributes.get("vulns", []):
        for item in value if isinstance(value, (list, tuple, set)) else [value]:
            cve = _cve_id(item)
            if cve:
                entry(cve, src)
    verified_ids: dict[str, str] = {}
    for value, src in node.attributes.get("vulns_verified", []):
        for item in value if isinstance(value, (list, tuple, set)) else [value]:
            cve = _cve_id(item)
            if cve:
                entry(cve, src)
                verified_ids.setdefault(cve, "source verified")
    findings = evidence_findings(node)
    item_cvss: dict[str, list[float]] = {}
    for f in findings:
        data = f.data if isinstance(f.data, Mapping) else {}
        for item in ([data.get("cve")] if data.get("cve") else []) + list(data.get("cves") or []):
            cve = _cve_id(item)
            if cve:
                entry(cve, f.module)
        for item in _vuln_items(data):
            cve = _cve_id(item.get("cve"))
            if not cve:
                continue
            entry(cve, f.module)
            item_cvss.setdefault(cve, []).extend(_floats([item.get("cvss")]))
            if item.get("verified") is True or item.get("verified_by_shodan") is True:
                verified_ids.setdefault(cve, "source verified")
    kev_listed = None
    for cve, vuln in vulns.items():
        cve_node = graph.nodes.get(f"cve:{cve}")
        if cve_node is not None:
            vuln.kev = any(v is True for v in cve_node.attr_values("kev"))
            epss = _floats(cve_node.attr_values("epss"))
            vuln.epss = max(epss) if epss else None
            cvss = _floats(cve_node.attr_values("cvss")) + _floats(cve_node.attr_values("cvss_scores"))
            vuln.cvss = max(cvss) if cvss else None
        if vuln.cvss is None and item_cvss.get(cve):
            vuln.cvss = max(item_cvss[cve])
        for f in findings:
            data = f.data if isinstance(f.data, Mapping) else {}
            if isinstance(data.get("kev"), (list, tuple)) and any(_cve_id(x) == cve for x in data["kev"]):
                vuln.kev = True
        if not vuln.kev:
            if kev_listed is None:
                kev_listed = local_kev()
            vuln.kev = cve in kev_listed
        vuln.products = _cve_products(cve_node)
        vuln.verified = verified_ids.get(cve, "")
        if not vuln.verified:
            for f in findings:
                if not _mentions(f, cve) or "version_inferred" in (f.tags or ()):
                    continue
                if not {"vulnerable", "kev", "exploit_available"} & set(f.tags or ()):
                    continue
                vuln.verified = "authorized ACTIVE check" if _active_module(f.module) else "CVE-specific evidence"
                break
    missing = [cve for cve, v in vulns.items() if v.epss is None]
    if missing:
        for cve, score in local_epss(missing).items():
            vulns[cve].epss = score
    return vulns


# ---- local KEV/EPSS copies (core/datasets; never downloaded here) -----------------------

_DATASET_LOCK = threading.Lock()
_KEV_CACHE: dict[str, Any] = {"stamp": None, "ids": frozenset()}
_EPSS_CACHE: dict[str, Any] = {"stamp": None, "scores": {}}


_PATHS: dict[tuple[str, str], Path] = {}  # (V3LUM_HOME, dataset) -> local path: resolved once, not per host


def _dataset_path(name: str) -> Path | None:
    """Local copy of dataset ``name`` when it exists (the path is resolved once per V3LUM home)."""
    key = (os.environ.get("V3LUM_HOME", ""), name)
    path = _PATHS.get(key)
    if path is None:
        try:
            from v3lum.core.datasets import DataStore

            path = DataStore(None).path(name)
        except Exception:  # noqa: BLE001 - no datasets directory, no lookups
            return None
        _PATHS[key] = path
    return path if path.is_file() else None


def _stamp(path: Path) -> tuple[str, int, int]:
    st = path.stat()
    return str(path), int(st.st_mtime_ns), int(st.st_size)


def local_kev() -> frozenset[str]:
    """CVE ids of the local CISA KEV copy (dataset ``cisa_kev``), empty when it was never fetched."""
    path = _dataset_path(KEV_DATASET)
    if path is None:
        return frozenset()
    with _DATASET_LOCK:
        try:
            stamp = _stamp(path)
            if _KEV_CACHE["stamp"] != stamp:
                doc = json.loads(path.read_text(encoding="utf-8-sig"))
                items = doc.get("vulnerabilities") if isinstance(doc, Mapping) else None
                ids = {_cve_id(i.get("cveID")) for i in items or [] if isinstance(i, Mapping)}
                _KEV_CACHE.update(stamp=stamp, ids=frozenset(i for i in ids if i))
        except (OSError, ValueError):
            return frozenset()
        return _KEV_CACHE["ids"]


def local_epss(cves: Iterable[str]) -> dict[str, float]:
    """EPSS scores of ``cves`` from the local FIRST EPSS copy (dataset ``epss_scores``), streamed."""
    wanted = {c for c in cves if c}
    path = _dataset_path(EPSS_DATASET) if wanted else None
    if path is None:
        return {}
    with _DATASET_LOCK:
        try:
            stamp = _stamp(path)
            if _EPSS_CACHE["stamp"] != stamp:
                _EPSS_CACHE.update(stamp=stamp, scores={})
            scores: dict[str, float] = _EPSS_CACHE["scores"]
            todo = wanted - set(scores)
            if todo:
                with path.open(encoding="utf-8", errors="replace", newline="") as fh:
                    for row in csv.reader(line for line in fh if not line.startswith("#")):
                        if len(row) >= 2 and row[0].strip().upper() in todo:
                            try:
                                scores[row[0].strip().upper()] = float(row[1])
                            except ValueError:
                                continue
                for cve in todo - set(scores):
                    scores[cve] = -1.0  # looked up, not scored
        except OSError:
            return {}
        return {c: scores[c] for c in wanted if scores.get(c, -1.0) >= 0.0}


# ----------------------------------------------------------------------------------------
# CR07 subdomain_takeover_candidate
# ----------------------------------------------------------------------------------------

_TAKEOVER_CACHE: dict[str, Any] = {}


def takeover_fingerprints() -> list[dict[str, Any]]:
    """Entries of the bundled fingerprint list (cached; [] when unreadable)."""
    if "entries" not in _TAKEOVER_CACHE:
        try:
            doc = json.loads(TAKEOVER_FILE.read_text(encoding="utf-8"))
            entries = doc.get("entries") if isinstance(doc, Mapping) and doc.get("schema") == TAKEOVER_SCHEMA else None
            _TAKEOVER_CACHE["entries"] = [e for e in entries or [] if isinstance(e, Mapping) and e.get("service")]
        except (OSError, ValueError):
            _TAKEOVER_CACHE["entries"] = []
    return list(_TAKEOVER_CACHE["entries"])


def vulnerable_services(target: str) -> list[dict[str, Any]]:
    """Vulnerable entries whose CNAME suffix matches ``target`` (label-wise, never a substring)."""
    host = str(target or "").strip().lower().rstrip(".")
    out = []
    for entry in takeover_fingerprints():
        if not entry.get("vulnerable"):
            continue
        for suffix in entry.get("cname") or []:
            suffix = str(suffix).lower().rstrip(".")
            if host == suffix or host.endswith("." + suffix):
                out.append(dict(entry))
                break
    return out


def _nxdomain_entry(entry: Mapping[str, Any]) -> bool:
    return bool(entry.get("nxdomain")) or str(entry.get("fingerprint") or "").strip().upper() == "NXDOMAIN"


def _dangling_nxdomain(graph: Graph, sub: Node, target: Node | None, target_name: str) -> str:
    """A confirmed NXDOMAIN of the CNAME target: the target's dns_records answer (attribute
    ``valid`` False, written only after a second resolver confirmed it) or ``cname_dangling``."""
    if target is not None and any(v is False for v in target.attr_values("valid")):
        return f"CNAME target {target_name} answers NXDOMAIN (confirmed by a second resolver)"
    for value, src in sub.attributes.get("cname_dangling", []):
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, Mapping):
                continue
            named = str(item.get("target") or "").strip().lower().rstrip(".")
            if named and named != target_name:
                continue
            if str(item.get("status") or "").upper() == "NXDOMAIN" and item.get("confirmed") is True:
                when = day(parse_when(item.get("observed_at")))
                return f"CNAME target {target_name} answers NXDOMAIN (confirmed by a second resolver; {src}, {when})"
    return ""


def _fingerprint_match(sub: Node, entry: Mapping[str, Any]) -> str:
    service = str(entry.get("service") or "").strip().lower()
    for value, src in sub.attributes.get("takeover_fingerprint", []):
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, Mapping) and str(item.get("service") or "").strip().lower() == service:
                when = day(parse_when(item.get("observed_at")))
                return f"unclaimed-resource fingerprint of {entry.get('service')} ({item.get('source') or src}, {when})"
    return ""


def _named_services(sub: Node) -> list[dict[str, Any]]:
    """Vulnerable entries without CNAME patterns named by a ``takeover_fingerprint`` of the name."""
    named = set()
    for value, _src in sub.attributes.get("takeover_fingerprint", []):
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, Mapping) and item.get("service"):
                named.add(str(item["service"]).strip().lower())
    return [dict(e) for e in takeover_fingerprints() if e.get("vulnerable") and not e.get("cname") and str(e.get("service")).lower() in named]


def _subject_for_name(node: Node, rctx: Any) -> Subject:
    """Ownership class of a DNS name for CR07/CR08 (own/in-scope first: an own name a feed flags is
    still the organisation's name)."""
    if own_asset(node, rctx):
        return Subject("own", "org-profile own asset")
    if in_scope(node, rctx):
        return Subject("in_scope", "target of the ACTIVE scope of the run")
    if hostile(node):
        return Subject("hostile", "entity tagged malicious/phishing/c2")
    seeds = set(getattr(getattr(rctx, "options", None), "unconfirmed_seeds", ()) or ())
    if node.seed and node.key not in seeds:
        return Subject("seed", "analyst-typed input (not in the org profile)")
    return Subject("third_party", "not an org-profile asset")


@rule(
    CR07,
    "Subdomain takeover candidate (dangling CNAME to a vulnerable service)",
    "CR07 (P291 cond 6): a CNAME to a service the pinned can-i-take-over-xyz list marks vulnerable AND dangling evidence "
    "(confirmed NXDOMAIN of the CNAME target, or the provider's unclaimed-resource fingerprint). A candidate: V3LUM never "
    "claims or registers the resource.",
    version="1",
    code="CR07",
    severity="high",
    criterion="CNAME to a vulnerable service (can-i-take-over-xyz) + confirmed NXDOMAIN of the target or the unclaimed-resource fingerprint",
    references=_REFS_TAKEOVER,
    attack=("T1584.001",),
    false_positives="Services that reserve deleted names, CNAMEs being re-provisioned, and fingerprints the provider changed "
    "since the pinned list: confirm in the provider console before acting.",
    fixtures=_fixtures(CR07, "positive_nxdomain_cname_to_vulnerable_service", "positive_unclaimed_fingerprint", "negative_not_vulnerable_or_unconfirmed"),
)
def subdomain_takeover_candidate(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        sub = graph.nodes[key]
        if sub.entity.type is not EntityType.DOMAIN:
            continue
        for edge in sorted(edges_out(graph, key, "cname_to"), key=lambda e: e.dst):
            target = graph.nodes.get(edge.dst)
            target_name = str(target.entity.value if target is not None else edge.dst.split(":", 1)[-1]).lower().rstrip(".")
            entries = vulnerable_services(target_name) + _named_services(sub)
            for entry in entries:
                nx = _dangling_nxdomain(graph, sub, target, target_name)
                fp = "" if _nxdomain_entry(entry) else _fingerprint_match(sub, entry)
                evidence = nx or fp
                if not evidence:
                    continue
                subject = _subject_for_name(sub, rctx)
                severity = TAKEOVER_SEVERITY[subject.kind]
                service = str(entry.get("service"))
                yield Correlation(
                    rule=CR07,
                    title=f"{sub.entity.display}: subdomain takeover candidate ({service})",
                    severity=severity,
                    description=(
                        f"{sub.entity.display} is a CNAME to {target_name}, a {service} name the pinned can-i-take-over-xyz list marks "
                        f"vulnerable, and {evidence}. Anyone who claims that {service} resource could serve content under this name. "
                        "A candidate, not a confirmed takeover: V3LUM never claims or registers the resource to prove it."
                        + ("" if subject.kind in ("own", "in_scope") else f" {subject.reason}: labelled third_party, never verified automatically.")
                    ),
                    entities=[sub.entity] + ([target.entity] if target is not None else []),
                    confidence=0.7,
                    evidence=[f"CNAME {sub.entity.value} -> {target_name}", f"service {service} ({entry.get('status')}; fingerprint {str(entry.get('fingerprint'))[:80]!r})", evidence],
                    recommendation=(
                        "Remove the dangling CNAME, or re-create the resource under your own account first. Never claim the resource "
                        "to 'prove' the takeover; report third-party candidates to their owner (manual disclosure)."
                    ),
                    tags=["takeover", "misconfiguration"] + ([] if subject.kind in ("own", "in_scope") else ["third_party"]),
                    criterion=f"candidate: CNAME to vulnerable service {service} + {('NXDOMAIN' if nx else 'unclaimed fingerprint')} evidence",
                    key=f"{target_name}|{service}",
                )


# ----------------------------------------------------------------------------------------
# CR08 dangling_cloud_ip
# ----------------------------------------------------------------------------------------


def _cloud(node: Node) -> str:
    if node.noise_kind == "cloud" or "cloud" in node.tags:
        return "cloud range"
    for name in ("cloud_service", "cloud_label"):
        values = [str(v) for v in node.attr_values(name) if v]
        if values:
            return values[0]
    if _flag(node, "is_hosting"):
        return "hosting/cloud range"
    return ""


def _registrable(name: Any) -> str:
    text = str(name or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if not text or " " in text:
        return ""
    try:
        return psl.registrable_domain(text) or ""
    except Exception:  # noqa: BLE001 - a malformed name is no name
        return ""


def _address_names(graph: Graph, ip: Node) -> dict[str, set[str]]:
    """Names indexed for an address, by kind: 'certificate' (cert_sans/cert_subject), 'hosted'
    (hostnames attribute, hosted_domain/reverse_dns edges)."""
    names: dict[str, set[str]] = {"certificate": set(), "hosted": set()}
    for attr in ("cert_sans", "cert_subject"):
        for value in ip.attr_values(attr):
            if isinstance(value, str):
                names["certificate"].add(value.strip().lower())
    for value in ip.attr_values("hostnames") + ip.attr_values("rdns"):
        if isinstance(value, str):
            names["hosted"].add(value.strip().lower())
    for rel in ("hosted_domain", "reverse_dns"):
        for other in adjacent(graph, ip.key, rel):
            if other.entity.type is EntityType.DOMAIN and not other.noise:
                names["hosted"].add(str(other.entity.value))
    return names


@rule(
    CR08,
    "Domain points to a cloud address that may have been released (dangling DNS)",
    "CR08 (P291 cond 7): a domain resolving to a cloud/hosting address whose indexed certificate names, hostnames or "
    "co-hosted domains belong to other organisations. POSSIBLE unless the evidence is strong; addresses are never re-acquired.",
    version="1",
    code="CR08",
    severity="medium",
    criterion="A record to a cloud address + indexed names of the address (certificate, hostnames, co-hosted domains) that do not cover the domain",
    references=_REFS_TAKEOVER,
    attack=("T1584.001",),
    false_positives="Shared load balancers, multi-tenant front doors and certificates issued per tenant name other "
    "customers legitimately; indexed data may be weeks old.",
    fixtures=_fixtures(CR08, "positive_released_cloud_address", "negative_address_serves_the_domain"),
)
def dangling_cloud_ip(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        dom = graph.nodes[key]
        if dom.entity.type is not EntityType.DOMAIN or dom.noise:
            continue
        subject = _subject_for_name(dom, rctx)
        if subject.kind == "hostile":
            continue
        reg = _registrable(dom.entity.value)
        for ip in sorted(adjacent(graph, key, "resolves_to"), key=lambda n: n.key):
            if ip.entity.type not in _IP_TYPES or shared_kind(ip):
                continue
            cloud = _cloud(ip)
            if not cloud:
                continue
            signals: list[str] = []
            serves_domain = False
            for kind, found in sorted(_address_names(graph, ip).items()):
                regs = {r for r in (_registrable(n) for n in found) if r}
                if reg in regs:
                    serves_domain = True  # the address still serves the domain
                    break
                if regs:
                    signals.append(f"{kind} names of {ip.entity.display} belong to other domains: {', '.join(sorted(regs)[:5])}")
            if serves_domain or not signals:
                continue
            if any(v == "not seen by Shodan scanners" for v in ip.attr_values("internetdb_status")):
                signals.append(f"no service observed on {ip.entity.display} (not seen by scanners)")
            strong = len(signals) >= DANGLING_IP_STRONG_SIGNALS
            base = DANGLING_IP_STRONG_SEVERITY if strong else DANGLING_IP_SEVERITY
            severity = base if subject.kind in ("own", "in_scope") else Severity.LOW if subject.kind == "seed" else Severity.INFO
            yield Correlation(
                rule=CR08,
                title=f"{dom.entity.display} points to {cloud} address {ip.entity.display} that may have been released",
                severity=severity,
                description=(
                    f"{dom.entity.display} resolves to {ip.entity.display} ({cloud}), and indexed data shows that address now serves "
                    f"other organisations: {'; '.join(signals)}. If the cloud resource was released, whoever holds the address can "
                    "serve content under this name (dangling DNS)." + ("" if strong else " Single signal: POSSIBLE.")
                    + ("" if subject.kind in ("own", "in_scope") else f" {subject.reason}: labelled third_party.")
                ),
                entities=[dom.entity, ip.entity],
                confidence=0.7 if strong else 0.4,
                evidence=[f"A {dom.entity.value} -> {ip.entity.value} ({cloud})"] + signals,
                recommendation="Confirm the address still belongs to your cloud account; remove or update the record if it was released. Never try to re-acquire the address.",
                tags=["takeover", "misconfiguration"] + ([] if subject.kind in ("own", "in_scope") else ["third_party"]),
                criterion=("strong" if strong else "POSSIBLE") + f": {len(signals)} passive signal(s) that {ip.entity.value} no longer serves {reg or dom.entity.value}",
                key=ip.key,
            )


# ----------------------------------------------------------------------------------------
# CR13 / CR14 exposures
# ----------------------------------------------------------------------------------------


def _exposure(graph: Graph, node: Node, rctx: Any, table: Mapping[int, tuple[str, Severity]], rule_id: str, what: str) -> Correlation | None:
    ports = host_ports(graph, node)
    hits = {p: table[p] for p in sorted(ports) if p in table}
    if not hits:
        return None
    subject = host_subject(graph, node, rctx)
    now = now_of(rctx)
    dates = _source_dates(node)
    srcs = sorted({s for p in hits for s in ports[p]})
    when = max((dates[s] for s in srcs if s in dates), default=None)
    age = age_days(when, now)
    active = any(_active_module(s) for s in srcs)
    label = Confidence.CONFIRMED if active else Confidence.PROBABLE
    stale = age is None or age > STALE_OBSERVATION_DAYS
    if stale:
        label = label.lower()
    worst = max(sev for _l, sev in hits.values())
    severity = scoped_severity(worst, subject)
    services = ", ".join(f"{p}/{lbl}" for p, (lbl, _s) in hits.items())
    observed = f"observed {day(when)}" + (f" ({int(age)} days ago: confidence lowered one level)" if age is not None and stale else "")
    if when is None:
        observed = "observation date unknown (treated as possibly stale: confidence lowered one level)"
    return Correlation(
        rule=rule_id,
        title=f"{node.entity.display} exposes {what} ({services})",
        severity=severity,
        description=f"{what.capitalize()} reachable from the internet on {node.entity.display}: {services}; {observed}." + _scope_note(subject),
        entities=[node.entity],
        confidence=label,
        evidence=[f"port {p}: {lbl} (reported by {', '.join(sorted(ports[p]))})" for p, (lbl, _s) in hits.items()] + [observed, f"ownership: {subject.reason}"],
        recommendation=(
            "Restrict the service to a VPN/allow-list or take it off the internet; confirm the exposure on the host (data may be weeks old)."
            if subject.keeps_severity else
            "Context only: not your asset (or hostile infrastructure). Never verify it automatically."
        ),
        tags=["exposure"] + _scope_tags(subject),
        criterion=f"open port(s) {', '.join(str(p) for p in hits)} reported by {', '.join(srcs)}; {observed}",
    )


@rule(
    CR13,
    "Remote administration service exposed to the internet",
    "CR13 (P291 cond 5, 8): RDP, SSH, Telnet, VNC, WinRM, SMB, IPMI, Docker/Kubernetes control planes... reachable from "
    "the internet. Severity only for own/in-scope assets (third-party: INFO; hostile: INFO pivot); the observation date "
    "is shown and data older than 30 days lowers confidence one level.",
    version="1",
    code="CR13",
    severity="high",
    criterion="a remote-administration port reported open by scan data, with its observation date",
    references=_REFS_EXPOSURE,
    attack=("T1133",),
    false_positives="Honeypots, port-forwarding tarpits and stale scan data (the service may have been closed since).",
    fixtures=_fixtures(CR13, "positive_rdp_on_own_ip", "positive_old_scan_lowers_confidence", "positive_third_party_host_is_info", "negative_web_ports_only_and_noise"),
)
def exposed_remote_admin(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type in _HOST_TYPES and not node.noise:
            corr = _exposure(graph, node, rctx, REMOTE_ADMIN_PORTS, CR13, "remote administration")
            if corr is not None:
                yield corr


@rule(
    CR14,
    "Database, cache or search index exposed to the internet",
    "CR14 (P291 cond 5, 8): Redis, MongoDB, Elasticsearch, Memcached, MySQL, PostgreSQL... reachable from the internet. "
    "Severity only for own/in-scope assets; observation date shown, older than 30 days lowers confidence one level.",
    version="1",
    code="CR14",
    severity="high",
    criterion="a database/cache port reported open by scan data, with its observation date",
    references=_REFS_DATABASE,
    attack=("T1190", "T1213"),
    false_positives="Honeypots and stale scan data; a listening port does not prove missing authentication.",
    fixtures=_fixtures(CR14, "positive_redis_on_own_domain_address", "positive_hostile_host_is_info_pivot", "negative_no_database_ports"),
)
def exposed_database_or_cache(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type in _HOST_TYPES and not node.noise:
            corr = _exposure(graph, node, rctx, DATABASE_PORTS, CR14, "databases/caches")
            if corr is not None:
                yield corr


# ----------------------------------------------------------------------------------------
# CR15 / CR16 / exploitable_exposure
# ----------------------------------------------------------------------------------------


def _cve_entities(vulns: Iterable[Vuln]) -> list[Entity]:
    out = []
    for v in vulns:
        ent = Entity.try_make(EntityType.CVE, v.cve)
        if ent is not None:
            out.append(ent)
    return out[:10]


@rule(
    CR15,
    "Known-exploited vulnerability verified on an asset",
    "CR15 (P291 cond 3, 5): CRITICAL only when (CISA KEV or EPSS >= 0.5) AND the vulnerability is verified (the source "
    "marks it verified, CVE-specific evidence beyond a version string, or an authorized ACTIVE check) AND the asset is an "
    "own or in-scope asset. CVSS >= 9 alone is at most HIGH; version-inferred matches are CR16's.",
    version="1",
    code="CR15",
    severity="critical",
    criterion="(KEV or EPSS >= 0.5) and verified and own/in-scope asset",
    references=_REFS_KEV,
    attack=("T1190",),
    false_positives="A 'verified' flag from a scanner can still miss vendor backports or mitigations: confirm on the host.",
    fixtures=_fixtures(
        CR15, "positive_verified_kev_on_own_asset", "positive_cvss9_alone_is_high", "positive_third_party_verified_kev_is_info",
        "negative_version_inferred_kev_is_cr16",
    ),
)
def known_exploited_vuln_on_asset(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    prime_local_scores(graph)
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in _HOST_TYPES or node.noise:
            continue
        verified = [v for v in host_vulns(graph, node).values() if v.verified]
        hot = sorted((v for v in verified if v.hot), key=lambda v: v.cve)
        severe = sorted((v for v in verified if not v.hot and v.cvss is not None and v.cvss >= CVSS_HIGH), key=lambda v: v.cve)
        if not hot and not severe:
            continue
        subject = host_subject(graph, node, rctx)
        severity = scoped_severity(Severity.CRITICAL if hot else Severity.HIGH, subject)
        strong = any(v.verified in ("source verified", "authorized ACTIVE check") for v in hot or severe)
        listed = (hot + severe)[:MAX_LISTED]
        yield Correlation(
            rule=CR15,
            title=f"{node.entity.display}: {len(hot) or len(severe)} {'known/likely exploited' if hot else 'critical-CVSS'} vulnerabilit{'y' if len(hot or severe) == 1 else 'ies'} verified",
            severity=severity,
            description=(
                "Verified on the host: " + "; ".join(v.describe() for v in listed) + "."
                + ("" if hot else " CVSS >= 9 without KEV/EPSS >= 0.5 is never CRITICAL.") + _scope_note(subject)
            ),
            entities=[node.entity] + _cve_entities(listed),
            confidence=0.9 if strong else 0.7,
            evidence=[v.describe() for v in listed] + [f"ownership: {subject.reason}"],
            recommendation=(
                "Patch or isolate the service now (KEV: exploited in the wild); check the host for compromise."
                if hot and subject.keeps_severity else
                "Patch in the next cycle and confirm the affected component." if subject.keeps_severity else
                "Context only: not your asset (or hostile infrastructure). Never verify it automatically."
            ),
            tags=["vulnerable"] + (["kev"] if any(v.kev for v in listed) else []) + _scope_tags(subject),
            criterion=("(KEV or EPSS >= 0.5) and verified" if hot else "verified, CVSS >= 9 (no KEV/EPSS >= 0.5): capped at HIGH")
            + f"; {subject.reason}",
        )


def _version_buckets(node: Node, vulns: list[Vuln]) -> dict[str, list[Vuln]]:
    """CVEs grouped by product (host CPEs matched with the CVE's affected products)."""
    products = _host_products(node)
    buckets: dict[str, list[Vuln]] = {}
    for v in vulns:
        match = sorted(set(products) & v.products)
        if match:
            key = match[0]
        elif len(products) == 1:
            key = next(iter(products))
        else:
            key = ""
        buckets.setdefault(key, []).append(v)
    return buckets


@rule(
    CR16,
    "Outdated software version disclosed (version-inferred CVEs)",
    "CR16 (P291 cond 4): CVEs matched from a version string (InternetDB/Shodan CPE) are POSSIBLE, ONE finding per "
    "host+product (never one per CVE), capped at HIGH when a CVE is in KEV and at MEDIUM otherwise, labelled "
    "'version-inferred, distro backports not considered: confirm on the host'.",
    version="1",
    code="CR16",
    severity="high",
    criterion="CVEs matched by software version (CPE), not verified on the host",
    references=_REFS_KEV,
    attack=("T1592.002", "T1190"),
    false_positives="Distributions backport fixes without changing the version string; banners can be stale or spoofed.",
    fixtures=_fixtures(CR16, "positive_nginx_20_cves_one_kev", "positive_third_party_host_is_info", "negative_verified_only_and_no_cves"),
)
def outdated_version_disclosed(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    prime_local_scores(graph)
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in _HOST_TYPES or node.noise:
            continue
        inferred = [v for v in host_vulns(graph, node).values() if not v.verified]
        if not inferred:
            continue
        subject = host_subject(graph, node, rctx)
        products = _host_products(node)
        for product, items in sorted(_version_buckets(node, inferred).items()):
            items = sorted(items, key=lambda v: (not v.kev, -(v.epss or 0.0), -(v.cvss or 0.0), v.cve))
            kev = [v for v in items if v.kev]
            if kev:
                base = Severity.HIGH
            elif any((v.cvss or 0.0) >= CVSS_MEDIUM or (v.epss or 0.0) >= EPSS_THRESHOLD for v in items):
                base = Severity.MEDIUM
            else:
                base = Severity.LOW
            severity = scoped_severity(base, subject)
            name = product or "software reported for the host"
            version = products.get(product, "") if product else ""
            shown = f"{name} {version}".strip()
            yield Correlation(
                rule=CR16,
                title=f"{node.entity.display}: {shown} - {len(items)} version-inferred CVE(s), KEV: {len(kev)}",
                severity=severity,
                description=(
                    f"{len(items)} CVE(s) match the disclosed version of {shown} ({VERSION_LABEL}). "
                    + (f"In CISA KEV: {', '.join(v.cve for v in kev[:5])}. " if kev else "")
                    + "Top: " + "; ".join(v.describe() for v in items[:5]) + "." + _scope_note(subject)
                ),
                entities=[node.entity] + _cve_entities(items[:5]),
                confidence=Confidence.POSSIBLE,
                evidence=[v.describe() for v in items[:MAX_LISTED]] + [VERSION_LABEL, f"ownership: {subject.reason}"],
                recommendation=(
                    "Confirm the installed package version on the host (backports) and upgrade; prioritise the KEV entries."
                    if subject.keeps_severity else
                    "Context only: not your asset (or hostile infrastructure). Never verify it automatically."
                ),
                tags=["vulnerable", "version_inferred"] + (["kev"] if kev else []) + _scope_tags(subject),
                criterion=f"{VERSION_LABEL}; capped at {'HIGH (KEV)' if kev else 'MEDIUM'}",
                key=product or "unattributed",
            )


@rule(
    ALIAS,
    "Exposed host with known or likely exploited vulnerabilities (alias of CR15/CR16)",
    "Legacy id kept as an alias (P291 cond 1): one summary per host with CVEs in KEV or with EPSS >= 0.5, applying the "
    "CR15/CR16 caps - CRITICAL only when verified on an own/in-scope asset, version-inferred matches POSSIBLE and capped "
    "at HIGH (KEV) or MEDIUM, third-party and hostile hosts INFO.",
    version="2",
    code="CR15/CR16",
    severity="critical",
    criterion="CVEs in KEV or with EPSS >= 0.5 on the host, with the CR15/CR16 caps",
    references=_REFS_KEV,
    attack=("T1190",),
    false_positives="Version-inferred matches ignore distribution backports; see CR15/CR16.",
    fixtures=_fixtures(ALIAS, "positive_alias_applies_caps", "negative_no_hot_cves"),
)
def exploitable_exposure(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    prime_local_scores(graph)
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in _HOST_TYPES or node.noise:
            continue
        hot = sorted((v for v in host_vulns(graph, node).values() if v.hot), key=lambda v: (not v.verified, not v.kev, v.cve))
        if not hot:
            continue
        subject = host_subject(graph, node, rctx)
        verified = [v for v in hot if v.verified]
        if verified:
            base, label = Severity.CRITICAL, Confidence.PROBABLE
        elif any(v.kev for v in hot):
            base, label = Severity.HIGH, Confidence.POSSIBLE
        else:
            base, label = Severity.MEDIUM, Confidence.POSSIBLE
        severity = scoped_severity(base, subject)
        yield Correlation(
            rule=ALIAS,
            title=f"{node.entity.display} exposes {len(hot)} vulnerabilit{'y' if len(hot) == 1 else 'ies'} with known/likely exploitation",
            severity=severity,
            description=(
                "CVEs in CISA KEV or with EPSS >= 0.5: " + "; ".join(v.describe() for v in hot[:10]) + ". "
                + ("Verified on the host." if verified else f"{VERSION_LABEL}.") + _scope_note(subject)
            ),
            entities=[node.entity] + _cve_entities(hot),
            confidence=label,
            evidence=[v.describe() for v in hot[:MAX_LISTED]] + [f"ownership: {subject.reason}"],
            recommendation="Patch or isolate the exposed service; confirm version-based matches on the host (see CR15/CR16).",
            tags=["vulnerable", "kev" if any(v.kev for v in hot) else "exploit_available"] + _scope_tags(subject),
            criterion=("verified" if verified else VERSION_LABEL) + f"; {subject.reason}",
        )


# ----------------------------------------------------------------------------------------
# CR25 stale_host
# ----------------------------------------------------------------------------------------


def stale_signals(graph: Graph, node: Node, now: _dt.datetime) -> list[str]:
    """Bad signals of a forgotten/unmaintained host (cond 8). A missing security.txt is not one."""
    signals: list[str] = []
    if _flag(node, "eol_software"):
        signals.append("end-of-life software or operating system")
    expired = [w for w in (parse_when(v) for v in node.attr_values("cert_not_after")) if w is not None and w < now]
    if expired:
        signals.append(f"TLS certificate expired on {day(max(expired))}")
    if _flag(node, "tls_self_signed"):
        signals.append("self-signed TLS certificate")
    vulns = host_vulns(graph, node)
    if vulns:
        signals.append(f"known-vulnerable software versions ({len(vulns)} CVE(s))")
    legacy = sorted({CLEARTEXT_PORTS[p] for p in host_ports(graph, node) if p in CLEARTEXT_PORTS})
    if legacy:
        signals.append(f"cleartext legacy service ({', '.join(legacy)})")
    missing = {str(v) for v in node.attr_values("security_headers_missing")}
    if len(missing) >= MISSING_HEADERS_MIN:
        signals.append(f"{len(missing)} recommended security headers missing")
    if node.entity.type is EntityType.DOMAIN:
        expires = [w for w in (parse_when(v) for v in node.attr_values("expires")) if w is not None]
        if expires and min(expires) <= now + _dt.timedelta(days=EXPIRY_WINDOW_DAYS):
            signals.append(f"registration expires/expired on {day(min(expires))}")
        captures = [w for w in (parse_when(v) for v in node.attr_values("archive_last")) if w is not None]
        if captures and (now - max(captures)).days > ARCHIVE_STALE_DAYS:
            signals.append(f"no web-archive capture since {day(max(captures))}")
    return signals


@rule(
    CR25,
    "Stale host (several signs of an unmaintained or forgotten asset)",
    "CR25 (P291 cond 8): >= 3 bad signals among end-of-life software, expired or self-signed certificates, "
    "version-inferred CVEs, cleartext legacy services, missing security headers, an expiring registration and no recent "
    "web-archive capture. A missing security.txt is not a signal. Severity only for own/in-scope assets.",
    version="1",
    code="CR25",
    severity="medium",
    criterion=">= 3 independent bad signals on the host (security.txt never counts)",
    references=_REFS_SURFACE,
    attack=("T1190",),
    false_positives="Lab and legacy systems kept on purpose; signals from stale scan data.",
    fixtures=_fixtures(CR25, "positive_three_signals", "negative_two_signals_and_security_txt"),
)
def stale_host(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    now = now_of(rctx)
    prime_local_scores(graph)
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type not in _HOST_TYPES or node.noise:
            continue
        signals = stale_signals(graph, node, now)
        if len(signals) < STALE_HOST_MIN_SIGNALS:
            continue
        subject = host_subject(graph, node, rctx)
        yield Correlation(
            rule=CR25,
            title=f"{node.entity.display} looks stale or unmaintained ({len(signals)} signals)",
            severity=scoped_severity(Severity.MEDIUM, subject),
            description="Signals: " + "; ".join(signals) + "." + _scope_note(subject),
            entities=[node.entity],
            confidence=0.7 if len(signals) > STALE_HOST_MIN_SIGNALS else 0.6,
            evidence=signals + [f"ownership: {subject.reason}"],
            recommendation="Find the owner of the host; decommission it or bring it back under patch and certificate management.",
            tags=["misconfiguration"] + _scope_tags(subject),
            criterion=f"{len(signals)} bad signals (>= {STALE_HOST_MIN_SIGNALS}); security.txt not considered",
        )


# ----------------------------------------------------------------------------------------
# CR26 shadow_it_outlier
# ----------------------------------------------------------------------------------------


def _first(values: Iterable[Any]) -> str:
    for v in values:
        text = str(v or "").strip()
        if text:
            return text
    return ""


def _dimensions(graph: Graph, node: Node) -> dict[str, str]:
    """Infrastructure attributes of an own asset compared across the estate (CR26)."""
    dims: dict[str, str] = {}
    if node.entity.type in _IP_TYPES:
        dims["hosting network"] = _first(node.attr_values("as_org")) or _first(node.attr_values("asn")) or _first(node.attr_values("isp"))
        dims["country"] = _first(node.attr_values("country")).upper()
    else:
        ips = [n for n in adjacent(graph, node.key, "resolves_to") if n.entity.type in _IP_TYPES]
        hosting = sorted({_first(ip.attr_values("as_org")) or _first(ip.attr_values("asn")) for ip in ips} - {""})
        dims["hosting network"] = hosting[0] if len(hosting) == 1 else ""
        ns = sorted({_registrable(n) for n in node.attr_values("nameservers")} - {""})
        dims["DNS provider"] = ns[0] if len(ns) == 1 else ""
        dims["registrar"] = _first(node.attr_values("registrar"))
    dims["certificate issuer"] = _first(node.attr_values("cert_issuer"))
    return {k: v for k, v in dims.items() if v}


@rule(
    CR26,
    "Shadow IT outlier among the organisation's assets",
    "CR26 (P291 cond 9): an own asset whose hosting network, DNS provider, registrar, certificate issuer or country is "
    "shared by <= 10% of the org assets while one value dominates (SpiderFoot-style outlier). Runs only with >= "
    "setting attack_surface_min_assets (default 20) own assets.",
    version="1",
    code="CR26",
    severity="low",
    criterion="attribute value held by <= 10% of >= attack_surface_min_assets own assets, next to a dominant value (>= 50%)",
    references=_REFS_SURFACE,
    attack=("T1190",),
    false_positives="Legitimate exceptions (a regional subsidiary, a marketing SaaS): confirm with the asset owners.",
    fixtures=_fixtures(CR26, "positive_one_asset_on_unusual_hosting", "negative_below_min_assets"),
)
def shadow_it_outlier(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    try:
        minimum = int(setting(rctx, MIN_ASSETS_SETTING, DEFAULT_MIN_ASSETS))
    except (TypeError, ValueError):
        minimum = DEFAULT_MIN_ASSETS
    assets = [
        n for _k, n in sorted(graph.nodes.items())
        if n.entity.type in _HOST_TYPES and not n.noise and host_subject(graph, n, rctx).kind == "own"
    ]
    if len(assets) < max(1, minimum):
        return
    dims = {n.key: _dimensions(graph, n) for n in assets}
    names = sorted({d for values in dims.values() for d in values})
    outliers: dict[str, list[str]] = {}
    for dim in names:
        values = {k: v[dim] for k, v in dims.items() if dim in v}
        if len(values) < OUTLIER_MIN_VALUES:
            continue
        counts = Counter(values.values())
        dominant, top = counts.most_common(1)[0]
        if top / len(values) < DOMINANT_MIN_SHARE:
            continue
        for k, value in sorted(values.items()):
            share = counts[value] / len(values)
            if value != dominant and share <= OUTLIER_MAX_SHARE:
                outliers.setdefault(k, []).append(
                    f"{dim} '{value}' on {counts[value]} of {len(values)} assets (dominant: '{dominant}', {top} of {len(values)})"
                )
    for key in sorted(outliers):
        node = graph.nodes[key]
        reasons = outliers[key]
        yield Correlation(
            rule=CR26,
            title=f"{node.entity.display} is an outlier among the organisation's assets (possible shadow IT)",
            severity=Severity.LOW,
            description="Unusual for this estate: " + "; ".join(reasons) + ". Unmanaged assets often miss patching and monitoring.",
            entities=[node.entity],
            confidence=Confidence.POSSIBLE,
            evidence=reasons + [f"{len(assets)} own assets compared (minimum {minimum})"],
            recommendation="Confirm the asset's owner and that it is covered by patch management, monitoring and the asset inventory.",
            tags=["infrastructure", "own_asset"],
            criterion=f"value shared by <= {int(OUTLIER_MAX_SHARE * 100)}% of {len(assets)} own assets",
        )


# ----------------------------------------------------------------------------------------
# CR31 certificate_san_affiliate
# ----------------------------------------------------------------------------------------


@rule(
    CR31,
    "Certificate SAN affiliates of an organisation domain (INFO)",
    "CR31 (P291 cond 1, 10): other registrable domains named by the certificates of an own or analyst-typed domain "
    "(related organisations, acquisitions, vendor-managed certificates). INFO: affiliates never join the scope.",
    version="1",
    code="CR31",
    severity="info",
    criterion="registrable domains other than the subject's in certificate SANs of the subject (shared CDN certificates excluded)",
    references=_REFS_CT,
    attack=("T1596.003",),
    false_positives="Vendor-managed and multi-tenant certificates list unrelated customers.",
    fixtures=_fixtures(CR31, "positive_affiliates_of_own_domain", "negative_shared_certificate_and_pivot"),
)
def certificate_san_affiliate(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterable[Correlation]:
    unconfirmed = set(getattr(getattr(rctx, "options", None), "unconfirmed_seeds", ()) or ())
    for key in sorted(graph.nodes):
        node = graph.nodes[key]
        if node.entity.type is not EntityType.DOMAIN or node.noise or hostile(node):
            continue
        if not (own_asset(node, rctx) or (node.seed and key not in unconfirmed)):
            continue
        if node.attr_values("shared_cert"):
            continue
        reg = _registrable(node.entity.value)
        names = {str(v).strip().lower() for v in node.attr_values("cert_sans") if isinstance(v, str)}
        for other in adjacent(graph, key, "cert_san"):
            if other.entity.type is EntityType.DOMAIN and not other.noise:
                names.add(str(other.entity.value))
        regs = {r for r in (_registrable(n) for n in names) if r}
        if len(regs) > SAN_SHARED_CERT_DOMAINS:
            continue  # a shared (CDN/hosting) certificate says nothing about affiliation
        affiliates = []
        for r in sorted(regs - {reg}):
            ent = Entity.try_make(EntityType.DOMAIN, r)
            if ent is None:
                continue
            own = owned(ent, rctx)
            if getattr(own, "own", False):
                continue  # already in the profile
            affiliates.append(r)
        if not affiliates:
            continue
        shown = affiliates[:MAX_LISTED]
        yield Correlation(
            rule=CR31,
            title=f"{node.entity.display}: certificates also name {len(affiliates)} other domain(s)",
            severity=Severity.INFO,
            description=(
                f"Certificates of {node.entity.display} list {', '.join(shown)}{' ...' if len(affiliates) > len(shown) else ''}. "
                "They may be related organisations, acquisitions or vendor-managed names: candidates for the org profile, "
                "never added to the scope automatically."
            ),
            entities=[node.entity] + [e for e in (Entity.try_make(EntityType.DOMAIN, r) for r in shown[:10]) if e is not None],
            confidence=Confidence.POSSIBLE,
            evidence=[f"SAN affiliate: {r}" for r in shown],
            recommendation="Review the affiliates with the asset owners; add confirmed ones to the org profile (seeded entries need analyst confirmation).",
            tags=["infrastructure", "third_party"],
            criterion="other registrable domains in the subject's certificate SANs (never joins the scope)",
        )
