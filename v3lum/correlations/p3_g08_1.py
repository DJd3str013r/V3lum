"""Correlation rules of batch p3-G08-1 (G08 vuln_cve): distro backport and vendor VEX checks of
version-inferred CVE matches on hosts.

``p3g081_debian_backport`` (P355 cond 2-4): on a host KNOWN to run Debian (fingerprint/OS, a banner showing
Debian, or the analyst's setting ``debian_security_tracker_assets``) a banner that exposes a Debian package
revision ('OpenSSH_9.2p1 Debian-2+deb12u3', 'PHP/8.2.29-1~deb12u1') is mapped to its source package and
release and compared, with the dpkg algorithm, with the Debian security tracker's fixed version of each
version-inferred CVE of the host. Tracker rows come from the CVE node (``distro_fixes`` with distro
'debian', written by debian_security_tracker or by OSV Debian records) or from the local tracker index
when the opt-in dataset was downloaded (read-only, no network). Then:

* every CVE of a version-inferred finding fixed (or never affected) in the distro package -> the finding is
  suppressed through the named P322 rule ``SUP-distro_backport_fixed`` with the reason 'fixed in distro
  package' (POSSIBLE, ``context_only``: never deleted, analyst overrides win);
* a CVE still open/unfixed in that release -> the finding's confidence is raised one level (two independent
  families: the banner source and the Debian tracker; capped at PROBABLE, it stays version-inferred);
* without a visible distro revision, on a derivative (Ubuntu, Raspbian...) or when the release is not tracked
  any more, nothing changes (the INFO correlation says why when the host is Debian-based).

``p3g081_vex_not_affected`` (P354 cond 3): on a host showing Red Hat Enterprise Linux (OS fingerprint, CPE
or banner), a version-inferred CVE whose Red Hat VEX statement (``csaf_redhat_vex``) says
known_not_affected for every matching product (component seen on the host, same RHEL major when known)
lowers the finding one level through the named rule ``vex_not_affected`` - context, never a deletion.

Both rules only read the graph (and the local index), never schedule modules or contact anything.
Limitation (core request): CR15/CR16 of the attack_surface pack read CVEs from has_vuln edges and
attributes too; per-CVE suppression there needs a core hook (see docs/backlog/p3-G08-1.md).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity
from v3lum.modules.vulnerability_cve.cve_record import normalize_cve_id
from v3lum.modules.vulnerability_cve.debian_security_tracker import (
    ASSETS_SETTING,
    BACKPORT_SETTING,
    DEBIAN_RELEASES,
    RAISE_RULE,
    SUPPRESSION_REASON,
    SUPPRESSION_RULE,
    backport_verdict,
    debian_applicable,
    lookup_cve,
    open_index,
    parse_debian_banner,
    repo_versions,
    rows_from_distro_fixes,
)

DEBIAN_RULE_ID = "p3g081_debian_backport"
VEX_RULE_ID = "p3g081_vex_not_affected"
VEX_RULE = "vex_not_affected"
HOST_TYPES = (EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN)
#: host attributes that may carry service banners, server headers or software facts
BANNER_ATTRIBUTES = ("services", "software_hints", "server", "technologies", "banners", "x_powered_by", "http_server")
MAX_BANNERS = 200
CONTEXT_ONLY = "context_only"
DECISIVE = ("fixed", "not_affected", "unfixed")

# --------------------------------------------------------------------------------------
# shared graph helpers
# --------------------------------------------------------------------------------------

_DISTRO_VERSION_RE = re.compile(r"^(\S+)\s+(Debian|Ubuntu|Raspbian)[ -](\S+)$")


def _flat(values: Iterable[Any]) -> Iterable[Any]:
    for value in values:
        if isinstance(value, (list, tuple)):
            yield from value
        else:
            yield value


def host_banners(node: Node) -> list[str]:
    """Banner-like strings of a host node: raw banners, server headers and product/version pairs (Shodan's
    'OpenSSH' + '9.2p1 Debian 2+deb12u3' becomes 'OpenSSH_9.2p1 Debian-2+deb12u3')."""
    out: list[str] = []

    def add(text: Any) -> None:
        if isinstance(text, str) and text.strip() and len(out) < MAX_BANNERS:
            value = text.strip()[:512]
            if value not in out:
                out.append(value)

    for name in BANNER_ATTRIBUTES:
        for item in _flat(node.attr_values(name)):
            if isinstance(item, str):
                add(item)
                continue
            if not isinstance(item, Mapping):
                continue
            for key in ("banner", "data", "raw", "display", "server", "http_server", "x_powered_by"):
                add(item.get(key))
            product, version = item.get("product"), item.get("version")
            if isinstance(product, str) and isinstance(version, str) and product and version:
                add(f"{product}/{version}")
                low = product.lower()
                match = _DISTRO_VERSION_RE.match(version.strip())
                if low == "openssh" and match:
                    add(f"OpenSSH_{match.group(1)} {match.group(2)}-{match.group(3)}")
                elif low == "openssh":
                    add(f"OpenSSH_{version.strip()}")
                elif low.startswith("php"):
                    add(f"PHP/{version.strip()}")
    return out


def finding_cves(f: Finding) -> list[str]:
    data = f.data if isinstance(f.data, Mapping) else {}
    raw: list[Any] = [data.get("cve")] + list(data.get("cves") or [])
    for item in data.get("vulns") or []:
        raw.append(item.get("cve") if isinstance(item, Mapping) else item)
    out: list[str] = []
    for value in raw:
        cve = normalize_cve_id(value) if isinstance(value, str) else None
        if cve and cve not in out:
            out.append(cve)
    return out


def version_inferred_cves(graph: Graph, node: Node) -> list[str]:
    """CVEs of a host that rest on a version match: version-inferred findings, has_vuln edges and the 'vulns'
    attribute, minus the CVEs a source verified (vulns_verified)."""
    verified = {c for c in (normalize_cve_id(v) for v in _flat(node.attr_values("vulns_verified")) if isinstance(v, str)) if c}
    out: list[str] = []
    candidates: list[str] = []
    for f in node.findings:
        if "version_inferred" in (f.tags or ()):
            candidates.extend(finding_cves(f))
    for edge in graph.out_edges(node.key, "has_vuln") if hasattr(graph, "out_edges") else []:
        dst = graph.get(edge.dst)
        if dst is not None and dst.entity.type is EntityType.CVE:
            candidates.append(dst.entity.value)
    candidates.extend(v for v in _flat(node.attr_values("vulns")) if isinstance(v, str))
    for value in candidates:
        cve = normalize_cve_id(value)
        if cve and cve not in verified and cve not in out:
            out.append(cve)
    return out


def _setting(rctx: Any, name: str, default: Any) -> Any:
    try:
        return rctx.setting(name, default) if rctx is not None else default
    except Exception:  # noqa: BLE001 - an unreadable setting falls back to its default
        return default


def _declared_assets(value: Any) -> dict[str, str]:
    """Setting debian_security_tracker_assets: ['203.0.113.5', 'srv.example.com=bookworm'] -> {host: codename}."""
    items = value if isinstance(value, (list, tuple)) else (str(value).split(",") if isinstance(value, str) else [])
    out: dict[str, str] = {}
    for item in items:
        if not isinstance(item, str) or not item.strip():
            continue
        host, _, release = item.strip().partition("=")
        release = release.strip().lower()
        out[host.strip().lower()] = DEBIAN_RELEASES.get(release, release) if release else ""
    return out


def _cve_node(graph: Graph, cve: str) -> Node | None:
    return graph.get(f"cve:{cve}")


def _apply_finding(f: Finding, cves: list[str], verdicts: dict[str, str], *, lower_rule: str, lower_reason: str,
                   suppress: bool, raise_rule: str | None, families: set[str], detail_key: str, detail: dict[str, Any]) -> str | None:
    """Annotate one version-inferred finding; suppress/lower it when every CVE it lists is lowered, raise it
    (+1, capped at PROBABLE) when one is confirmed unfixed. Returns the action taken or None."""
    if isinstance(f.data, dict):
        f.data[detail_key] = detail
    lowered = [c for c in cves if verdicts.get(c) in ("fixed", "not_affected")]
    unfixed = [c for c in cves if verdicts.get(c) == "unfixed"]
    if unfixed and raise_rule:
        if f.upgraded_by or f.label is not Confidence.POSSIBLE:
            return None  # once per finding; capped at PROBABLE (still version-inferred)
        f.upgrade(families, raise_rule, f"distro package not fixed for {', '.join(unfixed[:5])}")
        return "raised" if f.upgraded_by else None
    if lowered and len(lowered) == len(cves):
        if any(isinstance(s, dict) and s.get("rule") == lower_rule for s in f.suppressed_by):
            return None
        f.downgrade(lower_rule, lower_reason, to=Confidence.POSSIBLE if suppress else None)
        if suppress and not f.override and CONTEXT_ONLY not in f.tags:
            f.tags.append(CONTEXT_ONLY)
        return "suppressed" if suppress else "lowered"
    return None


# --------------------------------------------------------------------------------------
# P355: Debian backport check
# --------------------------------------------------------------------------------------


def _tracker_rows(graph: Graph, cve: str, con: Any) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    node = _cve_node(graph, cve)
    if node is not None:
        for row in rows_from_distro_fixes(cve, _flat(node.attr_values("distro_fixes"))):
            rows[(row["package"], row["release"])] = row
    if con is not None:
        for row in lookup_cve(con, cve):
            rows[(row["package"], row["release"])] = row  # the local tracker copy wins
    return list(rows.values())


def debian_host_check(graph: Graph, node: Node, declared: dict[str, str], con: Any) -> dict[str, Any] | None:
    """Backport verdicts of one host, or None when the host is not known to run a Debian-based system."""
    banners = host_banners(node)
    os_text = " ".join(str(v) for v in _flat(node.attr_values("host_os")) if isinstance(v, str))
    host = str(node.entity.value).lower()
    analyst = host in declared
    applicable = debian_applicable({"analyst_os": "debian" if analyst else "", "os": os_text, "banners": banners})
    if not applicable["applicable"]:
        return None
    infos = []
    for banner in banners:
        info = parse_debian_banner(banner)
        if info and info not in infos:
            if analyst and declared.get(host) and not info.get("release"):
                info = dict(info, release=declared[host])
            infos.append(info)
    cves = version_inferred_cves(graph, node)
    verdicts: dict[str, dict[str, Any]] = {}
    for cve in cves:
        rows = _tracker_rows(graph, cve, con)
        best: dict[str, Any] | None = None
        for info in infos:
            verdict = backport_verdict(info, cve, rows, repo_versions(con, info.get("source_package")))
            rank = {"unfixed": 3, "fixed": 2, "not_affected": 2}.get(verdict["verdict"], 0)
            if best is None or rank > {"unfixed": 3, "fixed": 2, "not_affected": 2}.get(best["verdict"], 0):
                best = verdict
        if best is not None and best["verdict"] not in ("not_in_tracker",):
            verdicts[cve] = best
    return {"applicable": applicable, "infos": infos, "cves": cves, "verdicts": verdicts}


@rule(
    DEBIAN_RULE_ID,
    "Debian backport check of version-inferred CVEs",
    "On a host known to run Debian, a banner exposing a Debian package revision is compared (dpkg algorithm) with the "
    "Debian security tracker's fixed version of each version-inferred CVE: fixed in the distro package -> the finding is "
    "suppressed through SUP-distro_backport_fixed ('fixed in distro package'); still open -> confidence +1 (capped at "
    "PROBABLE). Without a visible distro revision nothing changes (P355 cond 2-4).",
    version="1",
    severity="info",
    criterion="Debian-based host + banner with a Debian package revision + Debian tracker status of the CVE for that release",
    references=("https://security-tracker.debian.org/tracker/", "https://www.debian.org/doc/debian-policy/ch-controlfields.html#version"),
    false_positives="A banner can be edited or shared by a proxy; backports of other packages on the host are not visible.",
    fixtures=(
        f"tests/fixtures/rules/{DEBIAN_RULE_ID}/positive_fixed_in_distro_package_suppressed.json",
        f"tests/fixtures/rules/{DEBIAN_RULE_ID}/positive_unfixed_raises_confidence.json",
        f"tests/fixtures/rules/{DEBIAN_RULE_ID}/negative_no_distro_revision_nothing_changes.json",
        f"tests/fixtures/rules/{DEBIAN_RULE_ID}/negative_not_debian_based.json",
    ),
)
def debian_backport(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    if not _setting(rctx, BACKPORT_SETTING, True):
        return
    declared = _declared_assets(_setting(rctx, ASSETS_SETTING, []))
    con = open_index()
    try:
        for key in sorted(graph.nodes):
            node: Any = graph.nodes[key]
            if node.entity.type not in HOST_TYPES or getattr(node, "noise", False):
                continue
            check = debian_host_check(graph, node, declared, con)
            if check is None or not check["verdicts"]:
                continue
            verdicts = {c: v["verdict"] for c, v in check["verdicts"].items()}
            exact = check["applicable"]["exact"]
            actions: list[str] = []
            touched: list[str] = []
            if exact:
                for f in node.findings:
                    if "version_inferred" not in (f.tags or ()):
                        continue
                    cves = finding_cves(f) or [c for c in check["cves"] if c in verdicts]
                    detail = {"distro": "debian",
                              "fixed": sorted(c for c in cves if verdicts.get(c) == "fixed"),
                              "not_affected": sorted(c for c in cves if verdicts.get(c) == "not_affected"),
                              "unfixed": sorted(c for c in cves if verdicts.get(c) == "unfixed"),
                              "unknown": sorted(c for c in cves if verdicts.get(c) not in DECISIVE)}
                    action = _apply_finding(f, cves, verdicts, lower_rule=SUPPRESSION_RULE, lower_reason=SUPPRESSION_REASON, suppress=True,
                                            raise_rule=RAISE_RULE, families={str(f.module or "banner"), "debian_security_tracker"},
                                            detail_key="distro_backport", detail=detail)
                    if action:
                        actions.append(action)
                        touched.append(f.id or f.title)
            fixed = sorted(c for c, v in verdicts.items() if v in ("fixed", "not_affected"))
            unfixed = sorted(c for c, v in verdicts.items() if v == "unfixed")
            if not fixed and not unfixed and not touched:
                continue
            lines = [f"{c}: {v['verdict']} - {v['detail']}" for c, v in sorted(check["verdicts"].items())][:40]
            evidence_src = check["applicable"]["evidence"]
            if not exact:
                lines.insert(0, f"{check['applicable']['distro']} host: Debian fixed versions shown as context only, nothing changed")
            title = (f"Debian backport check: {len(fixed)} version-inferred CVE(s) fixed in the distro package"
                     if fixed else f"Debian backport check: {len(unfixed)} version-inferred CVE(s) still unfixed in the distro package")
            yield Correlation(
                rule=DEBIAN_RULE_ID,
                title=title,
                severity=Severity.INFO,
                description=(f"{node.entity.display} runs Debian ({evidence_src}). Fixed or never affected in the distro package: "
                             f"{', '.join(fixed[:10]) or 'none'}; still open: {', '.join(unfixed[:10]) or 'none'}. "
                             f"Findings adjusted: {len(touched)} ({', '.join(sorted(set(actions))) or 'none'})."),
                entities=[node.entity],
                confidence="probable",
                evidence=lines,
                recommendation=("Treat the suppressed CVEs as fixed by the distribution (backported patch); patch the still-open "
                                "packages through the Debian security archive."),
                tags=[CONTEXT_ONLY],
                criterion=f"Debian package revision in a banner ({len(check['infos'])} package(s)) vs the Debian security tracker "
                          f"(dpkg comparison); named rules {SUPPRESSION_RULE} / {RAISE_RULE}",
                why="distro backport",
            )
    finally:
        if con is not None:
            con.close()


# --------------------------------------------------------------------------------------
# P354 cond 3: Red Hat VEX not_affected lowers a version-based match
# --------------------------------------------------------------------------------------

_EL_RE = re.compile(r"\.el(\d{1,2})(?:_\d+)?\b")
_RHEL_OS_RE = re.compile(r"(?:red\s*hat\s+enterprise\s+linux|\brhel\b)\D{0,12}(\d{1,2})?", re.I)
_RHEL_CPE_RE = re.compile(r"cpe:(?:/|2\.3:)[ao]:redhat:enterprise_linux:(\d{1,2})")
#: banner product tokens -> Red Hat source/binary component names used in VEX
_COMPONENTS = (
    (re.compile(r"openssh", re.I), "openssh"),
    (re.compile(r"\bapache(?:/| httpd)|\bhttpd\b", re.I), "httpd"),
    (re.compile(r"\bnginx\b", re.I), "nginx"),
    (re.compile(r"\bphp\b|php/", re.I), "php"),
    (re.compile(r"openssl", re.I), "openssl"),
    (re.compile(r"\bmariadb\b|\bmysql\b", re.I), "mariadb"),
    (re.compile(r"\bpostfix\b", re.I), "postfix"),
    (re.compile(r"\bdovecot\b", re.I), "dovecot"),
    (re.compile(r"\bvsftpd\b", re.I), "vsftpd"),
    (re.compile(r"\bbind\b|\bnamed\b", re.I), "bind"),
    (re.compile(r"\bsquid\b", re.I), "squid"),
    (re.compile(r"\btomcat\b", re.I), "tomcat"),
)


def redhat_host(node: Node) -> dict[str, Any] | None:
    """Red Hat evidence of a host: {'major': '8' | None, 'components': [...], 'evidence': ...} or None."""
    banners = host_banners(node)
    os_text = " ".join(str(v) for v in _flat(node.attr_values("host_os")) if isinstance(v, str))
    cpes = [str(c) for c in _flat(node.attr_values("cpes")) if isinstance(c, str)]
    major, evidence = None, None
    match = _RHEL_OS_RE.search(os_text)
    if match:
        major, evidence = match.group(1), "fingerprint"
    for cpe in cpes:
        found = _RHEL_CPE_RE.search(cpe)
        if found:
            major, evidence = major or found.group(1), evidence or "cpe"
    for banner in banners:
        if re.search(r"\(Red Hat(?: Enterprise Linux)?\)", banner):
            evidence = evidence or "banner"
        el = _EL_RE.search(banner)
        if el:
            major, evidence = major or el.group(1), evidence or "banner"
    if evidence is None:
        return None
    components = []
    for banner in banners:
        for pattern, name in _COMPONENTS:
            if pattern.search(banner) and name not in components:
                components.append(name)
    return {"major": major, "components": components, "evidence": evidence}


def _vex_statuses(graph: Graph, results: list[ModuleResult], cve: str) -> list[dict[str, Any]]:
    """Red Hat VEX statuses of a CVE: the module evidence (up to 200 with platform CPE) or the attribute."""
    out: list[dict[str, Any]] = []
    for res in results or []:
        if getattr(res, "module", "") != "csaf_redhat_vex" or getattr(getattr(res, "entity", None), "value", None) != cve:
            continue
        raw = res.raw if isinstance(res.raw, Mapping) else {}
        out.extend(s for s in raw.get("statuses") or [] if isinstance(s, Mapping))
    node = _cve_node(graph, cve)
    if not out and node is not None:
        for value in _flat(node.attr_values("vex_statuses")):
            if isinstance(value, Mapping) and value.get("vendor") == "redhat":
                out.extend(s for s in value.get("products") or [] if isinstance(s, Mapping))
    return out


def vex_verdict(statuses: list[Mapping[str, Any]], components: list[str], major: str | None) -> dict[str, Any] | None:
    matching = []
    for status in statuses:
        if str(status.get("component") or "").lower() not in components:
            continue
        cpe = str(status.get("platform_cpe") or "")
        platform = str(status.get("platform") or "")
        if major and cpe and not re.search(rf"enterprise_linux:{major}\b", cpe) and f" {major}" not in platform:
            continue
        matching.append(status)
    if not matching:
        return None
    kinds = {s.get("status") for s in matching}
    first = matching[0]
    where = " ".join(str(x) for x in (first.get("platform"), first.get("component")) if x)
    if kinds == {"not_affected"}:
        return {"verdict": "not_affected", "detail": f"VEX known_not_affected (Red Hat, {first.get('justification') or 'no justification given'}): {where}"}
    if "affected" in kinds:
        return {"verdict": "affected", "detail": f"VEX known_affected (Red Hat): {where}"}
    if "fixed" in kinds:
        return {"verdict": "fixed_in_errata", "detail": f"VEX fixed (Red Hat): {where}"}
    return {"verdict": "under_investigation", "detail": f"VEX under_investigation (Red Hat): {where}"}


@rule(
    VEX_RULE_ID,
    "Red Hat VEX not_affected lowers a version-inferred CVE match",
    "On a host showing Red Hat Enterprise Linux, a version-inferred CVE whose Red Hat VEX statement says known_not_affected "
    "for every product matching the host's components (same RHEL major when known) lowers the finding one level through "
    "the named rule vex_not_affected: context, never a deletion (P354 cond 3).",
    version="1",
    severity="info",
    criterion="RHEL host (OS fingerprint, CPE or banner) + component seen in a banner + Red Hat VEX known_not_affected",
    references=("https://security.access.redhat.com/data/csaf/v2/vex/",),
    false_positives="A component installed outside the RHEL packages (vendor build, container) is not covered by Red Hat's VEX.",
    fixtures=(
        f"tests/fixtures/rules/{VEX_RULE_ID}/positive_not_affected_lowers_match.json",
        f"tests/fixtures/rules/{VEX_RULE_ID}/negative_affected_stays.json",
        f"tests/fixtures/rules/{VEX_RULE_ID}/negative_not_red_hat.json",
    ),
)
def vex_not_affected(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for key in sorted(graph.nodes):
        node: Any = graph.nodes[key]
        if node.entity.type not in HOST_TYPES or getattr(node, "noise", False):
            continue
        host = redhat_host(node)
        if host is None or not host["components"]:
            continue
        verdicts: dict[str, dict[str, Any]] = {}
        for cve in version_inferred_cves(graph, node):
            verdict = vex_verdict(_vex_statuses(graph, results, cve), host["components"], host["major"])
            if verdict:
                verdicts[cve] = verdict
        lowered_cves = sorted(c for c, v in verdicts.items() if v["verdict"] == "not_affected")
        if not lowered_cves:
            continue
        simple = {c: ("not_affected" if v["verdict"] == "not_affected" else v["verdict"]) for c, v in verdicts.items()}
        touched = []
        for f in node.findings:
            if "version_inferred" not in (f.tags or ()):
                continue
            cves = finding_cves(f) or [c for c in simple]
            detail = {"vendor": "redhat", "not_affected": sorted(c for c in cves if simple.get(c) == "not_affected"),
                      "other": sorted(c for c in cves if simple.get(c) not in (None, "not_affected"))}
            reason = f"Red Hat VEX known_not_affected for {', '.join(lowered_cves[:5])} on RHEL {host['major'] or '?'}"
            if _apply_finding(f, cves, simple, lower_rule=VEX_RULE, lower_reason=reason, suppress=False, raise_rule=None,
                              families=set(), detail_key="vex", detail=detail):
                touched.append(f.id or f.title)
        yield Correlation(
            rule=VEX_RULE_ID,
            title=f"Red Hat VEX: {len(lowered_cves)} version-inferred CVE(s) not affecting this RHEL host's packages",
            severity=Severity.INFO,
            description=(f"{node.entity.display} shows Red Hat Enterprise Linux {host['major'] or ''} ({host['evidence']}); Red Hat's VEX "
                         f"says known_not_affected for {', '.join(lowered_cves[:10])} ({', '.join(host['components'])}). "
                         f"Findings lowered: {len(touched)} (never deleted)."),
            entities=[node.entity],
            confidence="probable",
            evidence=[f"{c}: {v['detail']}" for c, v in sorted(verdicts.items())][:40],
            recommendation="Confirm the installed package source (RHEL repositories) before closing the version-based match.",
            tags=[CONTEXT_ONLY],
            criterion=f"Red Hat VEX known_not_affected for the host's components; named rule {VEX_RULE}",
            why="vendor VEX",
        )
