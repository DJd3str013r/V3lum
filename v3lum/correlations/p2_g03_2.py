"""Correlation rules of batch p2-G03-2 (P346 mobile_app_impersonation).

* ``mobile_app_apk_official_cert`` (P346 c4): an analyst-provided APK parsed by ``apk_triage`` (attributes
  ``android_package`` and ``apk_signing``) whose package is an official Android app of the organisation -
  listed in Digital Asset Links (attribute ``official_android_apps`` of ``digital_asset_links``, or the
  ``official_apps`` known_good list of ``mobile_app_impersonation``). Signed with an official certificate:
  INFO 'official certificate'; signed with another certificate: LOW 'needs analyst review' (possible
  repackaged app, c7: never 'malicious').
* ``mobile_app_apk_link`` (P346 c8): ``.apk`` URLs found on pages or in pasted messages are listed as url
  entities only (INFO); nothing downloads them automatically - obtain the file by hand in an isolated
  environment and run ``apk_triage`` offline.

Both rules only read the graph; they make no network call and change nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.domain_dns.digital_asset_links import normalize_cert_sha256
from v3lum.modules.url_web.mobile_app_impersonation import is_apk_url

RULE_APK_CERT = "mobile_app_apk_official_cert"
RULE_APK_LINK = "mobile_app_apk_link"
MAX_LINKS_LISTED = 20


def official_android_certs(graph: Graph) -> dict[str, dict[str, Any]]:
    """{package (lower-case): {"certs": set of 'AA:BB:..' fingerprints, "nodes": [keys]}} from every node's
    ``official_android_apps`` (P008) and ``official_apps`` android entries (P346)."""
    out: dict[str, dict[str, Any]] = {}

    def add(node: Any, pkg: Any, fps: Any) -> None:
        if not isinstance(pkg, str) or not pkg:
            return
        entry = out.setdefault(pkg.lower(), {"certs": set(), "nodes": []})
        for fp in fps if isinstance(fps, list) else [fps]:
            norm = normalize_cert_sha256(fp)
            if norm:
                entry["certs"].add(norm)
        if node.key not in entry["nodes"]:
            entry["nodes"].append(node.key)

    for node in graph.of_type(EntityType.DOMAIN, EntityType.ORG, EntityType.KEYWORD):
        for value in node.attr_values("official_android_apps"):
            for app in value if isinstance(value, list) else [value]:
                if isinstance(app, Mapping):
                    add(node, app.get("package"), app.get("sha256") or [])
        for value in node.attr_values("official_apps"):
            for app in value if isinstance(value, list) else [value]:
                if isinstance(app, Mapping) and app.get("store") == "android" and app.get("cert_sha256"):
                    add(node, app.get("bundle_id") or app.get("package"), app.get("cert_sha256"))
    return out


def apk_facts(graph: Graph, node: Any) -> tuple[str | None, set[str]]:
    """(package, signing-certificate fingerprints) of a file node analysed by apk_triage."""
    package = None
    for value in node.attr_values("android_package"):
        if isinstance(value, str) and value:
            package = value
            break
    certs: set[str] = set()
    for value in node.attr_values("apk_signing"):
        for cert in (value.get("certificates") if isinstance(value, Mapping) else None) or []:
            norm = normalize_cert_sha256(cert.get("sha256")) if isinstance(cert, Mapping) else None
            if norm:
                certs.add(norm)
    for edge in graph.out_edges(node.key, "signing_certificate"):
        target = graph.get(edge.dst)
        norm = normalize_cert_sha256(target.entity.value) if target is not None else None
        if norm:
            certs.add(norm)
    if package is None:
        for edge in graph.out_edges(node.key, "android_package"):
            target = graph.get(edge.dst)
            if target is not None and target.entity.type is EntityType.KEYWORD:
                package = str(target.entity.value)
                break
    return package, certs


@rule(
    RULE_APK_CERT,
    "APK signing certificate vs the organisation's official app",
    "An analyst-provided APK uses the package name of an official Android app of the organisation (Digital Asset "
    "Links): its apk_triage signing certificate either matches an official certificate or differs from all of them "
    "(possible repackaged app for analyst review; P346 c4, c7).",
    severity="low",
    criterion="apk_triage package name equals an official Android package (Digital Asset Links) and its signing-certificate "
              "SHA-256 is compared with the official fingerprints",
    false_positives="An official build signed with a key the site has not (yet) published in assetlinks.json, or an "
                    "upload key that differs from the Play App Signing key: confirm with the app owner.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_APK_CERT}/positive_other_certificate.json",
        f"tests/fixtures/rules/{RULE_APK_CERT}/positive_official_certificate.json",
        f"tests/fixtures/rules/{RULE_APK_CERT}/negative_unlisted_package.json",
    ),
)
def mobile_app_apk_official_cert(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    official = official_android_certs(graph)
    if not official:
        return
    for node in graph.of_type(EntityType.FILE):
        package, certs = apk_facts(graph, node)
        if not package or package.lower() not in official or not certs:
            continue
        ref = official[package.lower()]
        if not ref["certs"]:
            continue  # the package is listed without a certificate: nothing to compare
        sources = [graph.get(k) for k in ref["nodes"]]
        entities = [node.entity] + [n.entity for n in sources if n is not None]
        shown = ", ".join(sorted(c[:23] + "..." for c in certs)[:3])
        if certs & ref["certs"]:
            yield Correlation(
                rule=RULE_APK_CERT,
                title="APK signed with the official certificate of the organisation's app",
                severity=Severity.INFO,
                description=f"The APK declares package {package} and is signed with an official certificate listed in Digital "
                            "Asset Links: consistent with the organisation's official app (signature itself not verified).",
                entities=entities,
                confidence="probable",
                evidence=[f"package {package}", f"certificates {shown}"],
                recommendation="Treat as the official app unless other evidence (download origin, permissions) disagrees.",
                tags=["known_good"],
                criterion=f"package {package} listed in Digital Asset Links with a matching signing certificate",
                key=f"official:{node.key}",
            )
            continue
        yield Correlation(
            rule=RULE_APK_CERT,
            title="APK uses an official package name with another signing certificate (needs analyst review)",
            severity=Severity.LOW,
            description=f"The APK declares the official package {package} but none of its signing certificates ({shown}) is "
                        "listed in the organisation's Digital Asset Links: a possible repackaged or impersonating app. "
                        "Needs analyst review; this is not a malware verdict.",
            entities=entities,
            confidence="possible",
            evidence=[f"package {package}", f"APK certificates {shown}",
                      f"{len(ref['certs'])} official certificate(s) from {', '.join(ref['nodes'][:3])}"],
            recommendation="Confirm the download origin and compare the certificate with the app owner; if confirmed, "
                           "report the distribution site and the store listing for takedown.",
            tags=["lookalike_app"],
            criterion=f"package {package} listed in Digital Asset Links; APK certificate not among the official fingerprints",
            key=f"mismatch:{node.key}",
        )


@rule(
    RULE_APK_LINK,
    "APK download links recorded (never downloaded automatically)",
    "URLs of .apk files found on pages or in pasted messages are listed as url entities only: V3LUM never downloads "
    "them automatically (P346 c8).",
    severity="info",
    criterion="URL path, or a query value, ends with '.apk'",
    false_positives="Links to official APK mirrors of legitimate vendors.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_APK_LINK}/positive_apk_links.json",
        f"tests/fixtures/rules/{RULE_APK_LINK}/negative_no_apk.json",
    ),
)
def mobile_app_apk_link(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    nodes = sorted((n for n in graph.of_type(EntityType.URL) if is_apk_url(str(n.entity.value))), key=lambda n: n.key)
    if not nodes:
        return
    listed = nodes[:MAX_LINKS_LISTED]
    more = f" ({len(nodes) - len(listed)} more not listed)" if len(nodes) > len(listed) else ""
    yield Correlation(
        rule=RULE_APK_LINK,
        title="APK download links recorded (never downloaded automatically)",
        severity=Severity.INFO,
        description=f"{len(nodes)} .apk link(s) found in the case{more}. They are recorded as url entities only and are never "
                    "downloaded by V3LUM.",
        entities=[n.entity for n in listed],
        confidence="confirmed",
        evidence=[n.key for n in listed],
        recommendation="If the file is needed, obtain it by hand in an isolated environment and run apk_triage offline; "
                       "compare its package and signing certificate with the organisation's official apps.",
        tags=["apk_link"],
        criterion="URL path or query value ending with '.apk'",
        key="apk_links",
    )
