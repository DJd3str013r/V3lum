"""Correlation rules of batch p1-G12-1 (file analysis).

* ``g12_apk_dal_cert_mismatch`` (P364 c6, reference source 'P008 Digital Asset Links results already in
  the case'): an APK analysed by ``apk_triage`` declares the package name of an official Android app that
  an investigated domain lists in its Digital Asset Links statements (attribute ``official_android_apps``
  of ``digital_asset_links``), but none of the APK's signing certificates is one the domain declares for
  that package: a repackaged or impersonating app (HIGH, 'suspicious'; certificate digests are compared,
  signatures are never verified). A matching certificate stays silent (the module itself reports
  official-certificate matches it can see). The rule only reads the graph: it makes no request, never
  fetches an assetlinks.json and changes nothing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_DAL_MISMATCH = "g12_apk_dal_cert_mismatch"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")


def cert_hex(value: Any) -> str | None:
    """A SHA-256 certificate digest as 64 lower-case hex characters ('AA:BB:...' and bare hex accepted)."""
    if not isinstance(value, str):
        return None
    h = value.strip().replace(":", "").lower()
    return h if _HEX64.fullmatch(h) else None


def apk_facts(node: Any) -> tuple[str | None, set[str]]:
    """(package, {signing-certificate sha256}) of a FILE node analysed by apk_triage."""
    package = next((v for v in node.attr_values("android_package") if isinstance(v, str) and _PACKAGE.fullmatch(v)), None)
    certs: set[str] = set()
    for value in node.attr_values("apk_signing"):
        if not isinstance(value, Mapping):
            continue
        for cert in value.get("certificates") or []:
            h = cert_hex(cert.get("sha256")) if isinstance(cert, Mapping) else None
            if h:
                certs.add(h)
    return package, certs


def official_apps(node: Any) -> dict[str, set[str]]:
    """{package: {sha256}} a domain node declares (attribute official_android_apps of digital_asset_links)."""
    out: dict[str, set[str]] = {}
    for value in node.attr_values("official_android_apps"):
        for app in value if isinstance(value, list) else [value]:
            if not isinstance(app, Mapping) or not isinstance(app.get("package"), str):
                continue
            certs = {h for h in (cert_hex(fp) for fp in app.get("sha256") or []) if h}
            if certs:
                out.setdefault(app["package"], set()).update(certs)
    return out


@rule(
    RULE_DAL_MISMATCH,
    "APK reuses an official app's package name with a different signing certificate",
    "An analysed APK declares the package name of an official Android app listed in the Digital Asset Links "
    "statements of an investigated domain, but it is signed with a certificate the domain does not declare for "
    "that app: a repackaged or impersonating app (P364 c6).",
    severity="high",
    criterion="android_package of the APK equals a package in official_android_apps of a domain and no APK signing-certificate "
              "SHA-256 is among the certificates the domain declares for it",
    false_positives="An official app re-signed after a key rotation that the domain's assetlinks.json does not list yet, or a "
                    "debug/test build of the official app (digests only: signatures are not verified).",
    fixtures=(
        f"tests/fixtures/rules/{RULE_DAL_MISMATCH}/positive_package_reused.json",
        f"tests/fixtures/rules/{RULE_DAL_MISMATCH}/negative_official_certificate.json",
        f"tests/fixtures/rules/{RULE_DAL_MISMATCH}/negative_other_package.json",
    ),
)
def g12_apk_dal_cert_mismatch(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    declared: dict[str, dict[str, set[str]]] = {}
    for node in graph.of_type(EntityType.DOMAIN):
        for package, certs in official_apps(node).items():
            declared.setdefault(package, {}).setdefault(node.key, set()).update(certs)
    if not declared:
        return
    for node in graph.of_type(EntityType.FILE):
        package, certs = apk_facts(node)
        if not package or not certs or package not in declared:
            continue
        by_domain = declared[package]
        official = set().union(*by_domain.values())
        if certs & official:
            continue
        domains = [graph.get(key) for key in sorted(by_domain)]
        entities = [node.entity] + [d.entity for d in domains if d is not None]
        shown = ", ".join(d.entity.display for d in domains if d is not None)
        yield Correlation(
            rule=RULE_DAL_MISMATCH,
            title="APK reuses an official app's package name with a different signing certificate",
            severity=Severity.HIGH,
            description=f"The APK declares package {package}, which {shown} lists as its official Android app (Digital Asset "
                        f"Links), but it is signed with {', '.join(sorted(certs))[:200]} instead of a declared certificate: "
                        "suspicious repackaged or impersonating app. Digests only: signatures are not verified.",
            entities=entities,
            confidence="probable",
            evidence=[f"{node.key}: package {package}, certificates {', '.join(sorted(certs))[:200]}"]
                     + [f"{key}: official certificates {', '.join(sorted(c))[:200]}" for key, c in sorted(by_domain.items())],
            recommendation="Treat the APK as a suspected impersonation of the official app: do not install it, hash-check it "
                           "against malware sources and report the distribution channel to the brand owner.",
            tags=["brand_abuse", "suspicious"],
            criterion=f"package {package} declared by {len(by_domain)} domain(s) with other signing certificates",
            key=f"{node.key}|{package}",
        )
