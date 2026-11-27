"""Correlation rules of batch p2-G01-1.

* ``dal_shared_signing_cert`` (P008 cond 2): two or more investigated domains whose Digital Asset Links
  statements (attribute ``official_android_apps`` of ``digital_asset_links``) name an Android app signed
  with the same certificate: an organisation-asset link (INFO). One signing certificate across the apps
  of a single site is reported by the module itself; this rule links the domains. It only reads the
  graph, makes no network call and changes nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_SHARED_CERT = "dal_shared_signing_cert"


def signing_certs(node: Any) -> dict[str, list[str]]:
    """{SHA-256 fingerprint: [packages]} declared by one domain node (attribute official_android_apps)."""
    out: dict[str, list[str]] = {}
    for value in node.attr_values("official_android_apps"):
        for app in value if isinstance(value, list) else [value]:
            if not isinstance(app, Mapping) or not isinstance(app.get("package"), str):
                continue
            for fp in app.get("sha256") or []:
                if isinstance(fp, str) and len(fp) == 95:
                    out.setdefault(fp.upper(), [])
                    if app["package"] not in out[fp.upper()]:
                        out[fp.upper()].append(app["package"])
    return out


@rule(
    RULE_SHARED_CERT,
    "Domains share an Android app signing certificate",
    "Several investigated domains declare (Digital Asset Links) Android apps signed with the same certificate: the sites "
    "and apps belong to one organisation (P008 cond 2).",
    severity="info",
    criterion="the same SHA-256 signing-certificate fingerprint in the official_android_apps attribute of two or more domains",
    false_positives="A platform or agency that signs apps for several clients with one key (rare: Play App Signing uses a key per app).",
    fixtures=(
        f"tests/fixtures/rules/{RULE_SHARED_CERT}/positive_two_domains.json",
        f"tests/fixtures/rules/{RULE_SHARED_CERT}/negative_distinct_certificates.json",
    ),
)
def dal_shared_signing_cert(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    by_cert: dict[str, dict[str, list[str]]] = {}
    for node in graph.of_type(EntityType.DOMAIN):
        for fp, packages in signing_certs(node).items():
            by_cert.setdefault(fp, {})[node.key] = packages
    for fp, domains in sorted(by_cert.items()):
        if len(domains) < 2:
            continue
        nodes = [graph.get(key) for key in sorted(domains)]
        entities = [n.entity for n in nodes if n is not None]
        shown = "; ".join(f"{n.entity.display}: {', '.join(domains[n.key][:5])}" for n in nodes if n is not None)
        yield Correlation(
            rule=RULE_SHARED_CERT,
            title="Domains share an Android app signing certificate",
            severity=Severity.INFO,
            description=f"The signing certificate {fp[:23]}... signs the official apps of several domains ({shown}): an "
                        "organisation-asset link between the sites (Digital Asset Links statements).",
            entities=entities,
            confidence="probable",
            evidence=[f"{key}: {', '.join(pk[:5])}" for key, pk in sorted(domains.items())],
            recommendation="Treat the domains and their apps as assets of one organisation (official-app inventory for "
                           "impersonation checks); confirm before merging ownership.",
            tags=["info"],
            criterion=f"certificate {fp} in official_android_apps of {len(domains)} domains",
            key=fp,
        )
