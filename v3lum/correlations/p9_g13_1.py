"""Correlation rules of batch p9-G13-1 (P025 typosquat live checks).

The LIGHT module ``typosquat_live_checks`` records one ``page_fingerprint`` per fetched homepage: the
brand seed's page (role ``brand_reference``, fetched once in the LIGHT run) and each confirmed
lookalike's page (role ``candidate``). Brand and candidates run concurrently in the LIGHT phase, so
the comparison is made here, after the scan, from the recorded fingerprints only (P025 FC7):

* ``p9g131_typosquat_live_clone`` - HIGH: the lookalike's page scores at least
  :data:`~v3lum.modules.domain_dns.typosquat_live_checks.LIVE_CLONE_THRESHOLD` against the brand page
  (70 % ppdeep similarity of the normalised HTML + 10 same title + 10 same favicon mmh3 + 10 for a shared
  form-action host or a login form on both pages): 'page N% similar to <brand homepage> -> likely live
  clone (lookalike / phishing-capable indicator)', with the matched features and the compared hashes (FC9).
* ``p9g131_typosquat_page_unrelated`` - INFO: the page was compared and scores below the threshold
  ('unrelated content'), so the analyst sees that the lookalike was checked.

Parked, defensive and could-not-verify candidates never reach the comparison (the module records why);
own and supplier domains of the org profile are never flagged. The rules only read the graph: no
request, no pivot, no scheduling, and the wording never says 'malicious'.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.graph import Graph
from v3lum.core.http import normalize_host
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.modules.domain_dns.typosquat_live_checks import (
    INDICATOR,
    LIVE_CLONE_THRESHOLD,
    MODULE_NAME,
    best_comparison,
    brand_references,
    load_ppdeep,
)

RULE_LIVE_CLONE = "p9g131_typosquat_live_clone"
RULE_UNRELATED = "p9g131_typosquat_page_unrelated"
#: live-check states whose page fingerprint may be compared (parked/defensive/unregistered never are)
_COMPARABLE = frozenset({"fetched", "could_not_verify", "live_clone", "unrelated"})
_VERDICTS = frozenset({"live_clone", "unrelated"})
_REFERENCES = ("https://github.com/elceef/dnstwist", "https://attack.mitre.org/techniques/T1583/001/")


def _values(node: Any, attr: str) -> list[Mapping[str, Any]]:
    return [v for v, src in getattr(node, "attributes", {}).get(attr, []) if src == MODULE_NAME and isinstance(v, Mapping)]


def _fingerprint(node: Any, role: str) -> Mapping[str, Any] | None:
    for fp in _values(node, "page_fingerprint"):
        if fp.get("role") == role:
            return fp
    return None


def _own(org: Any, node: Any) -> bool:
    if org is None:
        return False
    try:
        owned = org.owns(node.entity)
    except Exception:  # noqa: BLE001 - a profile problem never flags anything
        return False
    return bool(getattr(owned, "own", False) or getattr(owned, "kind", "") == "supplier")


def _brand_hosts(graph: Graph, node: Any) -> list[str]:
    hosts: list[str] = []
    for live in _values(node, "live_check"):
        hosts += [normalize_host(h) for h in live.get("brands") or [] if isinstance(h, str)]
    for edge in graph.edges:
        if edge.relation == "lookalike" and edge.dst == node.key and edge.src.startswith("domain:"):
            hosts.append(edge.src.split(":", 1)[1])
        elif edge.relation == "lookalike_of" and edge.src == node.key and edge.dst.startswith("domain:"):
            hosts.append(edge.dst.split(":", 1)[1])
    return [h for i, h in enumerate(hosts) if h and h not in hosts[:i]]


def _recorded(graph: Graph, node: Any) -> tuple[Any, dict[str, Any]] | None:
    """The comparison the module already made (the brand page was in the case when the candidate ran)."""
    for live in _values(node, "live_check"):
        cmp = live.get("comparison")
        if not isinstance(cmp, Mapping) or cmp.get("state") not in _VERDICTS or not isinstance(cmp.get("score"), int):
            continue
        brand = graph.get(f"domain:{normalize_host(cmp.get('brand') or '')}")
        if brand is not None:
            out = dict(cmp)
            out.setdefault("matched", [])
            out.setdefault("hashes", {})
            return brand, out
    return None


def comparisons(graph: Graph, rctx: Any = None) -> Iterator[dict[str, Any]]:
    """The best comparison of every fetched lookalike page with the brand reference page(s) it imitates:
    the one the module recorded, else one made here from the recorded fingerprints (ppdeep)."""
    org = getattr(rctx, "org", None)
    nodes = list(graph.nodes.values()) if isinstance(getattr(graph, "nodes", None), dict) else []
    ppdeep = load_ppdeep()
    favicons = list(getattr(org, "favicon_hashes", ()) or ()) if org is not None else []
    for node in nodes:
        cand = _fingerprint(node, "candidate")
        if cand is None or _own(org, node):
            continue
        states = {str(v.get("state") or "") for v in _values(node, "live_check")}
        if states and not states & _COMPARABLE:
            continue
        found = _recorded(graph, node) or best_comparison(brand_references(graph, _brand_hosts(graph, node)), cand, ppdeep=ppdeep,
                                                          org_favicons=favicons)
        if found is not None and found[0].key != node.key:
            yield {"candidate": node, "brand": found[0], "cmp": found[1]}


def _correlation(item: Mapping[str, Any], rule_id: str, severity: Severity) -> Correlation:
    cand, brand, cmp = item["candidate"], item["brand"], item["cmp"]
    hashes = cmp.get("hashes") or {}
    matched = [str(m) for m in cmp.get("matched") or []]
    evidence = [
        f"{cand.key}: {MODULE_NAME} page ppdeep {hashes.get('ppdeep_candidate')}, favicon mmh3 {hashes.get('favicon_mmh3_candidate')}",
        f"{brand.key}: {MODULE_NAME} brand reference ppdeep {hashes.get('ppdeep_brand')}, favicon mmh3 {hashes.get('favicon_mmh3_brand')}",
    ] + [f"matched: {m}" for m in matched[:6]]
    clone = cmp.get("state") == "live_clone"
    return Correlation(
        rule=rule_id,
        title="Lookalike page is a likely live clone of the brand homepage" if clone else "Lookalike page checked: unrelated content",
        severity=severity,
        description=(f"{cand.entity.display}: {cmp.get('wording')}. Matched features: {', '.join(matched) or 'none'}."
                     + (" This is an indicator, not a verdict of maliciousness; the page was read once like a visitor (LIGHT)."
                        if clone else "")),
        entities=[cand.entity, brand.entity],
        confidence="probable" if clone else "possible",
        evidence=evidence,
        recommendation=("Review the lookalike page (screenshots only through the separately approved page_capture module), check "
                        "its mail capability and escalate a takedown through the manual, separately approved process."
                        if clone else "No action from the page comparison; keep the lookalike under watch with the passive modules."),
        tags=["typosquat", "phishing_capable"] if clone else ["typosquat"],
        criterion=(f"page similarity score {cmp.get('score')} (>= {LIVE_CLONE_THRESHOLD}): ppdeep {cmp.get('html_fuzzy')}% of the "
                   f"normalised HTML plus title/favicon/form-action matches" if clone else
                   f"page similarity score {cmp.get('score')} (< {LIVE_CLONE_THRESHOLD})"),
        attack=["T1583.001", "T1566"] if clone else [],
        references=list(_REFERENCES),
        key=f"{cand.key}|{brand.key}",
    )


@rule(
    RULE_LIVE_CLONE,
    "Lookalike page is a likely live clone of the brand homepage",
    "A registered lookalike's homepage (fetched once by the LIGHT typosquat_live_checks module) scores at least "
    f"{LIVE_CLONE_THRESHOLD} against the brand seed's homepage fetched in the same run: 70 % ppdeep similarity of the "
    "normalised HTML plus 10 for the same title, 10 for the same favicon mmh3 and 10 for a shared form-action host or a "
    "login form on both pages "
    f"(P025 FC7/FC9). Wording: 'page N% similar to <brand homepage> -> likely live clone ({INDICATOR})'.",
    severity="high",
    criterion=f"page_fingerprint comparison score >= {LIVE_CLONE_THRESHOLD} between a candidate and its brand reference page",
    references=_REFERENCES,
    attack=("T1583.001", "T1566"),
    false_positives="A reseller, partner or franchise site built from the same template; a brand-protection vendor's "
                    "holding page copying the brand. Defensive registrations redirecting to the brand are excluded upstream.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_LIVE_CLONE}/positive_identical_login_clone.json",
        f"tests/fixtures/rules/{RULE_LIVE_CLONE}/positive_recorded_comparison.json",
        f"tests/fixtures/rules/{RULE_LIVE_CLONE}/negative_parked_candidate.json",
        f"tests/fixtures/rules/{RULE_LIVE_CLONE}/negative_no_brand_reference.json",
        f"tests/fixtures/rules/{RULE_LIVE_CLONE}/negative_own_domain.json",
    ),
)
def p9g131_typosquat_live_clone(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    for item in comparisons(graph, rctx):
        if item["cmp"]["state"] == "live_clone":
            yield _correlation(item, RULE_LIVE_CLONE, Severity.HIGH)


@rule(
    RULE_UNRELATED,
    "Lookalike page checked: unrelated content",
    "A registered lookalike's homepage (LIGHT typosquat_live_checks) was compared with the brand seed's homepage and "
    f"scores below {LIVE_CLONE_THRESHOLD}: 'page N% similar to <brand homepage> -> unrelated content' (P025 FC9).",
    severity="info",
    criterion=f"page_fingerprint comparison score < {LIVE_CLONE_THRESHOLD}",
    references=_REFERENCES,
    false_positives="A clone that serves different content to the LIGHT fetch (cloaking by IP, user agent or referrer) "
                    "looks unrelated here.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_UNRELATED}/positive_different_page.json",
        f"tests/fixtures/rules/{RULE_UNRELATED}/negative_identical_login_clone.json",
    ),
)
def p9g131_typosquat_page_unrelated(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    for item in comparisons(graph, rctx):
        if item["cmp"]["state"] == "unrelated":
            yield _correlation(item, RULE_UNRELATED, Severity.INFO)
