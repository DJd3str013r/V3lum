"""Onion service metadata from AIL onion-lookup (CIRCL), behind the Ahmia banned-list filter (P199).

Final conditions (P199):

* cond 1 - GET https://onion.ail-project.org/api/lookup/{onion} only for onions already in the case (one
  request per onion, never bulk), after the v3 checksum is validated locally (P217, core validator):
  disclosure ``third_party`` (CIRCL sees the address). No Tor connection in this module.
* cond 2/3 - the Ahmia banned/CSAM md5 list is a registered dataset (``onion_safety``, at most daily);
  it is applied before anything is shown, stored or sent: a hit shows only "onion on Ahmia's abuse
  (banned) list: details withheld" and the onion is never enriched; without a usable list the module
  fails closed (UNAVAILABLE ``dataset``: nothing sent to AIL).
* cond 4 - the core HTTP layer refuses ``.onion`` hosts outside a LIGHT Tor profile (WP11); the DNS
  layer gap is a core request (docs/backlog/p2-G09-1.md). This module never resolves the onion.
* cond 5 - Ahmia's onion index list is not downloaded (ToS of 25 Sep 2026); Ahmia search stays manual
  (``manual_link``: the search page, the analyst types the value).
* cond 6 - AIL titles are plain text (control/bidi characters removed, deduplicated, capped), first/last
  seen dated, tags as attributes; MISP galaxy tags naming a threat actor/ransomware group become
  ``threat_actor`` pivots with ``expand=False`` (context, not attribution). Provider circl (AIL), tier
  trusted, terms open.

AIL answers HTTP 200 for everything (live 2026-11-26): ``{"error": "domain not found", ...}`` is EMPTY,
``{}`` (malformed onion) and any other error body are ERROR 'could not verify'.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import parse_day, safe_plain
from v3lum.modules.darkweb_ransomware.onion_safety import (
    AHMIA_SEARCH_URL,
    add_banned_finding,
    is_banned_onion,
    onion_service_domain,
)

SOURCE = "circl.onion_lookup_ail"
AIL_LOOKUP_URL = "https://onion.ail-project.org/api/lookup/{onion}"
AIL_DOCS_URL = "https://onion.ail-project.org/apiman/redoc/"
#: the Tor Project's own onion service: the benign health-check value (crawled by AIL)
TOR_PROJECT_ONION = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
MAX_TITLES = 10
TITLE_LEN = 160
_MISP_TAG_RE = re.compile(r'^(?P<ns>[^:=\s]+):(?P<pred>[^=\s]+)(?:="(?P<val>[^"]*)")?$')
_ACTOR_GALAXIES = ("threat-actor", "ransomware", "mitre-intrusion-set")


def parse_misp_tag(tag: str) -> dict[str, str | None]:
    """'infoleak:automatic-detection="onion"' -> {'namespace', 'predicate', 'value'}."""
    text = safe_plain(tag, 200)
    m = _MISP_TAG_RE.match(text)
    if not m:
        return {"namespace": None, "predicate": None, "value": text}
    return {"namespace": m.group("ns"), "predicate": m.group("pred"), "value": m.group("val")}


def parse_ail_lookup(doc: Any, queried: str | None = None) -> dict[str, Any]:
    """AIL onion-lookup answer -> {'status': 'found'|'empty'|'error', ...} (P199 cond 1, 6)."""
    out: dict[str, Any] = {"status": "error", "onion": None, "first_seen": None, "last_seen": None, "titles": [], "title_count": 0,
                           "languages": [], "tags": [], "actor_tags": [], "reason": ""}
    if not isinstance(doc, dict):
        out["reason"] = "AIL onion-lookup answered an unexpected JSON type: could not verify"
        return out
    if "error" in doc:
        message = safe_plain(doc.get("error"), 120)
        if message.lower() == "domain not found":
            out["status"] = "empty"
            out["onion"] = onion_service_domain(doc.get("domain")) or onion_service_domain(queried)
            return out
        out["reason"] = f"AIL onion-lookup error: {message}: could not verify"
        return out
    if not doc:
        out["reason"] = "AIL onion-lookup returned an empty object (malformed onion?): could not verify"
        return out
    onion = onion_service_domain(doc.get("id"))
    if not onion:
        out["reason"] = "AIL onion-lookup answer has no valid onion id: could not verify"
        return out
    if queried and onion_service_domain(queried) and onion_service_domain(queried) != onion:
        out["reason"] = "AIL onion-lookup answered for a different onion: could not verify"
        return out
    titles: list[str] = []
    seen: set[str] = set()
    for title in doc.get("titles") if isinstance(doc.get("titles"), list) else []:
        if not isinstance(title, str):
            continue
        clean = safe_plain(title, TITLE_LEN)
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            titles.append(clean)
    languages = [safe_plain(x, 12) for x in (doc.get("languages") or []) if isinstance(x, str) and x.strip()][:40]
    tags = [safe_plain(x, 200) for x in (doc.get("tags") or []) if isinstance(x, str) and x.strip()][:50]
    actors: list[dict[str, str]] = []
    for tag in tags:
        parsed = parse_misp_tag(tag)
        if parsed["namespace"] == "misp-galaxy" and parsed["predicate"] in _ACTOR_GALAXIES and parsed["value"]:
            name = safe_plain(parsed["value"], 80)
            if name and name not in [a["name"] for a in actors]:
                actors.append({"name": name, "tag": f"misp-galaxy:{parsed['predicate']}"})
    out.update(status="found", onion=onion, first_seen=parse_day(doc.get("first_seen")), last_seen=parse_day(doc.get("last_seen")),
               titles=titles[:MAX_TITLES], title_count=len(titles), languages=languages, tags=tags, actor_tags=actors)
    return out


@register
class OnionLookup(Module):
    name = "onion_lookup"
    title = "Onion metadata (AIL onion-lookup, Ahmia safety filter)"
    description = (
        "First/last seen, page titles, languages and MISP tags of an onion service already in the case from CIRCL's AIL "
        "onion-lookup, after the local v3 checksum check and the Ahmia banned-onion safety filter. No Tor connection."
    )
    category = "darkweb_ransomware"
    accepts = {T.ONION}
    produces = {T.THREAT_ACTOR}
    tags = {"free"}
    reference = AIL_DOCS_URL
    notice = (
        "CIRCL (AIL) receives the onion address. Onions on Ahmia's abuse (banned) list are never sent, shown or enriched "
        "('details withheld'); without the list the module sends nothing. Ahmia search is manual only."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # CIRCL sees the onion; V3LUM never touches the hidden service
    provider = "circl"
    sources = (SOURCE,)
    hosts = ("onion.ail-project.org",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 0.7
    timeout = 10.0
    min_interval = 2.0
    daily_quota = 200
    cache_ttl = 86400
    max_pivots = 10
    manual_link = AHMIA_SEARCH_URL  # Ahmia search form (rotating token): the analyst types the onion (P199 cond 5)
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.ONION, TOR_PROJECT_ONION)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return onion_service_domain(entity.value) is not None  # P217: a bad checksum or a v2 onion is never sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        onion = onion_service_domain(entity.value)
        if onion is None:
            return res.mark("skipped", "not a valid v3 onion address (checksum): never sent", reason_code="not_applicable")
        banned = is_banned_onion(entity.value, ctx)
        if banned is None:  # P199 cond 2: no filter, no enrichment (fail closed)
            return res.mark("unavailable", "Ahmia banned-onion list unavailable: nothing sent to AIL (run v3lum data update ahmia_banned_onions)", reason_code="dataset")
        if banned:
            return add_banned_finding(res)  # P199 cond 3: details withheld, never enriched
        doc = ctx.http.get_json(AIL_LOOKUP_URL.format(onion=onion), source=SOURCE, allow_redirects=False)
        parsed = parse_ail_lookup(doc, queried=onion)
        if parsed["status"] == "error":
            return res.mark("error", parsed["reason"])
        res.link("Ahmia search (manual: type the onion; search is never automated)", AHMIA_SEARCH_URL)
        if parsed["status"] == "empty":
            res.raw = {"status": "not found", "onion": defang(onion)}
            return res.mark("empty")
        self._report(res, onion, parsed)
        return res

    @staticmethod
    def _report(res: ModuleResult, onion: str, parsed: dict[str, Any]) -> None:
        res.attr("first_seen", parsed["first_seen"])
        res.attr("last_seen", parsed["last_seen"])
        res.attr("onion_titles", parsed["titles"])
        res.attr("languages", parsed["languages"])
        res.attr("tags", parsed["tags"])
        more = f" (first {len(parsed['titles'])} of {parsed['title_count']})" if parsed["title_count"] > len(parsed["titles"]) else ""
        titles = "; ".join(parsed["titles"][:3]) or "none recorded"
        res.finding(
            "Onion service seen by AIL (CIRCL)",
            "info",
            f"{defang(onion)} crawled by AIL: first seen {parsed['first_seen'] or 'unknown'}, last seen "
            f"{parsed['last_seen'] or 'unknown'}; titles{more}: {titles}; tags: {', '.join(parsed['tags']) or 'none'}. "
            "Titles are untrusted plain text. V3LUM never connects to the hidden service.",
            confidence="probable",
            data={"first_seen": parsed["first_seen"], "last_seen": parsed["last_seen"], "title_count": parsed["title_count"],
                  "languages": parsed["languages"], "tags": parsed["tags"]},
            tags=["darkweb", "tor"],
            source=SOURCE,
            observed_first=parsed["first_seen"],
            observed_last=parsed["last_seen"],
        )
        for actor in parsed["actor_tags"]:
            res.pivot(T.THREAT_ACTOR, actor["name"], "listed_for_actor", confidence="possible", expand=False,
                      note=f"AIL tag {actor['tag']} on this onion (crawler classification: context, not attribution)")
        res.raw = {"onion": defang(onion), **{k: parsed[k] for k in ("first_seen", "last_seen", "titles", "title_count", "languages", "tags")}}


__all__ = ["AIL_LOOKUP_URL", "OnionLookup", "TOR_PROJECT_ONION", "parse_ail_lookup", "parse_misp_tag"]
