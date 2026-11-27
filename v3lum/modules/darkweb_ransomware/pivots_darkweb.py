"""pivots_darkweb: ransomware group pages and clearnet onion search, manual links only (P203, batch p2-G14-2).

Disclosure ``none``: the module only builds URLs (``ctx.http`` refuses every request); V3LUM never requests
these pages or any API behind them (P203 cond 1). The pack is ``v3lum/data/pivot_links/darkweb.json``:

* ``darkweb:rlive_search`` (company names, keywords) is a core pack link, rendered by the engine and by
  ``v3lum links``;
* the threat-actor group pages, their search fallback and the onion search are ``x_module_links`` rendered
  here (:mod:`v3lum.modules.utility.pivot_pack_render`), because they need a per-site slug, a TLP ceiling or a
  warning the frozen core link model does not carry.

Final conditions and where they are met:

* cond 8 - group pages ``ransomlook.io/group/{slug}`` and ``ransomware.live/group/{slug}``: the slug comes from
  the pack's curated ``x_tracker_slugs`` table (each slug checked by the maintainer), matched on the typed name
  and on the canonical names the P295 alias index resolves it to (``actor_alias_index.resolve``; trackers name
  groups differently: 'LockBit Black' -> lockbit3). Two groups matching = ambiguous = no slug. Without a slug
  the ransomware.live search URL is used instead of a guessed path; RansomLook has no GET search URL (its
  search is a POST form), so no RansomLook link is rendered then.
* cond 9 (rule 3) - claim, leak-file, download and victim-file paths are refused by the batch lint
  (``pivot_pack_render.RULE3_PATH_RE``) on every darkweb entry; only group pages and search pages exist.
* cond 10 - OnionSearchEngine is an unknown-tier operator: its template takes IOC values only (domain, onion),
  carries the 'unknown operator' badge and has ``x_max_tlp: green``: at TLP:AMBER and above it is not emitted.
* cond 11 - the onion-search link carries the CSAM warning (ECA art. 241-B, isolated browsing environment);
  ``.onion`` hosts are never linked and nothing is ever fetched.
* cond 2 (A2) - at TLP:AMBER and above every label carries 'opening sends <value> to <host>' (the renderers
  show the link as non-clickable text); at RED the module emits nothing (SKIPPED 'tlp').
* cond 4-5 - tiers come from the provider registry: ransomlook and ransomware_live community,
  onionsearchengine unknown (registered by this batch).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_pack_render as pr

PACK = "darkweb"
SITES = ("ransomlook", "ransomware_live")
SLUG_PLACEHOLDER = {"ransomlook": "ransomlook_slug", "ransomware_live": "rlive_slug"}
GROUP_LINK = {"ransomlook": "ransomlook_group", "ransomware_live": "rlive_group"}
FALLBACK_LINK = "rlive_search_actor"
ONION_LINK = "onionsearch"


def _normalise(name: Any) -> str:
    """P295 normalisation (lower case, spaces/dashes/underscores removed); the alias index's own function when
    it imports, a local equivalent otherwise."""
    try:
        from v3lum.modules.cti_framework.actor_alias_index import normalise_alias
    except ImportError:  # pragma: no cover - the alias index ships with the core modules
        import re
        import unicodedata

        return re.sub(r"[\s\-_‐-―−]+", "", unicodedata.normalize("NFKC", str(name or "")).casefold())
    return normalise_alias(name)


def tracker_table(data: Mapping[str, Any] | None = None) -> dict[str, dict[str, str]]:
    """``{normalised name: {site: slug}}`` from the pack's ``x_tracker_slugs``; a name claimed by two groups is
    dropped (never guess between groups)."""
    data = data if data is not None else pr.pack_data(PACK)
    table: dict[str, dict[str, str]] = {}
    clashes: set[str] = set()
    groups = (data.get("x_tracker_slugs") or {}).get("groups") if isinstance(data.get("x_tracker_slugs"), Mapping) else None
    for group in groups or []:
        if not isinstance(group, Mapping):
            continue
        slugs = {site: str(group[site]) for site in SITES if isinstance(group.get(site), str) and pr.safe_token(group[site])}
        if not slugs:
            continue
        for name in group.get("names") or []:
            key = _normalise(name)
            if not key:
                continue
            if key in table and table[key] != slugs:
                clashes.add(key)
            table[key] = slugs
    for key in clashes:
        table.pop(key, None)
    return table


def candidate_names(value: str) -> list[str]:
    """The typed name plus the canonical names of the unambiguous P295 cards it resolves to (actor and
    malware namespaces: ransomware groups are often malware clusters there)."""
    names = [value]
    try:
        from v3lum.modules.cti_framework import actor_alias_index as aai
    except ImportError:  # pragma: no cover
        return names
    res = aai.resolve(value)
    if res:
        for namespace in ("actor", "malware"):
            for card in aai.namespace_cards(res, namespace):
                canonical = card.get("canonical")
                if isinstance(canonical, str) and canonical and not card.get("umbrella"):
                    names.append(canonical)
    return list(dict.fromkeys(names))


def resolve_slugs(value: str, table: Mapping[str, Mapping[str, str]] | None = None) -> tuple[dict[str, str], str]:
    """(site -> slug, note). A slug only when every matching name agrees (else ambiguous: no slug)."""
    table = table if table is not None else tracker_table()
    matches: dict[str, set[str]] = {site: set() for site in SITES}
    matched_names = []
    for name in candidate_names(value):
        entry = table.get(_normalise(name))
        if not entry:
            continue
        matched_names.append(name)
        for site, slug in entry.items():
            matches[site].add(slug)
    out = {site: next(iter(slugs)) for site, slugs in matches.items() if len(slugs) == 1}
    ambiguous = [site for site, slugs in matches.items() if len(slugs) > 1]
    note = ""
    if ambiguous:
        note = f"ambiguous group name for {', '.join(ambiguous)}: no group page"
    elif matched_names:
        note = f"matched {matched_names[0]!r} in the curated tracker table"
    return out, note


@register
class PivotsDarkweb(Module):
    name = "pivots_darkweb"
    title = "Ransomware group pages and onion search (manual links)"
    description = (
        "Manual pivot links for ransomware groups (RansomLook and ransomware.live group pages through a curated "
        "per-site slug table and the P295 alias index, ransomware.live search otherwise) and, at TLP:CLEAR/GREEN only, "
        "the OnionSearchEngine clearnet search for domains and onion addresses. V3LUM never fetches them."
    )
    category = "darkweb_ransomware"
    accepts = {T.THREAT_ACTOR, T.DOMAIN, T.ONION}
    produces = frozenset()
    reference = "https://www.ransomware.live/"
    tags = {"offline"}
    notice = (
        "Manual links only (never fetched). Group and search pages only: claim pages, leak files, downloads and victim "
        "files are never linked (rule 3). Onion search results may hold illicit content, possibly child sexual abuse "
        "material (possession is a crime, ECA art. 241-B): open them only in the team's isolated browsing environment. "
        "OnionSearchEngine is an unknown-tier operator: IOC values only, hidden at TLP:AMBER and above."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.01
    timeout = 10.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = pr.tlp_level(ctx)
        red = pr.hidden_reason(None, level)
        if red:
            return res.mark(Status.SKIPPED, red, reason_code="tlp")
        found = pr.module_links(PACK)
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        if entity.type is T.THREAT_ACTOR:
            slugs, note = resolve_slugs(entity.value)
            for site in SITES:
                ml = found.get(GROUP_LINK[site])
                slug = slugs.get(site)
                if ml is None:
                    hidden.append({"id": GROUP_LINK[site], "reason": "link not loaded (see module_link_errors)"})
                    continue
                if not slug:
                    why = "no known slug" + ("" if site == "ransomware_live" else ": RansomLook has no GET search URL (POST form)")
                    hidden.append({"id": ml.id, "reason": why})
                    if site == "ransomware_live":
                        fallback = found.get(FALLBACK_LINK)
                        rendered = pr.render(fallback, entity) if fallback else None
                        if rendered is not None:
                            shown.append(pr.emit(res, entity, level, rendered, ml=fallback))
                        else:
                            hidden.append({"id": FALLBACK_LINK, "reason": "did not render (lint, tier or value)"})
                    continue
                rendered = pr.render(ml, entity, {SLUG_PLACEHOLDER[site]: slug})
                if rendered is None:
                    hidden.append({"id": ml.id, "reason": "did not render (lint, tier or slug)"})
                    continue
                shown.append(pr.emit(res, entity, level, rendered, ml=ml, note=slug, sent=slug))
            res.raw = {"tlp": level.value_str, "slugs": slugs, "slug_note": note}
        else:
            ml = found.get(ONION_LINK)
            reason = pr.hidden_reason(ml, level) if ml is not None else "link not loaded (see module_link_errors)"
            if reason:
                res.raw = {"tlp": level.value_str, "links": [], "hidden": [{"id": ONION_LINK, "reason": reason}]}
                return res.mark(Status.SKIPPED, f"onion search link: {reason} (P203 cond 10)", reason_code="tlp")
            rendered = pr.render(ml, entity)
            if rendered is None:
                hidden.append({"id": ONION_LINK, "reason": "did not render (lint, tier or value)"})
            else:
                shown.append(pr.emit(res, entity, level, rendered, ml=ml))
            res.raw = {"tlp": level.value_str}
        res.raw.update({"links": shown, "hidden": hidden})
        if not shown:
            return res.mark(Status.EMPTY)
        return res
