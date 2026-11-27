"""pivots_url_web: URL & website tools, manual pivot links only (P083, batch p2-G14-1).

Disclosure ``none``: the module only builds URLs (``ctx.http`` refuses every request); V3LUM never requests
these pages or any API behind them (P083 cond 1). The pack is ``v3lum/data/pivot_links/url_web.json``:

* its ``links`` (BuiltWith profile, relationships and tag pages, Netcraft site report, aa419, W3Techs,
  WebTechSurvey, Website Informer, CrawlGraph, Ghostarchive, Google Play search; cond 8 and 12) are core pack
  links, rendered by the engine and by ``v3lum links``. The urlscan.io domain and IP pages are
  ``urlscan_search:domain`` / ``urlscan_search:ip`` (search pages only, never a scan submission; referenced in
  ``x_served_by``);
* the scan-trigger pages - ScamAdviser and securityheaders.com (always with hide=on, cond 9) - are
  ``x_module_links`` rendered here (cond 10-11): touches_target, rendered only for values the analyst typed
  (``ctx.is_seed`` and confirmed), not emitted at TLP:AMBER and above (``x_max_tlp`` green, read from the run's
  TLP: the architect's code-enforced floor) and not for an entity flagged hostile (``policy.hostile_reasons``);
  the label carries 'opening makes <host> contact the target live'.

Cond 9 (legal floor, rule 7): no MDN Observatory link (excluded and refused by the batch lint). Cond 12: Google
Play search for keywords only, never fetched or parsed; the app-details link waits for an Android package entity
type (``x_pending``). Known gap (docs/backlog/p2-G14-1.md): module links reach the renderers as plain
``{label, url}`` items, so at TLP:CLEAR/GREEN they are clickable rather than defanged.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_gated_links as pg

PACK = "url_web"


@register
class PivotsUrlWeb(Module):
    name = "pivots_url_web"
    title = "URL & website tools (manual pivot links)"
    description = (
        "Manual pivot links for domains, URLs, analytics IDs and brand keywords (BuiltWith, Netcraft, aa419, W3Techs, "
        "WebTechSurvey, Website Informer, CrawlGraph, Ghostarchive, Google Play search: pack url_web) plus the "
        "scan-trigger pages ScamAdviser and securityheaders.com for analyst-typed values at TLP:CLEAR/GREEN only. "
        "V3LUM never fetches them."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = frozenset()
    reference = "https://builtwith.com/"
    tags = {"offline", "pack"}
    notice = (
        "Manual links only (never fetched). ScamAdviser and securityheaders.com make the provider fetch the site live "
        "when opened: rendered only for values the analyst typed, at TLP:CLEAR/GREEN, never for hostile entities; "
        "securityheaders.com always with hide=on. No MDN Observatory link (its scans are published)."
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
        return pg.run_links(self, entity, ctx, PACK)
