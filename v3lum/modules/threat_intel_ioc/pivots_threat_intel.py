"""pivots_threat_intel: reputation pages, manual pivot links only (P170, batch p2-G14-1).

Disclosure ``none``: the module only builds URLs (``ctx.http`` refuses every request); V3LUM never requests
these pages or any API behind them (P170 cond 1). The pack is ``v3lum/data/pivot_links/threat_intel_ioc.json``:

* its ``links`` (CESNET NERD, FortiGuard search-results page, MultiRBL, HoneyLabs HTML page, CyberCrime-Tracker
  domain/IP search; cond 8) are core pack links, rendered by the engine and by ``v3lum links``. The GreyNoise
  Visualizer page is ``scanner_intel_g02_3:greynoise_viz_ip`` (same template, referenced in ``x_served_by``);
* the ``x_module_links`` are rendered here: URLVoid (runs a fresh check on view: touches_target, analyst-typed
  values only, not emitted at TLP:AMBER and above, not for hostile entities, cond 9) and the CyberCrime-Tracker
  URL search (stored C2 URLs have no scheme: the vetted ``{urlhp}`` encoder sends host[:port] and path only).

Cond 10: ThreatBook is kept only if its page shows a verdict without signing in; that could not be confirmed
(301 to i.threatbook.io, then 502 on 2026-11-26), so it stays in ``x_pending`` with login_required=true and is
never rendered. Cond 11: unknown-tier hosts (MultiRBL, HoneyLabs, CyberCrime-Tracker) receive IOC values only
(the core lint); the CyberCrime-Tracker malware_family search waits for a recorded tier promotion; automated DNSBL
checks belong to the DNS modules.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_gated_links as pg

PACK = "threat_intel_ioc"


@register
class PivotsThreatIntel(Module):
    name = "pivots_threat_intel"
    title = "Reputation pages (manual pivot links)"
    description = (
        "Manual reputation cross-checks (CESNET NERD, FortiGuard, MultiRBL, HoneyLabs, CyberCrime-Tracker: pack "
        "threat_intel_ioc) plus URLVoid for analyst-typed domains at TLP:CLEAR/GREEN and the CyberCrime-Tracker URL "
        "search. V3LUM never fetches them."
    )
    category = "threat_intel_ioc"
    accepts = {T.DOMAIN, T.URL}
    produces = frozenset()
    reference = "https://www.urlvoid.com/"
    tags = {"offline", "pack"}
    notice = (
        "Manual links only (never fetched). URLVoid runs a fresh check of the site when opened: rendered only for "
        "values the analyst typed, at TLP:CLEAR/GREEN, never for hostile entities. MultiRBL, HoneyLabs and "
        "CyberCrime-Tracker are unknown-tier operators (IOC values only)."
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
