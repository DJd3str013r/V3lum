"""UK Web Archive CDX (P059 cond 3): disabled until the service answers.

https://www.webarchive.org.uk/wayback/archive/cdx answered 403 'Under Maintenance' (the online service
has been degraded since the 2023 cyberattack) on 2026-11-25 and 2026-11-26, so this module ships
disabled: ``default_enabled = False``, terms 'unknown' (the terms page could not be reviewed: the
licence gate keeps it off in every profile) and setting ``web_archives_ukwa_enabled`` false. When the
service is back and legal has recorded its terms, enable the setting: the module then reads the pywb
CDX answer like Arquivo.pt's (NDJSON). The maintenance page is detected (marker ``ukwa_maintenance``)
and reported as 'could not verify', never as 'no captures'.
"""

from __future__ import annotations

from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.url_web.web_archives import parse_arquivo_cdx, query_target, redact_archived_url

SOURCE = "ukwa.cdx"
CDX = "https://www.webarchive.org.uk/wayback/archive/cdx"


@register
class WebArchivesUkwa(Module):
    name = "web_archives_ukwa"
    title = "UK Web Archive CDX (disabled until it answers)"
    description = "Capture index of the UK Web Archive (British Library); the online service is under maintenance, so the module is disabled."
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL}
    run_on = "seeds"
    reference = "https://www.webarchive.org.uk/"
    notice = "UKWA has answered 403 'Under Maintenance' since 2023: disabled until it answers and legal records its terms."
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ukwa"
    sources = (SOURCE,)
    hosts = ("www.webarchive.org.uk",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.0
    timeout = 20.0
    cache_ttl = 86400
    max_pivots = 20
    default_enabled = False
    settings = {
        "web_archives_ukwa_enabled": SettingSpec(False, "web_archives_ukwa: query the UK Web Archive (enable only once it answers again)"),
    }
    error_markers = (
        {
            "id": "ukwa_maintenance",
            "statuses": [200, 403, 503],
            "json_path": None,
            "equals": None,
            "regex": r"(?i)under maintenance|temporarily offline for maintenance",
            "final_url_regex": None,
            "maps_to": "error",
            "reason_code": "error",
            "reason": "UK Web Archive: service under maintenance (403 'Under Maintenance'): could not verify, never 'no captures'",
        },
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not bool(ctx.setting("web_archives_ukwa_enabled", False)):
            return res.mark("skipped", "UK Web Archive disabled until it answers (setting web_archives_ukwa_enabled)", reason_code="config")
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        query = f"{q['domain']}/*" if q["kind"] == "domain" else q["query"]
        resp = ctx.http.get(CDX, params={"url": query, "output": "json"}, source=SOURCE)
        ctx.http.check(resp)  # the maintenance page, challenges, 429 and 5xx raise (could not verify)
        result = parse_arquivo_cdx(resp.content, body_truncated=bool(getattr(resp, "truncated", False)))
        if result["state"] == "error":
            return res.mark("error", f"UK Web Archive: {result['error']}: could not verify")
        rows = result["rows"]
        if not rows:
            return res  # the archive answered without captures: empty, never 'never archived'
        stamps = sorted(r["captured_at"] for r in rows)
        distinct = sorted({r["url"] for r in rows})
        res.attr("archive_first", stamps[0])
        res.attr("archive_last", stamps[-1])
        res.attr("archive_count", len(distinct))
        res.attr("archived_urls", distinct[:500])
        for url in [r["url"] for r in rows if not r.get("secret_masked")][:20]:
            res.pivot(T.URL, url, "archived_url", confidence="probable", expand=False, note="historical URL from the UK Web Archive")
        res.raw = {"query": redact_archived_url(query)[0], "rows": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows[:500]]}
        if result["partial"]:
            res.stop("request_cap")
        return res
