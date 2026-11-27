"""gtm_expand: Google Tag Manager container expansion (P061 cond 1-3, batch p2-G03-1).

The networked half of P061 (architect floor, cond 1): ``https://www.googletagmanager.com/gtm.js?id=GTM-XXXX``
is fetched from Google (disclosure ``third_party``: Google receives the container id, never the page or
the target URL) and the measurement / advertising ids configured in the container become
``analytics_id`` pivots (relation ``gtm_loads``) so the reverse-lookup modules can run on them.

Final conditions implemented here (P061):

* c2 - ids are matched case-sensitively on quoted strings of the container data object: G-, UA-, AW-,
  DC- (and nested GTM-); AW-/DC- also from the ``__awct``/``__flc``/``__fls`` tag fields (flagged
  ``derived``). DC- ids are context attributes only (not an analytics_id entity type).
* c3 - at most 5 containers per run (cache hits are free), 1 MB cap, cache 7 days. Unknown containers
  answer HTTP 200 with a generic ~242 KB runtime and no macros/tags: 'not found' is decided from the
  content, never from the status; a cut or garbled data object is 'could not verify' (ERROR), never
  'not found'.
* c7/c8 - each loaded id records its provenance ('GTM container GTM-XXXX', fetch date) in the pivot note;
  linker domains, host lookup tables, custom script hosts and Facebook pixel ids are context
  attributes, never same-owner pivots.
"""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.url_web.analytics_ids import (
    GTM_QUOTED_ID_RE,
    KIND_LABELS,
    analytics_kind,
    is_template_id,
    normalise_analytics_id,
)

SOURCE = "googletagmanager.gtm_js"
GTM_URL = "https://www.googletagmanager.com/gtm.js"
GTM_ID_RE = re.compile(r"GTM-[A-Z0-9]{4,9}\Z")
GTM_MAX_CONTAINERS = 5  # c3: per run
GTM_MAX_BYTES = 1_048_576  # c3
GTM_CACHE_TTL = 7 * 86400  # c3
GOOGLE_CHALLENGE_MARKERS = ("our systems have detected unusual traffic", "/sorry/index", "may be sending automated queries", "g-recaptcha", "captcha-form")
_HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]\Z")
MAX_CONTEXT_ITEMS = 50


def _text(raw: Any, limit: int | None = None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    elif not isinstance(raw, str):
        raw = str(raw)
    return raw[:limit] if limit is not None else raw


def _looks_like_html(text: str) -> bool:
    head = text[:600].lstrip().lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body")) or ("<html" in head and "</" in head)


def _hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253:
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return v if _HOST_RE.match(v) else None


def gtm_container_url(gtm_id: Any) -> str | None:
    """https://www.googletagmanager.com/gtm.js?id=GTM-... for a syntactically valid id, else None (c3)."""
    if not isinstance(gtm_id, str) or not GTM_ID_RE.match(gtm_id.strip()):
        return None
    return GTM_URL + "?" + urllib.parse.urlencode({"id": gtm_id.strip()})


def _macro_value(macros: list[Any], ref: Any, depth: int = 0) -> list[str]:
    """Resolve ['macro', N] references to constant values; lookup tables give their candidate values."""
    if depth > 5:
        return []
    if isinstance(ref, str):
        return [ref]
    is_ref = isinstance(ref, list) and len(ref) == 2 and ref[0] == "macro" and isinstance(ref[1], int) and not isinstance(ref[1], bool)
    if not is_ref or not (0 <= ref[1] < len(macros)) or not isinstance(macros[ref[1]], dict):
        return []
    mac = macros[ref[1]]
    fn = mac.get("function")
    if fn == "__c":
        return _macro_value(macros, mac.get("vtp_value"), depth + 1)
    if fn in ("__smm", "__remm"):
        vals = _macro_value(macros, mac.get("vtp_defaultValue"), depth + 1)
        for _key, val in _smm_rows(mac):
            vals += _macro_value(macros, val, depth + 1)
        return vals
    return []


def _smm_rows(mac: dict[str, Any]) -> list[tuple[Any, Any]]:
    rows: list[tuple[Any, Any]] = []
    vmap = mac.get("vtp_map")
    if isinstance(vmap, list) and vmap[:1] == ["list"]:
        for row in vmap[1:]:
            if isinstance(row, list) and len(row) >= 5 and row[0] == "map":
                d = dict(zip(row[1::2], row[2::2]))
                rows.append((d.get("key"), d.get("value")))
    return rows


def parse_gtm_container(raw: Any, requested_id: str | None = None, max_bytes: int = GTM_MAX_BYTES) -> dict[str, Any]:
    """c3: expand gtm.js into the ids its configuration loads.

    'not found' is decided from the content, never from the HTTP status: unknown containers answer 200 with
    a generic runtime whose data object has no macros/tags -> status 'empty'. A cut or unparsable data
    object -> 'error' (could not verify) with any ids already seen in ``partial_ids``. HTML -> 'error', or
    'blocked' for Google's automated-traffic interstitial. The container's own id is excluded."""
    out: dict[str, Any] = {"status": "error", "reason_code": "error", "reason": None, "container": requested_id, "version": None,
                           "macro_count": 0, "tag_count": 0, "ids": [], "partial_ids": [], "linker_domains": [], "host_map": {},
                           "script_hosts": [], "facebook_pixel_ids": [], "truncated": False, "echoed_id": None}
    if isinstance(raw, (bytes, bytearray)) and len(raw) > max_bytes:
        raw, out["truncated"] = bytes(raw[:max_bytes]), True
    text = _text(raw)
    if len(text) > max_bytes:
        text, out["truncated"] = text[:max_bytes], True
    if not text.strip():
        out["reason"] = "empty body: could not verify"
        return out
    if _looks_like_html(text):
        low = text.lower()
        if any(m in low for m in GOOGLE_CHALLENGE_MARKERS):
            out.update(status="blocked", reason_code="challenge", reason="Google answered an automated-traffic interstitial (challenge): not retried")
        else:
            out["reason"] = "HTML instead of the gtm.js script: could not verify"
        return out
    m = re.search(r"var\s+data\s*=\s*\{", text)
    if not m:
        out["reason"] = "no container data object in the script: could not verify"
        return out
    try:
        doc, _end = json.JSONDecoder().raw_decode(text, m.end() - 1)
    except ValueError:
        partial: list[str] = []
        for mm in GTM_QUOTED_ID_RE.finditer(text, m.start()):
            if mm.group(1) != requested_id and mm.group(1) not in partial:
                partial.append(mm.group(1))
            if len(partial) >= MAX_CONTEXT_ITEMS:
                break
        out.update(reason="container data truncated or malformed: could not verify", partial_ids=partial)
        return out
    res = doc.get("resource") if isinstance(doc, dict) else None
    if not isinstance(res, dict):
        out["reason"] = "container data without 'resource': could not verify"
        return out
    blob = doc.get("blob") if isinstance(doc.get("blob"), dict) else {}
    echoed = blob.get("10")
    out["echoed_id"] = echoed if isinstance(echoed, str) else None
    macros = res.get("macros") if isinstance(res.get("macros"), list) else []
    tags = res.get("tags") if isinstance(res.get("tags"), list) else []
    out.update(version=str(res.get("version")) if res.get("version") is not None else None, macro_count=len(macros), tag_count=len(tags))
    if not macros and not tags:
        out.update(status="empty", reason_code=None, reason="container not found or empty (generic runtime without macros or tags; HTTP status ignored)")
        return out
    if requested_id and out["echoed_id"] and out["echoed_id"] != requested_id:
        out["reason"] = f"the container answered for {out['echoed_id']}, not {requested_id}: could not verify"
        return out
    ids: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(value: Any, via: str, derived: bool = False) -> None:
        norm = normalise_analytics_id(value)
        if not norm or norm == requested_id or norm in seen or len(ids) >= MAX_CONTEXT_ITEMS:
            return
        seen.add(norm)
        ids.append({"id": norm, "kind": analytics_kind(norm), "via": via, "derived": derived, "template": is_template_id(norm)})

    res_text = json.dumps(res, separators=(",", ":"))
    for mm in GTM_QUOTED_ID_RE.finditer(res_text):
        add(mm.group(1), "quoted")
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        fn = tag.get("function")
        if fn in ("__flc", "__fls"):
            adv = tag.get("vtp_advertiserId")
            if isinstance(adv, str) and re.fullmatch(r"\d{6,10}", adv):
                add("DC-" + adv, f"{fn}.vtp_advertiserId", derived=True)
        elif fn == "__awct":
            conv = tag.get("vtp_conversionId")
            if isinstance(conv, str) and re.fullmatch(r"\d{6,12}", conv):
                add("AW-" + conv, f"{fn}.vtp_conversionId", derived=True)
    linker: list[str] = []
    for item in list(macros) + list(tags):
        if isinstance(item, dict) and "vtp_autoLinkDomains" in item:
            for val in _macro_value(macros, item.get("vtp_autoLinkDomains")):
                for d in str(val).split(","):
                    h = _hostname(d)
                    if h and h not in linker and len(linker) < MAX_CONTEXT_ITEMS:
                        linker.append(h)
    host_map: dict[str, str] = {}
    for mac in macros:
        if isinstance(mac, dict) and mac.get("function") in ("__smm", "__remm"):
            for key, val in _smm_rows(mac):
                h = _hostname(key) if isinstance(key, str) else None
                norm = normalise_analytics_id(val) if isinstance(val, str) else None
                if h and norm and len(host_map) < MAX_CONTEXT_ITEMS:
                    host_map[h] = norm
    script_hosts: list[str] = []
    pixels: list[str] = []
    for tag in tags:
        if isinstance(tag, dict) and tag.get("function") == "__html":
            html = json.dumps(tag.get("vtp_html"))
            for src in re.findall(r'src=\\*"(https?://[^"\\\s]{1,2048})', html):
                try:
                    h = _hostname(urllib.parse.urlsplit(src).hostname or "")
                except ValueError:
                    h = None
                if h and h not in script_hosts and len(script_hosts) < MAX_CONTEXT_ITEMS:
                    script_hosts.append(h)
            for px in re.findall(r"facebook\.com/tr\?id=(\d{6,20})", html):
                if px not in pixels and len(pixels) < MAX_CONTEXT_ITEMS:
                    pixels.append(px)
    out.update(status="ok", reason_code=None, reason=None, ids=ids, linker_domains=linker, host_map=host_map, script_hosts=script_hosts,
               facebook_pixel_ids=pixels)
    if not ids:
        out["reason"] = "container found but it loads no measurement id other than itself"
    return out


class _RunBudget:
    """c3: at most N containers fetched per run (scan or single run); cache hits are refunded."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self._used: dict[str, int] = {}

    def take(self, key: str) -> bool:
        with self._lock:
            if len(self._used) > 1000:  # bounded: old runs are forgotten
                self._used.clear()
            used = self._used.get(key, 0)
            if used >= self.limit:
                return False
            self._used[key] = used + 1
            return True

    def refund(self, key: str) -> None:
        with self._lock:
            if self._used.get(key, 0) > 0:
                self._used[key] -= 1

    def reset(self) -> None:
        with self._lock:
            self._used.clear()


BUDGET = _RunBudget(GTM_MAX_CONTAINERS)


def _run_key(ctx: Any) -> str:
    case_id = str(getattr(ctx, "case_id", "") or "")
    return f"case:{case_id}" if case_id else f"runtime:{id(getattr(ctx, 'runtime', ctx))}"


@register
class GtmExpand(Module):
    name = "gtm_expand"
    title = "Google Tag Manager container expansion"
    description = (
        "Fetches a GTM container (gtm.js?id=GTM-...) from Google and lists the GA4/UA/Google Ads/Floodlight ids it loads, "
        "plus linker domains and custom script hosts; 'not found' is decided from the content, never from the status."
    )
    category = "url_web"
    accepts = {T.ANALYTICS_ID}
    produces = {T.ANALYTICS_ID}
    reference = "https://developers.google.com/tag-platform/tag-manager"
    terms = "open"  # public JavaScript served by Google (P061 chair rationale)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Google receives the container id, never the page or target URL
    provider = "googletagmanager"
    sources = (SOURCE,)
    hosts = ("www.googletagmanager.com",)
    access_model = "free_noauth_unlimited"
    max_requests = 1
    expected_latency = 0.3
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = GTM_CACHE_TTL
    default_enabled = True
    max_pivots = 50

    def applies(self, entity: Entity, ctx: Any) -> bool:
        value = str(entity.value or "").strip()
        return bool(GTM_ID_RE.match(value)) and not is_template_id(value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        gtm_id = str(entity.value).strip()
        url = gtm_container_url(gtm_id)
        if url is None:  # pragma: no cover - applies() filters these
            return res.mark(Status.SKIPPED, "not a GTM container id", reason_code="not_applicable")
        key = _run_key(ctx)
        if not BUDGET.take(key):
            return res.mark(Status.SKIPPED, f"GTM expansion cap reached: at most {GTM_MAX_CONTAINERS} containers per run (P061 cond 3)",
                            reason_code="policy")
        try:
            resp = ctx.http.get(url, max_bytes=GTM_MAX_BYTES, ttl=GTM_CACHE_TTL, source=SOURCE, headers={"Accept": "*/*"})
        except Exception:
            BUDGET.refund(key)  # nothing was learned from Google: the slot is not spent
            raise
        if resp.from_cache:
            BUDGET.refund(key)
        ctx.http.check(resp)  # classification + status: Blocked / RateLimited / AuthRequired / HttpError (rule 5)
        fetched_at = str(resp.fetched_at or ctx.now().isoformat(timespec="seconds")).replace("+00:00", "Z")
        parsed = parse_gtm_container(resp.content, gtm_id, GTM_MAX_BYTES)
        truncated = bool(parsed["truncated"] or resp.truncated)
        container = {"container": gtm_id, "found": parsed["status"] == "ok", "version": parsed["version"], "macro_count": parsed["macro_count"],
                     "tag_count": parsed["tag_count"], "fetched_at": fetched_at, "truncated": truncated}
        res.raw = {"url": url, "status": resp.status, "bytes": len(resp.content), "from_cache": bool(resp.from_cache),
                   **{k: parsed[k] for k in ("status", "reason", "version", "macro_count", "tag_count", "ids", "partial_ids", "echoed_id")}}
        if parsed["status"] == "blocked":
            ctx.http.evict(resp)
            return res.mark(Status.BLOCKED, parsed["reason"], reason_code="challenge")
        if parsed["status"] == "error":
            ctx.http.evict(resp)  # never serve an unusable copy for 7 days
            return res.mark(Status.ERROR, f"{gtm_id}: {parsed['reason']}")
        res.attr("gtm_container", container)
        if parsed["status"] == "empty":
            return res.mark(Status.EMPTY, f"{gtm_id}: {parsed['reason']}")
        res.attr("gtm_loaded_ids", parsed["ids"])
        res.attr("gtm_linker_domains", parsed["linker_domains"])
        res.attr("gtm_host_map", parsed["host_map"])
        res.attr("gtm_script_hosts", parsed["script_hosts"])
        res.attr("gtm_pixel_ids", parsed["facebook_pixel_ids"])
        day = fetched_at[:10]
        for item in parsed["ids"]:
            if item["template"] or item["kind"] == "dc":  # DC- ids are context only (not an analytics_id entity)
                continue
            how = "derived from a tag field" if item["derived"] else "quoted in the container configuration"
            res.pivot(T.ANALYTICS_ID, item["id"], "gtm_loads", confidence="probable",
                      note=f"{KIND_LABELS.get(item['kind'], item['kind'])} id configured in GTM container {gtm_id} ({how}; fetched from Google "
                           f"{day}): a container fact, never alone a same-owner link")
        if not parsed["ids"]:
            res.finding(
                "GTM container loads no other measurement id",
                "info",
                f"{gtm_id} (version {parsed['version']}) exists but configures no GA4/UA/Ads/Floodlight id other than itself.",
                confidence="confirmed",
                source=SOURCE,
            )
        return res
