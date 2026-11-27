"""Web archives, deep sources (P059 cond 3): Common Crawl (latest 1-2 indexes) and CarbonDate.

These sources are slow or touch the live site, so they run only with ``--preset deep`` or an explicit
``-M web_archives_deep`` (``default_enabled = False``):

* Common Crawl: ``collinfo.json`` (cached 7 days), then the newest ``web_archives_deep_crawls``
  indexes (default 2) with backoff - after a reset, 5xx or timeout the older index is not asked; a
  per-crawl 404 'No Captures found' is 'no records in this crawl', never 'never archived'. The newest
  homepage capture can be read from its WARC record by byte range on data.commoncrawl.org (1 MB cap,
  never cached, decompression bounded): only extracted indicators plus SHA-256 are kept (P059 c6).
* CarbonDate (``fetches_target``: it may read the live URI): only a scheme-less host/path is sent,
  never a URL carrying a query string, credentials, tokens or e-mail addresses (P059 c3). Its answer is
  an estimate, never a registration date.

Archived URLs pass the same redaction as ``web_archives`` (core helper + archive masking) before they
reach pivots, attributes or evidence. Archived URLs are never requested from the live target.
"""

from __future__ import annotations

import json
import re
import zlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.url_web.web_archives import (
    HOMEPAGE_MAX_BYTES,
    ROW_CAP,
    _cdx_result,
    _row,
    _split,
    clean,
    failure,
    homepage_indicators,
    is_masked,
    looks_like_html,
    query_target,
    redact_archived_url,
    report_failure,
    text_of,
)

SRC_CC = "commoncrawl.cdx_index"
SRC_WARC = "commoncrawl.web_archives_deep_warc"
SRC_CD = "odu_carbondate.carbondate"
COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CARBONDATE = "https://carbondate.cs.odu.edu"
_CC_FILENAME = re.compile(r"^crawl-data/CC-MAIN-\d{4}-\d{2,4}/[A-Za-z0-9._/-]+\.(?:warc|arc)\.gz$")
_CC_ID = re.compile(r"^CC-MAIN-\d{4}-\d{2,4}$")

# =====================================================================================
# parsers (pure, never raise on junk)
# =====================================================================================


def parse_collinfo(raw: Any, latest: int = 2) -> dict[str, Any]:
    """index.commoncrawl.org/collinfo.json -> the newest ``latest`` indexes (P059 c3: latest 1-2).
    Entries whose cdx-api is not https://index.commoncrawl.org/CC-MAIN-* are ignored."""
    try:
        obj = json.loads(text_of(raw)) if not isinstance(raw, list) else raw
    except ValueError:
        return {"indexes": [], "total": 0, "error": "malformed JSON"}
    if not isinstance(obj, list):
        return {"indexes": [], "total": 0, "error": "unexpected answer (not a list)"}
    good = []
    for e in obj:
        if not isinstance(e, Mapping):
            continue
        api, cid = e.get("cdx-api"), e.get("id")
        if not isinstance(api, str) or not isinstance(cid, str) or not _CC_ID.match(cid):
            continue
        parts = _split(api)
        if parts is None or parts.scheme != "https" or parts.hostname != "index.commoncrawl.org" or not parts.path.startswith("/CC-MAIN-"):
            continue
        good.append({"id": cid, "cdx_api": api, "to": e.get("to") if isinstance(e.get("to"), str) else ""})
    good.sort(key=lambda x: (x["to"], x["id"]), reverse=True)
    return {"indexes": good[: max(0, int(latest))], "total": len(good), "error": None}


def parse_cc_cdx(raw: Any, row_cap: int = ROW_CAP, body_truncated: bool = False) -> dict[str, Any]:
    """Common Crawl per-crawl CDX (output=json: NDJSON) -> rows (+ WARC pointers in memory)."""
    text = text_of(raw)
    if not text.strip():
        return _cdx_result([], state="empty")
    if looks_like_html(text):
        return _cdx_result([], error="HTML instead of NDJSON")
    rows: list[dict[str, Any]] = []
    partial = bool(body_truncated)
    stop = "body_truncated" if body_truncated else None
    lines = text.split("\n")
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            partial = True
            stop = "body_truncated" if idx >= len(lines) - 1 else "malformed_line"
            continue
        if not isinstance(obj, Mapping):
            continue
        if len(rows) >= row_cap:
            partial, stop = True, "row_cap"
            break
        row = _row(obj.get("url"), obj.get("timestamp"), obj.get("status"), obj.get("mime"))
        if row is None:
            continue
        for key in ("filename", "offset", "length"):
            if isinstance(obj.get(key), str):
                row["_" + key] = obj[key]
        rows.append(row)
    if not rows and partial:
        return _cdx_result([], partial=True, stop=stop, error="malformed NDJSON")
    return _cdx_result(rows, partial=partial, stop=stop)


def record_request(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """WARC record fetch for a Common Crawl row: {url, headers: {Range}} or None when the pointer is
    missing or invalid (path traversal, non-numeric offset, length > 1 MB)."""
    fn, off, ln = row.get("_filename"), row.get("_offset"), row.get("_length")
    if not (isinstance(fn, str) and _CC_FILENAME.match(fn) and ".." not in fn):
        return None
    if not (isinstance(off, str) and off.isdigit() and isinstance(ln, str) and ln.isdigit()):
        return None
    start, length = int(off), int(ln)
    if length <= 0 or length > HOMEPAGE_MAX_BYTES:
        return None
    return {"url": "https://data.commoncrawl.org/" + fn, "headers": {"Range": f"bytes={start}-{start + length - 1}"}}


def _bounded_gunzip(data: bytes, limit: int) -> bytes | None:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit + 1)
    except zlib.error:
        return None
    return out[:limit] if out else None


def _split_head(block: bytes) -> tuple[bytes, bytes] | None:
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = block.find(sep)
        if i >= 0:
            return block[:i], block[i + len(sep):]
    return None


def _dechunk(body: bytes, limit: int) -> bytes:
    out, pos = bytearray(), 0
    while pos < len(body) and len(out) <= limit:
        end = body.find(b"\r\n", pos)
        if end < 0:
            break
        try:
            size = int(body[pos:end].split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
        if size <= 0:
            break
        out += body[end + 2:end + 2 + size]
        pos = end + 2 + size + 2
    return bytes(out[:limit])


def parse_warc_record(data: Any, limit: int = HOMEPAGE_MAX_BYTES) -> dict[str, Any] | None:
    """One gzip member holding a WARC 'response' record -> {http_status, content_type, body} or None.

    Decompression is bounded (``limit``); chunked transfer and gzip content encoding are undone
    within the same bound. The body is returned for indicator extraction only and never stored."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    raw = _bounded_gunzip(bytes(data), limit * 2)
    if not raw or not raw.startswith(b"WARC/"):
        return None
    head = _split_head(raw)
    if head is None:
        return None
    warc_headers, block = head
    if b"warc-type: response" not in warc_headers.lower():
        return None
    http = _split_head(block)
    if http is None:
        return None
    status_head, body = http
    lines = status_head.decode("iso-8859-1", errors="replace").splitlines()
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    headers = {}
    for line in lines[1:]:
        name, _sep, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body, limit)
    if "gzip" in headers.get("content-encoding", "").lower():
        body = _bounded_gunzip(body, limit) or b""
    return {"http_status": int(m.group(1)) if m else None, "content_type": headers.get("content-type", ""), "body": body[:limit + 1]}


def _parse_dt(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_carbondate(raw: Any) -> dict[str, Any]:
    """carbondate.cs.odu.edu/cd/{uri} -> {state: ok|empty|error, estimated_creation, earliest_sources,
    sources, error}. Every source empty (seen live for well-known sites) is 'empty': no estimate,
    never 'new site'."""
    try:
        obj = json.loads(text_of(raw)) if not isinstance(raw, Mapping) else raw
    except ValueError:
        return {"state": "error", "estimated_creation": None, "earliest_sources": [], "sources": {}, "error": "malformed JSON"}
    if not isinstance(obj, Mapping) or "estimated-creation-date" not in obj:
        return {"state": "error", "estimated_creation": None, "earliest_sources": [], "sources": {}, "error": "unexpected answer"}
    est = _parse_dt(obj.get("estimated-creation-date"))
    sources = {}
    src = obj.get("sources") if isinstance(obj.get("sources"), Mapping) else {}
    for name, value in list(src.items())[:20]:
        if isinstance(value, Mapping):
            d = _parse_dt(value.get("earliest"))
            if d:
                sources[clean(str(name), 40)] = d
    earliest = [clean(x, 40) for x in obj.get("earliest-sources") or [] if isinstance(x, str)][:10]
    return {"state": "ok" if est else "empty", "estimated_creation": est, "earliest_sources": earliest, "sources": sources, "error": None}


def carbondate_path(url: Any) -> str | None:
    """Request path for CarbonDate, or None when the URL must not be sent (P059 c3: never URLs carrying
    tokens, query strings, credentials or recipient identifiers; http(s) only). The scheme-less form
    is used because the server merges '//' in the path."""
    if not isinstance(url, str) or not url.strip():
        return None
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    parts = _split(u)
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.query or parts.fragment or parts.username or parts.password or is_masked(redact_archived_url(u)[1]):
        return None
    host = parts.hostname.lower()
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    path = parts.path if parts.path not in ("", "/") else ""
    if not re.fullmatch(r"[A-Za-z0-9._~/%!$&'()*+,;=:@-]*", path):
        return None
    return "/cd/" + host + path


# =====================================================================================
# the module
# =====================================================================================


@register
class WebArchivesDeep(Module):
    name = "web_archives_deep"
    title = "Web archives, deep sources (Common Crawl, CarbonDate)"
    description = (
        "Common Crawl's newest indexes (captures, archived URLs and the homepage WARC record) and a CarbonDate creation "
        "estimate; slow sources, run only with --preset deep or -M."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.URL, T.ANALYTICS_ID, T.CNPJ}
    run_on = "seeds"
    tags = {"slow"}
    reference = "https://index.commoncrawl.org/"
    notice = (
        "CarbonDate may read the live page (fetches_target): it never receives URLs with query strings, credentials, tokens "
        "or e-mail addresses. Common Crawl WARC bodies are kept only as indicators plus SHA-256."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "commoncrawl"
    sources = (SRC_CC, SRC_WARC, SRC_CD)
    hosts = ("index.commoncrawl.org", "data.commoncrawl.org", "carbondate.cs.odu.edu")
    access_model = "free_noauth_limited"
    max_requests = 6  # collinfo, two crawl indexes, one WARC record, CarbonDate (+1 spare)
    expected_latency = 15.0
    timeout = 60.0
    cache_ttl = 86400
    max_pivots = 40
    default_enabled = False
    settings = {
        "web_archives_deep_crawls": SettingSpec(2, "web_archives_deep: newest Common Crawl indexes queried (1-2, P059 c3)"),
        "web_archives_deep_record": SettingSpec(True, "web_archives_deep: read the homepage WARC record (1 MB) for indicators"),
        "web_archives_deep_carbondate": SettingSpec(True, "web_archives_deep: ask CarbonDate for a creation estimate (fetches_target)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_target(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        sources: dict[str, str] = {}
        failures: dict[str, dict[str, Any]] = {}
        rows, homepage = self._commoncrawl(ctx, q, sources, failures)
        estimate = self._carbondate(ctx, q, sources, failures)
        for source_id, out in failures.items():
            report_failure(res, source_id, out)
        res.attr("archive_sources", sources)
        answered = [k for k, v in sources.items() if v.startswith(("ok", "empty"))]
        if not answered:
            reasons = "; ".join(str(f.get("reason")) for f in failures.values()) or "no deep source ran"
            code = "timeout" if failures and all(f.get("reason_code") == "timeout" for f in failures.values()) else "error"
            if failures and all(f.get("status") == "rate_limited" for f in failures.values()):
                return res.mark("rate_limited", f"could not verify: {reasons}", reason_code="rate_limited")
            return res.mark("error", f"could not verify: {reasons}", reason_code=code)
        stamps = sorted(r["captured_at"] for r in rows if r.get("captured_at"))
        if stamps:
            res.attr("archive_first", stamps[0])
            res.attr("archive_last", stamps[-1])
            distinct = sorted({r["url"] for r in rows})
            res.attr("archive_count", len(distinct))
            res.attr("archived_urls", distinct[:500])
            for url in [u for u in distinct if not any(r.get("secret_masked") for r in rows if r["url"] == u)][:20]:
                res.pivot(T.URL, url, "archived_url", confidence="probable", expand=False,
                          note="historical URL from Common Crawl: never requested from the live site")
        if homepage:
            res.attr("homepage_indicators", homepage)
            when = str(homepage.get("captured_at") or "")[:10]
            for item in (homepage.get("analytics_ids") or [])[:10]:
                res.pivot(T.ANALYTICS_ID, item["id"], "same_analytics", confidence="probable", expand=False,
                          note=f"tracking id on the Common Crawl homepage capture ({when})")
            for cnpj in (homepage.get("cnpjs") or [])[:5]:
                res.pivot(T.CNPJ, cnpj, "company_of", confidence="possible", expand=False,
                          note=f"CNPJ printed on the Common Crawl homepage capture ({when}): analyst selection required")
        if estimate and estimate.get("state") == "ok":
            res.attr("archive_estimate", {k: estimate[k] for k in ("estimated_creation", "earliest_sources", "sources")})
        if stamps or (estimate and estimate.get("state") == "ok"):
            res.finding(
                "Deep web-archive history",
                "info",
                (f"Common Crawl: first capture {stamps[0][:10]}, last {stamps[-1][:10]} in the newest crawls (a lower bound of web "
                 "presence, never a registration date). " if stamps else "")
                + (f"CarbonDate estimate: {estimate['estimated_creation'][:10]} (an estimate, never a registration date"
                   + ("; weak: only the live page's Last-Modified header" if estimate.get("earliest_sources") == ["last-modified"] else "")
                   + ")." if estimate and estimate.get("state") == "ok" else ""),
                confidence="probable",
                data={"sources": sources, "captures": len(rows)},
                tags=["info"],
                source=SRC_CC if stamps else SRC_CD,
                observed_first=stamps[0] if stamps else None,
            )
        res.raw = {"query": redact_archived_url(q["query"])[0], "sources": sources,
                   "rows": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows[:1000]],
                   "homepage": homepage, "carbondate": estimate}
        if any(str(v).find("partial") >= 0 for v in sources.values()):
            res.stop("request_cap")
        return res

    # ---- Common Crawl ---------------------------------------------------------------------------
    def _get(self, ctx: Any, endpoint: str, source_id: str, url: str, sources: dict[str, str], failures: dict[str, Any], **kw: Any) -> Any:
        try:
            resp = ctx.http.get(url, source=source_id, **kw)
            if resp.status == 404 and source_id == SRC_CC and "no captures found" in text_of(resp.content)[:500].lower():
                return resp  # documented per-crawl absence: handled by the caller
            ctx.http.check(resp)
            return resp
        except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
            out = failure(endpoint, exc)
            sources[endpoint] = f"{out['status']}: {out['reason']}"
            failures.setdefault(source_id, out)
            return None

    def _commoncrawl(self, ctx: Any, q: Mapping[str, Any], sources: dict[str, str], failures: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        crawls = max(1, min(2, _int(ctx.setting("web_archives_deep_crawls", 2), 2)))
        resp = self._get(ctx, "commoncrawl_collinfo", SRC_CC, COLLINFO, sources, failures, ttl=604800, timeout=20)
        if resp is None:
            return [], None
        info = parse_collinfo(resp.content, crawls)
        if info["error"] or not info["indexes"]:
            sources["commoncrawl_collinfo"] = f"could_not_verify: {info['error'] or 'no usable index'}"
            failures.setdefault(SRC_CC, {"status": "could_not_verify", "reason_code": "error", "reason": f"commoncrawl collinfo: {info['error'] or 'no usable index'}"})
            return [], None
        sources["commoncrawl_collinfo"] = "ok"
        rows: list[dict[str, Any]] = []
        params = {"url": q["query"], "output": "json", "limit": "1000"}
        if q["kind"] == "domain":
            params["matchType"] = "domain"
        for idx in info["indexes"]:
            endpoint = f"commoncrawl_{idx['id']}"
            resp = self._get(ctx, endpoint, SRC_CC, idx["cdx_api"], sources, failures, params=params, ttl=86400, timeout=20)
            if resp is None:
                break  # backoff: an overloaded index server is not asked for the older crawl
            if resp.status == 404:
                sources[endpoint] = "empty (no records in this crawl)"
                continue
            result = parse_cc_cdx(resp.content, body_truncated=bool(getattr(resp, "truncated", False)))
            if result["state"] == "error":
                sources[endpoint] = f"could_not_verify: {result['error']}"
                failures.setdefault(SRC_CC, {"status": "could_not_verify", "reason_code": "error", "reason": f"{endpoint}: {result['error']}"})
                break
            rows.extend(result["rows"])
            sources[endpoint] = ("ok" if result["rows"] else "empty (no records in this crawl)") + (
                f", partial: {result['stop']}" if result["partial"] else "")
        homepage = None
        if rows and bool(ctx.setting("web_archives_deep_record", True)):
            homepage = self._record(ctx, q, rows, sources, failures)
        return rows, homepage

    def _record(self, ctx: Any, q: Mapping[str, Any], rows: list[dict[str, Any]], sources: dict[str, str], failures: dict[str, Any]) -> dict[str, Any] | None:
        best = None
        for r in rows:
            parts = _split(r.get("_original") or "")
            if parts is None or r.get("statuscode") != "200" or "html" not in str(r.get("mimetype") or "html"):
                continue
            home = parts.path in ("", "/") and not parts.query if q["kind"] == "domain" else (r.get("_original") or "").rstrip("/") == str(q["query"]).rstrip("/")
            if home and (best is None or r["timestamp"] > best["timestamp"]):
                best = r
        req = record_request(best) if best else None
        if req is None:
            sources["commoncrawl_warc_record"] = "not_run: no homepage capture with a usable WARC pointer"
            return None
        resp = self._get(ctx, "commoncrawl_warc_record", SRC_WARC, req["url"], sources, failures, headers=req["headers"], ttl=0,
                         timeout=20, max_bytes=HOMEPAGE_MAX_BYTES + 1)
        if resp is None:
            return None
        record = parse_warc_record(resp.content)
        if record is None or not record.get("body"):
            sources["commoncrawl_warc_record"] = "could_not_verify: unreadable WARC record"
            return None
        sources["commoncrawl_warc_record"] = "ok"
        indicators = homepage_indicators(record["body"], content_type=record.get("content_type"))
        return {"source": "commoncrawl", "snapshot": redact_archived_url(best.get("_original") or "")[0], "captured_at": best.get("captured_at"), **indicators}

    # ---- CarbonDate ------------------------------------------------------------------------------
    def _carbondate(self, ctx: Any, q: Mapping[str, Any], sources: dict[str, str], failures: dict[str, Any]) -> dict[str, Any] | None:
        if not bool(ctx.setting("web_archives_deep_carbondate", True)):
            sources["carbondate"] = "not_run: disabled (web_archives_deep_carbondate)"
            return None
        target = f"http://{q['domain']}/" if q["kind"] == "domain" else str(q["query"])
        path = carbondate_path(target)
        if path is None:
            sources["carbondate"] = "not_run: the URL carries a query string, credentials or identifiers (never sent, P059 c3)"
            return None
        resp = self._get(ctx, "carbondate", SRC_CD, CARBONDATE + path, sources, failures, ttl=604800, timeout=30)
        if resp is None:
            return None
        parsed = parse_carbondate(resp.content)
        if parsed["state"] == "error":
            sources["carbondate"] = f"could_not_verify: {parsed['error']}"
            failures.setdefault(SRC_CD, {"status": "could_not_verify", "reason_code": "error", "reason": f"carbondate: {parsed['error']}"})
            return None
        sources["carbondate"] = "ok" if parsed["state"] == "ok" else "empty (no estimate: never 'new site')"
        return parsed


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
