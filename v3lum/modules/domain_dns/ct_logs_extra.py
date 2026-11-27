"""Certificate Transparency from small operators (P001 ct_logs_extra, opt-in): crt.name and MerkleMap.

P001 cond 1: the operators of crt.name and MerkleMap are unknown tier (A8) until a promotion is
recorded, so they live in this separate module: ``default_enabled = False``, excluded at TLP:AMBER and
above, ``--allow-unknown`` at CLEAR/GREEN (policy gate). Per-source terms (cond 2): crt.name 'unknown'
(licence-blocked in every profile until reviewed, A1), MerkleMap 'key-terms' on a company account.
Keys ``crtname`` (optional) and ``merklemap`` (required by that source) are Bearer headers only (cond 3).

Same hostname sink, statuses and pivots as ``ct_logs`` (shared helpers of that module): names are
validated and kept only under the queried registrable domain, wildcards become ``wildcard_cert``, a
source that does not answer is 'could not verify' and keeps its own status. crt.name answers
text/plain, one host name per line (NDJSON framing tolerated); a name that is not an apex answers 400
'invalid apex'. The MerkleMap answer shape is UNVERIFIED (no keyed sample: research saw only 401):
``{count, results: [{hostname|domain|name|subject_common_name}]}`` or a bare list are accepted.
"""

from __future__ import annotations

import concurrent.futures
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.ct_logs import (
    HostnameSink,
    SourceOutcome,
    UnexpectedAnswer,
    emit_subdomain_pivots,
    looks_like_html,
    mark_no_answer,
    psl,
    record_source_status,
    registrable,
    run_source,
    stop_reason_for,
)

SRC_CRTNAME = "crtname.search"
SRC_MERKLEMAP = "merklemap.search"
CRTNAME_URL = "https://crt.name/v1/search"
MERKLEMAP_URL = "https://api.merklemap.com/v1/search"
MERKLEMAP_MAX_PAGES = 3
BUDGET = 25.0
SUBDOMAINS_ATTR_CAP = 5000


def parse_crtname(text: Any, sink: HostnameSink, source: str = SRC_CRTNAME) -> int:
    """crt.name answer (text/plain, one host name per line; NDJSON framing tolerated) -> names in ``sink``.

    Returns the number of lines read. Raises UnexpectedAnswer for HTML pages and 'invalid apex' bodies
    (could not verify, never 'no names')."""
    body = text if isinstance(text, str) else ""
    if looks_like_html(body):
        raise UnexpectedAnswer("HTML instead of a host name list")
    low = body.strip().lower()
    if low.startswith("invalid apex") or low.startswith("error"):
        raise UnexpectedAnswer(f"error text instead of a host name list ({body.strip()[:80]})")
    lines = 0
    for line in body.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        lines += 1
        if item[0] in '{["':
            try:
                value = json.loads(item)
            except ValueError:
                value = None
            if isinstance(value, str):
                sink.add(value, source)
            elif isinstance(value, dict):
                name = next((value[k] for k in ("name", "hostname", "domain", "dns_name", "value") if isinstance(value.get(k), str)), None)
                if name is None:
                    sink.rejected["not_hostname"] += 1
                else:
                    sink.add(name, source)
            elif isinstance(value, list):
                for v in value:
                    sink.add(v, source)
            else:
                sink.rejected["not_hostname"] += 1
            continue
        sink.add(item, source)
    return lines


def parse_merklemap(data: Any, sink: HostnameSink, source: str = SRC_MERKLEMAP) -> tuple[int, int | None]:
    """MerkleMap search page -> names in ``sink``; returns ``(records on the page, total count or None)``.

    UNVERIFIED shape (no keyed sample): ``{count, results: [...]}`` or a bare list of strings/objects."""
    count: int | None = None
    if isinstance(data, dict):
        if data.get("error") or (data.get("message") and not data.get("results")):
            raise UnexpectedAnswer(f"error object instead of results ({str(data.get('error') or data.get('message'))[:80]})")
        results = data.get("results")
        if isinstance(data.get("count"), int) and not isinstance(data.get("count"), bool):
            count = int(data["count"])
    elif isinstance(data, list):
        results = data
    else:
        results = None
    if not isinstance(results, list):
        raise UnexpectedAnswer(f"{type(data).__name__} without a results list")
    for item in results:
        if isinstance(item, str):
            sink.add(item, source)
        elif isinstance(item, dict):
            for key in ("hostname", "domain", "name", "subject_common_name"):
                if isinstance(item.get(key), str):
                    sink.add(item[key], source)
    return len(results), count


@register
class CtLogsExtra(Module):
    name = "ct_logs_extra"
    title = "Certificate Transparency (crt.name, MerkleMap)"
    description = "Subdomains of a registrable domain from the crt.name and MerkleMap Certificate Transparency indexes (unknown-tier operators, opt-in)."
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    terms = "unknown"  # crt.name terms not reviewed (P001 cond 2)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "crtname"
    sources = (SRC_CRTNAME, SRC_MERKLEMAP)
    hosts = ("crt.name", "api.merklemap.com")
    access_model = "free_noauth_limited"
    optional_keys = ("crtname", "merklemap")
    max_requests = 1 + MERKLEMAP_MAX_PAGES
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 100
    default_enabled = False  # unknown tier and unknown terms (A3, A8; P001 cond 1)
    reference = "https://crt.name/"
    tags = {"cert_derived"}
    notice = (
        "crt.name and MerkleMap are unknown-tier operators (A8): never default, excluded at TLP:AMBER and above, "
        "--allow-unknown at CLEAR/GREEN. crt.name terms are unreviewed (licence-blocked until legal reviews them); "
        "MerkleMap needs a company-account key (key-terms)."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Registrable domains only (crt.name answers 400 'invalid apex' otherwise; P001 cond 7)."""
        name = str(entity.value)
        return psl.is_known_tld(name.rsplit(".", 1)[-1]) and registrable(name) == name

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value)
        allowed = ctx.allowed_sources
        clock = getattr(ctx.http, "clock", None)
        deadline = (clock.monotonic() if clock is not None else 0.0) + BUDGET
        tasks: list[tuple[SourceOutcome, Callable[[SourceOutcome], None], bool]] = []
        missing_key = False
        if SRC_CRTNAME in allowed:
            key = ctx.key("crtname")
            tasks.append((SourceOutcome(SRC_CRTNAME, "crt.name"), lambda o: self._crtname(o, ctx, apex, key, deadline), bool(key)))
        if SRC_MERKLEMAP in allowed:
            key = ctx.key("merklemap")
            if key:
                tasks.append((SourceOutcome(SRC_MERKLEMAP, "MerkleMap"), lambda o: self._merklemap(o, ctx, apex, key, deadline), True))
            else:
                missing_key = True
                res.source_status(SRC_MERKLEMAP, Status.NEEDS_KEY, reason="MerkleMap needs the merklemap key (Bearer)")
        if not tasks:
            if missing_key:
                return res.mark("needs_key", "MerkleMap needs the merklemap key and crt.name is not allowed in this run")
            return res.mark("skipped", "no allowed source for this run", reason_code="config")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="ct_logs_extra") as pool:
            futures = [pool.submit(run_source, outcome, fn, keyed=keyed) for outcome, fn, keyed in tasks]
            for fut in futures:
                fut.result()
        outcomes = [t[0] for t in tasks]
        stop = next((o.stop for o in outcomes if o.stop is not None), None)
        self._build(res, ctx, apex, outcomes, deadline)
        if stop is not None:
            raise stop
        return res

    @staticmethod
    def _crtname(out: SourceOutcome, ctx: Any, apex: str, key: str, deadline: float) -> None:
        out.sink = HostnameSink(apex)
        headers = {"Accept": "text/plain"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        resp = ctx.http.get(CRTNAME_URL + "?" + urlencode({"apex": apex}), headers=headers, source=SRC_CRTNAME, deadline=deadline)
        ctx.http.check(resp)  # 400 'invalid apex', 403/429/5xx and challenge pages raise (could not verify)
        out.pages = 1
        parse_crtname(resp.text, out.sink)
        out.status = "ok" if (out.sink.names or out.sink.wildcards) else "empty"

    @staticmethod
    def _merklemap(out: SourceOutcome, ctx: Any, apex: str, key: str, deadline: float) -> None:
        out.sink = HostnameSink(apex)
        headers = {"Accept": "application/json", "Authorization": f"Bearer {key}"}
        seen = 0
        for page in range(MERKLEMAP_MAX_PAGES):
            url = MERKLEMAP_URL + "?" + urlencode({"query": f"*.{apex}", "page": page})
            data = ctx.http.get_json(url, headers=headers, source=SRC_MERKLEMAP, deadline=deadline)
            records, total = parse_merklemap(data, out.sink)
            out.pages += 1
            seen += records
            if not records or (total is not None and seen >= total):
                break
        else:
            out.partial = True
            out.reason_code = "request_cap"  # the module's own page cap: stop reason request_cap
            out.reason = f"MerkleMap page cap reached ({MERKLEMAP_MAX_PAGES} pages): more names may exist"
        out.status = "ok" if (out.sink.names or out.sink.wildcards) else "empty"

    @staticmethod
    def _build(res: ModuleResult, ctx: Any, apex: str, outcomes: list[SourceOutcome], deadline: float) -> None:
        sink = HostnameSink(apex)
        for o in outcomes:
            record_source_status(res, o)
            if o.answered and o.sink is not None:
                sink.merge(o.sink)
        res.raw = {
            "apex": apex,
            "sources": {o.source: {"label": o.label, "status": o.status, "reason": o.reason, "partial": o.partial, "pages": o.pages} for o in outcomes},
            "rejected_names": dict(sink.rejected),
            "names": {n: list(info.sources) for n, info in list(sink.names.items())[:SUBDOMAINS_ATTR_CAP]},
        }
        answered = [o for o in outcomes if o.answered]
        if not answered:
            mark_no_answer(res, outcomes)
            return
        incomplete = [o for o in outcomes if o.partial or o.failed]
        if incomplete:
            res.partial = True
            stop = stop_reason_for(incomplete)
            if stop:
                res.stop(stop)
            res.error = "partial: " + ("; ".join(o.reason for o in incomplete if o.reason) or "a source could not be verified")
        if not (sink.names or sink.wildcards):
            res.mark("empty")
            return
        res.attr("subdomains", sink.subdomains()[:SUBDOMAINS_ATTR_CAP])
        res.attr("wildcard_cert", sink.wildcard_labels())
        historical, unresolved = emit_subdomain_pivots(res, ctx, sink, deadline)
        res.attr("ct_names_historical", historical)
        res.attr("ct_names_unresolved", unresolved)
