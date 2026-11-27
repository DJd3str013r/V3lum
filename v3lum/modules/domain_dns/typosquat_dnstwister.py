"""dnstwister.report adapter (P012 cond 11): one fuzz call per brand, candidates checked like the local engine.

The dnstwister.report API receives the brand domain, so this adapter is a separate, opt-in module:
``default_enabled = False``, community tier, excluded at TLP:AMBER and above (checked before any
request), one ``/api/fuzz/{hex}`` call per brand (7-day cache). dnstwister's ``/api/ip``, ``/api/mx``,
``/api/whois`` and ``/api/parked`` endpoints are never called (``parked`` makes dnstwister fetch the
lookalike): the returned candidates go through the same core DoH pipeline, .br RDAP and severity
ladder as ``typosquat`` (``ForwardScan``).

The provider's terms are 'unknown' since 2026-11-26 (the dnstwister.report homepage now redirects to
the commercial dnstwister.com and no terms are published for the free API): the licence gate keeps the
module disabled in every profile until legal records them (backlog p1-G01-2). The local engine
(``typosquat``) covers the same permutations without disclosing the brand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core import tlp as _tlp
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns import typosquat_permutations as perm
from v3lum.modules.domain_dns.typosquat import (
    SOURCE_BCB,
    SOURCE_DOH,
    SOURCE_RDAP_BR,
    ForwardScan,
    _bcb_dataset,
    _host_under,
    _int_setting,
    _org_entries,
    is_registrable,
    owner_facts,
    run_forward_scan,
)

SOURCE = "dnstwister.fuzz"
FUZZ = "https://dnstwister.report/api/fuzz/{hex}"

#: dnstwister fuzzer labels -> the local engine's fuzzer names (ranking weights)
_FUZZER_MAP = {
    "original": "*original", "addition": "addition", "bitsquatting": "bitsquatting", "cyrillic": "cyrillic",
    "homoglyph": "homoglyph", "hyphenation": "hyphenation", "insertion": "insertion", "omission": "omission",
    "plural": "plural", "repetition": "repetition", "replacement": "replacement", "subdomain": "subdomain",
    "transposition": "transposition", "vowel swap": "vowel-swap", "vowel-swap": "vowel-swap", "various": "various",
    "common tlds": "tld-swap", "tld swap": "tld-swap", "tld-swap": "tld-swap", "dictionary": "dictionary",
}


def dnstwister_hex(domain: Any) -> str | None:
    """dnstwister's path encoding: hex of the ASCII (punycode) domain, as /api/to_hex returns it."""
    ascii_name = perm.idna_ascii(str(domain or "").strip().rstrip("."))
    return ascii_name.encode("ascii").hex() if ascii_name else None


def _salvage(text: str) -> list[Any]:
    """Complete JSON objects of a truncated ``fuzzy_domains`` array."""
    i = text.find('"fuzzy_domains"')
    i = text.find("[", i) if i >= 0 else -1
    if i < 0:
        return []
    dec = json.JSONDecoder()
    pos, n, out = i + 1, len(text), []
    while pos < n:
        while pos < n and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= n or text[pos] != "{":
            break
        try:
            obj, pos = dec.raw_decode(text, pos)
        except ValueError:
            break
        out.append(obj)
    return out


def parse_fuzz(body: Any) -> dict[str, Any]:
    """/api/fuzz/{hex} body (bytes, text or parsed JSON) -> {domain, candidates:[{domain, domain_unicode,
    fuzzer, fuzzer_raw}], partial, error}. Entries are kept only when ``domain_as_hexadecimal`` decodes
    to ``domain`` and the name passes UTS-46 + VALID_FQDN; entries without a fuzzer label (dictionary
    names) get 'dictionary'; a truncated body keeps its complete entries with partial=True."""
    partial = False
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", errors="replace")
    if isinstance(body, str):
        try:
            data: Any = json.loads(body)
        except ValueError:
            entries = _salvage(body)
            if not entries:
                return {"domain": None, "candidates": [], "partial": False, "error": "malformed JSON"}
            m = re.match(r'\s*\{\s*"domain"\s*:\s*"([^"]{1,253})"', body)
            data = {"domain": m.group(1) if m else None, "fuzzy_domains": entries}
            partial = True
    else:
        data = body
    if not isinstance(data, Mapping) or not isinstance(data.get("fuzzy_domains"), list):
        return {"domain": None, "candidates": [], "partial": partial, "error": "unexpected answer (no fuzzy_domains list)"}
    seen: set[str] = set()
    cands: list[dict[str, Any]] = []
    for e in data["fuzzy_domains"]:
        if not isinstance(e, Mapping) or not isinstance(e.get("domain"), str):
            continue
        dom = e["domain"].strip().lower()
        hx = e.get("domain_as_hexadecimal")
        if isinstance(hx, str):
            try:
                if bytes.fromhex(hx).decode("ascii", "strict").lower() != dom:
                    continue
            except (ValueError, UnicodeError):
                continue
        ascii_name = perm.idna_ascii(dom)
        if not ascii_name or ascii_name != dom or not perm.VALID_FQDN.match(dom):
            continue
        raw = e.get("fuzzer") if isinstance(e.get("fuzzer"), str) else None
        fuzzer = _FUZZER_MAP.get(raw.strip().lower(), "various") if raw else "dictionary"
        if fuzzer == "*original" or dom in seen:
            continue
        seen.add(dom)
        cands.append({"domain": dom, "domain_unicode": perm.idna_unicode(dom), "fuzzer": fuzzer, "fuzzer_raw": (raw or "")[:40]})
    top = data.get("domain")
    return {"domain": top.lower() if isinstance(top, str) else None, "candidates": cands, "partial": partial, "error": None}


def _score(cands: Iterable[Mapping[str, Any]], seed: str) -> list[dict[str, Any]]:
    """Rank dnstwister candidates with the local engine's weights (P012 c5)."""
    base_tld = perm.split_domain(seed)[2]
    out = []
    for c in cands:
        tld = perm.split_domain(c["domain"])[2]
        score = perm.FUZZER_WEIGHT.get(c["fuzzer"], 20) + (3 if tld == base_tld else 0) + (6 if perm.is_br(tld) else 0)
        score += (4 if tld in perm.TLD_SWAP_PRIMARY else 0) + (3 if tld in perm.ABUSED_TLDS else 0)
        out.append({**c, "score": score})
    return out


@register
class TyposquatDnstwister(Module):
    name = "typosquat_dnstwister"
    title = "Typosquat candidates from dnstwister.report (opt-in)"
    description = (
        "Fetches dnstwister.report's permutation list for a brand domain (one call, discloses the brand) and checks the "
        "candidates through the core DoH resolver like the local typosquat engine."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    run_on = "seeds"
    reference = "https://dnstwister.report/api/"
    notice = (
        "Sends the brand domain to dnstwister.report (third party): opt-in, excluded at TLP:AMBER and above. Provider terms "
        "are 'unknown' (homepage now a commercial product): disabled by the licence gate until legal records them. "
        "The local typosquat engine covers the same permutations without disclosure."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "dnstwister"
    sources = (SOURCE, SOURCE_DOH, SOURCE_RDAP_BR, SOURCE_BCB)
    hosts = ("dnstwister.report", "rdap.registro.br")
    access_model = "free_noauth_limited"
    max_requests = 11  # one fuzz call + at most 10 RDAP lookups of .br candidates
    expected_latency = 20.0
    timeout = 45.0
    min_interval = 2.0
    daily_quota = 20
    cache_ttl = 604800  # deterministic permutation list: 7 days
    max_pivots = 100
    default_enabled = False
    error_markers = (
        {
            "id": "dnstwister_worker_error",
            "statuses": [500, 502, 503],
            "json_path": None,
            "equals": None,
            "regex": r"error code:\s*1\d{3}",
            "final_url_regex": None,
            "maps_to": "error",
            "reason_code": "error",
            "reason": "dnstwister.report: Cloudflare Workers error page (error code 1xxx): could not verify",
        },
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            level = _tlp.parse(getattr(ctx, "tlp", "") or "red")
        except (ValueError, TypeError):
            level = _tlp.TLP.RED  # unreadable TLP fails closed
        if level >= _tlp.TLP.AMBER:
            return res.mark(
                "skipped", f"dnstwister.report discloses the brand to a third party: excluded at TLP:{level.name.replace('_', '+')}"
                " and above (P012 cond 11); the local typosquat engine needs no disclosure", reason_code="tlp",
            )
        if not getattr(ctx, "is_seed", True) or not is_registrable(entity.value):
            return res.mark("skipped", "dnstwister runs once per brand: analyst-typed registrable domains only", reason_code="not_applicable")
        org = getattr(ctx, "org", None)
        owned = False
        try:
            owned = bool(org is not None and org.owns(entity).own)
        except Exception:
            owned = False
        include = getattr(getattr(ctx, "options", None), "include", None) or set()
        if not owned and self.name not in include:
            return res.mark("skipped", f"not an org_profile domain: select -M {self.name} to fuzz it through dnstwister.report",
                            reason_code="not_applicable")
        hx = dnstwister_hex(entity.value)
        if not hx:
            return res.mark("error", "the domain cannot be IDNA-encoded for dnstwister")
        resp = ctx.http.get(FUZZ.format(hex=hx), source=SOURCE)
        ctx.http.check(resp)  # error pages, 429, challenges and 5xx raise (rule 5)
        parsed = parse_fuzz(resp.content if resp.content else resp.text)
        if parsed["error"]:
            return res.mark("error", f"dnstwister.report: {parsed['error']}: could not verify")
        candidates = _score(parsed["candidates"], entity.value)
        org_domains, _brands = _org_entries(org)
        bcb_rows, _note = _bcb_dataset(ctx)
        owner = owner_facts(entity, org, [d["domain"] for d in org_domains if d.get("source") == "org_profile"], bcb_rows)
        own_rows = [c for c in candidates if _host_under(c["domain"], owner["domains"])]
        scan = [c for c in candidates if c not in own_rows]
        deep = str(getattr(getattr(ctx, "options", None), "preset", "") or "") == "deep"
        limit = _int_setting(ctx, "typosquat_candidates_deep" if deep else "typosquat_candidates", 500 if deep else 150, 1, 2000)
        ranked, cap_hit = perm.rank(scan, limit)
        coverage: dict[str, Any] = {
            "mode": "forward via dnstwister.report" + (" (deep)" if deep else ""), "seed": entity.value,
            "candidates_generated": len(candidates), "candidates_ranked": len(ranked), "candidate_cap": limit,
            "candidate_cap_hit": cap_hit, "dnstwister_partial": parsed["partial"],
        }
        rdap_cap = min(_int_setting(ctx, "typosquat_rdap_lookups", 10, 0, 100), int(self.max_requests) - 1)
        scanner = ForwardScan(ctx, res, seed=entity.value, owner=owner, deep=deep, rdap_cap=rdap_cap, max_pivots=int(self.max_pivots))
        res = run_forward_scan(scanner, ranked, coverage, own_rows, seed_label=entity.display)
        if parsed["partial"] and not res.partial and res.status.value in ("ok", "empty"):
            res.stop("request_cap")  # dnstwister's body was cut: the candidate list is partial, never complete
        return res
