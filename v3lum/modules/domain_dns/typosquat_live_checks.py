# Portions adapted from dnstwist (https://github.com/elceef/dnstwist),
# commit 341395377f40761fe4152f43fd18eea757b6069a (version 20250130), dnstwist.py UrlOpener._normalize.
# Copyright (c) Marcin Ulikowski. Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License. You may obtain a copy at
# http://www.apache.org/licenses/LICENSE-2.0. Modified: per-attribute (non-greedy) normalisation.
"""Typosquat live checks (P025, batch p9-G13-1): LIGHT page similarity of registered lookalikes.

Final conditions (FC) of P025 and where they are met:

* FC1 MX-spy is removed: no SMTP dialogue with any server, in any mode. Mail capability comes only
  from DNS facts already in the case (MX, null MX, SPF, DMARC; :func:`mail_capability`), worded
  ``can receive mail (reply/BEC risk)``. Nothing here opens a connection to ports 25/465/587.
* FC2 opsec LIGHT, disclosure 'target', default_enabled False, analyst-typed seeds only. Per candidate:
  one GET of the homepage (manual redirects, at most 5 hops) plus the favicon for its mmh3; no form
  is submitted, nothing is downloaded, non-HTML bodies are discarded unparsed.
* FC3 targets: a seed that is itself a lookalike is checked directly. An org-profile brand seed lists
  the registered lookalikes the P012 typosquat module found in the case (``live_check_candidates``)
  and never contacts them from the brand run: they are checked only when the analyst confirms them as
  seeds (core TTY confirmation, recorded in the case audit). At most :data:`MAX_LIGHT_CANDIDATES`
  candidates are contacted per run.
* FC4 passive first: unregistered names, names without an address, parked names (parking NS/IP) and
  defensive registrations (NS/registrant in the org profile's own domains, P012 own/defensive verdicts)
  are classified from the case graph (and passive DoH when the graph has no DNS facts, or no address for a
  registered name: 'no address' is never assumed from a partial case) and never fetched.
* FC5 the hostile-host guard of the core (GUARD-01) refuses lookalikes of an org brand from the
  corporate egress unless proxy_light or ``--egress-override`` is recorded: BLOCKED 'hostile_host'
  plus the manual link (urlscan search). A redirect hop the guard refuses ends the run the same way.
* FC6 every request goes through ``ctx.http`` (SSRF/address guard on every hop, seed binding, A7
  ceilings, ua_light, request ledger); redirects are followed by hand (:func:`safe_get` of the
  shared LIGHT helper) and re-checked; bodies are capped at :data:`MAX_BODY_BYTES`.
* FC7 similarity: ppdeep (optional extra) over :func:`normalize_html`, plus title, form-action hosts,
  login-form shape and favicon mmh3 (shared favicon helper); a shared form-action host or a login form
  on both pages scores the form component. JavaScript is never executed. The
  comparison against the brand reference page (the brand seed's ``page_fingerprint`` fetched once in
  the same LIGHT run) is made by the correlation rules of ``v3lum/correlations/p9_g13_1.py``, so the
  order in which the brand and its lookalikes run does not matter (:func:`compare_fingerprints`).
* FC8 no headless browser, screenshot or pHash.
* FC9 states: parked, defensive (never flagged), live clone (score >= :data:`LIVE_CLONE_THRESHOLD`),
  unrelated, could not verify; plain wording, 'lookalike / phishing-capable indicator', never
  'malicious' alone.
* FC10 the dnstwist web app is never used; the adapted normalisation carries the Apache-2.0 header
  above and the notice ``v3lum/data/notices/dnstwist_page_normalisation.json``.
"""

from __future__ import annotations

import importlib
import re
import threading
from collections.abc import Iterable, Mapping
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from v3lum.core import noise, psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked, NetworkError, PolicyError, RateLimited, normalize_host
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, package_available, register
from v3lum.modules.url_web.favicon import ICON_ACCEPT, classify_favicon_response, extract_icon_links, favicon_hashes
from v3lum.modules.url_web.light_fetch import Fetched, content_type, looks_like_html, safe_get

__all__ = [
    "LIVE_CLONE_THRESHOLD",
    "MAIL_LABEL",
    "MAX_BODY_BYTES",
    "MAX_LIGHT_CANDIDATES",
    "SIMILARITY_WEIGHTS",
    "TyposquatLiveChecks",
    "address_facts",
    "best_comparison",
    "brand_references",
    "compare_fingerprints",
    "defensive_redirect",
    "load_ppdeep",
    "mail_capability",
    "normalize_html",
    "page_features",
    "parked_marker",
    "passive_classify",
    "ppdeep_hash",
    "verdict_wording",
]

#: FC9: a candidate whose page scores at least this much against the brand page is a likely live clone
#: (dnstwist's note: >= 50 % on a registered lookalike is a HIGH finding).
LIVE_CLONE_THRESHOLD = 50
#: FC3: at most this many candidates are contacted per run (architect's cap).
MAX_LIGHT_CANDIDATES = 20
#: FC6: body cap of the homepage GET (a larger page is not compared).
MAX_BODY_BYTES = 2 * 1024 * 1024
#: below this many normalised bytes ppdeep gives no usable hash (dnstwist skips '3::').
MIN_NORMALISED_BYTES = 64
#: FC7: score = 70 % ppdeep similarity + 10 same title + 10 same favicon + 10 form match (a form-action host
#: both pages share, or a login form on both pages).
SIMILARITY_WEIGHTS = {"html_fuzzy": 0.70, "title": 0.10, "favicon": 0.10, "form": 0.10}
#: FC1 wording.
MAIL_LABEL = "can receive mail (reply/BEC risk)"
INDICATOR = "lookalike / phishing-capable indicator"
#: favicon cap (the shared favicon helper's limit) and hops for the icon GET
FAVICON_MAX_BYTES = 1_048_576
#: page verdicts change: cached homepage answers live 6 h (never above A10's 30 days)
PAGE_TTL = 6 * 3600
MODULE_NAME = "typosquat_live_checks"
#: runtime.meta key of the per-run contacted-candidate set (FC3 cap)
_RUN_KEY = "typosquat_live_checks.contacted"
_RUN_LOCK = threading.Lock()

# ======================================================================================
# FC7 normalisation (dnstwist-derived, Apache-2.0 header above)
# ======================================================================================

_NORM_ATTR = re.compile(rb"\b(action|src|href)\s*=\s*(\"[^\"]*\"|'[^']*')", re.I)
_NORM_CSS_URL = re.compile(rb"url\([^)]*\)", re.I)


def _to_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    return str(body).encode("utf-8", "replace")


def normalize_html(body: Any) -> bytes:
    """Collapse whitespace and blank the values of action/src/href attributes and every CSS url(...), so
    links (absolute in a clone, relative on the brand) do not dominate the fuzzy hash. Adapted from
    dnstwist ``UrlOpener._normalize`` with the greedy patterns made per attribute."""
    content = b" ".join(_to_bytes(body)[:MAX_BODY_BYTES].split())
    content = _NORM_ATTR.sub(lambda m: m.group(1) + b'=""', content)
    return _NORM_CSS_URL.sub(b"url()", content)


# ======================================================================================
# FC2/FC7 page features (HTML only, never executed)
# ======================================================================================


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False
        self._title_buf: list[str] = []
        self.forms: list[str] = []
        self.password_inputs = 0
        self.meta_refresh: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {str(k).lower(): (v or "") for k, v in attrs if k}
        if tag == "title" and self.title is None:
            self._in_title = True
        elif tag == "form" and len(self.forms) < 20:
            self.forms.append(a.get("action", "").strip())
        elif tag == "input" and a.get("type", "").strip().lower() == "password":
            self.password_inputs += 1
        elif tag == "meta" and a.get("http-equiv", "").strip().lower() == "refresh" and self.meta_refresh is None:
            m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = m.group(1).strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title = False
            self.title = " ".join("".join(self._title_buf).split())[:300]

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self._title_buf) < 50:
            self._title_buf.append(data)


#: FC9 'parked': parking-page markers (lower-case substrings of the page)
PARKED_MARKERS = (
    "this domain may be for sale", "this domain is for sale", "buy this domain", "domain is parked", "parked free",
    "parkingcrew", "sedoparking", "bodis.com", "above.com", "dan.com/buy", "afternic", "hugedomains", "domain parking",
    "este domínio está à venda", "este dominio esta a venda", "este domínio pode estar à venda",
)


def _site(host: str) -> str:
    host = normalize_host(host)
    return psl.registrable_domain(host) or host


def page_features(body: Any, base_url: str, ctype: Any = "text/html") -> dict[str, Any]:
    """Features of a fetched homepage. Non-HTML bodies are discarded unparsed (FC2): ``{"html": False}``.
    Returns title, form-action hosts, whether a password form posts off-site, the meta-refresh target,
    parking markers and the normalised length used for ppdeep."""
    raw = _to_bytes(body)
    text_type = str(ctype or "").split(";", 1)[0].strip().lower()
    html_type = text_type in ("text/html", "application/xhtml+xml") or (not text_type and looks_like_html(raw))
    if not raw:
        return {"html": False, "reason": "empty body"}
    if not html_type:
        return {"html": False, "reason": f"non-HTML body ({text_type or 'unknown type'}) discarded unparsed"}
    parser = _PageParser()
    try:
        parser.feed(raw.decode("utf-8", "replace"))
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup: keep what was parsed so far
        pass
    base = base_url if isinstance(base_url, str) else ""
    base_host = normalize_host(urlsplit(base).hostname or "")
    hosts: list[str] = []
    for action in parser.forms:
        try:
            absu = urljoin(base, action) if action else base
            host = normalize_host(urlsplit(absu).hostname or "")
        except ValueError:
            continue
        if host and host not in hosts:
            hosts.append(host)
    refresh = None
    if parser.meta_refresh:
        try:
            refresh = urljoin(base, parser.meta_refresh)
        except ValueError:
            refresh = None
    low = raw[:200_000].decode("utf-8", "replace").lower()
    parked = [m for m in PARKED_MARKERS if m in low]
    offsite = sorted(h for h in hosts if base_host and _site(h) != _site(base_host))
    return {
        "html": True,
        "title": parser.title,
        "form_action_hosts": hosts[:10],
        "login_form": parser.password_inputs > 0,
        "posts_offsite": bool(parser.password_inputs and offsite),
        "offsite_form_hosts": offsite[:10],
        "meta_refresh": refresh,
        "parked_markers": parked[:5],
        "normalised_bytes": len(normalize_html(raw)),
    }


def parked_marker(features: Mapping[str, Any] | None) -> str | None:
    """FC9 'parked' reason of a fetched page, else None."""
    if not isinstance(features, Mapping) or not features.get("html"):
        return None
    marks = list(features.get("parked_markers") or [])
    return f"parking page ({', '.join(marks[:3])})" if marks else None


def _host_of(url: Any) -> str:
    try:
        return normalize_host(urlsplit(str(url)).hostname or "")
    except ValueError:
        return ""


def _within(host: str, zones: Iterable[str]) -> str:
    for zone in zones:
        z = normalize_host(zone)
        if z and (host == z or host.endswith("." + z)):
            return z
    return ""


def defensive_redirect(urls: Iterable[Any], brand_hosts: Iterable[str]) -> str | None:
    """FC4/FC9 'defensive': the candidate sends visitors (HTTP redirect or meta refresh) to a brand host."""
    brands = [b for b in brand_hosts if isinstance(b, str) and b]
    for url in urls:
        host = _host_of(url)
        if host and _within(host, brands):
            return f"redirects to the brand ({str(url).split('?', 1)[0][:200]})"
    return None


# ======================================================================================
# FC1 mail capability and FC4 passive classification (graph facts only)
# ======================================================================================


def mail_capability(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Passive mail capability from DNS facts already gathered (no SMTP, ever).

    ``facts``: ``mx`` (list of hosts, '.' or '' for a null MX; None = unknown), ``has_address``, ``spf``
    and ``dmarc`` (record strings or None), ``mx_status`` ('ok' | 'nxdomain' | 'could_not_verify').
    """
    mx = facts.get("mx")
    out: dict[str, Any] = {"can_receive_mail": None, "label": "could not verify mail capability", "null_mx": False,
                           "mx_hosts": [], "spf_all": None, "dmarc_policy": None, "source": "dns facts (no SMTP contact)"}
    if facts.get("mx_status") == "nxdomain":
        out.update(can_receive_mail=False, label="name does not exist (no mail)")
    elif isinstance(mx, list):
        hosts = [str(h).strip().lower().rstrip(".") for h in mx]
        real = [h for h in hosts if h]
        if hosts and not real:
            out.update(can_receive_mail=False, null_mx=True, label="declares it receives no mail (null MX, RFC 7505)")
        elif real:
            out.update(can_receive_mail=True, mx_hosts=sorted(set(real))[:8], label=MAIL_LABEL)
        elif facts.get("has_address"):
            out.update(can_receive_mail="possible", label="no MX but has an address: may receive mail via implicit MX (RFC 5321 5.1)")
        elif facts.get("has_address") is False:
            out.update(can_receive_mail=False, label="no MX and no address (no mail)")
        else:
            out.update(can_receive_mail="possible", label="no MX; implicit MX depends on A/AAAA (unknown)")
    spf = facts.get("spf")
    if isinstance(spf, str) and spf.lower().startswith("v=spf1"):
        m = re.search(r"(?:^|\s)([-~?+]?)all\b", spf, re.I)
        out["spf_all"] = ((m.group(1) or "+") + "all") if m else None
    dmarc = facts.get("dmarc")
    if isinstance(dmarc, str) and dmarc.lower().startswith("v=dmarc1"):
        m = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", dmarc, re.I)
        out["dmarc_policy"] = m.group(1).lower() if m else None
    return out


def passive_classify(facts: Mapping[str, Any], *, own_zones: Iterable[str] = (), parking_ns: Any = None) -> dict[str, Any]:
    """FC4 (P376 passive first): classify a candidate WITHOUT contacting it.

    Returns ``{"state", "reason", "contact"}`` with state 'unregistered' | 'defensive' | 'parked' |
    'no_address' | 'could_not_verify' | 'fetch'; only 'fetch' allows the LIGHT GET. ``parking_ns`` is
    a callable host -> bool (default: the core noise lists, MISP parking-domain-ns via P169)."""
    own = [z for z in own_zones if z]
    if facts.get("own_verdict"):
        return {"state": "defensive", "reason": f"own or defensive registration ({facts['own_verdict']})", "contact": False}
    registered = facts.get("registered")
    if registered is False:
        return {"state": "unregistered", "reason": "not registered (NXDOMAIN)", "contact": False}
    ns = [normalize_host(h) for h in facts.get("ns") or [] if isinstance(h, str)]
    for host in ns:
        zone = _within(host, own)
        if zone:
            return {"state": "defensive", "reason": f"name server {host} is under the org profile domain {zone}", "contact": False}
    for url in facts.get("redirect_evidence") or []:
        hit = defensive_redirect([url], own + list(facts.get("brand_hosts") or []))
        if hit:
            return {"state": "defensive", "reason": f"archived/urlscan evidence: {hit}", "contact": False}
    if facts.get("parked"):
        return {"state": "parked", "reason": str(facts.get("parked_reason") or "parked (noise lists or P012)"), "contact": False}
    is_parking = parking_ns if callable(parking_ns) else _parking_ns
    for host in ns:
        if is_parking(host):
            return {"state": "parked", "reason": f"parking name server {host}", "contact": False}
    addrs = [a for a in list(facts.get("a") or []) + list(facts.get("aaaa") or []) if isinstance(a, str) and a]
    if registered is None and not ns and not addrs:
        return {"state": "could_not_verify", "reason": str(facts.get("dns_error") or "registration state unknown (DNS could not verify)"),
                "contact": False}
    if not addrs:
        if facts.get("address_status") == "could_not_verify":
            return {"state": "could_not_verify", "reason": "A/AAAA could not be verified (DNS error)", "contact": False}
        return {"state": "no_address", "reason": "no A/AAAA record (nothing to fetch)", "contact": False}
    return {"state": "fetch", "reason": "registered, has an address, not parked or defensive", "contact": True}


def _parking_ns(host: str) -> bool:
    ent = Entity.try_make(T.DOMAIN, host)
    try:
        return bool(ent is not None and noise.is_parked(ent))
    except Exception:  # noqa: BLE001 - a broken noise list never classifies
        return False


# ======================================================================================
# FC7 ppdeep and the comparison shared with the correlation rules
# ======================================================================================


def load_ppdeep() -> Any:
    """The optional ppdeep module (pure-Python ssdeep, Apache-2.0), or None when the extra is missing."""
    if not package_available("ppdeep"):
        return None
    try:
        return importlib.import_module("ppdeep")
    except Exception:  # noqa: BLE001 - a broken install is 'not installed'
        return None


def ppdeep_hash(ppdeep: Any, normalised: bytes) -> str | None:
    """ppdeep hash of normalised HTML, or None when the page is too small for a usable hash."""
    if ppdeep is None or len(normalised) < MIN_NORMALISED_BYTES:
        return None
    try:
        value = str(ppdeep.hash(normalised))
    except Exception:  # noqa: BLE001
        return None
    parts = value.split(":")
    if len(parts) != 3 or not parts[1]:
        return None
    return value


def _fuzzy(a: Any, b: Any, ppdeep: Any) -> int | None:
    if not (isinstance(a, str) and isinstance(b, str) and a and b):
        return None
    if a == b:
        return 100
    if ppdeep is None:
        return None
    try:
        return max(0, min(100, int(ppdeep.compare(a, b))))
    except Exception:  # noqa: BLE001
        return None


def compare_fingerprints(brand: Mapping[str, Any], cand: Mapping[str, Any], *, ppdeep: Any = None,
                         org_favicons: Iterable[Any] = ()) -> dict[str, Any]:
    """FC7/FC9: compare two ``page_fingerprint`` values. ``score`` is None when the ppdeep similarity is
    unavailable (tiny page, no ppdeep); ``state`` is 'live_clone' | 'unrelated' | 'could_not_verify'."""
    b = brand if isinstance(brand, Mapping) else {}
    c = cand if isinstance(cand, Mapping) else {}
    matched: list[str] = []
    bt = " ".join(str(b.get("title") or "").split()).casefold()
    ct = " ".join(str(c.get("title") or "").split()).casefold()
    title_eq = bool(bt) and bt == ct
    known = {str(v) for v in org_favicons if v not in (None, "")}
    bf, cf = b.get("favicon_mmh3"), c.get("favicon_mmh3")
    fav_eq = cf is not None and ((bf is not None and bf == cf) or str(cf) in known)
    # form features (FC7): the form-action hosts both pages share, or a password form on both pages
    shared = sorted({normalize_host(h) for h in b.get("form_action_hosts") or [] if isinstance(h, str)}
                    & {normalize_host(h) for h in c.get("form_action_hosts") or [] if isinstance(h, str)} - {""})
    login_both = bool(b.get("login_form")) and bool(c.get("login_form"))
    form_eq = login_both or bool(shared)
    fuzzy = _fuzzy(b.get("ppdeep"), c.get("ppdeep"), ppdeep)
    if fuzzy:
        matched.append(f"normalised HTML ppdeep {fuzzy}%")
    if title_eq:
        matched.append(f"same title '{str(c.get('title'))[:120]}'")
    if fav_eq:
        matched.append(f"same favicon mmh3 {cf}")
    if login_both:
        matched.append("login form with a password field on both pages")
    if shared:
        matched.append("form posts to the brand's host " + ", ".join(shared[:3]))
    if c.get("posts_offsite"):
        matched.append("password form posts off-site to " + ", ".join(list(c.get("offsite_form_hosts") or c.get("form_action_hosts") or [])[:3]))
    hashes = {"ppdeep_brand": b.get("ppdeep"), "ppdeep_candidate": c.get("ppdeep"), "favicon_mmh3_brand": bf, "favicon_mmh3_candidate": cf}
    out: dict[str, Any] = {"score": None, "html_fuzzy": fuzzy, "matched": matched, "title_match": title_eq, "favicon_match": fav_eq,
                           "form_match": form_eq, "hashes": hashes, "state": "could_not_verify"}
    if fuzzy is None:
        return out
    w = SIMILARITY_WEIGHTS
    score = round(w["html_fuzzy"] * fuzzy + 100 * (w["title"] * title_eq + w["favicon"] * fav_eq + w["form"] * form_eq))
    out["score"] = int(score)
    out["state"] = "live_clone" if score >= LIVE_CLONE_THRESHOLD else "unrelated"
    return out


def brand_references(graph: Any, brands: Iterable[str]) -> list[tuple[Any, Mapping[str, Any]]]:
    """``(node, page_fingerprint)`` of every brand reference page recorded in the case for ``brands``
    (a brand domain or one of its subdomains, role 'brand_reference' of this module)."""
    zones = [normalize_host(b) for b in brands if isinstance(b, str) and normalize_host(b)]
    out: list[tuple[Any, Mapping[str, Any]]] = []
    if graph is None or not zones:
        return out
    for node in _nodes(graph):
        if node.entity.type is not T.DOMAIN or not _within(normalize_host(node.entity.value), zones):
            continue
        for value, source in node.attributes.get("page_fingerprint", []):
            if source == MODULE_NAME and isinstance(value, Mapping) and value.get("role") == "brand_reference":
                out.append((node, value))
                break
    return out


def best_comparison(refs: Iterable[tuple[Any, Mapping[str, Any]]], cand: Mapping[str, Any], *, ppdeep: Any = None,
                    org_favicons: Iterable[Any] = ()) -> tuple[Any, dict[str, Any]] | None:
    """The highest-scoring comparison of a candidate page with the brand reference pages (None when no
    comparison gives a score), as ``(brand node, comparison)``; the comparison carries ``brand``,
    ``brand_url`` and the FC9 ``wording``."""
    favicons = list(org_favicons)
    best: tuple[Any, dict[str, Any]] | None = None
    for node, ref in refs:
        cmp = compare_fingerprints(ref, cand, ppdeep=ppdeep, org_favicons=favicons)
        if cmp["score"] is None or (best is not None and cmp["score"] <= best[1]["score"]):
            continue
        url = str(ref.get("final_url") or ref.get("url") or node.entity.value)
        cmp.update(brand=normalize_host(node.entity.value), brand_url=url, wording=verdict_wording(cmp["state"], cmp["score"], url))
        best = (node, cmp)
    return best


def verdict_wording(state: str, score: Any, brand_url: str) -> str:
    """FC9 plain wording (never 'malicious')."""
    if state == "live_clone":
        return f"page {score}% similar to {brand_url} -> likely live clone ({INDICATOR})"
    if state == "unrelated":
        return f"page {score}% similar to {brand_url} -> unrelated content"
    return f"could not compare with {brand_url}: page too small or similarity unavailable"


# ======================================================================================
# graph facts
# ======================================================================================


def _case_graph(ctx: Any) -> Any:
    """The case graph of this scan (passive results of the entity are merged before LIGHT runs, A13)."""
    return getattr(getattr(getattr(ctx, "runtime", None), "policy_context", None), "graph", None)


def _nodes(graph: Any) -> list[Any]:
    for _ in range(3):  # the engine may add nodes while we read: retry a changed-size iteration
        try:
            return list(getattr(graph, "nodes", {}).values())
        except RuntimeError:
            continue
    return []


def _edges(graph: Any) -> list[Any]:
    for _ in range(3):
        try:
            return list(getattr(graph, "edges", []) or [])
        except RuntimeError:
            continue
    return []


def _org_domains(org: Any) -> list[str]:
    out: list[str] = []
    for entry in getattr(org, "domains", ()) or ():
        name = normalize_host(getattr(entry, "name", "") or "")
        if name and name not in out:
            out.append(name)
    return out


def _str_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if isinstance(value, str) and value else []


def _p012_rows(graph: Any, domain: str) -> tuple[dict[str, Any], str]:
    """(merged P012 row for ``domain``, own/defensive verdict) from ``typosquat_lookalikes`` /
    ``typosquat_own_registrations`` of any node."""
    row: dict[str, Any] = {}
    verdict = ""
    for node in _nodes(graph):
        for own in node.attr_values("typosquat_own_registrations"):
            if isinstance(own, Mapping) and normalize_host(own.get("domain") or "") == domain:
                verdict = str(own.get("ownership") or "own_asset")
        for item in node.attr_values("typosquat_lookalikes"):
            if isinstance(item, Mapping) and normalize_host(item.get("domain") or "") == domain:
                for k, v in item.items():
                    if v not in (None, "", [], {}) and k not in row:
                        row[k] = v
    if str(row.get("ownership") or "") in ("own_asset", "defensive_probable") and not verdict:
        verdict = str(row["ownership"])
    return row, verdict


def graph_facts(graph: Any, domain: str) -> dict[str, Any]:
    """What the case graph already says about ``domain`` (nothing is fetched)."""
    facts: dict[str, Any] = {"registered": None, "ns": [], "a": [], "aaaa": [], "mx": None, "spf": None, "dmarc": None,
                             "parked": False, "parked_reason": "", "own_verdict": "", "redirect_evidence": [], "dns_known": False}
    if graph is None:
        return facts
    row, verdict = _p012_rows(graph, domain)
    facts["own_verdict"] = verdict
    node = graph.get(f"domain:{domain}") if hasattr(graph, "get") else None
    ns: list[str] = []
    a: list[str] = []
    aaaa: list[str] = []
    mx: list[str] | None = None
    if node is not None:
        flags = [v for v in node.attr_values("registered") if isinstance(v, bool)]
        if True in flags:
            facts["registered"] = True
        elif flags:
            facts["registered"] = False
        ns += [str(h) for h in node.attr_values("nameservers") if isinstance(h, str)]
        a += [str(v) for v in node.attr_values("a_records") if isinstance(v, str)]
        aaaa += [str(v) for v in node.attr_values("aaaa_records") if isinstance(v, str)]
        if "mx" in node.attributes:
            mx = [str(v) for v in node.attr_values("mx") if isinstance(v, str)]
            if not mx and any(isinstance(v, list) and not v for v, _src in node.attributes.get("mx", [])):
                mx = []
        spf = [v for v in node.attr_values("spf") if isinstance(v, str)]
        dmarc = [v for v in node.attr_values("dmarc") if isinstance(v, str)]
        facts["spf"] = spf[0] if spf else None
        facts["dmarc"] = dmarc[0] if dmarc else None
        if node.tagged("parked") or node.noise_kind == "parked" or any(v is True for v in node.attr_values("is_parked")):
            facts["parked"], facts["parked_reason"] = True, "parked (case graph: noise lists or a parked tag)"
        for value in node.attr_values("redirect_relations"):
            if isinstance(value, Mapping) and value.get("to"):
                facts["redirect_evidence"].append(str(value.get("to")))
        for edge in _edges(graph):
            if edge.src == node.key and edge.relation in ("resolves_to",):
                kind, _, val = edge.dst.partition(":")
                (a if kind == "ipv4" else aaaa if kind == "ipv6" else []).append(val)
            elif edge.src == node.key and edge.relation == "nameserver" and edge.dst.startswith("domain:"):
                ns.append(edge.dst.split(":", 1)[1])
    ns += _str_list(row.get("ns"))
    a += _str_list(row.get("a"))
    if row.get("mx") is not None or row.get("mx_present") is not None:
        mx = (mx or []) + _str_list(row.get("mx"))
    if row.get("parked") is True and not facts["parked"]:
        facts["parked"], facts["parked_reason"] = True, "parked (P012 typosquat: parking NS/IP)"
    if str(row.get("state") or "") == "registered" and facts["registered"] is None:
        facts["registered"] = True
    elif str(row.get("state") or "") in ("unregistered", "nxdomain") and facts["registered"] is None:
        facts["registered"] = False
    for ip in list(a) + list(aaaa):
        ip_node = graph.get(f"{'ipv6' if ':' in ip else 'ipv4'}:{ip}") if hasattr(graph, "get") else None
        if ip_node is not None and (ip_node.noise_kind == "parked" or "parked" in ip_node.tags):
            facts["parked"], facts["parked_reason"] = True, f"parking IP {ip} (noise lists)"
    facts["ns"] = sorted({normalize_host(h) for h in ns if normalize_host(h)})
    facts["a"] = sorted({x.strip() for x in a if x.strip()})
    facts["aaaa"] = sorted({x.strip() for x in aaaa if x.strip()})
    facts["mx"] = mx
    if facts["registered"] is None and (facts["ns"] or facts["a"] or facts["aaaa"] or mx):
        facts["registered"] = True
    facts["dns_known"] = bool(facts["ns"] or facts["a"] or facts["aaaa"] or mx is not None or facts["registered"] is not None)
    return facts


def dns_facts(ctx: Any, domain: str, facts: dict[str, Any]) -> dict[str, Any]:
    """Passive DoH for the facts the graph lacks (resolver queries only; the candidate is never contacted).
    Lookalike names are attacker-controlled: ``hostile=True`` keeps ECS off."""
    dns = getattr(ctx, "dns", None)
    if dns is None:
        facts.setdefault("dns_error", "no resolver")
        return facts

    def ask(rtype: str, name: str = domain) -> Any:
        try:
            return dns.query(name, rtype, hostile=True)
        except Exception as exc:  # noqa: BLE001 - a resolver failure is 'could not verify'
            facts["dns_error"] = f"{rtype}: {type(exc).__name__}"
            return None

    ns = ask("NS")
    if ns is not None and ns.nxdomain:
        confirmed = None
        try:
            confirmed = dns.confirm_nxdomain(domain, "NS", hostile=True)
        except Exception:  # noqa: BLE001
            confirmed = None
        if confirmed:
            facts["registered"] = False
            facts["mx_status"] = "nxdomain"
            return facts
        facts["dns_error"] = "NXDOMAIN not confirmed by a second resolver"
        facts["address_status"] = "could_not_verify"
        return facts
    if ns is not None and ns.ok:
        facts["ns"] = sorted({normalize_host(r.split()[-1]) for r in ns.records if r.strip()} - {""})
        facts["registered"] = True if facts["ns"] or facts["registered"] else facts["registered"]
    elif ns is not None:
        facts["dns_error"] = f"NS {ns.status}"
    for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
        ans = ask(rtype)
        if ans is None or ans.could_not_verify:
            facts.setdefault("address_status", "could_not_verify")
            continue
        facts[key] = sorted({r.strip() for r in ans.records if r.strip()})
        if ans.ok:
            facts["registered"] = True if (facts[key] or facts["registered"]) else facts["registered"]
    if facts.get("a") or facts.get("aaaa"):
        facts.pop("address_status", None)
    facts["address_checked"] = True
    mx = ask("MX")
    if mx is not None and mx.ok:
        facts["mx"] = [("" if r.split()[-1] in (".", "") else r.split()[-1].rstrip(".")) for r in mx.records if r.strip()]
        facts["mx_status"] = "ok"
    elif mx is not None and mx.nxdomain:
        facts["mx_status"] = "nxdomain"
    for name, key, prefix in ((domain, "spf", "v=spf1"), (f"_dmarc.{domain}", "dmarc", "v=dmarc1")):
        ans = ask("TXT", name)
        if ans is not None and ans.ok:
            recs = [str(r).strip().strip('"') for r in ans.records if str(r).strip().strip('"').lower().startswith(prefix)]
            facts[key] = recs[0] if recs else facts.get(key)
    return facts


def address_facts(ctx: Any, domain: str, facts: dict[str, Any]) -> dict[str, Any]:
    """FC4: A/AAAA through passive DoH when the case has no address for a registered candidate, so 'no
    address' is never assumed from a partial case (a P012 row without A, an IPv6-only lookalike). Only the
    resolvers are asked; the candidate is never contacted."""
    dns = getattr(ctx, "dns", None)
    if dns is None:
        facts["address_status"] = "could_not_verify"
        return facts
    for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
        try:
            ans = dns.query(domain, rtype, hostile=True)
        except Exception:  # noqa: BLE001 - a resolver failure is 'could not verify'
            ans = None
        if ans is None or ans.could_not_verify:
            facts["address_status"] = "could_not_verify"
            continue
        facts[key] = sorted({r.strip() for r in ans.records if r.strip()} | set(facts.get(key) or []))
    if facts.get("a") or facts.get("aaaa"):
        facts.pop("address_status", None)
    facts["address_checked"] = True
    return facts


# ======================================================================================
# the module
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: normalisation, page features, mail wording and the comparison (no network)."""
    sample = (b'<html><head><title>Example</title></head><body><a href="/x">x</a><form action="https://a.example/p">'
              b'<input type="password" name="p"></form>' + b"<p>text</p>" * 20 + b"</body></html>")
    if b'href=""' not in normalize_html(sample):
        return HealthResult("dead", "HTML normalisation self-test failed")
    feats = page_features(sample, "https://b.example/")
    if not (feats.get("html") and feats.get("title") == "Example" and feats.get("posts_offsite")):
        return HealthResult("dead", "page feature self-test failed")
    if page_features(b"PK\x05\x06", "https://b.example/", "application/zip").get("html"):
        return HealthResult("dead", "a non-HTML body was parsed")
    if mail_capability({"mx": ["mx.b.example"]})["label"] != MAIL_LABEL:
        return HealthResult("dead", "mail capability self-test failed")
    fp = {"ppdeep": "3:abc:def", "title": "Example", "favicon_mmh3": 1, "login_form": True}
    if compare_fingerprints(fp, dict(fp))["state"] != "live_clone":
        return HealthResult("dead", "comparison self-test failed")
    if load_ppdeep() is None:
        return HealthResult("ok", "normalisation, page features, mail wording and comparison ok; ppdeep (optional extra) is not "
                                  "installed, so runs are UNAVAILABLE 'package'")
    return HealthResult("ok", "normalisation, page features, mail wording and comparison ok")


def _domain_of(entity: Entity) -> str:
    if entity.type is T.DOMAIN:
        return normalize_host(entity.value)
    return _host_of(entity.value)


def _start_url(entity: Entity, domain: str) -> str:
    if entity.type is T.URL:
        try:
            parts = urlsplit(entity.value.strip())
        except ValueError:
            return f"https://{domain}/"
        if parts.scheme in ("http", "https") and parts.hostname:
            return parts._replace(fragment="").geturl()
    return f"https://{domain}/"


def _mode(ctx: Any) -> Opsec:
    """The scan mode of this run (PASSIVE when unknown: fail closed)."""
    try:
        return Opsec.parse(getattr(getattr(ctx, "options", None), "mode", Opsec.PASSIVE))
    except (KeyError, ValueError, TypeError):
        return Opsec.PASSIVE


def _egress(ctx: Any) -> str:
    try:
        return "proxy_light" if str(ctx.setting("proxy_light", "") or "").strip() else "default"
    except Exception:  # noqa: BLE001
        return "default"


def _now_iso(ctx: Any) -> str:
    try:
        return ctx.runtime.now().replace(microsecond=0).isoformat()
    except Exception:  # noqa: BLE001
        return ""


def _requests(ctx: Any) -> int:
    try:
        return int(getattr(ctx.http, "requests", 0) or 0)
    except Exception:  # noqa: BLE001
        return 0


def _reserve_slot(ctx: Any, domain: str) -> bool:
    """FC3: at most MAX_LIGHT_CANDIDATES contacted candidates per run (shared by every run of the scan)."""
    meta = getattr(getattr(ctx, "runtime", None), "meta", None)
    if not isinstance(meta, dict):
        return True
    with _RUN_LOCK:
        seen = meta.setdefault(_RUN_KEY, set())
        if domain in seen:
            return True
        if len(seen) >= MAX_LIGHT_CANDIDATES:
            return False
        seen.add(domain)
        return True


class _Outcome:
    """Result of the homepage step: the fingerprint (None when there is no comparable page), the module
    result to return early (None = keep going), and the live-check state with its reason."""

    __slots__ = ("failure", "fp", "reason", "state")

    def __init__(self) -> None:
        self.fp: dict[str, Any] | None = None
        self.failure: ModuleResult | None = None
        self.state = ""
        self.reason = ""

    def stop(self, state: str, reason: str, failure: ModuleResult | None = None) -> _Outcome:
        self.state, self.reason, self.failure = state, reason, failure
        return self


@register
class TyposquatLiveChecks(Module):
    name = "typosquat_live_checks"
    title = "Typosquat live checks (LIGHT page similarity)"
    description = (
        "LIGHT, analyst-typed seeds only: classifies a registered lookalike from the case's passive facts first (unregistered, "
        "parked, defensive, no address are never fetched), then makes one GET of its homepage plus the favicon and records a "
        "page fingerprint (ppdeep of normalised HTML, title, form-action hosts, favicon mmh3) that the p9g131 rules compare "
        "with the brand seed's page. Mail capability comes from DNS facts only (no SMTP, ever)."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.DOMAIN, T.URL}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://github.com/elceef/dnstwist"
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    requires_packages = ("ppdeep",)
    max_requests = 8  # homepage + up to 5 redirect hops + favicon (+ 1 icon hop)
    expected_latency = 3.0
    timeout = 60.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = PAGE_TTL
    max_pivots = 10
    default_enabled = False  # LIGHT is never default (A3); not enabled before the AR20 safety suite passes (FC11)
    manual_link = "https://urlscan.io/search/#domain:{q}"
    notice = (
        "LIGHT: contacts suspected lookalike infrastructure like a visitor (one homepage GET + favicon, ua_light), on "
        "analyst-typed seeds only, after the passive lane and through the hostile-host guard: configure proxy_light or "
        "record --egress-override. No SMTP, no form submission, no browser, no screenshot."
    )

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        res.raw = {}
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "LIGHT runs only on analyst-typed seeds, never on pivots (A7, FC3)", reason_code="scope")
        if _mode(ctx) < Opsec.LIGHT:
            # FC2 is stricter than light_for_own_assets: this module contacts hosts only under an explicit --mode light
            return res.mark("skipped", "runs only with --mode light (contacts the lookalike or brand host); nothing was fetched",
                            reason_code="opsec")
        domain = _domain_of(entity)
        if not domain:
            return res.mark("skipped", "no host name to check", reason_code="not_applicable")
        ppdeep = load_ppdeep()
        if ppdeep is None:  # FC7: checked before any contact
            return res.mark("unavailable", "needs python package: ppdeep (pip install 'v3lum[full]'); nothing was fetched",
                            reason_code="package")
        org = getattr(ctx, "org", None)
        graph = _case_graph(ctx)
        own = None
        try:
            own = org.owns(Entity.make(T.DOMAIN, domain)) if org is not None else None
        except Exception:  # noqa: BLE001 - a profile problem means 'not owned'
            own = None
        lookalikes = self._brand_lookalikes(graph, domain)
        if (own is not None and own.own) or lookalikes:
            return self._brand_run(res, ctx, entity, domain, lookalikes, ppdeep)
        if own is not None and getattr(own, "kind", "") == "supplier":
            return res.mark("skipped", f"{domain} is a supplier domain of the org profile: not a lookalike", reason_code="not_applicable")
        return self._candidate_run(res, ctx, entity, domain, graph, org, ppdeep)

    # ------------------------------------------------------------------ brand seed (FC3, FC7 reference)
    @staticmethod
    def _brand_lookalikes(graph: Any, domain: str) -> list[dict[str, Any]]:
        """Registered lookalikes P012 found for this brand domain in the case (listed, never contacted)."""
        if graph is None:
            return []
        node = graph.get(f"domain:{domain}") if hasattr(graph, "get") else None
        if node is None:
            return []
        out: dict[str, dict[str, Any]] = {}
        for row in node.attr_values("typosquat_lookalikes"):
            if not isinstance(row, Mapping):
                continue
            dom = normalize_host(row.get("domain") or "")
            state = str(row.get("state") or "")
            if dom and state == "registered":
                out.setdefault(dom, {"domain": dom, "state": "awaiting_confirmation",
                                     "reason": "registered lookalike (P012): confirm it as a LIGHT seed to check it"})
        for edge in _edges(graph):
            if edge.src == node.key and edge.relation == "lookalike" and edge.dst.startswith("domain:"):
                dom = edge.dst.split(":", 1)[1]
                out.setdefault(dom, {"domain": dom, "state": "awaiting_confirmation",
                                     "reason": "lookalike edge (P012): confirm it as a LIGHT seed to check it"})
        return [out[k] for k in sorted(out)]

    def _brand_run(self, res: ModuleResult, ctx: Any, entity: Entity, domain: str, lookalikes: list[dict[str, Any]], ppdeep: Any) -> ModuleResult:
        if lookalikes:
            listed = lookalikes[:MAX_LIGHT_CANDIDATES]
            res.attr("live_check_candidates", listed)
            res.raw["candidates_over_cap"] = max(0, len(lookalikes) - MAX_LIGHT_CANDIDATES)
        out = self._fetch_fingerprint(res, ctx, entity, domain, role="brand_reference", ppdeep=ppdeep, brand_hosts=[])
        if out.fp is not None:
            res.attr("page_fingerprint", out.fp)
        else:
            res.raw["brand_reference"] = {"state": out.state, "reason": out.reason}
        if out.failure is not None:
            return out.failure
        if out.fp is None and not lookalikes:
            # rule 5: a brand page that could not be read is 'could not verify', never an empty answer
            status = "error" if out.state in ("could_not_verify", "") else "empty"
            return res.mark(status, f"no brand reference page recorded for {domain}: {out.reason or 'no comparable page'}")
        return res

    # ------------------------------------------------------------------ candidate seed
    def _candidate_run(self, res: ModuleResult, ctx: Any, entity: Entity, domain: str, graph: Any, org: Any, ppdeep: Any) -> ModuleResult:
        brands = self._brand_hosts(graph, domain, org)
        facts = graph_facts(graph, domain)
        facts["brand_hosts"] = brands
        if not facts["dns_known"]:
            facts = dns_facts(ctx, domain, facts)
        # defensive = registered by the organisation itself: only its own domains count (a supplier's name
        # servers or a redirect to a supplier never make a lookalike 'defensive')
        own_zones = _org_domains(org)
        verdict = passive_classify(facts, own_zones=own_zones)
        if verdict["state"] == "no_address" and not facts.get("address_checked"):
            # the case holds no address for this name: ask the resolvers before calling it address-less
            facts = address_facts(ctx, domain, facts)
            verdict = passive_classify(facts, own_zones=own_zones)
        facts["has_address"] = bool(facts.get("a") or facts.get("aaaa")) if facts.get("address_status") != "could_not_verify" else None
        mail = mail_capability(facts)
        res.attr("mail_capability", mail)
        base = {"brands": brands[:20], "contacted": False, "requests": 0}
        if not verdict["contact"]:
            res.attr("live_check", {"state": verdict["state"], "reason": verdict["reason"], **base})
            if verdict["state"] == "could_not_verify":
                return res.mark("error", f"{domain}: could not verify ({verdict['reason']}); not contacted", reason_code="error")
            return res
        if not _reserve_slot(ctx, domain):
            res.attr("live_check", {"state": "could_not_verify", "reason": f"over the {MAX_LIGHT_CANDIDATES}-candidate cap of this run (FC3)", **base})
            return res.mark("skipped", f"over the {MAX_LIGHT_CANDIDATES}-candidate cap of this run: not contacted", reason_code="not_applicable")
        before = _requests(ctx)
        out = self._fetch_fingerprint(res, ctx, entity, domain, role="candidate", ppdeep=ppdeep, brand_hosts=brands)
        fp, failure = out.fp, out.failure
        state = out.state or ("fetched" if fp is not None else "could_not_verify")
        live = {"state": state, "reason": out.reason, **base, "contacted": _requests(ctx) > before,
                "requests": max(0, _requests(ctx) - before)}
        if fp is not None:
            live["reason"] = live["reason"] or ("page fingerprint recorded: compared with the brand page by the p9g131 rules"
                                                if brands else "page fingerprint recorded; no brand of the org profile or case to compare with")
            res.attr("page_fingerprint", fp)
            found = best_comparison(brand_references(graph, brands), fp, ppdeep=ppdeep,
                                    org_favicons=getattr(org, "favicon_hashes", ()) or ()) if fp.get("ppdeep") else None
            if found is not None:
                # the brand page was already in the case: record the verdict (the p9g131 rules report it)
                cmp = found[1]
                live["state"], live["reason"] = cmp["state"], cmp["wording"]
                live["comparison"] = {k: cmp[k] for k in ("brand", "brand_url", "score", "html_fuzzy", "matched", "hashes", "state", "wording")}
            for host in fp.get("offsite_form_hosts") or []:
                # an IOC taken from a hostile page: passive modules only, never contacted (A13)
                res.pivot(T.DOMAIN, host, "form_posts_to", confidence="probable", expand=False,
                          note="host a password form of the lookalike page posts to")
        res.attr("live_check", live)
        return failure if failure is not None else res

    @staticmethod
    def _brand_hosts(graph: Any, domain: str, org: Any) -> list[str]:
        """Protected domains this candidate imitates: lookalike edges of the case, P012 reverse matches and
        the org profile's domains (brand references and defensive-redirect targets)."""
        out: list[str] = []
        key = f"domain:{domain}"
        for edge in _edges(graph):
            if edge.relation == "lookalike" and edge.dst == key and edge.src.startswith("domain:"):
                out.append(edge.src.split(":", 1)[1])
            elif edge.relation == "lookalike_of" and edge.src == key and edge.dst.startswith("domain:"):
                out.append(edge.dst.split(":", 1)[1])
        out += _org_domains(org)
        seen: list[str] = []
        for host in out:
            h = normalize_host(host)
            if h and h != domain and h not in seen:
                seen.append(h)
        return seen

    # ------------------------------------------------------------------ one homepage GET + favicon
    def _fetch_fingerprint(self, res: ModuleResult, ctx: Any, entity: Entity, domain: str, *, role: str, ppdeep: Any,
                           brand_hosts: list[str]) -> _Outcome:
        """One homepage GET (manual redirects re-checked hop by hop) and, for a comparable HTML page, the
        favicon GET; returns the page fingerprint or why there is none."""
        url = _start_url(entity, domain)
        out = _Outcome()
        try:
            page = safe_get(ctx, url, accept=None, max_bytes=MAX_BODY_BYTES, entity=entity, ttl=PAGE_TTL)
        except Blocked as exc:
            code = str(getattr(exc, "reason_code", "") or "challenge")
            if code == "hostile_host":
                self._manual_pivots(res, domain)
            return out.stop("could_not_verify", f"blocked ({code})",
                            res.mark("blocked", f"could not verify {domain}: {str(exc)[:300]}", reason_code=code))
        except RateLimited as exc:
            return out.stop("could_not_verify", "rate limited (HTTP 429)",
                            res.mark("rate_limited", f"could not verify {domain}: {str(exc)[:200]}", reason_code="rate_limited"))
        except PolicyError as exc:
            return out.stop("could_not_verify", f"refused by policy ({exc.reason_code})",
                            res.mark("skipped", f"{domain}: {str(exc)[:300]}", reason_code=exc.reason_code))
        except NetworkError as exc:
            return out.stop("could_not_verify", f"network error ({type(exc).__name__})",
                            res.mark("error", f"could not verify {domain}: {str(exc)[:200]}", reason_code="error"))
        res.raw["homepage"] = {"url": page.url, "status": page.status, "hops": len(page.history), "from_cache": page.from_cache,
                               "truncated": page.truncated}
        if page.refused:
            hit = defensive_redirect([page.refused_url], brand_hosts)
            if hit:
                return out.stop("defensive", f"defensive registration: {hit}; not flagged")
            if page.refused_url and page.refused_url != url:
                res.pivot(T.URL, page.refused_url, "redirects_to", confidence="probable", expand=False,
                          note="redirect target of the homepage (not followed: outside the seed)")
            return out.stop("could_not_verify", page.refused[:300])
        hit = defensive_redirect(page.history[1:] + [page.url], brand_hosts) if page.history else None
        if hit:
            return out.stop("defensive", f"defensive registration: {hit}; not flagged")
        if page.blocked:
            if page.status == 429 or "rate_limited" in page.blocked_status.lower():
                return out.stop("could_not_verify", "rate limited (HTTP 429, not retried)",
                                res.mark("rate_limited", f"could not verify {domain}: HTTP 429 (not retried)", reason_code="rate_limited"))
            code = page.blocked_code if page.blocked_code in ("challenge", "geo_block", "login_wall", "hostile_host") else "challenge"
            return out.stop("could_not_verify", f"blocked: {page.blocked[:200]}",
                            res.mark("blocked", f"could not verify {domain}: {page.blocked[:200]} (not retried)", reason_code=code))
        if page.status >= 500 or page.status == 0:
            return out.stop("could_not_verify", f"HTTP {page.status}",
                            res.mark("error", f"could not verify {domain}: HTTP {page.status}", reason_code="error"))
        if page.status in (401, 403, 407, 451):
            return out.stop("could_not_verify", f"HTTP {page.status}",
                            res.mark("blocked", f"could not verify {domain}: HTTP {page.status}",
                                     reason_code="geo_block" if page.status == 451 else "challenge"))
        if not 200 <= page.status < 300:
            return out.stop("could_not_verify", f"HTTP {page.status}: no page to compare")
        if page.truncated:
            return out.stop("could_not_verify", f"page larger than {MAX_BODY_BYTES} bytes: not compared")
        feats = page_features(page.body, page.url, content_type(page.headers))
        if not feats.get("html"):
            return out.stop("could_not_verify", str(feats.get("reason") or "no HTML page"))
        if role == "candidate":
            refresh = feats.get("meta_refresh")
            hit = defensive_redirect([refresh], brand_hosts) if refresh else None
            if hit:
                return out.stop("defensive", f"defensive registration: meta refresh {hit}; not flagged")
            parked = parked_marker(feats)
            if parked:
                return out.stop("parked", f"parked lookalike ({parked})")
        normalised = normalize_html(page.body)
        digest = ppdeep_hash(ppdeep, normalised)
        fav = self._favicon(res, ctx, entity, page)
        out.fp = {
            "role": role,
            "url": url,
            "final_url": page.url,
            "http_status": page.status,
            "title": feats.get("title"),
            "ppdeep": digest,
            "normalised_bytes": len(normalised),
            "favicon_mmh3": fav.get("mmh3"),
            "favicon_url": fav.get("url"),
            "form_action_hosts": feats.get("form_action_hosts") or [],
            "offsite_form_hosts": feats.get("offsite_form_hosts") or [],
            "login_form": bool(feats.get("login_form")),
            "posts_offsite": bool(feats.get("posts_offsite")),
            "meta_refresh": feats.get("meta_refresh"),
            "fetched_at": _now_iso(ctx),
            "egress_profile": _egress(ctx),
        }
        if digest is None:
            out.state, out.reason = "could_not_verify", "page too small for a usable ppdeep hash"
        return out

    def _favicon(self, res: ModuleResult, ctx: Any, entity: Entity, page: Fetched) -> dict[str, Any]:
        """The first icon the safe fetch allows (one GET, image types only), hashed with the shared helper."""
        icons = extract_icon_links(page.body if looks_like_html(page.body) else b"", page.url)
        for cand in icons.get("candidates", [])[:1]:
            try:
                icon = safe_get(ctx, cand["url"], accept=ICON_ACCEPT, max_bytes=FAVICON_MAX_BYTES, entity=entity, max_hops=1, ttl=PAGE_TTL)
            except (Blocked, RateLimited, PolicyError, NetworkError) as exc:
                res.raw["favicon"] = {"url": cand["url"][:200], "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
                return {}
            if icon.refused or icon.blocked:
                res.raw["favicon"] = {"url": cand["url"][:200], "error": (icon.refused or icon.blocked)[:200]}
                return {}
            fmt, why = classify_favicon_response(icon.status, icon.headers, icon.body if not icon.truncated else icon.body + b"x")
            if fmt is None:
                res.raw["favicon"] = {"url": icon.url[:200], "error": why}
                return {}
            hashes = favicon_hashes(icon.body)
            res.raw["favicon"] = {"url": icon.url[:200], "mmh3": hashes["mmh3"], "format": fmt}
            return {"mmh3": hashes["mmh3"], "url": icon.url}
        return {}

    @staticmethod
    def _manual_pivots(res: ModuleResult, domain: str) -> None:
        """FC5: passive alternatives for a hostile-host refusal (links for the analyst, never fetched)."""
        res.link("urlscan search (passive)", f"https://urlscan.io/search/#domain:{domain}")
        res.link("Wayback Machine archived copies", f"https://web.archive.org/web/*/{domain}*")
