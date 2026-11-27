"""Google Digital Asset Links (P008): the Android apps a web site declares as its own.

Final conditions (council #1, P008) and where they live:

1. Keyless ``GET https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://{domain}
   &relation=delegate_permission/common.handle_all_urls`` on registrable domains (:func:`statements_url`,
   :meth:`DigitalAssetLinks.applies`); cache 24 h (``cache_ttl``; answers that could not be verified are
   never cached, :func:`cacheable`).
2. The linked Android package names and SHA-256 signing-certificate fingerprints are recorded as the
   attribute ``official_android_apps`` (vocabulary fragment ``v3lum/data/vocab/p2-G01-1.json``); no
   pivot expansion (package names and certificates pivot with ``expand=False`` only). The same signing
   certificate across apps is an organisation-asset link (info finding, :func:`cert_links`); across
   domains the correlation rule ``dal_shared_signing_cert`` (``v3lum/correlations/p2_g01_1.py``) links them.
3. One client: ``mobile_app_impersonation`` (P346) imports :func:`fetch_statements`,
   :func:`parse_statements` and :func:`confirms_app` from this file instead of re-implementing them (it
   declares the host and the ``google_dal.statements`` source itself).
4. An empty statements list - and Google's HTTP 200 ``ERROR_CODE_FETCH_ERROR`` with a '404 Not Found'
   for the site's ``/.well-known/assetlinks.json`` - reads 'no Digital Asset Links statements
   published' (EMPTY), never 'no official apps'. Other ``ERROR_CODE_*`` answers (redirect, TLS, malformed
   file...) are 'could not verify' (ERROR); 429 is RATE_LIMITED and 403/5xx could-not-verify statuses
   through the core classification (rule 5).
5. Tests: the trimmed real google.com answer plus the empty and error cases
   (``tests/modules/test_digital_asset_links.py``).

Google fetches the site's ``assetlinks.json`` itself when its cache is cold (``fetches_target`` is not
set: Google's statement service, not a scan of the target on V3LUM's behalf, and the value sent is the
public site URL).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "google_dal.statements"
HOST = "digitalassetlinks.googleapis.com"
ENDPOINT = f"https://{HOST}/v1/statements:list"
RELATION = "delegate_permission/common.handle_all_urls"
EMPTY_WORDING = "no Digital Asset Links statements published"
#: statements kept per answer (google.com publishes 58; a site with thousands is not a real delegation list)
MAX_STATEMENTS = 500
#: apps and certificates pivoted per run (attributes keep the full list up to MAX_STATEMENTS)
MAX_APP_PIVOTS = 40

_FP_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$")
_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_MAX_AGE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)s\s*$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _text(value: Any, limit: int = 300) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", _CTRL_RE.sub("", value)).strip()[:limit]


def statements_url(domain: str) -> str:
    """statements:list query for ``https://{domain}`` (cond 1)."""
    site = quote(f"https://{domain}", safe="")
    return f"{ENDPOINT}?source.web.site={site}&relation={quote(RELATION, safe='')}"


def normalize_cert_sha256(value: Any) -> str | None:
    """'f0fd6c5b...' or 'F0:FD:...' -> 'F0:FD:...' (32 colon-separated upper-case bytes), else None."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if re.sub(r"[0-9A-Fa-f:\s]", "", raw):
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    if len(digits) != 64:
        return None
    out = ":".join(digits[i : i + 2] for i in range(0, 64, 2))
    return out if _FP_RE.match(out) else None


def _site(value: Any) -> str | None:
    """'https://google.com.' -> 'https://google.com' (trailing root dot and slash removed)."""
    text = _text(value, 300)
    if not text.lower().startswith(("https://", "http://")):
        return None
    return text.rstrip("/").rstrip(".").rstrip("/") or None


def parse_statements(doc: Any) -> dict[str, Any]:
    """statements:list body -> ``{state, apps [{package, sha256 []}], web_targets [], error_codes [],
    debug, max_age_s, source_site, error}``.

    ``state``: ``ok`` (app or web statements), ``not_published`` (no statements; or Google's 200 answer
    ERROR_CODE_FETCH_ERROR with '404 Not Found' for the site's assetlinks.json - cond 4 wording),
    ``could_not_verify`` (any other ERROR_CODE_*: redirect, TLS, malformed file...) or ``error`` (not
    a statements answer: a Google API error object or junk). Never raises on odd input.
    """
    out: dict[str, Any] = {"state": "error", "apps": [], "web_targets": [], "error_codes": [], "debug": None,
                           "max_age_s": None, "source_site": None, "error": None}
    if not isinstance(doc, dict):
        out["error"] = "answer is not a JSON object"
        return out
    if isinstance(doc.get("error"), dict):
        err = doc["error"]
        out["error"] = _text(f"{err.get('status') or ''} {err.get('code') or ''} {err.get('message') or ''}", 200) or "API error object"
        return out
    match = _MAX_AGE_RE.match(str(doc.get("maxAge") or ""))
    out["max_age_s"] = float(match.group(1)) if match else None
    codes = doc.get("errorCode")
    out["error_codes"] = [_text(c, 60) for c in (codes if isinstance(codes, list) else []) if isinstance(c, str)][:10]
    out["debug"] = _text(doc.get("debugString"), 400) or None
    apps: dict[str, list[str]] = {}
    statements = doc.get("statements")
    if statements is not None and not isinstance(statements, list):
        out["error"] = "statements is not a list"
        return out
    for st in (statements or [])[:MAX_STATEMENTS]:
        if not isinstance(st, dict):
            continue
        if st.get("relation") not in (None, RELATION):
            continue
        source = st.get("source") if isinstance(st.get("source"), dict) else {}
        web = source.get("web") if isinstance(source.get("web"), dict) else {}
        if out["source_site"] is None:
            out["source_site"] = _site(web.get("site"))
        target = st.get("target") if isinstance(st.get("target"), dict) else {}
        app = target.get("androidApp") if isinstance(target.get("androidApp"), dict) else None
        if app is not None:
            pkg = app.get("packageName")
            if not isinstance(pkg, str) or len(pkg) > 255 or not _PKG_RE.match(pkg):
                continue
            cert = app.get("certificate") if isinstance(app.get("certificate"), dict) else {}
            fps = apps.setdefault(pkg, [])
            fp = normalize_cert_sha256(cert.get("sha256Fingerprint"))
            if fp and fp not in fps:
                fps.append(fp)
            continue
        site_target = target.get("web") if isinstance(target.get("web"), dict) else None
        if site_target is not None:
            site = _site(site_target.get("site"))
            if site and site not in out["web_targets"]:
                out["web_targets"].append(site)
    out["apps"] = [{"package": pkg, "sha256": fps} for pkg, fps in apps.items()]
    if out["apps"] or out["web_targets"]:
        out["state"] = "ok"
    elif not out["error_codes"]:
        out["state"] = "not_published"
    elif out["error_codes"] == ["ERROR_CODE_FETCH_ERROR"] and re.search(r"\b404 Not Found\b", out["debug"] or "", re.I):
        out["state"] = "not_published"  # Google could fetch nothing: the site publishes no assetlinks.json
    else:
        out["state"] = "could_not_verify"
    return out


def cacheable(resp: Any) -> bool:
    """``cache_if`` veto (cond 1): only statements answers and 'not published' answers are cached."""
    try:
        return parse_statements(resp.json())["state"] in ("ok", "not_published")
    except Exception:  # noqa: BLE001 - unparsable answers are never cached
        return False


def fetch_statements(ctx: Any, domain: str) -> dict[str, Any]:
    """The P008 client (cond 3: reused by P346): one statements:list call through ``ctx.http``.

    Classified answers (429, challenge, keyless 403) and non-2xx statuses raise the core exceptions;
    the parsed answer of :func:`parse_statements` is returned otherwise."""
    resp = ctx.http.get(statements_url(domain), source=SOURCE, cache_if=cacheable, headers={"Accept": "application/json"})
    ctx.http.check(resp)
    try:
        doc = resp.json()
    except ValueError:
        return {**parse_statements(None), "error": "answer is not JSON"}
    return parse_statements(doc)


def confirms_app(parsed: dict[str, Any], package: str, sha256: str | None = None) -> bool:
    """True when the official site's statements list ``package`` (and, when given, its signing
    certificate). The check P346 reuses to tell an official app from an impersonation candidate."""
    fp = normalize_cert_sha256(sha256) if sha256 else None
    for app in (parsed or {}).get("apps") or []:
        if app.get("package") == package:
            return fp is None or fp in (app.get("sha256") or [])
    return False


def cert_links(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Signing certificates shared by >= 2 packages of one site (cond 2: organisation-asset links)."""
    by_fp: dict[str, set[str]] = {}
    for app in (parsed or {}).get("apps") or []:
        for fp in app.get("sha256") or []:
            by_fp.setdefault(fp, set()).add(app["package"])
    return [{"cert_sha256": fp, "packages": sorted(pkgs)} for fp, pkgs in sorted(by_fp.items()) if len(pkgs) >= 2]


@register
class DigitalAssetLinks(Module):
    name = "digital_asset_links"
    title = "Google Digital Asset Links (official Android apps)"
    description = (
        "Android apps (package names and signing-certificate SHA-256) a web site declares as its own through its "
        "Digital Asset Links statements, read keyless from Google's statements:list API."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.KEYWORD, T.CERT_FP}
    tags = {"free"}
    reference = "https://developers.google.com/digital-asset-links/reference/rest/v1/statements/list"
    notice = (
        "An empty statements list means the site publishes no Digital Asset Links statements, never that the "
        "organisation has no official apps. Google may fetch the site's /.well-known/assetlinks.json itself."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "google_dal"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 0.5  # p50 of the live calls 2026-11-26: 0.26-0.60 s (1.9 s when Google fetched the site)
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400  # cond 1: 24 h
    max_pivots = 2 * MAX_APP_PIVOTS
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Registrable domains only (cond 1): a subdomain's statements belong to its own site."""
        try:
            return psl.registrable_domain(entity.value) == entity.value
        except Exception:  # noqa: BLE001 - an unknown suffix is not a registrable domain
            return False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        parsed = fetch_statements(ctx, entity.value)
        state = parsed["state"]
        res.raw = {k: parsed.get(k) for k in ("state", "apps", "web_targets", "error_codes", "max_age_s", "source_site", "debug", "error")}
        if state == "error":
            return res.mark("error", f"unexpected Digital Asset Links answer ({parsed.get('error') or 'no statements'}): could not verify")
        if state == "could_not_verify":
            codes = ", ".join(parsed["error_codes"]) or "unknown error"
            return res.mark("error", f"Digital Asset Links could not read the site's statements ({codes}): could not verify")
        if state == "not_published":
            return res.mark("empty", EMPTY_WORDING)
        apps = parsed["apps"]
        res.attr("official_android_apps", [{"package": a["package"], "sha256": list(a["sha256"])} for a in apps])
        res.attr("asset_link_sites", parsed["web_targets"])
        if apps:
            res.finding(
                "Official Android apps declared by the site (Digital Asset Links)",
                "info",
                f"{entity.display} delegates handle_all_urls to {len(apps)} Android package(s): "
                + ", ".join(a["package"] for a in apps[:10]) + (" ..." if len(apps) > 10 else "")
                + ". Use them to tell the organisation's official apps from impersonations (package plus signing certificate).",
                confidence="confirmed",
                data={"apps": apps[:MAX_APP_PIVOTS]},
                source=SOURCE,
            )
        shared = cert_links(parsed)
        if shared:
            res.finding(
                "Same signing certificate across official apps (organisation asset link)",
                "info",
                "; ".join(f"{link['cert_sha256'][:23]}... signs {', '.join(link['packages'][:8])}" for link in shared[:5]),
                confidence="confirmed",
                data={"shared_certificates": shared},
                source=SOURCE,
            )
        pivots = 0
        certs: set[str] = set()
        for app in apps:
            if pivots >= MAX_APP_PIVOTS:
                break
            if res.pivot(T.KEYWORD, app["package"], "official_android_app", confidence="confirmed", expand=False,
                         note="Android package the site delegates to (Digital Asset Links)"):
                pivots += 1
            certs.update(app["sha256"])
        for fp in sorted(certs)[:MAX_APP_PIVOTS]:
            res.pivot(T.CERT_FP, fp.replace(":", "").lower(), "app_signing_cert", confidence="confirmed", expand=False,
                      note="signing certificate of an official Android app (Digital Asset Links)")
        return res
