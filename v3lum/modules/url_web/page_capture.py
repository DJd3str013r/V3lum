"""Headless page capture for evidence: screenshot, rendered DOM and request log (P347, batch p9-G03-3).

LIGHT, explicit-only, for analyst-typed seed URLs already tagged phishing/malicious. The browser is a
**renderer only**: every request the page makes is intercepted by a route handler and either refused
or fulfilled with an answer fetched through ``ctx.http`` (LIGHT egress profile ``proxy_light``, names
resolved through the profile, SSRF guard on every hop, seed binding, the A7 ceilings, request ledger,
kill switch). The browser's own network stack points at a closed loopback port (a blackhole proxy) and
local DNS is disabled, so nothing can leave around ``ctx.http`` - not a WebSocket, a prefetch or a
browser background service (fail closed).

Final conditions implemented (P347):

* c1 - the separate optional extra ``v3lum[capture]`` (``v3lum/data/extras/playwright.json``); playwright
  is imported lazily here only (never in v3lum/core); without it UNAVAILABLE 'package'.
* c2 - refuses to start unless the Chromium sandbox can be on (``chromium_sandbox=True``, never
  ``--no-sandbox``; running as root is refused) and ``proxy_light`` (P376, non-corporate egress) is
  configured; ``ctx.http`` fails closed when that proxy is down, never falling back to the corporate route.
* c3 - the route interceptor refuses non-http(s) schemes, URL userinfo, IP literals of private, loopback,
  link-local, CGNAT, ULA, reserved and metadata classes, metadata and intranet names before anything is
  fetched; ``ctx.http`` then resolves the name through the egress profile and refuses a name that
  resolves to such an address (DNS rebinding). WebSockets are closed; downloads, permissions, service
  workers, extensions and file:// are disabled.
* c4 - a fresh ephemeral context with a temporary profile per page, deleted afterwards; launch arguments
  limit WebRTC to proxied traffic, turn QUIC off and disable integrated Windows/Kerberos auth;
  :func:`check_launch_config` asserts the hardening (launch-args test).
* c5 - hard budgets, enforced by the route handler and the driver: 30 s (no request is fetched after it;
  navigation, settling and the screenshot share it), 25 MB of responses (the HAR budget), one
  screenshot, <= 10 redirect hops (the core follows at most 5 per fetch; at most 11 document
  navigations per capture), <= 150 requests per capture (and the core LIGHT ceiling of 25 per host per
  scan); only GET/HEAD leave (no form submission, even auto-submitted by script); no clicks, scrolling,
  typing or credentials.
* c6 - explicit -M only (``default_enabled = False``; ``--preset deep`` alone never runs it: the module
  refuses unless it was selected by name), analyst-typed seeds only, and only for URLs the
  case already tagged phishing/malicious; URLs carrying a recipient identifier need ``--confirm-url``;
  no stealth or anti-detection plugin; a challenge page (Turnstile, hCaptcha, Cloudflare...) ends
  BLOCKED 'challenge' with no retry.
* c7 - unit tests run against a fake driver (:class:`CaptureDriver`) with one @live test; reuse of public
  urlscan screenshots lives in urlscan_search (P066) and needs no playwright.
* c8 - a capture without phishing indicators reads 'inconclusive (possible cloaking/geofencing)', never
  benign; the request log (HAR) and DOM are scrubbed of cookies, auth headers and proxy credentials;
  victims' e-mails shown on the page are redacted in report text (title, excerpts, findings, and the
  URLs of the attributes: e-mails and recipient tokens in a final URL are masked and such a URL is
  never a pivot; the unredacted record stays in the case evidence).
* c9 - the evidence record (final URL, redirect chain, UTC and America/Sao_Paulo timestamps, SHA-256 of
  screenshot/DOM/HAR, egress profile, case TLP) goes to ``res.raw`` (case evidence, case retention);
  the screenshot is an attribute holding a JPEG data URI (<= 1.5 MB) with its caption for the HTML report.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, package_available, register
from v3lum.core.redact import redact_text, redact_url
from v3lum.modules.url_web.url_unwrap import redact_url_values

UTC = _dt.timezone.utc
BUDGET = {"max_seconds": 30, "max_har_bytes": 25 * 1024 * 1024, "max_redirects": 10, "max_requests": 150,
          "max_screenshot_data_uri_bytes": int(1.5 * 1024 * 1024)}
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_DOM_KEPT = 1024 * 1024
#: the browser's own proxy: a closed loopback port - anything escaping the route handler fails
BLACKHOLE_PROXY = "http://127.0.0.1:9"
HOSTILE_TAGS = ("phishing", "malicious")
#: response headers handed to the renderer (never Set-Cookie: no cookie is stored or replayed)
FORWARD_HEADERS = ("content-type", "location", "content-security-policy", "x-frame-options", "refresh", "content-language")

# =============================================================================================
# c3 destination guard (pure)
# =============================================================================================

METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog", "metadata", "instance-data",
                            "instance-data.ec2.internal", "metadata.azure.internal"})
METADATA_IPS = frozenset({"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "192.0.0.192"})
INTRANET_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".corp", ".lan", ".home", ".home.arpa",
                     ".localdomain", ".private", ".test", ".invalid", ".onion")
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _parse_host_ip(host: str) -> Any:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-FxX.]+", h) and re.search(r"\d", h):
        try:  # decimal / octal / hex IPv4 forms browsers accept (2130706433, 0x7f.1)
            return ipaddress.ip_address(socket.inet_aton(h))
        except OSError:
            return None
    return None


def ip_block_reason(ip: Any) -> str | None:
    """Non-public address class -> reason, else None."""
    try:
        a = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return "unparseable address"
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    if str(a) in METADATA_IPS:
        return "metadata"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if isinstance(a, ipaddress.IPv4Address) and a in CGNAT:
        return "cgnat"
    if isinstance(a, ipaddress.IPv6Address) and a in ipaddress.ip_network("fc00::/7"):
        return "ula"
    if a.is_private:
        return "private"
    if a.is_multicast or a.is_unspecified or a.is_reserved or not a.is_global:
        return "reserved"
    return None


def destination_block_reason(url: str, resolved_ips: Any = ()) -> str | None:
    """c3: the route interceptor's static decision: None (may be fetched through ctx.http) or why not."""
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return "unparseable"
    if parts.scheme not in ("http", "https"):
        return "scheme"
    if not host:
        return "unparseable"
    if parts.username is not None or parts.password is not None:
        return "userinfo"
    ip = _parse_host_ip(host)
    if ip is not None:
        return ip_block_reason(ip)
    if host in METADATA_HOSTS:
        return "metadata"
    if "." not in host or host.endswith(INTRANET_SUFFIXES) or host == "localhost":
        return "intranet_name"
    for r in resolved_ips or ():
        if ip_block_reason(r):
            return "dns_rebinding"
    return None


# =============================================================================================
# c2/c4 launch configuration (pure)
# =============================================================================================

REQUIRED_ARGS = {
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp": "WebRTC limited to proxied traffic",
    "--disable-quic": "QUIC off",
    "--auth-server-allowlist=_": "integrated Windows/Kerberos auth disabled",
}
FORBIDDEN_ARG_PREFIXES = {
    "--no-sandbox": "sandbox disabled", "--disable-setuid-sandbox": "sandbox disabled", "--no-zygote": "sandbox weakened",
    "--disable-web-security": "same-origin policy off", "--load-extension": "extension loaded",
    "--remote-debugging-address": "remote debugging exposed", "--allow-running-insecure-content": "mixed content allowed",
    "--ignore-certificate-errors": "TLS errors ignored", "--proxy-bypass-list": "proxy bypass", "--no-proxy-server": "no proxy",
}
HARDENING_ARGS = (
    "--disable-extensions", "--disable-background-networking", "--disable-component-update", "--disable-sync",
    "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--no-pings", "--dns-prefetch-disable",
    "--disable-default-apps", "--no-first-run", "--disable-breakpad", "--metrics-recording-only", "--mute-audio",
)
FORBIDDEN_PERMISSIONS = frozenset({"geolocation", "notifications", "clipboard-read", "clipboard-write", "camera", "microphone"})


def running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(callable(geteuid) and geteuid() == 0)


def launch_config(proxy_server: str = BLACKHOLE_PROXY) -> dict[str, Any]:
    """c2/c4: the hardened launch and context options (what the Playwright driver passes)."""
    host = (urlsplit(proxy_server).hostname or "127.0.0.1").lower()
    args = [*REQUIRED_ARGS, f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {host}", *HARDENING_ARGS]
    return {
        "running_as_root": running_as_root(),
        "launch": {"headless": True, "chromium_sandbox": True, "args": args, "proxy": {"server": proxy_server, "bypass": ""}},
        "context": {"accept_downloads": False, "service_workers": "block", "permissions": [], "ignore_https_errors": False,
                    "bypass_csp": False, "java_script_enabled": True, "http_credentials": None, "storage_state": None,
                    "user_data_dir": None, "viewport": {"width": 1366, "height": 768}},
    }


def check_launch_config(cfg: Any) -> list[str]:
    """c2/c4/c5 launch-args check: the list of violations (empty = hardened)."""
    if not isinstance(cfg, dict):
        return ["config missing"]
    launch = cfg.get("launch") if isinstance(cfg.get("launch"), dict) else {}
    ctx = cfg.get("context") if isinstance(cfg.get("context"), dict) else {}
    args = [a for a in launch.get("args") or [] if isinstance(a, str)]
    v: list[str] = []
    if launch.get("chromium_sandbox") is not True:
        v.append("chromium_sandbox must be True (Playwright defaults to False and adds --no-sandbox)")
    if cfg.get("running_as_root"):
        v.append("running as root: Chromium has no usable sandbox as root -> refuse to start")
    for a in args:
        for pfx, why in FORBIDDEN_ARG_PREFIXES.items():
            if a == pfx or a.startswith(pfx + "="):
                v.append(f"forbidden arg {a}: {why}")
    for req, why in REQUIRED_ARGS.items():
        if req not in args:
            v.append(f"missing {req} ({why})")
    if not any(a.startswith("--host-resolver-rules=MAP * ~NOTFOUND") for a in args):
        v.append("missing --host-resolver-rules=MAP * ~NOTFOUND (no local DNS)")
    proxy = launch.get("proxy") if isinstance(launch.get("proxy"), dict) else ctx.get("proxy")
    if not (isinstance(proxy, dict) and isinstance(proxy.get("server"), str) and proxy.get("server")):
        v.append("no proxy configured: fail closed (never the corporate route)")
    elif proxy.get("bypass"):
        v.append("proxy bypass list set")
    if ctx.get("accept_downloads") is not False:
        v.append("accept_downloads must be False (Playwright default True)")
    if ctx.get("service_workers") != "block":
        v.append("service_workers must be 'block' (service workers can bypass routing)")
    perms = set(ctx.get("permissions") or [])
    if perms:
        v.append(f"permissions must be empty (got {sorted(perms)}; never {sorted(FORBIDDEN_PERMISSIONS & perms) or 'any'})")
    if ctx.get("ignore_https_errors"):
        v.append("ignore_https_errors must be False")
    if ctx.get("bypass_csp"):
        v.append("bypass_csp must be False")
    if ctx.get("http_credentials") or ctx.get("storage_state"):
        v.append("no credentials or storage state may be loaded")
    if ctx.get("user_data_dir"):
        v.append("persistent profile used: a fresh ephemeral context per page is required")
    return v


# =============================================================================================
# c5/c8/c9 analysis, scrubbing and evidence (pure)
# =============================================================================================

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
_SENSITIVE_REQ_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})


def budget_violations(*, request_count: int = 0, redirect_hops: int = 0, har_bytes: int = 0, elapsed_s: float = 0.0,
                      screenshots: int = 1) -> list[str]:
    """c5 hard budgets: 30 s, 25 MB HAR, one screenshot, <= 10 redirect hops, <= 150 requests."""
    v = []
    if request_count > BUDGET["max_requests"]:
        v.append(f"requests {request_count} > {BUDGET['max_requests']}")
    if redirect_hops > BUDGET["max_redirects"]:
        v.append(f"redirect hops {redirect_hops} > {BUDGET['max_redirects']}")
    if har_bytes > BUDGET["max_har_bytes"]:
        v.append(f"HAR {har_bytes} bytes > {BUDGET['max_har_bytes']}")
    if elapsed_s > BUDGET["max_seconds"]:
        v.append(f"elapsed {elapsed_s:.1f} s > {BUDGET['max_seconds']} s")
    if screenshots > 1:
        v.append(f"screenshots {screenshots} > 1")
    return v


def _strip_userinfo(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if p.username is None and p.password is None:
        return url
    netloc = (p.hostname or "") + (f":{p.port}" if p.port else "")
    return p._replace(netloc=netloc).geturl()


def scrub_har(har: Any, secrets: Any = ()) -> Any:
    """c8: a scrubbed deep copy: Cookie/Authorization/Proxy-Authorization request headers and every cookie
    value -> 'REDACTED' (names kept), userinfo removed from URLs, literal secrets (proxy credentials) replaced."""
    data = json.loads(json.dumps(har, default=str)) if isinstance(har, (dict, list)) else har
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) and isinstance(data.get("log"), dict) else []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        req = e.get("request") if isinstance(e.get("request"), dict) else {}
        resp = e.get("response") if isinstance(e.get("response"), dict) else {}
        if isinstance(req.get("url"), str):
            req["url"] = _strip_userinfo(req["url"])
        for h in req.get("headers") or []:
            if isinstance(h, dict) and str(h.get("name", "")).lower() in _SENSITIVE_REQ_HEADERS:
                h["value"] = "REDACTED"
        for c in (req.get("cookies") or []) + (resp.get("cookies") or []):
            if isinstance(c, dict):
                c["value"] = "REDACTED"
        for h in resp.get("headers") or []:
            if isinstance(h, dict) and str(h.get("name", "")).lower() == "set-cookie":
                h["value"] = str(h.get("value", "")).split("=", 1)[0] + "=REDACTED"
            elif isinstance(h, dict) and str(h.get("name", "")).lower() == "location" and isinstance(h.get("value"), str):
                h["value"] = _strip_userinfo(h["value"])
        if isinstance(resp.get("redirectURL"), str):
            resp["redirectURL"] = _strip_userinfo(resp["redirectURL"])
    secrets = [s for s in secrets or () if isinstance(s, str) and len(s) >= 4]
    if secrets:
        text = json.dumps(data)
        for s in secrets:
            text = text.replace(json.dumps(s)[1:-1], "REDACTED")
        data = json.loads(text)
    return data


def redact_emails(text: Any) -> str:
    """c8: victims' e-mails in report text -> 'u***@example.com'."""
    if not isinstance(text, str):
        return ""
    return _EMAIL.sub(lambda m: m.group(0)[0] + "***@" + m.group(0).split("@", 1)[1], text)


class _DomScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title, self._in_title, self._in_script = "", False, False
        self.forms: list[dict[str, Any]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form" and len(self.forms) < 50:
            self.forms.append({"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "has_password": False})
        elif tag == "input" and self.forms and a.get("type", "").lower() == "password":
            self.forms[-1]["has_password"] = True
        elif tag in ("script", "style"):
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style"):
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif not self._in_script and sum(len(t) for t in self.text) < 20000:
            self.text.append(data)


CHALLENGE_MARKERS = (
    ("challenges.cloudflare.com/turnstile", "turnstile"), ("cf-turnstile", "turnstile"), ("hcaptcha.com", "hcaptcha"),
    ("h-captcha", "hcaptcha"), ("g-recaptcha", "recaptcha"), ("www.google.com/recaptcha", "recaptcha"),
    ("_cf_chl_opt", "cloudflare_challenge"), ("/cdn-cgi/challenge-platform/", "cloudflare_challenge"),
    ("challenge-error-text", "cloudflare_challenge"), ("ddos-guard", "ddos_guard"), ("_vercel_challenge", "vercel"),
)


def challenge_marker(html: Any, headers: Any = None) -> str | None:
    """c6/A9: a challenge page -> its kind (end BLOCKED 'challenge', no retry), else None."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    if h.get("cf-mitigated") == "challenge":
        return "cloudflare_challenge"
    if isinstance(html, (bytes, bytearray)):
        html = bytes(html).decode("utf-8", "replace")
    if not isinstance(html, str):
        return None
    low = html.lower()[:500000]
    for needle, kind in CHALLENGE_MARKERS:
        if needle in low:
            return kind
    if re.search(r"<title>\s*just a moment\.\.\.\s*</title>", low):
        return "cloudflare_challenge"
    return None


def _registrable(host: str) -> str:
    try:
        return psl.registrable_domain(host) or host
    except Exception:  # noqa: BLE001
        return host


def dom_summary(html: Any, base_url: str) -> dict[str, Any]:
    """c6/c8: the rendered DOM -> title, forms (absolute action, password field, cross-domain target), e-mail
    count, a redacted text excerpt and a challenge marker. Nothing is executed or followed."""
    if isinstance(html, (bytes, bytearray)):
        html = bytes(html).decode("utf-8", "replace")
    if not isinstance(html, str):
        html = ""
    p = _DomScan()
    try:
        p.feed(html[:5_000_000])
        p.close()
    except Exception:  # noqa: BLE001 - hostile markup never crashes the module
        pass
    try:
        base_host = (urlsplit(base_url).hostname or "").lower()
    except ValueError:
        base_host = ""
    forms = []
    for f in p.forms:
        action = urljoin(base_url, f["action"]) if f["action"] else base_url
        try:
            ah = (urlsplit(action).hostname or "").lower()
        except ValueError:
            ah = ""
        forms.append({"action": action, "method": f["method"], "has_password": f["has_password"], "action_host": ah,
                      "cross_domain": bool(ah and base_host and _registrable(ah) != _registrable(base_host))})
    text = " ".join(" ".join(p.text).split())
    return {"title": " ".join(p.title.split())[:300] or None, "forms": forms, "email_count": len(set(_EMAIL.findall(html))),
            "text_excerpt": redact_emails(text[:300]), "challenge": challenge_marker(html)}


def capture_verdict(dom: dict[str, Any], blocked_requests: int = 0) -> dict[str, Any]:
    """c6/c8: never 'benign'. -> {status, reason_code, label, indicators}."""
    if dom.get("challenge"):
        return {"status": "blocked", "reason_code": "challenge", "label": f"challenge page ({dom['challenge']})", "indicators": []}
    ind = set()
    for f in dom.get("forms") or []:
        if f.get("has_password"):
            ind.add("password_form")
        if f.get("cross_domain"):
            ind.add("cross_domain_form_action")
    if blocked_requests:
        ind.add("blocked_subrequests")
    if ind & {"password_form", "cross_domain_form_action"}:
        return {"status": "ok", "reason_code": None, "label": "phishing indicators observed", "indicators": sorted(ind)}
    return {"status": "ok", "reason_code": None, "label": "inconclusive (possible cloaking/geofencing)", "indicators": sorted(ind)}


def sao_paulo(d: _dt.datetime) -> str:
    try:
        from zoneinfo import ZoneInfo

        return d.astimezone(ZoneInfo("America/Sao_Paulo")).isoformat()
    except Exception:  # noqa: BLE001 - fixed offset fallback (no DST in Brazil since 2019)
        return d.astimezone(_dt.timezone(_dt.timedelta(hours=-3))).isoformat()


def _sha(b: Any) -> str | None:
    return hashlib.sha256(bytes(b)).hexdigest() if isinstance(b, (bytes, bytearray)) else None


def evidence_record(*, seed_url: str, final_url: str | None, redirect_chain: list[Any], captured_at: _dt.datetime,
                    screenshot: bytes | None, dom: bytes | None, har: bytes | None, egress_profile: str, tlp: str) -> dict[str, Any]:
    """c9: final URL, redirect chain, UTC and America/Sao_Paulo timestamps, SHA-256 of screenshot/DOM/HAR, egress, TLP."""
    return {"seed_url": seed_url, "final_url": final_url, "redirect_chain": list(redirect_chain or []),
            "captured_at_utc": captured_at.astimezone(UTC).isoformat(), "captured_at_sao_paulo": sao_paulo(captured_at),
            "sha256": {"screenshot": _sha(screenshot), "dom": _sha(dom), "har": _sha(har)}, "egress_profile": egress_profile, "tlp": tlp}


def jpeg_data_uri(jpeg: Any, max_bytes: int = BUDGET["max_screenshot_data_uri_bytes"]) -> tuple[str | None, str | None]:
    """c9: a JPEG data URI of at most 1.5 MB -> (uri, None) or (None, reason)."""
    if not isinstance(jpeg, (bytes, bytearray)) or len(jpeg) < 4:
        return None, "no image"
    if not (jpeg[:3] == b"\xff\xd8\xff" and jpeg[-2:] == b"\xff\xd9"):
        return None, "not a JPEG"
    uri = "data:image/jpeg;base64," + base64.b64encode(bytes(jpeg)).decode("ascii")
    if len(uri) > max_bytes:
        return None, f"data URI {len(uri)} bytes > {max_bytes}"
    return uri, None


def screenshot_caption(*, source: str, egress_profile: str, captured_at: _dt.datetime) -> str:
    """c9: the caption under the embedded screenshot (source, egress, time)."""
    return (f"Source: {source} | egress: {egress_profile} | captured {captured_at.astimezone(UTC).isoformat()} "
            f"({sao_paulo(captured_at)} America/Sao_Paulo)")


# =============================================================================================
# the driver interface (c7: unit tests use a fake driver)
# =============================================================================================


@dataclass
class RouteRequest:
    """One request the page wants to make."""

    url: str
    method: str = "GET"
    resource_type: str = "document"
    is_navigation: bool = False


@dataclass
class RouteDecision:
    """What the route handler answers: fulfil with a ctx.http answer, or abort."""

    action: str  # 'fulfill' | 'abort'
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    reason: str = ""


@dataclass
class CaptureRequest:
    seed_url: str
    launch: dict[str, Any]
    route: Callable[[RouteRequest], RouteDecision]
    budget_s: float
    cancelled: Callable[[], bool]


@dataclass
class CaptureOutput:
    final_url: str | None
    dom_html: str
    screenshot_jpeg: bytes | None
    title: str | None = None
    elapsed_s: float = 0.0
    screenshots: int = 1
    error: str = ""


class CaptureDriver(Protocol):
    def capture(self, request: CaptureRequest) -> CaptureOutput:
        ...


class PlaywrightDriver:
    """The real renderer (optional extra v3lum[capture]): Chromium with the sandbox on, a blackhole proxy,
    no local DNS, a fresh ephemeral context per page; every request goes through ``request.route``."""

    def capture(self, request: CaptureRequest) -> CaptureOutput:
        from playwright.sync_api import Error as PwError  # v3lum-lint: allow LINT-01 -- renderer only: every page request is fulfilled through ctx.http by the route handler; the browser's own network goes to a closed loopback proxy (P347 c1-c3)
        from playwright.sync_api import sync_playwright  # v3lum-lint: allow LINT-01 -- renderer only (P347 c1-c3, see the line above)

        cfg = request.launch
        launch, cctx = cfg["launch"], cfg["context"]
        started = _dt.datetime.now(UTC)

        def on_route(route: Any) -> None:
            pw_req = route.request
            try:
                decision = request.route(RouteRequest(url=pw_req.url, method=pw_req.method, resource_type=pw_req.resource_type,
                                                      is_navigation=pw_req.is_navigation_request()))
            except Exception:  # noqa: BLE001 - a failing handler refuses (fail closed)
                decision = RouteDecision("abort", reason="handler error")
            if decision.action == "fulfill":
                route.fulfill(status=decision.status, headers=decision.headers, body=decision.body)
            else:
                route.abort("blockedbyclient")

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True, args=list(launch["args"]), proxy=dict(launch["proxy"]))
            try:
                context = browser.new_context(accept_downloads=False, service_workers="block", permissions=[], ignore_https_errors=False,
                                              bypass_csp=False, java_script_enabled=True, viewport=cctx["viewport"])
                try:
                    ws_route = getattr(context, "route_web_socket", None)
                    if callable(ws_route):
                        ws_route("**/*", lambda ws: ws.close())
                    page = context.new_page()
                    page.route("**/*", on_route)
                    end = time.monotonic() + max(1.0, request.budget_s)  # c5: one budget for everything below

                    def left_ms(reserve: float = 0.0) -> int:
                        return max(0, int((end - time.monotonic() - reserve) * 1000))

                    error = ""
                    try:
                        page.goto(request.seed_url, wait_until="load", timeout=max(1000, left_ms(reserve=5.0)))
                        if not request.cancelled() and left_ms(reserve=5.0) > 0:
                            page.wait_for_timeout(min(2000, left_ms(reserve=5.0)))  # let scripts settle: no interaction
                    except PwError as exc:
                        error = type(exc).__name__
                    dom = page.content()
                    title = page.title()
                    shot = None
                    if not request.cancelled() and left_ms() > 0:
                        try:
                            shot = page.screenshot(type="jpeg", quality=70, full_page=False, timeout=max(1, min(5000, left_ms())))
                        except PwError as exc:
                            error = error or type(exc).__name__
                    return CaptureOutput(final_url=page.url, dom_html=dom, screenshot_jpeg=shot, title=title,
                                         elapsed_s=(_dt.datetime.now(UTC) - started).total_seconds(), error=error)
                finally:
                    context.close()  # the ephemeral context and its temporary profile are deleted
            finally:
                browser.close()


#: the driver factory (tests install a fake driver; c7)
DRIVER_FACTORY: Callable[[], CaptureDriver] | None = None


def make_driver() -> CaptureDriver | None:
    if DRIVER_FACTORY is not None:
        return DRIVER_FACTORY()
    if not package_available("playwright"):
        return None
    return PlaywrightDriver()


# =============================================================================================
# run helpers
# =============================================================================================


def seed_url(entity: Entity) -> str | None:
    if entity.type is T.URL:
        return str(entity.value)
    if entity.type is T.DOMAIN:
        return f"https://{entity.value}/"
    return None


def case_tags(ctx: Any, entity: Entity, url: str) -> set[str]:
    """Hostile tags (phishing/malicious) the case graph holds for the URL or its host (c6)."""
    pctx = getattr(getattr(ctx, "runtime", None), "policy_context", None)
    graph = getattr(pctx, "graph", None)
    if graph is None:
        return set()
    found: set[str] = set()
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    candidates = [entity, Entity.try_make(T.URL, url), Entity.try_make(T.DOMAIN, host) if host else None]
    for ent in candidates:
        if ent is None:
            continue
        try:
            node = graph.get(ent)
        except Exception:  # noqa: BLE001
            node = None
        if node is not None:
            found |= {t for t in HOSTILE_TAGS if node.tagged(t)}
    return found


def recipient_identifier(ctx: Any, url: str) -> bool:
    try:
        from v3lum.core.policy import recipient_token

        return bool(recipient_token(url, getattr(ctx, "org", None)))
    except Exception:  # noqa: BLE001 - when in doubt, ask for the confirmation (fail closed)
        return True


def explicitly_selected(ctx: Any, name: str) -> bool:
    """c6: selected by name (-M / ``v3lum run``), not merely included by ``--preset deep``."""
    opts = getattr(ctx, "options", None)
    if name in set(getattr(opts, "include", None) or ()):
        return True
    pctx = getattr(getattr(ctx, "runtime", None), "policy_context", None)
    return name in set(getattr(pctx, "explicit", None) or ())


def report_url(url: Any) -> tuple[str | None, bool]:
    """c8: a URL for report text - e-mails, recipient tokens, userinfo and keys masked. (url, redacted?)"""
    if not isinstance(url, str) or not url:
        return None, False
    red, kinds = redact_url_values(url)
    red = redact_url(red if isinstance(red, str) else url)
    return red, bool(kinds) or red != url


def proxy_light(ctx: Any) -> str:
    """c2: the configured non-corporate LIGHT egress (setting proxy_light), '' when none."""
    value = ctx.setting("proxy_light", "")
    return str(value or "").strip()


def _proxy_secrets(proxy: str) -> list[str]:
    try:
        p = urlsplit(proxy)
    except ValueError:
        return []
    return [s for s in (p.username, p.password) if s]


class _Router:
    """The route handler: c3 destination guard, c5 budgets and method rule, fulfilment through ctx.http."""

    def __init__(self, ctx: Any, seed: str, deadline_s: float) -> None:
        self.ctx = ctx
        self.seed = seed
        self.deadline_s = deadline_s
        self.count = 0
        self.bytes = 0
        self.entries: list[dict[str, Any]] = []
        self.blocked: list[dict[str, str]] = []
        self.prefetched: dict[str, Any] = {}
        self.redirect_chain: list[str] = []
        self.challenge: str | None = None
        self.stop: BaseException | None = None
        self.server_ip = ""
        self.egress = ""
        self.seed_refusal: tuple[str, str] | None = None
        self.partial = ""
        self.navigations = 0
        self._t0 = time.monotonic()

    def _abort(self, req: RouteRequest, why: str) -> RouteDecision:
        if len(self.blocked) < 200:
            self.blocked.append({"url": req.url[:300], "reason": why})
        if req.is_navigation and req.url == self.seed and self.seed_refusal is None:
            self.seed_refusal = ("policy", why)
        return RouteDecision("abort", reason=why)

    def __call__(self, req: RouteRequest) -> RouteDecision:
        if self.stop is not None or self.ctx.cancelled():
            self.stop = self.stop or Cancelled("cancelled during the capture")
            return RouteDecision("abort", reason="cancelled")
        if req.url in self.prefetched:  # the final document of a redirect chain ctx.http already followed
            return self._fulfil(req, self.prefetched.pop(req.url))
        if time.monotonic() - self._t0 > self.deadline_s:  # c5: nothing is fetched after the 30 s budget
            self.partial = self.partial or "deadline"
            return self._abort(req, f"time budget ({self.deadline_s:.0f} s) reached")
        why = destination_block_reason(req.url)
        if why:
            return self._abort(req, f"destination refused: {why}")
        if req.method.upper() not in ("GET", "HEAD"):
            return self._abort(req, f"method {req.method.upper()} refused (no form submission, LIGHT GET/HEAD only)")
        if self.count >= BUDGET["max_requests"]:
            self.partial = "request_cap"
            return self._abort(req, f"request budget ({BUDGET['max_requests']}) reached")
        if self.bytes >= BUDGET["max_har_bytes"]:
            self.partial = "request_cap"
            return self._abort(req, "response byte budget (25 MB) reached")
        if req.is_navigation:
            # c5: <= 10 redirect hops - every further document navigation (script/meta redirects, frames)
            # is refused once the chain is that long
            if self.navigations > BUDGET["max_redirects"] or len(self.redirect_chain) > BUDGET["max_redirects"] + 1:
                self.partial = "request_cap"
                return self._abort(req, f"redirect budget ({BUDGET['max_redirects']} hops) reached")
            self.navigations += 1
        self.count += 1
        try:
            resp = self.ctx.http.request(req.method.upper(), req.url, allow_redirects=req.is_navigation, max_bytes=MAX_RESPONSE_BYTES, ttl=0)
        except (Cancelled, DeadlineExceeded) as exc:
            self.stop = exc
            return RouteDecision("abort", reason="cancelled")
        except RequestCapReached:
            self.partial = "request_cap"
            return self._abort(req, "LIGHT request ceiling reached (25 per host per scan)")
        except Blocked as exc:
            if req.is_navigation:
                self.challenge = getattr(exc, "reason_code", "") or "challenge"
            return self._abort(req, f"blocked ({getattr(exc, 'reason_code', '') or 'challenge'})")
        except PolicyError as exc:
            if req.is_navigation and req.url == self.seed:
                self.seed_refusal = (getattr(exc, "reason_code", "") or "policy", str(exc)[:300])
            return self._abort(req, f"refused by the core ({getattr(exc, 'reason_code', '') or 'policy'})")
        except (RateLimited, QuotaExceeded) as exc:
            if req.is_navigation and req.url == self.seed:
                self.stop = exc
            return self._abort(req, "rate limited")
        except (HttpError, NetworkError) as exc:
            return self._abort(req, f"could not fetch ({type(exc).__name__})")
        cls = getattr(resp, "classification", None)
        if cls is not None and getattr(cls, "status", "") == "blocked" and req.is_navigation:
            self.challenge = getattr(cls, "reason_code", "") or "challenge"
            return self._abort(req, "challenge page")
        hops = [h for h in (getattr(resp, "history", None) or []) if isinstance(h, str)]
        if req.is_navigation:
            if not self.egress:
                infos = list(getattr(self.ctx.http, "request_log", []) or [])
                self.egress = str(getattr(infos[-1], "egress_profile", "") or "") if infos else ""
            if not self.redirect_chain:
                self.redirect_chain = hops or [req.url]
            self.server_ip = str(getattr(resp, "pinned_ip", "") or "") or self.server_ip
        final = str(getattr(resp, "url", "") or req.url)
        if req.is_navigation and final != req.url:
            # ctx.http followed the redirects (every hop re-checked); the renderer is sent to the final URL
            self.prefetched[final] = resp
            self._log(req, resp, redirect_to=final)
            return RouteDecision("fulfill", status=302, headers={"location": final}, body=b"")
        return self._fulfil(req, resp)

    def _fulfil(self, req: RouteRequest, resp: Any) -> RouteDecision:
        body = bytes(getattr(resp, "content", b"") or b"")
        self.bytes += len(body)
        headers = {k: str(v) for k, v in (getattr(resp, "headers", {}) or {}).items() if str(k).lower() in FORWARD_HEADERS}
        self._log(req, resp)
        return RouteDecision("fulfill", status=int(getattr(resp, "status", 200) or 200), headers=headers, body=body)

    def _log(self, req: RouteRequest, resp: Any, redirect_to: str = "") -> None:
        if len(self.entries) >= BUDGET["max_requests"]:
            return
        headers = getattr(resp, "headers", {}) or {}
        self.entries.append({
            "startedDateTime": self.ctx.now().astimezone(UTC).isoformat(),
            "request": {"method": req.method.upper(), "url": req.url, "headers": [], "cookies": []},
            "response": {"status": int(getattr(resp, "status", 0) or 0), "redirectURL": redirect_to,
                         "headers": [{"name": k, "value": str(v)} for k, v in headers.items() if str(k).lower() in FORWARD_HEADERS + ("server", "set-cookie")],
                         "cookies": [], "content": {"size": len(getattr(resp, "content", b"") or b""),
                                                    "mimeType": str(headers.get("content-type", ""))}},
            "serverIPAddress": str(getattr(resp, "pinned_ip", "") or ""),
            "_resourceType": req.resource_type,
        })

    def har(self) -> dict[str, Any]:
        return {"log": {"version": "1.2", "creator": {"name": "v3lum page_capture (request log through ctx.http)", "version": "1"},
                        "entries": self.entries, "_blocked": self.blocked}}


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: the hardening checks hold and the optional renderer is installed (no browser is started)."""
    problems = [p for p in check_launch_config(launch_config()) if not p.startswith("running as root")]
    if problems:
        return HealthResult("dead", "launch configuration not hardened: " + "; ".join(problems))
    if running_as_root():
        return HealthResult("dead", "running as root: Chromium cannot sandbox, page_capture refuses to start")
    if not package_available("playwright"):
        return HealthResult("dead", "optional extra missing: pip install 'v3lum[capture]' and 'playwright install chromium'")
    return HealthResult("ok", "hardened launch configuration; renderer installed")


# =============================================================================================
# the module
# =============================================================================================


@register
class PageCapture(Module):
    name = "page_capture"
    title = "Headless page capture (evidence)"
    description = ("Screenshot, rendered DOM and request log of an analyst-typed phishing/malicious URL in a sandboxed headless "
                   "Chromium whose every request is fetched through the LIGHT egress (proxy_light) by V3LUM itself; hashed, "
                   "timestamped evidence for takedown and triage.")
    category = "url_web"
    accepts = frozenset({T.URL, T.DOMAIN})
    produces = frozenset({T.URL, T.DOMAIN, T.IPV4})
    reference = "https://playwright.dev/python/docs/api/class-browsertype"
    notice = ("LIGHT: renders a hostile page. Explicit -M only, analyst-typed seed URLs already tagged phishing/malicious, "
              "a configured proxy_light (non-corporate egress, fail closed) and the Chromium sandbox (never as root). "
              "Optional extra v3lum[capture]. A capture without indicators is inconclusive (possible cloaking), never benign.")
    run_on = "seeds"
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    requires_packages = ("playwright",)
    max_requests = BUDGET["max_requests"]
    expected_latency = 12.0
    timeout = 45.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 0  # captures are evidence: never served from the HTTP cache
    max_pivots = 30
    default_enabled = False

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        url = seed_url(entity)
        if not url:
            return res.mark("skipped", "no URL to capture", reason_code="not_applicable")
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "page_capture runs only on analyst-typed seed URLs, never on pivots (A7)", reason_code="scope")
        if not explicitly_selected(ctx, self.name):
            return res.mark("skipped", f"page_capture runs only when selected by name (-M {self.name}), never through --preset deep "
                            "(P347 c6)", reason_code="not_default")
        why = destination_block_reason(url)
        if why:
            return res.mark("skipped", f"seed refused by the destination guard ({why})", reason_code="policy")
        tags = case_tags(ctx, entity, url)
        if not tags:
            return res.mark("skipped", "page_capture runs only on seed URLs the case already tagged phishing/malicious (P347 c6)",
                            reason_code="policy")
        confirmed = set(getattr(getattr(ctx, "options", None), "confirmed_urls", set()) or set())
        if recipient_identifier(ctx, url) and url not in confirmed:
            return res.mark("skipped", "the URL probably carries a recipient identifier: capture only with --confirm-url <url> (P347 c6)",
                            reason_code="policy")
        proxy = proxy_light(ctx)
        if not proxy:
            return res.mark("skipped", "needs proxy_light (a non-corporate egress): fail closed, never the corporate route (P347 c2)",
                            reason_code="policy")
        cfg = launch_config()
        problems = check_launch_config(cfg)
        if problems:
            return res.mark("skipped", "refused to start: " + "; ".join(problems)[:300], reason_code="config")
        driver = make_driver()
        if driver is None:
            return res.mark("unavailable", "optional extra missing: pip install 'v3lum[capture]' (playwright) and "
                            "'playwright install chromium'", reason_code="package")
        remaining = ctx.remaining()
        budget = min(float(BUDGET["max_seconds"]), max(1.0, (remaining - 5.0) if remaining is not None else BUDGET["max_seconds"]))
        router = _Router(ctx, url, budget)
        out = driver.capture(CaptureRequest(seed_url=url, launch=cfg, route=router, budget_s=budget, cancelled=ctx.cancelled))
        if router.stop is not None:
            raise router.stop
        if router.challenge:
            return res.mark("blocked", f"challenge page on the seed ({router.challenge}): no retry (rule 1, P347 c6)", reason_code="challenge")
        if router.seed_refusal is not None:
            code, text = router.seed_refusal
            code = code if code in ("scope", "policy", "config", "tlp", "opsec") else "policy"
            return res.mark("skipped", f"the seed was not fetched: {text}"[:400], reason_code=code)
        if not router.entries:
            return res.mark("error", f"nothing was captured ({out.error or 'no response'}): could not verify")
        return self._report(res, ctx, url, out, router, proxy, tags)

    def _report(self, res: ModuleResult, ctx: Any, url: str, out: CaptureOutput, router: _Router, proxy: str, tags: set[str]) -> ModuleResult:
        now = ctx.now()
        final = out.final_url or url
        dom_html = out.dom_html if isinstance(out.dom_html, str) else ""
        dom = dom_summary(dom_html, final)
        challenge = dom.get("challenge")
        if challenge:
            return res.mark("blocked", f"challenge page ({challenge}): no retry (rule 1, P347 c6)", reason_code="challenge")
        verdict = capture_verdict(dom, len(router.blocked))
        secrets = _proxy_secrets(proxy)
        har = scrub_har(router.har(), secrets)
        har_bytes = json.dumps(har, sort_keys=True).encode()
        dom_kept = redact_text(dom_html[:MAX_DOM_KEPT])
        for s in secrets:
            dom_kept = dom_kept.replace(s, "REDACTED")
        dom_bytes = dom_kept.encode("utf-8", "replace")
        shot = out.screenshot_jpeg if isinstance(out.screenshot_jpeg, (bytes, bytearray)) else None
        egress = router.egress or "light"
        violations = budget_violations(request_count=router.count, redirect_hops=max(0, len(router.redirect_chain) - 1),
                                       har_bytes=router.bytes, elapsed_s=out.elapsed_s, screenshots=out.screenshots)
        record = evidence_record(seed_url=url, final_url=final, redirect_chain=router.redirect_chain, captured_at=now,
                                 screenshot=shot, dom=dom_bytes, har=har_bytes, egress_profile=egress, tlp=str(getattr(ctx, "tlp", "") or ""))
        record.update({"verdict": verdict["label"], "indicators": verdict["indicators"], "request_count": router.count,
                       "blocked_requests": len(router.blocked), "budget_violations": violations, "case_tags": sorted(tags)})
        shown = dict(record)  # c8: report text masks e-mails/recipient tokens in URLs; the evidence keeps them
        shown["seed_url"] = report_url(url)[0]
        shown["final_url"] = report_url(final)[0]
        shown["redirect_chain"] = [report_url(u)[0] for u in record["redirect_chain"]]
        res.attr("page_capture", shown)
        res.attr("capture_verdict", verdict["label"])
        if dom.get("title"):
            res.attr("title", redact_emails(dom["title"]))
        res.attr("login_form", any(f["has_password"] for f in dom["forms"]))
        uri, why_not = jpeg_data_uri(shot)
        final_shown, final_redacted = report_url(final)
        caption = screenshot_caption(source=final_shown or "", egress_profile=egress, captured_at=now)
        res.attr("page_screenshot", {"data_uri": uri, "caption": caption, "sha256": record["sha256"]["screenshot"],
                                     "bytes": len(shot) if shot else 0, "not_embedded": why_not})
        if verdict["label"] == "phishing indicators observed":
            targets = sorted({f["action_host"] for f in dom["forms"] if f["cross_domain"] and f["action_host"]})
            res.finding(
                "Phishing indicators observed in a headless capture",
                "medium",
                redact_emails(f"The page at {final_shown} shows {', '.join(verdict['indicators'])}"
                              + (f"; credentials would be posted to {', '.join(targets)}" if targets else "")
                              + ". Nothing was submitted, clicked or typed."),
                confidence="probable",
                criterion="password form and/or cross-domain form action in the rendered DOM of a URL the case tagged "
                          f"{'/'.join(sorted(tags))} (P347 c6/c8)",
                tags=["phishing"],
                observed_last=now,
                key="indicators",
            )
        else:
            res.finding(
                "Capture inconclusive (possible cloaking/geofencing)",
                "info",
                f"No phishing indicator was visible from egress '{egress}' at {now.isoformat()}: the page may cloak or geofence. "
                "This is never evidence of a benign page.",
                confidence="possible",
                tags=["cloaking_possible", "inconclusive", "context_only"],
                key="inconclusive",
            )
        if final != url and not final_redacted:  # a URL carrying a victim's e-mail or token is never a pivot (c8)
            res.pivot(T.URL, final, "capture_final_url", confidence="confirmed", note="final URL of the headless capture")
        try:
            host = (urlsplit(final).hostname or "").lower()
        except ValueError:
            host = ""
        if host and not _parse_host_ip(host):
            res.pivot(T.DOMAIN, host, "url_host", confidence="confirmed")
        for f in dom["forms"]:
            if f["cross_domain"] and f["action_host"]:
                res.pivot(T.DOMAIN, f["action_host"], "capture_form_action_host", confidence="probable",
                          note="credential-harvesting endpoint candidate (never submitted)")
        if router.server_ip:
            try:
                if ipaddress.ip_address(router.server_ip).version == 4:
                    res.pivot(T.IPV4, router.server_ip, "capture_server_ip", confidence="probable", expand=False,
                              note="address the final document came from (may be a CDN)")
            except ValueError:
                pass
        res.raw = {"evidence": record, "har": har, "dom": dom_kept,
                   "screenshot_jpeg_b64": base64.b64encode(bytes(shot)).decode("ascii") if shot else None,
                   "dom_summary": {k: (redact_emails(v) if isinstance(v, str) else v) for k, v in dom.items() if k != "forms"},
                   "forms": [{k: f[k] for k in ("action", "method", "has_password", "cross_domain")} for f in dom["forms"][:20]]}
        if router.partial:
            res.stop(router.partial if router.partial in ("request_cap", "deadline") else "request_cap")
        return res
