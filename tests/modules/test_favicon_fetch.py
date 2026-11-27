"""favicon_fetch (P062, LIGHT, opt-in): one safe GET of the icon of an analyst-typed seed, offline.

Every target host answers from FakeHttp, with DoH answers for its name (bound LIGHT runs resolve the
target through the egress profile and pin the checked address). Public documentation-free addresses
(93.184.216.34) are used: TEST-NET ranges are refused by the core SSRF guard like private ones.

Fixtures in tests/fixtures/favicon_fetch/ (batch p9-G03-1 prep, synthetic in the documented shapes: the
prep never contacts a target): a homepage with icon links (``<base href>``, SVG, data: and apple-touch
icons), a homepage whose hrefs point at a metadata IP, an RFC 1918 address, another host of the site, a
non-standard port, another site and ``file:``, the research's JSON 403 (github.com answered the egress
with it: hashing it would be wrong) and Google's favicon (Shodan test vector, favicorn, Apache-2.0).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import PolicyError
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import light_fetch as L
from v3lum.modules.url_web.favicon import FaviconFetch

FX = FIXTURES / "favicon_fetch"
SEED = "www.example.com"
IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
GOOGLE_ICO = (FX / "google_favicon.ico").read_bytes()
OLD_ICO = (FIXTURES / "favicon_hash" / "favicon_google_20090914.ico").read_bytes()


def target(http: FakeHttp, host: str = SEED, ip: str = IP) -> FakeHttp:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])
    return http


def target_calls(http: FakeHttp) -> list[tuple[str, str]]:
    return [(c["method"], c["url"]) for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns" not in c["url"]]


def run(http: FakeHttp, entity: str = f"domain:{SEED}", **kw):
    return run_module(FaviconFetch, entity, http, options=kw.pop("options", LIGHT), **kw)


def test_icon_from_link_rel_is_hashed_with_one_get():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text=(FX / "homepage_icons.html").read_text())
    http.add("GET", f"https://{SEED}/app/static/favicon-32x32.png", body=OLD_ICO, headers={"content-type": "image/png"})
    res = run(http)
    assert res.status is Status.OK, res.error
    fav = res.attributes["favicon"]
    assert fav["mmh3"] == -1184133586 and fav["source"] == "live" and fav["candidate"] == "link"
    (pivot,) = res.pivots
    assert pivot.relation == "favicon" and pivot.entity.value == "-1184133586"
    assert [m for m, _u in target_calls(http)] == ["GET", "GET"]  # the shared homepage + exactly one icon GET
    reasons = {r["reason"] for r in res.attributes["favicon_refused_hrefs"]}
    assert {"SVG icon (not hashed)", "data URI (not fetched)"} <= reasons
    assert all(c.get("pin_ip") == IP for c in http.calls if c["url"].startswith(f"https://{SEED}/"))  # pinned to the checked address


def test_google_default_favicon_is_noise_not_pivoted():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text="<html><head><title>x</title></head></html>")
    http.add("GET", f"https://{SEED}/favicon.ico", body=GOOGLE_ICO, headers={"content-type": "image/x-icon"})
    res = run(http)
    assert res.attributes["favicon"]["mmh3"] == 708578229  # Shodan test vector
    assert res.attributes["favicon_noise"]["name"] == "google"
    assert res.pivots == [] and res.links


def test_hostile_hrefs_are_refused_by_the_safe_fetch():
    """Metadata IP, RFC 1918 literal, another host of the site, :8443, another site and file: are never
    requested; the icon falls back to /favicon.ico of the seed."""
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text=(FX / "homepage_hostile_href.html").read_text())
    http.add("GET", f"https://{SEED}/favicon.ico", body=OLD_ICO, headers={"content-type": "image/x-icon"})
    res = run(http)
    assert res.status is Status.OK
    assert target_calls(http) == [("GET", f"https://{SEED}/"), ("GET", f"https://{SEED}/favicon.ico")]
    refused = {r["href"]: r["reason"] for r in res.attributes["favicon_refused_hrefs"]}
    assert "cloud metadata" in refused["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
    assert "private" in refused["http://10.0.0.5/favicon.ico"]
    assert "outside the analyst-typed seed" in refused["https://intranet.example.com/favicon.ico"]
    assert "port 8443" in refused["https://intranet.example.com:8443/favicon.ico"]
    assert "registrable domain" in refused["https://evil-cdn.example.net/favicon.ico"]
    assert any(r["reason"].startswith("scheme file") for r in res.attributes["favicon_refused_hrefs"])
    assert http.unexpected == []


def test_same_site_name_resolving_to_a_private_address_is_refused_after_resolution():
    http = target(FakeHttp())
    target(http, "img.www.example.com", "10.1.2.3")
    http.add("GET", f"https://{SEED}/", text='<html><head><link rel="icon" href="https://img.www.example.com/f.png"></head></html>')
    http.add("GET", f"https://{SEED}/favicon.ico", body=OLD_ICO, headers={"content-type": "image/x-icon"})
    res = run(http)
    refused = {r["href"]: r["reason"] for r in res.attributes["favicon_refused_hrefs"]}
    assert "10.1.2.3" in refused["https://img.www.example.com/f.png"]  # core SSRF guard after DNS, nothing sent
    assert ("GET", "https://img.www.example.com/f.png") not in target_calls(http)
    assert res.attributes["favicon"]["url"] == f"https://{SEED}/favicon.ico"


def test_redirect_hops_are_rechecked():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text="<html></html>")
    http.add("GET", f"https://{SEED}/favicon.ico", status=302, headers={"location": "https://evil.example.net/x.ico"})
    res = run(http)
    # the icon URL answered a redirect the safe fetch refuses: could not verify (policy), never 'no favicon'
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "redirect not followed" in res.error
    assert not any("evil.example.net" in u for _m, u in target_calls(http))


def test_token_href_is_never_fetched():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text='<html><link rel="icon" href="/i.ico?u=alice%40example.com"></html>')
    http.add("GET", f"https://{SEED}/favicon.ico", body=OLD_ICO, headers={"content-type": "image/x-icon"})
    res = run(http)
    refused = {r["href"]: r["reason"] for r in res.attributes["favicon_refused_hrefs"]}
    rows = [reason for href, reason in refused.items() if href.startswith(f"https://{SEED}/i.ico")]
    assert rows and "per-recipient token" in rows[0]
    assert "alice" not in str(res.attributes) and "alice" not in str(res.raw)  # hostile hrefs are masked before storage
    assert ("GET", f"https://{SEED}/i.ico?u=alice%40example.com") not in target_calls(http)


def test_homepage_redirect_to_another_site_is_not_followed_and_the_seed_icon_is_used():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", status=301, headers={"location": "https://landing.example.net/?u=bob%40example.org"})
    http.add("GET", f"https://{SEED}/favicon.ico", body=OLD_ICO, headers={"content-type": "image/x-icon"})
    res = run(http)
    assert res.status is Status.OK, res.error  # a redirect answer is not 'seed not fetched' (SKIPPED)
    assert target_calls(http) == [("GET", f"https://{SEED}/"), ("GET", f"https://{SEED}/favicon.ico")]
    assert any("redirect not followed" in r["reason"] for r in res.attributes["favicon_refused_hrefs"])
    assert "bob" not in str(res.attributes) and "bob" not in str(res.raw)


def test_json_403_is_blocked_never_hashed():
    err = module_fixture("favicon_fetch", "error_403_json.json")
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text="<html></html>")
    http.add("GET", f"https://{SEED}/favicon.ico", status=err["status"], text=err["body"], headers={"content-type": "application/json"})
    res = run(http)
    assert res.status is Status.BLOCKED and "favicon" not in res.attributes


@pytest.mark.parametrize(("status", "body", "ctype", "expected"), [
    (404, "<html>not found</html>", "text/html", Status.EMPTY),
    (200, "<html><body>soft 404</body></html>", "text/html", Status.EMPTY),
    (429, "slow down", "text/plain", Status.RATE_LIMITED),
    (500, "oops", "text/plain", Status.ERROR),
])
def test_icon_answers(status, body, ctype, expected):
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", text="<html></html>")
    http.add("GET", f"https://{SEED}/favicon.ico", status=status, text=body, headers={"content-type": ctype})
    res = run(http)
    assert res.status is expected
    assert "favicon" not in res.attributes


def test_challenge_homepage_is_blocked_and_no_icon_is_requested():
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", status=403, text="<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>",
             headers={"server": "cloudflare"})
    res = run(http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert target_calls(http) == [("GET", f"https://{SEED}/")]


def test_never_runs_on_a_pivot():
    http = target(FakeHttp())
    res = run(http, is_seed=False)
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert target_calls(http) == []


def test_kill_switch_stops_before_any_request():
    http = target(FakeHttp())
    rt = make_runtime(http)
    rt.cancel("test kill switch")
    res = run(http, runtime=rt)
    assert target_calls(http) == []
    assert res.status in (Status.EMPTY, Status.ERROR, Status.SKIPPED)


def test_state_changing_methods_are_refused_by_the_helper():
    http = target(FakeHttp())
    ctx = make_ctx(FaviconFetch, http, entity=f"domain:{SEED}", options=LIGHT)
    with pytest.raises(PolicyError):
        L.safe_get(ctx, f"https://{SEED}/favicon.ico", accept=None, max_bytes=10, method="POST")
    assert target_calls(http) == []


def test_offline_selftest_and_contract_metadata():
    hc = FaviconFetch.health_check()
    assert hc.offline is True and hc.selftest(None).status == "ok"
    assert FaviconFetch.opsec is Opsec.LIGHT and FaviconFetch.disclosure == "target"
    assert FaviconFetch.default_enabled is False and FaviconFetch.run_on == "seeds"
    assert FaviconFetch.max_rate <= 1.0 and FaviconFetch.hosts == ()


def test_internal_hosts_are_exempt_only_for_an_internal_typed_seed():
    """The helper refuses internal names/addresses itself; only the exact hosts of an internal
    analyst-typed seed are left to the core (which allows them only for such a seed)."""
    url = "http://127.0.0.1:8080/favicon.ico"
    assert L.check_target(url, site_host="127.0.0.1", allowed_ports=(80, 443, 8080), same_site_only=False)  # refused
    assert L.check_target(url, site_host="127.0.0.1", allowed_ports=(80, 443, 8080), same_site_only=False,
                          internal_hosts=("127.0.0.1",)) == ""
    assert L.check_target("http://10.0.0.5/", site_host="127.0.0.1", same_site_only=False, internal_hosts=("127.0.0.1",))
    http = FakeHttp()
    seed = "url:http://127.0.0.1:8080/"
    ctx = make_ctx(FaviconFetch, http, entity=seed, options=LIGHT)
    assert L.internal_seed_hosts(ctx, ctx.entity) == ()
    ctx = make_ctx(FaviconFetch, http, entity=seed, options=LIGHT, internal_seed=True)
    assert L.internal_seed_hosts(ctx, ctx.entity) == ("127.0.0.1",)
    ctx = make_ctx(FaviconFetch, http, entity=seed, options=LIGHT, internal_seed=True, is_seed=False)
    assert L.internal_seed_hosts(ctx, ctx.entity) == ()
