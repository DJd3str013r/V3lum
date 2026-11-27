"""js_endpoints_live (P068, LIGHT, opt-in) and the shared JS analysis library, offline.

Fixtures in tests/fixtures/js_endpoints_live/ (batch p9-G03-1 prep, 2026-11-26):

* ``jquery_3.7.1.min.js`` - jQuery 3.7.1 as served by code.jquery.com (SRI-verified, MIT): zero secrets,
  zero kit channels, only media-type strings the noise filter drops;
* ``adversarial_2mb_synthetic.js.gz`` - 2 MB of minified-looking quoted runs that make the original
  LinkFinder regex quadratic (``"//aa.aa...``, ``'/a/a/a...``);
* ``app_bundle_synthetic.js`` / ``kit_exfil_synthetic.js`` - synthetic bundles with placeholders the tests
  replace by positive-control secrets built at run time by concatenation (no committed literal looks
  like a live credential);
* ``homepage_scripts_synthetic.html``, ``kit_page_synthetic.html``, ``source_map_synthetic.json``;
* ``design_pivots_and_js_recorded.json`` - the research's js_extraction record (jQuery: 4 media-type
  'endpoints', no secret; positive controls aws-access-token and github-pat).
"""

from __future__ import annotations

import gzip
import re
import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import js_endpoints as J
from v3lum.modules.url_web.js_endpoints import JsEndpointsLive

FX = FIXTURES / "js_endpoints_live"
SEED = "www.example.com"
IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
JS = {"content-type": "application/javascript"}

# positive controls built at run time (never a committed literal)
AWS = "AKIA" + "QX7Z" + "PLMN" + "4RTW" + "2B6D"
GHP = "ghp_" + "Zq8Lm2Nx4Pv6Rt9Wb1Yc3Ud5Fg7Hj0Ks2Lm4"
GCP = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
TG = "7123456789:" + "AAH" + "x9Q2mLp4Rt6Vw8Yz1Ab3Cd5Ef7Gh9Ij0K"
DISCORD = "https://discord.com/api/webhooks/123456789012345678/" + "Ab3Cd5Ef7Gh9Ij0KLm2Np4Qr6St8Uv0Wx2Yz4Ab6Cd8Ef0Gh2Ij4Kl6Mn8Op0Qr"


def bundle() -> str:
    text = (FX / "app_bundle_synthetic.js").read_text()
    return text.replace("__AWS_KEY__", AWS).replace("__GITHUB_PAT__", GHP).replace("__GCP_KEY__", GCP)


def kit() -> str:
    return (FX / "kit_exfil_synthetic.js").read_text().replace("__TG_TOKEN__", TG).replace("__DISCORD_WEBHOOK__", DISCORD)


def target(http: FakeHttp, host: str = SEED, ip: str = IP) -> FakeHttp:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])
    return http


def target_calls(http: FakeHttp) -> list[str]:
    return [c["url"] for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns" not in c["url"]]


def run(http: FakeHttp, entity: str = f"domain:{SEED}", **kw):
    return run_module(JsEndpointsLive, entity, http, options=kw.pop("options", LIGHT), **kw)


# ---------------------------------------------------------------------------------- library (c4, c8, c9)


def test_linkfinder_alternations_and_noise_filter():
    found = J.extract_endpoints(bundle(), f"https://{SEED}/static/js/app.js", page_url=f"https://{SEED}/")
    values = {e["value"] for e in found["endpoints"]}
    assert {"/api/v1/users?id=1", "/api/v2/orders", "https://api.example.com/graphql", "config.json", "v1/accounts/list"} <= values
    assert "text/javascript" not in values and "12/31/2026" not in values  # media type and date dropped
    assert not any("node_modules" in v for v in values)
    assert found["dropped"]["media_type"] >= 1 and found["dropped"]["date"] == 1
    urls = {e["url"] for e in found["endpoints"]}
    assert f"https://{SEED}/api/v1/users?id=1" in urls  # relative paths resolve against the page


def test_jquery_gives_zero_endpoints_secrets_and_kit_hits():
    rec = module_fixture("js_endpoints_live", "design_pivots_and_js_recorded.json")["js_extraction"]
    jq = (FX / "jquery_3.7.1.min.js").read_text()
    assert len(jq.encode()) == rec["bytes"]
    analysis = J.analyse_js(jq, rec["js_url"])
    assert analysis["endpoints"] == [] and analysis["secrets"] == [] and analysis["kit"] == []
    assert analysis["generic_secrets"] == 0
    assert analysis["dropped"]["media_type"] >= len(rec["endpoints_sample"]) == 4  # the research's 4 'endpoints' were media types


def test_positive_controls_are_masked_and_never_leave_raw():
    analysis = J.analyse_js(bundle(), f"https://{SEED}/static/js/app.js")
    rules = {s["rule"] for s in analysis["secrets"]}
    assert {"aws-access-token", "github-pat"} <= rules
    assert "AKIAIOSFODNN7EXAMPLE" not in str(analysis)  # the AWS documentation example is allow-listed
    for s in analysis["secrets"]:
        assert s["masked"]["sha256"] and "…" in s["masked"]["display"]
        if s["excerpt"]:
            assert "[REDACTED]" in s["excerpt"]
    assert_no_secret(AWS, analysis)
    assert_no_secret(GHP, analysis)
    assert analysis["firebase"]["project_id"] == "example-app" and analysis["firebase"]["api_key"]["sha256"]
    assert_no_secret(GCP, analysis)


def test_kit_channels_are_masked_and_drop_urls_never_carry_tokens():
    found = J.kit_exfil_indicators(kit(), "https://phish.example.net/kit/")
    kinds = {k["kind"] for k in found}
    assert {"telegram_bot_api", "telegram_chat_id", "discord_webhook", "post_target"} <= kinds
    posts = {k["url"] for k in found if k["kind"] == "post_target"}
    assert posts == {"https://phish.example.net/kit/next.php", "https://drop.example.net/gate/receive.php"}
    assert_no_secret(TG, found)
    assert_no_secret(DISCORD.rsplit("/", 1)[1], found)
    assert "-1001234567890" not in str(found)  # the chat id is masked too
    forms = J.kit_exfil_indicators((FX / "kit_page_synthetic.html").read_text(), "https://phish.example.net/")
    assert {k["url"] for k in forms if k["kind"] == "form_action"} == {"https://phish.example.net/send.php", "https://drop.example.net/collect"}


def test_every_pattern_finishes_on_the_2mb_adversarial_fixture_within_2s():
    data = gzip.decompress((FX / "adversarial_2mb_synthetic.js.gz").read_bytes()).decode()
    assert len(data) >= 2 * 1024 * 1024
    checks = {
        "tokenizer": lambda: sum(1 for _ in J.iter_quoted_segments(data)),  # the whole 2 MB, every segment classified
        "linkfinder": lambda: J.extract_endpoints(data, "https://www.example.com/a.js"),
        "kit": lambda: J.kit_exfil_indicators(data, "https://www.example.com/"),
        "firebase": lambda: J.firebase_config(data),
        "scripts": lambda: J.extract_script_srcs(data, "https://www.example.com/"),
        "inline": lambda: J.inline_scripts(data),
        "source_map": lambda: J.find_source_map_url(data, "https://www.example.com/a.js"),
    }
    # hostile pages: 2 MB of unclosed <script> tags / repeated <form> tags (a lazy '.{0,262144}?' regex or an
    # unbounded per-form window is quadratic here)
    scripts = "<script>" * (2 * 1024 * 1024 // 8)
    forms = '<form action="https://x.example.net/a">' * (2 * 1024 * 1024 // 39)
    checks["inline_unclosed"] = lambda: J.inline_scripts(scripts)
    checks["kit_forms"] = lambda: J.kit_exfil_indicators(forms, "https://www.example.com/")
    checks["page_scripts"] = lambda: J.extract_script_srcs(scripts, "https://www.example.com/")
    for name, fn in checks.items():
        started = time.monotonic()
        fn()
        assert time.monotonic() - started < 2.0, name


def test_script_srcs_same_site_budget_and_third_parties():
    srcs = J.extract_script_srcs((FX / "homepage_scripts_synthetic.html").read_text(), f"https://{SEED}/")
    assert srcs["fetch"][0] == f"https://{SEED}/static/js/main.4f2a.js" and len(srcs["fetch"]) == 20
    assert srcs["not_fetched_budget"]  # beyond the 20-file budget: listed, not fetched
    assert "https://static.example.com/vendor.js" in srcs["fetch"]  # same registrable domain
    third = set(srcs["third_party"])
    assert "https://www.googletagmanager.com/gtm.js?id=GTM-EXAMPLE" in third and "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js" in third
    assert srcs["inline_scripts"] == 1 and srcs["skipped"][0]["reason"] == "non-http script source"


def test_source_map_reference_and_parse():
    ref = J.find_source_map_url(bundle(), f"https://{SEED}/static/js/app.min.js")
    assert ref == {"url": f"https://{SEED}/static/js/app.min.js.map", "inline": False, "source": "comment"}
    parsed = J.parse_source_map((FX / "source_map_synthetic.json").read_text())
    assert parsed["sources"] == ["src/api/client.ts", "src/config/endpoints.ts", "node_modules/axios/lib/axios.js"]
    assert parsed["has_sources_content"] is True and parsed["node_modules"] == 1


# ---------------------------------------------------------------------------------- the LIGHT module (c2, c3, c5-c8)


def homepage(http: FakeHttp, scripts: list[str], body: str = "") -> None:
    tags = "".join(f'<script src="{s}"></script>' for s in scripts)
    http.add("GET", f"https://{SEED}/", text=f"<html><head>{tags}</head><body>{body}</body></html>")


def test_same_site_scripts_are_analysed_and_secrets_masked_everywhere():
    http = target(FakeHttp())
    homepage(http, ["/static/js/app.min.js", "https://cdn.jsdelivr.net/npm/x.js"], body='<form action="/login" method="post"></form>')
    http.add("GET", f"https://{SEED}/static/js/app.min.js", text=bundle(), headers=JS)
    http.add("GET", f"https://{SEED}/static/js/app.min.js.map", text=(FX / "source_map_synthetic.json").read_text(),
             headers={"content-type": "application/json"})
    res = run(http)
    assert res.status is Status.OK, res.error
    assert target_calls(http) == [f"https://{SEED}/", f"https://{SEED}/static/js/app.min.js", f"https://{SEED}/static/js/app.min.js.map"]
    endpoints = [p for p in res.pivots if p.relation == "js_endpoint"]
    assert endpoints and all(p.expand is False for p in endpoints)
    assert f"https://{SEED}/api/v1/users?id=1" in {p.entity.value for p in endpoints}
    assert f"https://{SEED}/api/internal/v3" in {p.entity.value for p in endpoints}  # from the source map's sourcesContent
    third = {p.entity.value for p in res.pivots if p.relation == "links_to"}
    assert "jsdelivr.net" in third and all(p.expand is False for p in res.pivots if p.relation == "links_to")
    titles = {f.title for f in res.findings}
    assert {"Secret in public JavaScript: aws-access-token", "Secret in public JavaScript: github-pat"} <= titles
    for f in res.findings:
        if "credential_exposure" in f.tags:
            assert f.data["masked"]["sha256"] and f.data["locations"][0]["path"].startswith("https://") and f.criterion
    assert res.attributes["js_source_maps"][0]["n_sources"] == 3
    assert res.attributes["secret_counts"]["aws-access-token"] == 1
    for secret in (AWS, GHP, GCP):
        assert_no_secret(secret, res.findings, res.attributes, res.raw, res.pivots)  # findings, attributes, evidence
    assert "js_files" in res.attributes and all("sha256" in f for f in res.attributes["js_files"]["files"])


def test_kit_page_gives_masked_channels_and_host_pivots_only():
    http = target(FakeHttp())
    homepage(http, ["/kit/send.js"], body=(FX / "kit_page_synthetic.html").read_text())
    http.add("GET", f"https://{SEED}/kit/send.js", text=kit(), headers=JS)
    res = run(http)
    channel = next(f for f in res.findings if f.title == "Phishing-kit exfiltration channels in page scripts")
    assert channel.severity.name == "MEDIUM" and "phishing_kit_exfil" in channel.tags
    hosts = {p.entity.value for p in res.pivots if p.relation == "exfil_endpoint"}
    assert {"api.telegram.org", "discord.com", "drop.example.net"} <= hosts
    assert all(p.expand is False for p in res.pivots if p.relation == "exfil_endpoint")
    assert_no_secret(TG, res.findings, res.attributes, res.raw, res.pivots)
    assert_no_secret(DISCORD.rsplit("/", 1)[1], res.findings, res.attributes, res.raw, res.pivots)
    assert not any("telegram" in p.entity.value and "bot" in p.entity.value for p in res.pivots)
    assert not any("api.telegram.org" in u or "discord.com" in u or "drop.example.net" in u for u in target_calls(http))


def test_ordinary_forms_and_posts_are_not_phishing_kit_channels():
    """A site's own search/login forms, same-site POSTs and a cross-site newsletter form are no exfiltration
    channel: no finding, no exfil_endpoint pivot; the cross-site form stays a listed candidate (c7)."""
    http = target(FakeHttp())
    body = ('<form action="/search"></form><form action="/login" method="post"><input type="password" name="p"></form>'
            '<form action="https://news.us1.list-manage.com/subscribe/post?u=abc&amp;id=def" method="post"><input name="EMAIL"></form>'
            '<script>fetch("/api/track", {method: "POST"}); var chat_id = "12345678";</script>')
    homepage(http, [], body=body)
    res = run(http)
    assert res.status is Status.OK, res.error
    assert not [f for f in res.findings if "phishing_kit_exfil" in f.tags]
    assert not [p for p in res.pivots if p.relation == "exfil_endpoint"]
    candidates = res.attributes["exfil_channels"]
    assert [c["host"] for c in candidates] == ["news.us1.list-manage.com"] and all(c["candidate"] for c in candidates)


def test_credential_form_posting_to_another_site_is_a_kit_channel():
    http = target(FakeHttp())
    homepage(http, [], body='<form method="post" action="https://collect.example.net/gate.php"><input name="cpf">'
                            '<input type="password" name="senha"></form>')
    res = run(http)
    channel = next(f for f in res.findings if f.title == "Phishing-kit exfiltration channels in page scripts")
    assert channel.severity.name == "MEDIUM" and channel.tags == ["phishing_kit_exfil"]
    assert {p.entity.value for p in res.pivots if p.relation == "exfil_endpoint"} == {"collect.example.net"}


def test_files_beyond_the_budget_are_listed_not_fetched():
    http = target(FakeHttp())
    homepage(http, [f"/js/part{i}.js" for i in range(23)])
    for i in range(20):
        http.add("GET", f"https://{SEED}/js/part{i}.js", text=f'var a{i}="/api/p{i}";', headers=JS)
    res = run(http)
    nf = res.attributes["js_files"]["not_fetched"]
    assert [x["url"] for x in nf] == [f"https://{SEED}/js/part{i}.js" for i in (20, 21, 22)]
    assert all("budget" in x["reason"] for x in nf)
    assert len(target_calls(http)) == 21


def test_light_request_budget_stops_partial():
    http = target(FakeHttp())
    rt = make_runtime(http)
    rt.http.ceilings.charge("light", SEED, n=22)  # 22 of the 25 LIGHT requests of this host are used
    homepage(http, [f"/js/part{i}.js" for i in range(5)])
    for i in range(2):
        http.add("GET", f"https://{SEED}/js/part{i}.js", text="var a=1;", headers=JS)
    res = run(http, runtime=rt)
    assert res.partial is True and res.stop_reason == "request_cap"
    assert {x["url"] for x in res.attributes["js_files"]["not_fetched"]} >= {f"https://{SEED}/js/part{i}.js" for i in (2, 3, 4)}


def test_scripts_on_other_hosts_tokens_and_private_names_are_never_fetched():
    http = target(FakeHttp())
    target(http, "assets.www.example.com", "10.0.0.8")
    homepage(http, ["https://other.example.org/a.js", "/t.js?u=alice%40example.com", "https://assets.www.example.com/b.js",
                    "https://static.example.com/c.js"])
    res = run(http)
    refused = {r["url"]: r["reason"] for r in res.attributes["js_files"]["refused"]}
    token_rows = [reason for url, reason in refused.items() if url.startswith(f"https://{SEED}/t.js")]
    assert token_rows and "per-recipient token" in token_rows[0]
    assert "alice" not in str(res.attributes) and "alice" not in str(res.raw)  # the address is masked before it is stored (c5)
    assert "10.0.0.8" in refused["https://assets.www.example.com/b.js"]  # core SSRF guard after resolution
    assert "outside the analyst-typed seed" in refused["https://static.example.com/c.js"]
    assert target_calls(http) == [f"https://{SEED}/"]


@pytest.mark.parametrize(("status", "text", "headers", "expected"), [
    (403, "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>", {"server": "cloudflare"}, Status.BLOCKED),
    (429, "slow down", {}, Status.RATE_LIMITED),
    (500, "oops", {}, Status.ERROR),
])
def test_homepage_failures_are_could_not_verify(status, text, headers, expected):
    http = target(FakeHttp())
    http.add("GET", f"https://{SEED}/", status=status, text=text, headers=headers)
    res = run(http)
    assert res.status is expected
    assert target_calls(http) == [f"https://{SEED}/"]


def test_never_runs_on_a_pivot_and_honours_the_kill_switch():
    http = target(FakeHttp())
    res = run(http, is_seed=False)
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and target_calls(http) == []
    rt = make_runtime(http)
    rt.cancel("test kill switch")
    run(http, runtime=rt)
    assert target_calls(http) == []


def test_only_get_is_used():
    http = target(FakeHttp())
    homepage(http, ["/a.js"])
    http.add("GET", f"https://{SEED}/a.js", text="var a=1;", headers=JS)
    run(http)
    assert {c["method"] for c in http.calls if c["url"].startswith("https://www.")} == {"GET"}


def test_offline_selftest_and_contract_metadata():
    hc = JsEndpointsLive.health_check()
    assert hc.offline is True and hc.selftest(None).status == "ok"
    assert JsEndpointsLive.opsec is Opsec.LIGHT and JsEndpointsLive.disclosure == "target"
    assert JsEndpointsLive.default_enabled is False and JsEndpointsLive.run_on == "seeds" and JsEndpointsLive.max_rate <= 1.0
    assert re.fullmatch(r"[a-z_]+", JsEndpointsLive.name)
