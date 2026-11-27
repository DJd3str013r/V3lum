"""web_fingerprint (P072, LIGHT) and the shared matcher library: offline tests.

Fixtures in tests/fixtures/web_fingerprint/ (prep p9-G03-2, 2026-11-26; FC9):
* trimmed real homepages: ``ok_nicbr_home.http.json`` and ``ok_cloudflare_home.http.json`` (live exchanges
  with headers, body cut, CF-Ray redacted), ``ok_tranco_home.html`` and ``ok_phishstats_home.html``
  (research captures, bodies only);
* ``challenge_cloudflare_403.http.json``: a real Cloudflare managed-challenge body (tokens redacted);
* corporate secure-web-gateway block pages (Zscaler, Netskope, FortiGuard, PAN-OS) and the squid proxy
  error page are SYNTHETIC shapes (a vendor block page can only be captured from behind that vendor's
  gateway), as are the 503 page, the phishing-kit page and the Grafana panel page;
* ``technologies_handwritten.json`` / ``categories_handwritten.json``: own patterns in the Wappalyzer
  format (FC4: tests never use the GPL-3.0 webappanalyzer data).

Target addresses are routable test values (93.184.216.0/24): TEST-NET ranges are refused by the SSRF guard.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, add_dns, make_ctx, make_runtime, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import web_fingerprint as wf
from v3lum.modules.url_web.web_fingerprint import WebFingerprint

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "web_fingerprint"
IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
NO_DNS = {"web_fingerprint_dns": False}


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def exchange(name: str) -> dict:
    return json.loads(fx(name))


def install_wa(tech: str = "technologies_handwritten.json", cats: str = "categories_handwritten.json") -> None:
    """Install the hand-written fingerprint file as the runtime dataset copies (fresh mtime)."""
    root = paths.datasets_dir()
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for name in wf.WA_TECH_DATASETS:
        p = root / name
        p.write_text(fx(tech) if name.endswith("_a") else "{}", encoding="utf-8")
        os.utime(p, (now, now))
    p = root / wf.WA_CATEGORIES
    p.write_text(fx(cats), encoding="utf-8")
    os.utime(p, (now, now))


@pytest.fixture(autouse=True)
def _dataset():
    install_wa()
    yield


def target(http: FakeHttp, host: str, ip: str = IP) -> None:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])


def target_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns.com" not in c["url"]]


def serve(http: FakeHttp, url: str, ex: dict) -> None:
    headers = {k: v for k, v in ex["headers"]}
    http.add("GET", url, status=ex["status"], body=ex["body"].encode("utf-8"), headers=headers)


def run(http: FakeHttp, value: str = "domain:nic.br", **kw):
    kw.setdefault("options", LIGHT)
    kw.setdefault("settings", NO_DNS)
    return run_module(WebFingerprint, value, http, **kw)


# ------------------------------------------------------------------ metadata and the self-test
def test_metadata_light_opt_in_target_contact():
    cls = WebFingerprint
    assert cls.opsec is Opsec.LIGHT and cls.disclosure == "target" and cls.hosts == ()
    assert cls.default_enabled is False and cls.run_on == "seeds" and cls.terms == "open"
    assert cls.max_rate == 1.0 and cls.sources == (wf.WA_SOURCE, wf.RETIRE_SOURCE, wf.KEV_SOURCE)
    hc = cls.health_check()
    assert hc.offline is True and callable(hc.selftest)


def test_offline_selftest_passes_without_network():
    http = FakeHttp()
    ctx = make_ctx(WebFingerprint, http, entity=Entity.make(T.DOMAIN, "example.com"))
    result = WebFingerprint.health_check().selftest(ctx)
    assert result.status == "ok", result.detail
    assert http.calls == []


# ------------------------------------------------------------------ happy paths (trimmed real homepages)
def test_nicbr_homepage_technologies_and_version_inferred_cves():
    http = FakeHttp()
    target(http, "nic.br")
    serve(http, "https://nic.br/", exchange("ok_nicbr_home.http.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    techs = {t["name"]: t for t in res.attributes["technologies"]}
    assert {"Apache HTTP Server", "jQuery", "HSTS"} <= set(techs)
    assert techs["jQuery"]["version"] == "1.10.2"
    assert res.attributes["http_status"] == 200 and res.attributes["server"] == "Apache"
    assert res.attributes["fingerprint_verdict"]["verdict"] == "ok"
    # FC8: one collapsed finding per technology, POSSIBLE, at most MEDIUM without KEV
    cve_findings = [f for f in res.findings if "version_inferred" in f.tags]
    assert len(cve_findings) == 1
    f = cve_findings[0]
    assert re.match(r"^jQuery 1\.10\.2: \d+ CVEs?, max severity \w+$", f.title)
    assert f.severity.name.lower() in ("low", "medium") and f.confidence_label.value == "possible"
    assert f.criterion and "version-inferred" in f.criterion
    cves = [p for p in res.pivots if p.entity.type is T.CVE]
    assert cves and all(not p.expand for p in cves)
    # one GET to the seed, pinned to the checked address, browser-like UA (never the V3LUM UA)
    calls = target_calls(http)
    assert [c["url"] for c in calls] == ["https://nic.br/"]
    assert calls[0]["method"] == "GET" and calls[0].get("pin_ip") == IP
    ua = {k.lower(): v for k, v in calls[0]["headers"].items()}.get("user-agent", "")
    assert "v3lum" not in ua.lower()
    http.assert_hosts_within(WebFingerprint, extra=("nic.br",))


def test_cloudflare_homepage_passive_waf_cdn_signatures():
    http = FakeHttp()
    target(http, "www.cloudflare.com")
    serve(http, "https://www.cloudflare.com/", exchange("ok_cloudflare_home.http.json"))
    res = run(http, "domain:www.cloudflare.com")
    assert res.status is Status.OK
    names = {w["name"] for w in res.attributes["waf_cdn"]}
    assert any(n.startswith("Cloudflare") for n in names)
    assert res.attributes["waf"].startswith("Cloudflare")
    assert "Cloudflare" in {t["name"] for t in res.attributes["technologies"]}


def test_tranco_body_versions_and_cpe_guesses():
    http = FakeHttp()
    target(http, "tranco-list.eu")
    http.add("GET", "https://tranco-list.eu/", text=fx("ok_tranco_home.html"))
    res = run(http, "domain:tranco-list.eu")
    techs = {t["name"]: t["version"] for t in res.attributes["technologies"]}
    assert techs.get("jQuery") == "3.7.1" and techs.get("Bootstrap") == "4.6.2"
    assert {"technology": "jQuery", "version": "3.7.1", "cpe": "cpe:2.3:a:jquery:jquery:3.7.1:*:*:*:*:*:*:*"} in res.attributes["cpe_guesses"]


def test_analytics_ids_and_redirect_chain_pivots():
    http = FakeHttp()
    target(http, "example.com")
    target(http, "www.example.com")
    http.add("GET", "https://example.com/", redirect_to="https://www.example.com/")
    body = "<html><head><title>Shop</title><script>gtag('config','G-ABCDEF1234');</script></head><body>ok</body></html>"
    http.add("GET", "https://www.example.com/", text=body)
    res = run(http, "domain:example.com")
    assert res.status is Status.OK
    assert res.attributes["redirect_chain"][-1] == "https://www.example.com/"
    hop = [p for p in res.pivots if p.entity.type is T.DOMAIN]
    assert [(p.entity.value, p.relation, p.expand) for p in hop] == [("www.example.com", "redirects_to", False)]
    assert any(p.entity.type is T.ANALYTICS_ID and p.entity.value == "G-ABCDEF1234" for p in res.pivots)
    assert [c["url"] for c in target_calls(http)] == ["https://example.com/", "https://www.example.com/"]


def test_dns_matcher_through_ctx_dns_and_cname_attribution():
    http = FakeHttp()
    target(http, "acme.example")
    http.add("GET", "https://acme.example/", text="<html><head><title>x</title></head></html>")
    add_dns(http, "acme.example", "MX", ["1 aspmx.l.google.com."])
    add_dns(http, "acme.example", "TXT", [])
    add_dns(http, "acme.example", "NS", ["ns1.example.net."])
    add_dns(http, "acme.example", "SOA", [])
    add_dns(http, "acme.example", "CNAME", [])
    res = run(http, "domain:acme.example", settings={"web_fingerprint_dns": True})
    assert "Google Workspace" in {t["name"] for t in res.attributes["technologies"]}
    assert res.raw["dns"]["MX"][0].startswith("1 aspmx.l.google.com")


# ------------------------------------------------------------------ FC3 / FC7: blocks, challenges, inconclusive
def test_challenge_page_is_blocked_and_never_retried():
    ex = exchange("challenge_cloudflare_403.http.json")
    http = FakeHttp()
    target(http, "app.example.org")
    serve(http, "https://app.example.org/", ex)
    res = run(http, "domain:app.example.org")
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert "technologies" not in res.attributes
    assert len(target_calls(http)) == 1  # no retry, no other UA


@pytest.mark.parametrize(("page", "vendor"), [
    ("corporate_block_zscaler_synthetic.html", "Zscaler"),
    ("corporate_block_netskope_synthetic.html", "Netskope"),
    ("corporate_block_fortiguard_synthetic.html", "Fortinet"),
    ("corporate_block_paloalto_synthetic.html", "Palo Alto Networks"),
])
def test_corporate_proxy_block_pages_are_never_fingerprinted(page, vendor):
    http = FakeHttp()
    target(http, "example.org")
    http.add("GET", "https://example.org/", text=fx(page))
    res = run(http, "domain:example.org")
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert f"blocked by corporate proxy ({vendor})" in res.error
    assert "technologies" not in res.attributes and not res.findings


def test_configured_proxy_signature_is_honoured():
    http = FakeHttp()
    target(http, "example.org")
    http.add("GET", "https://example.org/", text="<html><title>Blocked</title>AcmeGate policy denied this site</html>")
    sigs = [{"vendor": "AcmeGate", "any": ["AcmeGate policy denied"]}]
    res = run(http, "domain:example.org", settings={"web_fingerprint_dns": False, "web_fingerprint_proxy_signatures": sigs})
    assert res.status is Status.BLOCKED and "AcmeGate" in res.error


def test_5xx_body_is_inconclusive_headers_only():
    ex = exchange("error_503_synthetic.http.json")
    http = FakeHttp()
    target(http, "example.net")
    serve(http, "https://example.net/", ex)
    res = run(http, "domain:example.net")
    names = {t["name"] for t in res.attributes.get("technologies", [])}
    assert "jQuery" not in names  # the error body is never fingerprinted (FC7)
    assert "Nginx" in names  # headers still are
    assert res.attributes["fingerprint_verdict"]["verdict"] == "inconclusive"
    assert not [f for f in res.findings if "version_inferred" in f.tags]


def test_404_without_header_facts_is_could_not_verify():
    http = FakeHttp()
    target(http, "example.net")
    http.add("GET", "https://example.net/", status=404, text="<html><title>Not Found</title></html>")
    res = run(http, "domain:example.net")
    assert res.status is Status.ERROR and "inconclusive" in res.error


def test_squid_proxy_error_page_is_an_error():
    http = FakeHttp()
    target(http, "example.net")
    http.add("GET", "https://example.net/", status=200, text=fx("proxy_error_squid_synthetic.html"))
    res = run(http, "domain:example.net")
    assert res.status is Status.ERROR


def test_429_is_rate_limited():
    http = FakeHttp()
    target(http, "example.net")
    http.add("GET", "https://example.net/", status=429, text="slow down")
    assert run(http, "domain:example.net").status is Status.RATE_LIMITED


def test_connection_failure_on_https_falls_back_to_http_once():
    from v3lum.core.http import NetworkError

    http = FakeHttp()
    target(http, "legacy.example.org")
    http.add("GET", "https://legacy.example.org/", error=NetworkError("connection refused", kind="ConnectionError"))
    http.add("GET", "http://legacy.example.org/", text="<html><title>old</title></html>", headers={"Server": "Microsoft-IIS/6.0"})
    res = run(http, "domain:legacy.example.org")
    assert res.status is Status.OK
    assert [c["url"] for c in target_calls(http)][-1] == "http://legacy.example.org/"


# ------------------------------------------------------------------ own MIT rules and hostile pages
def test_phishing_kit_page_gives_a_finding_and_cves_as_attribute():
    http = FakeHttp()
    target(http, "banco-seguro.example.org")
    page = fx("phishing_kit_synthetic.html").replace("jquery-3.5.1.min.js", "jquery-1.12.4.min.js")
    http.add("GET", "https://banco-seguro.example.org/", text=page)
    res = run(http, "domain:banco-seguro.example.org")
    kit = [f for f in res.findings if "phishing" in f.tags]
    assert kit and kit[0].severity.name.lower() == "high"
    assert res.attributes["own_rule_hits"][0]["kind"] == "phishing_kit"
    # FC8: hostile hosts get technologies (and CVE summaries) as attributes, never vulnerability findings
    assert not [f for f in res.findings if "version_inferred" in f.tags]
    assert res.attributes["technology_cves"] and res.attributes["technology_cves"][0]["technology"] == "jQuery"


def test_panel_rule_hit_is_a_low_exposure_finding():
    http = FakeHttp()
    target(http, "grafana.example.org")
    http.add("GET", "https://grafana.example.org/", text=fx("panel_grafana_synthetic.html"))
    res = run(http, "domain:grafana.example.org")
    panel = [f for f in res.findings if f.title.startswith("Administration panel exposed")]
    assert panel and panel[0].severity.name.lower() == "low"


# ------------------------------------------------------------------ AR20 safety expectations
def test_light_never_runs_on_a_pivot():
    http = FakeHttp()
    target(http, "nic.br")
    serve(http, "https://nic.br/", exchange("ok_nicbr_home.http.json"))
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.com", "links_to", "x"),))
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert target_calls(http) == []


def test_needs_light_mode():
    from v3lum.core.module import readiness_check

    ready = readiness_check(WebFingerprint, {}, Opsec.PASSIVE)
    assert not ready.ready and ready.reason_code == "opsec"
    assert readiness_check(WebFingerprint, {}, Opsec.LIGHT).ready


def test_redirect_hop_to_a_private_address_is_refused_after_resolution():
    http = FakeHttp()
    target(http, "example.com")
    target(http, "inner.example.net", ip="10.0.0.9")
    http.add("GET", "https://example.com/", redirect_to="https://inner.example.net/")
    http.add("GET", "https://inner.example.net/", text="internal")
    res = run(http, "domain:example.com")
    assert res.status is not Status.OK
    assert "https://inner.example.net/" not in [c["url"] for c in target_calls(http)]


def test_kill_switch_stops_before_any_target_request():
    http = FakeHttp()
    target(http, "nic.br")
    serve(http, "https://nic.br/", exchange("ok_nicbr_home.http.json"))
    rt = make_runtime(http, settings=NO_DNS)
    rt.cancel("test kill switch")
    res = run_module(WebFingerprint, "domain:nic.br", http, options=LIGHT, runtime=rt)
    assert target_calls(http) == []
    assert res.status is not Status.OK or res.partial


def test_only_get_is_ever_sent():
    http = FakeHttp()
    target(http, "nic.br")
    serve(http, "https://nic.br/", exchange("ok_nicbr_home.http.json"))
    run(http)
    assert {c["method"] for c in target_calls(http)} == {"GET"}


def test_cookie_values_never_reach_the_evidence():
    http = FakeHttp()
    target(http, "example.org")
    http.add("GET", "https://example.org/", text="<html><title>x</title></html>",
             headers={"Set-Cookie": "PHPSESSID=s3cr3tSessionValue123; path=/", "Server": "nginx"})
    res = run(http, "domain:example.org")
    assert "PHP" in {t["name"] for t in res.attributes["technologies"]}
    assert "s3cr3tSessionValue123" not in json.dumps(res.raw)
    assert res.raw["headers"]["set-cookie"] == "PHPSESSID"


def test_missing_dataset_is_unavailable_not_empty():
    root = paths.datasets_dir()
    for p in root.glob("webappanalyzer.*"):
        p.unlink()
    http = FakeHttp()
    http.add("GET", re.compile(r"https://raw\.githubusercontent\.com/enthec/webappanalyzer/.*"), status=404, text="404: Not Found")
    target(http, "nic.br")
    res = run(http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert not [c for c in target_calls(http) if "nic.br" in c["url"]]


# ------------------------------------------------------------------ library: FC5 converter and time budget
def test_js_regex_converter_and_skipped_patterns():
    assert wf.js_regex_to_python(r"(?<v>\d+)\k<v>\/x[^]") == r"(?P<v>\d+)(?P=v)/x[\s\S]"
    assert wf.compile_wa_pattern(r"\p{L}+")["ok"] is False
    db = wf.build_fingerprint_db({"Bad": {"cats": [1], "html": [r"\p{L}", "(a+)+$"], "headers": {"X": "ok"}}}, {}, screen=False)
    reasons = sorted(s["reason"].split(":")[0] for s in db["skipped"])
    assert reasons == ["convert", "redos"] and db["stats"]["compiled"] == 1


def test_quadratic_html_pattern_fails_the_budget_screen_linear_passes():
    quadratic = re.compile(r"<[^>]*data-bem", re.I)
    linear = re.compile(r"<link[^>]{0,200}href=[\"']/wp-content/", re.I)
    assert wf.budget_screen(quadratic)[0] is False
    assert wf.budget_screen(linear)[0] is True


@pytest.mark.parametrize("name", ["technologies_handwritten.json"])
def test_every_test_and_bundled_pattern_passes_the_time_budget(name):
    db = wf.build_fingerprint_db(fx(name), fx("categories_handwritten.json"))
    assert db["skipped"] == [] and db["budget_skipped"] == []
    rules = json.loads((Path(wf.__file__).resolve().parents[2] / "data" / "web_fingerprint" / "own_rules.json").read_text(encoding="utf-8"))
    waf = json.loads((Path(wf.__file__).resolve().parents[2] / "data" / "web_fingerprint" / "wafw00f_passive.json").read_text(encoding="utf-8"))
    html_rx = [rx for r in rules["rules"] for rx in r.get("html", [])]
    short_rx = [rx for r in rules["rules"] for k in ("title", "assets") for rx in r.get(k, [])]
    stack = [r for s in waf["signatures"] for r in s["rules"]]
    while stack:
        node = stack.pop()
        if "regex" in node:
            short_rx.append(node["regex"])
        stack.extend(node.get("all", []) + node.get("any", []))
    for rx in html_rx:  # scanned over up to 500 KB of HTML
        ok, ms = wf.budget_screen(re.compile(rx, re.I))
        assert ok, (rx, ms)
    for rx in short_rx:  # header values (<= 8 KB), titles and asset URLs (<= 1 KB)
        ok, ms = wf.budget_screen(re.compile(rx, re.I), small=512, large=2048, target=wf.MAX_HEADER_VALUE_CHARS)
        assert ok, (rx, ms)


def test_slow_pattern_is_remembered_and_skipped_next_time():
    ctx = make_ctx(WebFingerprint, FakeHttp(), entity=Entity.make(T.DOMAIN, "example.com"))
    wf.remember_slow(ctx, "dbkey", ["abc123"])
    assert wf._slow_ids(ctx, "dbkey") == ["abc123"]
    db = wf.build_fingerprint_db({"T": {"cats": [1], "html": ["x"]}}, {}, skip_ids=[wf.pattern_id("T", "html", "x")])
    assert db["budget_skipped"] and db["stats"]["compiled"] == 0


def test_html_is_scanned_only_up_to_500_kb():
    facts = wf.extract_page_facts(b"<html><title>t</title>" + b"a" * 600_000 + b"/wp-content/")
    assert facts["truncated"] is True and len(facts["html"]) == wf.MAX_HTML_BYTES
    db = wf.build_fingerprint_db(fx("technologies_handwritten.json"), fx("categories_handwritten.json"))
    found = wf.match_technologies(db, facts)["detections"]
    assert "WordPress" not in {d["name"] for d in found}


def test_implies_requires_excludes_and_every_pattern_counts():
    db = wf.build_fingerprint_db({
        "Lib": {"cats": [59], "scriptSrc": ["/lib\\.js", "lib-([\\d.]+)\\.js\\;version:\\1"], "implies": ["Base\\;confidence:50"]},
        "Base": {"cats": [22]},
        "Needs": {"cats": [1], "scriptSrc": ["needs"], "requires": ["Missing"]},
        "Old": {"cats": [1], "scriptSrc": ["old"]},
        "New": {"cats": [1], "scriptSrc": ["new"], "excludes": ["Old"]},
    }, {"59": {"name": "JavaScript libraries", "priority": 9}, "22": {"name": "Web servers", "priority": 8}, "1": {"name": "CMS", "priority": 1}})
    facts = {"script_src": ["/static/lib.js", "/cdn/lib-2.1.0.js", "/needs.js", "/old.js", "/new.js"]}
    found = {d["name"]: d for d in wf.match_technologies(db, facts)["detections"]}
    assert found["Lib"]["version"] == "2.1.0" and found["Base"]["implied_by"] == ["Lib"] and found["Base"]["confidence"] == 50
    assert "Needs" not in found and "Old" not in found and "New" in found


def test_archive_headers_keep_only_the_original_site_headers():
    out = wf.archive_original_headers([["Server", "Apache"], ["Via", "1.1 Caddy"], ["x-archive-orig-server", "nginx/1.0"]])
    assert out["headers"] == {"server": ["nginx/1.0"]} and out["dropped"] == 2


def test_collapse_cves_caps_and_kev():
    rows = [{"id": "CVE-2020-11022", "cvss": 6.1}, {"id": "CVE-2020-11023", "cvss": 6.9}, {"id": "CVE-2019-11358", "cvss": 6.1},
            {"id": "CVE-2015-9251", "cvss": 6.1}]
    f = wf.collapse_cves("jQuery", "1.12.4", rows)
    assert f["title"] == "jQuery 1.12.4: 4 CVEs, max CVSS 6.9" and f["severity"] == "medium" and f["confidence"] == 0.5
    crit = wf.collapse_cves("X", "1", [{"id": "CVE-2021-44228", "cvss": 10.0}])
    assert crit["severity"] == "medium"  # capped without KEV
    kev = wf.collapse_cves("X", "1", [{"id": "CVE-2021-44228", "cvss": 10.0, "kev": True}])
    assert kev["severity"] == "high" and kev["labels"] == ["kev"]
    assert wf.collapse_cves("X", "1", [{"id": "CVE-2021-44228"}], hostile=True)["kind"] == "attribute"
    assert wf.collapse_cves("X", "1", [{"id": "not-a-cve"}]) is None


def test_wafw00f_subset_has_no_attack_probe_rules():
    waf = json.loads((Path(wf.__file__).resolve().parents[2] / "data" / "web_fingerprint" / "wafw00f_passive.json").read_text(encoding="utf-8"))
    stack = [r for s in waf["signatures"] for r in s["rules"]]
    kinds = set()
    while stack:
        node = stack.pop()
        if "kind" in node:
            kinds.add(node["kind"])
        stack.extend(node.get("all", []) + node.get("any", []))
    assert kinds <= {"header", "cookie"}
    hits = wf.waf_passive_detect(waf, {"Server": "AkamaiGHost"})
    assert hits and hits[0]["kind"] == "waf"
    envoy = wf.waf_passive_detect(waf, {"server": "envoy"})
    assert envoy and envoy[0]["kind"] == "cdn_or_proxy"


def test_parsers_never_raise_on_garbage():
    for junk in (None, b"\x00\xff" * 50, "<<<", 42, [], {"a": 1}, "‮"):
        wf.extract_page_facts(junk)
        wf.classify_response(junk, junk, junk if isinstance(junk, (str, bytes)) else None)
        wf.waf_passive_detect(junk, junk)
        wf.match_own_rules(junk, {})
        wf.normalise_headers(junk)
        wf.build_fingerprint_db(junk, junk)


# ------------------------------------------------------------------ FC2: the shared safe fetch (review p9-G03-2)
def test_a_redirect_cached_by_another_light_module_is_followed_never_read_as_the_homepage():
    """Sibling LIGHT modules (favicon_fetch, js_endpoints_live...) cache the homepage hop by hop through
    light_fetch.fetch_homepage; web_fingerprint shares those rows: the cached 301 is followed to the page
    (cache hits only), never fingerprinted as an empty homepage."""
    from v3lum.modules.url_web.light_fetch import fetch_homepage

    http = FakeHttp()
    target(http, "example.com")
    target(http, "www.example.com")
    http.add("GET", "https://example.com/", status=301, headers={"Location": "https://www.example.com/", "Server": "nginx"}, text="")
    http.add("GET", "https://www.example.com/", text="<html><head><title>Shop</title><script src='/js/jquery-3.7.1.min.js'></script></head></html>")
    rt = make_runtime(http, settings=NO_DNS, cache=True)
    entity = Entity.make(T.DOMAIN, "example.com")
    sibling = fetch_homepage(make_ctx(WebFingerprint, http, runtime=rt, entity=entity, options=LIGHT), entity)
    assert sibling.status == 200 and sibling.history == ["https://example.com/"]
    sent = len(target_calls(http))
    res = run_module(WebFingerprint, entity, http, options=LIGHT, runtime=rt)
    assert res.status is Status.OK, res.error
    assert res.attributes["title"] == "Shop" and res.attributes["redirect_chain"] == ["https://example.com/", "https://www.example.com/"]
    assert {t["name"] for t in res.attributes["technologies"]} >= {"jQuery"}
    assert len(target_calls(http)) == sent  # both hops served from the shared cache rows
    assert res.raw["from_cache"] is True


def test_a_redirect_off_the_seed_is_not_followed_and_is_reported():
    http = FakeHttp()
    target(http, "www.example.com")
    http.add("GET", "https://www.example.com/", status=302, headers={"Location": "https://landing.example.org/promo"}, text="")
    http.add("GET", "https://landing.example.org/promo", text="<html><title>elsewhere</title></html>")
    res = run(http, "domain:www.example.com")
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert "https://landing.example.org/promo" not in [c["url"] for c in target_calls(http)]
    assert res.attributes["redirect_chain"] == ["https://www.example.com/", "https://landing.example.org/promo"]
    hop = [(p.entity.value, p.relation, p.expand) for p in res.pivots if p.entity.type is T.DOMAIN]
    assert hop == [("landing.example.org", "redirects_to", False)]
    assert "technologies" not in res.attributes


def test_a_timeout_on_https_is_never_retried_over_http():
    from v3lum.core.http import NetworkError

    http = FakeHttp()
    target(http, "slow.example.org")
    http.add("GET", "https://slow.example.org/", error=NetworkError("read timed out", kind="ReadTimeout", reason_code="timeout"))
    res = run(http, "domain:slow.example.org")
    assert res.status is Status.ERROR
    assert "http://slow.example.org/" not in [c["url"] for c in target_calls(http)]


def test_login_wall_on_the_homepage_is_blocked_not_fingerprinted():
    http = FakeHttp()
    target(http, "intranet.example.org")
    page = "<html><head><title>Sign in</title></head><body><form><input type='password' name='p'></form>Log in</body></html>"
    http.add("GET", "https://intranet.example.org/", status=401, text=page)
    res = run(http, "domain:intranet.example.org")
    assert res.status is Status.BLOCKED and res.reason_code in ("login_wall", "challenge")
    assert "technologies" not in res.attributes
    assert len(target_calls(http)) == 1


def test_the_time_budget_screen_runs_once_per_dataset_version(monkeypatch):
    """FC5 screen verdicts (pattern-id hashes only) are kept in ctx.state per dataset version: a new
    process compiles the patterns without re-timing them (the screen costs seconds of CPU)."""
    from v3lum.modules.url_web.web_fingerprint import WebFingerprintArchive

    ctx = make_ctx(WebFingerprintArchive, FakeHttp(), entity=Entity.make(T.DOMAIN, "example.com"))
    wf._DB_MEMO.clear()
    first = wf.load_fingerprint_db(ctx)
    saved = ctx.state.get("slow_patterns")
    assert saved["db"] == first["key"] and saved["screened"] is True
    wf._DB_MEMO.clear()  # a new process

    def no_screen(*_a, **_k):
        raise AssertionError("the screen ran again for an already screened dataset version")

    monkeypatch.setattr(wf, "budget_screen", no_screen)
    again = wf.load_fingerprint_db(ctx)
    assert again["stats"] == first["stats"]
    wf._DB_MEMO.clear()


def test_a_refused_redirect_target_is_recorded_without_query_or_token_path():
    http = FakeHttp()
    target(http, "www.example.com")
    lure = "https://www.example.com/r/AbCdEf0123456789AbCdEf/fulana@example.org?sid=s3cr3tvalue123456"
    http.add("GET", "https://www.example.com/", status=302, headers={"Location": lure}, text="")
    res = run(http, "domain:www.example.com")
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    text = json.dumps({"a": res.attributes, "raw": res.raw, "e": res.error})
    assert "fulana" not in text and "s3cr3tvalue" not in text and "AbCdEf0123456789" not in text
    assert lure not in [c["url"] for c in target_calls(http)]


def test_a_same_site_redirect_hop_resolving_to_a_private_address_is_refused_by_the_core():
    """FC2: a hop the helper lets through (same site, inside the seed) is still checked after resolution:
    private, loopback, link-local, CGNAT and metadata addresses are refused, nothing is sent there."""
    for bad in ("10.0.0.9", "127.0.0.1", "169.254.169.254", "100.64.0.7"):
        http = FakeHttp()
        target(http, "example.com")
        target(http, "inner.example.com", ip=bad)
        http.add("GET", "https://example.com/", redirect_to="https://inner.example.com/")
        http.add("GET", "https://inner.example.com/", text="internal")
        res = run(http, "domain:example.com")
        assert res.status is Status.SKIPPED and res.reason_code == "policy", (bad, res.status, res.error)
        assert "https://inner.example.com/" not in [c["url"] for c in target_calls(http)], bad
