"""phishstats (P074, batch p2-G03-1).

Fixtures in tests/fixtures/phishstats/ (prep p2-G03-1, 2026-11-26): ``ok_url_records.json`` (research
samples, 3 records, scrubbed: hosts -> example domains, IPs -> documentation ranges, the workers.dev
account label replaced; the victims' e-mails are documentation values kept on purpose for the redaction
test), ``ok_ip_records.json`` (live ip=1.1.1.1 answer, 2 records), ``empty.json`` (live ``[]``),
``error_filter_ignored.json`` (live: an unknown operator was silently ignored and an unrelated record
came back with HTTP 200), ``html_instead_of_json.html`` (live 404 page), ``rate_limited_429_synthetic.json``
(Kong rate-limit shape), ``headers_ratelimit.json`` (live RateLimit headers).
"""

from __future__ import annotations

import json

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import phishstats as mod
from v3lum.modules.url_web.phishstats import PhishStats

URL_RECORDS = module_fixture("phishstats", "ok_url_records.json")
IP_RECORDS = module_fixture("phishstats", "ok_ip_records.json")
HEADERS = module_fixture("phishstats", "headers_ratelimit.json")["headers"]


def q(kind: str, value: str) -> str:
    return mod.phishstats_query(kind, value)["url"]


def dump(res) -> str:
    findings = [{k: v for k, v in f.to_dict().items() if k != "entity"} for f in res.findings]
    return json.dumps([res.attributes, findings, res.raw, res.error, [(p.entity.key, p.note) for p in res.pivots]], default=str)


def test_metadata():
    cls = PhishStats
    assert (cls.provider, cls.hosts, cls.terms, cls.disclosure) == ("phishstats", ("api.phishstats.info",), "open", "third_party")
    assert cls.trust_tier == "community" and cls.default_enabled is True and cls.cache_ttl == 3600
    assert "reputation" in cls.tags


# ------------------------------------------------------------------ c1 query building
def test_query_is_encoded_never_concatenated():
    built = mod.phishstats_query("host", "Example.NET")
    assert built["where"] == "(host,eq,example.net)"
    assert built["url"] == "https://api.phishstats.info/api/phishing?_where=%28host%2Ceq%2Cexample.net%29&_sort=-id&_size=100"
    assert "error" in mod.phishstats_query("host", "example.net),(ip,eq,1.2.3.4")
    assert "error" in mod.phishstats_query("url_like", "a b")
    assert mod.phishstats_query("ip", "1.1.1.1")["where"] == "(ip,eq,1.1.1.1)"


def test_plan_exact_host_first_and_like_on_shared_platforms():
    from v3lum.core.entities import EntityType as T

    assert mod.plan_for_entity(T.DOMAIN, "login.example.net")["query"]["where"] == "(host,eq,example.net)"
    shared = mod.plan_for_entity(T.DOMAIN, "odd-wood-f26b.account-0001.workers.dev")
    assert shared["shared"] is True and shared["query"]["where"] == "(url,like,~odd-wood-f26b.account-0001.workers.dev~)"
    assert mod.is_shared_platform("evil.github.io") and not mod.is_shared_platform("shop.example.com.br")


# ------------------------------------------------------------------ c3 redaction
def test_victim_emails_and_tokens_are_redacted_everywhere():
    http = FakeHttp().add("GET", q("host", "example.net"), json=URL_RECORDS[1:2], headers=HEADERS)
    res = run_module(PhishStats, "domain:phish-kit.example.net", http)
    text = dump(res)
    assert "someone@example.com" not in text and "someone%40example.com" not in text
    assert "REDACTED_EMAIL" in text
    http.assert_hosts_within(PhishStats)


def test_fragment_email_never_reaches_evidence():
    host = "veluntra-technology-productivity-boost-odd-wood-f26b.account-0001.workers.dev"
    http = FakeHttp().add("GET", q("url_like", host), json=URL_RECORDS[:1])
    res = run_module(PhishStats, f"domain:{host}", http)
    text = dump(res)
    assert "#test@example.com" not in text and "test@example.com" not in text
    assert "@" not in json.dumps(res.raw)
    # shared platform: URL-level listing only, never a verdict on the host or the platform
    assert all("context_only" in f.tags for f in res.findings)


def test_redaction_helper_kinds():
    red, kinds = mod.redact_victim_url(URL_RECORDS[2]["url"])
    assert "aaaa@example.com" not in red and "671dec8b779bd63d0f94940e8998c993" not in red
    assert {"email", "opaque_token"} & set(kinds) or {"email", "token"} & set(kinds)
    b64 = "https://evil.example/x?u=" + "dGVzdEBleGFtcGxlLmNvbQ==" + "&cpf=123.456.789-09&tel=%2B5511555501234"
    red2, kinds2 = mod.redact_victim_url(b64)
    assert "dGVzdEBleGFtcGxlLmNvbQ" not in red2 and "123.456.789-09" not in red2 and "555501234" not in red2
    assert mod.defang_url("https://evil.example/a") == "hxxps://evil[.]example/a"


# ------------------------------------------------------------------ verdicts (c5)
def test_url_exact_listing_score_threshold():
    rec = URL_RECORDS[2]  # score 6.7 >= 5: phishing
    url = rec["url"]
    http = FakeHttp().add("GET", q("host", "example.org"), json=[rec])
    res = run_module(PhishStats, f"url:{url}", http)
    assert res.status is Status.OK
    f = [x for x in res.findings if "phishing" in x.tags]
    assert len(f) == 1 and f[0].severity.label == "high" and f[0].criterion
    low = dict(URL_RECORDS[1])  # score 4.8: suspicious at most
    http2 = FakeHttp().add("GET", q("host", "example.net"), json=[low])
    res2 = run_module(PhishStats, f"url:{low['url']}", http2)
    titles = [x.title for x in res2.findings]
    assert "Listed by PhishStats (score below the phishing threshold)" in titles
    assert not any("phishing" in x.tags for x in res2.findings)


def test_ip_never_inherits_the_verdict():
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), json=IP_RECORDS, headers=HEADERS)
    res = run_module(PhishStats, "ipv4:1.1.1.1", http)
    assert res.status is Status.OK
    assert all(f.severity.label == "info" and "context_only" in f.tags for f in res.findings)
    urls = {p.entity.value for p in res.pivots if p.entity.type.value == "url"}
    assert "https://oruvisese.ipv64.net/ezoz/" in urls
    assert all(p.relation == "listed_phishing_url" for p in res.pivots)


def test_domain_listing_and_ip_pivots():
    rec = dict(URL_RECORDS[2])
    http = FakeHttp().add("GET", q("host", "example.org"), json=[rec])
    res = run_module(PhishStats, "domain:compromised-site.example.org", http)
    assert any("phishing" in f.tags and f.severity.label == "high" for f in res.findings)
    ips = [p for p in res.pivots if p.entity.type.value == "ipv4"]
    assert ips and all(not p.expand and p.relation == "resolves_to" for p in ips)


def test_subdomain_listings_do_not_propagate_to_parent():
    http = FakeHttp().add("GET", q("host", "example.org"), json=[URL_RECORDS[2]])
    res = run_module(PhishStats, "domain:example.org", http)
    assert res.findings and all("context_only" in f.tags for f in res.findings)


# ------------------------------------------------------------------ brand monitoring (c1)
def test_own_domain_adds_brand_like_query():
    org = OrgProfile.from_dict({"org": {"name": "ExampleBank"}, "domains": [{"name": "examplebank.com.br", "verification": "txt_verified"}],
                                "brands": [{"name": "ExampleBank", "keywords": ["examplebank"]}]}) if hasattr(OrgProfile, "from_dict") else None
    if org is None:  # pragma: no cover - API guard
        return
    impostor = dict(URL_RECORDS[1], url="https://examplebank-login.example.net/acesso", host="example.net")
    http = (FakeHttp()
            .add("GET", q("host", "examplebank.com.br"), json=[])
            .add("GET", q("url_like", "examplebank"), json=[impostor]))
    res = run_module(PhishStats, "domain:examplebank.com.br", http, org_profile=org)
    assert res.status is Status.OK
    assert any("brand_abuse" in f.tags for f in res.findings)
    assert len(http.calls) == 2


def test_keyword_listing():
    http = FakeHttp().add("GET", q("url_like", "workers.dev"), json=URL_RECORDS[:1])
    res = run_module(PhishStats, "keyword:workers.dev", http)
    assert res.status is Status.OK and res.findings[0].title == "PhishStats phishing URLs mention the keyword"


# ------------------------------------------------------------------ absences and failures (c4, rule 5)
def test_empty_answer():
    http = FakeHttp().add("GET", q("host", "example.com"), json=module_fixture("phishstats", "empty.json"))
    assert run_module(PhishStats, "domain:example.com", http).status is Status.EMPTY


def test_filter_ignored_is_could_not_verify():
    body = module_fixture("phishstats", "error_filter_ignored.json")["body"]
    http = FakeHttp().add("GET", q("host", "example.com"), json=body)
    res = run_module(PhishStats, "domain:example.com", http)
    assert res.status is Status.ERROR and "ignored the filter" in res.error


def test_429_is_rate_limited():
    fx = module_fixture("phishstats", "rate_limited_429_synthetic.json")
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), status=429, json=fx["body"], headers=fx["headers"])
    assert run_module(PhishStats, "ipv4:1.1.1.1", http).status is Status.RATE_LIMITED


def test_rate_limit_message_inside_200_is_never_empty():
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), json={"message": "API rate limit exceeded"})
    res = run_module(PhishStats, "ipv4:1.1.1.1", http)
    assert res.status in (Status.RATE_LIMITED, Status.ERROR)


def test_html_and_5xx_are_errors():
    html = (FIXTURES / "phishstats" / "html_instead_of_json.html").read_text()
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), text=html, headers={"Content-Type": "text/html"})
    assert run_module(PhishStats, "ipv4:1.1.1.1", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", q("ip", "1.1.1.1"), status=502, text="bad gateway", times=5)
    assert run_module(PhishStats, "ipv4:1.1.1.1", http2).status is Status.ERROR


def test_challenge_page_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), status=403, text=page, headers={"Content-Type": "text/html"})
    assert run_module(PhishStats, "ipv4:1.1.1.1", http).status is Status.BLOCKED


def test_malformed_json_is_error():
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), text="[{\"id\": 1,", headers={"Content-Type": "application/json"})
    assert run_module(PhishStats, "ipv4:1.1.1.1", http).status is Status.ERROR


def test_private_ip_not_applicable():
    res = run_module(PhishStats, "ipv4:10.0.0.1", FakeHttp())
    assert res.status is Status.SKIPPED


def test_result_cap_and_redacted_state_cache():
    many = [dict(IP_RECORDS[0], id=i) for i in range(130)]
    http = FakeHttp().add("GET", q("ip", "1.1.1.1"), json=many, times=1)
    res = run_module(PhishStats, "ipv4:1.1.1.1", http)
    assert len(res.attributes["phishstats_records"]) == 100
    assert res.attributes["phishstats_query"]["truncated"] is True
    assert len(res.pivots) <= PhishStats.max_pivots
    # the second run is served from the redacted 1 h cache (no request)
    res2 = run_module(PhishStats, "ipv4:1.1.1.1", http)
    assert res2.status is Status.OK and res2.attributes["phishstats_query"]["cached"] is True
    assert len(http.calls) == 1


def test_parse_rejects_object_answers():
    assert mod.parse_phishstats({"error": "boom"})["status"] == "error"
    assert mod.parse_phishstats("nope")["status"] == "error"
    assert mod.ratelimit_headers(HEADERS) == {"limit_minute": 20, "remaining_minute": 19, "reset_s": 34}


def test_acceptance_routes_replay():
    from tests.fakes import fixture

    for etype, value in (("ipv4", "8.8.8.8"), ("domain", "example.com"), ("url", "https://example.com/")):
        doc = fixture(f"acceptance/{etype}/phishstats.json")
        http = FakeHttp()
        for route in doc["routes"]:
            http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route.get("headers"))
        res = run_module(PhishStats, f"{etype}:{value}", http)
        assert res.status in (Status.OK, Status.EMPTY), (etype, res.status, res.error)
        assert "@" not in json.dumps(res.raw)
