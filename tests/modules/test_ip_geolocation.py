"""Offline tests of ip_geolocation (P051) with the recorded answers in tests/fixtures/ip_geolocation/."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.ip_network import ip_geolocation as mod
from v3lum.modules.ip_network.ip_geolocation import (
    NOT_WIRED,
    PENDING,
    IpGeolocation,
    bogon_reason,
    geo_answer,
    geo_vote,
    json_ok,
    parse_freeipapi,
    parse_geojs,
    parse_ip2location,
    parse_ipguide,
    parse_ipwhois,
)

FIX = "ip_geolocation"
IPWHOIS = "https://ipwho.is/{ip}"
FREEIPAPI = "https://free.freeipapi.com/api/v1/json/{ip}"
CHALLENGE = "tests/fixtures/ip_geolocation/challenge_page_synthetic.html"


def fx(name: str):
    return module_fixture(FIX, name)


def routes(ip: str, ipwhois: dict | None = None, freeipapi: dict | None = None) -> FakeHttp:
    http = FakeHttp()
    http.add("GET", IPWHOIS.format(ip=ip), **(ipwhois or {}))
    http.add("GET", FREEIPAPI.format(ip=ip), **(freeipapi or {}))
    return http


# --------------------------------------------------------------------------------------
# metadata (council decisions)
# --------------------------------------------------------------------------------------


def test_metadata_follows_the_council_decision():
    cls = IpGeolocation
    assert (cls.terms, cls.disclosure, cls.default_enabled, cls.run_on) == ("open", "third_party", False, "seeds")
    assert cls.trust_tier == "community" and cls.max_requests == 2  # FC1: at most 2 providers per IP
    assert (cls.min_interval, cls.cache_ttl) == (1.0, 86400)  # FC7
    assert set(cls.hosts) == {"ipwho.is", "free.freeipapi.com"}  # FC3: only the two wired providers
    for pending in PENDING.values():  # FC4: ip.guide / IP2Location / GeoJS not wired until legal records them
        assert pending["host"] not in cls.hosts
    assert "keycdn" in NOT_WIRED and "tools.keycdn.com" not in cls.hosts  # FC4: KeyCDN never wired
    assert not any(s.startswith(("ipguide", "ip2location", "geojs", "keycdn")) for s in cls.sources)


# --------------------------------------------------------------------------------------
# the vote (FC5/FC6)
# --------------------------------------------------------------------------------------


def test_two_providers_agree_on_country_and_asn_and_city_disagreement_is_shown():
    http = routes("1.1.1.1", {"json": fx("ipwhois_ok_1111.json")}, {"json": fx("freeipapi_ok_1111.json")})
    res = run_module(IpGeolocation, "ipv4:1.1.1.1", http)
    assert res.status is Status.OK
    geo = res.attributes["geo_votes"]
    assert geo["country"] == "AU" and geo["country_votes"] == "AU - 2/2 providers"
    assert geo["asn_votes"] == "AS13335 Cloudflare, Inc. - 2/2 providers"
    assert geo["city"] == "Brisbane - approximate (ipwho.is), disagreement: Sydney (FreeIPAPI)"
    assert geo["approximate"] is True
    assert "country: AU - 2/2 providers (approximate)" in geo["line"]
    assert res.attributes["asn"] == "AS13335" and res.attributes["as_org"] == "Cloudflare, Inc."
    # FC6: context only - no plain country/city/coordinates attributes, no located_at pivot
    assert not {"country", "city", "coordinates", "latitude", "longitude"} & set(res.attributes)
    pivots = {(p.entity.type.value, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {("asn", "AS13335"), ("domain", "cloudflare.com")}
    assert all(p.expand is False for p in res.pivots)
    assert pivots[("asn", "AS13335")].relation == "belongs_to_asn"
    assert pivots[("domain", "cloudflare.com")].relation == "operator_domain"
    assert not any(p.relation == "located_at" for p in res.pivots)
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags
    assert {s: v["status"] for s, v in res.source_statuses.items()} == {"ipwhois.geo": "ok", "freeipapi.geo": "ok"}
    assert "latitude" not in str(res.raw) and "postal" not in str(res.raw)
    http.assert_hosts_within(IpGeolocation)
    assert len(http.calls) == 2


def test_google_dns_and_ipv6_answers():
    res = run_module(IpGeolocation, "ipv4:8.8.8.8",
                     routes("8.8.8.8", {"json": fx("ipwhois_ok_8888.json")}, {"json": fx("freeipapi_ok_8888.json")}))
    assert res.attributes["geo_votes"]["country_votes"] == "US - 2/2 providers"
    assert res.attributes["asn"] == "AS15169"
    v6 = "2606:4700:4700::1111"
    res6 = run_module(IpGeolocation, f"ipv6:{v6}", routes(v6, {"json": fx("ipwhois_ok_ipv6.json")}, {"json": fx("freeipapi_ok_ipv6.json")}))
    assert res6.status is Status.OK and res6.attributes["asn"] == "AS13335"


def test_a_split_is_disputed_never_a_verdict():
    other = dict(fx("freeipapi_ok_1111.json"), countryCode="NZ", asn="64496")  # reserved ASN does not vote
    res = run_module(IpGeolocation, "ipv4:1.1.1.1", routes("1.1.1.1", {"json": fx("ipwhois_ok_1111.json")}, {"json": other}))
    geo = res.attributes["geo_votes"]
    assert geo["country"] is None and geo["country_votes"] == "disputed: AU (ipwho.is), NZ (FreeIPAPI)"
    assert geo["asn_votes"] == "AS13335 Cloudflare, Inc. - 1/1 providers"
    asn_pivot = next(p for p in res.pivots if p.entity.type.value == "asn")
    assert asn_pivot.confidence == 0.6  # one provider only


def test_the_vote_goes_through_the_shared_p046_helper(monkeypatch):
    seen = []
    real = mod.vote_tally

    def spy(answers, categories, need, labels):
        seen.append((categories, need))
        return real(answers, categories=categories, need=need, labels=labels)

    monkeypatch.setattr(mod, "vote_tally", spy)
    a = geo_answer(parse_ipwhois(fx("ipwhois_ok_1111.json")), "ipwho.is")
    b = geo_answer(parse_freeipapi(fx("freeipapi_ok_1111.json")), "FreeIPAPI")
    vote = geo_vote([a, b])
    assert seen == [(("country",), 2), (("asn",), 2)]  # strict majority of the 2 voters per category
    assert vote["country_votes"] == "AU - 2/2 providers"


# --------------------------------------------------------------------------------------
# rule 5: errors inside HTTP 200 bodies, limits, challenges - never 'no data'
# --------------------------------------------------------------------------------------


def test_success_false_in_a_200_body_is_an_error_of_that_provider():
    http = routes("9.9.9.9", {"json": fx("ipwhois_reserved_error_in_200.json")}, {"json": fx("freeipapi_ok_1111.json")})
    res = run_module(IpGeolocation, "ipv4:9.9.9.9", http)
    assert res.status is Status.OK  # FreeIPAPI answered
    status = res.source_statuses["ipwhois.geo"]
    assert status["status"] == "error" and "Reserved range" in status["reason"]
    assert "could not verify: ipwho.is (Reserved range)" in res.attributes["geo_votes"]["line"]
    assert not any(p.relation == "operator_domain" for p in res.pivots)


def test_both_providers_failing_is_could_not_verify_never_empty():
    http = routes("9.9.9.9", {"json": fx("ipwhois_invalid_ip_error_in_200_documented.json")}, {"json": fx("freeipapi_all_null.json")})
    res = run_module(IpGeolocation, "ipv4:9.9.9.9", http)
    assert res.status is Status.ERROR and "all-null body" in res.error
    assert not res.findings and "geo_votes" not in res.attributes


def test_daily_limit_is_quota_and_a_429_is_rate_limited():
    limit = fx("ipwhois_rate_limited_429_documented.json")
    http = routes("9.9.9.9", {"status": limit["_status"], "json": limit["body"], "headers": {"retry-after": "86400"}},
                  {"status": 429, "text": "Too Many Requests"})
    res = run_module(IpGeolocation, "ipv4:9.9.9.9", http)
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    assert res.source_statuses["freeipapi.geo"]["status"] == "rate_limited"


def test_challenge_pages_are_blocked_and_5xx_or_malformed_bodies_are_errors():
    with open(CHALLENGE, encoding="utf-8") as fh:
        page = fh.read()
    blocked = run_module(IpGeolocation, "ipv4:9.9.9.9", routes("9.9.9.9", {"status": 403, "text": page}, {"status": 403, "text": page}))
    assert blocked.status is Status.BLOCKED
    with open("tests/fixtures/ip_geolocation/ipwhois_malformed_truncated.txt", encoding="utf-8") as fh:
        truncated = fh.read()
    broken = run_module(IpGeolocation, "ipv4:9.9.9.9",
                        routes("9.9.9.9", {"text": truncated, "headers": {"content-type": "application/json"}}, {"status": 503, "text": "down"}))
    assert broken.status is Status.ERROR
    odd = run_module(IpGeolocation, "ipv4:9.9.9.9", routes("9.9.9.9", {"json": ["not", "an", "object"]}, {"json": "text"}))
    assert odd.status is Status.ERROR


# --------------------------------------------------------------------------------------
# FC1/FC2: seeds only, bogons and personal IPs never leave the machine
# --------------------------------------------------------------------------------------


def test_bogons_are_filtered_before_any_call():
    for ip in ("192.0.2.1", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1", "::ffff:10.0.0.1", "fd00::1"):
        assert bogon_reason(ip), ip
        etype = "ipv6" if ":" in ip else "ipv4"
        http = FakeHttp()
        res = run_module(IpGeolocation, f"{etype}:{ip}", http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable", ip
        assert http.calls == []
    assert bogon_reason("1.1.1.1") is None


def test_pivots_extracted_and_unconfirmed_ips_are_never_sent():
    http = FakeHttp()
    res = run_module(IpGeolocation, "ipv4:1.1.1.1", http, is_seed=False, depth=1, provenance=(("domain:example.com", "resolves_to", "dns_records"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run_module(IpGeolocation, "ipv4:1.1.1.1", http, options=ScanOptions(unconfirmed_seeds={"ipv4:1.1.1.1"}))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    assert http.calls == []


def test_own_network_addresses_get_offline_data_only():
    http = FakeHttp()
    res = run_module(IpGeolocation, "ipv4:1.1.1.1", http, org_profile=OrgProfile.from_dict({"cidrs": ["1.1.1.0/24"]}))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "own network" in res.error
    assert http.calls == []


# --------------------------------------------------------------------------------------
# FC4: pending providers - parsers ready, nothing wired
# --------------------------------------------------------------------------------------


def test_pending_parsers_read_the_recorded_answers_without_any_request():
    text_plain = fx("ipguide_ok_text_plain_1111.json")
    import json

    rec = parse_ipguide(json.dumps(text_plain["body"]))  # JSON served as text/plain: parsed regardless of the header
    assert (rec["asn"], rec["network"], rec["as_country"], rec["country"]) == (13335, "1.1.1.0/24", "US", None)
    assert parse_ipguide(fx("ipguide_ok.json"))["asn"]
    assert parse_ipguide("<html>not json</html>") is None
    i2l = parse_ip2location(fx("ip2location_ok.json"))
    assert i2l["country"] and i2l["asn"]
    assert parse_ip2location({"error": {"error_code": 10001, "error_message": "Invalid IP address."}}) is None
    nil = parse_geojs(fx("geojs_ok_nil_1111.json"))
    assert nil["country"] is None  # GeoJS gave no country for the anycast resolver
    assert parse_geojs(fx("geojs_ok.json"))["asn"]
    keycdn = fx("keycdn_ua_refused_403.json")
    assert keycdn["_status"] == 403 and "User-Agent" in keycdn["body"]["description"]


def test_error_bodies_are_never_cached():
    class Resp:
        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    ok_ipwhois = json_ok(mod._OK["ipwhois"])
    assert ok_ipwhois(Resp(fx("ipwhois_ok_1111.json"))) is True
    assert ok_ipwhois(Resp(fx("ipwhois_reserved_error_in_200.json"))) is False
    ok_free = json_ok(mod._OK["freeipapi"])
    assert ok_free(Resp(fx("freeipapi_all_null.json"))) is False
    assert ok_free(Resp(fx("freeipapi_ok_1111.json"))) is True
