"""Offline tests of ip_anonymizer_consensus (P046) with the recorded answers in tests/fixtures/ip_anonymizer_consensus/."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.ip_network import ip_anonymizer_consensus as mod
from v3lum.modules.ip_network.ip_anonymizer_consensus import (
    ASK_ORDER,
    INCONCLUSIVE,
    IpAnonymizerConsensus,
    answer,
    dedupe_families,
    format_value_votes,
    parse_iplocate,
    parse_ipquery,
    parse_proxycheck,
    parse_vpndetection,
    vote_should_stop,
    vote_tally,
)

FIX = "ip_anonymizer_consensus"
URLS = {
    "ipquery": "https://api.ipquery.io/{ip}?format=json",
    "iplocate": "https://iplocate.io/api/lookup/{ip}",
    "vpndetection": "https://api.vpndetection.io/{ip}",
    "proxycheck": "https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1",
}


def fx(name: str):
    return module_fixture(FIX, name)


@pytest.fixture
def silent_offline(monkeypatch):
    """The recorded answers are for 8.8.8.8 and 2606:4700:4700::1111, which the offline lists answer
    (public resolvers, CDN): silence them to exercise the online vote with real bodies."""
    monkeypatch.setattr(mod, "offline_answer", lambda entity: "")


def route(http: FakeHttp, provider: str, ip: str, **kw) -> None:
    http.add("GET", URLS[provider].format(ip=ip), **kw)


# --------------------------------------------------------------------------------------
# parsers and the shared vote helper
# --------------------------------------------------------------------------------------


def test_parsers_read_the_recorded_answers():
    q = parse_ipquery(fx("ipquery_ok.json"))
    assert q["answered"] and q["votes"] == {"vpn": False, "proxy": False, "hosting": True} and q["asn"] == "AS15169"
    loc = parse_iplocate(fx("iplocate_tor_vpn.json"))
    assert loc["votes"] == {"vpn": True, "proxy": False, "hosting": True} and loc["tor"] is False
    vd = parse_vpndetection(fx("vpndetection_tor.json"))
    assert vd["votes"] == {"vpn": False, "proxy": None, "hosting": True} and vd["tor"] is True  # no proxy flag (free tier)
    pc = parse_proxycheck(fx("proxycheck_ok.json"), "8.8.8.8")
    assert pc["votes"] == {"vpn": False, "proxy": False, "hosting": False} and pc["type"] == "Business"
    v6 = parse_proxycheck(fx("proxycheck_ipv6_ok.json"), "2606:4700:4700:0:0:0:0:1111")  # matched by normalised IP
    assert v6["answered"] and v6["asn"] == "AS13335"
    assert parse_iplocate(fx("iplocate_ipv6_expanded.json"))["votes"]["hosting"] is True
    assert not parse_proxycheck(fx("proxycheck_ok.json"), "8.8.4.4")["answered"]  # no record for another IP
    for bad in (fx("vpndetection_error_400.json"), ["not", "an", "object"], None):
        assert not parse_vpndetection(bad)["answered"]
    assert not parse_ipquery(fx("ipquery_error_404.json"))["answered"]


def test_a_verdict_needs_three_agreeing_independent_answers():
    two = [answer("ipquery", "IPQuery", {"vpn": True, "proxy": False, "hosting": True}),
           answer("iplocate", "IPLocate", {"vpn": True, "proxy": False, "hosting": True})]
    tally = vote_tally(two)
    assert tally["inconclusive"] and tally["tags"] == []
    assert tally["line"] == f"{INCONCLUSIVE}: 2 of 2 providers answered"
    assert "not a vpn" not in tally["line"].lower() and "clean" not in tally["line"].lower()
    three = [*two, answer("proxycheck", "proxycheck.io", {"vpn": True, "proxy": False, "hosting": False})]
    tally = vote_tally(three)
    assert tally["tags"] == ["vpn"] and tally["categories"]["vpn"]["verdict"] is True
    assert tally["line"].startswith("VPN: 3 of 3 providers (IPQuery, IPLocate, proxycheck.io)")
    assert "hosting: 2/3" in tally["line"] and tally["malicious"] is False


def test_vpndetection_and_internetdata_count_once():
    answers = [answer("vpndetection", "VPNDetection", {"vpn": True, "hosting": True}),
               answer("internetdata", "InternetData", {"hosting": True}),
               answer("ipquery", "IPQuery", {"vpn": True, "hosting": True})]
    kept, dropped = dedupe_families(answers)
    assert [a["name"] for a in kept] == ["VPNDetection", "IPQuery"] and dropped == ["InternetData"]
    assert vote_tally(answers)["inconclusive"]  # 2 independent answers, not 3


def test_asking_stops_once_three_agree_or_three_agreeing_become_impossible():
    agree = [answer(p, p, {"vpn": False, "proxy": False, "hosting": True}) for p in ("ipquery", "iplocate", "proxycheck")]
    assert vote_should_stop(agree, remaining=1)
    assert not vote_should_stop(agree[:2], remaining=1)
    split = [answer("ipquery", "IPQuery", {"vpn": True}), answer("iplocate", "IPLocate", {"vpn": False})]
    assert vote_should_stop(split, remaining=0)
    assert not vote_should_stop(split, remaining=2)


def test_categorical_votes_for_ip_geolocation():
    answers = [answer(p, p, {"country": "BR"}) for p in ("a", "b", "c")]
    tally = vote_tally(answers, categories=("country",), labels={"country": "country"})
    assert format_value_votes(tally, "country") == "BR - 3/3 providers"
    assert format_value_votes(vote_tally(answers[:2], categories=("country",)), "country") is None


# --------------------------------------------------------------------------------------
# module runs
# --------------------------------------------------------------------------------------


def test_recorded_8888_votes_hosting_3_of_4_and_asks_one_at_a_time(silent_offline):
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", json=fx("ipquery_ok.json"))
    route(http, "iplocate", "8.8.8.8", json=fx("iplocate_ok.json"), headers=fx("iplocate_ratelimit_headers.json"))
    route(http, "vpndetection", "8.8.8.8", json=fx("vpndetection_ok.json"))
    route(http, "proxycheck", "8.8.8.8", json=fx("proxycheck_ok.json"))
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    votes = res.attributes["anonymizer_votes"]
    assert votes["line"] == "VPN: 0/4; proxy: 0/3; hosting: 3 of 4 providers (IPQuery, IPLocate, VPNDetection)"
    assert res.attributes["is_hosting"] is True and "is_vpn" not in res.attributes
    [finding] = res.findings
    assert finding.severity is Severity.INFO and finding.description == votes["line"]
    assert "hosting" in finding.tags and "malicious" not in finding.tags and "context_only" in finding.tags
    assert [u.split("/")[2] for u in http.urls()] == ["api.ipquery.io", "iplocate.io", "api.vpndetection.io", "proxycheck.io"]
    assert set(res.source_statuses) == {"ipquery.api", "iplocate.api", "vpndetection.api", "proxycheck.api"}
    http.assert_hosts_within(IpAnonymizerConsensus)


def test_failed_providers_are_could_not_verify_and_two_answers_are_inconclusive(silent_offline):
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", json=fx("ipquery_ok.json"))
    route(http, "iplocate", "8.8.8.8", status=429, text="slow down")
    route(http, "vpndetection", "8.8.8.8", json=fx("vpndetection_ok.json"))
    route(http, "proxycheck", "8.8.8.8", json=fx("proxycheck_error_in_200.json"))  # error inside an HTTP 200 body
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK  # c6: fewer answers still give the votes, status ok
    votes = res.attributes["anonymizer_votes"]
    assert votes["inconclusive"] and votes["line"].startswith(f"{INCONCLUSIVE}: 2 of 4 providers answered; could not verify: IPLocate")
    assert "proxycheck.io" in votes["line"]
    assert res.source_statuses["iplocate.api"]["status"] == "rate_limited"
    assert res.source_statuses["proxycheck.api"]["status"] == "error"
    assert "is_hosting" not in res.attributes and res.findings[0].tags == ["context_only"]


def test_asking_stops_when_three_agreeing_answers_became_impossible(silent_offline):
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", status=404, json=fx("ipquery_error_404.json"))
    route(http, "iplocate", "8.8.8.8", status=400, json=fx("iplocate_error_400.json"))
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)  # VPNDetection/proxycheck have no route: never asked
    assert res.status is Status.ERROR and "no provider answered" in res.error
    assert len(http.calls) == 2


def test_proxycheck_denied_quota_marker_and_challenge_pages(silent_offline):
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", json=fx("ipquery_ok.json"))
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    route(http, "iplocate", "8.8.8.8", status=403, text=page)
    route(http, "vpndetection", "8.8.8.8", json=fx("vpndetection_ok.json"))
    route(http, "proxycheck", "8.8.8.8", json=fx("proxycheck_denied_quota_synthetic.json"))
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)
    assert res.source_statuses["iplocate.api"]["status"] == "blocked"
    assert (res.source_statuses["proxycheck.api"]["status"], res.source_statuses["proxycheck.api"]["reason_code"]) == ("quota", "quota")
    assert res.attributes["anonymizer_votes"]["inconclusive"]


def test_malformed_json_is_an_error_never_a_vote(silent_offline):
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", body=b"{not json", headers={"content-type": "application/json"})
    route(http, "iplocate", "8.8.8.8", json=["unexpected"])
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR
    assert {row["status"] for row in res.source_statuses.values()} == {"error"}


def test_ipv6_answers_are_matched_by_normalised_address(silent_offline):
    http = FakeHttp()
    ip = "2606:4700:4700::1111"
    route(http, "ipquery", ip, json=fx("ipquery_ipv6_ok.json"))
    route(http, "iplocate", ip, json=fx("iplocate_ipv6_expanded.json"))
    route(http, "vpndetection", ip, json=fx("vpndetection_ipv6_ok.json"))
    route(http, "proxycheck", ip, json=fx("proxycheck_ipv6_ok.json"))
    res = run_module(IpAnonymizerConsensus, f"ipv6:{ip}", http)
    votes = res.attributes["anonymizer_votes"]
    assert votes["answered"] == 4 and votes["categories"]["hosting"]["verdict"] is True


def test_optional_keys_are_sent_and_never_kept(silent_offline):
    key = "loc0123456789abcdef"
    http = FakeHttp()
    route(http, "ipquery", "8.8.8.8", json=fx("ipquery_ok.json"))
    http.add("GET", f"https://iplocate.io/api/lookup/8.8.8.8?apikey={key}", json=fx("iplocate_ok.json"))
    route(http, "vpndetection", "8.8.8.8", json=fx("vpndetection_ok.json"))
    route(http, "proxycheck", "8.8.8.8", json=fx("proxycheck_ok.json"))
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http, keys={"iplocate": key})
    assert res.status is Status.OK
    assert_no_secret(key, res.to_dict(), res.raw, [f.to_dict() for f in res.findings])


def test_offline_lists_answer_first_and_nothing_is_sent():
    http = FakeHttp()
    res = run_module(IpAnonymizerConsensus, "ipv4:8.8.8.8", http)  # a public resolver: shared infrastructure (noise lists)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "offline answer" in res.error
    assert http.calls == []


def test_current_tor_exit_is_answered_by_the_local_exit_list():
    from v3lum import paths
    from v3lum.modules.ip_network.tor_exit_local import BULK_EXIT_LIST

    target = paths.datasets_dir() / BULK_EXIT_LIST
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("185.220.101.1\n192.0.2.1\n", encoding="utf-8")
    http = FakeHttp()
    res = run_module(IpAnonymizerConsensus, "ipv4:185.220.101.1", http)
    assert res.status is Status.SKIPPED and "Tor exit" in res.error and http.calls == []


def test_seeds_only_and_never_bogons():
    http = FakeHttp()
    assert run_module(IpAnonymizerConsensus, "ipv4:185.220.101.1", http, is_seed=False).reason_code == "policy"
    assert run_module(IpAnonymizerConsensus, "ipv4:185.220.101.1", http, depth=1).reason_code == "policy"
    assert run_module(IpAnonymizerConsensus, "ipv4:10.1.2.3", http).reason_code == "not_applicable"
    assert run_module(IpAnonymizerConsensus, "ipv4:198.51.100.7", http).reason_code == "not_applicable"
    assert http.calls == []


def test_org_network_addresses_get_offline_answers_only():
    http = FakeHttp()
    res = run_module(IpAnonymizerConsensus, "ipv4:23.132.164.50", http, org_profile=OrgProfile.from_dict({"cidrs": ["23.132.164.0/24"]}))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_licence_blocked_providers_are_never_asked():
    http = FakeHttp()
    res = run_module(IpAnonymizerConsensus, "ipv4:23.132.164.50", http, allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []


def test_metadata_follows_the_council_decision():
    cls = IpAnonymizerConsensus
    assert cls.default_enabled is False and cls.terms == "unknown" and cls.trust_tier == "unknown"
    assert cls.run_on == "seeds" and cls.min_interval == 1.0 and cls.cache_ttl == 86400
    assert len(ASK_ORDER) <= 4 and cls.max_requests == len(ASK_ORDER)
    assert not any("iplogs" in h for h in cls.hosts)  # c2
    assert set(cls.optional_keys) == {"iplocate", "proxycheck"}
