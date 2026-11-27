"""hibp_account (P133): HIBP breachedaccount/pasteaccount with the company-paid key.

The keyed endpoints were never called (no key in research): ``needs_key_401.json`` is the recorded 401
('Access denied due to missing hibp-api-key.'); ``breachedaccount_ok.json`` is a SYNTHETIC
breachedaccount answer built from 8 REAL breach objects of the keyless /api/v3/breaches catalogue (same
schema; a credited researcher's name and address replaced); the other envelopes follow the HIBP API
documentation (404, 403, 429, the truncated form, paste metadata).
"""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import run_rules
from v3lum.core.graph import Graph
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations.p2_g04_1 import RULE_BREACH_MERGE
from v3lum.modules.breach_leak.breach_accounts import breach_key
from v3lum.modules.breach_leak.hibp_account import HibpAccount, hibp_min_interval, parse_pastes
from v3lum.modules.breach_leak.leakcheck_public import LeakcheckPublic
from v3lum.modules.breach_leak.xposedornot import XposedOrNot

MOD = HibpAccount
KEY = "hibp-fixture-key-0123456789abcdef"
API = "https://haveibeenpwned.com/api/v3"
OWN = "analyst@acme.com.br"
ORG = {"domains": [{"name": "acme.com.br", "verification": "txt_verified"}, {"name": "seeded-corp.com.br", "verification": "seeded"}]}
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name):
    return module_fixture(HibpAccount, name)


def org():
    return OrgProfile.from_dict(ORG)


def breached(email):
    return f"{API}/breachedaccount/{email.replace('@', '%40')}?truncateResponse=false"


def pastes(email):
    return f"{API}/pasteaccount/{email.replace('@', '%40')}"


def env(http, url, name, **kw):
    data = fx(name)
    body = data.get("body")
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=data["status"], json=body, headers=data.get("headers"), **kw)
    return http.add("GET", url, status=data["status"], text=body or "", headers=data.get("headers"), **kw)


def own_http(email=OWN, *, paste_status=404):
    http = FakeHttp()
    env(http, breached(email), "breachedaccount_ok.json", match_headers={"hibp-api-key": KEY})
    if paste_status == 404:
        http.add("GET", pastes(email), status=404, text="")
    else:
        env(http, pastes(email), "pasteaccount_ok.json")
    return http


def by_name(res):
    return {f.data.get("name"): f for f in res.findings if isinstance(f.data, dict) and f.data.get("name")}


def test_own_address_breaches_one_finding_each_with_next_steps():
    http = own_http()
    res = run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org())
    assert res.status is Status.OK
    found = by_name(res)
    assert {"8tracks", "000webhost", "Adobe", "Zomato", "RiverCityMedia", "AlienStealerLogs"} <= set(found)
    assert "AshleyMadison" not in json.dumps([f.to_dict() for f in res.findings]) and "Zoosk" not in json.dumps(res.attributes)
    masked = [f for f in res.findings if f.data.get("sensitive")]
    assert len(masked) == 2 and all(f.title == "Listed in breach: sensitive breach (name withheld)" for f in masked)
    assert all("Ethnicities" not in f.data["data_classes"] for f in masked)  # special categories dropped
    assert found["AlienStealerLogs"].severity.label == "high"
    eight = found["8tracks"]
    assert eight.severity.label == "medium" and "credential_exposure" in eight.tags  # passwords: old but no rotation known
    assert eight.data["breach_key"] == "8tracks" and eight.data["sources"] == ["hibp.account"]
    assert "password exposed in a 2017 breach: confirm it was changed and not reused" in eight.description
    spam = found["RiverCityMedia"]
    assert spam.severity.label == "info" and "context_only" in spam.tags and spam.data["counted"] is False
    fabricated = [f for f in masked if f.data.get("fabricated")]
    assert fabricated and fabricated[0].severity.label == "info"
    assert res.attributes["first_seen_breach"] == "2013-10-04"
    assert res.attributes["breach_count"] == 6  # spam list and fabricated breach never count
    assert any("Have I Been Pwned" in label for label, _ in res.links)  # CC BY 4.0 attribution
    blob = json.dumps([res.raw, res.attributes, [f.to_dict() for f in res.findings]], default=str)
    for dropped in ("LogoPath", "Description", "researcher@example.org", "a security researcher", KEY):
        assert dropped not in blob
    http.assert_hosts_within(MOD)


def test_404_is_not_found_in_hibp_never_never_breached():
    http = FakeHttp()
    env(http, breached(OWN), "not_found_404.json")
    http.add("GET", pastes(OWN), status=404, text="")
    res = run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org())
    assert res.status is Status.EMPTY
    assert "not found in HIBP" in res.error and "never" not in res.error.lower()
    assert res.attributes["presence"]["state"] == "absent"


def test_recorded_401_is_needs_key_and_a_missing_key_sends_nothing():
    http = FakeHttp()
    env(http, breached(OWN), "needs_key_401.json")
    res = run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org())
    assert res.status is Status.NEEDS_KEY
    http2 = FakeHttp()
    res2 = run_module(MOD, f"email:{OWN}", http2, org_profile=org())
    assert res2.status is Status.NEEDS_KEY and http2.calls == []


def test_rate_limit_and_refusals_are_could_not_verify():
    http = FakeHttp()
    env(http, breached(OWN), "rate_limited_429.json")
    assert run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org()).status is Status.RATE_LIMITED
    http2 = FakeHttp()
    env(http2, breached(OWN), "forbidden_403.json")
    assert run_module(MOD, f"email:{OWN}", http2, keys={"hibp": KEY}, org_profile=org()).status not in (Status.OK, Status.EMPTY)
    http3 = FakeHttp().add("GET", breached(OWN), status=403, text=CHALLENGE)
    assert run_module(MOD, f"email:{OWN}", http3, keys={"hibp": KEY}, org_profile=org()).status is Status.BLOCKED
    http4 = FakeHttp().add("GET", breached(OWN), status=503, text="unavailable", times=3)
    assert run_module(MOD, f"email:{OWN}", http4, keys={"hibp": KEY}, org_profile=org()).status is Status.ERROR


def test_unexpected_body_is_an_error():
    http = FakeHttp().add("GET", breached(OWN), json={"unexpected": True})
    http.add("GET", pastes(OWN), status=404, text="")
    assert run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org()).status is Status.ERROR


def test_third_party_needs_breach_scope_all_and_is_context_at_most_medium():
    other = "jdoe@other-corp.com.br"
    http = FakeHttp()
    res = run_module(MOD, f"email:{other}", http, keys={"hibp": KEY}, org_profile=org())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "not an org domain" in res.error
    seeded = run_module(MOD, "email:analyst@seeded-corp.com.br", http, keys={"hibp": KEY}, org_profile=org())
    assert seeded.status is Status.SKIPPED  # seeded != verified
    pivot = run_module(MOD, f"email:{other}", http, keys={"hibp": KEY}, options=ScanOptions(breach_scope="all", purpose="case 42"),
                       is_seed=False, depth=1)
    assert pivot.status is Status.SKIPPED  # never for pivots
    assert http.calls == []
    http2 = own_http(other)
    res2 = run_module(MOD, f"email:{other}", http2, keys={"hibp": KEY}, options=ScanOptions(breach_scope="all", purpose="case 42"))
    assert res2.status is Status.OK
    assert all(f.severity.label in ("info", "low", "medium") for f in res2.findings)
    assert all("context_only" in f.tags and "third_party" in f.tags for f in res2.findings)
    assert all("credential_exposure" not in f.tags for f in res2.findings)


def test_generic_address_is_one_info_summary_never_scored():
    email = "info@acme.com.br"
    res = run_module(MOD, f"email:{email}", own_http(email), keys={"hibp": KEY}, org_profile=org())
    assert res.attributes["generic_address"] == "role"
    assert [f.title for f in res.findings] == ["Generic or shared identity listed in breaches"]
    assert res.findings[0].severity.label == "info" and "context_only" in res.findings[0].tags


def test_pastes_are_metadata_only_with_a_manual_link():
    res = run_module(MOD, f"email:{OWN}", own_http(paste_status=200), keys={"hibp": KEY}, org_profile=org())
    assert res.attributes["paste_count"] == 2
    assert res.attributes["pastes"][0] == {"source": "Pastebin", "id": "8Q0BvKD8", "date": "2014-03-04", "email_count": 139}
    assert "syslog" not in json.dumps([res.attributes, res.raw, [f.to_dict() for f in res.findings]])  # title dropped
    assert ("https://pastebin.com/8Q0BvKD8" in [u for _, u in res.links])
    assert parse_pastes({"not": "a list"}) is None


def test_truncated_answer_still_lists_names():
    http = FakeHttp()
    env(http, breached(OWN), "truncated_ok.json")
    http.add("GET", pastes(OWN), status=404, text="")
    res = run_module(MOD, f"email:{OWN}", http, keys={"hibp": KEY}, org_profile=org())
    assert set(res.attributes["breaches"]) == {"8tracks", "Adobe"}


def test_licence_skip_reads_licence_and_rpm_setting_drives_min_interval():
    res = run_module(MOD, f"email:{OWN}", FakeHttp(), keys={"hibp": KEY}, org_profile=org(), allowed_sources=["hibp.hibp_account_pastes"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert hibp_min_interval(10) == 6.0 and hibp_min_interval(50) == 1.2 and hibp_min_interval("junk") == 6.0


# ------------------------------------------------------------------ P133 cond 7/10: one breach, three sources
@pytest.fixture
def small_catalogues(monkeypatch):
    from v3lum.core import datasets
    from v3lum.modules.breach_leak import hibp_catalog as hc
    from v3lum.modules.breach_leak import xposedornot as xon

    monkeypatch.setattr(hc, "MIN_BREACHES", 5)
    monkeypatch.setattr(xon, "MIN_CATALOGUE", 5)
    monkeypatch.setitem(datasets.DATASETS[hc.CATALOG_DATASET], "min_bytes", 1)
    monkeypatch.setitem(datasets.DATASETS[xon.CATALOGUE_DATASET], "min_bytes", 1)


def test_same_breach_from_three_sources_gives_one_finding_with_three_sources(small_catalogues):
    options = {"org_profile": org()}
    hibp = run_module(MOD, f"email:{OWN}", own_http(), keys={"hibp": KEY}, **options)
    hibp_catalogue = module_fixture("leakcheck_public", "hibp_catalogue_subset.json")["body"]
    lc_http = FakeHttp().add("GET", "https://haveibeenpwned.com/api/v3/breaches", json=hibp_catalogue)
    lc_http.add("GET", "https://leakcheck.io/api/public?check=analyst%40acme.com.br", json=module_fixture("leakcheck_public", "email_small.json"))
    leak = run_module(LeakcheckPublic, f"email:{OWN}", lc_http, **options)
    check = copy.deepcopy(module_fixture("xposedornot", "check_email_ok.json"))
    check["breaches"] = [["8tracks", "Zomato"]]
    xon_http = FakeHttp().add("GET", "https://api.xposedornot.com/v1/check-email/analyst%40acme.com.br", json=check)
    xon_http.add("GET", "https://api.xposedornot.com/v1/breach-analytics?email=analyst%40acme.com.br",
                 json=module_fixture("xposedornot", "breach_analytics_not_found.json"))
    xon_http.add("GET", "https://api.xposedornot.com/v1/breaches", json=module_fixture("xposedornot", "catalogue_subset.json"))
    xon_http.add("GET", "https://haveibeenpwned.com/api/v3/breaches", json=hibp_catalogue)
    xon = run_module(XposedOrNot, f"email:{OWN}", xon_http, **options)
    for res in (hibp, leak, xon):
        assert res.status is Status.OK, (res.module, res.error)
    graph = Graph()
    node, _ = graph.add_node(hibp.entity, seed=True)
    for res in (hibp, leak, xon):
        for f in res.findings:
            graph.add_finding(f)
    eight = [f for f in node.findings if isinstance(f.data, dict) and f.data.get("breach_key") == breach_key("8Tracks.com")]
    assert {f.module for f in eight} == {"hibp_account", "leakcheck_public", "xposedornot"}
    corrs = [c for c in run_rules(graph, [hibp, leak, xon], only={RULE_BREACH_MERGE}) if c.rule == RULE_BREACH_MERGE]
    merged = [c for c in corrs if c.key == "8tracks"] if any(getattr(c, "key", "") for c in corrs) else [c for c in corrs if "8tracks" in c.title]
    assert len(merged) == 1
    scored = [f for f in eight if f.severity.label != "info"]
    assert len(scored) == 1 and scored[0].module == "hibp_account"
    assert scored[0].data["sources"] == ["hibp.account", "leakcheck.public", "xposedornot.api"]
    assert scored[0].data["date"] == "2017-06-27"
    assert all("context_only" in f.tags for f in eight if f is not scored[0])
