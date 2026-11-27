"""wikimedia (P120): global account + pt/en contributions, contact UA, seed-only IP lookups, minimisation.

Fixtures in tests/fixtures/wikimedia/ (batch p3-G05-3 prep, 2026-11-26): ``rate_limited`` is the REAL 429
from the datacenter egress (request id zeroed); the 200 answers are DOC-SHAPED from the MediaWiki /
CentralAuth API formats (documentation account 'Example'; the IP fixtures use the central benign values
8.8.8.8 / 8.8.8.0/24 because reserved ranges are never sent) - FC5 asks for a re-capture with the team's
contact UA before default use (docs/backlog/p3-G05-3.md); the 403/503/HTML/malformed answers are SYNTHETIC.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.username_social import wikimedia as W
from v3lum.modules.username_social.wikimedia import Wikimedia

CONTACT = {"contact_email": "soc@example.com"}
META = W.META
PT = "https://pt.wikipedia.org/w/api.php"
EN = "https://en.wikipedia.org/w/api.php"
ORG = OrgProfile.from_dict({"org": {"name": "Exemplo S.A."}, "brands": [{"keyword": "Exemplo"}]})


def fx(name: str) -> dict[str, Any]:
    return module_fixture("wikimedia", name)


def add(http: FakeHttp, url: str, name: str) -> FakeHttp:
    env = fx(name)
    return http.add("GET", url, status=int(env["status"]), body=(env.get("body") or "").encode("utf-8"), headers=env.get("headers") or {})


def q(base: str, params: dict[str, str]) -> str:
    return f"{base}?{urlencode(params)}"


def gui(user: str = "Example") -> str:
    return q(META, W.globaluserinfo_params(user))


def contribs(base: str, **kw: str) -> str:
    return q(base, W.usercontribs_params(**kw))


def user_http(gui_fixture: str = "globaluserinfo_ok.http.json", contribs_fixture: str = "usercontribs_user_ok.http.json") -> FakeHttp:
    http = FakeHttp()
    add(http, gui(), gui_fixture)
    add(http, contribs(PT, user="Example"), contribs_fixture)
    add(http, contribs(EN, user="Example"), contribs_fixture)
    return http


def test_metadata_matches_the_council_decision():
    assert Wikimedia.terms == "open" and Wikimedia.default_enabled is True and Wikimedia.trust_tier == "trusted"
    assert set(Wikimedia.hosts) == {"meta.wikimedia.org", "pt.wikipedia.org", "en.wikipedia.org"}
    assert Wikimedia.min_interval == 1.0 and Wikimedia.provider == "wikimedia"
    p = W.usercontribs_params(user="x", limit=500)
    assert p["uclimit"] == "50" and p["maxlag"] == "5" and "comment" not in p["ucprop"]  # cond 1/4/5
    assert W.globaluserinfo_params("x")["maxlag"] == "5"


def test_username_keeps_counts_dates_and_case_pages_only():
    http = user_http()
    res = run_module(Wikimedia, "username:Example", http, settings=CONTACT, org_profile=ORG)
    assert res.status is Status.OK, res.error
    acct = res.attributes["wikimedia_account"]
    assert acct["home_wiki"] == "enwiki" and acct["editcount"] == 26 and acct["registration"] == "2006-04-28T19:36:07Z"
    assert [w["wiki"] for w in acct["wikis"]] == ["enwiki", "ptwiki"]  # home + pt/en only, never groups or other wikis
    assert "groups" not in str(res.attributes) and "commonswiki" not in str(res.attributes)
    pt = res.attributes["wikimedia_contributions"]["ptwiki"]
    assert pt["count"] == 4 and pt["more"] is True and pt["first"] == "2021-05-05T05:05:05Z"
    assert [p["title"] for p in pt["relevant_pages"]] == ["Exemplo S.A.", "Talk:Exemplo S.A."]
    flat = str(res.attributes) + str(res.raw) + str([p.entity.value for p in res.pivots])
    assert "Sandbox" not in flat and "User:Example" not in flat  # cond 4: never the full edit history
    urls = {p.entity.value for p in res.pivots}
    assert "https://pt.wikipedia.org/wiki/Exemplo_S.A." in urls and all(not p.expand for p in res.pivots)
    assert {p.relation for p in res.pivots} == {"edited_page"}
    assert res.attributes["presence"]["state"] == "found" and res.attributes["created"] == "2006-04-28T19:36:07Z"
    assert [f.title for f in res.findings] == ["Wikimedia global account"]
    http.assert_hosts_within(Wikimedia)
    for call in http.calls:  # cond 2: contact UA built at run time, only towards Wikimedia hosts
        ua = {k.lower(): v for k, v in call["headers"].items()}["user-agent"]
        assert ua.startswith("V3LUM/") and "(+soc@example.com)" in ua
        query = parse_qs(urlsplit(call["url"]).query)
        assert query["maxlag"] == ["5"]


def test_without_case_terms_no_page_is_kept():
    res = run_module(Wikimedia, "username:Example", user_http(), settings=CONTACT)
    assert res.status is Status.OK
    assert res.attributes["wikimedia_contributions"]["enwiki"]["relevant_pages"] == []
    assert not res.pivots


def test_missing_global_account_is_empty_with_evidence():
    http = FakeHttp()
    add(http, gui(), "globaluserinfo_missing.http.json")
    res = run_module(Wikimedia, "username:Example", http, settings=CONTACT)
    assert res.status is Status.EMPTY and "no global (SUL)" in res.error
    assert res.attributes["presence"]["state"] == "absent"
    assert len(http.calls) == 1  # no contributions asked for an account that does not exist


def test_locked_account_formatversion_1():
    http = FakeHttp()
    add(http, gui(), "globaluserinfo_locked_fv1.http.json")
    add(http, contribs(PT, user="Example locked"), "usercontribs_empty.http.json")
    add(http, contribs(EN, user="Example locked"), "usercontribs_empty.http.json")
    res = run_module(Wikimedia, "username:Example", http, settings=CONTACT)
    assert res.status is Status.OK
    assert res.attributes["wikimedia_account"]["locked"] is True
    locked = [f for f in res.findings if f.title == "Wikimedia global account is locked"]
    assert locked and locked[0].severity is Severity.LOW and locked[0].criterion


def test_contact_setting_is_required_and_never_personal():
    for settings in ({}, {"contact_email": "analyst@gmail.com"}, {"contact_email": "not-an-address"}):
        http = FakeHttp()
        res = run_module(Wikimedia, "username:Example", http, settings=settings)
        assert res.status is Status.SKIPPED and res.reason_code == "config" and "needs contact setting" in res.error
        assert http.calls == []


def test_could_not_verify_answers_are_never_absent():
    cases = {
        "rate_limited.http.json": (Status.RATE_LIMITED, "rate_limited"),
        "error_in_200_maxlag.http.json": (Status.RATE_LIMITED, "rate_limited"),
        "error_in_200_baduser.http.json": (Status.ERROR, "error"),
        "blocked_ua_policy.http.json": (Status.BLOCKED, "challenge"),
        "server_error_html.http.json": (Status.ERROR, "error"),
        "html_in_200.http.json": (Status.ERROR, "error"),
        "malformed.http.json": (Status.ERROR, "error"),
    }
    for name, (status, code) in cases.items():
        http = FakeHttp()
        add(http, gui(), name)
        res = run_module(Wikimedia, "username:Example", http, settings=CONTACT)
        assert res.status is status and res.reason_code == code, (name, res.status, res.reason_code, res.error)
        assert "wikimedia_account" not in res.attributes and "presence" not in res.attributes


def test_ip_seed_lists_historical_low_confidence_edits():
    http = FakeHttp()
    add(http, contribs(PT, user="8.8.8.8"), "usercontribs_ip_ok.http.json")
    add(http, contribs(EN, user="8.8.8.8"), "usercontribs_empty.http.json")
    res = run_module(Wikimedia, "ipv4:8.8.8.8", http, settings=CONTACT, org_profile=ORG)
    assert res.status is Status.OK, res.error
    pt = res.attributes["wikimedia_contributions"]["ptwiki"]
    assert pt["count"] == 2 and pt["rows"][0]["ip"] == "8.8.8.8" and pt["rows"][0]["title"] == "Exemplo S.A."
    assert any("closed logged-out (IP) editing in 2020" in n for n in pt["notes"])  # cond 3
    assert any("low confidence" in n for n in pt["notes"])
    f = res.findings[0]
    assert f.title == "Wikipedia edits from this IP" and {"historical", "weak_signal"} <= set(f.tags)
    assert all(p.confidence_label == "possible" and not p.expand for p in res.pivots)
    http.assert_hosts_within(Wikimedia)


def test_cidr_uses_uciprange_and_respects_the_range_limit():
    http = FakeHttp()
    add(http, contribs(PT, iprange="8.8.8.0/24"), "usercontribs_range_ok.http.json")
    add(http, contribs(EN, iprange="8.8.8.0/24"), "usercontribs_empty.http.json")
    res = run_module(Wikimedia, "cidr:8.8.8.0/24", http, settings=CONTACT)
    assert res.status is Status.OK
    assert {r["ip"] for r in res.attributes["wikimedia_contributions"]["ptwiki"]["rows"]} == {"8.8.8.42", "8.8.8.7"}
    assert res.findings[0].title == "Wikipedia edits from this IP range"
    http = FakeHttp()
    res = run_module(Wikimedia, "cidr:8.0.0.0/8", http, settings=CONTACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_pivot_ips_are_never_looked_up_but_org_cidrs_are():
    http = FakeHttp()
    res = run_module(Wikimedia, "ipv4:8.8.8.8", http, settings=CONTACT, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and http.calls == []
    org = OrgProfile.from_dict({"org": {"name": "Exemplo S.A."}, "cidrs": [{"value": "8.8.8.0/24"}]})
    http = FakeHttp()
    add(http, contribs(PT, iprange="8.8.8.0/24"), "usercontribs_empty.http.json")
    add(http, contribs(EN, iprange="8.8.8.0/24"), "usercontribs_empty.http.json")
    res = run_module(Wikimedia, "cidr:8.8.8.0/24", http, settings=CONTACT, org_profile=org, is_seed=False, depth=1)
    assert res.status is Status.EMPTY and "says little" in res.error


def test_private_addresses_are_never_sent():
    http = FakeHttp()
    res = run_module(Wikimedia, "ipv4:10.1.2.3", http, settings=CONTACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_one_wiki_failing_is_reported_per_source():
    http = FakeHttp()
    add(http, contribs(PT, user="8.8.8.8"), "server_error_html.http.json")
    add(http, contribs(EN, user="8.8.8.8"), "usercontribs_ip_ok.http.json")
    res = run_module(Wikimedia, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.OK
    assert set(res.attributes["wikimedia_contributions"]) == {"enwiki"}
    assert res.source_statuses["wikimedia.usercontribs"]["reason_code"] == "error"


def test_a_429_backs_off_the_whole_provider_and_is_could_not_verify():
    http = FakeHttp()
    add(http, contribs(PT, user="8.8.8.8"), "rate_limited.http.json")
    add(http, contribs(EN, user="8.8.8.8"), "usercontribs_ip_ok.http.json")
    res = run_module(Wikimedia, "ipv4:8.8.8.8", http, settings=CONTACT)
    assert res.status is Status.RATE_LIMITED and "could not be verified" in res.error
    assert [c["url"].split("/")[2] for c in http.calls] == ["pt.wikipedia.org"]  # en.wikipedia is not hammered after a 429


def test_range_error_inside_http_200_is_could_not_verify():
    http = FakeHttp()
    add(http, contribs(PT, iprange="8.8.0.0/16"), "error_in_200_cidrtoobroad.http.json")
    add(http, contribs(EN, iprange="8.8.0.0/16"), "error_in_200_cidrtoobroad.http.json")
    res = run_module(Wikimedia, "cidr:8.8.0.0/16", http, settings=CONTACT)
    assert res.status is Status.ERROR and "could not be verified" in res.error
    assert "wikimedia_contributions" not in res.attributes
