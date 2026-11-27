"""ransomware_live (P197): ransomware.live victims - PRO with the team key, keyless v2 in research only.

Fixtures in tests/fixtures/ransomware_live/ (prep batch p1-G09-1; v2 answers recorded 2026-11-25/26 from
api.ransomware.live, victims replaced with documentation values, group names and onions kept as public
IOC data): ``v2_search_ok.json`` (/v2/searchvictims key set, 3 victims), ``v2_search_placeholder_domain.json``
(killsec rows with the tracker's example.com placeholder), ``v2_search_not_found.json`` (the documented
404 'No victims found'), ``v2_rate_limited.json`` (429 '1 per 1 minute'), ``pro_needs_key.json`` (401
'Missing X-API-KEY header'), ``v2_recent_ok.json``, ``v2_groups_ok.json`` (2 group cards) and
``v2_html_root.html`` (HTML where JSON was expected). PRO success shapes are built inline from the PRO
swagger description until the team-key capture (P197 cond 7, backlog p1-G09-1).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.darkweb_ransomware import ransomware_live as rwl
from v3lum.modules.darkweb_ransomware.ransomware_live import RansomwareLive

V2 = "https://api.ransomware.live/v2"
PRO = "https://api-pro.ransomware.live"
KEY = "rl-team-key-0123456789abcdef"
LOCKBIT_ONION = "lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
RESEARCH = ScanOptions(licence_profile="research")


def raw(name: str) -> bytes:
    return (FIXTURES / "ransomware_live" / name).read_bytes()


def jsonbody(name: str) -> dict:
    return {"body": raw(name), "headers": {"content-type": "application/json"}}


# ------------------------------------------------------------------ metadata and licence (cond 1-3)
def test_metadata_follows_the_council_decision():
    cls = RansomwareLive
    assert cls.terms == "noncommercial" and cls.default_enabled is True and cls.trust_tier == "community"
    assert cls.terms_sources == {"ransomware_live.v2": "noncommercial", "ransomware_live.pro": "license",
                                 "ransomware_live.pro_iocs": "license", "ransomware_live.pro_notes": "license"}
    assert cls.optional_keys == ("ransomwarelive",) and cls.manual_link == "https://www.ransomware.live/search?q={q}"
    assert set(cls.hosts) == {"api.ransomware.live", "api-pro.ransomware.live"} and cls.sensitive is True
    assert cls.cache_ttl >= 1800 and cls.min_interval >= 1.0 and cls.max_requests == 4  # <= 60 req/min, cache >= 30 min
    assert "licence_allow" in cls.notice and "Ransomware.live" in cls.notice


def test_off_under_the_corporate_profile_until_licence_cleared():
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime(keys={"ransomwarelive": KEY})
    org = Entity.make(T.ORG, "Exemplo Alimentos")
    decision = policy.decide(RansomwareLive, org, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=org, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.SKIPPED, "licence")
    assert decision.emit_manual_link is True  # cond 3: the manual victim-search link
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [{
        "source_id": "ransomware_live.pro", "basis": "provider_grant", "scope": "internal CTI, no resale",
        "legal_ref": "LEGAL-RWL-1", "approver": "legal", "decided_at": "2026-11-20", "review_by": "2027-05-20",
        "evidence_url": "https://www.ransomware.live/t&c", "quote": "written approval of the owner"}]}), encoding="utf-8")
    allow.chmod(0o600)
    cleared = policy.decide(RansomwareLive, org, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=org, is_seed=True))
    assert cleared.allowed and cleared.allowed_sources == frozenset({"ransomware_live.pro"})


def test_without_licence_or_key_the_run_is_one_line_plus_the_manual_link():
    res = run_module(RansomwareLive, "company_name:Exemplo Alimentos", FakeHttp(), allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and "manual" in res.error
    assert ("ransomware.live victim search (manual lookup)", "https://www.ransomware.live/search?q=exemplo%20alimentos") in res.links
    res = run_module(RansomwareLive, "company_name:Exemplo Alimentos", FakeHttp(), allowed_sources=["ransomware_live.pro"])
    assert res.status is Status.NEEDS_KEY and "V3LUM_RANSOMWARELIVE_KEY" in res.error
    # v2 outside the research profile never runs, even when a gate allowed it (cond 1)
    res = run_module(RansomwareLive, "company_name:Exemplo Alimentos", FakeHttp(), allowed_sources=["ransomware_live.v2"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"


# ------------------------------------------------------------------ keyless v2, research profile (cond 1, 4, 6)
def test_v2_name_search_in_research_profile():
    http = FakeHttp().add("GET", f"{V2}/searchvictims/exemplo%20alimentos", **jsonbody("v2_search_ok.json"))
    res = run_module(RansomwareLive, "company_name:Exemplo Alimentos Ltda.", http, options=RESEARCH)
    assert res.status is Status.OK and len(http.calls) == 1
    [finding] = res.findings
    assert finding.data["group"] == "lockbit3" and finding.severity.label == "medium"
    assert finding.confidence_label.value == "possible" and finding.source == "ransomware_live.v2"
    assert finding.data["screenshot_url"].startswith("https://images.ransomware.live/")
    assert finding.data["claim_url_display"].startswith("hxxp://") and "Ransomware.live" in finding.description
    pivots = {(p.entity.type, p.entity.value, p.relation): p for p in res.pivots}
    assert pivots[(T.ONION, LOCKBIT_ONION, "leak_site")].expand is False
    assert pivots[(T.DOMAIN, "exemplo-alimentos.example", "victim_website")].expand is False
    assert (T.THREAT_ACTOR, "lockbit3", "victim_of") in pivots
    shots = [label for label, url in res.links if url.startswith("https://images.ransomware.live/")]
    assert shots and "never fetched" in shots[0]  # shown as a link with a warning, never fetched (cond 6)
    assert ("Source: Ransomware.live", "https://www.ransomware.live/") in res.links
    assert res.attributes["ransomware_mentions"] == 2
    assert all("images.ransomware.live" not in u for u in http.urls())
    http.assert_hosts_within(RansomwareLive)


def test_v2_domain_search_exact_match_and_org_criticality():
    http = FakeHttp().add("GET", f"{V2}/searchvictims/initech.example", **jsonbody("v2_search_ok.json"), times=2)
    res = run_module(RansomwareLive, "domain:initech.example", http, options=RESEARCH)
    [finding] = res.findings
    assert finding.data["match_type"] == "domain" and finding.severity.label == "high" and finding.data["group"] == "Dark Project"
    supplier = OrgProfile.from_dict({"org": {"name": "Exemplo"}, "suppliers": [{"name": "Initech", "domains": ["initech.example"]}]})
    res = run_module(RansomwareLive, "domain:initech.example", http, options=RESEARCH, org_profile=supplier)
    assert res.findings[0].severity.label == "critical" and res.findings[0].data["org_relation"] == "supplier"


def test_v2_placeholder_domains_never_match():
    http = FakeHttp().add("GET", f"{V2}/searchvictims/example.com", **jsonbody("v2_search_placeholder_domain.json"))
    res = run_module(RansomwareLive, "domain:example.com", http, options=RESEARCH)
    assert res.status is Status.EMPTY and not res.findings


def test_v2_documented_404_is_not_listed_never_not_breached():
    http = FakeHttp().add("GET", f"{V2}/searchvictims/nic.br", status=404, **jsonbody("v2_search_not_found.json"))
    res = run_module(RansomwareLive, "domain:nic.br", http, options=RESEARCH)
    assert res.status is Status.EMPTY
    assert res.attributes["ransomware_listing"].startswith("not listed by Ransomware.live (data as of")


@pytest.mark.parametrize(
    "status,name,expected",
    [(429, "v2_rate_limited.json", Status.RATE_LIMITED), (404, "v2_html_root.html", Status.ERROR), (502, "v2_html_root.html", Status.ERROR)],
)
def test_v2_refusals_are_could_not_verify(status, name, expected):
    http = FakeHttp().add("GET", f"{V2}/searchvictims/exemplo", status=status, body=raw(name), times=3,
                          headers={"content-type": "application/json" if name.endswith(".json") else "text/html; charset=utf-8"})
    res = run_module(RansomwareLive, "company_name:Exemplo", http, options=RESEARCH)
    assert res.status is expected and "ransomware_listing" not in res.attributes


def test_v2_html_in_a_200_is_an_error():
    http = FakeHttp().add("GET", f"{V2}/searchvictims/exemplo", body=raw("v2_html_root.html"), headers={"content-type": "text/html; charset=utf-8"})
    res = run_module(RansomwareLive, "company_name:Exemplo", http, options=RESEARCH)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_v2_group_card_gives_hostile_leak_site_pivots():
    card = module_fixture(RansomwareLive, "v2_groups_ok.json")[1]
    http = FakeHttp().add("GET", f"{V2}/group/lockbit3", json=card)
    res = run_module(RansomwareLive, "threat_actor:LockBit 3.0", http, options=RESEARCH)
    assert res.status is Status.OK
    profile = res.attributes["ransomware_group_profile"]
    assert profile["name"] == "lockbit3" and profile["known"] is True and len(profile["leak_sites"]) == 2
    assert profile["about"].startswith("LockBit")
    onions = [p for p in res.pivots if p.entity.type is T.ONION]
    assert len(onions) == 2 and all(p.expand is False and p.note.startswith("hostile") for p in onions)
    assert ("Ransomware.live group page: lockbit3", "https://www.ransomware.live/group/lockbit3") in res.links


# ------------------------------------------------------------------ PRO with the team key (cond 1, 6)
PRO_VICTIMS = {"victims": [{
    "victim": "Exemplo Alimentos Ltda.", "group": "lockbit3", "discovered": "2026-11-24T13:07:40+00:00",
    "attackdate": "2026-11-22T00:00:00+00:00", "country": "BR", "activity": "Manufacturing",
    "website": "exemplo-alimentos.example", "description": "Exemplo Alimentos Ltda. is a food producer.",
    "screenshot": "https://images.ransomware.live/victims/e358429c84cbe1c3464f6f5662f02722.png",
    "infostealer": {"employees": 3, "users": 41, "thirdparties": 0, "top_logins": ["someone@example.com"], "update": "2026-11-20"},
    "press": None, "id": "RXhlbXBsbyBBbGltZW50b3MgTHRkYS5AbG9ja2JpdDM=",
    "permalink": "https://www.ransomware.live/id/RXhlbXBsbyBBbGltZW50b3MgTHRkYS5AbG9ja2JpdDM=",
}]}


def test_pro_search_sends_the_key_in_a_header_and_keeps_counts_only():
    http = FakeHttp().add("GET", f"{PRO}/victims/search?q=exemplo-alimentos.example", json=PRO_VICTIMS, match_headers={"X-API-KEY": KEY})
    res = run_module(RansomwareLive, "domain:exemplo-alimentos.example", http, keys={"ransomwarelive": KEY})
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.severity.label == "high" and finding.source == "ransomware_live.pro"
    assert finding.data["infostealer_counts"] == {"employees": 3, "users": 41, "thirdparties": 0}
    assert KEY not in http.urls()[0]  # header only, never in the URL (cond 6, AR01)
    blob = json.dumps([f.to_dict() for f in res.findings]) + json.dumps(res.raw) + json.dumps(res.attributes) + res.error
    assert "top_logins" not in blob and "someone@example.com" not in blob
    assert_no_secret(KEY, res.findings, res.attributes, res.raw, res.links, res.error)


def test_pro_without_a_valid_key_is_needs_key_and_quota_is_quota():
    http = FakeHttp().add("GET", f"{PRO}/victims/search?q=exemplo", status=401, **jsonbody("pro_needs_key.json"))
    res = run_module(RansomwareLive, "company_name:Exemplo", http, keys={"ransomwarelive": KEY})
    assert res.status is Status.NEEDS_KEY
    http = FakeHttp().add("GET", f"{PRO}/victims/search?q=exemplo", status=429, json={"message": "500000 per 1 month"}, times=2)
    res = run_module(RansomwareLive, "company_name:Exemplo", http, keys={"ransomwarelive": KEY})
    assert res.status is Status.QUOTA


def test_pro_actor_card_and_iocs_are_hostile_pivots():
    card = module_fixture(RansomwareLive, "v2_groups_ok.json")[1]
    iocs = {"md5": ["44d88612fea8a8f36de82e1278abb02f"], "domain": ["c2-exemplo.example"], "ip": ["203.0.113.7"],
            "url": [{"value": "https://c2-exemplo.example/gate.php"}], "weird": ["x"]}
    http = (FakeHttp()
            .add("GET", f"{PRO}/group/lockbit3", json=card, match_headers={"X-API-KEY": KEY})
            .add("GET", f"{PRO}/iocs/lockbit3", json=iocs))
    res = run_module(RansomwareLive, "threat_actor:lockbit3", http, keys={"ransomwarelive": KEY})
    assert res.status is Status.OK
    got = {(p.entity.type, p.entity.value, p.relation): p for p in res.pivots}
    assert got[(T.MD5, "44d88612fea8a8f36de82e1278abb02f", "group_ioc")].expand is False
    assert (T.DOMAIN, "c2-exemplo.example", "group_ioc") in got and (T.URL, "https://c2-exemplo.example/gate.php", "group_ioc") in got
    assert all(p.expand is False and p.note.startswith("hostile") for p in res.pivots)
    assert not any(p.entity.type is T.IPV4 for p in res.pivots)  # A4: a sensitive tracker's IPs never reach the graph
    assert res.attributes["ransomware_group_profile"]["iocs"] == {"published": 3, "pivots": 3}  # the 'ip' list never arrives
    # A4: the core drops 'content' fields of a sensitive provider, so the ransom-note text cannot be read:
    # no request is spent on it and the feed says why (cond 6 partly met, backlog p1-G09-1)
    assert len(http.calls) == 2
    notes = res.source_statuses["ransomware_live.pro_notes"]
    assert notes["status"] == "skipped" and notes["reason_code"] == "policy"


def test_ransom_note_contacts_parser():
    note = {"content": f"All your files are encrypted. Chat: http://{LOCKBIT_ONION}/chat Mail: recovery@example.net qTox: "
                       + "B2" * 38, "extension": "txt"}
    contacts = rwl.note_contacts(note)
    assert contacts == {"onions": [LOCKBIT_ONION], "emails": ["recovery@example.net"], "qtox": ["B2" * 38]}
    assert rwl.note_names(["Restore-My-Files", "../x"]) == ["Restore-My-Files"]


def test_sensitive_sanitizer_drops_hashes_next_to_email_iocs():
    """A4 (core P145): in a sensitive tracker's answer, hex hashes next to an e-mail list are treated as
    credential hashes and dropped before the module sees them; e-mail IOCs still pivot (backlog p1-G09-1)."""
    card = module_fixture(RansomwareLive, "v2_groups_ok.json")[1]
    iocs = {"md5": ["44d88612fea8a8f36de82e1278abb02f"], "email": [{"value": "decrypt@example.org"}]}
    http = FakeHttp().add("GET", f"{PRO}/group/lockbit3", json=card).add("GET", f"{PRO}/iocs/lockbit3", json=iocs)
    res = run_module(RansomwareLive, "threat_actor:lockbit3", http, keys={"ransomwarelive": KEY})
    got = {(p.entity.type, p.entity.value) for p in res.pivots}
    assert (T.EMAIL, "decrypt@example.org") in got and (T.MD5, "44d88612fea8a8f36de82e1278abb02f") not in got


def test_pro_feed_failures_are_per_feed():
    card = module_fixture(RansomwareLive, "v2_groups_ok.json")[1]
    http = (FakeHttp().add("GET", f"{PRO}/group/lockbit3", json=card)
            .add("GET", f"{PRO}/iocs/lockbit3", status=429, json={"message": "60 per 1 minute"}, times=2))
    res = run_module(RansomwareLive, "threat_actor:lockbit3", http, keys={"ransomwarelive": KEY})
    assert res.status is Status.OK and res.source_statuses["ransomware_live.pro_iocs"]["status"] == "rate_limited"


# ------------------------------------------------------------------ parsers
def test_parsers_accept_every_documented_shape_and_never_raise():
    recent = rwl.parse_victims(module_fixture(RansomwareLive, "v2_recent_ok.json"))
    assert [c["victim"] for c in recent] == ["Exemplo Alimentos Ltda.", "Hospital Exemplo"]
    old = rwl.parse_victims([{"post_title": "Globex", "group_name": "play", "published": "2026-11-20 10:00:00", "website": "globex.example",
                              "post_url": f"http://{LOCKBIT_ONION}/x"}])
    assert old[0]["website"] == "globex.example" and old[0]["onions"] == [LOCKBIT_ONION]
    assert rwl.parse_iocs([{"type": "sha256", "value": "a" * 64}, {"type": "url", "ioc": "https://c2.example/x"}]) == [
        (T.SHA256, "a" * 64), (T.URL, "https://c2.example/x")]
    assert rwl.parse_iocs({"iocs": {"ip": ["2001:db8::1"]}}) == [(T.IPV6, "2001:db8::1")]
    assert rwl.note_names({"notes": [{"name": "README"}, {"name": "../etc"}]}) == ["README"]
    for bad in (None, 1, "x", [], {}, [None], {"victims": "x"}, {"locations": "x", "name": 3}):
        rwl.parse_victims(bad)
        rwl.parse_group(bad)
        rwl.parse_iocs(bad)
        rwl.note_names(bad)
        rwl.note_contacts(bad)
        rwl.normalize_victim(bad)
