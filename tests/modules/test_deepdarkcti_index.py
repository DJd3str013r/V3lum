"""deepdarkcti_index (P198): deepdarkCTI lists -> onion/Telegram index, matched offline (disclosure none).

Fixtures in tests/fixtures/deepdarkcti_index/ (prep batch p2-G09-1, live 2026-11-26 from
raw.githubusercontent.com/fastfire/deepdarkCTI/main/<list>.md, trimmed to rows chosen for parser cases;
actor contact e-mails, Tox IDs, the User:Password values, Twitter handles and one criminal host IP were
replaced with documentation values): ``<list>_ok.md`` for the seven lists, ``truncated_malformed.md``
(the research sample cut mid-row), ``empty_table.md`` (header only) and ``github_commits_derived.json``
(the GitHub REST commits schema with documentation values: api.github.com could not be reached from the
build session). The Ahmia banned list comes from tests/fixtures/onion_lookup/ahmia_banned_ok.txt.
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.darkweb_ransomware import deepdarkcti_index as ddc
from v3lum.modules.darkweb_ransomware import onion_safety
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import COMMIT_URL, LIST_URL, LISTS, DeepdarkctiIndex
from v3lum.modules.darkweb_ransomware.onion_safety import AHMIA_BANNED_URL, BANNED_ONION_TEXT

FIX = FIXTURES / "deepdarkcti_index"
BANNED_ONION = "yrb5vnqn4gnkmamewpbq6so6oe6dejqr36eroyjpvi26mdj7kq4exnqd.onion"  # synthetic line 7 of the banned fixture
LOCKBIT2 = "lockbitapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd.onion"
OAPT = "oaptxiyisljt2kv3we2we34kuudmqda7f2geffoylzpeo7ourhtz4dad.onion"
UNLISTED = "7lv6yjwjmm4xc5kxdf4lozqu5vjeq4s4il4ut5gg4wg2vcpumg7rvxyd.onion"  # synthetic valid-checksum onion


@pytest.fixture(autouse=True)
def small_floors(monkeypatch):
    """The fixtures are trimmed lists: the production row floors would mark them unhealthy."""
    monkeypatch.setattr(ddc, "FLOORS", {name: (1, 1) for name in LISTS})
    monkeypatch.setattr(onion_safety, "MIN_HASHES", 1)
    ddc._MEMO.clear()
    onion_safety._FAILED.clear()


def text(name: str) -> bytes:
    return (FIX / name).read_bytes()


def lists_http(*, overrides: dict | None = None, commit_status: int = 200, ahmia: bool = True) -> FakeHttp:
    """Routes for the seven lists, their commit datasets and (optionally) the Ahmia banned list."""
    overrides = overrides or {}
    http = FakeHttp()
    for name in LISTS:
        status, body = overrides.get(name, (200, text(f"{name}_ok.md")))
        http.add("GET", LIST_URL.format(name=name), status=status, body=body, headers={"content-type": "text/plain; charset=utf-8"})
        http.add("GET", COMMIT_URL.format(name=name), status=commit_status, body=text("github_commits_derived.json"),
                 headers={"content-type": "application/json; charset=utf-8"})
    if ahmia:
        add_ahmia(http)
    return http


def add_ahmia(http: FakeHttp, status: int = 200) -> FakeHttp:
    body = (FIXTURES / "onion_lookup" / "ahmia_banned_ok.txt").read_bytes()
    return http.add("GET", AHMIA_BANNED_URL, status=status, body=body, headers={"content-type": "text/plain; charset=utf-8"})


def dataset_hosts(http: FakeHttp) -> set[str]:
    return set(http.hosts())


# ------------------------------------------------------------------ metadata (cond 1)
def test_metadata_offline_open_and_datasets_registered():
    cls = DeepdarkctiIndex
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.default_enabled) == ("none", (), "", "open", True)
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.max_requests == 0 and cls.shares_input is False
    assert set(cls.sources) == {"github.deepdarkcti_index_lists", "github.deepdarkcti_index_commits", "ahmia.banned_list"}
    for name in LISTS:
        reg = DATASETS[ddc.list_dataset(name)]
        assert reg["url"] == LIST_URL.format(name=name) and reg["ttl"] == 7 * 86400 and reg["terms_class"] == "open"
        assert "GPL-3.0" in reg["licence"] and reg["source"] == "github.deepdarkcti_index_lists" and reg["large"] is False
        commit = DATASETS[ddc.commit_dataset(name)]
        assert commit["url"] == COMMIT_URL.format(name=name) and commit["source"] == "github.deepdarkcti_index_commits"
    assert "twitter_threat_actors" not in LISTS and "discord" not in LISTS  # no onion/t.me key: not downloaded


# ------------------------------------------------------------------ onion matches (cond 3, 4, 5)
def test_onion_leak_site_match_is_context_with_status_and_list_date():
    http = lists_http()
    res = run_module(DeepdarkctiIndex, f"onion:{OAPT}", http)
    assert res.status is Status.OK and res.requests == 0
    assert dataset_hosts(http) <= {"raw.githubusercontent.com", "api.github.com", "ahmia.fi"}  # never the onion itself
    [finding] = res.findings
    assert finding.title == "Listed in deepdarkCTI: ransomware leak site" and finding.severity.label == "medium"
    assert finding.confidence_label.value == "possible" and finding.source == "github.deepdarkcti_index_lists"
    assert "listed in deepdarkCTI as ransomware leak site of 0APT (status ONLINE, list date 2026-11-20)" in finding.description
    assert "context, not attribution" in finding.description and "never visit" in finding.description
    assert OAPT not in finding.description and "[.]onion" in finding.description  # defanged
    assert {"suspicious", "ransomware", "darkweb"} <= set(finding.tags) and "historical" not in finding.tags
    [pivot] = res.pivots
    assert (pivot.entity.value, pivot.relation, pivot.expand, pivot.confidence_label.value) == ("0APT", "leak_site_of", False, "possible")
    listing = res.attributes["ddc_listings"][0]
    assert listing["status"] == "ONLINE" and listing["list_date"] == "2026-11-20" and listing["historical"] is False
    assert res.attributes["threat_actors"] == ["0APT"]
    assert res.attributes["feed_status"]["ransomware_gang"]["state"] in ("ok", "stale")
    assert {d["name"] for d in res.datasets} >= {"deepdarkcti_index_ransomware_gang", "ahmia_banned_onions"}


def test_rebranded_and_seized_entries_are_historical_info():
    res = run_module(DeepdarkctiIndex, f"onion:{LOCKBIT2}", lists_http())
    [finding] = res.findings
    assert finding.severity.label == "info" and "historical" in finding.tags and "suspicious" in finding.tags
    assert "status REBRANDED" in finding.description and "historical entry" in finding.description
    assert res.pivots[0].entity.value == "LOCKBIT 2.0"


def test_onion_with_subdomain_and_url_form_matches_the_service():
    res = run_module(DeepdarkctiIndex, f"onion:http://www.{OAPT}/leaks", lists_http())
    assert res.status is Status.OK and res.findings[0].data["group"] == "0APT"


def test_miss_is_empty_with_feed_status():
    res = run_module(DeepdarkctiIndex, f"onion:{UNLISTED}", lists_http())
    assert res.status is Status.EMPTY and not res.findings and not res.pivots
    assert set(res.attributes["feed_status"]) == set(LISTS)


def test_tracker_rows_are_categorised_and_never_pivot():
    res = run_module(DeepdarkctiIndex, "onion:ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion", lists_http())
    assert res.findings[0].title == "Listed in deepdarkCTI: ransomware tracker/index site"
    assert not res.pivots


# ------------------------------------------------------------------ Telegram matches
def test_telegram_contact_channel_from_the_ransomware_list():
    res = run_module(DeepdarkctiIndex, "telegram_handle:@eightbase", lists_http())
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.title == "Listed in deepdarkCTI: ransomware gang contact channel"
    assert "t[.]me/eightbase" in finding.description and "darkweb" not in finding.tags
    assert res.pivots[0].relation == "listed_for_actor" and res.pivots[0].entity.value == "8BASE"


def test_username_matches_a_threat_actor_channel():
    res = run_module(DeepdarkctiIndex, "username:CrazyHuntersTeam", lists_http())
    assert res.status is Status.OK
    assert res.findings[0].data["category"] == "Telegram threat-actor channel" and res.findings[0].severity.label == "medium"
    assert "Telegram channel with this handle" in res.findings[0].criterion
    assert {"suspicious", "cybercrime"} <= set(res.findings[0].tags)


def test_telegram_offline_channel_is_historical():
    res = run_module(DeepdarkctiIndex, "telegram_handle:handala_team", lists_http())
    assert res.findings[0].severity.label == "info" and res.findings[0].data["status"] == "OFFLINE"


# ------------------------------------------------------------------ group summary (threat_actor / keyword)
def test_group_summary_counts_with_defanged_examples():
    res = run_module(DeepdarkctiIndex, "threat_actor:RANION", lists_http())
    assert res.status is Status.OK and not res.pivots
    summary = res.attributes["ddc_group_summary"]
    assert summary["onion"] == 4 and summary["lists"] == ["maas"] and summary["active"] == 4
    assert all("[.]onion" in e for e in summary["examples"])
    [finding] = res.findings
    assert finding.title == "deepdarkCTI lists infrastructure for this group" and finding.severity.label == "info"


def test_group_summary_version_suffix_and_keyword():
    res = run_module(DeepdarkctiIndex, "keyword:lockbit", lists_http())
    assert res.status is Status.OK and res.attributes["ddc_group_summary"]["onion"] == 1  # LOCKBIT 2.0 only


def test_group_examples_withheld_without_the_banned_list():
    http = lists_http(ahmia=False)
    add_ahmia(http, status=503)
    res = run_module(DeepdarkctiIndex, "threat_actor:RANION", http)
    summary = res.attributes["ddc_group_summary"]
    assert summary["examples"] == [] and summary["examples_withheld"] == 4  # fail closed: no onion shown


def test_unknown_group_is_empty():
    assert run_module(DeepdarkctiIndex, "threat_actor:Nonexistent Crew", lists_http()).status is Status.EMPTY


# ------------------------------------------------------------------ Ahmia safety filter (P199 cond 2-3)
def test_banned_onion_shows_only_the_fixed_text_and_reads_no_list():
    http = add_ahmia(FakeHttp())  # no list routes: the lists are never read for a banned onion
    res = run_module(DeepdarkctiIndex, f"onion:{BANNED_ONION}", http)
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.title == BANNED_ONION_TEXT and finding.description == BANNED_ONION_TEXT
    assert set(finding.tags) == {"banned_onion", "suspicious"} and not finding.data
    assert res.attributes == {} and res.pivots == [] and res.links == [] and not res.raw
    assert BANNED_ONION not in repr(res.to_dict()["findings"])


def test_without_the_banned_list_onion_details_are_withheld():
    http = add_ahmia(FakeHttp(), status=503)
    res = run_module(DeepdarkctiIndex, f"onion:{OAPT}", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and not res.findings


# ------------------------------------------------------------------ dataset health (cond 2) and rule 5
def test_unhealthy_list_is_never_empty():
    http = lists_http(overrides={"ransomware_gang": (200, text("empty_table.md"))})
    res = run_module(DeepdarkctiIndex, f"onion:{UNLISTED}", http)
    # the download is refused by the validator (no previous copy): 'missing', and a miss is 'could not verify'
    assert res.status is Status.ERROR and "ransomware_gang" in res.error and "could not verify" in res.error
    assert res.attributes["feed_status"]["ransomware_gang"]["state"] == "missing"


def test_local_copy_below_the_floor_reads_unhealthy(monkeypatch):
    http = lists_http()
    assert run_module(DeepdarkctiIndex, f"onion:{UNLISTED}", http).status is Status.EMPTY  # installs the copies
    monkeypatch.setattr(ddc, "FLOORS", {**{n: (1, 1) for n in LISTS}, "forum": (500, 100)})
    res = run_module(DeepdarkctiIndex, f"onion:{UNLISTED}", lists_http())
    assert res.status is Status.ERROR and res.attributes["feed_status"]["forum"]["state"] == "unhealthy"
    match = run_module(DeepdarkctiIndex, f"onion:{OAPT}", lists_http())
    assert match.status is Status.OK  # a match in a healthy list still stands


def test_all_lists_missing_is_unavailable():
    http = lists_http(overrides={n: (404, b"404: Not Found") for n in LISTS})
    res = run_module(DeepdarkctiIndex, "threat_actor:RANION", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_challenge_page_instead_of_a_list_is_never_installed():
    page = b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = lists_http(overrides={"markets": (403, page)})
    res = run_module(DeepdarkctiIndex, "onion:alphabay522szl32u4ci5e3iokdsyth56ei7rwngr2wm7i5jo54j2eid.onion", http)
    assert res.status is Status.ERROR and res.attributes["feed_status"]["markets"]["state"] == "missing"


def test_commit_date_unavailable_falls_back_to_the_fetch_date():
    res = run_module(DeepdarkctiIndex, f"onion:{OAPT}", lists_http(commit_status=403))
    assert res.status is Status.OK and "list date unknown, fetched " in res.findings[0].description
    assert res.attributes["ddc_listings"][0]["list_date"] is None


def test_failed_downloads_are_not_retried_by_every_run():
    http = FakeHttp()
    for name in LISTS:
        http.add("GET", LIST_URL.format(name=name), body=text(f"{name}_ok.md"), headers={"content-type": "text/plain"})
        http.add("GET", COMMIT_URL.format(name=name), status=403, json={"message": "rate limit"}, times=1)
    add_ahmia(http)
    first = run_module(DeepdarkctiIndex, f"onion:{OAPT}", http)
    second = run_module(DeepdarkctiIndex, f"onion:{OAPT}", http)  # a second commit request would be unexpected
    assert first.status is Status.OK and second.status is Status.OK
    assert sum(1 for u in http.urls() if "api.github.com" in u) == len(LISTS)


def test_stale_list_makes_an_online_entry_historical():
    entry = {"category": "ransomware leak site", "group": "0APT", "status": "ONLINE", "active": True, "commit_date": "2025-01-10"}
    wording, historical, stale = ddc.match_wording(entry, "2026-11-26")
    assert historical and stale and "list older than 180 days" in wording


# ------------------------------------------------------------------ parser (cond 2, 3) - pure functions
def test_tolerant_table_reader_skips_cut_rows():
    parsed = ddc.parse_ddc_list(text("truncated_malformed.md").decode(), "ransomware_gang")
    assert parsed["rows"] == 2 and len(parsed["entries"]) == 2 and parsed["skipped"]["truncated_row"] == 1
    assert ddc.parse_markdown_table("")["problem"] == "empty"
    assert ddc.parse_markdown_table("<html><head></head><body>x</body></html>")["problem"] == "html"
    assert ddc.parse_markdown_table("no table here\n")["problem"] == "no_table"
    assert ddc.split_md_row("a|b|c") == ["a", "b", "c"] and ddc.split_md_row("|a\\|b|c|") == ["a|b", "c"]


def test_parser_handles_live_quirks():
    rg = ddc.parse_ddc_list(text("ransomware_gang_ok.md").decode(), "ransomware_gang")
    by_group = {e["group"]: e for e in rg["entries"] if e["kind"] == "onion"}
    assert by_group["BYOD"]["status"] == "ONLINE"  # status shifted one cell right
    assert by_group["RANSOM CORP"]["status"] == "OFFLINE"  # 'OFFILINE' typo
    assert by_group["SCATTERED SPIDER"]["status"] == "SEIZED"
    assert rg["skipped"]["onion_v2"] == 1 and rg["skipped"]["telegram_invite"] == 1
    markets = ddc.parse_ddc_list(text("markets_ok.md").decode(), "markets")
    groups = [e["group"] for e in markets["entries"]]
    assert groups.count("DARKCLUB") == 2  # unbalanced link text 'DARKCLUB (Onion Site 2'
    oni = [e for e in markets["entries"] if e["key"] == "oniforum"][0]
    assert oni["status"] == "ONLINE" and oni["category"] == "dark-web market Telegram channel"  # name fused with status
    tg = ddc.parse_ddc_list(text("telegram_threat_actors_ok.md").decode(), "telegram_threat_actors")
    keys = {e["key"] for e in tg["entries"]}
    assert "defacement" in keys and "altenens" in keys  # telegram.me alias
    assert tg["skipped"]["telegram_invite"] == 3 and tg["skipped"]["telegram_private_link"] == 1


def test_parser_never_keeps_credentials_or_contacts():
    for name in LISTS:
        parsed = ddc.parse_ddc_list(text(f"{name}_ok.md").decode(), name)
        blob = repr(parsed)
        for secret in ("demo:demo", "DEMOSECRET", "actor-contact@example.com", "203.0.113.10", "example_actor", "0000000000000000"):
            assert secret not in blob, (name, secret)


def test_status_normalisation_drops_unrecognised_cells():
    assert ddc.normalize_status("OFFLINE (Seized)")["status"] == "SEIZED"
    assert ddc.normalize_status("Siezed")["status"] == "SEIZED"
    assert ddc.normalize_status("ONLINE (Parked)")["active"] is False
    unknown = ddc.normalize_status("demo:demo")
    assert unknown["status"] == "UNKNOWN" and unknown["text"] == ""  # a misaligned credential cell is never kept


def test_telegram_paths():
    assert ddc.classify_telegram_path("+abcDEF123") == ("invite", None)
    assert ddc.classify_telegram_path("joinchat/xyz") == ("invite", None)
    assert ddc.classify_telegram_path("c/1228309110/7662") == ("private_link", None)
    assert ddc.classify_telegram_path("s/SomeChannel/12") == ("handle", "somechannel")
    assert ddc.telegram_key("https://t.me/Some_Channel") == "some_channel" and ddc.telegram_key("@x") is None


def test_validators_refuse_html_and_short_lists(tmp_path, monkeypatch):
    monkeypatch.setattr(ddc, "FLOORS", {**{n: (1, 1) for n in LISTS}, "maas": (5, 3)})
    page = tmp_path / "maas.md"
    page.write_bytes(text("empty_table.md"))
    with pytest.raises(ValueError, match="unhealthy"):
        ddc._list_validator("maas")(page)
    page.write_text("<html><head></head><body>blocked</body></html>")
    with pytest.raises(ValueError, match="not a markdown table"):
        ddc._list_validator("maas")(page)
    commits = tmp_path / "commits.json"
    commits.write_text("[]")
    with pytest.raises(ValueError):
        ddc._commit_validator(commits)
    commits.write_bytes(text("github_commits_derived.json"))
    assert ddc._commit_validator(commits) is True
    assert ddc.parse_commit_date([{"commit": {"committer": {"name": "x", "date": "2026-11-20T09:12:44Z"}}}]) == "2026-11-20"


def test_values_without_an_index_key_are_not_applicable():
    res = run_module(DeepdarkctiIndex, "username:ab", FakeHttp())  # too short for a Telegram handle: nothing read
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
