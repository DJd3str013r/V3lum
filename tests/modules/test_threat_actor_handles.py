"""P195 threat_actor_handles: offline exact match on the spmedia forum user lists (batch p2-G05-2).

The lists used here are format-faithful synthetic files (no real handle is ever committed, cond 6);
the README fixture is the real dataset README trimmed to headings, links, dates and amounts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.cti_framework import threat_actor_handles as tah
from v3lum.modules.cti_framework.threat_actor_handles import ThreatActorHandles

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "threat_actor_handles"
LISTS = tah.lists_manifest()
#: which real list file serves which synthetic fixture in these tests
SERVED = {"forum_users_xss.txt": "forum_users_examplehub.txt", "forum_users_dread.txt": "dead_forum_users_oldboard.txt",
          "dnm_users_drughub.txt": "dnm_users_examplemarket.txt"}
FILLER = b"zz_filler_example\n"


def lists_http(*, missing: tuple[str, ...] = (), readme: bool = False) -> FakeHttp:
    http = FakeHttp()
    for item in LISTS:
        url = tah.RAW.format(file=item["file"])
        if item["file"] in missing:
            doc = module_fixture("threat_actor_handles", "file_not_found.http.json")
            http.add("GET", url, status=doc["status"], text=doc["body"], headers={"content-type": "text/plain; charset=utf-8"})
            continue
        body = (FIX / SERVED[item["file"]]).read_bytes() if item["file"] in SERVED else FILLER
        http.add("GET", url, body=body, headers={"content-type": "text/plain; charset=utf-8"})
    if readme:
        http.add("GET", tah.RAW.format(file="README.md"), body=(FIX / "readme_ok.md").read_bytes(), headers={"content-type": "text/plain"})
    return http


# ------------------------------------------------------------------------------------- metadata (cond 1/2)


def test_metadata_offline_opt_in_and_datasets():
    cls = ThreatActorHandles
    assert (cls.disclosure, cls.hosts, cls.provider, cls.category) == ("none", (), "", "cti_framework")
    assert cls.default_enabled is False and cls.run_on == "seeds" and cls.terms == "open" and cls.trust_tier == "n/a"
    assert cls.max_tlp.value_str == "red" and cls.max_pivots == 0
    assert len(LISTS) == 18  # the 9 dead-forum lists answered 404 upstream on 2026-11-26: listed, not registered
    gone = {i["file"] for i in tah.missing_upstream_lists()}
    assert "dead_forum_users_nohide_io.txt" in gone and "dead_forum_users_ramp.txt" in gone and not gone & {i["file"] for i in LISTS}
    assert not any(tah.dataset_name(f) in DATASETS for f in gone)
    for item in LISTS:
        reg = DATASETS[tah.dataset_name(item["file"])]
        assert reg["url"] == tah.RAW.format(file=item["file"]) and reg["large"] is True
        assert (reg["licence"], reg["terms_class"], reg["source"]) == ("MIT", "open", tah.SOURCE)
    assert DATASETS[tah.README_DATASET]["large"] is True
    assert "threatactorusernames.com" not in " ".join(cls.hosts)  # cond 2: the TAU API is not in this build


# ------------------------------------------------------------------------------------- matching (cond 3/4/6)


def test_hit_is_info_possible_context_only_without_pivots():
    http = lists_http()
    res = run_module(ThreatActorHandles, "username:example_actor", http)
    assert res.status is Status.OK and res.requests == 0  # dataset downloads only: the handle never leaves the machine
    assert res.pivots == []  # never auto-expanded, no identity link
    f = res.findings[0]
    assert f.severity.label == "info" and f.confidence_label.value == "possible" and f.confidence <= 0.3
    assert {"weak_signal", "context_only"} <= set(f.tags)  # never scored, never counted in CR27
    assert "a user with the same handle appears on forum lists:" in f.description and "collision likely" in f.description
    assert "XSS.pro" in f.description and "Dread" in f.description and "Drughub" in f.description
    assert "9 dead-forum list(s) are gone upstream" in f.description
    assert set(f.data) == {"handle", "forums", "lists_checked"} and f.data["handle"] == "example_actor"
    lists = {h["forum"]: h for h in res.attributes["forum_handle_lists"]}
    assert set(lists) == {"xss", "dread", "drughub"}
    assert lists["xss"]["status"] == "active" and len(lists["xss"]["list_date"]) == 10  # ongoing: the local copy's date
    assert res.raw["lists_missing_upstream"] == 9
    assert {d["name"] for d in res.datasets} >= {tah.dataset_name("forum_users_xss.txt")}


@pytest.mark.parametrize("entity", ["username:EXAMPLE_ACTOR", "username:zz_example_vendor", "username:octocat",
                                    "threat_actor:Example Actor", "threat_actor:#example_hash", "threat_actor:Пример"])
def test_exact_case_folded_matches(entity):
    res = run_module(ThreatActorHandles, entity, lists_http())
    assert res.status is Status.OK, res.error


def test_benign_octocat_collides_on_two_lists():
    res = run_module(ThreatActorHandles, "username:octocat", lists_http())
    assert {h["forum"] for h in res.attributes["forum_handle_lists"]} == {"xss", "dread"}


def test_partial_handles_never_match():
    res = run_module(ThreatActorHandles, "username:example_acto", lists_http())
    assert res.status is Status.EMPTY and "18 local forum list" in res.error and "gone upstream" in res.error


@pytest.mark.parametrize("handle,why", [("ab", "shorter"), ("abc1", "shorter"), ("123456789", "numeric"), ("james", "common"),
                                        ("administrator", "common")])
def test_short_numeric_and_common_handles_are_skipped(handle, why):
    http = FakeHttp()
    res = run_module(ThreatActorHandles, f"username:{handle}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and why in res.error
    assert http.calls == []  # no list is even read


def test_dictionary_words_are_labelled_low_signal():
    res = run_module(ThreatActorHandles, "username:falcon", lists_http())
    assert res.status is Status.OK
    assert res.attributes["collision_reason"] == "common handle: low signal"
    assert "high_collision" in res.findings[0].tags and "low signal" in res.findings[0].description


def test_threat_actor_entities_are_matched_too():
    res = run_module(ThreatActorHandles, "threat_actor:example_actor", lists_http())
    assert res.status is Status.OK


# ------------------------------------------------------------------------------------- availability


def test_a_missing_upstream_list_is_reported_and_the_rest_answers():
    res = run_module(ThreatActorHandles, "username:example_actor", lists_http(missing=("forum_users_cracked.txt",)))
    assert res.status is Status.OK
    status = res.source_statuses[tah.SOURCE]
    assert status["status"] == "unavailable" and status["reason_code"] == "dataset"
    assert "1 list(s) were not available" in res.findings[0].description


def test_a_miss_with_missing_lists_says_so():
    res = run_module(ThreatActorHandles, "username:unlisted_example", lists_http(missing=("forum_users_cracked.txt",)))
    assert res.status is Status.EMPTY and "could not verify those" in res.error


def test_never_downloaded_and_offline_is_unavailable_dataset():
    rt = make_runtime(FakeHttp(), offline=True)
    res = run_module(ThreatActorHandles, "username:example_actor", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code in ("dataset", "offline")


def test_readme_dates_are_used_when_present():
    http = lists_http(readme=True)
    rt = make_runtime(http)
    rt.data.update(tah.README_DATASET)
    res = run_module(ThreatActorHandles, "username:example_actor", runtime=rt)
    lists = {h["forum"]: h for h in res.attributes["forum_handle_lists"]}
    assert lists["xss"]["date_range"] == "December 25 2025 to current date"
    assert lists["drughub"]["date_range"] == "September 04 2026 to current date"


def test_health_selftest():
    hc = ThreatActorHandles.health_check()
    assert hc.offline is True
    assert hc.selftest(make_ctx(ThreatActorHandles, FakeHttp())).status == "dead"
    rt = make_runtime(lists_http())
    run_module(ThreatActorHandles, "username:example_actor", runtime=rt)
    assert hc.selftest(make_ctx(ThreatActorHandles, runtime=rt)).status == "ok"


# ------------------------------------------------------------------------------------- privacy (cond 5)


def test_pivots_are_refused():
    http = FakeHttp()
    res = run_module(ThreatActorHandles, "username:example_actor", http, is_seed=False, depth=1,
                     provenance=(("email:analyst@example.com", "email_local_part", "email_basics"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_org_identity_provenance_needs_an_insider_case_with_purpose():
    org = {"domains": [{"name": "example.com", "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-01"}]}
    prov = (("email:dev@example.com", "same_person", "email_basics"),)
    res = run_module(ThreatActorHandles, "username:example_actor", FakeHttp(), provenance=prov, org_profile=org)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "own-domain e-mail" in res.error
    options = ScanOptions(purpose="insider investigation INC-1", subject_roles={"email:dev@example.com": "insider"})
    res = run_module(ThreatActorHandles, "username:example_actor", lists_http(), provenance=prov, org_profile=org, options=options)
    assert res.status is Status.OK
    other = (("email:someone@example.org", "same_person", "email_basics"),)
    assert run_module(ThreatActorHandles, "username:example_actor", lists_http(), provenance=other, org_profile=org).status is Status.OK


# ------------------------------------------------------------------------------------- parsing helpers


def test_line_format_edge_cases():
    crlf = (FIX / "crlf_bom.txt").read_bytes()
    assert tah.lookup_in_text(crlf, "example_actor") and tah.lookup_in_text(crlf, "padded_example")
    bad = (FIX / "malformed.bin").read_bytes()
    assert tah.lookup_in_text(bad, "good_example") and not tah.lookup_in_text(bad, "bad")
    assert tah.normalise_handle("  Example Actor ") == "example actor"
    assert tah.normalise_handle("a\nb") is None and tah.normalise_handle("x" * 300) is None and tah.normalise_handle(5) is None


def test_manifest_matches_the_trimmed_readme():
    readme = (FIX / "readme_ok.md").read_text(encoding="utf-8")
    by_file = {i["file"]: i for i in LISTS}
    for name in ("forum_users_xss.txt", "forum_users_cracked.txt", "dnm_users_drughub.txt"):
        assert name in readme and name in by_file
    gone = {i["file"]: i for i in tah.missing_upstream_lists()}
    assert gone["forum_users_breachforumsBF.txt"]["status"] == "dead"  # listed under 'Dead Forums', gone upstream
    assert by_file["forum_users_xss.txt"]["ongoing"] is True


def test_ended_lists_use_their_readme_end_date():
    class Info:
        fetched_at = "2026-11-26T10:00:00Z"

    class Data:
        def info(self, name):
            return Info()

    class Ctx:
        data = Data()

    ended = {"file": "dead_forum_users_example.txt", "forum": "example", "title": "Example", "status": "dead", "date_end": "2026-01", "ongoing": False}
    assert ThreatActorHandles._hit(Ctx(), ended, "x", {})["list_date"] == "2026-01"
    ongoing = {**ended, "ongoing": True, "date_end": None}
    assert ThreatActorHandles._hit(Ctx(), ongoing, "x", {})["list_date"] == "2026-11-26"
