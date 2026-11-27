"""nrd_feeds (P005): local NRD / release-list matching, DoH-confirmed tagging, stale lists, archive limits.

Fixtures in tests/fixtures/nrd_feeds/ (live 2026-11-26, see the batch notes): ``whoisds_ok.zip`` is the
real WhoisDS list of 2026-11-25 trimmed to 17 of its 70,000 names and re-zipped (member
``domain-names.txt``); ``registrobr_ok.txt`` the real registro.br release list (ISO-8859-1, generated
2026-11-09) with its header, trailer and 15 names; ``registrobr_html_page.html`` the real release-process
page (an SPA shell, scripts removed); ``whoisds_not_available_empty.html`` the real empty HTTP 200 answer
for a date outside the free window; ``challenge_page.html`` a real Cloudflare managed-challenge page
(tokens redacted). Derived: ``registrobr_truncated.txt`` (no trailer), ``registrobr_empty.txt`` (header
and trailer only). Synthetic: the zip bomb (4 MiB of zeros), the 4-member zip and the ``../`` member.
DoH answers are built with ``tests.fakes.doh`` for an internal resolver (offline modules may use only it).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, doh, doh_url, make_runtime, run_module
from v3lum.core.datasets import DATASETS, unregister_dataset
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import nrd_feeds as mod
from v3lum.modules.domain_dns.nrd_feeds import RELEASE_DATASET, RELEASE_URL, NrdFeeds

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nrd_feeds"
DAY = dt.date(2026, 11, 25)
INTERNAL = "https://doh.corp.example/dns-query"
ORG = {"domains": [{"name": "example.org", "verification": "txt_verified"}], "brands": [{"keyword": "outlook"}, {"keyword": "nubank"}]}


@pytest.fixture(autouse=True)
def small_lists(monkeypatch):
    monkeypatch.setattr(mod, "MIN_NAMES", 5)  # the trimmed fixtures hold 17 / 15 names (real lists 70,000 / 125,922)
    monkeypatch.setitem(DATASETS[RELEASE_DATASET], "min_bytes", 10)
    mod._TEXTS.clear()
    mod._RELEASE_META.clear()
    yield
    for name in [n for n in DATASETS if n.startswith(mod.WHOISDS_PREFIX) and n not in mod.WHOISDS_DATASETS]:
        unregister_dataset(name)


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def runtime(*, whoisds: bool = True, release: bool = True, org: dict | None = None, settings: dict | None = None, http: FakeHttp | None = None):
    """A runtime where `v3lum data update` installed the WhoisDS list of DAY and the release list."""
    http = http or FakeHttp()
    clock = FakeClock()
    if whoisds:
        mod.register_whoisds_day(DAY)
        http.add("GET", mod.whoisds_url(DAY), body=fixture_bytes("whoisds_ok.zip"), headers={"content-type": "application/octet-stream"}, times=1)
    if release:
        http.add("GET", RELEASE_URL, body=fixture_bytes("registrobr_ok.txt"), headers={"content-type": "text/plain"}, times=1)
    rt = make_runtime(http, clock=clock, org_profile=OrgProfile.from_dict(org) if org else None, settings=settings)
    if whoisds:
        assert rt.data.update(mod.whoisds_name(DAY)).ok
    if release:
        assert rt.data.update(RELEASE_DATASET).ok
    http.calls.clear()
    return http, rt


def add_internal_dns(http: FakeHttp, name: str, a: list[str], mx: list[str]) -> None:
    http.add("GET", doh_url(name, "A", provider=INTERNAL), json=doh(name, "A", a, status=0 if a else 3))
    http.add("GET", doh_url(name, "MX", provider=INTERNAL), json=doh(name, "MX", mx, status=0 if mx else 3))


def finding_on(res, domain):
    return next(f for f in res.findings if f.entity.value == domain)


# ------------------------------------------------------------------ metadata (cond 1, 5)
def test_contract_metadata():
    cls = NrdFeeds
    assert (cls.terms, cls.disclosure, cls.hosts, cls.provider) == ("open", "none", (), "")
    assert cls.sources == ("whoisds.nrd_daily", "registrobr.release_list") and cls.shares_input is False
    assert cls.default_enabled is True and "watch_source" in cls.tags
    reg = DATASETS[RELEASE_DATASET]
    assert reg["large"] is True and reg["terms_class"] == "open"  # cond 5: never downloaded during a scan
    for name in mod.WHOISDS_DATASETS:
        assert DATASETS[name]["large"] is True and DATASETS[name]["source"] == "whoisds.nrd_daily"
    assert len(mod.WHOISDS_DATASETS) == mod.FREE_DAYS
    assert mod.whoisds_url(DAY).endswith("/MjAyNi0xMS0yNS56aXA=/nrd")  # base64('2026-11-25.zip')


# ------------------------------------------------------------------ local brand matching (cond 1, 8)
def test_brand_lookalikes_matched_locally_and_untagged_without_doh():
    http, rt = runtime(org=ORG)
    res = run_module(NrdFeeds, "keyword:outlook", runtime=rt)
    assert res.status is Status.OK
    hits = {h["domain"]: h for h in res.attributes["nrd_hits"]}
    assert set(hits) == {"outlook-login.com", "msoutlook.help"}
    assert hits["outlook-login.com"]["technique"] == "combo" and hits["outlook-login.com"]["list_date"] == "2026-11-25"
    assert not any(h["tags"] for h in hits.values())  # cond 9: no tag without a DoH confirmation
    f = finding_on(res, "outlook-login.com")
    assert f.severity is Severity.LOW and not f.tags and "not DoH-confirmed" in f.criterion
    assert "internal resolver" in f.description
    assert {p.entity.value for p in res.pivots} == set(hits) and all(p.expand is False and p.relation == "brand_match" for p in res.pivots)
    assert not http.calls  # nothing left the machine: no brand, no keyword, no DoH (public DoH is refused to offline modules)
    summary = next(f for f in res.findings if f.entity.value == "outlook")
    assert summary.severity is Severity.INFO and not summary.tags  # the protected brand itself is never tagged
    assert res.attributes["watch_hits"][0]["first_seen"] == "2026-11-25"


def test_doh_confirmed_hits_are_tagged_and_brand_plus_mx_is_medium():
    http, rt = runtime(org=ORG, settings={"doh_internal": INTERNAL})
    add_internal_dns(http, "outlook-login.com", ["192.0.2.50"], ["10 mx.example.net."])
    add_internal_dns(http, "msoutlook.help", [], [])
    res = run_module(NrdFeeds, "keyword:outlook", runtime=rt)
    confirmed = finding_on(res, "outlook-login.com")
    assert set(confirmed.tags) == {"newly_registered", "typosquat"} and confirmed.severity is Severity.MEDIUM
    unconfirmed = finding_on(res, "msoutlook.help")  # NXDOMAIN: listed, untagged, LOW
    assert not unconfirmed.tags and unconfirmed.severity is Severity.LOW
    assert {c["url"].split("?")[0] for c in http.calls} == {INTERNAL}


def test_confirmations_are_capped_per_run():
    http, rt = runtime(org=ORG, settings={"doh_internal": INTERNAL, "nrd_feeds_confirmations": 1})
    add_internal_dns(http, "outlook-login.com", ["192.0.2.50"], [])
    res = run_module(NrdFeeds, "keyword:outlook", runtime=rt)
    hits = {h["domain"]: h for h in res.attributes["nrd_hits"]}
    assert hits["outlook-login.com"]["confirmed"] is True and hits["msoutlook.help"]["confirmation"] == "not_checked"
    assert len(http.calls) == 2  # A + MX of the strongest hit only


def test_release_list_hits_are_in_release_never_newly_registered():
    _http, rt = runtime(org=ORG)
    res = run_module(NrdFeeds, "keyword:nubank", runtime=rt)
    (hit,) = res.attributes["nrd_hits"]
    assert (hit["domain"], hit["source"], hit["tags"]) == ("nubanks.com.br", "registrobr", ["in_release"])
    f = finding_on(res, "nubanks.com.br")
    assert "in_release" in f.tags and "newly_registered" not in f.tags and f.severity is Severity.LOW


def test_keywords_that_are_not_org_brands_are_not_applicable():
    _http, rt = runtime(org=ORG)
    res = run_module(NrdFeeds, "keyword:paypal", runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_own_domain_seed_protects_that_domain():
    _http, rt = runtime(org={"domains": [{"name": "outlook.com", "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-26"}]})
    res = run_module(NrdFeeds, "domain:outlook.com", runtime=rt)
    assert {h["domain"] for h in res.attributes["nrd_hits"]} >= {"outlook-login.com"}


# ------------------------------------------------------------------ domain inputs (first_seen, release, wording)
def test_domain_in_the_window_gets_first_seen():
    _http, rt = runtime(org=ORG, settings={"doh_internal": INTERNAL})
    add_internal_dns(_http, "outlook-login.com", ["192.0.2.50"], [])
    res = run_module(NrdFeeds, "domain:outlook-login.com", runtime=rt)
    assert res.attributes["nrd_first_seen"] == "2026-11-25"
    (f,) = [f for f in res.findings if f.title == "Listed in a newly registered domains list"]
    assert set(f.tags) == {"newly_registered", "typosquat"} and f.severity is Severity.LOW  # brand match without MX stays LOW
    assert f.observed_first.startswith("2026-11-25")


def test_domain_in_the_release_list_and_own_domain_severity():
    _http, rt = runtime(org={"domains": [{"name": "nubanks.com.br", "verification": "txt_verified"}]})
    res = run_module(NrdFeeds, "domain:nubanks.com.br", runtime=rt)
    f = next(f for f in res.findings if "release process" in f.title)
    assert f.severity is Severity.HIGH and "in_release" in f.tags and f.title.startswith("Own domain")
    assert res.attributes["release_window"]["start"] == "2026-11-11T18:00:00Z"
    _http2, rt2 = runtime()
    res2 = run_module(NrdFeeds, "domain:nubanks.com.br", runtime=rt2)
    assert next(f for f in res2.findings if "release process" in f.title).severity is Severity.LOW


def test_miss_wording_is_honest():
    _http, rt = runtime()
    res = run_module(NrdFeeds, "domain:example.com", runtime=rt)
    assert res.status is Status.EMPTY and res.error == "not in the last 1 days of WhoisDS lists (gTLD coverage only)"
    assert "not newly registered" not in res.error
    br = run_module(NrdFeeds, "domain:exemplo.com.br", runtime=rt)
    assert br.status is Status.EMPTY and br.error.startswith("no NRD feed for .br: CT + permutations + DoH only")
    assert "registro.br release list (2026-11-11 to 2026-11-18)" in br.error
    assert mod.miss_wording("example.com", 30) == "not in the last 30 days of WhoisDS lists (gTLD coverage only)"


# ------------------------------------------------------------------ stale / missing lists (cond 5)
def test_missing_lists_are_unavailable_never_empty():
    res = run_module(NrdFeeds, "domain:example.com", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and mod.NOT_DOWNLOADED in res.error


def test_stale_lists_are_unavailable_but_hits_still_count():
    _http, rt = runtime(org=ORG)
    rt.clock.advance(49 * 3600)
    miss = run_module(NrdFeeds, "domain:example.com", runtime=rt)
    assert miss.status is Status.UNAVAILABLE and miss.reason_code == "dataset" and "whoisds: stale" in miss.error
    assert miss.source_statuses["whoisds.nrd_daily"]["reason_code"] == "dataset"
    hit = run_module(NrdFeeds, "domain:outlook-login.com", runtime=rt)
    assert hit.status is Status.OK and hit.attributes["nrd_first_seen"] == "2026-11-25"


def test_a_missing_feed_that_does_not_cover_the_name_is_ignored():
    _http, rt = runtime(release=False)
    res = run_module(NrdFeeds, "domain:example.com", runtime=rt)
    assert res.status is Status.EMPTY  # registro.br lists only .br names
    br = run_module(NrdFeeds, "domain:exemplo.com.br", runtime=rt)
    assert br.status is Status.UNAVAILABLE and "registrobr" in br.error


def test_older_window_copies_are_read_in_place():
    old = DAY - dt.timedelta(days=12)  # outside the free window: registered at run time from its local copy
    http = FakeHttp()
    mod.register_whoisds_day(old)
    http.add("GET", mod.whoisds_url(old), body=fixture_bytes("whoisds_ok.zip"), times=1)
    rt = make_runtime(http, clock=FakeClock())
    assert rt.data.update(mod.whoisds_name(old)).ok
    unregister_dataset(mod.whoisds_name(old))  # a new process: only the free window is registered at import
    res = run_module(NrdFeeds, "domain:paypalbz.live", runtime=rt)
    assert res.attributes["nrd_first_seen"] == old.isoformat()
    assert mod.whoisds_name(old) in DATASETS


# ------------------------------------------------------------------ archive limits and bad downloads (cond 5, 6, 11)
@pytest.mark.parametrize(("fixture", "reason"), [
    ("whoisds_zip_bomb_synthetic.zip", "ratio"),
    ("whoisds_too_many_members_synthetic.zip", "members"),
    ("whoisds_unsafe_member_synthetic.zip", "parent directory"),
    ("whoisds_not_available_empty.html", "short body"),
    ("challenge_page.html", ""),
])
def test_bad_downloads_never_replace_the_last_good_copy(fixture, reason):
    http, rt = runtime(release=False)
    name = mod.whoisds_name(DAY)
    before = rt.data.info(name).sha256
    http.add("GET", mod.whoisds_url(DAY), body=fixture_bytes(fixture),
             headers={"content-type": "text/html" if fixture.endswith(".html") else "application/octet-stream"})
    result = rt.data.update(name)
    assert result.status == "failed" and reason in result.reason
    assert rt.data.info(name).sha256 == before  # the last good copy stays
    res = run_module(NrdFeeds, "domain:outlook-login.com", runtime=rt)
    assert res.attributes["nrd_first_seen"] == "2026-11-25"


@pytest.mark.parametrize("fixture", ["registrobr_truncated.txt", "registrobr_empty.txt", "registrobr_html_page.html", "challenge_page.html"])
def test_bad_release_lists_never_replace_the_cached_copy(fixture):
    http, rt = runtime(whoisds=False)
    http.add("GET", RELEASE_URL, body=fixture_bytes(fixture), headers={"content-type": "text/plain"})
    assert rt.data.update(RELEASE_DATASET).status == "failed"
    res = run_module(NrdFeeds, "domain:nubanks.com.br", runtime=rt)
    assert any("release process" in f.title for f in res.findings)


def test_in_memory_reader_limits():
    good = mod.read_zip_member(fixture_bytes("whoisds_ok.zip"))
    assert "outlook-login.com" in good and good.count("\n") >= 16
    for fixture, reason in (("whoisds_zip_bomb_synthetic.zip", "ratio"), ("whoisds_too_many_members_synthetic.zip", "members"),
                            ("whoisds_unsafe_member_synthetic.zip", "unsafe"), ("challenge_page.html", "not a zip")):
        with pytest.raises(mod.ZipProblem, match=reason):
            mod.read_zip_member(fixture_bytes(fixture))


def test_release_list_is_decoded_as_iso_8859_1():
    parsed = mod.parse_release_list(fixture_bytes("registrobr_ok.txt"))
    assert parsed["error"] is None and parsed["complete"] is True and len(parsed["names"]) == 15
    assert (parsed["window_start"], parsed["window_end"], parsed["generated_at"]) == (
        "2026-11-11T18:00:00Z", "2026-11-18T18:00:00Z", "2026-11-09T13:00:05Z")
    assert mod.parse_release_list(fixture_bytes("registrobr_truncated.txt"))["error"].startswith("truncated")


def test_doh_confirmation_rules():
    class A:
        def __init__(self, records=(), ok=True, nxdomain=False, cnv=False, error=""):
            self.records, self.ok, self.nxdomain, self.could_not_verify, self.error = list(records), ok, nxdomain, cnv, error

    assert mod.doh_confirmation(A(["192.0.2.1"]), None)["confirmed"] is True
    null_mx = mod.doh_confirmation(A([]), A(["0 ."]))
    assert null_mx["confirmed"] is False and null_mx["mx"] is False  # RFC 7505 null MX never confirms
    assert mod.doh_confirmation(A(ok=False, nxdomain=True), A(ok=False, nxdomain=True))["state"] == "nxdomain"
    assert mod.doh_confirmation(A(ok=False, cnv=True, error="SERVFAIL"), None)["state"] == "could_not_verify"
    assert mod.severity_for("whoisds", True, True, True) == "medium" and mod.severity_for("whoisds", True, False, True) == "low"
    assert mod.severity_for("registrobr", True, True, True) == "low"


def test_tlp_red_keeps_matching_local():
    _http, rt = runtime(org=ORG)
    from v3lum.core.context import ScanOptions

    res = run_module(NrdFeeds, "keyword:outlook", runtime=rt, options=ScanOptions(tlp="red"))
    assert res.status is Status.OK and {h["domain"] for h in res.attributes["nrd_hits"]} == {"outlook-login.com", "msoutlook.help"}
    assert T.DOMAIN in NrdFeeds.produces
