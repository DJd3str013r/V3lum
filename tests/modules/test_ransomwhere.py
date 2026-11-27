"""ransomwhere (P210): offline match against the Ransomwhere export (disclosure none).

Fixtures in tests/fixtures/ransomwhere/ (prep batch p3-G09-1): ``export_ok.json`` is TRIMMED from the live export of
2026-11-26 (5,575,290 B, 11,186 rows; 8 rows kept, <= 3 transactions each: Conti, Netwalker (Mailto), Locky,
Unlabeled, Ryuk without transactions, Qlocker, the newest row (Akira, 2024-10-29) and a 'REvil / Sodinokibi' alias
row). The addresses are criminal payment addresses (CTI), not personal data. ``api_error_403.json`` is the verbatim
API Gateway answer of a wrong route, ``export_empty.json`` is synthetic, ``export_truncated_malformed.json`` the first
1,500 bytes of a truncated download. The dataset is installed through the real dataset manager over FakeHttp.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import ransomwhere as rw
from v3lum.modules.crypto.ransomwhere import DATASET, EXPORT_URL, Ransomwhere

FX = FIXTURES / "ransomwhere"
CONTI = "bc1qnf273myysxjw23g9hze4vcu3uqkget9ra70hen"
REVIL = "3BeQ9H5tByJK9CeeZftDsBFhgt1i5Q7AQK"
UNLABELED = "3DJK6n5rUYbkbm166dH83C2Pq2pCYrUzTz"
LOCKY = "1kJTyPQ8jPDCvpt2MpnA8R8viLKAGQqyT"
RYUK = "15FC73BdkpDMUWmxo7e7gtLRtM8gQgXyb4"
MISS = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"  # the Bitcoin wiki example address


@pytest.fixture(autouse=True)
def _small_fixture(monkeypatch, clean_registry):
    """The trimmed export holds 8 rows: lower the production floors (>= 1,000 rows, >= 1 MB)."""
    monkeypatch.setattr(rw, "MIN_ROWS", 1)
    monkeypatch.setitem(DATASETS[DATASET], "min_bytes", 10)
    rw._MEMO.clear()


def runtime(body: bytes | None = None, *, status: int = 200, clock: FakeClock | None = None):
    http = FakeHttp()
    rt = make_runtime(http, clock=clock or FakeClock())
    if body is not None:
        http.add("GET", EXPORT_URL, status=status, body=body, headers={"content-type": "application/json"})
    return rt, http


def installed():
    rt, _ = runtime((FX / "export_ok.json").read_bytes())
    result = rt.data.update(DATASET)
    assert result.ok, result.reason
    return rt


def run(entity: str, rt):
    return run_module(Ransomwhere, entity, None, runtime=rt)


# ------------------------------------------------------------------ metadata (cond 1, 3)
def test_metadata_offline_dataset_registration():
    cls = Ransomwhere
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ("ransomwhere.export",))
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "n/a" and cls.shares_input is False
    assert cls.max_tlp.value_str == "red" and cls.accepts == {T.BTC} and cls.produces == {T.THREAT_ACTOR}
    reg = DATASETS[DATASET]
    assert reg["url"] == EXPORT_URL and reg["ttl"] == 7 * 86400 and reg["large"] is True  # weekly, never mid-scan
    assert reg["licence"] == "CC-BY-4.0" and reg["terms_class"] == "open" and "zenodo.6512122" in reg["attribution"]
    notice = json.loads((FIXTURES.parent.parent / "v3lum/data/notices/ransomwhere_dataset.json").read_text())
    assert notice["licence"] == "CC-BY-4.0" and "Cable, Jack. (2024)" in notice["attribution"]


def test_missing_dataset_is_unavailable_never_downloaded_mid_scan():
    rt, http = runtime((FX / "export_ok.json").read_bytes())
    rt.in_scan = True  # large dataset: never downloaded during a scan, only by `v3lum data update`
    res = run(f"btc_address:{CONTI}", rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and http.calls == []


# ------------------------------------------------------------------ cond 2: hits and misses
def test_conti_hit_is_historical_with_payments_and_actor_pivot():
    rt = installed()
    res = run(f"btc_address:{CONTI.upper()}", rt)  # bech32 compared lower-case
    assert res.status is Status.OK and res.requests == 0
    [finding] = res.findings
    assert finding.title == "Ransomware payment address (Ransomwhere, historical)" and finding.severity.label == "high"
    assert set(finding.tags) == {"ransomware", "historical", "crowdsourced"} and finding.source == "ransomwhere.export"
    assert "stale since 2024-10-29" in finding.description and "a lead, not attribution" in finding.description
    assert finding.data["tx_count"] == 3 and finding.data["family"] == "Conti"
    pay = res.attributes["ransomware_payments"]
    assert pay["total_btc"] == "14.05126047" and pay["first_payment"] and pay["last_payment"] >= pay["first_payment"]
    assert len(pay["transactions"]) == 3 and all(len(t["hash"]) == 64 for t in pay["transactions"])
    [actor] = res.pivots
    assert (actor.entity.type, actor.entity.value, actor.relation, actor.expand) == (T.THREAT_ACTOR, "Conti", "attributed_to", False)
    assert actor.confidence_label.value == "probable"
    assert "Zenodo" in res.attributes["data_attribution"]
    assert [d["name"] for d in res.datasets] == [DATASET]  # the copy used is cited


def test_alias_family_gives_one_actor_pivot_per_alias():
    res = run(f"btc_address:{REVIL}", installed())
    assert {p.entity.value for p in res.pivots} == {"REvil", "Sodinokibi"}


def test_unlabeled_rows_have_no_actor_pivot():
    res = run(f"btc_address:{UNLABELED}", installed())
    assert res.status is Status.OK and res.pivots == [] and "not labelled" in res.findings[0].description
    assert "family_unknown" in res.findings[0].data["labels"]


def test_duplicate_transaction_entries_count_once_and_empty_tx_rows_still_hit():
    rt = installed()
    locky = run(f"btc_address:{LOCKY}", rt)
    assert locky.attributes["ransomware_payments"]["tx_count"] == 1  # the export repeats the same tx 3 times
    ryuk = run(f"btc_address:{RYUK}", rt)
    assert ryuk.status is Status.OK and ryuk.attributes["ransomware_payments"]["tx_count"] == 0


def test_miss_means_nothing():
    res = run(f"btc_address:{MISS}", installed())
    assert res.status is Status.EMPTY and res.findings == [] and res.pivots == []
    assert "a miss means nothing" in res.attributes["ransomwhere_status"] and "2024-10-29" in res.attributes["ransomwhere_status"]


# ------------------------------------------------------------------ cond 1: refresh validation keeps the previous copy
@pytest.mark.parametrize("name,status", [("api_error_403.json", 200), ("export_empty.json", 200), ("export_truncated_malformed.json", 200)])
def test_bad_downloads_are_refused(name, status):
    rt, _ = runtime((FX / name).read_bytes(), status=status)
    result = rt.data.update(DATASET)
    assert not result.ok
    rt.in_scan = True
    assert run(f"btc_address:{CONTI}", rt).status is Status.UNAVAILABLE  # nothing installed: could not verify


def test_refused_refresh_keeps_the_good_copy():
    http = FakeHttp()
    http.add("GET", EXPORT_URL, body=(FX / "export_ok.json").read_bytes(), headers={"content-type": "application/json"})
    rt = make_runtime(http, clock=FakeClock())
    assert rt.data.update(DATASET).ok
    rw._MEMO.clear()
    second = FakeHttp().add("GET", EXPORT_URL, body=(FX / "api_error_403.json").read_bytes(), headers={"content-type": "application/json"})
    rt2 = make_runtime(second, clock=FakeClock("2026-12-10T00:00:00Z"))
    assert not rt2.data.update(DATASET).ok  # the error body never replaces the installed export
    assert run(f"btc_address:{CONTI}", rt2).status is Status.OK


def test_index_built_at_refresh_is_reused():
    rt = installed()
    assert rw._MEMO.get("index") and rw._MEMO["index"]["rows"] == 8  # loaded into a dict at refresh (cond 1)
    index = rw._MEMO["index"]
    run(f"btc_address:{CONTI}", rt)
    assert rw._MEMO["index"] is index


# ------------------------------------------------------------------ pure helpers
def test_family_parsing_and_normalisation():
    assert rw.family_names("Netwalker (Mailto)") == {"raw": "Netwalker (Mailto)", "labelled": True, "names": ["Netwalker"], "variant": "Mailto"}
    assert rw.family_names("Unlabeled")["labelled"] is False and rw.family_names(None)["names"] == []
    assert rw.normalize_btc(" BC1QNF273MYYSXJW23G9HZE4VCU3UQKGET9RA70HEN ") == CONTI
    assert rw.normalize_btc("0x1111111111111111111111111111111111111111") is None and rw.normalize_btc(5) is None
    assert rw.btc(162152900) == "1.62152900" and rw.btc(-1) is None
    assert rw.validate_export({"message": "Missing Authentication Token"}).startswith("ransomwhere export has no result list")
    assert rw.validate_export([1]) and rw.validate_export({"result": [{"address": "junk", "family": "x"}]}, min_rows=1)
    assert rw.lookup(rw.build_index({"result": []}), "junk")["status"] == "invalid"
