"""card_bin (P318, batch p3-G12-1): binlist.net BIN lookup and the PCI minimisation guarantee."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.utility import card_bin as CB
from v3lum.modules.utility.card_bin import CardBin

URL = "https://lookup.binlist.net/{}"
ACCEPT_V3 = {"Accept-Version": "3"}
PANS = ("4111111111111111", "5555555555554444", "378282246310005", "6362970000457013")


def env(name: str) -> dict:
    data = module_fixture("card_bin", name)
    kw = {"status": data["status"], "headers": data.get("headers") or {}}
    body = data["body"]
    if isinstance(body, str):
        kw["text"] = body
    else:
        kw["json"] = body
    return kw


def test_ok_only_the_bin6_is_sent_with_accept_version_3():
    http = FakeHttp().add("GET", URL.format("457173"), match_headers=ACCEPT_V3, **env("binlist_ok.json"))
    res = run_module(CardBin, "card_bin:45717360", http)
    assert res.status is Status.OK
    info = res.attributes["card_bin_info"]
    assert info["scheme"] == "visa" and info["type"] == "debit" and info["brand"] == "Visa Classic/Dankort"
    assert info["country"]["alpha2"] == "DK" and info["bank"]["name"] == "Jyske Bank A/S"
    assert res.attributes["card_scheme"] == "visa" and res.attributes["country"] == "DK"
    f = res.findings[0]
    assert f.severity.name == "INFO" and f.source == "binlist.lookup" and "own_asset" not in f.tags
    assert res.pivots == []
    assert http.urls() == [URL.format("457173")]  # never the 8-digit BIN, never a PAN
    http.assert_hosts_within(CardBin)


def test_empty_fields_in_200_is_empty_never_unknown_bin():
    http = FakeHttp().add("GET", URL.format("100000"), **env("binlist_empty_in_200.json"))
    res = run_module(CardBin, "card_bin:100000", http)
    assert res.status is Status.EMPTY
    assert "not proof" in res.error and "unknown BIN" not in res.error


def test_404_is_a_documented_absence():
    http = FakeHttp().add("GET", URL.format("999999"), **env("binlist_not_found_404.json"))
    res = run_module(CardBin, "card_bin:999999", http)
    assert res.status is Status.EMPTY


def test_429_is_rate_limited_never_unknown_bin():
    http = FakeHttp().add("GET", URL.format("457173"), **env("binlist_rate_limited_429.json"), times=2)
    res = run_module(CardBin, "card_bin:457173", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_cloudflare_challenge_is_blocked():
    http = FakeHttp().add("GET", URL.format("457173"), **env("binlist_challenge_403.json"))
    res = run_module(CardBin, "card_bin:457173", http)
    assert res.status is Status.BLOCKED


def test_400_invalid_input_and_5xx_are_errors():
    http = FakeHttp().add("GET", URL.format("000000"), **env("binlist_invalid_400.json"))
    assert run_module(CardBin, "card_bin:000000", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", URL.format("457173"), status=502, text="bad gateway", times=3)
    assert run_module(CardBin, "card_bin:457173", http2).status is Status.ERROR


def test_malformed_json_and_html_in_200_are_errors_never_empty():
    http = FakeHttp().add("GET", URL.format("457173"), text="{not json", headers={"content-type": "application/json"})
    assert run_module(CardBin, "card_bin:457173", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", URL.format("457174"), json=["unexpected"])
    assert run_module(CardBin, "card_bin:457174", http2).status is Status.ERROR


def test_own_bin_is_tagged_own_asset():
    org = OrgProfile.from_dict({"card_bins": ["457173"]})
    http = FakeHttp().add("GET", URL.format("457173"), **env("binlist_ok.json"))
    res = run_module(CardBin, "card_bin:45717360", http, org_profile=org)
    assert "own_asset" in res.findings[0].tags
    assert CB.own_bin_match("457173", ["45717360"]) == "possible_own"
    assert CB.own_bin_match("999999", ["457173"]) is None


def test_card_bin_entity_never_holds_more_than_8_digits():
    assert Entity.try_make(T.CARD_BIN, "4111111111111111") is None
    card = Entity.make(T.PAYMENT_CARD, "4111 1111 1111 1111")
    assert "4111111111111111" not in card.value and card.value.startswith("411111")
    try:
        CB.binlist_url("4111111111111111")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("a PAN must never become a request")


def test_offline_pan_helpers_truncate_and_mask():
    text = (Path(__file__).parents[1] / "fixtures" / "card_bin" / "pan_text_synthetic.txt").read_text(encoding="utf-8")
    found = CB.find_pans(text)
    assert [p["display"] for p in found] == ["411111******1111", "555555******4444", "378282*****0005", "636297******7013"]
    assert all("4111111111111111" not in json.dumps(p) for p in found)
    masked = CB.mask_pans_in_text(text)
    for pan in PANS:
        assert pan not in masked
    assert "00.000.000/0001-91" in masked and "1234567890123" in masked  # CNPJ and Luhn-invalid numbers kept
    t = CB.truncate_pan("4111 1111 1111 1111")
    assert t["bin6"] == "411111" and t["last4"] == "1111" and t["luhn_valid"] is True
    assert CB.scheme_guess("6362970000457013") == "elo"


def test_pan_never_reaches_cache_evidence_logs_or_case_db(caplog):
    """FC1: a scan of a text holding card numbers keeps only BIN6...last4 anywhere on disk or in logs."""
    from v3lum.core import ioc
    from v3lum.core.store import Store

    raw = (Path(__file__).parents[1] / "fixtures" / "card_bin" / "pan_text_synthetic.txt").read_text(encoding="utf-8")
    text = ioc.scrub(raw)  # the input path every seed takes (App.scrub_input, P145 cond 5 / AR24)
    http = (FakeHttp().add("GET", URL.format("411111"), **env("binlist_ok.json"))
            .add("GET", URL.format("457173"), **env("binlist_ok.json")))
    rt = make_runtime(http, cache=True)
    opts = ScanOptions(include={"ioc_extract", "card_bin"}, include_disabled=True, purpose="pci test", tlp="amber")
    seeds = [Entity.make(T.TEXT, text), Entity.make(T.CARD_BIN, "457173")]
    case = Engine(rt, opts).investigate(seeds)
    Store().save_case(case.to_dict())
    blob = json.dumps(case.to_dict(), default=str) + caplog.text + json.dumps([c for c in http.calls], default=str)
    home = Path(paths.home())
    for f in home.rglob("*"):
        if f.is_file():
            data = f.read_bytes()
            if f.suffix in (".db", ".sqlite") or data[:16] == b"SQLite format 3\x00":
                con = sqlite3.connect(str(f))
                try:
                    for (sql,) in con.execute("SELECT 'x'"):
                        pass
                    dump = "\n".join(con.iterdump())
                finally:
                    con.close()
                blob += dump
            blob += data.decode("utf-8", "replace")
    for pan in PANS:
        forms = {pan, " ".join(pan[i:i + 4] for i in range(0, len(pan), 4)), "-".join(pan[i:i + 4] for i in range(0, len(pan), 4))}
        assert not any(form in blob for form in forms), f"PAN ending {pan[-4:]} leaked"
    # only the BIN ever left the host
    assert all(c["url"].rsplit("/", 1)[-1].isdigit() and len(c["url"].rsplit("/", 1)[-1]) == 6 for c in http.calls)


def test_metadata_matches_the_council_decision():
    assert CardBin.terms == "unknown" and CardBin.default_enabled is False  # FC2: no published terms
    assert CardBin.trust_tier == "community" and CardBin.cache_ttl == 30 * 86400
    assert CardBin.accepts == frozenset({T.CARD_BIN}) and CardBin.max_requests == 1
