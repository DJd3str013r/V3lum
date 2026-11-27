"""crypto_address_labels (P358, batch p2-G09-3): GraphSense TagPacks + manual PoR imports + team label file.

Fixtures in tests/fixtures/crypto_address_labels/ (built from the prep material, see its MANIFEST):
real GraphSense packs minimised from commit 507756d2 (exchange-wallets-binance/okx, ofac, aidecisions_ofac
(organisations only), ransomware, etherscamdb, hacks, usdt_blacklist, etherscan word cloud, 1inch defi,
plustoken with its real corrupted base58 tag, the demo pack with no tags, a derived truncated transfer) and
the ActorPack (14 actors), packed like a codeload/git-archive zip (commit id as zip comment); the OKX PoR
CSV in OKX's documented format, a generic PoR CSV derived from Binance's 2022 list, the live OKX PoR page
(no address data), the observed Binance 202 interstitial and egress 403, and synthetic team label files
(documentation addresses, fictional institutions, example.com contacts).

``parsed/*.json`` holds what ``yaml.safe_load`` returns for each YAML fixture (recorded with PyYAML 6.0.3):
the venv of this repository has no PyYAML (optional extra 'yaml'), so the pipeline runs here with a
recording double that only replays those results; :func:`test_recorded_parse_matches_pyyaml` checks the
recording against the real ``yaml.safe_load`` wherever PyYAML is installed.
"""

from __future__ import annotations

import copy
import inspect
import io
import json
import os
import stat
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum.core import datasets, policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import crypto_address_labels as CAL
from v3lum.modules.crypto.crypto_address_labels import CryptoAddressLabels

FIX = FIXTURES / "crypto_address_labels"
ARCHIVE_URL = "https://github.com/graphsense/graphsense-tagpacks/archive/refs/heads/master.zip"
CODELOAD_URL = "https://codeload.github.com/graphsense/graphsense-tagpacks/zip/refs/heads/master"
ARCHIVE = (FIX / "archive_ok.zip").read_bytes()
COMMIT = "507756d2a8ad0a60d148ee2fe56bf559a747f250"
BINANCE_BTC = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
OKX_BTC = "13jTtHxBPFwZkaCdm6BwJMMJkqvTpBZccw"
TRON_UNLABELLED = "TDvSsdrNM5eeXNL3czpa6AxLDHZA9nwe9K"  # private-key-2 test vector
TEAM_TRON = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"  # private-key-1 test vector
OKX_PAGE = "https://www.okx.com/en-br/proof-of-reserves"


def recorded_safe_load():
    """A replay of the recorded ``yaml.safe_load`` results of the fixture texts (named and placed like
    ``yaml.safe_load`` so the FC1 loader guard accepts it); any other text is refused."""
    twins = {}
    for path in FIX.glob("*.yaml"):
        twins[path.read_bytes().decode("utf-8-sig")] = json.loads((FIX / "parsed" / f"{path.stem}.json").read_text(encoding="utf-8"))

    def safe_load(text):
        twin = twins.get(text)
        if twin is None:
            raise ValueError("text without a recorded yaml.safe_load result")
        if not twin["ok"]:
            raise ValueError(twin["error"])
        return copy.deepcopy(twin["doc"])

    safe_load.__module__ = "yaml"
    return safe_load


@pytest.fixture()
def loader(monkeypatch):
    """The real yaml.safe_load when PyYAML is installed, else the recorded replay."""
    real = CAL.yaml_safe_load()
    chosen = real or recorded_safe_load()
    monkeypatch.setattr(CAL, "yaml_safe_load", lambda: chosen)
    return chosen


def archive_http(body: bytes = ARCHIVE, **route) -> FakeHttp:
    http = FakeHttp()
    http.add("GET", ARCHIVE_URL, status=302, redirect_to=CODELOAD_URL)  # github.com -> codeload (same provider)
    http.add("GET", CODELOAD_URL, body=body, headers={"content-type": "application/zip"}, **route)
    return http


def installed(*, settings=None, body: bytes = ARCHIVE):
    http = archive_http(body)
    rt = make_runtime(http, settings=settings)
    result = rt.data.update(CAL.GS_DATASET)
    assert result.status == "updated", result.reason
    return rt, http


def run(rt, entity):
    return run_module(CryptoAddressLabels, entity, runtime=rt)


def team_file(tmp_path, name="team_labels.json", doc=None):
    path = tmp_path / "team.json"
    if doc is None:
        path.write_bytes((FIX / name).read_bytes())
    else:
        path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ------------------------------------------------------------------ metadata (FC1, council metadata)
def test_metadata_offline_open_default_enabled():
    cls = CryptoAddressLabels
    assert (cls.disclosure, cls.hosts, cls.provider, cls.access_model) == ("none", (), "", "offline")
    assert cls.sources == ("github.crypto_address_labels_graphsense_tagpacks",) and cls.terms == "open"
    assert cls.default_enabled is True and cls.shares_input is False and cls.trust_tier == "n/a"
    assert cls.max_tlp.value_str == "red"  # the address never leaves the machine
    assert cls.accepts == {T.BTC, T.ETH, T.CRYPTO} and cls.produces == {T.ORG}
    assert cls.max_requests == 0 and cls.requires_packages == ()  # PoR/team labels work without PyYAML
    reg = datasets.DATASETS[CAL.GS_DATASET]
    assert reg["url"] == ARCHIVE_URL and reg["large"] is True and reg["ttl"] == 7 * 86400 and reg["archive"] is None
    assert reg["source"] == CAL.GS_SOURCE and reg["terms_class"] == "open" and "MIT" in reg["licence"]
    assert "Iknaio" in reg["attribution"]


def test_module_never_fetches_anything_and_uses_safe_load_only():
    source = inspect.getsource(CAL)
    assert "ctx.http" not in source and "ctx.net" not in source  # FC1/FC2: offline; PoR pages never fetched
    assert "yaml.load(" not in source and "full_load" not in source.replace("load/full_load", "")
    for bad in (json.loads, lambda text: text):
        with pytest.raises(ValueError):
            CAL.check_yaml_loader(bad)


def test_bundled_team_file_is_clean_and_lists_brazilian_exchanges():
    doc = json.loads((CAL.Path(datasets.__file__).parent.parent / "data" / CAL.TEAM_BUNDLED).read_text(encoding="utf-8"))
    parsed = CAL.parse_team_labels(doc, origin="team_file_bundled")
    assert parsed["problems"] == [] and parsed["labels"] == []
    insts = parsed["institutions"]
    assert {"mercadobitcoin", "foxbit", "novadax"} <= set(insts)
    assert all(i["country"] == "BR" and i["provenance"]["reference"].startswith("https://") for i in insts.values())


# ------------------------------------------------------------------ FC1: archive refresh, safe reader, index
def test_refresh_reads_archive_in_memory_and_indexes(loader, tmp_path):
    rt, http = installed()
    assert http.urls() == [ARCHIVE_URL, CODELOAD_URL]
    info = rt.data.info(CAL.GS_DATASET)
    path = CAL.index_path(info.sha256)
    assert path.is_file() and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    meta = CAL.LabelIndex(path).meta()
    assert meta["commit"] == COMMIT and meta["commit_date"] == "2026-11-18"
    assert int(meta["packs"]) == 12 and int(meta["tags"]) > 30 and meta["packs_refused"] == "1"
    assert "zz_truncated_transfer.yaml: yaml_error" in meta["problems"]  # one malformed pack refused, others indexed
    assert meta["actorpack_lastmod"] == "2026-10-14" and meta["actors"] == "14"
    # nothing was extracted next to the dataset: only the archive and its index exist
    extracted = [p.name for p in CAL.paths.datasets_dir().rglob("*.yaml")]
    assert extracted == []


def test_refresh_without_pyyaml_fails_and_module_reports_package(monkeypatch):
    monkeypatch.setattr(CAL, "yaml_safe_load", lambda: None)
    rt = make_runtime(archive_http())
    result = rt.data.update(CAL.GS_DATASET)
    assert result.status == "failed" and "PyYAML" in result.reason
    res = run(rt, f"btc_address:{BINANCE_BTC}")
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "package")
    assert "could not verify" in res.error and "v3lum[yaml]" in res.error


@pytest.mark.parametrize(
    ("route", "expect"),
    [
        ({"status": 403, "body": (FIX / "archive_blocked_egress_403.json").read_bytes(), "headers": {"content-type": "application/json"}}, ("403", "blocked", "challenge")),
        ({"status": 429, "text": "slow down"}, ("rate", "429")),
        ({"status": 503, "text": "unavailable"}, ("503", "error", "unavailable")),
        ({"status": 200, "body": (FIX / "por_okx_page.html").read_bytes(), "headers": {"content-type": "text/html"}}, ("zip", "html", "short body")),
    ],
)
def test_refresh_failures_install_nothing_and_never_read_as_no_label(loader, route, expect):
    http = FakeHttp()
    http.add("GET", ARCHIVE_URL, status=302, redirect_to=CODELOAD_URL)
    http.add("GET", CODELOAD_URL, **route)
    rt = make_runtime(http)
    result = rt.data.update(CAL.GS_DATASET)
    assert result.status == "failed" and result.reason
    assert any(word in result.reason.lower() for word in expect), result.reason
    assert not rt.data.info(CAL.GS_DATASET).present
    res = run(rt, f"other_crypto_address:{TRON_UNLABELLED}")
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset")  # could not verify, never EMPTY


def _zip(members: dict[str, bytes], *, comment: bytes = COMMIT.encode(), method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        zf.comment = comment
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_read_archive_refuses_unsafe_or_bomb_archives(loader):
    pack = (FIX / "tagpack_ransomware.yaml").read_bytes()
    ok = CAL.read_archive(_zip({"graphsense-tagpacks-master/packs/ransomware.yaml": pack}), loader=loader)
    assert ok["commit"] == COMMIT and [m[1] for m in ok["members"]] == ["packs/ransomware.yaml"]
    with pytest.raises(ValueError, match="unsafe zip member names"):
        CAL.read_archive(_zip({"graphsense-tagpacks-master/packs/../../evil.yaml": pack}), loader=loader)
    with pytest.raises(ValueError, match="ratio"):
        CAL.read_archive(_zip({"graphsense-tagpacks-master/packs/bomb.yaml": b"a" * (3 * 1024 * 1024)}), loader=loader)
    with pytest.raises(ValueError, match="not a graphsense-tagpacks archive"):
        CAL.read_archive(_zip({"other-repo/packs/x.yaml": pack}), loader=loader)
    with pytest.raises(ValueError, match="not a zip"):
        CAL.read_archive((FIX / "por_okx_page.html").read_bytes(), loader=loader)
    with pytest.raises(ValueError):
        CAL.read_archive(ARCHIVE[: len(ARCHIVE) // 2], loader=loader)  # truncated download
    with pytest.raises(ValueError):
        CAL.read_archive(ARCHIVE, loader=json.loads)  # FC1: never another loader


def test_archive_member_selection_never_uses_names_as_paths():
    sel = CAL.tagpack_archive_members([
        "graphsense-tagpacks-master/", "graphsense-tagpacks-master/packs/a.yaml",
        "graphsense-tagpacks-master/packs/defi_updated/b.yaml", "graphsense-tagpacks-master/actors/graphsense.actorpack.yaml",
        "graphsense-tagpacks-master/tools/check_actor_links.py", "/etc/passwd", "graphsense-tagpacks-master/packs/..\\x.yaml",
    ])
    assert sel["prefix"] == "graphsense-tagpacks-master/"
    assert [r for _m, r in sel["tagpacks"]] == ["packs/a.yaml", "packs/defi_updated/b.yaml"]
    assert [r for _m, r in sel["actorpacks"]] == ["actors/graphsense.actorpack.yaml"]
    assert sel["ignored"] == 1 and len(sel["rejected"]) == 2
    assert CAL.archive_listing_problem([("a", 10, 1)] * 2001) == "too_many_members"
    assert CAL.archive_listing_problem([("a", 17 * 1024 * 1024, 17 * 1024 * 1024)]) == "member_too_large:a"


def test_yaml_pre_parse_guard():
    assert CAL.yaml_text_problem("title: x\nexploit: !!python/object/apply:os.system ['id']\n") == "yaml_python_tag"
    assert CAL.yaml_text_problem("a: &x [1]\nb: *x\n") == "yaml_anchor_alias"
    assert CAL.yaml_text_problem("<!DOCTYPE html><html></html>") == "html_instead_of_yaml"
    assert CAL.yaml_text_problem('{"message":"GitHub access to this repository is not enabled"}') == "json_error_body"
    assert CAL.yaml_text_problem("a\x00b") == "nul_bytes"
    assert CAL.yaml_text_problem("   ") == "empty"
    for path in FIX.glob("tagpack_*.yaml"):  # no false positive on the real packs
        assert CAL.yaml_text_problem(path.read_bytes()) is None, path.name
    assert CAL.yaml_text_problem((FIX / "actorpack.yaml").read_bytes()) is None


def test_recorded_parse_matches_pyyaml():
    yaml = pytest.importorskip("yaml")
    for path in FIX.glob("*.yaml"):
        twin = json.loads((FIX / "parsed" / f"{path.stem}.json").read_text(encoding="utf-8"))
        text = path.read_bytes().decode("utf-8-sig")
        if not twin["ok"]:
            with pytest.raises(yaml.YAMLError):
                yaml.safe_load(text)
            continue
        assert json.loads(json.dumps(yaml.safe_load(text), default=str)) == twin["doc"], path.name


def test_missing_index_is_rebuilt_from_the_installed_archive(loader):
    rt, _http = installed()
    path = CAL.index_path(rt.data.info(CAL.GS_DATASET).sha256)
    path.unlink()
    CAL._INDEX_MEMO.clear()
    res = run(rt, f"btc_address:{BINANCE_BTC}")
    assert res.status is Status.OK and path.is_file()


# ------------------------------------------------------------------ FC2/FC4: GraphSense labels
def test_exchange_label_names_the_institution_and_is_a_stop_node(loader):
    rt, http = installed()
    calls = len(http.calls)
    res = run(rt, f"btc_address:{BINANCE_BTC}")
    assert res.status is Status.OK and len(http.calls) == calls  # offline lookup
    (label,) = res.attributes["crypto_labels"]
    assert (label["source"], label["entity_class"], label["actor"]) == ("graphsense", "exchange", "binance")
    assert label["source_url"].startswith("https://www.binance.com/") and label["label_date"] == "2022-11-16"
    assert label["provenance"]["commit"] == COMMIT and label["provenance"]["pack_path"] == "packs/exchange-wallets-binance.yaml"
    # FC2: a PoR snapshot older than 12 months loses one step (service_data PROBABLE -> POSSIBLE)
    assert (label["confidence_base"], label["confidence"], label["downgraded"]) == ("PROBABLE", "POSSIBLE", True)
    target = res.attributes["court_order_target"]
    assert (target["name"], target["legal_name"]) == ("Binance", "Binance Holdings Limited") and "MT" in target["jurisdictions"]
    assert "not proof of who holds the funds" in target["wording"]
    assert res.attributes["stop_node_hint"] == "exchange"
    assert res.attributes["data_attribution"].startswith("GraphSense public TagPacks")
    pivots = {(p.entity.type, p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert pivots == {(T.ORG, "Binance", "label_attributed_to", False), (T.ORG, "Binance Holdings Limited", "label_attributed_to", False)}
    (finding,) = res.findings
    assert finding.severity.label == "info" and "legal request to Binance" in finding.description
    assert finding.source == CAL.GS_SOURCE and finding.criterion.startswith("exact address match")
    assert ("Binance proof-of-reserves (manual download, then import with provenance)", "https://www.binance.com/en/proof-of-reserves") in res.links


def test_tron_exchange_and_evm_networks(loader):
    rt, _http = installed()
    res = run(rt, "other_crypto_address:TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9")
    assert res.status is Status.OK and res.attributes["chain"] == "tron"
    assert res.attributes["court_order_target"]["name"] == "Binance"
    res = run(rt, "eth_address:0xF977814E90DA44BFA03B6295A0616A897441ACEC")  # BEP20 label, EVM key lower-cased
    assert res.status is Status.OK and res.attributes["crypto_labels"][0]["network"] == "BEP20"
    res = run(rt, "other_crypto_address:bnb1edrs5cukhx060e02u98v9j8spum7vhuqg9ctxd")  # BEP2 (BNB Beacon Chain)
    assert res.status is Status.OK and res.attributes["court_order_target"]["name"] == "Binance"


def test_ofac_label_is_critical_with_dated_wording(loader):
    rt, _http = installed()
    res = run(rt, "btc_address:3K35dyL85fR9ht7UgzPfd1gLRRXQtNTqE3")
    (finding,) = res.findings
    assert finding.severity.label == "critical" and "sanctions" in finding.tags
    assert "crypto_sanctions_offline" in finding.description and finding.confidence_label.value == "probable"
    label = res.attributes["crypto_labels"][0]
    assert (label["risk_class"], label["confidence_id"], label["confidence_inferred"]) == ("ofac", "authority_data", True)
    assert res.attributes["stop_node_hint"] == "sanctioned" and "court_order_target" not in res.attributes
    assert res.pivots == []  # a sanctions label never becomes a company pivot


def test_tron_address_declared_as_btc_is_kept_under_tron(loader):
    rt, _http = installed()
    res = run(rt, "other_crypto_address:TUCsTq7TofTCJRRoHk6RvhMoS2mJLm5Yzq")
    label = res.attributes["crypto_labels"][0]
    assert res.status is Status.OK and label["currency_mismatch"] is True and label["risk_class"] == "ofac"


def test_sanctioned_exchange_entity_is_not_a_legal_request_target(loader):
    rt, _http = installed()
    res = run(rt, "other_crypto_address:TFwjPScaJRCbSWVAywE1S1WgaUgSnyYUbD")  # Garantex Europe (SDN)
    assert [f.severity.label for f in res.findings] == ["critical"]
    assert res.attributes["crypto_labels"][0]["label"] == "GARANTEX EUROPE OU"
    assert "court_order_target" not in res.attributes and res.pivots == []


@pytest.mark.parametrize(
    ("entity", "severity", "tag", "confidence"),
    [
        ("btc_address:1Lud76Q98VRHCUiyK7XUs7AgFofrqXeP78", "high", "ransomware", "probable"),  # forensic (50)
        ("eth_address:0xf9fe85e19bd533c69067c6e2ff02727d40a54100", "medium", "crypto_scam", "possible"),  # no confidence -> unknown
        ("eth_address:0xD0cC2B24980CBCCA47EF755Da88B220a82291407", "medium", "crypto_scam", "possible"),  # phishing, mixed case
        ("btc_address:1HVi6re6zDr5c5v9Sk2mmL9u7svEHfiBt4", "medium", "malicious", "possible"),  # service_hack, web_crawl
        ("eth_address:0x008fe40574e881e7247b50b991c0cc057d66647f", "medium", "issuer_freeze", "confirmed"),  # ledger_immanent
    ],
)
def test_risk_categories_raise_severity(loader, entity, severity, tag, confidence):
    rt, _http = installed()
    res = run(rt, entity)
    assert res.status is Status.OK
    risky = [f for f in res.findings if f.severity.label != "info"]
    assert len(risky) == 1 and risky[0].severity.label == severity and tag in risky[0].tags
    assert risky[0].confidence_label.value == confidence and risky[0].criterion
    assert "stop_node_hint" not in res.attributes and res.pivots == []  # perpetrator labels: the trail continues


def test_skipped_tags_are_never_indexed(loader):
    rt, _http = installed()
    index = CAL.LabelIndex(CAL.index_path(rt.data.info(CAL.GS_DATASET).sha256))
    # plustoken.yaml: a 35-character typo (checksum fails) and a lower-cased base58 value; usdt_blacklist: the zero address
    for key in ("1MFgcyJ7ZNSknbTBRaih6zWDE6V1A64tRYs", "14bwh6gmvol5ntwbvxqjkjdtzv4y5ebtvm", "0x0000000000000000000000000000000000000000"):
        assert index.lookup(key) == []
    assert run(rt, "eth_address:0x0000000000000000000000000000000000000000").status is Status.EMPTY


def test_hack_pack_exchange_cold_wallet_and_service_classes(loader):
    rt, _http = installed()
    res = run(rt, "btc_address:1JoktQJhCzuCQkt3GnQ8Xddcq4mUgNyXEa")
    target = res.attributes["court_order_target"]
    assert (target["name"], target["legal_name"], target["best_confidence"]) == ("Bitstamp", "Bitstamp Limited", "POSSIBLE")
    gambling = run(rt, "btc_address:1Lgnzb1p9YE3uKwGpspMQZ1NcAD1EMxzSh")
    assert gambling.attributes["stop_node_hint"] == "service"
    (finding,) = gambling.findings
    assert finding.title.startswith("Address labelled as service (stop-node)") and finding.severity.label == "info"
    defi = run(rt, "eth_address:0x1111111254EEB25477B68fb85Ed929f73A960582")
    assert defi.attributes["stop_node_hint"] == "defi" and "court_order_target" not in defi.attributes


def test_word_cloud_exchange_label_without_actor_is_shown_not_targeted(loader):
    rt, _http = installed()
    res = run(rt, "eth_address:0xc96c1609a1a45ccc667b2b7fa6508e29617f7b69")
    assert res.attributes["crypto_labels"][0]["label"] == "2GT_token (2GT)"
    assert res.attributes["crypto_labels"][0]["label_date"] == "2023-08-16"  # datetime lastmod normalised
    assert "court_order_target" not in res.attributes and res.pivots == []
    assert any("without an identified institution" in n for n in res.raw["notes"])


def test_no_label_is_empty_and_never_unhosted(loader):
    rt, _http = installed()
    res = run(rt, f"other_crypto_address:{TRON_UNLABELLED}")
    assert res.status is Status.EMPTY and res.findings == [] and res.pivots == []
    note = res.attributes["crypto_label_status"]
    assert "'No label' does not mean the address is unhosted or self-custodied" in note
    assert "Exchange coverage for TRON is thin: 2 exchange-labelled addresses (newest label 2022-11-16)" in note
    assert res.attributes["crypto_label_coverage"]["thin"] is True and res.raw["match"] is False


def test_missing_dataset_is_unavailable_never_empty():
    http = FakeHttp()  # no route: any request would fail the test
    res = run_module(CryptoAddressLabels, f"btc_address:{BINANCE_BTC}", http)
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset") or (res.status, res.reason_code) == (Status.UNAVAILABLE, "package")
    assert "could not verify" in res.error and http.calls == []


def test_policy_gate_and_tlp_red(loader):
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.BTC, BINANCE_BTC)
    pctx = policy.make_context(rt, ScanOptions(), path="scan")
    decision = policy.decide(CryptoAddressLabels, ent, pctx, run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.UNAVAILABLE, "dataset")
    rt, _http = installed()
    pctx = policy.make_context(rt, ScanOptions(tlp="red"), path="scan")
    assert policy.decide(CryptoAddressLabels, ent, pctx, run=RunInfo(entity=ent, is_seed=True, tlp="red")).allowed


def test_corrupt_index_is_error_never_no_label(loader):
    rt, _http = installed()
    path = CAL.index_path(rt.data.info(CAL.GS_DATASET).sha256)
    CAL._INDEX_MEMO.clear()
    path.write_bytes(b"this is not an SQLite database" * 100)
    res = run(rt, f"other_crypto_address:{TRON_UNLABELLED}")
    assert (res.status, res.reason_code) == (Status.ERROR, "error") and "could not verify" in res.error
    assert res.source_statuses[CAL.GS_SOURCE]["status"] == "error"


def test_malformed_local_team_file_is_reported_not_fatal(loader, tmp_path):
    bad = tmp_path / "team.json"
    bad.write_text('{"schema": "v3lum.crypto_labels/1", "labels": [', encoding="utf-8")
    rt, _http = installed(settings={CAL.TEAM_FILE_SETTING: str(bad)})
    res = run(rt, f"btc_address:{BINANCE_BTC}")
    assert res.status is Status.OK and any("local team file unreadable" in p for p in res.raw["sources"]["problems"])
    assert CAL.parse_team_labels(["not", "a", "mapping"])["problems"] == ["not_a_mapping"]
    assert CAL.parse_team_labels({"schema": "other/1"})["problems"] == ["bad_schema"]


def test_health_selftest(loader):
    from tests.fakes import make_ctx

    hc = CryptoAddressLabels.health_check()
    assert hc.offline is True
    assert hc.selftest(make_ctx(CryptoAddressLabels)).status == "dead"
    rt, _http = installed()
    assert hc.selftest(make_ctx(CryptoAddressLabels, runtime=rt)).status == "ok"


# ------------------------------------------------------------------ FC2: manual PoR imports
def import_okx(tmp_path, **kw):
    folder = tmp_path / "por"
    args = {"exchange": "OKX", "por_date": "2026-10-01", "source_url": OKX_PAGE, "imported_by": "cti-analyst-01"}
    args.update(kw)
    return folder, CAL.import_por_file(FIX / "por_okx.csv", directory=folder, **args)


def test_por_import_writes_file_and_provenance_0600(tmp_path):
    folder, out = import_okx(tmp_path)
    assert out["format"] == "okx" and out["labels"] == 5  # ETH, 2 BTC, TON, ADA
    assert out["skipped"] == {"validator_pubkey": 1, "duplicate": 2, "invalid_address": 1}
    side = json.loads(next(folder.glob("*.provenance.json")).read_text(encoding="utf-8"))
    assert side["schema"] == CAL.POR_SIDECAR_SCHEMA and side["exchange"] == "OKX" and side["por_date"] == "2026-10-01"
    assert side["source_url"] == OKX_PAGE and side["imported_by"] == "cti-analyst-01" and len(side["file_sha256"]) == 64
    for path in folder.iterdir():
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.parametrize(
    ("name", "kw", "reason"),
    [
        ("por_okx_page.html", {}, "html_page_not_por_file"),  # the PoR page saved instead of the file
        ("por_okx.csv", {"source_url": ""}, "source URL"),
        ("por_okx.csv", {"por_date": "yesterday"}, "PoR date"),
        ("por_okx.csv", {"imported_by": ""}, "mandatory"),
    ],
)
def test_por_import_refusals(tmp_path, name, kw, reason):
    args = {"exchange": "OKX", "por_date": "2026-10-01", "source_url": OKX_PAGE, "imported_by": "cti-analyst-01"}
    args.update(kw)
    with pytest.raises(ValueError, match=reason):
        CAL.import_por_file(FIX / name, directory=tmp_path / "por", **args)
    assert not (tmp_path / "por").exists() or list((tmp_path / "por").iterdir()) == []


def test_por_interstitials_are_never_por_data():
    observed = json.loads((FIX / "por_binance_blocked_202.json").read_text(encoding="utf-8"))
    assert CAL.por_input_problem(observed["body"], status=observed["status"], headers=observed["headers"]) == "bot_interstitial"
    challenge = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    assert CAL.por_input_problem(challenge) == "bot_challenge"
    assert CAL.por_input_problem('{"code": 0}') == "json_not_csv"


def test_okx_signed_por_and_graphsense_agree_on_one_institution(loader, tmp_path):
    folder, _out = import_okx(tmp_path)
    rt, _http = installed(settings={CAL.POR_DIR_SETTING: str(folder)})
    res = run(rt, f"btc_address:{OKX_BTC}")
    labels = res.attributes["crypto_labels"]
    assert [lab["source"] for lab in labels] == ["por:okx", "graphsense"]  # strongest first, side by side
    por, gs = labels
    assert (por["confidence"], por["signed"], por.get("downgraded", False)) == ("CONFIRMED", True, False)
    assert por["provenance"]["por_date"] == "2026-10-01" and por["provenance"]["imported_by"] == "cti-analyst-01"
    assert por["actor"] == "okex" and gs["confidence"] == "POSSIBLE" and gs["downgraded"] is True
    target = res.attributes["court_order_target"]
    assert target["name"] == "OKX" and target["sources"] == ["por:okx", "graphsense"] and target["best_confidence"] == "CONFIRMED"
    assert "label_conflict" not in res.attributes
    assert ("OKX proof-of-reserves files (manual download, then import with provenance)", OKX_PAGE) in res.links
    staking = run(rt, "eth_address:0x0cdcdb19a857c2ac24818ca4fdfe38cce071483e")  # reserve row (staking EOA deduplicated)
    assert staking.attributes["court_order_target"]["name"] == "OKX"


def test_por_label_older_than_12_months_is_downgraded(loader, tmp_path):
    folder, _out = import_okx(tmp_path, por_date="2025-10-01")
    rt, _http = installed(settings={CAL.POR_DIR_SETTING: str(folder)})
    por = run(rt, f"btc_address:{OKX_BTC}").attributes["crypto_labels"][0]
    assert (por["source"], por["confidence_base"], por["confidence"], por["downgraded"], por["age_months"]) == (
        "por:okx", "CONFIRMED", "PROBABLE", True, 13)


def test_generic_por_csv_and_tampered_file(tmp_path):
    folder = tmp_path / "por"
    CAL.import_por_file(FIX / "por_generic.csv", exchange="Binance", por_date="2022-11-16",
                        source_url="https://www.binance.com/en/proof-of-reserves", imported_by="cti-analyst-02", directory=folder)
    loaded = CAL.load_por_labels(folder)
    assert loaded["problems"] == [] and loaded["imports"][0]["labels"] == 4
    rec = loaded["by_key"]["tv6mumxfmlbbqpzvbhdwfsdnqevfnmiusi".upper()[:0] + "TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi"][0]
    assert (rec["confidence_base"], rec["signed"], rec["family"]) == ("PROBABLE", False, "tron")
    csv_path = next(folder.glob("*.csv"))
    os.chmod(csv_path, 0o600)
    csv_path.write_text(csv_path.read_text(encoding="utf-8") + "Binance,BTC,BTC,1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2,2022-11-16,https://example.com/\n", encoding="utf-8")
    tampered = CAL.load_por_labels(folder)
    assert tampered["by_key"] == {} and "SHA-256 differs" in tampered["problems"][0]


# ------------------------------------------------------------------ FC3: team label file
def test_team_label_names_brazilian_exchange_without_graphsense(tmp_path):
    rt = make_runtime(FakeHttp(), settings={CAL.TEAM_FILE_SETTING: str(team_file(tmp_path))})
    res = run(rt, f"other_crypto_address:{TEAM_TRON}")
    assert res.status is Status.OK  # the team file answers; GraphSense is reported per source
    state = res.source_statuses[CAL.GS_SOURCE]
    assert state["status"] == "unavailable" and state["reason_code"] in ("dataset", "package")
    target = res.attributes["court_order_target"]
    assert (target["name"], target["cnpj"], target["legal_contact"], target["jurisdictions"]) == (
        "Exchange Exemplo", "11.222.333/0001-81", "juridico@example.com", ["BR"])
    label = res.attributes["crypto_labels"][0]
    assert label["confidence"] == "CONFIRMED" and label["provenance"]["reference"].startswith("CASE-2026-0001")
    assert {p.entity.value for p in res.pivots} == {"Exchange Exemplo", "Exchange Exemplo Servicos Digitais Ltda (fixture)"}


def test_team_ransomware_label(tmp_path):
    rt = make_runtime(FakeHttp(), settings={CAL.TEAM_FILE_SETTING: str(team_file(tmp_path))})
    res = run(rt, "btc_address:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    (finding,) = res.findings
    assert finding.severity.label == "high" and "ransomware" in finding.tags and finding.source == ""


def test_team_file_drops_personal_data_and_bad_entries(tmp_path):
    doc = json.loads((FIX / "team_labels_invalid.json").read_text(encoding="utf-8"))
    parsed = CAL.parse_team_labels(doc)
    problems = " ".join(parsed["problems"])
    for expected in ("missing_provenance", "invalid_address@1", "personal_field_dropped:cpf@2", "personal_field_dropped:owner_name@2",
                     "personal_field_dropped:email@2", "unknown_chain:dogecoin-classic", "bad_confidence:SURE", "unknown_institution:missing_institution",
                     "bad_provenance_date@5"):
        assert expected in problems
    rt = make_runtime(FakeHttp(), settings={CAL.TEAM_FILE_SETTING: str(team_file(tmp_path, "team_labels_invalid.json"))})
    res = run(rt, "eth_address:0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
    assert res.status is Status.OK
    dumped = json.dumps([res.attributes, res.raw, [f.description for f in res.findings]], default=str)
    for personal in ("000.000.000-00", "Pessoa Exemplo", "pessoa@example.com"):
        assert personal not in dumped


def test_local_team_label_can_reference_bundled_brazilian_institution(loader, tmp_path):
    doc = {"schema": "v3lum.crypto_labels/1", "updated": "2026-11-20", "institutions": {},
           "labels": [{"address": TEAM_TRON, "chain": "tron", "label": "MB USDT-TRC20 deposit (case)", "category": "exchange",
                       "institution": "mercadobitcoin", "confidence": "PROBABLE",
                       "provenance": {"source": "case", "reference": "CASE-2026-0009", "date": "2026-09-01", "added_by": "cti-analyst-01"}}]}
    rt, _http = installed(settings={CAL.TEAM_FILE_SETTING: str(team_file(tmp_path, doc=doc))})
    res = run(rt, f"other_crypto_address:{TEAM_TRON}")
    target = res.attributes["court_order_target"]
    assert (target["name"], target["legal_name"], target["jurisdictions"], target["actor"]) == (
        "Mercado Bitcoin", "Mercado Bitcoin Serviços Digitais Ltda.", ["BR"], "mercadobitcoin")


def test_conflicting_labels_are_shown_side_by_side(loader, tmp_path):
    doc = json.loads((FIX / "team_labels.json").read_text(encoding="utf-8"))
    doc["labels"].append({"address": BINANCE_BTC, "chain": "btc", "label": "Exchange Exemplo hot wallet (case)", "category": "exchange",
                          "institution": "exchange_exemplo", "confidence": "PROBABLE",
                          "provenance": {"source": "case", "reference": "CASE-2026-0010", "date": "2026-10-10", "added_by": "cti-analyst-01"}})
    rt, _http = installed(settings={CAL.TEAM_FILE_SETTING: str(team_file(tmp_path, doc=doc))})
    res = run(rt, f"btc_address:{BINANCE_BTC}")
    assert res.status is Status.OK
    assert [lab["source"] for lab in res.attributes["crypto_labels"]] == ["team", "graphsense"]
    assert set(res.attributes["label_conflict"]) == {"Binance", "Exchange Exemplo"}
    assert "court_order_target" not in res.attributes  # no silent choice
    (finding,) = res.findings
    assert "several institutions" in finding.description and "conflict" in finding.tags
    assert {p.entity.value for p in res.pivots} >= {"Binance", "Exchange Exemplo"}  # both listed, none expanded
    assert all(p.expand is False for p in res.pivots)


# ------------------------------------------------------------------ pure helpers
def test_confidence_and_dates():
    assert CAL.months_between("2025-11-26", "2026-11-26") == 12 and CAL.months_between("2025-11-27", "2026-11-26") == 11
    rec = {"confidence_base": "PROBABLE", "label_date": "2022-11-15", "por_snapshot": True}
    assert CAL.effective_confidence(rec, "2026-11-26") == ("POSSIBLE", True, 48)
    assert CAL.effective_confidence(dict(rec, por_snapshot=False), "2026-11-26") == ("PROBABLE", False, 48)
    assert CAL.iso_date("2023-08-16 12:18:52.619444") == "2023-08-16" and CAL.iso_date("16/08/2023") is None
    assert CAL.por_date_from_filename("okx_por_20261001.csv") == "2026-10-01"


def test_address_normalisation():
    tron = CAL.normalize_address("41" + "a614f803b6fd780986a42c78ec9c7f77e6ded13c")
    assert tron["family"] == "tron" and tron["key"].startswith("T") and tron["checksum_ok"] is True
    assert CAL.normalize_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")["checksum_ok"] is True
    assert CAL.normalize_address("0x0000000000000000000000000000000000000000")["special"] is True
    usdt_tron = CAL.normalize_address("TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9", currency="USDT")
    assert usdt_tron["family"] == "tron"  # tokens take the family of the address shape
    assert CAL.normalize_address("0xAbC", currency="ETH")["shape_ok"] is False
    assert CAL.normalize_address(None) is None


def test_natural_person_labels_are_withheld():
    view = CAL.label_view({"source": "graphsense", "label": "Jane Example", "label_personal_hint": CAL.label_looks_personal("Jane Example")})
    assert view["label"] == CAL.PERSON_LABEL_WITHHELD and view["label_withheld"] is True
    assert CAL.label_looks_personal("GARANTEX EUROPE OU") is False and CAL.label_looks_personal("binance reserve wallets BTC") is False


def test_parse_tagpack_rules_on_fixtures():
    def doc(name):
        return json.loads((FIX / "parsed" / f"{name}.json").read_text(encoding="utf-8"))["doc"]

    okx = CAL.parse_tagpack(doc("tagpack_exchange_okx"), pack_path="packs/exchange-wallets-okx.yaml", commit=COMMIT)
    assert okx["pack"]["por_snapshot"] is True and {t["label"] for t in okx["tags"]} == {"okx reserves wallets", "okx ERC20 reserves"}
    assert all(t["actor"] == "okex" and t["entity_class"] == "exchange" for t in okx["tags"])  # header inherited
    empty = CAL.parse_tagpack(doc("tagpack_empty"), pack_path="packs/demo.yaml")
    assert empty["tags"] == [] and empty["problems"] == []
    blacklist = CAL.parse_tagpack(doc("tagpack_usdt_blacklist"), pack_path="packs/usdt_blacklist.yaml")
    assert blacklist["skipped"] == {"special_address": 1} and blacklist["tags"][0]["risk_class"] == "issuer_blacklist"
    bad = CAL.parse_tagpack(doc("tagpack_invalid_address"), pack_path="packs/plustoken.yaml")
    assert bad["skipped"] == {"invalid_address": 1, "checksum_failed": 1} and bad["tags"] == []
    assert CAL.parse_tagpack(["not", "a", "mapping"], pack_path="x")["problems"] == ["not_a_mapping"]
    private = CAL.parse_tagpack({"title": "t", "creator": "c", "is_public": False, "tags": []}, pack_path="x")
    assert private["pack"] is None and "pack_not_public" in private["problems"]
