"""Live checks of batch p2-G09-3 (P358 crypto_address_labels); run with V3LUM_LIVE=1.

crypto_address_labels has disclosure 'none': no investigated value ever leaves the machine. The only
network traffic is the dataset manager downloading the public GraphSense TagPacks (github.com archive ->
codeload.github.com, or raw.githubusercontent.com files). Benign values only: Binance's published 2022
proof-of-reserves BTC wallet (a public exchange address) and a private-key-2 test-vector TRON address.

A 403/429/challenge from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (the update fails with a reason, nothing is installed, the module answers UNAVAILABLE or
ERROR, never EMPTY). The YAML steps need the optional extra 'yaml' (PyYAML); without it they are skipped
and the module reports UNAVAILABLE 'package'.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.datasets import register_dataset
from v3lum.core.models import Status
from v3lum.modules.crypto import crypto_address_labels as CAL
from v3lum.modules.crypto.crypto_address_labels import CryptoAddressLabels

pytestmark = pytest.mark.live
RAW = "https://raw.githubusercontent.com/graphsense/graphsense-tagpacks/master/"
BINANCE_BTC = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"  # Binance proof-of-reserves wallet (public, 2022 list)
TRON_TEST_VECTOR = "TDvSsdrNM5eeXNL3czpa6AxLDHZA9nwe9K"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _probe(rt: Runtime, name: str, path: str) -> str | None:
    """Download one raw GraphSense file through the dataset manager (registered for this test only)."""
    register_dataset(name, RAW + path, ttl=0, description="live probe", licence="MIT", terms_class="open",
                     attribution=CAL.GRAPHSENSE_ATTRIBUTION, provider="github", source=CAL.GS_SOURCE,
                     expect="text", min_bytes=100, max_bytes=16 * 1024 * 1024, large=False)
    result = rt.data.update(name)
    print(f"{path}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
    if result.status == "failed":
        assert result.reason  # could not verify from this egress: reported, nothing installed
        return None
    return rt.data.fetch_text(name)


def test_graphsense_archive_refresh_and_lookup():
    rt = live_runtime()
    result = rt.data.update(CAL.GS_DATASET)
    print(f"{CAL.GS_DATASET}: {result.status} {result.reason[:200]} {result.new_sha256[:12]}")
    assert result.status in ("updated", "unchanged", "failed")
    res = run_module(CryptoAddressLabels, f"btc_address:{BINANCE_BTC}", runtime=rt)
    print(f"lookup: {res.status.value} {res.reason_code} {res.error[:200]}")
    if result.status == "failed":
        assert result.reason
        assert res.status in (Status.UNAVAILABLE, Status.ERROR)  # could not verify, never 'no label'
        return
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["court_order_target"]["name"] == "Binance"
    empty = run_module(CryptoAddressLabels, f"other_crypto_address:{TRON_TEST_VECTOR}", runtime=rt)
    assert empty.status is Status.EMPTY and "unhosted" in empty.attributes["crypto_label_status"]


def test_graphsense_raw_pack_and_actorpack_parse_live(clean_registry):
    loader = CAL.yaml_safe_load()
    if loader is None:
        pytest.skip("PyYAML (optional extra 'yaml') not installed: the TagPacks cannot be parsed here")
    rt = live_runtime()
    text = _probe(rt, "crypto_address_labels.live_probe_okx", "packs/exchange-wallets-okx.yaml")
    if text is not None:
        doc, problem = CAL.load_pack_text(text, loader)
        assert problem is None, problem
        parsed = CAL.parse_tagpack(doc, pack_path="packs/exchange-wallets-okx.yaml")
        print(f"okx pack: {len(parsed['tags'])} tags, skipped {parsed['skipped']}, problems {parsed['problems']}")
        assert parsed["pack"]["por_snapshot"] is True and len(parsed["tags"]) >= 20
        assert all(t["entity_class"] == "exchange" and t["actor"] == "okex" for t in parsed["tags"])
    actors_text = _probe(rt, "crypto_address_labels.live_probe_actorpack", "actors/graphsense.actorpack.yaml")
    if actors_text is not None:
        doc, problem = CAL.load_pack_text(actors_text, loader)
        assert problem is None, problem
        actors = CAL.parse_actorpack(doc)["actors"]
        print(f"actorpack: {len(actors)} actors")
        br = {aid for aid, info in actors.items() if "BR" in info["jurisdictions"]}
        assert {"mercadobitcoin", "foxbit", "novadax"} <= br  # the bundled team table copies these
        assert actors["mercadobitcoin"]["legal_name"] == "Mercado Bitcoin Serviços Digitais Ltda."
