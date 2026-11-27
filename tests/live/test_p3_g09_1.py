"""Live checks of batch p3-G09-1 (ens_resolver P209, ransomwhere P210, ton_explorer P214); run with V3LUM_LIVE=1.

Benign public values only: the ENS DAO's own name ``ens.eth`` and its wallet, the Ethereum Foundation wallet (no
reverse record), the TON Foundation wallet, the @github collectible username NFT (an organisation's handle, checked
as a fraud-subject lookup with a recorded test purpose) and a Ransomwhere-listed criminal payment address (public
CTI, matched offline after one download of the export). crypto_tx_graph (P213) sends nothing: no live check.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (statuses blocked / rate_limited / quota / error / unavailable, never 'empty').
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto.ens_resolver import EnsResolver
from v3lum.modules.crypto.ransomwhere import DATASET, Ransomwhere
from v3lum.modules.crypto.ton_explorer import TON_FOUNDATION_RAW, TonExplorer

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
DAO = "0xfe89cc7abb2c4183683ab71653c4cdc9b02d44b7"
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
CONTI = "bc1qnf273myysxjw23g9hze4vcu3uqkget9ra70hen"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _could_not_verify(res) -> bool:
    if res.status in COULD_NOT_VERIFY:
        print(f"could not verify: {res.status.value} {res.reason_code} {res.error[:160]}")
        return True
    return False


# ------------------------------------------------------------------ ENSData (P209)
def test_ens_name_and_reverse_records():
    rt = live_runtime()
    name = run_module(EnsResolver, "domain:ens.eth", runtime=rt)
    if not _could_not_verify(name):
        assert name.status is Status.OK, (name.status, name.error)
        assert any(p.relation == "ens_resolves_to" and p.entity.value == DAO for p in name.pivots)
        assert all(p.confidence_label.value == "possible" for p in name.pivots if p.relation == "ens_text_record")
    reverse = run_module(EnsResolver, f"eth_address:{EF}", runtime=rt)
    if not _could_not_verify(reverse):
        assert reverse.status is Status.EMPTY, (reverse.status, reverse.error)  # no primary name: never 'absent'
        assert "says nothing about the wallet" in reverse.attributes["ens_reverse_record"]


# ------------------------------------------------------------------ Ransomwhere (P210)
def test_ransomwhere_export_downloads_and_matches_offline():
    rt = live_runtime()
    result = rt.data.update(DATASET)
    print(f"{DATASET}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
    if not result.ok:
        pytest.skip(f"Ransomwhere export could not be installed from this egress: {result.reason[:120]}")
    hit = run_module(Ransomwhere, f"btc_address:{CONTI}", runtime=rt)
    assert hit.status is Status.OK and hit.requests == 0, (hit.status, hit.error)
    assert hit.findings[0].data["family"] == "Conti" and "historical" in hit.findings[0].tags
    assert {p.entity.value for p in hit.pivots} == {"Conti"}
    miss = run_module(Ransomwhere, "btc_address:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", runtime=rt)
    assert miss.status is Status.EMPTY and "a miss means nothing" in miss.attributes["ransomwhere_status"]


# ------------------------------------------------------------------ Toncenter (P214)
def test_ton_foundation_wallet():
    res = run_module(TonExplorer, f"other_crypto_address:{TON_FOUNDATION_RAW}", runtime=live_runtime())
    if _could_not_verify(res):
        return
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["chain"] == "ton" and res.attributes["balance"].endswith(" TON")
    assert all(p.expand is False for p in res.pivots)


def test_ton_collectible_owner_of_an_organisation_handle():
    entity = Entity.make(T.USERNAME, "github")
    options = ScanOptions(subject_roles={entity.key: "fraud"}, purpose="live parser check of an organisation's collectible handle")
    res = run_module(TonExplorer, entity, runtime=live_runtime(), options=options)
    if _could_not_verify(res):
        return
    assert res.status is Status.OK, (res.status, res.error)
    [lead] = res.pivots
    assert lead.relation == "current_nft_owner" and lead.expand is False and lead.confidence_label.value == "probable"
    assert res.attributes["ton_collectible"]["token"] == "@github"
