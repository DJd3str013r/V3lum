"""Live checks of the P113 username packs (run with V3LUM_LIVE=1; benign values only).

* the runtime datasets (WhatsMyName pinned copy, Sherlock manifest and exclusions, Maigret
  db_meta) download, validate and parse; the archived WhatsMyName copy still matches its pin;
* the default pack runs end to end on the central benign handle (module.BENIGN_VALUES: 'octocat');
* the FC15 self-test re-measures the default pack's calibration (official claimed account FOUND,
  random control ABSENT);
* the extended pack sends nothing to sites whose terms legal has not reviewed.

A 403/429/challenge from this datacenter egress is an accepted outcome when the module reports it as
blocked / rate_limited (could not verify), never as an absence.
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.module import BENIGN_VALUES
from v3lum.modules.username_social import username_check as uc
from v3lum.modules.username_social.username_check_extended import UsernameCheckExtended

pytestmark = pytest.mark.live

COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR)


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def test_live_runtime_datasets_download_validate_and_parse():
    rt = _runtime()
    store = rt.data
    for name in (uc.WMN, uc.SHERLOCK_DATA, uc.SHERLOCK_EXCLUSIONS, uc.MAIGRET_META):
        result = store.update(name)
        assert result.status in ("updated", "unchanged"), (name, result.status, result.reason)
    assert store.info(uc.WMN).sha256 == uc.WMN_SHA256  # archived dataset: the pin still holds
    wmn = uc.parse_wmn_dataset(store.path(uc.WMN).read_bytes())
    assert wmn["ok"] and len(wmn["sites"]) > 600
    manifest = uc.parse_sherlock_manifest(store.path(uc.SHERLOCK_DATA).read_bytes())
    assert manifest["ok"] and uc.sherlock_username_regexes(manifest)["by_host"]
    exclusions = uc.parse_sherlock_exclusions(store.path(uc.SHERLOCK_EXCLUSIONS).read_bytes())
    assert exclusions["ok"] and exclusions["names"]
    meta = uc.parse_maigret_db_meta(store.path(uc.MAIGRET_META).read_bytes())
    assert meta["ok"]
    plan = uc.maigret_update_plan(meta, uc._bundled()["datasets"].get("maigret"))
    assert plan["action"] in ("keep", "download")
    print(f"live datasets: wmn pinned ok, {len(wmn['sites'])} sites; sherlock {len(manifest['sites'])} sites, "
          f"{len(exclusions['names'])} exclusions; maigret db_meta {meta['updated_at']} -> {plan['action']}")


def test_live_default_pack_on_the_benign_handle():
    handle = BENIGN_VALUES[T.USERNAME]
    res = Engine(_runtime(), ScanOptions()).run_module(uc.UsernameCheck, Entity.make(T.USERNAME, handle))
    print(f"live username_check({handle}): {res.status.value} {res.reason_code} | {res.attributes.get('site_checks')} | "
          f"{res.attributes.get('site_checks_coverage', '')} | hosts {res.hosts}")
    assert res.status in (Status.OK, Status.EMPTY, *COULD_NOT_VERIFY), res.error
    assert res.attributes["site_checks"].startswith("username_check: ")
    states = {e["state"] for e in res.raw["sites"]}
    assert states <= {"found", "absent", "unknown"}
    if res.status in (Status.OK, Status.EMPTY):
        assert all(e["body_sha256"] for e in res.raw["sites"] if e["state"] in ("found", "absent"))
    assert set(res.hosts) <= set(uc.UsernameCheck.hosts)


def test_live_selftest_recalibrates_the_default_pack():
    rt = _runtime()
    result = uc.run_selftest(uc.UsernameCheck, rt.context(uc.UsernameCheck, ScanOptions()))
    print(f"live self-test username_check: {result.status} | {result.detail}")
    assert result.status in ("ok", "blocked"), result.detail


def test_live_extended_pack_sends_nothing_to_unreviewed_sites():
    handle = BENIGN_VALUES[T.USERNAME]
    res = Engine(_runtime(), ScanOptions()).run_module(UsernameCheckExtended, Entity.make(T.USERNAME, handle))
    print(f"live username_check_extended({handle}): {res.status.value} {res.reason_code} | {res.attributes.get('site_checks_coverage')}")
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert not set(res.hosts) & set(UsernameCheckExtended.hosts)
