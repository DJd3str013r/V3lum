"""Live check of batch p3-G06-1 (P127 brasilapi_ddd); run with V3LUM_LIVE=1.

The dataset manager downloads two parts (DDD 11 and DDD 61: well-known public area codes, never taken from
case data), validates them before install, revalidates DDD 11 with its stored ETag (conditional GET) and
the offline lookup then answers from the local copies. Each request carries only the 2-digit DDD.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify: the failed update installs nothing and the lookup says 'city list unavailable', never an
empty city list.
"""

from __future__ import annotations

import pytest

from tests.fakes import make_ctx
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.datasets import DataStore
from v3lum.modules.phone import brasilapi_ddd as b
from v3lum.modules.phone.phone_parse import PhoneParse

pytestmark = pytest.mark.live


def test_brasilapi_ddd_parts_download_validate_and_answer_offline():
    rt = Runtime(Config(), no_cache=True)
    table = DataStore.bundled_json(b.DDD_TABLE)
    results = {}
    for ddd in ("11", "61"):
        res = rt.data.update(b.part_name(ddd))
        print(f"{b.part_name(ddd)}: {res.status} {b.update_outcome(res)} {res.reason[:200]}")
        assert res.status in ("updated", "unchanged", "failed")
        results[ddd] = res
    ctx = make_ctx(PhoneParse)  # an offline module's ctx.data: reads only, never downloads
    for ddd, res in results.items():
        look = b.lookup_ddd(ddd, b.installed_part(ctx.data, ddd), table)
        if res.status == "failed":  # could not verify from this egress: nothing installed, never an empty list
            assert b.update_outcome(res) in ("blocked", "rate_limited", "error")
            assert look["coverage"] == b.CITY_LIST_UNAVAILABLE and look["cities"] is None
            continue
        assert look["coverage"] is None and look["city_count"] >= 10 and look["main_city_in_list"] is True
        assert not look["notes"], look["notes"]
        print(b.ddd_report(look)["terminal"])
    if results["11"].status != "failed":
        again = rt.data.update(b.part_name("11"))  # conditional GET with the stored ETag
        print(f"revalidation: {again.status} {again.reason[:200]}")
        assert again.status in ("unchanged", "updated", "failed")
        rec = b.installed_part(ctx.data, "11")
        assert rec["ok"] and "SÃO PAULO" in rec["cities"]
        rep = b.ddd_report(b.lookup_ddd("11", rec, table))
        assert rep["terminal"].startswith("DDD 11: SP - São Paulo - ") and rep["terminal"].endswith("cities in DDD")
