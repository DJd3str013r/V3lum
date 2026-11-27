"""ip_offline_geo (P047 c1-c4, c6, c8, c9): DB-IP Lite country/ASN mmdb lookups through maxminddb.

Fixtures in tests/fixtures/ip_offline_geo/: small MaxMind DB files holding the real DB-IP Lite
2026-11 records of six networks (Google, Cloudflare and Quad9 resolvers, NIC.br, IPv6 resolvers),
written with a stdlib mmdb writer; a gzip copy of the country file for the download path.

The optional ``maxminddb`` package is not installed in the test environment: a stand-in module with
the same API (``open_database`` -> Reader with ``get_with_prefix_len`` and ``metadata``), backed by
the small stdlib reader below, is put in ``sys.modules`` for the lookup tests.
"""

from __future__ import annotations

import gzip
import importlib.machinery
import ipaddress
import shutil
import struct
import sys
import types
from datetime import datetime, timezone

import pytest

from tests.fakes import FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.ip_network import ip_offline_geo
from v3lum.modules.ip_network.ip_offline_geo import (
    ASN,
    COUNTRY,
    IpOfflineGeo,
    dbip_release,
    dbip_url,
    geolite2_must_refresh,
    geolite2_request,
    normalise_geo,
)

FIX = "tests/fixtures/ip_offline_geo"
MARKER = b"\xab\xcd\xefMaxMind.com"


# ------------------------------------------------------------------ a tiny MaxMind DB reader (test stand-in)
def _decode(buf: bytes, base: int, off: int, depth: int = 0):
    ctrl = buf[off]
    off += 1
    typ = ctrl >> 5
    if typ == 1:  # pointer
        ss, vvv = (ctrl >> 3) & 3, ctrl & 7
        if ss == 0:
            ptr = (vvv << 8) | buf[off]
        elif ss == 1:
            ptr = ((vvv << 16) | (buf[off] << 8) | buf[off + 1]) + 2048
        elif ss == 2:
            ptr = ((vvv << 24) | int.from_bytes(buf[off:off + 3], "big")) + 526336
        else:
            ptr = int.from_bytes(buf[off:off + 4], "big")
        value, _ = _decode(buf, base, base + ptr, depth + 1)
        return value, off + ss + 1
    if typ == 0:
        typ = 7 + buf[off]
        off += 1
    size = ctrl & 0x1F
    if size == 29:
        size, off = 29 + buf[off], off + 1
    elif size == 30:
        size, off = 285 + int.from_bytes(buf[off:off + 2], "big"), off + 2
    elif size == 31:
        size, off = 65821 + int.from_bytes(buf[off:off + 3], "big"), off + 3
    if typ == 2:
        return buf[off:off + size].decode("utf-8"), off + size
    if typ == 3:
        return struct.unpack(">d", buf[off:off + 8])[0], off + 8
    if typ in (5, 6, 9, 10):
        return int.from_bytes(buf[off:off + size], "big"), off + size
    if typ == 7:
        out = {}
        for _ in range(size):
            key, off = _decode(buf, base, off, depth + 1)
            out[key], off = _decode(buf, base, off, depth + 1)
        return out, off
    if typ == 11:
        items = []
        for _ in range(size):
            item, off = _decode(buf, base, off, depth + 1)
            items.append(item)
        return items, off
    if typ == 14:
        return bool(size), off
    raise ValueError(f"mmdb type {typ} not supported by the test reader")


class _Reader:
    def __init__(self, path: str) -> None:
        with open(path, "rb") as fh:
            self.buf = fh.read()
        idx = self.buf.rfind(MARKER)
        if idx < 0:
            raise ValueError("not a MaxMind DB")
        self.meta, _ = _decode(self.buf, idx + len(MARKER), idx + len(MARKER))

    def metadata(self):
        return types.SimpleNamespace(**self.meta)

    def get_with_prefix_len(self, ip: str):
        meta, buf = self.meta, self.buf
        nodes, rs = meta["node_count"], meta["record_size"]
        addr = ipaddress.ip_address(ip)
        packed = addr.packed if addr.version == meta["ip_version"] else b"\x00" * 12 + addr.packed
        nbytes = rs * 2 // 8
        node, depth = 0, 0
        for i in range(len(packed) * 8):
            if node >= nodes:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            off = node * nbytes
            node = int.from_bytes(buf[off + bit * 3:off + bit * 3 + 3], "big")  # record_size 24
            depth = i + 1
        prefix = depth if addr.version == meta["ip_version"] else max(0, depth - 96)
        if node <= nodes:
            return None, prefix
        start = nbytes * nodes + 16
        record, _ = _decode(buf, start, start + node - nodes - 16)
        return record, prefix

    def get(self, ip: str):
        return self.get_with_prefix_len(ip)[0]

    def close(self) -> None:
        pass


@pytest.fixture
def maxminddb(monkeypatch):
    mod = types.ModuleType("maxminddb")
    mod.__spec__ = importlib.machinery.ModuleSpec("maxminddb", None)
    mod.open_database = lambda path, mode=0: _Reader(path)
    monkeypatch.setitem(sys.modules, "maxminddb", mod)
    monkeypatch.setattr(ip_offline_geo, "_READERS", {})
    return mod


def install(name: str, fixture: str) -> None:
    """Place a database as `v3lum data update` would have installed it."""
    shutil.copyfile(f"{FIX}/{fixture}", paths.datasets_dir() / name)


# ------------------------------------------------------------------ metadata
def test_metadata_and_datasets():
    cls = IpOfflineGeo
    assert (cls.terms, cls.disclosure, cls.hosts, cls.sources, cls.requires_packages) == ("open", "none", (), ("dbip.lite",), ("maxminddb",))
    for name in (COUNTRY, ASN):
        reg = DATASETS[name]
        assert (reg["large"], reg["archive"], reg["licence"], reg["source"]) == (True, "gz", "CC-BY-4.0", "dbip.lite")
        assert "city" not in reg["url"]
    with pytest.raises(ValueError):
        dbip_url("city", "2026-11")  # the 86 MB city file is never fetched (c1/c8)


def test_release_falls_back_before_the_second():
    assert dbip_release(datetime(2026, 11, 26).date()) == "2026-11"
    assert dbip_release(datetime(2026, 12, 1).date()) == "2026-11"
    assert dbip_release(datetime(2027, 1, 1).date()) == "2026-12"


# ------------------------------------------------------------------ lookups (c3, c4, c8)
def test_ipv4_country_and_asn(maxminddb):
    install(COUNTRY, "dbip_country_lite_slice.mmdb")
    install(ASN, "dbip_asn_lite_slice.mmdb")
    http = FakeHttp()
    res = run_module(IpOfflineGeo, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    assert (res.attributes["country"], res.attributes["asn"]) == ("US", "AS15169")
    assert res.attributes["continent"] == "NA" and res.attributes["in_eu"] is False
    assert res.attributes["as_org"].startswith("Google")
    assert any(p.entity.value == "AS15169" for p in res.pivots)
    assert any(line.startswith("DB-IP Lite country 2026-11") for line in res.attributes["dataset_age"])
    assert not http.calls  # local lookup, disclosure 'none'
    assert not {"city", "location", "postal", "subdivisions"} & set(str(res.raw).split("'"))


def test_ipv6_and_br_networks(maxminddb):
    install(COUNTRY, "dbip_country_lite_slice.mmdb")
    install(ASN, "dbip_asn_lite_slice.mmdb")
    assert run_module(IpOfflineGeo, "ipv4:200.160.2.3", FakeHttp()).attributes["country"] == "BR"
    v6 = run_module(IpOfflineGeo, "ipv6:2606:4700:4700::1111", FakeHttp())
    assert v6.status is Status.OK and v6.attributes["asn"] == "AS13335"


def test_ip_not_in_the_databases_is_empty(maxminddb):
    install(COUNTRY, "dbip_country_lite_slice.mmdb")
    install(ASN, "dbip_asn_lite_slice.mmdb")
    assert run_module(IpOfflineGeo, "ipv4:45.33.32.156", FakeHttp()).status is Status.EMPTY


def test_missing_dataset_is_unavailable_dataset(maxminddb):
    install(COUNTRY, "dbip_country_lite_slice.mmdb")
    http = FakeHttp()
    res = run_module(IpOfflineGeo, "ipv4:8.8.8.8", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "run v3lum data update" in res.error and not http.calls  # never downloaded by the module


def test_corrupt_local_copy_is_could_not_verify(maxminddb):
    (paths.datasets_dir() / COUNTRY).write_bytes(b"not an mmdb at all")
    install(ASN, "dbip_asn_lite_slice.mmdb")
    res = run_module(IpOfflineGeo, "ipv4:8.8.8.8", FakeHttp())
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_package_missing_is_unavailable_package():
    assert run_module(IpOfflineGeo, "ipv4:8.8.8.8", FakeHttp()).reason_code == "package"
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime()
    ip = Entity.make(EntityType.IPV4, "8.8.8.8")
    decision = policy.decide(IpOfflineGeo, ip, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ip, is_seed=True))
    assert (decision.status, decision.reason_code) == (Status.UNAVAILABLE, "package")


# ------------------------------------------------------------------ data update path (c1, c9)
def test_data_update_extracts_the_gzip_with_caps(monkeypatch):
    monkeypatch.setitem(DATASETS[COUNTRY], "min_bytes", 10)
    with open(f"{FIX}/dbip_country_lite_slice.mmdb.gz", "rb") as fh:
        body = fh.read()
    http = FakeHttp().add("GET", DATASETS[COUNTRY]["url"], body=body)
    rt = make_runtime(http)
    assert rt.data.update(COUNTRY).ok
    with open(paths.datasets_dir() / COUNTRY, "rb") as fh:
        assert MARKER in fh.read()
    bad = FakeHttp().add("GET", DATASETS[COUNTRY]["url"], body=gzip.compress(b"<html>Just a moment...</html>" * 10))
    rejected = make_runtime(bad).data.update(COUNTRY)  # an HTML page inside the gzip never replaces the good copy
    assert rejected.status == "failed" and "MaxMind DB" in rejected.reason
    with open(paths.datasets_dir() / COUNTRY, "rb") as fh:
        assert MARKER in fh.read()


def test_data_update_rejects_a_non_mmdb(monkeypatch):
    monkeypatch.setitem(DATASETS[ASN], "min_bytes", 10)
    http = FakeHttp().add("GET", DATASETS[ASN]["url"], body=gzip.compress(b"x" * 4096))
    result = make_runtime(http).data.update(ASN)
    assert result.status == "failed" and "MaxMind DB" in result.reason


# ------------------------------------------------------------------ GeoLite2 helpers (c6) and geo context (c8)
def test_geolite2_basic_auth_never_a_query_key_and_30_day_rule():
    req = geolite2_request("GeoLite2-Country", "123456", "lic-key-example")
    assert "license_key" not in req["url"] and req["url"].startswith("https://download.maxmind.com/geoip/databases/GeoLite2-Country/")
    assert req["headers"]["Authorization"].startswith("Basic ")
    assert geolite2_request("GeoLite2-ASN", "", "x") is None
    with pytest.raises(ValueError):
        geolite2_request("GeoLite2-City", "1", "2")
    now = datetime(2026, 11, 26, tzinfo=timezone.utc)
    assert geolite2_must_refresh(datetime(2026, 10, 20, tzinfo=timezone.utc), now) is True
    assert geolite2_must_refresh(datetime(2026, 11, 20, tzinfo=timezone.utc), now) is False


def test_city_location_and_postal_fields_are_never_copied():
    record = {"city": {"names": {"en": "Somewhere"}}, "location": {"latitude": 1.0, "longitude": 2.0}, "postal": {"code": "00000"},
              "subdivisions": [{"iso_code": "SP"}], "country": {"iso_code": "br", "is_in_european_union": False}, "continent": {"code": "SA"}}
    assert normalise_geo(record) == {"country": "BR", "continent": "SA", "in_eu": False}
