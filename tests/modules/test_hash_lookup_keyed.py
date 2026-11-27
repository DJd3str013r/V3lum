"""P177 cross-adapter tests: allow-lists (FC2), keys (FC1/FC4), order, tiers and votes (FC5/FC6)."""

from __future__ import annotations

import inspect
import re

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core import providers
from v3lum.core.models import Status
from v3lum.modules.malware_hash import hash_lookup_keyed as hk

ADAPTERS = (hk.Triage, hk.MetaDefender, hk.MalShare, hk.PolySwarm, hk.VirusShare)
H32 = "44d88612fea8a8f36de82e1278abb02f"
H64 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SID = "201026-n8zz26cd4s"

ALLOWED = [
    ("triage", "GET", f"https://tria.ge/api/v0/search?query=sha256:{H64}&limit=10", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/{SID}/overview.json", None),
    ("metadefender", "GET", f"https://api.metadefender.com/v4/hash/{H64}", None),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "details", "hash": H32}),
    ("malshare", "GET", "https://malshare.com/api.php?action=getlimit&api_key=k", None),
    ("polyswarm", "GET", "https://api.polyswarm.network/v3/search/hash/md5", {"hash": H32, "community": "default"}),
    ("virusshare", "GET", "https://virusshare.com/apiv2/file", {"apikey": "k", "hash": H64}),
]

#: download, submission, deletion and other non-search endpoints of the providers' documentation
FORBIDDEN = [
    ("triage", "POST", "https://tria.ge/api/v0/samples", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/{SID}/sample", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/{SID}/behavioral1/files/payload.exe", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/{SID}/behavioral1/dump.pcap", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/{SID}/behavioral1/memory/1.dmp", None),
    ("triage", "DELETE", f"https://tria.ge/api/v0/samples/{SID}", None),
    ("triage", "POST", f"https://tria.ge/api/v0/samples/{SID}/profile", None),
    ("triage", "GET", "https://tria.ge/api/v0/samples/events", None),
    ("triage", "GET", "https://tria.ge/api/v0/search?query=family:emotet", None),
    ("triage", "GET", f"https://tria.ge/api/v0/samples/../../{SID}/overview.json", None),
    ("triage", "GET", f"http://tria.ge/api/v0/search?query=sha256:{H64}", None),
    ("triage", "GET", f"https://evil.example/api/v0/search?query=sha256:{H64}", None),
    ("metadefender", "POST", "https://api.metadefender.com/v4/file", None),
    ("metadefender", "GET", "https://api.metadefender.com/v4/file/bzIwMDkyMEp6eWVBZEhqUnZ", None),
    ("metadefender", "GET", "https://api.metadefender.com/v4/file/converted/bzIwMDkyMEp6eWVBZEhqUnZ", None),
    ("metadefender", "GET", f"https://api.metadefender.com/v4/hash/{H64}/download", None),
    ("metadefender", "POST", f"https://api.metadefender.com/v4/hash/{H64}/rescan", None),
    ("metadefender", "GET", f"https://api.metadefender.com/v4/hash/{H64}?apikey=x", None),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "getfile", "hash": H32}),
    ("malshare", "POST", "https://malshare.com/api.php", {"api_key": "k", "action": "upload"}),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "download_url", "url": "https://x.example/"}),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "download_url_check", "guid": "1"}),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "getlist"}),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "getsources"}),
    ("malshare", "GET", "https://malshare.com/api.php", {"api_key": "k", "action": "search", "query": "x"}),
    ("malshare", "GET", "https://malshare.com/api.php?action=getfile&hash=" + H32, {"api_key": "k"}),
    ("malshare", "GET", "https://malshare.com/api.php?action=details&action=getfile&hash=" + H32, None),
    ("polyswarm", "GET", f"https://api.polyswarm.network/v3/consumer/download/sha256/{H64}", None),
    ("polyswarm", "GET", "https://api.polyswarm.network/v3/instance/download", {"id": "1"}),
    ("polyswarm", "POST", "https://api.polyswarm.network/v3/instance", None),
    ("polyswarm", "PUT", "https://api.polyswarm.network/v3/instance", None),
    ("polyswarm", "POST", f"https://api.polyswarm.network/v3/consumer/submission/default/rescan/sha256/{H64}", None),
    ("polyswarm", "POST", "https://api.polyswarm.network/v3/sandbox/sandboxtask", None),
    ("polyswarm", "GET", "https://api.polyswarm.network/v3/search/hash/sha256", {"hash": H64, "community": "default", "with_bundle": "1"}),
    ("virusshare", "GET", "https://virusshare.com/apiv2/download", {"apikey": "k", "hash": H64}),
    ("virusshare", "GET", "https://virusshare.com/apiv2/source", {"apikey": "k", "hash": H64}),
    ("virusshare", "POST", "https://virusshare.com/apiv2/file", {"apikey": "k", "hash": H64}),
    ("virusshare", "GET", "https://virusshare.com/hashfiles/VirusShare_00000.md5", None),
    ("unknown", "GET", "https://example.com/", None),
]


@pytest.mark.parametrize(("provider", "method", "url", "params"), ALLOWED)
def test_search_and_metadata_requests_pass_the_allow_list(provider, method, url, params) -> None:
    assert hk.check_request(provider, method, url, params) is None


@pytest.mark.parametrize(("provider", "method", "url", "params"), FORBIDDEN)
def test_download_submission_and_other_endpoints_are_never_built(provider, method, url, params) -> None:
    assert hk.check_request(provider, method, url, params), (provider, method, url, params)


def test_guard_raises_policy_error() -> None:
    with pytest.raises(hk.PolicyError):
        hk.guard("malshare", "GET", "https://malshare.com/api.php", {"action": "getfile", "hash": H32})


def test_every_request_the_adapters_send_passes_its_allow_list() -> None:
    """Run each adapter on its happy path and re-check the exact URLs it sent."""
    key = "adapter-test-key-0123456789abcdef"
    sent: list[tuple[str, str]] = []
    for cls, provider in ((hk.MetaDefender, "metadefender"), (hk.VirusShare, "virusshare"), (hk.PolySwarm, "polyswarm"), (hk.MalShare, "malshare")):
        http = FakeHttp().add("GET", re.compile(r"^https://"), status=404, json={})
        run_module(cls, f"sha256:{H64}", http, keys={cls.requires_keys[0]: key})
        sent += [(provider, c["url"]) for c in http.calls]
    assert len(sent) == 4
    for provider, url in sent:
        assert hk.check_request(provider, "GET", url) is None, url


def test_one_module_per_provider_in_the_council_order_all_opt_in() -> None:
    order = [name for name, obj in inspect.getmembers(hk, inspect.isclass) if obj in ADAPTERS]
    assert {c.name for c in ADAPTERS} == {"triage", "metadefender", "malshare", "polyswarm", "virusshare"}
    src = inspect.getsource(hk)
    positions = [src.index(f"class {c.__name__}(Module)") for c in ADAPTERS]
    assert positions == sorted(positions), order  # Triage, then MetaDefender, then the rest
    for cls in ADAPTERS:
        assert cls.default_enabled is False and cls.disclosure == "third_party"
        assert len(cls.requires_keys) == 1 and cls.requires_keys[0] == cls.name
        assert cls.daily_quota and cls.max_requests >= 1
    assert len({c.requires_keys[0] for c in ADAPTERS}) == 5  # each adapter has its own key


def test_terms_tiers_and_votes_follow_the_council() -> None:
    expected = {
        "triage": ("noncommercial", "trusted"), "metadefender": ("noncommercial", "trusted"),
        "malshare": ("unknown", "community"), "polyswarm": ("unknown", "trusted"), "virusshare": ("unknown", "community"),
    }
    for cls in ADAPTERS:
        assert (cls.terms, cls.trust_tier) == expected[cls.name]
    families = [frozenset(c.upstream_families) for c in ADAPTERS]
    assert len(set(families)) == 5  # one vote per adapter
    assert hk.MetaDefender.upstream_families == frozenset({"opswat"})  # shared with Filescan (P171)
    reg = providers.registry()
    assert reg.source("filescan.filescan_reputation").upstream_family == "opswat"


@pytest.mark.parametrize("key", ["", "  ", "none", "your_api_key", "abc", "0123456789abcde", "key with spaces 0123", None, 42])
def test_unusable_keys(key) -> None:
    assert not hk.usable_key(key)


def test_usable_key() -> None:
    assert hk.usable_key("0123456789abcdef")


def test_virusshare_204_marker_classifies_before_parsing() -> None:
    from v3lum.core.http import Response, classify

    marker = next(m for m in providers.registry().get("virusshare").error_markers if m.id == "virusshare_rate_limit_204")
    found = classify(Response(204, "https://virusshare.com/apiv2/file", {}, b""), markers=(marker,))
    assert found is not None and found.status == "rate_limited"
    res = run_module(hk.VirusShare, f"md5:{H32}", FakeHttp().add("GET", re.compile(r"^https://virusshare\.com/apiv2/file"), status=204, body=b""),
                     keys={"virusshare": "virusshare-key-0123456789abcdef"})
    assert res.status is Status.RATE_LIMITED


def test_parsers_survive_wrong_types() -> None:
    for parse in (hk.parse_triage_search, hk.parse_triage_overview, hk.parse_metadefender_hash, hk.parse_malshare_details,
                  hk.parse_polyswarm_search, hk.parse_virusshare_file):
        for junk in (None, [], "x", 3, {"data": "x", "result": 1, "sample": [], "scan_results": "y"}):
            assert parse(junk)["status"] in ("error", "empty")
    assert hk.parse_endpoint("tcp://[2001:db8::5]:99") == {"type": "ipv6", "value": "2001:db8::5", "port": 99, "url": None}
    assert hk.parse_endpoint("10.0.0.1:80") == {"skip": "non-routable address 10.0.0.1"}
    assert hk.parse_endpoint("a b") is None and hk.parse_endpoint("host:99999") is None
    assert hk.parse_ssdeep("3:abc:def") == "3:abc:def" and hk.parse_ssdeep("5:abc:def") is None
    assert hk.normalize_tlsh("TNULL") is None and hk.normalize_tlsh("a" * 70) == "T1" + "A" * 70
    assert hk.iso_utc("12/31/2022, 01:15:32") == "2022-12-31T01:15:32Z" and hk.iso_utc("junk") is None
