"""Scope files for ACTIVE engagements (A7, WP11): schema validation, window, wildcard and CIDR
matching, exclusions, CDN/shared-infrastructure rules, the third_party_hosted org exclusion and a
stable SHA-256."""

from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import noise
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.scope import RulesOfEngagement, Scope, ScopeError, ScopeLimits, authorization_ref_problem

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)

BASE: dict = {
    "authorization_ref": "PENTEST-2026-042",
    "owner": "ACME S.A. information security",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1234",
    "window_start": "2026-11-26T09:00:00Z",
    "window_end": "2026-11-27T18:00:00Z",
    "targets": {
        "domains": ["acme.example", "*.apps.acme.example"],
        "cidrs": ["93.184.216.0/24", "2001:4860:4860::/48"],
        "url_prefixes": ["https://portal.partner.example/acme/"],
    },
    "exclusions": {"domains": ["mail.apps.acme.example"], "cidrs": ["93.184.216.99/32"], "url_prefixes": ["https://portal.partner.example/acme/admin"]},
    "shared_infra_hosts": ["cdn.apps.acme.example"],
    "limits": {"max_rps": 5, "max_concurrency": 1, "max_pps": 200, "max_requests": 20000},
    "roe": {"user_agent": "pentest-PENTEST-2026-042", "header": {"name": "X-Engagement-Token", "value": "c0ffee42"}},
}

TOML = """
authorization_ref = "PENTEST-2026-042"
owner = "ACME S.A. information security"
contacts = ["soc@acme.example"]
ticket = "SEC-1234"
window_start = 2026-11-26T09:00:00Z
window_end = 2026-11-27T18:00:00Z
shared_infra_hosts = ["cdn.apps.acme.example"]

[targets]
domains = ["acme.example", "*.apps.acme.example"]
cidrs = ["93.184.216.0/24", "2001:4860:4860::/48"]
url_prefixes = ["https://portal.partner.example/acme/"]

[exclusions]
domains = ["mail.apps.acme.example"]
cidrs = ["93.184.216.99/32"]
url_prefixes = ["https://portal.partner.example/acme/admin"]

[limits]
max_rps = 5
max_concurrency = 1
max_pps = 200
max_requests = 20000

[roe]
user_agent = "pentest-PENTEST-2026-042"
header = {name = "X-Engagement-Token", value = "c0ffee42"}
"""


def scope(**changes) -> Scope:
    data = copy.deepcopy(BASE)
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return Scope.from_dict(data)


@pytest.fixture()
def cdn_list(tmp_path):
    """A CDN noise fragment covering 104.16.0.0/13 (a public range, as real CDN lists are)."""
    frag = tmp_path / "noise_frag"
    frag.mkdir()
    (frag / "test_cdn.json").write_text(
        json.dumps({"schema": "v3lum.noise/1", "kind": "cdn", "source": "test fixture", "licence": "CC0-1.0", "cidrs": ["104.16.0.0/13"]}),
        encoding="utf-8",
    )
    noise.reload(extra_dirs=[frag])
    yield
    noise.reload(extra_dirs=())


# --------------------------------------------------------------------------------------
# loading, schema and SHA-256
# --------------------------------------------------------------------------------------


def test_a_complete_scope_validates(tmp_path):
    sc = scope()
    assert sc.problems == ()
    assert sc.validate("PENTEST-2026-042", NOW) == []
    assert sc.limits == ScopeLimits(max_rps=5.0, max_concurrency=1, max_pps=200, max_requests=20000)
    assert (sc.limits.rps(), sc.limits.concurrency(), sc.limits.pps(), sc.limits.requests()) == (5.0, 1, 200, 20000)
    assert sc.roe == RulesOfEngagement("pentest-PENTEST-2026-042", "X-Engagement-Token", "c0ffee42")
    assert sc.in_window(NOW) and not sc.window_expired(NOW)
    assert "c0ffee42" not in json.dumps(sc.to_dict())  # the ROE token value never reaches the audit view


def test_json_and_toml_files_load_the_same_scope(tmp_path):
    pytest.importorskip("tomllib")
    jpath = tmp_path / "scope.json"
    jpath.write_text(json.dumps(BASE), encoding="utf-8")
    tpath = tmp_path / "scope.toml"
    tpath.write_text(TOML, encoding="utf-8")
    js, ts = Scope.load(jpath), Scope.load(tpath)
    assert js.problems == ts.problems == ()
    assert js.to_dict() | {"sha256": "", "path": ""} == ts.to_dict() | {"sha256": "", "path": ""}
    assert js.window_start == ts.window_start == dt.datetime(2026, 11, 26, 9, 0, tzinfo=dt.timezone.utc)


def test_sha256_is_the_file_digest_and_stable(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(BASE), encoding="utf-8")
    import hashlib

    first, second = Scope.load(path), Scope.load(path)
    assert first.sha256 == second.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_text(json.dumps(dict(BASE, ticket="SEC-9999")), encoding="utf-8")
    assert Scope.load(path).sha256 != first.sha256
    # without a file the digest is the canonical JSON of the data (key order does not matter)
    shuffled = dict(reversed(list(BASE.items())))
    assert Scope.from_dict(BASE).sha256 == Scope.from_dict(shuffled).sha256


@pytest.mark.parametrize(
    ("content", "suffix", "needle"),
    [
        ("{not json", ".json", "not a valid scope file"),
        ("[1, 2]", ".json", "table/object"),
        ("authorization_ref = ", ".toml", "not a valid scope file"),
    ],
)
def test_unparsable_files_raise_scope_error(tmp_path, content, suffix, needle):
    if suffix == ".toml":
        pytest.importorskip("tomllib")
    path = tmp_path / f"scope{suffix}"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ScopeError) as err:
        Scope.load(path)
    assert needle in str(err.value)


def test_a_missing_file_raises_scope_error(tmp_path):
    with pytest.raises(ScopeError, match="cannot read scope file"):
        Scope.load(tmp_path / "absent.toml")


@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"authorization_ref": None}, "authorization_ref"),
        ({"authorization_ref": "confirmed"}, "placeholder"),
        ({"owner": ""}, "owner is required"),
        ({"contacts": []}, "deconfliction contact"),
        ({"ticket": None}, "ticket is required"),
        ({"window_start": "2026-11-26T09:00:00"}, "no UTC offset"),
        ({"window_end": "yesterday"}, "not an ISO-8601"),
        ({"window_end": "2026-11-26T08:00:00Z"}, "window_end must be after window_start"),
        ({"targets": {}}, "targets lists nothing"),
        ({"targets": {"domains": ["*.com"]}}, "wildcard over a public suffix"),
        ({"targets": {"domains": ["co.uk"]}}, "public suffix"),
        ({"targets": {"domains": ["*"]}}, "not a host name"),
        ({"targets": {"domains": ["10.0.0.1"]}}, "IPs go in cidrs"),
        ({"targets": {"cidrs": ["0.0.0.0/0"]}}, "too broad"),
        ({"targets": {"cidrs": ["2001::/16"]}}, "too broad"),
        ({"targets": {"cidrs": ["999.1.1.0/24"]}}, "not an IP network"),
        ({"targets": {"url_prefixes": ["ftp://acme.example/"]}}, "http(s) URL prefix"),
        ({"targets": {"url_prefixes": ["https://user:pw@acme.example/"]}}, "without credentials"),
        ({"targets": {"hosts": ["acme.example"]}}, "unknown keys"),
        ({"shared_infra_hosts": ["cdn.other.example"]}, "not covered by targets.domains"),
        ({"limits": {"max_rps": 11}}, "above the A7 ceiling"),
        ({"limits": {"max_concurrency": 3}}, "above the A7 ceiling"),
        ({"limits": {"max_pps": 1001}}, "above the A7 ceiling"),
        ({"limits": {"max_requests": 50001}}, "above the A7 ceiling"),
        ({"limits": {"max_rps": 0}}, "greater than 0"),
        ({"limits": {"max_concurrency": 1.5}}, "whole"),
        ({"roe": {"user_agent": "V3LUM/1.0 (+soc@acme.example)"}}, "V3LUM user agent"),
        ({"roe": {"user_agent": "Mozilla/5.0 (compatible; V3LUM/1.0)"}}, "V3LUM user agent"),  # anywhere in the value
        ({"roe": {"header": {"name": "X-Engagement-Token", "value": "team-v3lum-42"}}}, "V3LUM user agent"),
        ({"roe": {"user_agent": "scanner (cti@acme.example)"}}, "mailbox"),
        ({"roe": {"header": {"name": "Authorization", "value": "Bearer x"}}}, "not allowed"),
        ({"roe": {"header": {"name": "X-Token", "value": ""}}}, "non-empty value"),
        ({"windows": "x"}, "unknown keys"),
    ],
)
def test_malformed_scopes_are_reported_by_validate(changes, needle):
    sc = scope(**changes)
    problems = sc.validate("PENTEST-2026-042", NOW)
    assert any(needle in p for p in problems), problems
    assert sc.allows_contact("acme.example", ["93.184.216.34"]) == (False, sc.allows_contact("acme.example", ["93.184.216.34"])[1])
    assert "problems" in sc.allows_contact("acme.example", ["93.184.216.34"])[1]  # fail closed


def test_validate_reports_ref_mismatch_window_and_org_identity():
    sc = scope()
    assert any("mismatch" in p for p in sc.validate("PENTEST-2026-043", NOW))
    assert any("no --authorized" in p for p in sc.validate("", NOW))
    before = dt.datetime(2026, 11, 26, 8, 59, tzinfo=dt.timezone.utc)
    after = dt.datetime(2026, 11, 27, 18, 0, tzinfo=dt.timezone.utc)
    assert any("opens at" in p for p in sc.validate("PENTEST-2026-042", before))
    assert any("closed at" in p for p in sc.validate("PENTEST-2026-042", after))
    assert not sc.in_window(before) and sc.window_expired(after) and not sc.window_expired(before)
    named = scope(roe={"user_agent": "acme-redteam-2026"})
    assert any("names the organisation" in p for p in named.validate("PENTEST-2026-042", NOW, org_terms=["ACME", "x"]))


@pytest.mark.parametrize(
    ("ref", "ok"),
    [("PENTEST-2026-042", True), ("SEC:1234#a/b", True), ("ab", False), ("confirmed", False), ("YES", False), ("n/a", False), ("-x-1", False), ("", False)],
)
def test_authorization_ref_rules(ref, ok):
    assert (authorization_ref_problem(ref) == "") is ok


# --------------------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("acme.example", True),  # exact
        ("ACME.example.", True),
        ("www.acme.example", False),  # exact entries never cover subdomains
        ("x.apps.acme.example", True),  # wildcard: strict subdomains
        ("deep.x.apps.acme.example", True),
        ("apps.acme.example", False),  # the wildcard never covers its apex
        ("mail.apps.acme.example", False),  # excluded
        ("evilacme.example", False),
        ("93.184.216.34", True),  # an IP host matches the CIDRs
        ("93.184.216.99", False),  # excluded address
        ("2001:4860:4860::8888", True),
        ("8.8.8.8", False),
    ],
)
def test_matches_host(host, expected):
    assert scope().matches_host(host) is expected


@pytest.mark.parametrize(
    ("ip", "expected"),
    [("93.184.216.1", True), ("::ffff:93.184.216.1", True), ("93.184.216.99", False), ("93.184.217.1", False), ("not-an-ip", False)],
)
def test_matches_ip(ip, expected):
    assert scope().matches_ip(ip) is expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://portal.partner.example/acme/", True),
        ("https://portal.partner.example/acme/login?x=1", True),
        ("https://portal.partner.example/acmeco/", False),  # segment-aware prefix
        ("https://portal.partner.example/acme/admin", False),  # excluded prefix wins
        ("https://portal.partner.example/acme/admin/users", False),
        ("http://portal.partner.example/acme/", False),  # scheme is part of the prefix
        ("https://portal.partner.example:8443/acme/", False),
        ("https://acme.example/anything", True),  # the host is a target
        ("https://mail.apps.acme.example/", False),
        ("ftp://acme.example/", False),
    ],
)
def test_matches_url(url, expected):
    assert scope().matches_url(url) is expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # what requests/urllib3 actually send (dot segments removed, unreserved escapes decoded)
        ("https://portal.partner.example/acme/./login", True),
        ("https://portal.partner.example/acme/../private", False),  # sent as /private: outside the prefix
        ("https://portal.partner.example/acme/%2e%2e/private", False),
        ("https://portal.partner.example/acme/..%2fprivate", False),  # a server may take %2f as '/'
        ("https://portal.partner.example/%61cme/login", True),  # %61 is 'a': sent as /acme/login
        # exclusions see every form a server may give the path, case-insensitively
        ("https://portal.partner.example/acme/x/../admin", False),
        ("https://portal.partner.example/acme/%61dmin", False),
        ("https://portal.partner.example/acme//admin", False),
        ("https://portal.partner.example/acme/ADMIN", False),
        ("https://portal.partner.example/acme/x%2f..%2fadmin", False),
    ],
)
def test_url_prefixes_judge_the_path_the_server_sees(url, expected):
    """A prefix or exclusion is matched against the path the transport sends and the server sees,
    never the literal text: dot segments and percent-encoding cannot leave a target prefix or slip
    past an exclusion (AR02)."""
    sc = scope()
    assert sc.matches_url(url) is expected
    assert sc.allows_contact("portal.partner.example", ["8.8.4.4"], probe="http", url=url)[0] is expected  # not a target CIDR


def test_an_excluded_directory_also_covers_its_bare_path():
    sc = scope(exclusions={"url_prefixes": ["https://acme.example/admin/"]})
    for url in ("https://acme.example/admin/", "https://acme.example/admin", "https://acme.example/Admin/users", "https://acme.example/x/../admin/"):
        assert not sc.matches_url(url), url
    assert sc.matches_url("https://acme.example/administrator")  # segment-aware


def test_prefixes_are_stored_canonical_and_ambiguous_ones_refused():
    sc = scope(targets={"url_prefixes": ["https://portal.partner.example/a/./b/../acme/"]})
    assert sc.targets.url_prefixes == (("https", "portal.partner.example", 443, "/a/acme/"),)
    bad = scope(targets={"url_prefixes": ["https://portal.partner.example/a%2Fb/"]})
    assert any("encoded slash" in p for p in bad.problems)


# --------------------------------------------------------------------------------------
# allows_contact
# --------------------------------------------------------------------------------------


def test_private_and_metadata_addresses_need_an_explicit_listing():
    sc = scope()
    for ip in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.1.1", "fc00::1"):
        ok, why = sc.allows_contact("acme.example", [ip])
        assert not ok and "not listed in the scope" in why
    listed = scope(targets={"domains": ["intranet.acme.example"], "cidrs": ["10.0.0.0/24"]}, shared_infra_hosts=None)
    assert listed.allows_contact("intranet.acme.example", ["10.0.0.5"]) == (True, "")
    assert not listed.allows_contact("intranet.acme.example", ["10.0.1.5"])[0]


def test_out_of_scope_and_excluded_hosts_are_refused():
    sc = scope()
    assert sc.allows_contact("acme.example", ["93.184.216.34"]) == (True, "")
    assert sc.allows_contact("other.example", ["8.8.8.8"])[1] == "other.example is outside the scope"
    assert "excluded" in sc.allows_contact("mail.apps.acme.example", ["93.184.216.34"])[1]
    assert "excluded" in sc.allows_contact("acme.example", ["93.184.216.99"])[1]  # a resolved address excluded
    # a name outside the domains is in scope when every resolved address is a listed target
    assert sc.allows_contact("www.acme-cdn.example", ["93.184.216.10"]) == (True, "")
    assert not sc.allows_contact("www.acme-cdn.example", ["93.184.216.10", "8.8.8.8"])[0]
    # URL prefixes make their host contactable for HTTP probes of those paths only
    assert sc.allows_contact("portal.partner.example", ["93.184.216.20"], url="https://portal.partner.example/acme/x")[0]
    assert not sc.allows_contact("portal.partner.example", ["8.8.4.4"], url="https://portal.partner.example/other")[0]
    assert not sc.allows_contact("portal.partner.example", ["93.184.216.20"], url="https://portal.partner.example/acme/admin")[0]


def test_cdn_addresses_need_shared_infra_hosts_for_http_and_the_ip_for_network(cdn_list):
    sc = scope(targets={"domains": ["acme.example", "*.apps.acme.example"], "cidrs": ["93.184.216.0/24"]})
    cdn_ip = "104.16.1.1"
    ok, why = sc.allows_contact("www.apps.acme.example", [cdn_ip], probe="http")
    assert not ok and "shared_infra_hosts" in why
    assert sc.allows_contact("cdn.apps.acme.example", [cdn_ip], probe="http") == (True, "")  # listed host
    ok, why = sc.allows_contact("cdn.apps.acme.example", [cdn_ip], probe="network")
    assert not ok and "IP/CIDR listed" in why  # shared_infra_hosts never opens network probes
    listed = scope(targets={"domains": ["acme.example", "*.apps.acme.example"], "cidrs": ["104.16.1.1/32"]})
    assert listed.allows_contact("cdn.apps.acme.example", [cdn_ip], probe="network") == (True, "")


def test_shared_hosting_names_need_shared_infra_hosts():
    sc = scope(targets={"domains": ["acme.github.io"]}, shared_infra_hosts=["acme.github.io"])
    assert sc.allows_contact("acme.github.io", ["185.199.108.153"], probe="http") == (True, "")
    bare = scope(targets={"domains": ["acme.github.io"]}, shared_infra_hosts=None)
    ok, why = bare.allows_contact("acme.github.io", ["185.199.108.153"], probe="http")
    assert not ok and "shared hosting infrastructure" in why


def test_third_party_hosted_org_addresses_are_excluded_from_network_probes_unless_listed():
    org = OrgProfile.from_dict(
        {"domains": [{"name": "shop.acme.example", "verification": "txt_verified", "third_party_hosted": True}], "cidrs": [{"value": "93.184.216.0/26", "third_party_hosted": True}]}
    )
    sc = scope(targets={"domains": ["acme.example", "*.acme.example"]})
    ok, why = sc.allows_contact("www.acme.example", ["93.184.216.34"], probe="network", org=org)
    assert not ok and "third_party_hosted" in why
    assert sc.allows_contact("www.acme.example", ["93.184.216.34"], probe="http", org=org) == (True, "")  # HTTP is not a network probe
    assert not sc.allows_contact("shop.acme.example", ["93.184.217.5"], probe="network", org=org)[0]  # flagged domain entry
    listed = scope(targets={"domains": ["acme.example", "*.acme.example"], "cidrs": ["93.184.216.34/32"]})
    assert listed.allows_contact("www.acme.example", ["93.184.216.34"], probe="network", org=org) == (True, "")
    assert sc.allows_contact("www.acme.example", ["93.184.217.5"], probe="network", org=org) == (True, "")  # not flagged


def test_window_expiry_is_fail_closed_for_a_malformed_window():
    assert scope(window_end="bad").window_expired(NOW)
    assert not scope(window_end="bad").in_window(NOW)


def test_bad_probe_kind_is_a_programming_error():
    with pytest.raises(ValueError):
        scope().allows_contact("acme.example", [], probe="udp")


def test_load_accepts_a_path_string(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps(BASE), encoding="utf-8")
    assert Scope.load(str(path)).path == str(Path(path))


def test_contract_additions_names_resolve():
    """Every backticked v3lum.* name of docs/contract_additions/WP11.md exists (module attribute,
    class attribute, dataclass field, or an attribute of a fresh instance of the class)."""
    import dataclasses
    import importlib
    import re

    from tests.fakes import FakeClock, FakeHttp
    from v3lum.core.http import HttpClient
    from v3lum.core.net import Connector, EgressProfiles

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP11.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`", doc)))
    instances = [Connector(module="t"), HttpClient(transport=FakeHttp(clock=FakeClock())), EgressProfiles(), Scope.from_dict(BASE)]
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        obj, rest = None, []
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for i, attr in enumerate(rest):
            if hasattr(obj, attr):
                obj = getattr(obj, attr)
                continue
            last = i == len(rest) - 1
            if last and dataclasses.is_dataclass(obj) and attr in {f.name for f in dataclasses.fields(obj)}:
                break
            inst = next((x for x in instances if isinstance(obj, type) and isinstance(x, obj)), None)
            if last and inst is not None and hasattr(inst, attr):
                break
            missing.append(dotted)
            break
    assert len(names) > 25 and not missing, missing
