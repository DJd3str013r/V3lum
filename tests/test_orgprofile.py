"""Organisation profile (P378 conditions 1-4 and 6): TOML/JSON load, collected errors, ownership
by PSL + label match and ipaddress containment, verified semantics."""

from __future__ import annotations

import importlib.util
import json

import pytest

from v3lum.core import orgprofile
from v3lum.core.entities import Entity
from v3lum.core.orgprofile import (
    NOT_OWNED,
    BrandEntry,
    DomainEntry,
    OrgProfile,
    Ownership,
    fold,
    load_default,
)

TOML = """
cnpj_roots = ["43.828.151"]
card_bins = ["412345"]
favicon_hashes = ["-1234567890"]

[org]
name = "ACME S.A."
card_bins = ["51234567"]

[[domains]]
name = "acme.com.br"
verification = "txt_verified"
criticality = "high"

[[domains]]
name = "cdn.acme.com.br"
verification = "confirmed"
third_party_hosted = true
criticality = "low"

[[domains]]
name = "açúcar.com.br"
verification = "attested"
attested = { by = "Analyst One", date = 2026-11-01 }

[[domains]]
name = "acme-seeded.com"

[[brands]]
keyword = "Açme"
variants = ["acrne", "ACMÉ"]
criticality = "high"

[[asns]]
value = "AS64500"

[[cidrs]]
value = "203.0.113.0/24"
criticality = "high"

[[cidrs]]
value = "203.0.113.128/25"
third_party_hosted = true

[[cidrs]]
value = "2001:db8:ac::/48"

[[app_ids]]
kind = "m365_tenant"
value = "00000000-0000-0000-0000-000000000000"

[[suppliers]]
name = "Supplier Ltd"
domains = ["supplier.example"]
brands = ["supplierbrand"]

[[executives]]
name = "Executive Person"
opt_in = true
programme = "VIP protection"
informed_at = 2026-10-01
"""


#: The TOML document above as JSON (TOML dates become ISO strings). Python 3.10 has no tomllib, so
#: the shared fixture loads this JSON there (the tree stays green on 3.10 until WP29, AR23).
JSON_DOC = {
    "cnpj_roots": ["43.828.151"],
    "card_bins": ["412345"],
    "favicon_hashes": ["-1234567890"],
    "org": {"name": "ACME S.A.", "card_bins": ["51234567"]},
    "domains": [
        {"name": "acme.com.br", "verification": "txt_verified", "criticality": "high"},
        {"name": "cdn.acme.com.br", "verification": "confirmed", "third_party_hosted": True, "criticality": "low"},
        {"name": "açúcar.com.br", "verification": "attested", "attested": {"by": "Analyst One", "date": "2026-11-01"}},
        {"name": "acme-seeded.com"},
    ],
    "brands": [{"keyword": "Açme", "variants": ["acrne", "ACMÉ"], "criticality": "high"}],
    "asns": [{"value": "AS64500"}],
    "cidrs": [
        {"value": "203.0.113.0/24", "criticality": "high"},
        {"value": "203.0.113.128/25", "third_party_hosted": True},
        {"value": "2001:db8:ac::/48"},
    ],
    "app_ids": [{"kind": "m365_tenant", "value": "00000000-0000-0000-0000-000000000000"}],
    "suppliers": [{"name": "Supplier Ltd", "domains": ["supplier.example"], "brands": ["supplierbrand"]}],
    "executives": [{"name": "Executive Person", "opt_in": True, "programme": "VIP protection", "informed_at": "2026-10-01"}],
}
HAS_TOML = importlib.util.find_spec("tomllib") is not None
needs_toml = pytest.mark.skipif(not HAS_TOML, reason="TOML profiles need Python 3.11+ (tomllib)")


def E(etype: str, value: str) -> Entity:
    return Entity.make(etype, value)


@pytest.fixture
def profile(tmp_path) -> OrgProfile:
    if HAS_TOML:
        path = tmp_path / "org_profile.toml"
        path.write_text(TOML, encoding="utf-8")
    else:  # Python 3.10: the same profile as JSON
        path = tmp_path / "org_profile.json"
        path.write_text(json.dumps(JSON_DOC), encoding="utf-8")
    path.chmod(0o600)  # P378 cond 1: the profile is a 0600 file
    prof = OrgProfile.load(path)
    assert prof.errors == []
    return prof


# --------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------


@needs_toml
def test_toml_load(profile, tmp_path):
    assert profile.name == "ACME S.A."
    assert [d.name for d in profile.domains] == ["acme.com.br", "cdn.acme.com.br", "xn--acar-0oa8i.com.br", "acme-seeded.com"]
    attested = profile.domains[2]
    assert attested.verification == "attested" and attested.attested_by == "Analyst One" and attested.attested_date == "2026-11-01"
    assert profile.domains[3].verification == "seeded" and profile.domains[3].criticality == "medium"
    assert profile.cnpj_roots == ["43828151"]
    assert profile.card_bins == ["412345", "51234567"]  # top-level and [org] lists are merged
    assert profile.favicon_hashes == ["-1234567890"]
    assert [n.value for n in profile.cidrs] == ["203.0.113.0/24", "203.0.113.128/25", "2001:db8:ac::/48"]
    assert profile.asns[0].value == "AS64500"
    assert profile.app_ids[0].kind == "m365_tenant"
    assert profile.executives[0].informed_at == "2026-10-01"
    assert profile.path.endswith("org_profile.toml") and len(profile.sha256) == 64
    import hashlib

    assert profile.sha256 == hashlib.sha256((tmp_path / "org_profile.toml").read_bytes()).hexdigest()
    assert not profile.is_empty


def test_json_load_and_round_trip(profile, tmp_path):
    path = tmp_path / "org.json"
    path.write_text(json.dumps(profile.to_dict()), encoding="utf-8")
    path.chmod(0o600)
    again = OrgProfile.load(path)
    assert again.errors == []
    assert again.to_dict() == profile.to_dict()
    assert again.domains == profile.domains and again.brands == profile.brands


@needs_toml
def test_toml_and_json_documents_are_the_same_profile(tmp_path):
    toml_path, json_path = tmp_path / "org_profile.toml", tmp_path / "org_profile.json"
    toml_path.write_text(TOML, encoding="utf-8")
    json_path.write_text(json.dumps(JSON_DOC), encoding="utf-8")
    for path in (toml_path, json_path):
        path.chmod(0o600)
    from_toml, from_json = OrgProfile.load(toml_path), OrgProfile.load(json_path)
    assert from_toml.errors == from_json.errors == []
    assert from_toml.to_dict() == from_json.to_dict()


def test_toml_without_tomllib_is_a_clear_error_never_a_crash(tmp_path, monkeypatch):
    """Python 3.10 (no tomllib): a .toml profile is reported in errors with the JSON alternative."""
    monkeypatch.setattr(orgprofile, "_toml", None)
    path = tmp_path / "org_profile.toml"
    path.write_text(TOML, encoding="utf-8")
    path.chmod(0o600)
    prof = OrgProfile.load(path)
    assert prof.is_empty and prof.errors == ["TOML profiles need Python 3.11+ (tomllib): use an org_profile.json"]


def test_missing_file_is_empty_profile(tmp_path):
    prof = OrgProfile.load(tmp_path / "nope.toml")
    assert prof.is_empty and prof.errors == [] and prof.owns(E("domain", "acme.com.br")) == NOT_OWNED
    assert OrgProfile.empty().is_empty


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        pytest.param("bad.toml", "[[domains]\nname = ", "invalid TOML", marks=needs_toml),
        ("bad.json", "{not json", "invalid JSON"),
        ("list.json", "[1, 2]", "must be a table"),
        ("latin1.toml", "name = 'caf\xe9'", "not UTF-8"),
    ],
)
def test_parse_errors_are_collected_not_raised(tmp_path, name, content, expected):
    path = tmp_path / name
    path.write_bytes(content.encode("latin-1"))
    prof = OrgProfile.load(path)
    assert prof.is_empty
    assert any(expected in e for e in prof.errors), prof.errors


def test_entry_errors_are_collected_and_fail_closed():
    prof = OrgProfile.from_dict(
        {
            "org": {"name": "X", "colour": "blue"},
            "typo_domains": [],
            "domains": [
                "com.br",  # a public suffix
                "not a domain",
                {"name": "ok.example", "verification": "trusted"},  # unknown state -> seeded
                {"name": "att.example", "verification": "attested"},  # no by/date -> confirmed
                {"name": "att2.example", "verification": "attested", "attested_by": "A", "attested_date": "01/11/2026"},
                {"name": "ok.example", "verification": "txt_verified"},  # duplicate: first kept
                {"name": "crit.example", "criticality": "urgent", "third_party_hosted": "yes", "extra": 1},
                42,
            ],
            "card_bins": ["4111111111111111", "12345"],
            "cnpj_roots": ["43.828.151/0001-45", "123"],
            "asns": ["AS-x", {"value": "64501", "criticality": "low"}],
            "cidrs": ["300.0.0.0/8", "198.51.100.7"],
            "favicon_hashes": ["abc"],
            "app_ids": [{"kind": "m365_tenant"}],
            "suppliers": [{"domains": ["s.example"]}, {"name": "S", "domains": ["bad domain", "s.example"]}],
            "executives": [
                {"name": "Person One", "opt_in": False, "informed_at": "2026-01-01"},
                {"name": "Person Two", "opt_in": True},
                {"name": "Person Three", "opt_in": "true", "informed_at": "2026-01-01"},
            ],
            "brands": [{"variants": ["x"]}, {"keyword": "b", "variants": "notalist"}],
        }
    )
    text = "\n".join(prof.errors)
    for expected in (
        "unknown keys ['typo_domains']", "org: unknown keys ['colour']", "domains[0]", "domains[1]", "treated as seeded",
        "treated as confirmed", "duplicate domain ok.example", "criticality must be one of", "expected true/false",
        "card_bins[0]", "card_bins[1]", "only its 8-character root is kept", "cnpj_roots[1]", "asns[0]", "cidrs[0]",
        "favicon_hashes[0]", "app_ids[0]", "suppliers[0]", "suppliers[1].domains[0]", "executives[0]", "executives[1]",
        "executives[2]", "brands[0]", "brands[1].variants",
    ):
        assert expected in text, expected
    assert "4111111111111111" not in text  # a full card number is never echoed
    assert "Person" not in text  # executive names never appear in messages
    assert prof.card_bins == [] and prof.executives == []
    verification = {d.name: d.verification for d in prof.domains}
    assert verification == {"ok.example": "seeded", "att.example": "confirmed", "att2.example": "confirmed", "crit.example": "seeded"}
    assert prof.domains[-1].criticality == "medium" and prof.domains[-1].third_party_hosted is False
    assert prof.cnpj_roots == ["43828151"]
    assert [n.value for n in prof.asns] == ["AS64501"]
    assert [n.value for n in prof.cidrs] == ["198.51.100.7/32"]
    assert prof.suppliers[0].domains == ("s.example",)


# --------------------------------------------------------------------------------------
# ownership
# --------------------------------------------------------------------------------------


def test_owns_domains_subdomains_email_and_url(profile):
    own = profile.owns(E("domain", "acme.com.br"))
    assert own.own and own.verified and own.kind == "domain" and own.criticality == "high" and own.tag == "own_asset"
    sub = profile.owns(E("domain", "www.shop.acme.com.br"))
    assert sub.own and sub.entry.name == "acme.com.br"
    cdn = profile.owns(E("domain", "img.cdn.acme.com.br"))  # the most specific entry wins
    assert cdn.own and cdn.entry.name == "cdn.acme.com.br" and cdn.third_party_hosted and not cdn.verified and cdn.criticality == "low"
    assert profile.owns(E("email", "soc@acme.com.br")).own
    assert profile.owns(E("url", "https://login.acme.com.br/path?q=1")).own
    assert profile.owns("domain:acme.com.br").own


@pytest.mark.parametrize(
    "value",
    ["evilacme.com.br", "acme.com.br.evil.example", "notacme.com.br", "acme.com", "acmecom.br", "xacme-seeded.com"],
)
def test_never_string_suffix_matching(profile, value):
    result = profile.owns(E("domain", value))
    assert result == NOT_OWNED and result.tag == "third_party"


@pytest.mark.parametrize("value", ["xcdn.acme.com.br", "img.xcdn.acme.com.br", "notcdn.acme.com.br"])
def test_subdomain_entries_match_label_wise_never_by_string_suffix(profile, value):
    """A more specific entry (cdn.acme.com.br, confirmed, third-party hosted) covers its own labels
    only: 'xcdn.acme.com.br' ends with the string 'cdn.acme.com.br' but belongs to acme.com.br
    (txt_verified) - a string-suffix match would hand it the wrong verification and hosting state."""
    own = profile.owns(E("domain", value))
    assert own.own and own.entry.name == "acme.com.br"
    assert own.verified and not own.third_party_hosted and own.criticality == "high"
    assert profile.is_verified_domain(value)


def test_idn_entries_match_through_punycode(profile):
    assert profile.owns(E("domain", "loja.açúcar.com.br")).own  # Unicode input
    assert profile.owns(E("domain", "loja.xn--acar-0oa8i.com.br")).own  # punycode input
    assert profile.owns(E("domain", "xn--acar-0oa8i.com.br")).verified
    assert not profile.owns(E("domain", "acucar.com.br")).own  # the ASCII look-alike is not ours


def test_owns_ips_and_networks(profile):
    v4 = profile.owns(E("ipv4", "203.0.113.10"))
    assert v4.own and v4.kind == "cidr" and v4.criticality == "high" and not v4.third_party_hosted
    assert not v4.verified  # networks carry no verification state
    hosted = profile.owns(E("ipv4", "203.0.113.200"))  # the more specific /25 wins
    assert hosted.own and hosted.third_party_hosted and hosted.entry.value == "203.0.113.128/25"
    assert profile.owns(E("ipv6", "2001:db8:ac:1::5")).own
    assert not profile.owns(E("ipv6", "2001:db8:ad::5")).own
    assert not profile.owns(E("ipv4", "203.0.114.1")).own
    assert profile.owns(E("cidr", "203.0.113.64/26")).own
    assert not profile.owns(E("cidr", "203.0.112.0/23")).own  # only partly ours
    assert profile.owns(E("url", "http://203.0.113.10/admin")).own


def test_owns_asn_cnpj_bins_and_favicon(profile):
    assert profile.owns(E("asn", "AS64500")).kind == "asn"
    assert not profile.owns(E("asn", "AS64501")).own
    cnpj = profile.owns(E("cnpj", "43.828.151/0001-45"))
    assert cnpj.own and cnpj.kind == "cnpj_root" and cnpj.entry == "43828151"
    assert not profile.owns(E("cnpj", "11.222.333/0001-81")).own
    assert profile.owns(E("card_bin", "41234567")).own  # own prefix 412345
    assert profile.owns(E("card_bin", "51234567")).own
    assert not profile.owns(E("card_bin", "512345")).own  # shorter than the own 8-digit prefix
    assert profile.owns(E("favicon_hash", "-1234567890")).kind == "favicon_hash"
    assert not profile.owns(E("favicon_hash", "1234567890")).own


def test_other_types_and_suppliers(profile):
    assert profile.owns(E("sha256", "a" * 64)) == NOT_OWNED
    assert profile.owns(E("person_name", "Executive Person")) == NOT_OWNED
    supplier = profile.owns(E("domain", "portal.supplier.example"))
    assert supplier.own is False and supplier.kind == "supplier" and supplier.entry.name == "Supplier Ltd"
    assert profile.owns(None) == NOT_OWNED
    assert profile.owns("garbage") == NOT_OWNED


def test_verified_semantics(profile):
    assert profile.is_verified_domain("acme.com.br")  # txt_verified
    assert profile.is_verified_domain("mail.acme.com.br")
    assert profile.is_verified_domain("xn--acar-0oa8i.com.br")  # attested
    assert not profile.is_verified_domain("cdn.acme.com.br")  # confirmed
    assert not profile.is_verified_domain("acme-seeded.com")  # seeded
    assert not profile.is_verified_domain("evilacme.com.br")
    assert DomainEntry("x.example", "attested").verified and not DomainEntry("x.example", "confirmed").verified


def test_brand_terms_and_suppliers(profile):
    assert profile.brand_terms() == ["acme", "acrne"]  # accent-folded, deduplicated
    assert fold("Açúcar  União") == "acucar uniao"
    assert profile.supplier_domains() == ["supplier.example"]
    prof = OrgProfile(brands=[BrandEntry("Marca Ótima", ("marca-otima",))])
    assert prof.brand_terms() == ["marca otima", "marca-otima"]


def test_repr_never_dumps_the_inventory(profile):
    text = repr(profile)
    assert "Executive Person" not in text and "acme.com.br" not in text
    assert "domains=4" in text


def test_ownership_defaults():
    assert Ownership() == NOT_OWNED
    assert NOT_OWNED.own is False and NOT_OWNED.verified is False and NOT_OWNED.tag == "third_party"


# --------------------------------------------------------------------------------------
# load_default
# --------------------------------------------------------------------------------------


def test_load_default_paths(tmp_path, isolated_home):
    assert load_default(None).is_empty
    (isolated_home / "org_profile.json").write_text(json.dumps({"domains": ["json.example"]}))
    assert [d.name for d in load_default({}).domains] == ["json.example"]
    (isolated_home / "org_profile.toml").write_text('[[domains]]\nname = "toml.example"\n')
    if HAS_TOML:
        assert [d.name for d in load_default({"org_profile_path": ""}).domains] == ["toml.example"]  # .toml first
    else:  # Python 3.10: the .toml file still comes first and is reported, never silently skipped
        assert any("Python 3.11+" in e for e in load_default({"org_profile_path": ""}).errors)
    team = tmp_path / "team" / "profile.json"
    team.parent.mkdir()
    team.write_text(json.dumps({"domains": [{"name": "team.example", "verification": "attested", "attested_by": "A", "attested_date": "2026-01-02"}]}))
    prof = load_default({"org_profile_path": str(team)})
    assert prof.is_verified_domain("team.example") and prof.path == str(team)
    missing = load_default({"org_profile_path": str(tmp_path / "missing.toml")})
    assert missing.is_empty and any("not a readable file" in e for e in missing.errors)


def test_load_default_with_config_object():
    from v3lum.config import Config

    cfg = Config()
    assert load_default(cfg).is_empty


# --------------------------------------------------------------------------------------
# review hardening: file mode (P378 cond 1), JSON-friendly name, IPv4-mapped addresses
# --------------------------------------------------------------------------------------

VERIFIED_JSON = {"domains": [{"name": "acme.example", "verification": "txt_verified"}], "cidrs": ["203.0.113.0/24"]}


def _write(path, mode):
    path.write_text(json.dumps(VERIFIED_JSON), encoding="utf-8")
    path.chmod(mode)
    return path


def test_world_readable_profile_is_reported(tmp_path):
    prof = OrgProfile.load(_write(tmp_path / "team.json", 0o644))
    assert any("accessible to other users" in e and "chmod 600" in e for e in prof.errors)
    assert prof.is_verified_domain("acme.example")  # reported, still loaded
    assert OrgProfile.load(_write(tmp_path / "team2.json", 0o640)).errors == []  # team path: group read is allowed


def test_group_access_to_the_personal_profile_is_reported(isolated_home):
    prof = OrgProfile.load(_write(isolated_home / "org_profile.json", 0o640))
    assert any("accessible to other users" in e for e in prof.errors)
    assert OrgProfile.load(_write(isolated_home / "org_profile.json", 0o600)).errors == []


def test_world_writable_profile_fails_closed(tmp_path):
    prof = OrgProfile.load(_write(tmp_path / "open.json", 0o666))
    assert any("writable by other users" in e for e in prof.errors)
    assert not prof.is_verified_domain("acme.example")  # anyone could have marked it verified
    own = prof.owns(Entity.make("domain", "acme.example"))
    assert own.own and not own.verified and own.entry.verification == "confirmed"


def test_top_level_name_is_the_org_name():
    prof = OrgProfile.from_dict({"name": "Corp", "domains": ["corp.example"]})
    assert prof.errors == [] and prof.name == "Corp"
    assert OrgProfile.from_dict({"name": "Top", "org": {"name": "Table"}}).name == "Table"


def test_ipv4_mapped_ipv6_addresses_are_contained(profile):
    assert profile.owns(E("ipv6", "::ffff:203.0.113.10")).own
    assert not profile.owns(E("ipv6", "::ffff:198.51.100.1")).own
