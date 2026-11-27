"""Offline tests of pgp_keyservers (P091) with the recorded fixtures in tests/fixtures/pgp_keyservers/.

HKP index fixtures are trimmed live keyserver.ubuntu.com answers (UIDs scrubbed: 'Example Person N',
@example.com/@example.org); the VKS keys are the scrubbed real keys.openpgp.org answers (UID re-encoded,
key material untouched); the malformed packet cases are built for the bounded reader (P091 cond 8).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.email import pgp_keyservers as mod
from v3lum.modules.email.pgp_keyservers import PgpKeyservers, crc24, hkp_index_url, parse_hkp_index, parse_openpgp_key, vks_url

FIXDIR = Path(__file__).resolve().parents[1] / "fixtures/pgp_keyservers"
TEXT = {"content-type": "text/plain; charset=utf-8"}
KEYS = {"content-type": "application/pgp-keys"}
VKS_FPR = "0E7BEF12E59AAB25416AF4A3222FDE8206A67236"


def raw(name: str) -> bytes:
    return (FIXDIR / name).read_bytes()


def env(name: str) -> dict:
    return module_fixture("pgp_keyservers", name)


def hkp(term: str) -> str:
    return hkp_index_url(term)


def add_env(http: FakeHttp, url: str, item: dict, **kw) -> FakeHttp:
    body = item["body"]
    extra = {"json": body} if isinstance(body, (dict, list)) else {"text": body}
    return http.add("GET", url, status=item["status"], headers=item.get("headers"), **extra, **kw)


def run(http: FakeHttp, entity: str = "email:test@example.com", **kw):
    kw.setdefault("options", ScanOptions(purpose="key provenance check, ticket EX-4"))
    return run_module(PgpKeyservers, entity, http, **kw)


def armored(packets: bytes) -> str:
    b64 = base64.b64encode(packets).decode()
    crc = base64.b64encode(crc24(packets).to_bytes(3, "big")).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + "\n".join(lines) + f"\n={crc}\n-----END PGP PUBLIC KEY BLOCK-----\n"


def packet(tag: int, body: bytes) -> bytes:
    assert len(body) < 192
    return bytes([0xC0 | tag, len(body)]) + body


def ed25519_key(created: int = 1700000000) -> bytes:
    oid = bytes.fromhex("2b06010401da470f01")
    body = b"\x04" + created.to_bytes(4, "big") + b"\x16" + bytes([len(oid)]) + oid + b"\x01\x07\x40" + b"\x11" * 32
    return packet(6, body)


# ------------------------------------------------------------------------------------------ metadata and builders
def test_metadata_follows_the_council_decision():
    cls = PgpKeyservers
    assert (cls.terms, cls.default_enabled, cls.trust_tier) == ("open", True, "community")
    assert cls.hosts == ("keyserver.ubuntu.com", "keys.openpgp.org") and cls.cache_ttl == 0
    assert set(cls.sources) == {"ubuntu_keyserver.hkp_index", "openpgp.vks"}


def test_only_the_two_keyservers_are_ever_built():
    assert hkp("test@example.com") == "https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search=test%40example.com"
    assert vks_url("by-email", "Test@Example.com") == "https://keys.openpgp.org/vks/v1/by-email/test%40example.com"
    assert vks_url("by-fingerprint", "0x" + VKS_FPR.lower()).endswith("/by-fingerprint/" + VKS_FPR)
    for kind, value in (("by-email", "not-an-address"), ("by-fingerprint", "ABCD"), ("search", "x"), ("by-keyid", VKS_FPR)):
        with pytest.raises(ValueError):
            vks_url(kind, value)
    src = Path(mod.__file__).read_text()
    assert "pgp.mit.edu" not in src.split('"""', 2)[2] and "keyserver.pgp.com" not in src.split('"""', 2)[2]


# ------------------------------------------------------------------------------------------ HKP parsing and minimisation
def test_hkp_index_parsing_escapes_flags_and_cap():
    idx = parse_hkp_index(raw("hkp_index_escaped.txt"))
    first = idx["keys"][0]
    assert first["uids"][0]["name"] == "José Exemplo" and first["uids"][0]["comment"] == "Gerência: TI"
    assert idx["keys"][1]["revoked"] is True and idx["keys"][2]["expired"] is True and idx["keys"][2]["fingerprint"] is None
    capped = parse_hkp_index(raw("hkp_index_capped.txt"))
    assert capped["capped"] and capped["count_mismatch"] and capped["declared"] == 100 and capped["listed"] == 4
    assert parse_hkp_index(b"<html>nope</html>")["is_index"] is False


def test_email_seed_keeps_only_tied_uids_and_never_pivots_hkp_claims():
    http = FakeHttp().add("GET", hkp("test@example.com"), text=raw("hkp_index_ok.txt").decode(), headers=TEXT)
    add_env(http, vks_url("by-email", "test@example.com"), env("vks_not_found.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    keys = res.attributes["pgp_keyserver_keys"]
    assert keys and all(k["keyserver"] == "keyserver.ubuntu.com" and k["claim"] == "unverified self-published claim" for k in keys)
    kept = {u["email"] for k in keys for u in k["uids"]}
    assert kept == {"test@example.com"}  # every other UID is a count (cond 4)
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings]})
    assert "example987@example.com" not in dump and "example-handle-4" not in dump and "test comment" not in dump
    assert not res.pivots  # cond 3: HKP claims never pivot
    finding = res.findings[0]
    assert finding.confidence_label == "possible" and "unverified self-published claim" in finding.criterion
    assert res.attributes["pgp_keyserver_results"]["keys.openpgp.org"]["state"] == "none"
    http.assert_hosts_within(PgpKeyservers)


def test_vks_verified_key_pivots_its_fingerprint_without_expansion():
    http = FakeHttp().add("GET", hkp("security@example.com"), text=raw("hkp_index_uid_hidden.txt").decode(), headers=TEXT)
    http.add("GET", vks_url("by-email", "security@example.com"), text=raw("vks_ok.asc").decode(), headers=KEYS)
    res = run(http, "email:security@example.com")
    assert res.status is Status.OK, res.error
    (pivot,) = res.pivots
    assert pivot.entity.value == VKS_FPR and pivot.relation == "pgp_key" and pivot.expand is False
    vks = [k for k in res.attributes["pgp_keyserver_keys"] if k["keyserver"] == "keys.openpgp.org"]
    assert vks[0]["fingerprint"] == VKS_FPR and vks[0]["expiry_checked"] is False
    hidden = [k for k in res.attributes["pgp_keyserver_keys"] if k["keyserver"] == "keyserver.ubuntu.com"]
    assert hidden[0]["fingerprint"] == VKS_FPR and hidden[0]["address_match"] is None  # UIDs hidden by the server
    titles = {f.title for f in res.findings}
    assert "OpenPGP key with a verified address (keys.openpgp.org)" in titles


def test_other_verified_address_on_the_same_key_is_a_probable_non_expanded_link():
    key = ed25519_key() + packet(13, b"Example Person <user@example.com>") + packet(13, b"Example Person <alias@example.org>")
    http = FakeHttp().add("GET", hkp("user@example.com"), status=404, text="Not Found\n", headers=TEXT)
    http.add("GET", vks_url("by-email", "user@example.com"), text=armored(key), headers=KEYS)
    res = run(http, "email:user@example.com")
    assert res.status is Status.OK
    by_rel = {(p.relation, p.entity.value) for p in res.pivots}
    assert ("same_person", "alias@example.org") in by_rel and all(p.expand is False for p in res.pivots)
    assert next(p for p in res.pivots if p.relation == "same_person").confidence_label == "probable"


# ------------------------------------------------------------------------------------------ gates (cond 5/6)
def test_pivot_address_outside_the_org_is_skipped_privacy():
    http = FakeHttp()
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.org", "contact_email", "whois"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_org_profile_address_runs_even_as_a_pivot():
    org = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    http = FakeHttp().add("GET", hkp("test@example.com"), status=404, text="Not Found\n", headers=TEXT)
    add_env(http, vks_url("by-email", "test@example.com"), env("vks_not_found.json"))
    res = run(http, is_seed=False, depth=1, org_profile=org)
    assert res.status is Status.EMPTY


def test_domain_search_only_for_org_domains_or_the_typed_case_company():
    http = FakeHttp()
    res = run(http, "domain:example.org", options=ScanOptions())  # typed, but no recorded purpose
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run(http, "domain:example.org", is_seed=False, depth=1)  # a pivot domain
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    assert http.calls == []
    org = OrgProfile.from_dict({"domains": [{"name": "example.org", "verification": "confirmed"}]})
    http = FakeHttp().add("GET", hkp("example.org"), text=raw("hkp_index_org.txt").decode(), headers=TEXT)
    res = run(http, "domain:example.org", org_profile=org, is_seed=False, depth=1)
    assert res.status is Status.OK
    kept = {u["email"] for k in res.attributes["pgp_keyserver_keys"] for u in k["uids"]}
    assert kept == {"security@example.org", "team@security.example.org"}
    assert "privacy" in res.findings[0].tags


def test_fingerprint_keyword_queries_both_keyservers_and_free_text_is_not_applicable():
    http = FakeHttp().add("GET", hkp("0x" + VKS_FPR), text=raw("hkp_index_uid_hidden.txt").decode(), headers=TEXT)
    http.add("GET", vks_url("by-fingerprint", VKS_FPR), text=raw("vks_ok.asc").decode(), headers=KEYS)
    res = run(http, f"pgp_fingerprint:{VKS_FPR}")
    assert res.status is Status.OK and {u["email"] for k in res.attributes["pgp_keyserver_keys"] for u in k["uids"]} == {"security@example.com"}
    res = run(FakeHttp(), "keyword:Some Person Name")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ------------------------------------------------------------------------------------------ absences and rule 5 (cond 7)
def test_nothing_published_reads_no_key_published_never_no_such_person():
    http = add_env(FakeHttp(), hkp("nobody@example.com"), env("hkp_not_found.json"))
    add_env(http, vks_url("by-email", "nobody@example.com"), env("vks_not_found.json"))
    res = run(http, "email:nobody@example.com")
    assert res.status is Status.EMPTY
    assert "no key published on keyserver.ubuntu.com" in res.error and "no key published on keys.openpgp.org" in res.error
    for banned in ("no such", "does not exist", "no account", "not found"):
        assert banned not in res.error.lower()


def test_one_keyserver_rate_limited_is_could_not_verify_for_that_source_only():
    http = add_env(FakeHttp(), hkp("test@example.com"), env("hkp_rate_limited_429.json"), times=2)
    add_env(http, vks_url("by-email", "test@example.com"), env("vks_not_found.json"))
    res = run(http)
    assert res.status is Status.EMPTY
    assert res.source_statuses["ubuntu_keyserver.hkp_index"]["status"] == "rate_limited"
    assert "could not verify" in res.error


def test_both_failing_is_never_empty():
    http = add_env(FakeHttp(), hkp("test@example.com"), env("hkp_rate_limited_429.json"), times=2)
    add_env(http, vks_url("by-email", "test@example.com"), env("vks_rate_limited_429.json"), times=2)
    assert run(http).status is Status.RATE_LIMITED
    http = add_env(FakeHttp(), hkp("test@example.com"), env("hkp_error_502.json"), times=2)
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\"></div></body></html>"
    http.add("GET", vks_url("by-email", "test@example.com"), status=403, text=page, headers={"content-type": "text/html"})
    res = run(http)
    assert res.status in (Status.ERROR, Status.BLOCKED) and res.status is not Status.EMPTY
    assert res.source_statuses["openpgp.vks"]["status"] == "blocked"


def test_html_or_garbage_instead_of_an_index_is_an_error():
    http = FakeHttp().add("GET", hkp("test@example.com"), text="<html><body>maintenance</body></html>", headers={"content-type": "text/html"})
    add_env(http, vks_url("by-email", "test@example.com"), env("vks_not_found.json"))
    res = run(http)
    assert res.status is Status.EMPTY and res.source_statuses["ubuntu_keyserver.hkp_index"]["status"] == "error"


# ------------------------------------------------------------------------------------------ bounded reader (cond 2, cond 8)
@pytest.mark.parametrize("name, error", [
    ("malformed_truncated.asc", "truncated"),
    ("malformed_oversized.asc", "oversized_packet"),
    ("malformed_partial.asc", "partial_length"),
    ("malformed_armor.asc", "bad_base64"),
])
def test_malformed_packets_are_refused(name, error):
    parsed = parse_openpgp_key(raw(name))
    assert any(e.startswith(error) for e in parsed["errors"]), parsed["errors"]


def test_reader_limits():
    assert parse_openpgp_key(b"x" * (mod.MAX_BYTES + 1))["errors"][0].startswith("oversized")
    uid_first = packet(13, b"<a@example.com>") + ed25519_key()
    assert parse_openpgp_key(armored(uid_first))["errors"][0].startswith("bad_order")
    indeterminate = bytes([0x80 | (6 << 2) | 3]) + b"\x04" * 10
    assert parse_openpgp_key(indeterminate)["errors"][0].startswith("indeterminate_length")
    ok = parse_openpgp_key(armored(ed25519_key() + packet(13, b"Example <a@example.com>")))
    assert not ok["errors"] and ok["keys"][0]["algorithm"] == "EdDSA (legacy)" and ok["keys"][0]["bits"] == 255 and ok["crc_ok"]


def test_unreadable_vks_key_records_existence_only():
    http = FakeHttp().add("GET", hkp("security@example.com"), status=404, text="Not Found\n", headers=TEXT)
    http.add("GET", vks_url("by-email", "security@example.com"), text=raw("malformed_truncated.asc").decode(), headers=KEYS)
    res = run(http, "email:security@example.com")
    assert res.status is Status.OK and not res.pivots
    assert res.attributes["pgp_keyserver_results"]["keys.openpgp.org"]["existence_only"] is True
    assert res.findings[0].title == "OpenPGP key published (existence only)"


def test_fixtures_carry_no_real_uids():
    for path in FIXDIR.iterdir():
        text = path.read_bytes().decode("utf-8", "replace")
        for line in text.splitlines():
            if line.startswith("uid:"):
                assert "example" in line.lower(), (path.name, line[:40])


def test_acceptance_routes_of_the_golden_email():
    doc = json.loads((FIXDIR.parent / "acceptance/email/pgp_keyservers.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "pgp_keyservers"
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], text=route.get("text"), json=route.get("json"),
                 headers=route.get("headers"))
    res = run(http, "email:someone@example.com")
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert {u["email"] for k in res.attributes["pgp_keyserver_keys"] for u in k["uids"]} == {"someone@example.com"}
    assert all(f.severity.name == "INFO" for f in res.findings)
