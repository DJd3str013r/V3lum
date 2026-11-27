"""Offline tests of proton_pks (P092) with the recorded fixtures in tests/fixtures/proton_pks/.

ok.txt / empty.txt are the research proton_pks_index samples (test account replaced by user@example.com,
fingerprint synthetic, CRLF and epoch kept); ok_org.txt is the live answer for Proton's published role
address; the other cases are built from the documented HKP shape.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, add_dns_failure, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.email import proton_pks as mod
from v3lum.modules.email.proton_pks import ProtonPks, generated_reason, parse_proton_index, proton_url

FIXDIR = Path(__file__).resolve().parents[1] / "fixtures/proton_pks"
TEXT = {"content-type": "text/plain; charset=UTF-8"}
OPTS = ScanOptions(purpose="account verification, ticket EX-5")


def raw(name: str) -> bytes:
    return (FIXDIR / name).read_bytes()


def route(http: FakeHttp, address: str, body: bytes, **kw) -> FakeHttp:
    return http.add("GET", proton_url("index", address), body=body, headers=TEXT, **kw)


def run(http: FakeHttp, address: str = "user@proton.me", **kw):
    kw.setdefault("options", OPTS)
    return run_module(ProtonPks, f"email:{address}", http, **kw)


def test_metadata_and_registration_oracle_never_built():
    cls = ProtonPks
    assert (cls.terms, cls.run_on, cls.default_enabled, cls.trust_tier) == ("open", "seeds", True, "trusted")
    assert cls.hosts == ("api.protonmail.ch",) and cls.max_requests == 1
    for kind in ("users_available", "users/available", "get", "available"):
        with pytest.raises(ValueError):
            proton_url(kind, "user@proton.me")
    with pytest.raises(ValueError):
        proton_url("index", "user@proton.me", host="account.proton.me")
    source = Path(mod.__file__).read_text()
    assert "https://account.proton.me" not in source and "core/v4/users/available" not in source


def test_published_key_stores_only_fingerprint_and_date():
    http = route(FakeHttp(), "user@proton.me", raw("ok.txt"))
    res = run(http)
    assert res.status is Status.OK, res.error
    fact = res.attributes["proton_key"]
    assert fact["published"] is True and fact["keys"] == [{"fingerprint": "2B895D095152D359DE48DF93974F3E18F4BC410F", "created": "2025-09-18T00:16:02Z"}]
    finding = res.findings[0]
    assert finding.title == "Proton key published" and "created 2025-09-18" in finding.description
    assert "approximates the account creation date" in finding.description
    assert "user@example.com" not in json.dumps({"a": res.attributes, "raw": res.raw})  # UID lines are never kept
    http.assert_hosts_within(ProtonPks)


def test_two_keys_earliest_creation():
    parsed = parse_proton_index(raw("ok_two_keys.txt"))
    assert parsed["earliest_created"].startswith("2021-01-01") and len(parsed["keys"]) == 2


def test_no_key_is_empty_never_no_account():
    res = run(route(FakeHttp(), "user@proton.me", raw("empty.txt")))
    assert res.status is Status.EMPTY and res.error == "no public key published"
    assert "account" not in res.error


def test_generated_or_pivoted_addresses_are_refused():
    assert generated_reason(True, 0, ()) == ""
    gen = (("person_name:Maria Souza @ example.com", "guessed_email", "hunter_io_finder"),)
    assert "generated" in generated_reason(True, 0, gen)
    http = FakeHttp()
    res = run(http, is_seed=False, depth=1, provenance=gen)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "generated" in res.error
    res = run(http, is_seed=False, depth=1, provenance=(("domain:proton.me", "contact_email", "whois"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    assert http.calls == []


def test_custom_domain_needs_a_proton_mx():
    http = FakeHttp()
    add_dns(http, "example.com", "MX", ["0 ."])
    res = run(http, "user@example.com")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert not [c for c in http.calls if "protonmail" in c["url"]]
    http = FakeHttp()
    add_dns(http, "example.org", "MX", ["10 mail.protonmail.ch.", "20 mailsec.protonmail.ch."])
    route(http, "user@example.org", raw("ok.txt"))
    res = run(http, "user@example.org")
    assert res.status is Status.OK and res.raw["via"] == "proton_mx"


def test_unverifiable_mx_is_could_not_verify():
    http = FakeHttp()
    add_dns_failure(http, "example.net", "MX", kind="servfail", provider="all")
    res = run(http, "user@example.net")
    assert res.status is Status.ERROR and "could not be verified" in res.error


def test_new_key_in_a_fraud_case_is_suspicious_context():
    clock = FakeClock(datetime(2025, 10, 1, tzinfo=timezone.utc))
    http = route(FakeHttp(), "user@proton.me", raw("ok.txt"))
    res = run(http, options=ScanOptions(purpose="fraud investigation, ticket EX-6"), clock=clock)
    titles = {f.title for f in res.findings}
    assert "Recently created Proton key (fraud case context)" in titles
    ctx_finding = next(f for f in res.findings if f.title.startswith("Recently"))
    assert "context_only" in ctx_finding.tags and res.attributes["proton_key"]["age_days"] == 13
    res = run(route(FakeHttp(), "user@proton.me", raw("ok.txt")), clock=clock)  # not a fraud case
    assert {f.title for f in res.findings} == {"Proton key published"}


def test_rate_limit_server_error_and_malformed_answers():
    item = module_fixture("proton_pks", "rate_limited_429.json")
    http = FakeHttp().add("GET", proton_url("index", "user@proton.me"), status=429, json=item["body"], headers=item["headers"], times=2)
    assert run(http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", proton_url("index", "user@proton.me"), status=500, text="oops", times=2)
    assert run(http).status is Status.ERROR
    assert run(route(FakeHttp(), "user@proton.me", raw("malformed.txt"))).status is Status.ERROR
    http = FakeHttp().add("GET", proton_url("index", "user@proton.me"), json={"Code": 2001, "Error": "Invalid input"})
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("GET", proton_url("index", "user@proton.me"), text="<html>maintenance</html>", headers={"content-type": "text/html"})
    assert run(http).status is Status.ERROR


def test_org_role_address_live_shape():
    res = run(route(FakeHttp(), "security@proton.me", raw("ok_org.txt")), "security@proton.me")
    assert res.status is Status.OK and res.attributes["proton_key"]["earliest_created"].startswith("2022-05-03")


def test_acceptance_routes_of_the_golden_email():
    doc = json.loads((FIXDIR.parent / "acceptance/email/proton_pks.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "proton_pks"
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route.get("json"), headers=route.get("headers"))
    res = run(http, "someone@example.com")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"  # null MX: no key-server call
    assert len(http.calls) == 1
