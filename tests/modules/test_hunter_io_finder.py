"""Offline tests of hunter_io_finder (P090 cond 3) with the fixtures in tests/fixtures/hunter_io_finder/
(documentation-shaped Hunter v2 bodies; the 401 is a real research capture)."""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.email.hunter_io import OPT_OUT_TEXT, HunterIoFinder, split_person

KEY = "hu-test-key-0123456789abcdef"  # fake key
FINDER = re.compile(r"^https://api\.hunter\.io/v2/email-finder\?")
PURPOSE = ScanOptions(purpose="BEC investigation, ticket EX-2")


def fx(name: str):
    return module_fixture("hunter_io_finder", name)


def add(http: FakeHttp, item) -> FakeHttp:
    if item.get("_envelope"):
        return http.add("GET", FINDER, status=item["status"], json=item["body"], headers=item.get("headers"))
    return http.add("GET", FINDER, json=item)


def run(http: FakeHttp, value: str = "Maria Souza @ example.com", **kw):
    kw.setdefault("keys", {"hunter": KEY})
    kw.setdefault("options", PURPOSE)
    return run_module(HunterIoFinder, f"person_name:{value}", http, **kw)


def test_metadata_person_module_is_never_default():
    cls = HunterIoFinder
    assert (cls.default_enabled, cls.run_on, cls.sources) == (False, "seeds", ("hunter.email_finder",))


@pytest.mark.parametrize("value, expected", [
    ("Maria Souza @ example.com", ("Maria", "Souza", "example.com")),
    ("Maria da Souza <example.com>", ("Maria", "Souza", "example.com")),
    ("José Exemplo@Example.COM", ("José", "Exemplo", "example.com")),
])
def test_person_values(value, expected):
    assert split_person(value) == expected


def test_person_values_refused():
    assert split_person("Maria @ example.com") is None  # one token
    assert split_person("Maria Souza") is None  # no domain
    assert split_person("Maria Souza", "example.com") == ("Maria", "Souza", "example.com")
    assert split_person("maria.souza@example.com") is None  # an address is not a person


def test_guessed_address_is_a_generated_pivot_never_expanded():
    http = add(FakeHttp(), fx("email_finder_ok.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    (pivot,) = res.pivots
    assert pivot.entity.value == "maria.souza@example.com" and pivot.relation == "guessed_email" and pivot.expand is False
    assert res.attributes["guessed_address"]["provenance"] == "generated"
    finding = res.findings[0]
    assert {"privacy", "generated_address"} <= set(finding.tags)
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings]})
    for gone in ("Finance Manager", "position", "verification", "phone_number", "Example Org"):
        assert gone not in dump
    url = http.calls[0]["url"]
    assert "first_name=Maria" in url and "last_name=Souza" in url and "domain=example.com" in url
    http.assert_hosts_within(HunterIoFinder)
    assert_no_secret(KEY, res.to_dict())


def test_not_found_and_opt_out_are_empty_with_honest_wording():
    res = run(add(FakeHttp(), fx("email_finder_not_found.json")))
    assert res.status is Status.EMPTY and not res.pivots
    res = run(add(FakeHttp(), fx("unavailable_451.json")))
    assert res.status is Status.EMPTY and res.error == OPT_OUT_TEXT and not res.pivots


def test_gates():
    http = FakeHttp()
    res = run(http, options=ScanOptions())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.com", "partner", "x"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run(http, "Maria Souza")  # no domain and no setting: not applicable
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY
    assert http.calls == []


def test_domain_setting_and_401():
    http = add(FakeHttp(), fx("email_finder_ok.json"))
    res = run(http, "Maria Souza", settings={"hunter_io_finder_domain": "example.com"})
    assert res.status is Status.OK
    res = run(add(FakeHttp(), fx("needs_key_401.json")))
    assert res.status is Status.NEEDS_KEY
