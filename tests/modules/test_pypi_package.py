"""Offline tests of pypi_package (P100) on trimmed real PyPI JSON answers (tests/fixtures/pypi_package/)."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.dev_profiles import PypiPackage
from v3lum.modules.username_social.dev_registries import pypi_json_url

URL = "https://pypi.org/pypi/{p}/json"


def env(name: str) -> dict:
    d = module_fixture("pypi_package", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_org_owned_package_counts_addresses_only():
    http = FakeHttp().add("GET", URL.format(p="sampleproject"), json=module_fixture("pypi_package", "ok.json"))
    res = run_module(PypiPackage, "keyword:sampleproject", http)
    assert res.status is Status.OK
    proj = res.attributes["pypi_project"]
    assert proj["organization"] == "pypa" and proj["release_count"] == 6 and proj["first_release"] == "2015-06-14T14:37:56Z"
    assert res.attributes["third_party_counts"]["other_emails"] == 2
    assert not [p for p in res.pivots if p.entity.type is T.EMAIL]  # no case username holds a role: nothing kept
    urls = {p.entity.value for p in res.pivots if p.relation == "project_url"}
    assert "https://github.com/pypa/sampleproject" in urls and all(p.expand is False for p in res.pivots)
    text = json.dumps(res.to_dict(), default=str)
    assert "author@example.com" not in text and "maintainer@example.com" not in text
    http.assert_hosts_within(PypiPackage)


def test_case_username_role_keeps_only_its_own_address():
    http = FakeHttp().add("GET", URL.format(p="example-pkg"), json=module_fixture("pypi_package", "ownership_roles.json"))
    opts = ScanOptions(seed_tlp={"username:example-dev": "amber", "keyword:example-pkg": "amber"})
    res = run_module(PypiPackage, "url:https://pypi.org/project/Example_Pkg/", http, options=opts)
    assert res.status is Status.OK
    assert res.attributes["pypi_project"]["seed_role"] == "Owner"
    emails = [p for p in res.pivots if p.entity.type is T.EMAIL]
    assert [p.entity.value for p in emails] == ["dev@example.com"] and emails[0].expand is False
    text = json.dumps(res.to_dict(), default=str)
    assert "other@example.org" not in text and "co-maintainer-1@example.org" not in text
    assert res.attributes["third_party_counts"] == {"other_emails": 2, "other_roles": 1}


def test_not_found_is_absent_and_challenge_is_blocked():
    http = FakeHttp().add("GET", URL.format(p="qz7k2v9m4p1w8n3x5c6b"), **env("not_found.http.json"))
    res = run_module(PypiPackage, "keyword:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", URL.format(p="sampleproject"), **env("client_challenge.http.json"))
    res = run_module(PypiPackage, "keyword:sampleproject", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"  # error-in-200 challenge, never data


def test_429_and_malformed_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(p="sampleproject"), status=429, text="slow down")
    assert run_module(PypiPackage, "keyword:sampleproject", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", URL.format(p="sampleproject"), json={"message": "Not Found"})
    assert run_module(PypiPackage, "keyword:sampleproject", http).status is Status.ERROR


def test_user_pages_are_never_fetched():
    http = FakeHttp()
    res = run_module(PypiPackage, "url:https://pypi.org/user/example-dev/", http)
    assert res.status is Status.SKIPPED and http.calls == []
    assert pypi_json_url("Sample_Project") == "https://pypi.org/pypi/sample-project/json"
    assert pypi_json_url("not a name") is None
