"""Offline tests of dockerhub (P102) on trimmed real Hub API answers (tests/fixtures/dockerhub/)."""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social import dockerhub as dh_mod
from v3lum.modules.username_social.dockerhub import Dockerhub
from v3lum.modules.username_social.dev_registries import dockerhub_namespace_of, parse_dockerhub_images

HUB = "https://hub.docker.com/v2/"
PLANTED_PASSWORD = "v3lum-fixture-not-a-real-password"
PLANTED_URL_PASSWORD = "v3lumFakePass1"
AWS_DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def env(name: str, **headers) -> dict:
    d = module_fixture("dockerhub", name)
    return {"status": d["status"], "headers": {**d["headers"], **headers}, "text": d["body"]}


def user_routes(http: FakeHttp, ns: str = "example-dev", repos_headers: dict | None = None) -> FakeHttp:
    http.add("GET", f"{HUB}users/{ns}/", json=module_fixture("dockerhub", "user_ok.json"), headers={"x-ratelimit-remaining": "170"})
    http.add("GET", f"{HUB}repositories/{ns}/?page_size=5&ordering=last_updated", **env("repositories_ok.http.json", **(repos_headers or {})))
    http.add("GET", re.compile(r"/tags\?page_size=1&ordering=last_updated$"), json=module_fixture("dockerhub", "tags_ok.json"))
    http.add("GET", re.compile(r"/sandbox-templates/tags/[^/]+/images$"), json=module_fixture("dockerhub", "tag_images_planted_secret.json"))
    http.add("GET", re.compile(r"/tags/[^/]+/images$"), json=module_fixture("dockerhub", "tag_images_inherited_label.json"))
    return http


def seeds(*emails: str) -> ScanOptions:
    return ScanOptions(seed_tlp={f"email:{e}": "amber" for e in emails})


def test_user_profile_repositories_and_planted_secret():
    http = user_routes(FakeHttp())
    res = run_module(Dockerhub, "username:example-dev", http, options=seeds("dev@example.com"))
    assert res.status is Status.OK
    assert res.attributes["account_type"] == "user" and res.attributes["created"] == "2019-01-15T12:00:00Z"
    assert res.attributes["avatar_hash"] == "be9d18f611892a738e54f2a3a171e2f9"
    assert [r["name"] for r in res.attributes["docker_repositories"]][0] == "sandbox-templates"
    # cond 3 + A3: max_requests 10 -> 4 of the 5 listed repositories, partial with request_cap
    assert len(res.attributes["docker_images"]) == 4 and res.partial and res.stop_reason == "request_cap"
    assert len(http.calls) == Dockerhub.max_requests
    emails = {p.entity.value: p for p in res.pivots if p.entity.type is T.EMAIL}
    assert set(emails) == {"dev@example.com"}  # ops@example.org discarded, the nginx label inherited
    assert emails["dev@example.com"].relation == "image_label_email" and emails["dev@example.com"].expand is False
    assert emails["dev@example.com"].confidence_label == "possible"  # A4: example.com is a test domain
    counts = res.attributes["label_email_counts"]
    assert counts["kept"] == 1 and counts["discarded"] == 1 and counts["inherited"] == 4
    exposure = [f for f in res.findings if f.title == "Secrets in public image layer instructions"]
    assert len(exposure) == 1 and exposure[0].severity.name == "MEDIUM" and "credential_exposure" in exposure[0].tags
    kinds = {e["type"] for e in res.attributes["layer_exposures"]}
    assert {"aws_access_key_id", "aws_secret_access_key", "url_credentials"} <= kinds
    for e in res.attributes["layer_exposures"]:
        assert set(e) <= {"type", "preview", "sha256", "repo_tag", "instruction_index", "instruction_kind", "variable", "severity",
                          "documentation_example", "dropped"}
    blob = json.dumps(res.to_dict(), default=str)
    assert_no_secret(PLANTED_PASSWORD, blob)
    assert_no_secret(PLANTED_URL_PASSWORD, blob)
    assert_no_secret(AWS_DOC_SECRET, blob)
    http.assert_hosts_within(Dockerhub)
    assert not [u for u in http.urls() if "registry-1.docker.io" in u or "auth.docker.io" in u]


def test_label_email_probable_only_for_case_address(monkeypatch):
    monkeypatch.setattr(dh_mod, "is_generic_email", lambda _e: False)  # lift the A4 test-domain cap
    res = run_module(Dockerhub, "username:example-dev", user_routes(FakeHttp()), options=seeds("dev@example.com"))
    label = [p for p in res.pivots if p.entity.type is T.EMAIL]
    assert [p.confidence_label for p in label] == ["probable"]
    res = run_module(Dockerhub, "username:example-dev", user_routes(FakeHttp()))
    assert not [p for p in res.pivots if p.entity.type is T.EMAIL]  # no case e-mail: every label address is discarded


def test_inherited_base_image_label_gives_no_pivot():
    parsed = parse_dockerhub_images(module_fixture("dockerhub", "tag_images_inherited_label.json"), "library/nginx:stable",
                                    case_mails=["docker-maint@nginx.com"])
    assert parsed["label_emails"] == [] and parsed["label_counts"]["inherited"] == 1
    assert parsed["image"]["base_boundary"] == 15 and parsed["exposures"] == []


def test_high_severity_only_for_org_confirmed_accounts():
    planted = module_fixture("dockerhub", "tag_images_planted_secret.json")
    plain = parse_dockerhub_images(planted, "example-dev/app:latest")
    confirmed = parse_dockerhub_images(planted, "example-dev/app:latest", org_confirmed=True)
    assert plain["exposure"]["severity"] == "medium" and confirmed["exposure"]["severity"] == "high"
    assert all(e.get("documentation_example") and e["severity"] == "info" for e in plain["exposures"] if e["type"].startswith("aws"))
    dropped = [e for e in plain["exposures"] if e.get("dropped")]
    assert dropped and all("preview" not in e and "sha256" not in e for e in dropped)  # passwords: type only


def test_organisation_redirect_is_followed_on_the_same_host():
    http = FakeHttp()
    http.add("GET", f"{HUB}users/docker/", status=308, redirect_to="/v2/orgs/docker")
    http.add("GET", f"{HUB}orgs/docker", json=module_fixture("dockerhub", "org_ok.json"))
    http.add("GET", f"{HUB}repositories/docker/?page_size=5&ordering=last_updated", json=module_fixture("dockerhub", "repositories_empty.json"))
    res = run_module(Dockerhub, "url:https://hub.docker.com/u/docker", http)
    assert res.status is Status.OK
    assert res.attributes["account_type"] == "org" and res.attributes["verified"] is True
    assert "docker_images" not in res.attributes  # no public repository: nothing inspected
    links = {p.entity.value for p in res.pivots if p.relation == "link_on_profile"}
    assert links == {"https://www.docker.com/"}


def test_user_not_found_is_absent():
    http = FakeHttp().add("GET", f"{HUB}users/qz7k2v9m4p1w8n3x5c6b/", **env("user_not_found.http.json"))
    res = run_module(Dockerhub, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_429_and_malformed_answers_are_could_not_verify():
    http = FakeHttp().add("GET", f"{HUB}users/example-dev/", **env("rate_limited.http.json"))
    assert run_module(Dockerhub, "username:example-dev", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", f"{HUB}users/example-dev/", json=["not", "an", "account"])
    assert run_module(Dockerhub, "username:example-dev", http).status is Status.ERROR
    http = FakeHttp().add("GET", f"{HUB}users/example-dev/", json={"message": "internal error"})
    assert run_module(Dockerhub, "username:example-dev", http).status is Status.ERROR
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", f"{HUB}users/example-dev/", status=403, text=page)
    assert run_module(Dockerhub, "username:example-dev", http).status is Status.BLOCKED


def test_rate_budget_header_stops_new_requests():
    http = user_routes(FakeHttp(), repos_headers={"x-ratelimit-remaining": "3"})
    res = run_module(Dockerhub, "username:example-dev", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert len(http.calls) == 2  # account + repositories, then the shared NAT budget is protected


def test_tag_failure_is_reported_per_source_and_run_continues():
    http = FakeHttp()
    http.add("GET", f"{HUB}users/example-dev/", json=module_fixture("dockerhub", "user_ok.json"))
    http.add("GET", f"{HUB}repositories/example-dev/?page_size=5&ordering=last_updated", **env("repositories_ok.http.json"))
    http.add("GET", re.compile(r"/tags\?page_size=1"), status=500, text="err", times=20)
    res = run_module(Dockerhub, "username:example-dev", http)
    assert res.status is Status.OK
    assert "docker_hub.hub_api" in res.source_statuses


@pytest.mark.parametrize("value,ns", [("username:example-dev", "example-dev"), ("social_account:dockerhub:Example-Dev", "example-dev"),
                                      ("url:https://hub.docker.com/r/library/nginx", "library"), ("url:https://example.com/u/x", None)])
def test_namespace_inputs(value, ns):
    from tests.fakes import _as_entity  # noqa: PLC0415 - the kit's entity parser

    assert dockerhub_namespace_of(_as_entity(value)) == ns
