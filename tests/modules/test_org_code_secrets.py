"""P359 org_code_secrets: deep-preset secret scan of confirmed organisations' public repositories (p2-G05-2).

Archives are synthetic (``tests/fixtures/org_code_secrets/archive_*.tar.gz``: AWS documentation example
keys, unsafe members, a truncated stream); the secret-bearing archive is built in memory by the test
from split literals, so no token-shaped string is ever committed.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import urlencode

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.company_org import org_code_footprint as ocf
from v3lum.modules.company_org.org_code_footprint import OrgCodeSecrets

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "org_code_secrets"
GH = "https://api.github.com"
CB = "https://codeberg.org/api/v1"
GL = "https://gitlab.com/api/v4"
JSON = {"content-type": "application/json; charset=utf-8"}
COMMIT = "89abcdef0123456789abcdef0123456789abcdef"
TOKEN = "gh" + "p_" + "Xk9vB2mQ7rT4wZ1nL8sD5fH3jP6cY0aE2uIo"  # synthetic, split so no token literal is committed
SLACK = "xo" + "xb-" + "1234567890-0987654321-Zq8Wn3Lk5Vb7Rt2Yh9Pm4Sd6"
ORG_PROFILE = {"org": {"name": "Example Org"},
               "domains": [{"name": "example.com", "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-01"}]}


def url(base, **params):
    return base + ("?" + urlencode(params) if params else "")


def secret_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": COMMIT}) as tf:
        def add(name: str, text: str) -> None:
            data = text.encode()
            info = tarfile.TarInfo(f"api-gateway-{COMMIT[:7]}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        add("README.md", "# api-gateway\n")
        add("config/settings.py", f'DEBUG = False\nGITHUB_TOKEN = "{TOKEN}"\n')
        add("deploy/notify.py", f'# notifier\n\nSLACK_BOT = "{SLACK}"\n')
        add("assets/logo.png", "\x89PNG not scanned")
    return buf.getvalue()


def repos_with(*names):
    items = module_fixture("org_code_secrets", "gh_org_repos_ok.json")["items"]
    return [r for r in items if r["name"] in names]


def discovery(http, repos):
    http.add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5),
             json={"total_count": 1, "items": [{"login": "example-org", "html_url": "https://github.com/example-org", "type": "Organization"}]}, headers=JSON)
    http.add("GET", f"{GH}/orgs/example-org", json={k: v for k, v in module_fixture("org_code_secrets", "gh_org_ok.json").items() if k != "_fixture"}, headers=JSON)
    http.add("GET", url(f"{GH}/orgs/example-org/repos", per_page=30, sort="pushed", type="public"), json=repos, headers=JSON)
    http.add("GET", url(f"{GH}/orgs/example-org/public_members", per_page=1), json=[], headers=JSON)
    http.add("GET", f"{CB}/orgs/exampleorg", status=404, json={"message": "GetOrgByName"}, headers=JSON)
    http.add("GET", url(f"{GL}/groups", search="exampleorg", top_level_only="true", per_page=5), json=[], headers=JSON)
    return http


def codeload(repo: str) -> str:
    return f"https://codeload.github.com/example-org/{repo}/tar.gz/main"


def test_own_repository_secrets_are_one_high_finding_with_fingerprints_only():
    http = discovery(FakeHttp(), repos_with("api-gateway", "patched-lib", "legacy-portal", "docs", "ml-models", "upstream-lib"))
    http.add("GET", codeload("api-gateway"), body=secret_archive(), headers={"content-type": "application/x-gzip"})
    http.add("GET", codeload("patched-lib"), body=(FIX / "archive_ok.tar.gz").read_bytes(), headers={"content-type": "application/x-gzip"})
    http.add("GET", codeload("legacy-portal"), body=(FIX / "archive_truncated.tar.gz").read_bytes(), headers={"content-type": "application/x-gzip"})
    blocked = module_fixture("org_code_secrets", "codeload_blocked_proxy.http.json")
    http.add("GET", codeload("docs"), status=blocked["status"], text=blocked["body"], headers=blocked["headers"])
    res = run_module(OrgCodeSecrets, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status is Status.OK
    assert len(res.findings) == 1  # one grouped finding per repository; AWS documentation examples are allowlisted
    f = res.findings[0]
    assert f.severity.label == "high" and "credential_exposure" in f.tags and "third_party_disclosure" not in f.tags
    assert ocf.SECRET_WORDING in f.description and f.data["validated"] is False
    items = {(i["type"], i["file"], i["line"]) for i in f.data["items"]}
    assert ("github-pat", "config/settings.py", 2) in items and ("slack-bot-token", "deploy/notify.py", 3) in items
    for item in f.data["items"]:
        assert item["commit"] == COMMIT
        assert item["prefix"] is None or len(item["prefix"]) <= 4
        assert item["fingerprint"] is None or re.fullmatch(r"[0-9a-f]{16}", item["fingerprint"])
    assert {i["prefix"] for i in f.data["items"]} >= {"ghp_", "xoxb"}
    assert_no_secret(TOKEN, res.findings, res.attributes, res.raw, res.error)  # full values never leave the scan (cond 6)
    assert_no_secret(SLACK, res.findings, res.attributes, res.raw)
    assert TOKEN[-4:] not in json.dumps(f.data)  # never the last characters either
    scan = res.attributes["code_secret_scan"]
    assert scan["repos_scanned"] == 3 and scan["secrets"] == 2
    reasons = {s["repo"]: s["reason"] for s in scan["repos_skipped"]}
    assert reasons["example-org/ml-models"] == "over_50mb"
    assert reasons["example-org/docs"].startswith("could not download")
    assert "example-org/upstream-lib" not in reasons and not any("upstream-lib" in u for u in http.urls())  # unpushed fork never fetched
    http.assert_hosts_within(OrgCodeSecrets)


def test_archives_are_never_cached_and_no_token_reaches_codeload():
    http = discovery(FakeHttp(), repos_with("api-gateway"))
    http.add("GET", codeload("api-gateway"), body=secret_archive(), headers={"content-type": "application/x-gzip"})
    res = run_module(OrgCodeSecrets, "company_name:Example Org", http, org_profile=ORG_PROFILE, keys={"github": "ghp_FAKEKEYFORTESTS0000000000000000000000"})
    assert res.status is Status.OK
    for call in http.calls:
        auth = {k.lower(): v for k, v in (call.get("headers") or {}).items()}.get("authorization")
        assert (auth is not None) == call["url"].startswith(GH)


def test_supplier_repositories_go_to_the_disclosure_workflow():
    supplier_profile = {"org": {"name": "Acme"},
                        "domains": [{"name": "acme.example", "verification": "attested", "attested_by": "a", "attested_date": "2026-11-01"}],
                        "suppliers": [{"name": "Example Org", "domains": ["example.com"]}]}
    http = discovery(FakeHttp(), repos_with("api-gateway"))
    http.add("GET", codeload("api-gateway"), body=secret_archive(), headers={"content-type": "application/x-gzip"})
    options = ScanOptions(purpose="supplier exposure review TICKET-7")
    res = run_module(OrgCodeSecrets, "company_name:Example Org", http, org_profile=supplier_profile, options=options)
    assert res.status is Status.OK
    f = res.findings[0]
    assert f.severity.label == "medium" and "third_party_disclosure" in f.tags and "disclosure workflow" in f.description


def test_third_parties_need_a_purpose():
    http = FakeHttp()
    res = run_module(OrgCodeSecrets, "company_name:Other Org", http, org_profile=ORG_PROFILE)
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and http.calls == []


def test_unconfirmed_organisations_yield_no_secret_scan():
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Other Org type:org", per_page=5),
             json={"total_count": 1, "items": [{"login": "otherorg", "html_url": "https://github.com/otherorg", "type": "Organization"}]}, headers=JSON)
    http.add("GET", f"{GH}/orgs/otherorg", json={"login": "otherorg", "blog": "https://other.example.net"}, headers=JSON)
    http.add("GET", f"{CB}/orgs/otherorg", status=404, json={"message": "GetOrgByName"}, headers=JSON)
    http.add("GET", url(f"{GL}/groups", search="otherorg", top_level_only="true", per_page=5), json=[], headers=JSON)
    res = run_module(OrgCodeSecrets, "company_name:Other Org", http, org_profile=ORG_PROFILE, options=ScanOptions(purpose="review"))
    assert res.status is Status.EMPTY and "org-confirmed" in res.error
    assert "codeload.github.com" not in http.hosts()


def test_every_forge_failing_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), status=429, text="slow down")
    http.add("GET", f"{CB}/orgs/exampleorg", status=503, text="down", times=3)
    http.add("GET", url(f"{GL}/groups", search="exampleorg", top_level_only="true", per_page=5), status=429, text="Retry later")
    res = run_module(OrgCodeSecrets, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status in (Status.RATE_LIMITED, Status.ERROR)


def test_archive_streaming_limits():
    out = ocf.scan_archive_members((FIX / "archive_ok.tar.gz").read_bytes())
    paths = [f["path"] for f in out["files"]]
    assert "assets/logo.png" not in paths and "bin/tool" not in paths  # binaries skipped (extension, NUL bytes)
    reasons = {s["path"]: s["reason"] for s in out["skipped"]}
    assert reasons["data/big.txt"] == "over_1mb" and reasons["link-to-passwd"] == "not_regular_file"
    assert reasons["../escape.txt"] == "unsafe_path" and reasons["/abs/path.txt"] == "unsafe_path"
    assert out["commit"] == "0123456789abcdef0123456789abcdef01234567"
    assert ocf.scan_archive_members(b"not a tarball")["error"].startswith("archive_error")
    assert ocf.scan_archive_members(secret_archive(), max_members=2)["error"] == "member_cap"


def test_metadata():
    cls = OrgCodeSecrets
    assert cls.default_enabled is False and cls.run_on == "seeds" and cls.timeout >= 300
    assert set(cls.hosts) == {"api.github.com", "codeload.github.com", "gitlab.com", "codeberg.org"}
    assert cls.terms == "key-terms" and cls.trust_tier == "community"
