"""``v3lum export`` (WP21, P303): 0600 files with the TLP in the name and an audit row, and the gated
push to the organisation's own MISP/OpenCTI - dry run sends nothing, confirmation required, RED /
research / engagement cases refused, only the configured internal host is contacted, errors inside
HTTP 200 bodies are 'could not verify'. Offline: the App's runtimes go over a FakeHttp."""

from __future__ import annotations

import io
import json
import os
import re
import stat
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, test_provider
from tests.test_stix_v2 import load_case, pinned_indexes  # noqa: F401 - autouse fixture
from v3lum import paths
from v3lum.cli import main
from v3lum.commands.export import export_path, push_refusal
from v3lum.core.store import Store

CASE_ID = "20261126-100000-a1b2"
MISP = "https://misp.internal.example"
OPENCTI = "https://opencti.internal.example"
MISP_KEY = "test-misp-key-0123456789"
OPENCTI_KEY = "test-opencti-token-0123456789"


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")


@pytest.fixture()
def http(monkeypatch):
    """Runtimes built by the App go over this FakeHttp (unmatched requests fail the test)."""
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp()

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    return fake


@pytest.fixture()
def configured(monkeypatch, capsys):
    assert main(["config", "set", "misp_url", MISP]) == 0
    assert main(["config", "set", "opencti_url", OPENCTI]) == 0
    monkeypatch.setenv("V3LUM_KEY_MISP", MISP_KEY)
    monkeypatch.setenv("V3LUM_KEY_OPENCTI", OPENCTI_KEY)
    capsys.readouterr()


def store_case(**changes) -> dict:
    case = load_case(**changes)
    with Store() as st:
        st.save_case(case)
    return case


def audit(kind: str) -> list[dict]:
    with Store() as st:
        rows = st.audit_rows(CASE_ID)
    return [dict(r["payload"]) for r in rows if r["kind"] == kind]


def run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["export", *argv])
    out, err = capsys.readouterr()
    return rc, out, err


def misp_ok(fake: FakeHttp, path: str = "/events/add", **extra) -> None:
    fake.add("POST", MISP + path, json={"Event": {"id": "17", "uuid": "x", "published": False, "distribution": "0", **extra}})


# --------------------------------------------------------------------------------------
# file export
# --------------------------------------------------------------------------------------


def test_file_export_writes_0600_with_the_tlp_in_the_name_and_an_audit_row(capsys):
    store_case()
    rc, out, _ = run(capsys, CASE_ID)
    assert rc == 0
    target = paths.case_dir(CASE_ID) / f"v3lum-{CASE_ID}.TLP-AMBER.stix.json"
    assert target.is_file() and stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert "TLP:AMBER" in out and "2 indicators" in out
    bundle = json.loads(target.read_text(encoding="utf-8"))
    assert bundle["objects"][0]["name"] == "TLP:AMBER"
    assert "joao.silva" not in target.read_text(encoding="utf-8")
    rows = audit("export")
    assert rows and rows[-1]["format"] == "stix" and rows[-1]["include_personal"] is False and rows[-1]["file"] == target.name
    with Store() as st:  # recorded for the A10 purge and `cases verify`
        assert os.path.abspath(target) in [os.path.abspath(p) for p in st.report_paths(CASE_ID)]
        assert os.path.abspath(target) in st.report_hashes(CASE_ID)


def test_include_personal_is_recorded_and_warned(capsys):
    store_case()
    rc, out, _ = run(capsys, CASE_ID, "--format", "misp", "--include-personal")
    assert rc == 0 and "contains personal data" in out
    target = paths.case_dir(CASE_ID) / f"v3lum-{CASE_ID}.TLP-AMBER.misp.json"
    text = target.read_text(encoding="utf-8")
    assert "joao.silva@acme-corp.example" in text and "52998224725" not in text
    assert audit("export")[-1]["include_personal"] is True


def test_out_option_keeps_the_tlp_label(tmp_path, capsys):
    store_case(tlp="amber+strict")
    rc, _out, _ = run(capsys, CASE_ID, "-o", str(tmp_path / "share.json"))
    assert rc == 0
    assert (tmp_path / "share.TLP-AMBER+STRICT.json").is_file()
    rc, _out, _ = run(capsys, CASE_ID, "--format", "misp", "-o", str(tmp_path) + os.sep)
    assert rc == 0 and (tmp_path / f"v3lum-{CASE_ID}.TLP-AMBER+STRICT.misp.json").is_file()
    case = load_case(tlp="red")
    assert export_path(case, "stix", None, tmp_path).name == f"v3lum-{CASE_ID}.TLP-RED.stix.json"
    assert export_path(case, "stix", str(tmp_path / "x.TLP-RED.json"), tmp_path).name == "x.TLP-RED.json"


def test_out_option_replaces_a_stale_tlp_label(tmp_path, capsys):
    """A2: a file name never carries another TLP than the content (no 'x.TLP-CLEAR.TLP-RED.json')."""
    case = load_case(tlp="red")
    assert export_path(case, "stix", str(tmp_path / "share.TLP-CLEAR.json"), tmp_path).name == "share.TLP-RED.json"
    assert export_path(case, "stix", str(tmp_path / "share_tlp-amber+strict.json"), tmp_path).name == "share.TLP-RED.json"
    amber = load_case()
    assert export_path(amber, "misp", str(tmp_path / "x.TLP-AMBER+STRICT.json"), tmp_path).name == "x.TLP-AMBER.json"
    assert export_path(amber, "misp", str(tmp_path / "TLP-GREEN"), tmp_path).name == f"v3lum-{CASE_ID}.TLP-AMBER"
    with pytest.raises(ValueError):
        export_path(load_case(case_id="../../etc/x"), "stix", None, tmp_path)
    store_case()
    rc, _out, _ = run(capsys, CASE_ID, "-o", str(tmp_path / "out.TLP-CLEAR.json"))
    assert rc == 0 and (tmp_path / "out.TLP-AMBER.json").is_file() and not (tmp_path / "out.TLP-CLEAR.json").exists()


def test_analyst_override_in_the_store_makes_an_indicator(capsys):
    """The export applies the stored analyst decisions (P322 cond 3): a finding the analyst marks
    malicious becomes a to_ids attribute although no consensus exists; the override note never leaves."""
    case = load_case(correlations=[])
    case["findings"] = [f for f in case["findings"] if f["id"] == "f0dom0000000002"]
    with Store() as st:
        st.save_case(case)
        st.set_override("f0dom0000000002", analyst="analyst1", verdict="malicious", note="STORED OVERRIDE NOTE", case_id=CASE_ID)
    rc, _out, _ = run(capsys, CASE_ID, "--format", "misp")
    assert rc == 0
    text = (paths.case_dir(CASE_ID) / f"v3lum-{CASE_ID}.TLP-AMBER.misp.json").read_text(encoding="utf-8")
    attrs = {a["value"]: a for a in json.loads(text)["Event"]["Attribute"]}
    assert attrs["login-acme.example"]["to_ids"] is True and "analyst-confirmed" in attrs["login-acme.example"]["comment"]
    assert "STORED OVERRIDE NOTE" not in text


def test_unknown_case_and_push_only_flags(capsys):
    rc, _out, err = run(capsys, "20990101-000000-ffff")
    assert rc == 1 and "not found" in err
    store_case()
    rc, _out, err = run(capsys, CASE_ID, "--dry-run")
    assert rc == 1 and "--push only" in err


# --------------------------------------------------------------------------------------
# push: refusals
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"tlp": "red"}, "TLP:RED"),
        ({"licence_profile": "research"}, "research-profile"),
        ({"engagement": {"mode": "active", "authorization_ref": "PT-2026-042"}}, "--allow-engagement"),
    ],
)
def test_push_refused_for_red_research_and_engagement_cases(changes, needle, http, configured, capsys):
    store_case(**changes)
    rc, _out, err = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and needle in err and "push refused" in err
    assert http.calls == []
    assert push_refusal(load_case(**changes))


def test_engagement_case_pushed_only_with_allow_engagement_and_audited(http, configured, capsys):
    case = load_case()
    case["options"]["mode"] = "light"
    with Store() as st:
        st.save_case(case)
    misp_ok(http)
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--allow-engagement", "--yes")
    assert rc == 0 and "pushed to misp.internal.example" in out
    row = audit("export_push")[-1]
    assert row["engagement"] is True and row["allow_engagement"] is True and row["ok"] is True


def test_personal_data_never_pushed(http, configured, capsys):
    store_case()
    rc, _out, err = run(capsys, CASE_ID, "--push", "misp", "--include-personal", "--yes")
    assert rc == 1 and "never carries personal data" in err and http.calls == []


def test_push_needs_an_https_url_and_a_key(http, monkeypatch, capsys):
    store_case()
    rc, _out, err = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "misp_url" in err
    assert main(["config", "set", "misp_url", MISP]) == 0
    capsys.readouterr()
    rc, _out, err = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "API key 'misp'" in err
    monkeypatch.setenv("V3LUM_KEY_MISP", MISP_KEY)
    assert main(["config", "set", "misp_url", "http://misp.internal.example"]) != 0  # the setting refuses plain http
    capsys.readouterr()
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--dry-run")
    assert rc == 0 and "misp.internal.example" in out  # the https URL set before is kept
    assert http.calls == []


def test_push_to_a_community_or_other_organisation_instance_is_refused(http, configured, capsys):
    store_case()
    with test_provider("community_misp_test", hosts=("misp.community.example",), tier="community"):
        assert main(["config", "set", "misp_url", "https://misp.community.example"]) == 0
        capsys.readouterr()
        rc, _out, err = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "not the organisation's own" in err and "community_misp_test" in err
    assert http.calls == []


# --------------------------------------------------------------------------------------
# push: dry run and confirmation
# --------------------------------------------------------------------------------------


def test_dry_run_prints_the_summary_and_sends_nothing(http, configured, capsys):
    store_case()
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--dry-run")
    assert rc == 0 and http.calls == []
    assert re.search(r"1 event, \d+ attributes, 2 to_ids", out)
    assert "distribution 0 (your organisation only)" in out and "unpublished" in out and "nothing was sent" in out
    rc, out, _ = run(capsys, CASE_ID, "--push", "opencti", "--dry-run")
    assert rc == 0 and http.calls == [] and re.search(r"1 bundle, \d+ objects, 2 indicators", out)
    assert audit("export_push") == []


def test_amber_strict_dry_run_names_the_own_instance_rule(http, configured, capsys):
    store_case(tlp="amber+strict")
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--dry-run")
    assert rc == 0 and "AMBER+STRICT: allowed only because the target is the organisation's own instance" in out


def test_confirmation_is_required(http, configured, capsys, monkeypatch):
    store_case()
    rc, _out, err = run(capsys, CASE_ID, "--push", "misp")
    assert rc == 1 and "interactive confirmation" in err and "misp.internal.example" in err and http.calls == []
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp")
    assert rc == 0 and "not pushed" in out and "push 1 event" in out and http.calls == []
    misp_ok(http)
    monkeypatch.setattr("sys.stdin", _Tty("y\n"))
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp")
    assert rc == 0 and "pushed to misp.internal.example (17)" in out


# --------------------------------------------------------------------------------------
# push: what is sent, and to whom
# --------------------------------------------------------------------------------------


def test_misp_push_contacts_only_the_internal_host_with_an_unpublished_org_only_event(http, configured, capsys):
    store_case(tlp="green")
    misp_ok(http)
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 0
    assert http.hosts() == {"misp.internal.example"}
    call = http.calls[0]
    assert call["method"] == "POST" and call["url"] == MISP + "/events/add"
    assert {k.lower(): v for k, v in call["headers"].items()}["authorization"] == MISP_KEY
    body = json.loads(call["body"])["Event"]
    assert body["distribution"] == "0" and body["published"] is False and "sharing_group_id" not in body
    assert {"name": "tlp:green"} in body["Tag"]
    assert "joao.silva" not in call["body"].decode("utf-8")
    row = audit("export_push")[-1]
    assert row["ok"] is True and row["host"] == "misp.internal.example" and row["result"]["event_id"] == "17"
    assert MISP_KEY not in json.dumps(audit("export_push"))


def test_misp_error_inside_an_http_200_body_is_could_not_verify(http, configured, capsys):
    store_case()
    http.add("POST", MISP + "/events/add", json={"saved": False, "errors": {"Event": ["validation failed"]}})
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "could not verify" in out and "validation failed" in out
    assert audit("export_push")[-1]["ok"] is False


def test_misp_existing_event_is_updated_in_place(http, configured, capsys):
    store_case()
    http.add("POST", MISP + "/events/add", status=403, json={"name": "Event already exists, if you would like to edit it, use the url in the location header.", "message": "Event already exists"})
    from v3lum.report.misp import event

    ev_uuid = event(load_case())["Event"]["uuid"]
    misp_ok(http, f"/events/edit/{ev_uuid}")
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 0, out
    assert [c["url"] for c in http.calls] == [MISP + "/events/add", MISP + f"/events/edit/{ev_uuid}"]


def test_misp_transport_failure_is_could_not_verify(http, configured, capsys):
    from v3lum.core.http import NetworkError

    store_case()
    http.add("POST", MISP + "/events/add", error=NetworkError("TLS certificate verify failed", retryable=False))
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "could not verify" in out


@pytest.mark.parametrize("status", [429, 500, 503])
def test_misp_throttling_and_server_errors_are_could_not_verify(status, http, configured, capsys):
    store_case()
    http.add("POST", MISP + "/events/add", status=status, json={"message": "try later"})
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "could not verify" in out and "pushed to" not in out
    assert [c["url"] for c in http.calls] == [MISP + "/events/add"]  # no retry storm, no edit attempt
    row = audit("export_push")[-1]
    assert row["ok"] is False and "could not verify" in row["result"]["error"]


def test_unexpected_client_failure_is_still_audited(http, configured, capsys):
    store_case()
    http.add("POST", MISP + "/events/add", error=RuntimeError("boom"))
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--yes")
    assert rc == 1 and "could not verify" in out
    assert audit("export_push")[-1]["ok"] is False


class _Cfg(dict):
    def key(self, name):
        return "k-" + name


class _App:
    def __init__(self, **settings):
        self.config = _Cfg(settings)


@pytest.mark.parametrize(
    "url",
    ["https://user:pw@misp.internal.example", "https://misp.internal.example/?org=1", "https://misp.internal.example/#x", "https://misp.internal.example:99999"],
)
def test_push_url_must_be_a_plain_https_base(url):
    from v3lum.app import UserError
    from v3lum.commands.export import _target

    with pytest.raises(UserError):
        _target(_App(misp_url=url), "misp")


def test_amber_strict_goes_only_to_a_trusted_internal_instance(monkeypatch):
    from types import SimpleNamespace

    from v3lum.app import UserError
    from v3lum.commands import export as export_cmd
    from v3lum.core import providers

    prov = SimpleNamespace(id="internal_misp", internal=True, tier="community", flags=SimpleNamespace(publishes_queries=False, reuses_queries=False))
    reg = SimpleNamespace(get=lambda pid: prov, hosts_for=lambda pid, cfg: ["misp.internal.example"], provider_for_host=lambda h: None)
    monkeypatch.setattr(providers, "registry", lambda: reg)
    app = _App(misp_url=MISP)
    with pytest.raises(UserError, match="AMBER\\+STRICT"):
        export_cmd._target(app, "misp", "amber+strict")
    assert export_cmd._target(app, "misp", "amber")[1] == "misp.internal.example"
    prov.flags.reuses_queries = True
    with pytest.raises(UserError, match="never pushed"):
        export_cmd._target(app, "misp", "amber")


def test_opencti_push_uploads_the_bundle_to_the_import_area(http, configured, capsys):
    store_case()
    http.add("POST", OPENCTI + "/graphql", json={"data": {"uploadImport": {"id": "import/global/v3lum.json", "name": "v3lum.json"}}})
    rc, out, _ = run(capsys, CASE_ID, "--push", "opencti", "--yes")
    assert rc == 0 and "pushed to opencti.internal.example" in out
    assert http.hosts() == {"opencti.internal.example"}
    call = http.calls[0]
    headers = {k.lower(): v for k, v in call["headers"].items()}
    assert headers["authorization"] == f"Bearer {OPENCTI_KEY}" and headers["content-type"].startswith("multipart/form-data; boundary=")
    body = call["body"].decode("utf-8")
    assert "uploadImport" in body and f'filename="v3lum-{CASE_ID}.TLP-AMBER.stix.json"' in body
    assert "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421" in body and "joao.silva" not in body
    assert audit("export_push")[-1]["result"]["import_id"] == "import/global/v3lum.json"


def test_opencti_graphql_errors_in_200_are_could_not_verify(http, configured, capsys):
    store_case()
    http.add("POST", OPENCTI + "/graphql", json={"errors": [{"message": "You are not allowed to do this."}], "data": None})
    rc, out, _ = run(capsys, CASE_ID, "--push", "opencti", "--yes")
    assert rc == 1 and "could not verify" in out and "not allowed" in out


def test_json_summary(http, configured, capsys):
    store_case()
    rc, out, _ = run(capsys, CASE_ID, "--push", "misp", "--dry-run", "--json")
    data = json.loads(out)
    assert rc == 0 and data["dry_run"] is True and data["host"] == "misp.internal.example" and data["to_ids"] == 2
    rc, out, _ = run(capsys, CASE_ID, "--format", "stix", "--json")
    data = json.loads(out)
    assert rc == 0 and Path(data["path"]).is_file() and data["indicators"] == 2


def test_contract_additions_names_resolve():
    """Every backticked ``v3lum.*`` name of docs/contract_additions/WP21.md is importable."""
    import importlib

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP21.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?![/\w])", doc)))  # schema ids ('v3lum.galaxy/1') excluded
    assert "v3lum.report.stix.bundle" in names and "v3lum.core.galaxy.lookup" in names
    for name in names:
        parts = name.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            for attr in parts[cut:]:
                obj = getattr(obj, attr)
            break
        else:  # pragma: no cover - nothing importable
            raise AssertionError(name)
