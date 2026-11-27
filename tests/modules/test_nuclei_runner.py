"""nuclei_runner (P369, ACTIVE): the contract, the pinned template allow-list gate (FC4/FC5/FC8),
the fixed argv and scrubbed environment (FC6/FC7), the scope-bound target list (FC1/FC2), the
JSONL -> findings/technology mapping (FC10), the tri-state, the kill handling and the ledger trace
(FC9/FC11).

Target-contact code never contacts a third-party host here: the engine's ``run_tool`` is driven with
a stub ``nuclei`` executable on a temporary PATH (FC11) that emits recorded JSONL, and the only live
target is a routable in-scope IP literal the scope lists, so no DNS leaves. The deep scope/egress/kill
enforcement around ``run_tool`` is proved by the AR20 safety suite; here we prove the module hands it
only the one in-scope seed, the fixed argv, the pinned templates and nothing else."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, fixture, make_ctx, run_module
from v3lum.config import Config
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Opsec, Status
from v3lum.core.module import HealthResult
from v3lum.core.net import Connector, EgressProfiles
from v3lum.core.scope import Scope
from v3lum.core.tools import ToolResult
from v3lum.modules.pentest_recon import g134_parsers as P
from v3lum.modules.pentest_recon.nuclei_runner import NucleiRunner

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the stub nuclei is a POSIX script")

REF = "PENTEST-2026-042"
IN_SCOPE_IP = "93.184.216.34"
TEMPLATES_DIR = FIXTURES / "nuclei_runner" / "templates"
BUNDLED = json.loads((Path(__file__).resolve().parents[2] / "v3lum" / "data" / "nuclei_runner" / "allowlist.json").read_text())

SCOPE = {
    "authorization_ref": REF,
    "owner": "ACME S.A. - information security",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1234",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",
    "targets": {"domains": ["acme.example", "*.acme.example"], "cidrs": ["93.184.216.0/24"]},
    "roe": {"user_agent": "pentest-PENTEST-2026-042", "header": {"name": "X-Engagement-Token", "value": "c0ffee42"}},
}

# A stub nuclei: answers -version, records its argv and environment names, writes the trace to the
# -tlog path, prints the baked JSONL.
STUB = """#!{python}
import json, os, sys
argv = sys.argv[1:]
if argv[:1] == ["-version"]:
    sys.stdout.write({version!r} + "\\n")
    sys.exit(0)
with open({record!r}, "w") as fh:
    json.dump({{"argv": argv, "env": sorted(os.environ)}}, fh)
if "-tlog" in argv:
    p = argv[argv.index("-tlog") + 1]
    open(p, "w").write({trace!r})
sys.stdout.write({stdout!r})
sys.stderr.write({stderr!r})
sys.exit({code})
"""


def make_scope(**changes) -> Scope:
    data = copy.deepcopy(SCOPE)
    data.update(changes)
    return Scope.from_dict(data)


def cfg(**settings) -> Config:
    config = Config()
    config.settings.update(settings)
    return config


def _stub(bindir: Path, *, version="nuclei v3.11.1", stdout="", stderr="", trace="", code=0) -> Path:
    path = bindir / "nuclei"  # the ToolSpec binary name; found first on the temporary PATH
    record = bindir / "last_run.json"
    path.write_text(
        STUB.format(python=sys.executable, version=version, stdout=stdout, stderr=stderr, trace=trace, code=code, record=str(record)),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return record


def _pinned_allowlist(*files: Path) -> dict:
    """The bundled allow-list shape, pinned to the (author-redacted) fixture templates' own bytes."""
    allow = {"schema": "v3lum.nuclei_allowlist/1", "release": "v10.5.2", "reviewed_ids": [], "templates": {}}
    for f in files:
        meta = P.parse_template_meta(f.read_bytes())
        allow["reviewed_ids"].append(meta["id"])
        allow["templates"][meta["id"]] = {"path": f.name, "tags": meta["tags"], "severity": meta["severity"],
                                          "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
    return allow


@pytest.fixture()
def stub_path(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bindir


@pytest.fixture()
def pinned(monkeypatch):
    """Pin the allow-list to the fixture templates (the bundled pins are the upstream v10.5.2 bytes)."""
    allow = _pinned_allowlist(TEMPLATES_DIR / "jaeger-ui-dashboard.yaml", TEMPLATES_DIR / "allowed-dns.yaml")
    monkeypatch.setattr(NucleiRunner, "_allowlist", staticmethod(lambda ctx: allow))
    return allow


def active_ctx(templates_dir=TEMPLATES_DIR, scope=None, **run_kw):
    """An ACTIVE ctx whose ctx.net resolves an IP literal and launches the stub nuclei."""
    options = ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=scope or make_scope())
    ent = Entity.make(EntityType.IPV4, IN_SCOPE_IP)
    ctx = make_ctx(
        NucleiRunner, settings={"nuclei_runner_templates_dir": str(templates_dir)}, options=options, entity=ent,
        case_id="case-1", **run_kw,
    )
    conf = cfg()
    egress = EgressProfiles(conf, resolver=lambda host, profile: [IN_SCOPE_IP])
    ctx.net = Connector(
        module="nuclei_runner", disclosure="target", opsec=Opsec.ACTIVE, scope=options.scope,
        run=RunInfo(entity=ent, case_id="case-1"), config=conf, egress=egress, clock=ctx.runtime.clock,
    )
    return ctx, ent


def _trace(*templates: str) -> str:
    return "".join(json.dumps({"template": t, "type": "http", "input": f"https://{IN_SCOPE_IP}", "address": f"{IN_SCOPE_IP}:443",
                               "error": "none", "kind": "api"}) + "\n" for t in templates)


def _result(template_id: str, severity: str, tags: list[str], *, name: str = "", matcher: str = "", extracted=None) -> str:
    return json.dumps({
        "template-id": template_id, "template-path": f"http/{template_id}.yaml",
        "info": {"name": name or template_id, "tags": tags, "severity": severity},
        "matcher-name": matcher, "type": "http", "host": IN_SCOPE_IP, "matched-at": f"https://{IN_SCOPE_IP}/search",
        "extracted-results": extracted or [], "matcher-status": True,
    }) + "\n"


# --------------------------------------------------------------------------------------
# contract / metadata
# --------------------------------------------------------------------------------------


def test_contract_metadata():
    m = NucleiRunner
    assert m.opsec is Opsec.ACTIVE and m.disclosure == "target" and m.default_enabled is False
    assert m.terms == "open" and m.hosts == () and m.run_on == "seeds"
    assert m.shares_input is True and m.trust_tier == "n/a"
    assert m.timeout == 600.0 and (m.max_rate or 0) <= 10.0


def test_health_self_test_is_offline():
    hc = NucleiRunner.health_check()
    assert hc.offline is True and callable(hc.selftest)
    res = hc.selftest(make_ctx(NucleiRunner))
    assert isinstance(res, HealthResult)
    # nuclei is usually not installed in CI: 'blocked' (reported UNAVAILABLE 'package' at run time), never a crash
    assert res.status in ("ok", "blocked")


# --------------------------------------------------------------------------------------
# FC4/FC5/FC8 - the pinned allow-list gate (the CI test over the pinned set)
# --------------------------------------------------------------------------------------


def _tmpl(body: str, *, tags: str = "tech", tid: str = "probe") -> dict:
    return P.parse_template_meta(f"id: {tid}\ninfo:\n  name: x\n  severity: info\n  tags: {tags}\n{body}# digest: 00:00\n")


GET = "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"


@pytest.mark.parametrize("tags", ["cve,tech", "kev,panel", "takeover,dns", "vkev,exposure", "default-login,panel",
                                  "intrusive,tech", "oast,tech", "fuzz,misconfig", "sqli,exposure", "fileupload,tech",
                                  "rce,exposure", "wordpress,tech"])
def test_fc8_gate_rejects_excluded_forbidden_and_non_governing_tags(tags):
    assert P.template_decision(_tmpl(GET, tags=tags))["allowed"] is False


@pytest.mark.parametrize("name,body", [
    ("interactsh", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/?u=http://{{interactsh-url}}'\n"),
    ("post", "http:\n  - method: POST\n    path:\n      - '{{BaseURL}}/'\n"),
    ("options", "http:\n  - method: OPTIONS\n    path:\n      - '{{BaseURL}}/'\n"),
    ("raw_put", "http:\n  - raw:\n      - |\n        PUT /x HTTP/1.1\n        Host: {{Hostname}}\n"),
    ("file_read_traversal", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/static/../../etc/hostname'\n"),
    ("file_read_matcher", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/dl?f=x'\n    matchers:\n      - type: regex\n        regex:\n          - 'root:.*:0:0:'\n"),
    ("command_exec", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/?q=;id'\n    matchers:\n      - type: regex\n        regex:\n          - 'uid=[0-9]+'\n"),
    ("command_subshell", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/cgi-bin/x?$(whoami)'\n"),
    ("auth_bypass_header", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/admin'\n    headers:\n      X-Original-URL: /admin\n"),
    ("auth_payloads", "http:\n  - raw:\n      - |\n        GET /admin HTTP/1.1\n        Host: {{Hostname}}\n        Authorization: Basic {{base64(username + ':' + password)}}\n    payloads:\n      username:\n        - admin\n      password:\n        - admin\n"),
    ("ssrf_metadata", "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/proxy?u=http://169.254.169.254/latest/'\n"),
    ("code_protocol", "code:\n  - engine:\n      - sh\n    source: echo\n"),
    ("headless_protocol", "headless:\n  - steps:\n      - action: navigate\n"),
    ("network_protocol", "tcp:\n  - inputs:\n      - data: x\n"),
    ("unsigned", None),
])
def test_fc8_gate_rejects_oast_methods_exploit_confirmation_and_protocols(name, body):
    if body is None:  # unsigned: no '# digest:' line
        meta = P.parse_template_meta("id: probe\ninfo:\n  name: x\n  severity: info\n  tags: tech\n" + GET)
    else:
        meta = _tmpl(body)
    decision = P.template_decision(meta)
    assert decision["allowed"] is False, (name, decision)


def test_fc8_gate_accepts_get_and_head_detection_templates():
    assert P.template_decision(_tmpl(GET))["allowed"] is True
    head = "http:\n  - method: HEAD\n    path:\n      - '{{BaseURL}}/'\n"
    assert P.template_decision(_tmpl(head, tags="panel,discovery"))["allowed"] is True
    jaeger = P.parse_template_meta((TEMPLATES_DIR / "jaeger-ui-dashboard.yaml").read_bytes())
    assert P.template_decision(jaeger)["allowed"] is True  # literal FC4 gate: misconfig,discovery; GET; signed


def test_fc8_audit_over_a_set_flags_the_templates_that_must_not_ship():
    metas = [
        P.parse_template_meta((TEMPLATES_DIR / "jaeger-ui-dashboard.yaml").read_bytes()),
        P.parse_template_meta(fixture("nuclei_runner/reject_file_read.yaml")),
        P.parse_template_meta((TEMPLATES_DIR / "allowed-exposure-descriptor.yaml").read_bytes()),
        P.parse_template_meta("id: cve-thing\ninfo:\n  name: x\n  severity: high\n  tags: cve,rce\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}']\n# digest: 00:00\n"),
    ]
    audit = P.audit_template_set(metas)
    assert audit["ok"] is False
    rejected_ids = {r["id"] for r in audit["rejected"]}
    assert {"cve-thing", "example-path-traversal-detect", "git-config"} <= rejected_ids  # git/config: not governing tags
    assert "jaeger-ui-dashboard" not in rejected_ids


def test_bundled_allowlist_is_a_pinned_binding_floor_subset():
    """The CI test over the pinned set (FC8): every reviewed id is pinned by path + SHA-256 in an
    http/ssl/dns directory, every tag is governing and none is excluded or forbidden."""
    data = BUNDLED
    assert data["release"] == "v10.5.2" and data["reviewed_ids"]
    assert set(data["reviewed_ids"]) == set(data["templates"])
    for tid, meta in data["templates"].items():
        assert len(meta["sha256"]) == 64 and int(meta["sha256"], 16) >= 0, tid
        assert meta["path"].split("/", 1)[0] in ("http", "ssl", "dns") and ".." not in meta["path"], tid
        tags = set(meta["tags"])
        assert tags and tags <= P.NUCLEI_ALLOWED_TAGS, tid  # literal FC4: every tag governing
        assert not (tags & (P.A7_FORBIDDEN_TAGS | P.A7_FORBIDDEN_TAG_VARIANTS | P.BUILD_EXCLUDED_TAGS | P.BUILD_EXCLUDED_TAG_VARIANTS)), tid
    assert NucleiRunner._pins(data).keys() == set(data["reviewed_ids"])


# --------------------------------------------------------------------------------------
# FC6/FC7 - the fixed argv and never-passed flags
# --------------------------------------------------------------------------------------


def test_forced_args_hold_the_fixed_flags_and_the_forbidden_set():
    forced = P.NUCLEI_FORCED_ARGS
    for flag in ("-ni", "-duc", "-dut", "-dr", "-or", "-jsonl"):
        assert flag in forced
    assert forced[forced.index("-c") + 1] == "2" and forced[forced.index("-bs") + 1] == "5"
    assert forced[forced.index("-timeout") + 1] == "10" and forced[forced.index("-retries") + 1] == "1"
    assert forced[forced.index("-ept") + 1] == "code,headless,javascript,file,websocket,whois"
    for flag in ("-cup", "-ut", "-turl", "-sa", "-ev", "-lfa", "-tlsi", "-dast", "-code", "-headless", "-sresp", "-srd", "-sf",
                 "-pd", "-pdu", "-iserver"):
        assert flag in P.NUCLEI_FORBIDDEN_FLAGS


def test_module_args_are_deterministic_and_carry_lna_and_roe():
    args = P.nuclei_module_args(["/t/a.yaml", "/t/b.yaml"], "/w/targets.txt", "/w/trace.jsonl",
                                roe_header="X-Engagement-Token: c0ffee42", roe_user_agent="pentest-REF")
    assert args == ["-t", "/t/a.yaml,/t/b.yaml", "-l", "/w/targets.txt", "-tlog", "/w/trace.jsonl", "-lna",
                    "-H", "X-Engagement-Token: c0ffee42", "-H", "User-Agent: pentest-REF"]
    assert "-lna" not in P.nuclei_module_args(["/t/a.yaml"], "/w/t", "/w/tr", scope_has_private=True)
    assert P.audit_argv(list(P.NUCLEI_FORCED_ARGS) + ["-rl", "10"])["ok"] is True


def test_the_launched_argv_is_fixed_and_the_environment_is_scrubbed(stub_path, pinned, monkeypatch):
    """FC6/FC7 end to end: the argv nuclei really receives, in order, and its environment."""
    monkeypatch.setenv("PDCP_API_KEY", "should-never-reach-nuclei")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    record = _stub(stub_path, stdout="", stderr="", trace="")
    ctx, ent = active_ctx()
    NucleiRunner().run(ent, ctx)
    seen = json.loads(record.read_text())
    argv = seen["argv"]
    forced = list(P.NUCLEI_FORCED_ARGS)
    assert argv[: len(forced)] == forced  # the core's fixed flags come first
    assert argv[len(forced): len(forced) + 2] == ["-rl", "10"]  # A7 rate ceiling set by the core
    rest = argv[len(forced) + 2:]
    assert rest[0] == "-t" and rest[2] == "-l" and rest[4] == "-tlog" and rest[6] == "-lna"
    templates = rest[1].split(",")
    assert sorted(Path(t).name for t in templates) == ["jaeger-ui-dashboard.yaml", "txt-fingerprint.yaml"]  # only pinned files...
    assert all(not t.startswith(str(TEMPLATES_DIR)) for t in templates)  # ...as private copies of the verified bytes
    assert rest[7:] == ["-H", "X-Engagement-Token: c0ffee42", "-H", "User-Agent: pentest-PENTEST-2026-042"]
    assert "-p" not in argv  # no proxy_active configured in this test: nothing but the core sets -p
    for flag in P.NUCLEI_FORBIDDEN_FLAGS:
        assert flag not in argv
    assert "PDCP_API_KEY" not in seen["env"] and "HTTPS_PROXY" not in seen["env"]


def test_the_proxy_active_profile_is_passed_with_p_and_nothing_else_moves(stub_path, pinned):
    """FC6: '-p' is the proxy_active profile, set by the core right after the rate (never by the module)."""
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    proxy = f"http://127.0.0.1:{listener.getsockname()[1]}"
    try:
        record = _stub(stub_path)
        ctx, ent = active_ctx()
        conf = cfg(proxy_active=proxy)
        ctx.net = Connector(
            module="nuclei_runner", disclosure="target", opsec=Opsec.ACTIVE, scope=ctx.options.scope,
            run=RunInfo(entity=ent, case_id="case-1"), config=conf,
            egress=EgressProfiles(conf, resolver=lambda host, profile: [IN_SCOPE_IP]), clock=ctx.runtime.clock,
        )
        NucleiRunner().run(ent, ctx)
    finally:
        listener.close()
    argv = json.loads(record.read_text())["argv"]
    forced = list(P.NUCLEI_FORCED_ARGS)
    assert argv[len(forced): len(forced) + 4] == ["-rl", "10", "-p", proxy]


# --------------------------------------------------------------------------------------
# run-path - UNAVAILABLE gates when the binary / templates are absent or not the pinned ones
# --------------------------------------------------------------------------------------


def test_unavailable_package_without_the_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing"))
    res = run_module(
        NucleiRunner, f"ipv4:{IN_SCOPE_IP}",
        settings={"nuclei_runner_templates_dir": str(TEMPLATES_DIR)},
        options=ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=make_scope()),
    )
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_unavailable_package_for_a_binary_outside_the_pinned_range(stub_path):
    _stub(stub_path, version="nuclei v2.9.15")
    res = run_module(
        NucleiRunner, f"ipv4:{IN_SCOPE_IP}",
        settings={"nuclei_runner_templates_dir": str(TEMPLATES_DIR)},
        options=ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=make_scope()),
    )
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_unavailable_dataset_without_a_reviewed_templates_dir(stub_path):
    _stub(stub_path)
    res = run_module(
        NucleiRunner, f"ipv4:{IN_SCOPE_IP}",
        settings={"nuclei_runner_templates_dir": ""},
        options=ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=make_scope()),
    )
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_unavailable_dataset_when_no_template_matches_the_allowlist(stub_path, tmp_path):
    _stub(stub_path)
    empty_dir = tmp_path / "templates-empty"
    empty_dir.mkdir()
    (empty_dir / "not-reviewed.yaml").write_text("id: not-on-the-list\ninfo:\n  name: x\n  tags: tech\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n# digest: 0:0\n")
    res = run_module(
        NucleiRunner, f"ipv4:{IN_SCOPE_IP}",
        settings={"nuclei_runner_templates_dir": str(empty_dir)},
        options=ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=make_scope()),
    )
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_a_file_that_differs_from_its_pinned_sha256_is_never_run(stub_path, tmp_path):
    """FC4: the bundled pins are the upstream v10.5.2 bytes; an edited copy (here the author-redacted
    fixture under the reviewed path) is refused even though its id is reviewed and it passes the gate."""
    record = _stub(stub_path, stdout=_result("jaeger-ui-dashboard", "low", ["misconfig", "discovery"]))
    checkout = tmp_path / "nuclei-templates"
    target = checkout / "http" / "misconfiguration" / "jaeger-ui-dashboard.yaml"
    target.parent.mkdir(parents=True)
    shutil.copy(TEMPLATES_DIR / "jaeger-ui-dashboard.yaml", target)
    ctx, ent = active_ctx(templates_dir=checkout)
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "pinned SHA-256" in res.error and not record.exists()  # nuclei never launched


def test_url_targets_lose_credentials_query_and_fragment():
    runner = NucleiRunner()
    scope = make_scope()
    target, _ = runner._target_for(Entity.make(EntityType.URL, "https://app.acme.example/login?token=abcdef0123456789abcd#x"), scope)
    assert target == "https://app.acme.example/login"
    refused, reason = runner._target_for(Entity.make(EntityType.URL, "https://admin:admin@app.acme.example/"), scope)
    assert refused is None and "credentials" in reason


# --------------------------------------------------------------------------------------
# run-path - the stub nuclei end to end (FC9/FC10/FC11)
# --------------------------------------------------------------------------------------


def test_happy_path_findings_technologies_and_ledger_trace(stub_path, pinned):
    stdout = (
        _result("jaeger-ui-dashboard", "low", ["misconfig", "discovery"], name="Jaeger UI", extracted=["1.52.0"])
        + _result("tech-detect", "info", ["tech", "discovery"], name="Wappalyzer Technology Detection", matcher="nginx")
        + _result("tech-detect", "info", ["tech", "discovery"], name="Wappalyzer Technology Detection", matcher="jquery")
        + _result("acunetix-panel-detect", "info", ["panel", "discovery"], name="Acunetix Panel - Detect")
        + _result("git-config", "medium", ["exposure"], name="Git Configuration - Detect", extracted=["[core]"])
    )
    _stub(stub_path, stdout=stdout, stderr="[INF] Templates loaded for current scan: 2\n",
          trace=_trace("http/misconfiguration/jaeger-ui-dashboard.yaml", "dns/allowed-dns.yaml"))
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.OK and not res.partial
    # FC10: low+ results are findings reading 'exposure/misconfiguration', never 'vulnerable'
    by_template = {f.data["template_id"]: f for f in res.findings}
    assert set(by_template) == {"jaeger-ui-dashboard", "git-config"}
    assert by_template["jaeger-ui-dashboard"].severity.name == "LOW" and by_template["git-config"].severity.name == "MEDIUM"
    for f in res.findings:
        assert "vulnerab" not in f.title.lower() and f.criterion and ({"exposure", "misconfiguration"} & set(f.tags))
        assert f.data["template_version"] == "v10.5.2" and f.data["matched_url"].startswith("https://")
    assert by_template["jaeger-ui-dashboard"].data["template_sha256"] == pinned["templates"]["jaeger-ui-dashboard"]["sha256"]
    # FC10: info results collapse into one technology count (per technology, not per template)
    summary = res.attributes["exposure_summary"]
    assert summary["status"] == "confirmed" and summary["technologies_detected"] == 3
    assert summary["label"] == "3 technologies detected" and summary["templates_passed"] == 2
    assert any("nginx" in t for t in res.attributes["technologies"])
    # FC9: the audit trail names the pinned templates; the trace is folded into the request ledger
    assert {t["id"] for t in res.raw["templates"]} == {"jaeger-ui-dashboard", "txt-fingerprint"}
    assert res.raw["templates_release"] == "v10.5.2" and not res.raw["off_target_trace"]
    execs = [r for r in ctx.net.request_log if r.method == "EXEC"]
    assert len(execs) == 1 + 2  # run_tool's launch record + one per traced request
    assert all(r.host == IN_SCOPE_IP and r.opsec in ("active", Opsec.ACTIVE) for r in execs)


def test_low_only_results_are_an_observed_exposure_never_empty(stub_path, pinned):
    _stub(stub_path, stdout=_result("jaeger-ui-dashboard", "low", ["misconfig", "discovery"]), trace=_trace("x.yaml"))
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.OK and len(res.findings) == 1
    assert res.attributes["exposure_summary"]["status"] == "confirmed"


def test_technologies_without_findings_is_not_observed(stub_path, pinned):
    _stub(stub_path, stdout=fixture("nuclei_runner/tech_only.jsonl"), trace=_trace("x.yaml"))
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.OK and not res.findings
    assert res.attributes["exposure_summary"]["status"] == "not_observed"


def test_empty_output_is_empty_not_a_crash(stub_path, pinned):
    _stub(stub_path, stdout=fixture("nuclei_runner/empty.jsonl") or "", stderr=fixture("nuclei_runner/no_results.txt"), trace="")
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.EMPTY
    assert res.attributes["exposure_summary"]["status"] == "not_observed"


def test_malformed_output_is_could_not_test_never_empty(stub_path, pinned):
    _stub(stub_path, stdout="<html><body>proxy error</body></html>\nnot-json at all\n", trace="")
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.ERROR
    assert res.attributes["exposure_summary"]["status"] == "could_not_test"


def test_partly_garbled_jsonl_keeps_the_good_lines(stub_path, pinned):
    _stub(stub_path, stdout=fixture("nuclei_runner/error_in_200.jsonl"), trace="")
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.OK  # the good tech line survives; the garbled ones are counted
    assert res.attributes["exposure_summary"]["malformed_lines"] >= 2


def test_a_crash_without_results_is_could_not_test(stub_path, pinned):
    _stub(stub_path, stdout="", stderr="panic: runtime error\n", code=2)
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.ERROR
    assert res.attributes["exposure_summary"]["status"] == "could_not_test"


def test_a_binary_that_cannot_start_its_engine_is_unavailable_package(stub_path, pinned):
    _stub(stub_path, stdout="", stderr=fixture("nuclei_runner/binary_missing.txt"), code=1)
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_proxy_dead_is_could_not_test(stub_path, pinned):
    _stub(stub_path, stdout="", stderr=fixture("nuclei_runner/proxy_dead.txt"), code=1)
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.SKIPPED and res.reason_code == "policy"  # the egress fails closed (A13)
    assert res.attributes["exposure_summary"]["status"] == "could_not_test"


def test_no_templates_loaded_is_an_error(stub_path, pinned):
    _stub(stub_path, stdout="", stderr="[FTL] Program exiting: no templates were found\n", code=1)
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.ERROR


def test_off_target_trace_entries_are_flagged(stub_path, pinned):
    _stub(stub_path, stdout="", trace=fixture("nuclei_runner/trace.jsonl"))
    ctx, ent = active_ctx()
    res = NucleiRunner().run(ent, ctx)
    assert set(res.raw["off_target_trace"]) == {"app.example.com", "ops.example.com"}


def _report_after(killed: str, stdout: str = ""):
    ctx, ent = active_ctx()
    runner = NucleiRunner()
    reviewed = [{"id": "jaeger-ui-dashboard", "file": "/t/j.yaml", "path": "http/j.yaml", "sha256": "0" * 64}]
    result = ToolResult(returncode=-15, stdout=stdout, stderr="", duration=1.0, truncated=False, killed=killed)
    return runner._report(runner.result(ent), ctx, result, [], IN_SCOPE_IP, reviewed, "v10.5.2")


def test_a_kill_keeps_what_was_observed_and_never_reads_as_not_observed():
    res = _report_after("cancelled", _result("jaeger-ui-dashboard", "low", ["misconfig"]))
    assert res.partial and res.stop_reason == "cancelled" and res.findings
    res = _report_after("deadline")
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert res.attributes["exposure_summary"]["status"] == "could_not_test"
    res = _report_after("timeout", _result("git-config", "medium", ["exposure"]))
    assert res.partial and res.stop_reason == "deadline" and res.findings


# --------------------------------------------------------------------------------------
# FC1/FC2 - scope binding: only the in-scope seed is ever handed to run_tool
# --------------------------------------------------------------------------------------


def test_out_of_scope_target_is_refused_before_launch(stub_path, pinned):
    record = _stub(stub_path, stdout=fixture("nuclei_runner/ok.jsonl"))
    out_ip = "93.184.217.66"
    scope = make_scope(targets={"domains": ["acme.example"], "cidrs": ["93.184.216.0/24"]})
    res = run_module(
        NucleiRunner, f"ipv4:{out_ip}",
        settings={"nuclei_runner_templates_dir": str(TEMPLATES_DIR)},
        options=ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=scope),
    )
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert not record.exists()  # nuclei never launched


@pytest.mark.parametrize("scope", [None, "closed"])
def test_no_scope_or_a_closed_window_never_launches(stub_path, pinned, scope):
    record = _stub(stub_path, stdout=fixture("nuclei_runner/ok.jsonl"))
    options = ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF,
                          scope=None if scope is None else make_scope(window_start="2025-01-01T00:00:00Z", window_end="2025-02-01T00:00:00Z"))
    ent = Entity.make(EntityType.IPV4, IN_SCOPE_IP)
    ctx = make_ctx(NucleiRunner, settings={"nuclei_runner_templates_dir": str(TEMPLATES_DIR)}, options=options, entity=ent, case_id="c")
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and not record.exists()


def test_a_private_ip_outside_the_scope_is_never_a_target():
    target, reason = NucleiRunner()._target_for(Entity.make(EntityType.IPV4, "10.0.0.5"), make_scope())
    assert target is None and "private" in reason
