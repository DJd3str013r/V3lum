"""Forbidden-capability lint (P327 static rules, WP09): the CI gate over the shipped tree, one positive and
one negative snippet per rule (tests/fixtures/lint/), pragmas, data files and trees."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import v3lum
from v3lum.core import lint
from v3lum.core.lint import (
    LINT_RULES,
    PEOPLE_SEARCH_DENYLIST,
    LintIssue,
    forbidden_probe,
    lint_data_file,
    lint_module_source,
    lint_tree,
)

FIX = Path(__file__).parent / "fixtures" / "lint"
PACKAGE = Path(v3lum.__file__).resolve().parent
RULE_IDS = [f"LINT-{n:02d}" for n in range(1, 11)]


def blocking(issues: list[LintIssue]) -> list[LintIssue]:
    return [i for i in issues if not i.allowed]


def rules(issues: list[LintIssue]) -> set[str]:
    return {i.rule_id for i in blocking(issues)}


def show(issues: list[LintIssue]) -> list[str]:
    return [str(i) for i in issues]


def fake_package(root: Path, files: dict[str, str]) -> Path:
    """A package-shaped tree (``<root>/pkg/core/module.py`` marks the package root)."""
    pkg = root / "pkg"
    (pkg / "core").mkdir(parents=True)
    (pkg / "core" / "module.py").write_text('"""marker"""\n')
    for rel, text in files.items():
        path = pkg / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return pkg


# ------------------------------------------------------------------ the CI gate (acceptance)
def test_shipped_tree_is_clean():
    """lint_tree over the shipped tree reports nothing that fails the gate (P327 cond 7)."""
    issues = lint_tree("v3lum")
    assert blocking(issues) == [], show(blocking(issues))
    for issue in issues:  # pragma'd exceptions are reported with their reason, never silent
        assert issue.allowed and issue.justification, str(issue)
    assert blocking(lint_tree(PACKAGE)) == []


def test_default_root_is_the_installed_package_outside_the_repository(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert blocking(lint_tree()) == []
    assert lint_tree(tmp_path / "missing")[0].rule_id == "LINT-00"


def test_a_module_importing_socket_or_requests_fails_the_gate(tmp_path):
    pkg = fake_package(tmp_path, {
        "modules/ip_network/raw_banner.py": "import socket\n\n\ndef run(self, entity, ctx):\n    return socket\n",
        "modules/url_web/direct_fetch.py": "import requests\n\n\ndef run(self, entity, ctx):\n    return requests.get(entity.value)\n",
        "modules/url_web/proper.py": "def run(self, entity, ctx):\n    return ctx.http.get_json('https://api.example.com/v1/x')\n",
        "core/http.py": "import requests\nimport socket\n",  # the core HTTP client may use them
    })
    issues = blocking(lint_tree(pkg))
    flagged = {(i.path, i.rule_id) for i in issues}
    assert flagged == {("pkg/modules/ip_network/raw_banner.py", "LINT-01"), ("pkg/modules/url_web/direct_fetch.py", "LINT-01")}, show(issues)


# ------------------------------------------------------------------ rule table
def test_rule_table_and_probe_rules():
    assert list(LINT_RULES) == ["LINT-00", *RULE_IDS]
    assert all(text.strip() and "(" in text for text in LINT_RULES.values())
    assert set(lint.PROBE_RULES) == {"LINT-03", "LINT-04", "LINT-05"}  # the WP05 table keeps its keys
    assert LINT_RULES["LINT-04"] == lint.PROBE_RULES["LINT-04"]
    assert frozenset({"LINT-10"}) == lint.NO_PRAGMA_RULES


# ------------------------------------------------------------------ one positive and one negative snippet per rule
@pytest.mark.parametrize("rule", RULE_IDS)
def test_positive_snippet_fires_its_rule(rule):
    issues = lint_module_source(FIX / f"lint{rule[-2:]}_bad.py.txt")
    assert rule in rules(issues), show(issues)


@pytest.mark.parametrize("rule", RULE_IDS)
def test_negative_snippet_is_clean(rule):
    issues = lint_module_source(FIX / f"lint{rule[-2:]}_good.py.txt")
    assert issues == [], show(issues)


def test_positive_snippets_flag_every_offending_line():
    lines = {(i.rule_id, i.line) for i in lint_module_source(FIX / "lint03_bad.py.txt")}
    assert {("LINT-03", n) for n in (5, 8, 9, 10, 11, 12, 13, 14)} <= lines
    lines = {(i.rule_id, i.line) for i in lint_module_source(FIX / "lint09_bad.py.txt")}
    assert {("LINT-09", n) for n in (3, 6, 12, 13, 14, 15)} <= lines


# ------------------------------------------------------------------ LINT-01 details
def test_lint01_dynamic_imports_raw_tls_and_core_clients():
    src = (
        "import importlib\nimport ssl\nfrom v3lum.core.http import HttpClient\n\n\n"
        "def run(self, entity, ctx):\n"
        "    importlib.import_module('requests')\n"
        "    __import__('socket')\n"
        "    ssl.get_server_certificate((entity.value, 443))\n"
        "    ssl.create_default_context().wrap_socket(None)\n"
        "    return HttpClient()\n"
    )
    found = {(i.line, i.rule_id) for i in lint_module_source("m.py", source=src)}
    assert {(7, "LINT-01"), (8, "LINT-01"), (9, "LINT-01"), (10, "LINT-01"), (11, "LINT-01")} <= found
    ok = "from v3lum.core.http import Blocked, PolicyError\n\n\ndef run(self, entity, ctx):\n    return ctx.net.wrap_tls(entity.value, 443)\n"
    assert lint_module_source("m.py", source=ok) == []


def test_lint01_subprocess_only_inside_core_tools(tmp_path):
    pkg = fake_package(tmp_path, {
        "core/tools.py": "import subprocess\n\n\ndef run(args):\n    return subprocess.run(args, check=False)\n",
        "core/other.py": "import os\nimport subprocess\n\n\ndef x():\n    os.system('id')\n",
        "cli.py": "import webbrowser\n\n\ndef open_report(path):\n    webbrowser.open(path)\n",
        "modules/utility/runner.py": "def run(self, entity, ctx):\n    return ctx.net.run_tool('nuclei', ['-u', entity.value], targets=[entity.value])\n",
    })
    issues = blocking(lint_tree(pkg))
    assert {(i.path, i.line) for i in issues} == {("pkg/core/other.py", 2), ("pkg/core/other.py", 6)}, show(issues)
    assert {i.rule_id for i in issues} == {"LINT-01"}


# ------------------------------------------------------------------ LINT-02 / LINT-08 / LINT-09 data sides
def test_forbidden_optional_dependencies_in_extras_fragments(tmp_path):
    for package, rule in (("cloudscraper", "LINT-02"), ("curl_cffi", "LINT-02"), ("hashcat", "LINT-08"), ("impacket", "LINT-09")):
        path = tmp_path / f"{package}.json"
        path.write_text(json.dumps({"schema": "v3lum.extra/1", "package": package, "pip": f"{package}>=1", "extra": "full",
                                    "licence": "MIT", "justification": "lint test"}))
        assert rules(lint_data_file(path)) == {rule}, package
    ok = tmp_path / "phonenumbers.json"
    ok.write_text(json.dumps({"schema": "v3lum.extra/1", "package": "phonenumbers", "pip": "phonenumbers>=8", "extra": "full",
                              "licence": "Apache-2.0", "justification": "lint test"}))
    assert lint_data_file(ok) == []


def test_offensive_and_cracking_tools_through_run_tool():
    src = "def run(self, entity, ctx):\n    ctx.net.run_tool('hydra', ['-l', 'admin'], targets=[entity.value])\n    return ctx.net.run_tool('hashcat', [], targets=[])\n"
    assert {(i.line, i.rule_id) for i in lint_module_source("m.py", source=src)} == {(2, "LINT-09"), (3, "LINT-08")}


# ------------------------------------------------------------------ LINT-03 (carry-forward: host-level signals)
@pytest.mark.parametrize(
    "url",
    [
        "https://passport.twitch.tv/usernames/{account}",
        "https://www.example.com/join?email={account}",
        "https://emailverification.whoisxmlapi.com/api/v3?emailAddress={account}",
        "https://api.zerobounce.net/v2/validate?email={account}",
        "https://accounts.example.com/users/{account}",
        "https://example.com/newsletter/subscribe?email={account}",
    ],
)
def test_lint03_host_level_and_join_oracles(url):
    assert forbidden_probe(url) == "LINT-03"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.mailcheck.ai/domain/{value}",  # P088: domain classification, not SMTP probing
        "https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration",
        "https://api.github.com/users/{}",
        "https://id.example.com/",
        "https://www.example.com/join-us",
    ],
)
def test_lint03_host_level_signals_keep_public_endpoints(url):
    assert forbidden_probe(url) is None


def test_lint03_detection_only_constants_are_not_probes():
    src = (
        "WALLS = ('/login', '/accounts/login')\nLOGIN = '/signin'\n\n\n"
        "def blocked(url):\n"
        "    if url.endswith('/password_reset') or LOGIN in url:\n"
        "        return True\n"
        "    for wall in WALLS:\n"
        "        if wall in url:\n"
        "            return True\n"
        "    return any(w in url for w in WALLS)\n"
    )
    assert lint_module_source("m.py", source=src) == []
    used = src + "\n\ndef fetch(ctx):\n    return ctx.http.get('https://x.example' + LOGIN)\n"
    assert rules(lint_module_source("m.py", source=used)) == {"LINT-03"}


def test_lint03_error_markers_are_detection_data():
    src = (
        "class M:\n    error_markers = [{'id': 'login_wall', 'final_url_regex': '/accounts/login', 'maps_to': 'blocked',\n"
        "                      'reason_code': 'login_wall', 'reason': 'Example: login wall'}]\n"
    )
    assert lint_module_source("m.py", source=src) == []


# ------------------------------------------------------------------ LINT-04 / LINT-07 on provider fragments
def test_provider_fragments_people_search_hosts_and_credential_keep_paths(tmp_path):
    providers_dir = tmp_path / "providers"
    providers_dir.mkdir()
    fragment = json.loads((PACKAGE / "data" / "providers" / "shodan.json").read_text())
    fragment["id"] = "people_lookup"
    fragment["hosts"] = ["api.people-lookup.example", "api.tudosobretodos.info"]
    first = next(iter(fragment["sources"]))
    fragment["sources"] = {first: {**fragment["sources"][first], "sanitizer": {"keep": ["results[].top_passwords", "results[].name"]}}}
    path = providers_dir / "people_lookup.json"
    path.write_text(json.dumps(fragment))
    found = rules(lint_data_file(path))
    assert {"LINT-04", "LINT-07"} <= found
    broken = providers_dir / "broken.json"
    broken.write_text(json.dumps({"schema": "v3lum.provider/1", "id": "broken"}))
    issues = lint_data_file(broken)
    assert issues and {i.rule_id for i in issues} == {"LINT-00"}  # schema problems through the provider loader


def test_lint07_is_satisfied_by_a_p145_schema():
    src = (
        "from v3lum.core import sanitize\n\nsanitize.register_schema('synthetic.breach', keep=['breaches[].name'])\n\n\n"
        "def run(self, entity, ctx):\n    res = self.result(entity)\n    entry = ctx.http.get_json('https://api.example.com/x')\n"
        "    res.raw = {'password': entry.get('password')}\n    return res\n"
    )
    assert lint_module_source("m.py", source=src) == []
    assert rules(lint_module_source("m.py", source=src.replace("sanitize.register_schema", "print"))) == {"LINT-07"}
    static = "LABELS = {'credential': 'credential line', 'password': 'password line'}\n"
    assert lint_module_source("m.py", source=static) == []  # a static label table produces no credential


def test_lint07_applies_to_source_reading_modules_only():
    body = "\n    def run(self, entity, ctx):\n        kind = identify(entity.value)\n        return {'password_hash': kind}\n"
    offline = "class Ident:\n    name = 'hash_ident'\n    disclosure = 'none'\n    hosts = ()\n" + body
    assert lint_module_source("m.py", source=offline) == []  # no registry source, no schema possible: runtime net
    third = "class Leaks:\n    name = 'leaks'\n    disclosure = 'third_party'\n    sources = ('synthetic.leaks',)\n" + body
    assert rules(lint_module_source("m.py", source=third)) == {"LINT-07"}


def test_socket_address_helpers_are_not_network_use():
    helpers = "import socket\n\n\ndef packed(text):\n    return socket.inet_pton(socket.AF_INET6, text)\n"
    assert lint_module_source("m.py", source=helpers) == []
    assert lint_module_source("m.py", source="from socket import AF_INET, inet_pton\n") == []
    for src in ("import socket\n", helpers + "\n\ndef dial(h):\n    return socket.socket()\n",
                "from socket import create_connection\n", "import importlib\nimportlib.import_module('socket')\n"):
        assert rules(lint_module_source("m.py", source=src)) == {"LINT-01"}, src


def test_dataset_urls_and_repository_files_carry_no_value():
    src = (
        "from v3lum.core.datasets import register_dataset\n\n"
        "LIST = register_dataset('verifier_roles', 'https://raw.githubusercontent.com/example/email-verifier/master/roles.go', ttl=1)\n"
        "LEAKED = register_dataset('dump', 'https://dehashed.com/dumps/latest.zip', ttl=1)\n"
        "DOCS = 'https://github.com/example/email-verifier'\n"
        "SIGNUP = 'https://github.com/signup'\n"
    )
    found = {(i.line, i.rule_id) for i in lint_module_source("m.py", source=src)}
    assert found == {(4, "LINT-04"), (6, "LINT-03")}  # people-search hosts still fail; repo paths and dataset files do not


# ------------------------------------------------------------------ LINT-06 and the method allow-list (WP11 fragments)
def _active_module(method: str = "post") -> str:
    return (
        "from v3lum.core.models import Opsec\n\n\nclass Probe:\n    name = 'synthetic_probe'\n    opsec = Opsec.LIGHT\n\n"
        f"    def run(self, entity, ctx):\n        return ctx.http.{method}('https://' + entity.value + '/api')\n"
    )


def test_lint06_method_allow_list_fragment(tmp_path):
    root = tmp_path / "pkg"
    allow = root / "data" / "policy" / "method_allowlist"
    allow.mkdir(parents=True)
    assert rules(lint_module_source("m.py", source=_active_module(), root=root)) == {"LINT-06"}
    fragment = {"schema": "v3lum.method_allow/1", "module": "synthetic_probe", "methods": {"POST": "read-only GraphQL introspection"},
                "approved_by": "", "decision_ref": ""}
    (allow / "synthetic_probe.json").write_text(json.dumps(fragment))
    assert rules(lint_module_source("m.py", source=_active_module(), root=root)) == {"LINT-06"}  # not approved
    fragment.update(approved_by="legal_dpo + redteam_lead", decision_ref="COUNCIL-2026-11-26-07")
    (allow / "synthetic_probe.json").write_text(json.dumps(fragment))
    assert lint_module_source("m.py", source=_active_module(), root=root) == []
    assert lint_module_source("m.py", source=_active_module("get"), root=root) == []
    issues = lint_data_file(allow / "synthetic_probe.json")
    assert issues == []
    fragment["methods"] = {"DELETE": "cleanup"}
    (allow / "synthetic_probe.json").write_text(json.dumps(fragment))
    assert rules(lint_data_file(allow / "synthetic_probe.json")) == {"LINT-09"}  # writes are never allow-listed


def test_lint06_specs_only_get():
    assert rules(lint_data_file(FIX / "spec_bad.json")) == {"LINT-03", "LINT-04", "LINT-06", "LINT-07"}
    assert lint_data_file(FIX / "spec_good.json") == []


# ------------------------------------------------------------------ LINT-10: no pragma, every profile
def test_lint10_no_pragma_and_every_file_of_the_tree(tmp_path):
    issues = lint_module_source(FIX / "lint10_bad.py.txt")
    assert all(not i.allowed for i in issues)
    assert any("no pragma is accepted for LINT-10" in i.message for i in issues)
    pkg = fake_package(tmp_path, {
        "core/net.py": "import requests\nimport ssl\n\n\ndef get(url):\n    return requests.get(url, verify=False)  # v3lum-lint: allow LINT-10 -- appliance\n",
        "correlations/pack.py": "import urllib3\n\nurllib3.disable_warnings()\n",
        "report/html.py": "import os\n\nos.environ['PYTHONHTTPSVERIFY'] = '0'\n",
        "core/guard.py": "import ssl\n\n\ndef strict(ctx):\n    assert ctx.verify_mode != ssl.CERT_NONE\n",
    })
    issues = blocking(lint_tree(pkg))
    assert {(i.path, i.rule_id) for i in issues} >= {("pkg/core/net.py", "LINT-10"), ("pkg/report/html.py", "LINT-10"),
                                                     ("pkg/correlations/pack.py", "LINT-10")}, show(issues)
    assert not any(i.path == "pkg/core/guard.py" for i in issues)  # a comparison guard is not a disabled check


# ------------------------------------------------------------------ pragmas
def test_pragma_is_reported_never_silent():
    issues = lint_module_source(FIX / "pragma.py.txt")
    allowed = [i for i in issues if i.allowed]
    assert len(allowed) == 1 and allowed[0].line == 2 and allowed[0].rule_id == "LINT-01"
    assert allowed[0].justification == "offline loopback banner fixture reviewed in #42"
    assert "[allowed: offline loopback banner fixture reviewed in #42]" in str(allowed[0])
    missing = blocking(issues)
    assert len(missing) == 1 and missing[0].line == 3 and "justification" in missing[0].message
    assert lint.blocking(issues) == missing


def test_pragma_applies_to_its_own_rule_and_line_only():
    src = "import socket  # v3lum-lint: allow LINT-09 -- wrong rule\n# v3lum-lint: allow LINT-01 -- wrong line\nimport requests\n"
    assert [i.allowed for i in lint_module_source("m.py", source=src)] == [False, False]
    multi = "import socket  # v3lum-lint: allow LINT-02, LINT-01 -- two rules listed\n"
    assert [i.allowed for i in lint_module_source("m.py", source=multi)] == [True]


def test_unparsable_source_falls_back_to_regex_checks():
    issues = lint_module_source("broken.py", source="def broken(:\n    requests.get('x', verify=False)\nimport subprocess\n")
    assert [i.rule_id for i in issues][:1] == ["LINT-00"]
    assert {"LINT-00", "LINT-10", "LINT-01"} <= {i.rule_id for i in issues}


# ------------------------------------------------------------------ data files
def test_username_site_lists():
    wmn = lint_data_file(FIX / "sites_wmn_bad.json")
    assert rules(wmn) == {"LINT-03", "LINT-05"} and all("ProfilePage" not in i.message for i in wmn)
    assert lint_data_file(FIX / "sites_wmn_good.json") == []  # uri_pretty is a display URL, never probed
    maigret = lint_data_file(FIX / "sites_maigret_bad.json")
    assert {i.message.split(" ", 1)[0] for i in maigret} == {"OracleSite", "Twitch"}


def test_pivot_packs_through_links_lint_pack():
    assert rules(lint_data_file(FIX / "pack_bad.json")) == {"LINT-03", "LINT-05"}
    assert lint_data_file(FIX / "pack_good.json") == []


def test_generic_data_files_with_probe_urls(tmp_path):
    path = tmp_path / "checks.json"
    path.write_text(json.dumps({
        "checks": [{"name": "reset", "probe_url": "https://example.com/forgot-password?email={value}"},
                   {"name": "submit", "url": "https://tools.example/api/v1/scan", "method": "POST"},
                   {"name": "fine", "url": "https://tools.example/api/v1/lookup/{value}", "method": "GET"}],
        "keys": {"signup_url": "https://example.com/register"},  # documentation links are not probes
    }))
    assert rules(lint_data_file(path)) == {"LINT-03", "LINT-05"}
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert [i.rule_id for i in lint_data_file(broken)] == ["LINT-00"]
    assert lint_data_file(tmp_path / "notes.txt") == []  # not a data format the lint reads


def test_lint_data_file_takes_parsed_data_and_is_wp12_compatible():
    data = json.loads((FIX / "spec_bad.json").read_text())
    issues = lint_data_file(data)  # a Mapping as the first argument
    assert issues and all(i.path == "<data>" for i in issues)
    assert rules(lint_data_file("specs/x.json", data=data)) == rules(issues)
    for issue in lint_data_file(FIX / "spec_bad.json"):
        assert isinstance(issue.rule_id, str) and issue.message and issue.allowed is False
        assert issue.to_dict()["rule_id"] == issue.rule_id


def test_shipped_data_fragments_are_linted(tmp_path):
    """The tree lint reads every JSON fragment: a forbidden entry in a data directory is caught."""
    pkg = fake_package(tmp_path, {
        "data/pivot_links/pack_bad.json": (FIX / "pack_bad.json").read_text(),
        "data/specs/spec_bad.json": (FIX / "spec_bad.json").read_text(),
        "data/vocab/ok.json": json.dumps({"schema": "v3lum.vocab/1", "attributes": {"x": "y"}}),
    })
    paths = {i.path for i in blocking(lint_tree(pkg))}
    assert paths == {"pkg/data/pivot_links/pack_bad.json", "pkg/data/specs/spec_bad.json"}


def test_plugin_and_spec_directories_are_linted_as_modules(tmp_path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "bad_plugin.py").write_text((FIX / "lint01_bad.py.txt").read_text())
    (plugins / "good_plugin.py").write_text((FIX / "lint01_good.py.txt").read_text())
    (plugins / "spec_bad.json").write_text((FIX / "spec_bad.json").read_text())
    issues = blocking(lint_tree(plugins))
    assert {i.path for i in issues} == {"plugins/bad_plugin.py", "plugins/spec_bad.json"}


# ------------------------------------------------------------------ host tables grow with data fragments
def test_host_tables_grow_with_lint_table_fragments(tmp_path):
    good = {"schema": "v3lum.lint_tables/1", "name": "batch_extra", "sources": ["C0000"], "notes": "test",
            "people_search_hosts": ["people-lookup.example"], "oast_hosts": ["callbacks.example"]}
    (tmp_path / "batch_extra.json").write_text(json.dumps(good))
    (tmp_path / "bad.json").write_text(json.dumps({"schema": "v3lum.lint_tables/1", "name": "bad", "people_search_hosts": ["Not A Host"]}))
    try:
        errors = lint.reload_tables(tmp_path)
        assert errors and all(e.startswith("bad.json") for e in errors) and lint.lint_table_errors() == errors
        assert "people-lookup.example" in lint.PEOPLE_SEARCH_DENYLIST and "callbacks.example" in lint.OAST_HOSTS
        assert forbidden_probe("https://api.people-lookup.example/search?q={value}") == "LINT-04"
        assert PEOPLE_SEARCH_DENYLIST <= lint.PEOPLE_SEARCH_DENYLIST  # seeds kept
        assert rules(lint_data_file(tmp_path / "bad.json")) == {"LINT-00"}
        assert lint_data_file(tmp_path / "batch_extra.json") == []
    finally:
        lint.reload_tables()
    assert "people-lookup.example" not in lint.PEOPLE_SEARCH_DENYLIST


# ------------------------------------------------------------------ review additions (wave 2)
def _found(src: str, **kw) -> set[tuple[int, str]]:
    return {(i.line, i.rule_id) for i in blocking(lint_module_source("m.py", source=src, **kw))}


@pytest.mark.parametrize(
    ("src", "line"),
    [
        ("def run(self, e, ctx):\n    return eval(ctx.setting('expr'))\n", 2),
        ("def run(self, e, ctx):\n    exec('import socket')\n", 2),
        ("import importlib\n\n\ndef run(self, e, ctx):\n    return importlib.import_module(ctx.setting('lib'))\n", 5),
        ("import pickle\n\n\ndef run(self, e, ctx):\n    return pickle.loads(ctx.http.get('https://a.example/x').content)\n", 5),
        ("import yaml\n\n\ndef parse(text):\n    return yaml.load(text)\n", 5),
        ("import webbrowser\n", 1),
        ("import whois\n", 1),
        ("from ipwhois import IPWhois\n", 1),
        ("from multiprocessing.connection import Client\n", 1),
        ("import anyio\n\n\nasync def dial():\n    return await anyio.connect_tcp('a.example', 443)\n", 5),
        ("from invoke import run\n", 1),
    ],
)
def test_lint01_dynamic_code_unsafe_loaders_and_more_clients(src, line):
    assert (line, "LINT-01") in _found(src)


def test_lint01_safe_forms_stay_allowed():
    ok = (
        "import importlib\nimport re\nimport yaml\n\nHELPER = 'v3lum.modules.url_web.url_unwrap'\n\n\n"
        "def parse(text):\n    re.compile(text)\n    importlib.import_module(HELPER)\n"
        "    return yaml.load(text, Loader=yaml.SafeLoader), yaml.safe_load(text)\n"
    )
    assert lint_module_source("m.py", source=ok) == []


def test_lint06_sees_http_aliases_opsec_constants_and_base_classes():
    aliased = (
        "from v3lum.core.models import Opsec\n\n\nclass Probe:\n    name = 'synthetic_probe'\n    opsec = Opsec.LIGHT\n\n"
        "    def run(self, entity, ctx):\n        h = ctx.http\n        return h.post('https://' + entity.value + '/api')\n"
    )
    assert (10, "LINT-06") in _found(aliased)
    constant = (
        "from v3lum.core.models import Opsec\n\nMODE = Opsec.ACTIVE\n\n\nclass Probe:\n    name = 'synthetic_probe'\n    opsec = MODE\n\n"
        "    def run(self, entity, ctx):\n        return ctx.http.post('https://' + entity.value + '/api')\n"
    )
    assert (11, "LINT-06") in _found(constant)
    inherited = (
        "from v3lum.core.models import Opsec\n\n\nclass LightBase:\n    opsec = Opsec.LIGHT\n\n\nclass Probe(LightBase):\n"
        "    name = 'synthetic_probe'\n\n    def run(self, entity, ctx):\n        return ctx.http.post('https://' + entity.value + '/api')\n"
    )
    assert (12, "LINT-06") in _found(inherited)


@pytest.mark.parametrize(
    "src",
    [
        "def f(x):\n    return x.TCPConnector(ssl=False)\n",
        "def f(x):\n    return x.get('https://a.example', verify_ssl=False)\n",
        "def f(x):\n    return x.Elasticsearch('https://a.example', verify_certs=False)\n",
        "def f(x):\n    return x.connect('a.example', insecure=True)\n",
        "import os\nos.environ.setdefault('PYTHONHTTPSVERIFY', '0')\n",
        "import os\nos.environ.update({'CURL_CA_BUNDLE': ''})\n",
    ],
)
def test_lint10_aliases_of_verify_false_in_every_profile(src):
    for profile in ("module", "code", "core"):
        issues = lint_module_source("m.py", source=src + "  # v3lum-lint: allow LINT-10 -- not accepted\n", profile=profile)
        assert "LINT-10" in rules(issues), (profile, src)


def test_lint03_smtp_probing_and_borrowed_session_settings():
    smtp = "def run(self, e, ctx):\n    return ctx.net.send(f'RCPT TO:<{e.value}>')\n"
    assert (2, "LINT-03") in _found(smtp)
    assert (2, "LINT-03") in _found("def run(self, e, ctx):\n    return ctx.net.send(b'VRFY alice\\r\\n')\n")
    prose = "class M:\n    name = 'm'\n    notice = 'MX records only: never SMTP VRFY, EXPN or RCPT TO probing (team rule 2)'\n"
    assert lint_module_source("m.py", source=prose) == []
    setting = "def run(self, e, ctx):\n    return ctx.setting('session_cookie')\n"
    assert (2, "LINT-03") in _found(setting)
    declared = "class M:\n    name = 'm'\n    settings = {'session_id': '', 'timeout_s': 10}\n"
    assert (3, "LINT-03") in _found(declared)
    assert lint_module_source("m.py", source="def run(self, e, ctx):\n    return ctx.setting('session_timeout')\n") == []


@pytest.mark.parametrize(
    "url",
    [
        "https://discord.com/api/v9/unique-username/username-attempt-unauthed",
        "https://login.microsoftonline.com/common/GetCredentialType",
        "https://iforgot.apple.com/password/verify/appleid",
        "https://example.com/recovery/start?email={account}",
        "https://example.com/api/v1/auth/otp/send?phone={account}",
        "https://example.com/api/magic-link?email={account}",
        "https://example.com/api/isEmailRegistered?email={account}",
        "https://api.sendgrid.com/v3/validations/email",
    ],
)
def test_lint03_more_enumeration_oracles(url):
    assert forbidden_probe(url) == "LINT-03"


def test_lint07_finding_data_is_produced_data():
    src = (
        "class Leaks:\n    name = 'leaks'\n    disclosure = 'third_party'\n    sources = ('synthetic.leaks',)\n\n"
        "    def run(self, entity, ctx):\n        res = self.result(entity)\n        row = ctx.http.get_json('https://api.example.com/x')\n"
        "        res.finding('t', 'high', 'd', criterion='c', data={'password': row['password']})\n        return res\n"
    )
    assert (9, "LINT-07") in _found(src)


def test_lint08_run_tool_by_path_or_keyword():
    src = ("def run(self, e, ctx):\n    ctx.net.run_tool('/usr/bin/hashcat', [], targets=[])\n"
           "    return ctx.net.run_tool(name='hydra', args=[], targets=[e.value])\n")
    assert {(2, "LINT-08"), (3, "LINT-09")} <= _found(src)


def test_lint09_jwt_alg_none_forgery():
    assert (1, "LINT-09") in _found("HEADER = '{\"alg\": \"none\", \"typ\": \"JWT\"}'\n")
    assert lint_module_source("m.py", source="def weak(header):\n    return header.get('alg') == 'none'\n") == []


def test_method_allow_list_lookup_ignores_names_that_leave_its_directory(tmp_path):
    root = tmp_path / "pkg"
    (root / "data" / "policy" / "method_allowlist").mkdir(parents=True)
    (tmp_path / "outside.json").write_text(json.dumps({"schema": "v3lum.method_allow/1", "module": "../../../outside",
                                                       "methods": {"POST": "x"}, "approved_by": "me", "decision_ref": "r"}))
    src = ("from v3lum.core.models import Opsec\n\n\nclass M:\n    name = '../../../outside'\n    opsec = Opsec.LIGHT\n\n"
           "    def run(self, e, ctx):\n        return ctx.http.post('https://' + e.value + '/x')\n")
    assert (9, "LINT-06") in _found(src, root=root)


def test_pragma_inside_a_function_body_does_not_cover_its_name():
    src = "def brute_force_login(ctx):\n    x = 1  # v3lum-lint: allow LINT-09 -- unrelated line\n    return x\n"
    assert (1, "LINT-09") in _found(src)


def test_deeply_nested_sources_and_data_never_crash_the_gate(tmp_path):
    deep = "X = " + " + ".join(["'a'"] * 5000) + "\nimport requests\n"
    assert (2, "LINT-01") in _found(deep)  # an iterative pass: no RecursionError, the rest of the file still linted
    chain = "def run(self, e, ctx):\n    return ctx" + ".x()" * 3000 + "\n"
    assert isinstance(lint_module_source("m.py", source=chain), list)
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "nested.json").write_text("[" * 100_000 + "]" * 100_000)
    (plugins / "huge.json").write_text(json.dumps({"sites": [{"uri_check": "https://example.com/signup?u={account}"}],
                                                   "pad": "x" * (lint._MAX_DATA_BYTES + 1)}))
    issues = blocking(lint_tree(plugins))
    assert {(i.path, i.rule_id) for i in issues} == {("plugins/nested.json", "LINT-00"), ("plugins/huge.json", "LINT-00")}


# ------------------------------------------------------------------ robustness
def test_lint_stays_fast_on_large_and_hostile_sources():
    lines = ['"""Generated module."""', "import re", ""]
    for n in range(3000):
        lines.append(f"URL_{n} = 'https://api{n}.example.com/v1/items/' + 'a' * {n % 7}")
        lines.append(f"def f_{n}(ctx, value):\n    return ctx.http.get_json(URL_{n} + value, params={{'q': value}})")
    lines.append("HOSTILE = '" + "/" + "a_" * 20000 + "'")
    lines.append("PAYLOADISH = '" + "../" * 2 + "x" * 50000 + "'")
    source = "\n".join(lines) + "\n"
    start = time.perf_counter()
    issues = lint_module_source("big.py", source=source)
    assert time.perf_counter() - start < 5.0
    assert blocking(issues) == [], show(issues)[:5]


# ------------------------------------------------------------------ contract additions (docs/contract_additions/WP09.md)
def test_contract_additions_names_resolve():
    """Every backticked v3lum.* name of docs/contract_additions/WP09.md is importable."""
    import importlib
    import re

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP09.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?![/\w])", doc)))  # 'v3lum.x/1' is a schema id
    assert "v3lum.core.sanitize.scrub_text" in names and "v3lum.core.lint.lint_tree" in names
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for attr in rest:
            if not hasattr(obj, attr):
                missing.append(dotted)
                break
            obj = getattr(obj, attr)
    assert missing == []
