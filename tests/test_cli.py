"""End-to-end CLI tests (offline: no network is touched).

Wave 3 (WP13): scans default to TLP:AMBER (setting tlp), `v3lum run` defaults to the configured mode
(passive) and never escalates, doctor/keys/cases/data/links come from the command registry
(``v3lum.commands``), `config show` lists every setting of SETTINGS_META and `extract` defangs by
default. The policy refusals of every path are in tests/test_cli_policy.py.
"""

from __future__ import annotations

import json
import os

import pytest

from v3lum.cli import build_parser, main


@pytest.fixture(autouse=True)
def _restore_umask():
    """main() sets the process umask to 0o077 (AR03): restore it for the rest of the session."""
    old = os.umask(0o022)
    os.umask(old)
    yield
    os.umask(old)


def test_version(capsys):
    assert main(["version"]) == 0
    assert "V3LUM" in capsys.readouterr().out


def test_detect_json(capsys):
    assert main(["detect", "--json", "8.8.8.8", "user:alice"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["detections"][0]["type"] == "ipv4"
    assert data[1]["detections"][0]["type"] == "username"


def test_detect_scrubs_a_pasted_combo(capsys):
    assert main(["detect", "--json", "ana@example.com:Hunter2Secret!"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["input"] == "ana@example.com" and data[0]["detections"][0]["type"] == "email"
    assert "Hunter2Secret" not in out


def test_modules_and_info(capsys):
    assert main(["--no-fx", "modules"]) == 0
    out = capsys.readouterr().out
    assert "dns_records" in out and "default set" in out
    assert main(["modules", "--json"]) == 0
    mods = json.loads(capsys.readouterr().out)
    by_name = {m["name"]: m for m in mods}
    assert "ioc_extract" in by_name
    assert by_name["ioc_extract"]["default_set"]["member"] is True
    # Shodan InternetDB is noncommercial: off under the shipped corporate profile (A1)
    assert by_name["shodan_internetdb"]["default_set"] == {"member": False, "reason_code": "licence", "reason": by_name["shodan_internetdb"]["default_set"]["reason"]}
    assert main(["info", "dns_records"]) == 0
    info = capsys.readouterr().out
    assert "disclosure" in info and "default set" in info and "policy" in info and "POL-" in info
    assert main(["info", "shodan_internetdb"]) == 0
    info = capsys.readouterr().out
    assert "noncommercial" in info and "licence" in info
    assert main(["info", "no_such_module"]) == 1


def test_extract_file_defangs_by_default(tmp_path, capsys):
    f = tmp_path / "report.txt"
    f.write_text("C2 at hxxp://bad[.]example/gate.php and 203.0.113.9; hash 44d88612fea8a8f36de82e1278abb02f")
    assert main(["extract", str(f), "--json"]) == 0
    items = json.loads(capsys.readouterr().out)
    keys = {f"{i['type']}:{i['value']}" for i in items}
    assert "ipv4:203.0.113.9" in keys and "md5:44d88612fea8a8f36de82e1278abb02f" in keys
    assert main(["extract", str(f), "--defang"]) == 0
    assert "hxxp://bad[.]example" in capsys.readouterr().out
    assert main(["extract", str(f)]) == 0  # P172 cond 11: defanged by default in the terminal
    out = capsys.readouterr().out
    assert "hxxp://bad[.]example" in out and "203[.]0[.]113[.]9" in out
    assert main(["extract", str(f), "--no-defang"]) == 0
    out = capsys.readouterr().out
    assert "http://bad.example/gate.php" in out and "203.0.113.9" in out


def test_extract_scrubs_credentials(tmp_path, capsys):
    f = tmp_path / "dump.txt"
    f.write_text("leak: ana@example.com:Hunter2Secret!\nC2 203.0.113.9\n")
    assert main(["extract", str(f), "--json"]) == 0
    captured = capsys.readouterr()
    assert "Hunter2Secret" not in captured.out
    assert "sensitive data in pasted text" in captured.err


def test_scan_offline_text_blob(capsys):
    blob = "incident notes\nbeacon to 203.0.113.50 and evil-domain.example\nCVE-2024-3400"
    rc = main(["--offline", "scan", blob, "--json", "-M", "ioc_extract", "-f", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    keys = {e["key"] for e in data["entities"]}
    assert "ipv4:203.0.113.50" in keys and "cve:CVE-2024-3400" in keys
    assert data["reports"]["json"].endswith(".json")


def test_scan_defaults_to_tlp_amber_and_accepts_amber_strict(capsys):
    assert main(["--offline", "scan", "203.0.113.7", "--json", "-M", "ioc_extract", "-f", ""]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tlp"] == "amber" and data["options"]["tlp"] == "amber"
    assert data["options"]["seed_tlp"] == {"ipv4:203.0.113.7": "amber"}
    assert main(["--offline", "scan", "203.0.113.7", "--json", "-M", "ioc_extract", "-f", "", "--tlp", "amber+strict"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tlp"] == "amber+strict"
    assert main(["config", "set", "tlp", "red"]) == 0
    capsys.readouterr()
    assert main(["--offline", "scan", "203.0.113.7", "--json", "-M", "ioc_extract", "-f", ""]) == 0
    assert json.loads(capsys.readouterr().out)["tlp"] == "red"  # the setting is the default


def test_scan_flags_reach_the_options(capsys):
    rc = main([
        "--offline", "scan", "203.0.113.8", "--json", "-f", "", "-M", "ioc_extract", "--preset", "deep", "--legal-basis", "legitimate_interest",
        "--purpose", "incident 42", "--ticket", "INC-42", "--breach-scope", "all", "--allow-unknown", "--egress-override", "lab egress",
        "--show-personal", "--no-defang", "--confirm-url", "https://a.example.test/t/0123456789abcdef0123", "--incident-victim",
    ])
    assert rc == 0
    opts = json.loads(capsys.readouterr().out)["options"]
    assert opts["preset"] == "deep" and opts["legal_basis"] == "legitimate_interest"
    assert opts["purpose"] == "incident 42" and opts["ticket"] == "INC-42" and opts["breach_scope"] == "all"
    assert opts["allow_unknown"] is True and opts["egress_override"] == "lab egress"
    assert opts["show_personal"] is True and opts["no_defang"] is True
    assert len(opts["confirmed_urls"]) == 1 and len(opts["confirmed_urls"][0]) == 64  # recorded by SHA-256 only
    assert opts["subject_roles"] == {"ipv4:203.0.113.8": "incident_victim"}


def test_default_purpose_applies_to_ioc_only_scans(capsys):
    for key, value in (("default_purpose", "SOC triage"), ("default_ticket", "SOC-1"), ("default_legal_basis", "legitimate_interest")):
        assert main(["config", "set", key, value]) == 0
    capsys.readouterr()
    assert main(["--offline", "scan", "203.0.113.9", "--json", "-M", "ioc_extract", "-f", ""]) == 0
    opts = json.loads(capsys.readouterr().out)["options"]
    assert (opts["purpose"], opts["ticket"], opts["legal_basis"]) == ("SOC triage", "SOC-1", "legitimate_interest")
    # a personal seed never takes the defaults: it needs an explicit purpose (AR16)
    assert main(["--offline", "scan", "ana@example.com", "--json", "-M", "email_basics", "-f", ""]) == 1
    assert "--purpose" in capsys.readouterr().err


def test_all_modules_is_preset_deep(capsys):
    assert main(["--offline", "scan", "203.0.113.10", "--json", "-f", "", "-M", "ioc_extract", "--all-modules"]) == 0
    assert json.loads(capsys.readouterr().out)["options"]["preset"] == "deep"


def test_egress_override_needs_a_reason(capsys):
    assert main(["--offline", "scan", "203.0.113.11", "--json", "-f", "", "--egress-override", "  "]) == 1
    assert "needs a reason" in capsys.readouterr().err
    # a given reason reaches the options (case audit overrides and the report header, P376 cond 8)
    assert main(["--offline", "scan", "203.0.113.11", "--json", "-f", "", "-M", "ioc_extract", "--egress-override", "lab VPN"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["options"]["egress_override"] == "lab VPN"
    assert "egress override: lab VPN" in out.err  # notices go to stderr in --json mode


def test_empty_authorized_reference_is_refused(capsys):
    for mode in ("passive", "active"):
        assert main(["--offline", "scan", "203.0.113.12", "--json", "-f", "", "--mode", mode, "--authorized", " "]) == 1
        assert "--authorized needs a non-empty authorization reference" in capsys.readouterr().err
    assert main(["--offline", "run", "ioc_extract", "203.0.113.12", "--authorized", ""]) == 1
    assert "non-empty" in capsys.readouterr().err


def test_cases_list_show_report(tmp_path, capsys):
    main(["--offline", "scan", "a\nb 203.0.113.1", "--json", "-M", "ioc_extract", "-f", ""])
    capsys.readouterr()
    assert main(["cases", "list"]) == 0
    assert main(["cases", "show", "last"]) == 0
    assert main(["cases", "report", "last", "-f", "md,stix", "-o", str(tmp_path)]) == 0
    assert any(p.suffix == ".md" for p in tmp_path.iterdir())


def test_keys_set_list_unset(capsys):
    assert main(["keys", "set", "shodan", "abcdef123456"]) == 0
    assert main(["keys", "list"]) == 0
    out = capsys.readouterr().out
    assert "abc******456" in out or "abc" in out
    assert "abcdef123456" not in out
    assert main(["keys", "unset", "shodan"]) == 0


def test_config_set_show_lists_every_setting(capsys):
    assert main(["config", "set", "depth", "2"]) == 0
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "2" in out
    assert "tlp" in out and "default TLP of scans" in out  # descriptions from SETTINGS_META
    assert "retention_days" in out and "default_purpose" in out
    assert main(["config", "set", "nonsense", "1"]) == 1
    assert main(["config", "set", "tpl", "red"]) == 1
    assert "tlp" in capsys.readouterr().err  # the hint suggests close setting names


def test_config_never_prints_a_proxy_password(capsys):
    """AR01: `config set` / `config show` print setting values through the central redactor."""
    assert main(["config", "set", "proxy", "http://bob:S3cretPw@proxy.example:3128"]) == 0
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "S3cretPw" not in out and "proxy.example:3128" in out
    assert main(["config", "set", "proxy", ""]) == 0


def test_tlp_and_mode_flags_are_case_insensitive():
    args = build_parser().parse_args(["scan", "example.com", "--tlp", "RED", "--mode", "Light"])
    assert args.tlp == "red" and args.mode == "light"


def test_config_show_lists_module_settings(capsys, clean_registry):
    from v3lum.config import SettingSpec, register_settings

    register_settings("cli_test_module", {"cli_test_depth": SettingSpec(3, "synthetic module setting")})
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "module cli_test_module" in out and "cli_test_depth" in out and "synthetic module setting" in out


def test_cache_stats_shows_the_oldest_entry(capsys):
    assert main(["cache", "stats"]) == 0
    out = capsys.readouterr().out
    assert "oldest entry" in out and "responses" in out


def test_active_mode_requires_authorization(capsys):
    rc = main(["--offline", "scan", "example.com", "--mode", "active", "--json"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "authorized" in err and "--scope" in err


def test_bare_authorized_flag_is_gone():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "example.com", "--mode", "active", "--authorized"])


def test_run_defaults_to_the_configured_mode(capsys):
    args = build_parser().parse_args(["run", "dns_records", "example.com"])
    assert args.mode is None  # resolved from setting mode (passive) by the app, never 'light'
    assert main(["--offline", "run", "ioc_extract", "text_blob:beacon 203.0.113.4", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["module"] == "ioc_extract" and out["status"] == "ok"
    assert any(p["entity"] == "ipv4:203.0.113.4" for p in out["pivots"])


def test_bad_input_type(capsys):
    assert main(["scan", "--type", "ipv4", "not-an-ip", "--json"]) == 1


def test_links_command(capsys):
    assert main(["links", "example.com", "--json"]) == 0
    json.loads(capsys.readouterr().out)


def test_feedback_stats(capsys):
    assert main(["feedback", "--json"]) == 0
    assert "verdicts" in json.loads(capsys.readouterr().out)


def test_registered_commands_are_in_the_parser():
    from v3lum.commands import load_commands

    parser = build_parser()
    names = set(load_commands())
    sub = next(a for a in parser._actions if a.dest == "command")
    assert names <= set(sub.choices)
    for inline in ("scan", "run", "detect", "modules", "info", "extract", "feedback", "cache", "config", "version", "shell"):
        assert inline in sub.choices
