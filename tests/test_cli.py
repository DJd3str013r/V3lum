"""End-to-end CLI tests (offline: no network is touched)."""

from __future__ import annotations

import json

from v3lum.cli import main


def test_version(capsys):
    assert main(["version"]) == 0
    assert "V3LUM" in capsys.readouterr().out


def test_detect_json(capsys):
    assert main(["detect", "--json", "8.8.8.8", "user:alice"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["detections"][0]["type"] == "ipv4"
    assert data[1]["detections"][0]["type"] == "username"


def test_modules_and_info(capsys):
    assert main(["--no-fx", "modules"]) == 0
    assert "dns_records" in capsys.readouterr().out
    assert main(["modules", "--json"]) == 0
    mods = json.loads(capsys.readouterr().out)
    assert any(m["name"] == "ioc_extract" for m in mods)
    assert main(["info", "dns_records"]) == 0
    assert main(["info", "no_such_module"]) == 1


def test_extract_file(tmp_path, capsys):
    f = tmp_path / "report.txt"
    f.write_text("C2 at hxxp://bad[.]example/gate.php and 203.0.113.9; hash 44d88612fea8a8f36de82e1278abb02f")
    assert main(["extract", str(f), "--json"]) == 0
    items = json.loads(capsys.readouterr().out)
    keys = {f"{i['type']}:{i['value']}" for i in items}
    assert "ipv4:203.0.113.9" in keys and "md5:44d88612fea8a8f36de82e1278abb02f" in keys
    assert main(["extract", str(f), "--defang"]) == 0
    assert "hxxp://bad[.]example" in capsys.readouterr().out


def test_scan_offline_text_blob(capsys):
    blob = "incident notes\nbeacon to 203.0.113.50 and evil-domain.example\nCVE-2024-3400"
    rc = main(["--offline", "scan", blob, "--json", "-M", "ioc_extract", "-f", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    keys = {e["key"] for e in data["entities"]}
    assert "ipv4:203.0.113.50" in keys and "cve:CVE-2024-3400" in keys
    assert data["reports"]["json"].endswith(".json")


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


def test_config_set_show(capsys):
    assert main(["config", "set", "depth", "2"]) == 0
    assert main(["config", "show"]) == 0
    assert "2" in capsys.readouterr().out
    assert main(["config", "set", "nonsense", "1"]) == 1


def test_active_mode_requires_authorization(capsys):
    rc = main(["--offline", "scan", "example.com", "--mode", "active", "--json"])
    assert rc == 1
    assert "authorized" in capsys.readouterr().err


def test_bad_input_type(capsys):
    assert main(["scan", "--type", "ipv4", "not-an-ip", "--json"]) == 1


def test_links_command(capsys):
    assert main(["links", "example.com", "--json"]) == 0
    json.loads(capsys.readouterr().out)


def test_feedback_stats(capsys):
    assert main(["feedback", "--json"]) == 0
    assert "verdicts" in json.loads(capsys.readouterr().out)
