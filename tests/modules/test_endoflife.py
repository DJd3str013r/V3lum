"""endoflife (P187): registered weekly datasets + the offline correlation rule g08_endoflife.

Fixtures in tests/fixtures/endoflife/ (live 2026-11-26 from endoflife.date, minimised): ``product_nginx``,
``product_php``, ``product_log4j``, ``products_index`` (the 68 mapped products of the 490 listed),
``product_not_found.http`` (the 404 HTML page an unknown slug gets) and ``product_schema_drift`` (derived:
'releases' renamed). Graph fixtures of the rule are in tests/fixtures/rules/g08_endoflife/.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.fakes import FakeHttp, graph_fixture, make_runtime, module_fixture
from v3lum.core import correlate
from v3lum.core.correlate import RuleContext
from v3lum.core.datasets import DATASETS, DataStore, dataset_errors
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Severity
from v3lum.modules.vulnerability_cve import endoflife as eol

TODAY = "2026-11-26"
FIXTURES_DIR = "tests/fixtures/rules/g08_endoflife"


def fx(name: str):
    return module_fixture("endoflife", name)


def product(name: str) -> dict:
    return eol.parse_eol_product(fx(f"product_{name}.json"))


# ------------------------------------------------------------------ pinned mapping (cond 1-2)
def test_every_pinned_slug_is_an_endoflife_product():
    index = {p["name"] for p in fx("products_index.json")["result"]}
    assert set(eol.mapped_slugs()) <= index and len(eol.mapped_slugs()) == 68
    mapping = eol.load_mapping()
    assert len(mapping["products"]) == 74 and mapping["cpe_products"]["apache:http_server"] == "apache-http-server"


@pytest.mark.parametrize(("name", "slug"), [
    ("nginx", "nginx"), ("Apache HTTP Server ", "apache-http-server"), ("Joomla!", "joomla"), ("PHP", "php"),
    ("Apache Log4j", "log4j"), ("Microsoft-IIS", None), ("OpenSSH", None), ("ngx", None), ("apache tomcat 9", None),
])
def test_mapping_is_exact_never_fuzzy(name, slug):
    assert eol.eol_slug_for(name) == slug


def test_cpe_mapping():
    assert eol.cpe_slug("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*") == ("nginx", "1.24.0")
    assert eol.cpe_slug("cpe:/a:igor_sysoev:nginx:1.18.0") == ("nginx", "1.18.0")
    assert eol.cpe_slug("cpe:/a:microsoft:internet_information_services:10.0") == (None, "10.0")
    assert eol.cpe_slug("not a cpe") == (None, "")


# ------------------------------------------------------------------ registered datasets (cond 1)
def test_one_weekly_dataset_per_pinned_slug():
    names = [n for n in DATASETS if n.startswith("endoflife.")]
    assert sorted(names) == sorted(eol.DATASET_NAMES) and len(names) == 68
    reg = DATASETS["endoflife.nginx"]
    assert reg["url"] == "https://endoflife.date/api/v1/products/nginx"
    assert reg["ttl"] == 7 * 86400 and reg["terms_class"] == "open" and reg["source"] == "endoflife.products"
    assert reg["licence"].startswith("MIT") and reg["essential"] is True
    assert not [e for e in dataset_errors() if "endoflife" in str(e)]


def test_validator_rejects_html_and_schema_drift(tmp_path):
    assert eol.validate_eol_product(fx("product_nginx.json")) == (True, None)
    html = fx("product_not_found.http.json")["response"]["body"]
    assert eol.validate_eol_product(html)[0] is False
    assert eol.validate_eol_product(fx("product_schema_drift.json"))[0] is False
    assert eol.validate_eol_product({"schema_version": "2.0", "result": {}})[0] is False
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(__import__("json").dumps(fx("product_php.json")))
    bad.write_text(html)
    assert eol.validate_eol_file(good) is True and eol.validate_eol_file(bad) is False
    assert eol.validate_eol_file(tmp_path / "missing.json") is False


def test_data_update_installs_the_copy_and_a_404_page_never_replaces_it():
    http = FakeHttp()
    http.add("GET", "https://endoflife.date/api/v1/products/nginx", json=fx("product_nginx.json"), times=1)
    ex = fx("product_not_found.http.json")["response"]
    http.add("GET", "https://endoflife.date/api/v1/products/nginx", status=404, text=ex["body"])
    rt = make_runtime(http)
    assert rt.data.update("endoflife.nginx").status == "updated"
    copy = eol.local_product("nginx")
    assert copy and copy["slug"] == "nginx" and {r["cycle"] for r in copy["releases"]} >= {"1.24", "1.31"}
    second = rt.data.update("endoflife.nginx")
    assert second.status != "updated"
    assert eol.local_product("nginx")["slug"] == "nginx"  # previous copy kept (AR10)
    assert eol.local_product("php") is None  # never downloaded: nothing, and no request
    assert all("php" not in u for u in http.urls())


# ------------------------------------------------------------------ version parsing per product (cond 2)
@pytest.mark.parametrize(("text", "version", "precision", "distro"), [
    ("nginx/1.18.0 (Ubuntu)", "1.18.0", "patch", "ubuntu"),
    ("PHP/7.4.3-4ubuntu2.24", "7.4.3", "patch", "ubuntu"),
    ("OpenSSL/1.0.2k-fips", "1.0.2k", "patch", None),
    ("Apache/2.4.6 (CentOS)", "2.4.6", "patch", "centos"),
    ("2.4", "2.4", "minor", None),
    ("v3.6.0", "3.6.0", "patch", None),
    ("1.24.0-r7", "1.24.0", "patch", "alpine"),
    ("8.2.20+deb12u1", "8.2.20", "patch", "debian"),
    ("1", "1", "major", None),
])
def test_parse_version_string(text, version, precision, distro):
    info = eol.parse_version_string(text)
    assert (info["version"], info["precision"], info["distro"]) == (version, precision, distro)


def test_parse_version_string_rejects_non_versions():
    assert eol.parse_version_string("") is None and eol.parse_version_string(None) is None
    assert eol.parse_version_string("nginx") is None


@pytest.mark.parametrize(("name", "version", "cycle"), [
    ("log4j", "2.14.1", "2"), ("log4j", "2.12.4", "2.12"), ("log4j", "2.3.2", "2.3"), ("log4j", "1.2.17", "1"),
    ("php", "8.1.27", "8.1"), ("php", "8.10.0", None), ("php", "8.2.20", "8.2"),
    ("nginx", "1.24.0", "1.24"), ("nginx", "1.240.0", None), ("nginx", "1.31.2", "1.31"),
])
def test_release_cycle_matching_per_product(name, version, cycle):
    rel = eol.match_release_cycle(version, product(name)["releases"])
    assert (rel or {}).get("cycle") == cycle


def test_split_server_banner_carries_the_platform_comment():
    parts = eol.split_server_banner("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16")
    assert parts == [("Apache", "2.4.6 (CentOS)"), ("OpenSSL", "1.0.2k-fips (CentOS)"), ("PHP", "5.4.16 (CentOS)")]


# ------------------------------------------------------------------ evaluation (cond 3-5)
def test_explicit_eol_version_on_own_asset_is_medium():
    ev = eol.eol_evaluate(product("nginx"), "1.24.0", "header", TODAY, asset_scope="own")
    assert (ev["finding"], ev["severity"], ev["status"], ev["cycle"]) == (True, "medium", "eol", "1.24")
    assert ev["confidence"] == 0.8 and ev["labels"] == ["version from header"] and "2024-04-23" in ev["reason"]


def test_security_only_cycle_is_low_and_third_party_is_info():
    ev = eol.eol_evaluate(product("php"), "8.2.20", "banner", TODAY, asset_scope="in_scope")
    assert (ev["severity"], ev["status"]) == ("low", "security_only")
    third = eol.eol_evaluate(product("nginx"), "1.24.0", "header", TODAY, asset_scope="third_party")
    assert third["severity"] == "info" and "third-party asset: context" in third["labels"]


def test_inferred_and_major_only_versions_are_info_and_labelled():
    inferred = eol.eol_evaluate(product("nginx"), "1.24.0", "cpe", TODAY, inferred=True)
    assert (inferred["severity"], inferred["confidence"], inferred["labels"]) == ("info", 0.3, ["version-inferred"])
    major = eol.eol_evaluate(product("log4j"), "1", "banner", TODAY)
    assert (major["finding"], major["severity"], major["confidence"]) == (True, "info", 0.4) and "version-inferred" in major["labels"]
    ambiguous = eol.eol_evaluate(product("php"), "8", "banner", TODAY)
    assert ambiguous["finding"] is False and ambiguous["status"] == "ambiguous"


def test_distro_builds_and_supported_cycles_give_no_finding():
    distro = eol.eol_evaluate(product("nginx"), "nginx/1.18.0 (Ubuntu)", "header", TODAY)
    assert distro["finding"] is False and distro["labels"][0].startswith("distro-package (ubuntu)")
    assert eol.eol_evaluate(product("nginx"), "1.31.2", "header", TODAY)["finding"] is False
    assert eol.eol_evaluate(product("nginx"), "garbage", "header", TODAY)["status"] == "no_version"


def test_severity_never_exceeds_medium_without_an_authoritative_version():
    ev = eol.eol_evaluate(product("nginx"), "1.18.0", "header", TODAY, asset_scope="own", authoritative=False)
    assert ev["severity"] == "medium"
    auth = eol.eol_evaluate(product("nginx"), "1.18.0", "header", TODAY, asset_scope="own", authoritative=True)
    assert auth["severity"] == "medium"  # the rule's own ceiling: EOL alone is never HIGH


def test_one_grouped_result_per_asset():
    evals = [
        eol.eol_evaluate(product("nginx"), "1.24.0", "header", TODAY),
        eol.eol_evaluate(product("php"), "8.2.20", "header", TODAY),
        eol.eol_evaluate(product("nginx"), "1.31.2", "header", TODAY),
    ]
    group = eol.eol_group("corp.example", evals)
    assert group["severity"] == "medium" and len(group["components"]) == 2 and group["inferred"] is False
    assert all("version from header" in line for line in group["lines"])
    assert group["attribution"] == "endoflife.date (MIT data)."
    assert eol.eol_group("corp.example", [evals[2]]) is None


def test_components_from_detected_values_prefer_explicit_sources():
    comps = eol.components_from_values([
        ("server", "nginx/1.24.0"),
        ("services", [{"port": 443, "product": "nginx", "version": "1.24.0"}, {"product": "OpenSSH", "version": "8.9p1"}]),
        ("technologies", [{"name": "WordPress", "version": "6.0", "source": "meta_generator"}, "PHP 8.1.2", {"name": "jQuery", "version": "3.5.1"}]),
        ("cpes", ["cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", "cpe:/a:php:php:8.1.2"]),
    ])
    by = {(c["slug"], c["version"]): c for c in comps}
    assert by[("nginx", "1.24.0")]["source"] == "header" and by[("nginx", "1.24.0")]["inferred"] is False
    assert by[("wordpress", "6.0")]["source"] == "meta_generator" and by[("wordpress", "6.0")]["inferred"] is False
    assert by[("php", "8.1.2")]["inferred"] is True and by[("jquery", "3.5.1")]["inferred"] is True
    assert not any(c["slug"] == "openssh" for c in comps)  # unmapped: skipped


# ------------------------------------------------------------------ the rule (cond 1, 5)
def test_rule_fixture_details_own_asset():
    graph, results, rctx = graph_fixture(f"{FIXTURES_DIR}/positive_own_asset_header.json")
    corrs = correlate.run_rules(graph, results, only={"g08_endoflife"}, rctx=rctx)
    assert len(corrs) == 1
    corr = corrs[0]
    assert corr.severity is Severity.MEDIUM and "end_of_life" in corr.tags and "context_only" not in corr.tags
    assert any("nginx 1.24.0" in line and "version from header" in line for line in corr.evidence)
    assert any("PHP 8.2.20" in line and "security fixes only" in line for line in corr.evidence)
    assert "endoflife.date (MIT data)" in corr.description and corr.references == ["https://endoflife.date/"]


def test_rule_reads_the_local_dataset_copy_without_any_request():
    path = DataStore(None).path("endoflife.nginx")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(__import__("json").dumps(fx("product_nginx.json")), encoding="utf-8")
    graph = Graph()
    graph.add_node(Entity.make(T.DOMAIN, "corp.example"), depth=0, seed=True)
    graph.add_attributes(Entity.make(T.DOMAIN, "corp.example"), {"server": "nginx/1.18.0"}, "hostio")
    rctx = RuleContext(now=datetime(2026, 11, 26, 12, tzinfo=timezone.utc))
    corrs = correlate.run_rules(graph, [], only={"g08_endoflife"}, rctx=rctx)
    assert len(corrs) == 1 and corrs[0].severity is Severity.INFO  # no org profile: third-party context
    assert "context_only" in corrs[0].tags
