"""Noise lists (AR06 data part): built-in kinds, v3lum.noise/1 fragments, bare-host rule,
legitimate platforms, bundled and runtime warninglists, errors()."""

from __future__ import annotations

import json

import pytest

from v3lum import paths
from v3lum.core import noise
from v3lum.core.datasets import DATASETS, register_dataset
from v3lum.core.entities import Entity


def E(etype: str, value: str) -> Entity:
    return Entity.make(etype, value)


@pytest.fixture(autouse=True)
def _isolate():
    saved_datasets = dict(DATASETS)
    saved_runtime = dict(noise._RUNTIME)
    noise.reload(extra_dirs=())
    yield
    noise.reload(extra_dirs=())
    noise._RUNTIME.clear()
    noise._RUNTIME.update(saved_runtime)
    DATASETS.clear()
    DATASETS.update(saved_datasets)


def fragment_dir(tmp_path, *docs, name="frags"):
    d = tmp_path / name
    d.mkdir()
    for i, doc in enumerate(docs):
        fname = doc.pop("_file", f"f{i}.json") if isinstance(doc, dict) else f"f{i}.json"
        (d / fname).write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    noise.reload(extra_dirs=[d])
    return d


def frag(kind: str, **kw) -> dict:
    doc = {"schema": "v3lum.noise/1", "kind": kind, "source": "test", "licence": "CC0-1.0"}
    doc.update(kw)
    return doc


# --------------------------------------------------------------------------------------
# built-in core and kinds
# --------------------------------------------------------------------------------------


def test_bundled_tree_has_no_errors_and_no_dangling_noise_json():
    assert noise.errors() == []
    from v3lum.core.datasets import DataStore

    assert not DataStore.bundled_exists("noise.json")  # AR06 'ship or remove': the v1 reference is gone


def test_core_json_documents_every_kind():
    doc = noise.kinds_doc()
    assert set(doc) == set(noise.KINDS) | set(noise.COMPUTED_KINDS)
    assert set(noise._CORE) <= set(doc)
    raw = json.loads((paths.Path(noise.__file__).parent.parent / "data" / "noise" / "core.json").read_text())
    assert set(raw["builtin_kinds"]) == set(noise._CORE)


@pytest.mark.parametrize(
    ("etype", "value", "kind"),
    [
        ("domain", "gmail.com", "webmail"),
        ("ipv4", "8.8.8.8", "resolver"),
        ("ipv6", "2606:4700:4700::1111", "resolver"),
        ("domain", "global.fastly.net", "cdn"),
        ("domain", "x.outlook.office365.com", "saas"),
        ("domain", "lh3.googleusercontent.com", "cloud"),
        ("domain", "ns1.domaincontrol.com", "hosting"),
        ("domain", "ns1.sedoparking.com", "parked"),
        ("ipv4", "10.1.2.3", "private"),
        ("ipv6", "::1", "private"),
    ],
)
def test_builtin_kinds(etype, value, kind):
    ent = E(etype, value)
    assert noise.is_noise(ent)
    assert noise.noise_kind(ent) == kind


def test_shared_mail_infrastructure_is_noise():
    """AR06 regression (noise part): Google Workspace MX hosts never link unrelated domains."""
    for host in ("aspmx.l.google.com", "alt1.aspmx.l.google.com", "github-com.mail.protection.outlook.com"):
        assert noise.is_noise(E("domain", host)) and "saas" in noise.noise_kinds(E("domain", host)), host


def test_kind_predicates():
    assert noise.is_cdn(E("domain", "cloudfront.net"))
    assert noise.is_cdn(E("domain", "github.io"))  # hosting counts as cdn-like
    assert not noise.is_cdn(E("domain", "gmail.com"))
    assert noise.is_parked(E("domain", "dns-parking.com"))
    assert not noise.is_sinkhole(E("domain", "gmail.com"))


def test_noise_applies_only_to_infrastructure():
    assert not noise.is_noise(E("email", "someone@gmail.com"))  # an address at gmail.com is a person
    assert not noise.is_noise(E("cidr", "8.8.8.0/24"))
    assert not noise.is_noise(E("sha256", "a" * 64))
    assert noise.is_noise(E("url", "https://www.google.com/"))
    assert noise.is_noise(E("url", "http://8.8.8.8/"))
    assert not noise.is_noise(E("url", "https://www.google.com/search?q=x"))
    assert not noise.is_noise(E("url", "https://www.google.com/?q=x"))
    assert not noise.is_noise(E("url", "https://drive.google.com/file/d/abc/view"))


def test_google_forms_url_with_path_is_not_noise_but_forms_gle_is():
    form = E("url", "https://docs.google.com/forms/d/e/1FAIpQLSe-phish/viewform")
    assert not noise.is_noise(form)
    assert noise.legit_platform(form) == "google_forms"
    assert noise.is_noise(E("url", "https://forms.gle/"))
    assert noise.is_noise(E("domain", "forms.gle"))
    assert not noise.is_noise(E("url", "https://forms.gle/AbCdEf123"))


def test_matching_stops_at_the_registrable_domain():
    # PSL private suffixes make tenant hosts their own registrable domains: they are investigated
    assert not noise.is_noise(E("domain", "my-bucket.s3.eu-west-1.amazonaws.com"))
    assert not noise.is_noise(E("domain", "tenant.azurewebsites.net"))
    assert noise.is_noise(E("domain", "github.io"))
    assert not noise.is_noise(E("domain", "evil.github.io"))  # a user site, not the platform
    assert not noise.is_noise(E("domain", "phish.pages.dev"))
    assert not noise.is_noise(E("domain", "notgmail.com"))  # never string-suffix matching
    assert not noise.is_noise(E("domain", "gmail.com.evil.example"))


def test_is_public_ip():
    assert noise.is_public_ip("8.8.8.8")
    assert not noise.is_public_ip("10.0.0.1")
    assert not noise.is_public_ip("not-an-ip")


# --------------------------------------------------------------------------------------
# legitimate platforms
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "platform"),
    [
        ("https://docs.google.com/forms/d/e/x/viewform", "google_forms"),
        ("https://forms.gle/abc", "google_forms"),
        ("https://sites.google.com/view/evil", "google_sites"),
        ("https://drive.google.com/file/d/1/view", "google_drive"),
        ("https://onedrive.live.com/?cid=1", "onedrive"),
        ("https://1drv.ms/u/s!abc", "onedrive"),
        ("https://evilcorp-my.sharepoint.com/:b:/g/x", "sharepoint"),
        ("https://www.dropbox.com/s/abc/file.pdf", "dropbox"),
        ("https://dropbox.com/s/abc", "dropbox"),
        ("https://evil.github.io/login", "github_pages"),
        ("https://x.pages.dev/", "cloudflare_pages"),
        ("https://x.web.app/", "firebase_hosting"),
        ("https://x.firebaseapp.com/", "firebase_hosting"),
        ("https://x.blogspot.com/2026/11/p.html", "blogger"),
        ("https://x.wixsite.com/site", "wix"),
        ("https://x.notion.site/page", "notion"),
        ("evil.github.io/path", "github_pages"),
    ],
)
def test_legit_platform(url, platform):
    assert noise.legit_platform(url) == platform


@pytest.mark.parametrize(
    "url",
    ["https://docs.google.com/document/d/1/edit", "https://github.io/", "https://sharepoint.com/", "https://example.com/forms", "https://evildropbox.com/s/x", ""],
)
def test_not_a_legit_platform(url):
    assert noise.legit_platform(url) is None


def test_legit_platform_accepts_entities():
    assert noise.legit_platform(E("url", "https://x.github.io/a")) == "github_pages"
    assert noise.legit_platform(E("domain", "forms.gle")) == "google_forms"
    assert noise.legit_platform(E("email", "a@x.github.io")) is None
    assert set(noise.PLATFORM_HOSTS.values()) >= {"google_forms", "sharepoint", "github_pages", "notion"}


# --------------------------------------------------------------------------------------
# fragments
# --------------------------------------------------------------------------------------


def test_fragment_loading_and_kinds(tmp_path):
    fragment_dir(
        tmp_path,
        frag("sinkhole", name="test_sinkholes", domains=["sinkhole.example.org"], ips=["192.0.2.10"], cidrs=["198.51.100.0/24"]),
        frag("benign_scanner", ips=["203.0.113.5"], _file="scanners.json"),
        frag("cdn", domains=["*.cdn.example.net"]),
    )
    assert noise.errors() == []
    names = {lst.name for lst in noise.lists()}
    assert {"test_sinkholes", "scanners", "core_webmail"} <= names
    sink_ip = E("ipv4", "198.51.100.77")
    assert noise.is_sinkhole(sink_ip) and noise.noise_kind(sink_ip) == "sinkhole"
    assert noise.is_sinkhole(E("domain", "a.sinkhole.example.org"))
    assert noise.is_sinkhole(E("ipv4", "192.0.2.10"))
    assert noise.noise_kind(E("ipv4", "203.0.113.5")) == "benign_scanner"
    assert noise.is_cdn(E("domain", "edge7.cdn.example.net"))
    assert not noise.is_noise(E("ipv4", "198.51.101.1"))


def test_sinkhole_takes_precedence(tmp_path):
    fragment_dir(tmp_path, frag("sinkhole", ips=["8.8.4.4"]))
    ent = E("ipv4", "8.8.4.4")
    assert noise.noise_kinds(ent) == {"sinkhole", "resolver"}
    assert noise.noise_kind(ent) == "sinkhole"


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ("{not json", "invalid JSON"),
        ({"schema": "v3lum.noise/2", "kind": "cdn", "source": "s", "licence": "CC0-1.0", "domains": ["a.example"]}, "schema must be"),
        (frag("cdn", licence="", domains=["a.example"]), "'licence' is required"),
        (frag("cdn", licence="GPL-3.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="CC BY-SA 4.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="CC-BY-NC-4.0", domains=["a.example"]), "cannot be bundled"),
        # A6 is an allow-list: spelling variants of share-alike and other non-permissive licences fail too
        (frag("cdn", licence="CC BY SA 4.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="Creative Commons Attribution-ShareAlike 4.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="ODbL-1.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="CC-BY-ND-4.0", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", licence="proprietary", domains=["a.example"]), "only MIT, BSD, Apache-2.0"),
        (frag("cdn", licence="unknown", domains=["a.example"]), "cannot be bundled"),
        (frag("cdn", source="", domains=["a.example"]), "'source' is required"),
        (frag("tracker", domains=["a.example"]), "is not one of"),
        (frag("warninglist", domains=["a.example"]), "must name their list"),
        (frag("cdn", domains=["not a domain", "ok.example"]), "invalid domain"),
        (frag("cdn", ips=["999.1.1.1"], domains=["ok.example"]), "invalid ip"),
        (frag("cdn", cidrs=["10.0.0.0/33"], domains=["ok.example"]), "invalid cidr"),
        (frag("cdn", domains="a.example"), "must be a list"),
        (frag("cdn", domain=["a.example"], ips=["192.0.2.1"]), "unknown keys"),
        (frag("cdn"), "no valid entries"),
        ([1, 2], "JSON object"),
    ],
)
def test_malformed_fragments_are_reported_not_raised(tmp_path, doc, expected):
    fragment_dir(tmp_path, json.dumps(doc) if isinstance(doc, list) else doc)
    errs = noise.errors()
    assert any(expected in e for e in errs), errs
    assert noise.is_noise(E("domain", "gmail.com"))  # the rest keeps working


def test_permissive_licences_are_accepted(tmp_path):
    for i, lic in enumerate(["MIT", "CC0-1.0", "CC-BY-4.0", "Apache-2.0", "BSD-3-Clause", "public domain", "CC0-1.0 (MISP warninglists)", "MIT License"]):
        (tmp_path / f"l{i}.json").write_text(json.dumps(frag("cdn", name=f"lic{i}", licence=lic, domains=[f"c{i}.example"])))
    noise.reload(extra_dirs=[tmp_path])
    assert noise.errors() == []
    assert noise.is_cdn(E("domain", "c5.example")) and noise.is_cdn(E("domain", "c7.example"))


def test_duplicate_list_names(tmp_path):
    fragment_dir(tmp_path, frag("cdn", name="dupe", domains=["a.example"]), frag("cloud", name="dupe", domains=["b.example"]))
    assert any("duplicate list name 'dupe'" in e for e in noise.errors())


# --------------------------------------------------------------------------------------
# warninglists: bundled kind and runtime lists
# --------------------------------------------------------------------------------------


def test_warninglist_fragments_are_named_and_not_noise(tmp_path):
    fragment_dir(tmp_path, frag("warninglist", name="top_sites", domains=["popular.example"], cidrs=["192.0.2.0/28"]))
    assert noise.errors() == []
    assert noise.warninglists(E("domain", "www.popular.example")) == ["top_sites"]
    assert noise.warninglists(E("ipv4", "192.0.2.3")) == ["top_sites"]
    assert not noise.is_noise(E("domain", "popular.example"))
    assert noise.warninglists(E("url", "https://popular.example/phish/login")) == []  # path: investigated
    assert noise.warninglists(E("url", "https://popular.example/")) == ["top_sites"]
    assert noise.warninglists(E("domain", "unrelated.example")) == []


def _dataset(name: str, body: str, **kw) -> None:
    register_dataset(name, f"https://lists.example.test/{name}", **kw)
    (paths.datasets_dir() / name).write_text(body, encoding="utf-8")  # as `v3lum data update` leaves it


def test_runtime_misp_warninglists(tmp_path):
    _dataset("wl_hosts.json", json.dumps({"name": "Known good hosts", "type": "hostname", "list": ["cdn.example", "Assets.Example"]}), expect="json")
    _dataset("wl_cidr.json", json.dumps({"name": "Public DNS", "type": "cidr", "list": ["8.8.8.0/24", "2001:4860:4860::/48"]}), expect="json")
    _dataset("wl_strings.json", json.dumps({"name": "Known URLs", "type": "string", "list": ["https://good.example/login"]}), expect="json")
    _dataset("wl_sub.json", json.dumps({"name": "Substrings", "type": "substring", "list": ["-tracker."]}), expect="json")
    noise.register_list("misp_hosts", dataset="wl_hosts.json")
    noise.register_list("misp_dns", dataset="wl_cidr.json", description="public resolvers")
    noise.register_list("misp_urls", dataset="wl_strings.json")
    noise.register_list("misp_sub", dataset="wl_sub.json")
    assert noise.errors() == []
    assert noise.warninglists(E("domain", "img.cdn.example")) == ["misp_hosts"]
    assert noise.warninglists(E("domain", "assets.example")) == ["misp_hosts"]
    assert noise.warninglists(E("ipv4", "8.8.8.99")) == ["misp_dns"]
    assert noise.warninglists(E("ipv6", "2001:4860:4860::8888")) == ["misp_dns"]
    assert noise.warninglists(E("url", "https://good.example/login")) == ["misp_urls"]
    assert noise.warninglists(E("domain", "ads-tracker.example")) == ["misp_sub"]
    assert noise.warninglists(E("domain", "evil.example")) == []
    assert not noise.is_noise(E("domain", "img.cdn.example"))  # warninglists are not noise


def test_runtime_lines_and_cidrs_lists():
    _dataset("benign_hashes.txt", "# known good\n" + "A" * 64 + "\n", expect="lines")
    _dataset("scanners.txt", "198.51.100.0/24\n203.0.113.9\n", expect="lines")
    noise.register_list("good_hashes", dataset="benign_hashes.txt", fmt="lines")
    noise.register_list("research_scanners", kind="benign_scanner", dataset="scanners.txt", fmt="cidrs")
    assert noise.warninglists(E("sha256", "a" * 64)) == ["good_hashes"]
    assert noise.noise_kind(E("ipv4", "198.51.100.200")) == "benign_scanner"
    assert noise.is_noise(E("ipv4", "203.0.113.9"))
    assert noise.warninglists(E("ipv4", "203.0.113.9")) == []  # a noise kind, not a warninglist


def test_missing_runtime_dataset_is_reported_never_raised():
    register_dataset("wl_missing.json", "https://lists.example.test/wl_missing.json", expect="json")
    noise.register_list("not_downloaded", dataset="wl_missing.json")
    assert noise.warninglists(E("domain", "evil.example")) == []
    assert noise.is_noise(E("domain", "gmail.com"))
    errs = noise.errors()
    assert any("not_downloaded" in e and "run v3lum data update wl_missing.json" in e for e in errs)
    # once the dataset arrives the list applies without a restart
    (paths.datasets_dir() / "wl_missing.json").write_text(json.dumps({"type": "string", "list": ["evil.example"]}))
    assert noise.warninglists(E("domain", "evil.example")) == ["not_downloaded"]
    assert noise.errors() == []


def test_unusable_runtime_dataset_is_reported():
    _dataset("wl_bad.json", json.dumps({"no": "list"}), expect="json")
    _dataset("wl_regex.json", json.dumps({"type": "regex", "list": [".*"]}), expect="json")
    noise.register_list("bad_shape", dataset="wl_bad.json")
    noise.register_list("regex_list", dataset="wl_regex.json")
    assert noise.warninglists(E("domain", "x.example")) == []
    errs = " | ".join(noise.errors())
    assert "bad_shape" in errs and "no 'list'" in errs and "unsupported MISP warninglist type 'regex'" in errs


def test_register_list_validation():
    with pytest.raises(ValueError):
        noise.register_list("Bad Name", dataset="x.json")
    with pytest.raises(ValueError):
        noise.register_list("ok_name", kind="tracker", dataset="x.json")
    with pytest.raises(ValueError):
        noise.register_list("ok_name", dataset="x.json", fmt="yaml")
    with pytest.raises(ValueError):
        noise.register_list("ok_name", dataset="../x.json")
    assert noise.register_list("same", dataset="a.json") == "same"
    assert noise.register_list("same", dataset="a.json") == "same"  # idempotent re-import
    with pytest.raises(ValueError, match="already registered"):
        noise.register_list("same", dataset="b.json")
    assert noise.unregister_list("same") and not noise.unregister_list("same")
