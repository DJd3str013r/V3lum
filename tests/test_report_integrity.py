"""Report integrity (P336, P311 cond 5/8, AR03, AR13): no external loads, neutralised links,
defanged hostile URLs, a CSP whose script hash matches the embedded JS, sidecar hashes that match
the file and the case DB, owner-only files, and a recording failure that never fails the write."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from v3lum.core.store import Store
from v3lum.report import SIDECAR_SUFFIX, write_reports
from v3lum.report import html as H
from v3lum.report import markdown as M
from v3lum.report import pivot_page as P
from v3lum.report import summary as S

CASE_ID = "20261126-111500-cd34"
HOSTILE_URL = "https://evil-login.example/secure/login.php"
HOSTILE_HOST = "evil-login.example"


def hostile_case(tlp: str = "amber", **over: Any) -> dict[str, Any]:
    """A phishing URL seed, tagged phishing, with every kind of dangerous link the renderers must neutralise."""
    seed = f"url:{HOSTILE_URL}"
    case: dict[str, Any] = {
        "schema": "v3lum.case/2", "tool": {"version": "2.0.0"}, "case_id": CASE_ID, "created": "2026-11-26T11:15:00+00:00", "tlp": tlp,
        "inputs": [{"type": "url", "value": HOSTILE_URL, "reason": "reported by a user"}],
        "seeds": [seed],
        "options": {"mode": "passive"},
        "summary": {"risk_score": 80, "risk_level": "critical"},
        "risk": {"score": 80, "level": "critical", "entities": {seed: {"score": 80, "level": "critical"}}},
        "entities": [
            {"key": seed, "type": "url", "value": HOSTILE_URL, "seed": True, "depth": 0, "tags": ["phishing"],
             "attributes": {"title": [{"value": "<script>alert(document.cookie)</script> Login", "source": "t_fetch"}],
                            "links": [{"value": {"url": "javascript:alert(1)", "name": "x"}, "source": "t_fetch"}]}},
            {"key": f"domain:{HOSTILE_HOST}", "type": "domain", "value": HOSTILE_HOST, "depth": 1, "tags": ["phishing"], "attributes": {}},
        ],
        "edges": [{"src": seed, "dst": f"domain:{HOSTILE_HOST}", "relation": "hosted_on", "module": "t_fetch"}],
        "findings": [{
            "id": "f-kit", "title": f"Phishing kit at {HOSTILE_URL} <img src=x onerror=alert(1)>", "severity": "critical", "entity": seed,
            "module": "t_fetch", "confidence_label": "confirmed", "criterion": "kit signature [x](javascript:alert(1))", "tags": ["phishing", "malicious"],
            "references": ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox(1)", "file:///etc/passwd",
                           f"https://{HOSTILE_HOST}/kit.zip", "https://attack.mitre.org/techniques/T1566/002/", "https://unlisted-docs.example/x"],
            "data": {"note": "see https://evil-login.example/admin and www.evil-login.example"},
        }],
        "correlations": [],
        "modules": [{"module": "t_fetch", "entity": seed, "status": "ok", "hosts": {}}],
        "coverage": {"t_fetch": {"status": "ok", "runs": 1}},
        "links": {seed: [
            {"label": "Template on a third party", "url": "https://www.example-intel.org/url/check?q=x", "host": "www.example-intel.org",
             "ref": "t_pack:check", "category": "reputation", "verified": True},
            {"label": "Template touching the target", "url": f"https://{HOSTILE_HOST}/", "host": HOSTILE_HOST, "ref": "t_pack:open",
             "category": "other", "touches_target": True},
            {"label": "Fetch-live service", "url": "https://screenshots.example.net/shot?u=evil-login.example", "host": "screenshots.example.net",
             "ref": "t_pack:shot", "category": "history", "touches_target": True},
            {"label": "Module link", "url": "https://www.example-intel.org/host/evil-login.example"},
            {"label": "js", "url": "javascript:alert(1)"},
            {"label": "data", "url": "data:text/html,<script>alert(1)</script>"},
            {"label": "Personal pivot", "url": "https://people.example.org/q?x=1", "host": "people.example.org", "ref": "t_pack:people",
             "category": "social", "privacy": True},
        ]},
        "timeline": [], "notes": [], "meta": {}, "answered": {}, "skips": {},
    }
    case.update(over)
    return case


def hrefs(html: str) -> list[str]:
    return re.findall(r'href="([^"]*)"', html)


# ======================================================================================
# self-contained, no external loads
# ======================================================================================


@pytest.mark.parametrize("render", [H.render, P.render])
@pytest.mark.parametrize("tlp", ["clear", "amber", "red"])
def test_no_external_loads(render, tlp):
    html = render(hostile_case(tlp))
    tags = re.findall(r"<[A-Za-z][^>]*>", html)  # real tags only (escaped module text is &lt;...)
    for tag in tags:
        assert not re.search(r"\s(src|srcset|data|poster|background|action|formaction)\s*=", tag, re.I), tag
        assert not re.search(r"url\s*\(", tag, re.I), tag
        assert not re.match(r"<(link|iframe|img|object|embed|base|frame|audio|video|source|form)\b", tag, re.I), tag
    css = "".join(re.findall(r"<style>(.*?)</style>", html, re.S))
    assert css and not re.search(r"url\s*\(", css, re.I) and "@import" not in css and "@font-face" not in css
    assert html.count("<script>") == 1 and len(re.findall(r"<script\b", html)) == 1  # the one bundled script, inline
    for href in hrefs(html):  # anchors are navigations only, never loads, and always http(s)
        assert href.startswith("https://"), href
    for anchor in re.findall(r"<a [^>]*>", html):
        assert 'rel="noreferrer noopener"' in anchor
    assert '<meta name="referrer" content="no-referrer">' in html


def test_csp_script_hash_matches_the_embedded_js():
    for html in (H.render(hostile_case()), P.render(hostile_case())):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1).replace("&#x27;", "'")
        assert csp.startswith("default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'sha256-")
        assert "unsafe-inline' script" not in csp and "script-src 'unsafe-inline'" not in csp and "unsafe-eval" not in csp
        script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
        assert f"script-src 'sha256-{digest}'" in csp
        assert H.csp_hash(script) == f"sha256-{digest}" == H.csp_hash()
        assert html.index("Content-Security-Policy") < html.index("<style>") < html.index("<script>")


def test_footer_hash_covers_the_content_above_it():
    for text in (H.render(hostile_case()), M.render(hostile_case())):
        content, _, tail = text.partition(S.CONTENT_END_MARKER)
        assert tail and "covers" not in content[-10:]
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert digest in tail and "content above this note" in tail


# ======================================================================================
# neutralised links (AR13, P336 cond 2-3, P311 cond 5/8)
# ======================================================================================


@pytest.mark.parametrize("tlp", ["clear", "amber"])
def test_javascript_and_data_links_are_neutralised(tlp):
    case = hostile_case(tlp)
    html, md, page = H.render(case), M.render(case), P.render(case)
    for text in (html, page):
        for href in hrefs(text):
            assert not re.match(r"(?i)\s*(javascript|data|vbscript|file):", href)
        assert "<script>alert" not in text and "<img" not in text
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt; Login" in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert not re.search(r"(?<!\\)\]\(\s*<?\s*(javascript|data|vbscript|file):", md, re.I)  # no unescaped link to them
    assert "<script>" not in md and "\\<script\\>alert(document.cookie)" in md  # escaped, never raw HTML
    assert "[x](javascript" not in md and "\\[x\\](javascript" in md


@pytest.mark.parametrize("tlp", ["clear", "amber", "red"])
def test_phishing_url_fixture_is_defanged_and_never_clickable(tlp):
    case = hostile_case(tlp)
    html, md, page = H.render(case), M.render(case), P.render(case)
    for text in (html, md, page):
        assert HOSTILE_URL not in text and f"https://{HOSTILE_HOST}" not in text and "http://evil-login" not in text
        assert "evil-login[.]example" in text or text is page
    for text in (html, page):
        assert not [h for h in hrefs(text) if HOSTILE_HOST in h], "no clickable link to the investigated/hostile host"
    assert not re.search(r"\]\(<?https?://[^)>]*evil-login", md)
    assert "hxxps://evil-login[.]example/secure/login.php" in html
    assert "hxxps://evil-login[.]example/admin" in html and "www[.]evil-login" in html  # URLs inside module text defanged


def test_pivot_links_follow_the_tlp_rules():
    clear = H.render(hostile_case("clear"))
    assert "https://www.example-intel.org/url/check?q=x" in hrefs(clear)  # template at CLEAR: clickable
    assert "https://www.example-intel.org/host/evil-login.example" not in hrefs(clear)  # module link: not a template
    assert "https://attack.mitre.org/techniques/T1566/002/" in hrefs(clear)  # allow-listed reference host
    assert "https://unlisted-docs.example/x" not in hrefs(clear)  # other reference hosts stay text
    amber = H.render(hostile_case("amber"))
    pivots = re.search(r'<section id="pivots">(.*?)</section>', amber, re.S).group(1)
    assert hrefs(pivots) == [] and "opening sends" in pivots and "www.example-intel.org" in pivots
    assert "hxxps://www[.]example-intel[.]org/url/check?q=x" in pivots
    red = H.render(hostile_case("red"))
    assert "example-intel" not in red.split('<section id="pivots">', 1)[-1].split("</section>", 1)[0] or 'id="pivots"' not in red
    assert "omitted at TLP:RED" in red
    md_red = M.render(hostile_case("red"))
    assert "Template on a third party" not in md_red and "omitted at TLP:RED" in md_red


def test_touches_target_links_defanged_and_collapsed_for_hostile_entities():
    html = H.render(hostile_case("clear"))
    pivots = re.search(r'<section id="pivots">(.*?)</section>', html, re.S).group(1)
    collapsed = "".join(re.findall(r"target-contact link\(s\) of a hostile entity \(expand to show, defanged\)</summary>(.*?)</details>", pivots, re.S))
    assert "Template touching the target" in collapsed and "Fetch-live service" in collapsed
    assert "hxxps://screenshots[.]example[.]net" in collapsed and "https://screenshots" not in " ".join(hrefs(html))
    md = M.render(hostile_case("clear"))
    assert "Template touching the target" not in md and "target-contact link(s) of hostile entities omitted" in md
    plan = S.pivot_plan(hostile_case("clear"), full=False)
    assert plan.hidden_hostile == 2 and plan.hidden_privacy == 1 and plan.dropped == 2


def test_privacy_links_only_with_show_personal():
    assert "Personal pivot" not in H.render(hostile_case("clear"))
    assert "Personal pivot" in H.render(hostile_case("clear"), show_personal=True)


def test_duplicate_manual_and_pack_links_are_merged():
    items = S.merged_links([
        {"label": "VT", "url": "https://www.virustotal.com/gui/domain/x.example", "ref": "p:vt", "host": "www.virustotal.com", "verified": True},
        {"label": "VT", "url": "https://www.virustotal.com/gui/domain/x.example", "manual": True, "note": "automation skipped: licence"},
    ])
    assert len(items) == 1 and items[0]["manual"] and items[0]["ref"] == "p:vt" and items[0]["note"] == "automation skipped: licence"


def test_attribute_values_never_become_links():
    html = H.render(hostile_case("clear"))
    entities = re.search(r'<section id="entities">(.*?)</section>', html, re.S).group(1)
    assert "<a " not in entities and "javascript:alert(1)" in entities  # shown as text only


# ======================================================================================
# files: 0600, sidecars, DB rows, recording failures (AR03, P336 cond 4, P324 cond 6)
# ======================================================================================


def mode(path: str | Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_reports_written_0600_with_matching_sidecars_and_db_rows(tmp_path):
    out = tmp_path / "out"
    written = write_reports(hostile_case(), ["html", "md", "json", "stix", "pivots"], out)
    assert "_errors" not in written and set(written) == {"html", "md", "json", "stix", "pivots"}
    with Store() as store:
        recorded = {os.path.realpath(p): h for p, h in store.report_hashes(CASE_ID).items()}
        paths = {os.path.realpath(p) for p in store.report_paths(CASE_ID)}
    for fmt, path in written.items():
        data = Path(path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        sidecar = Path(path + SIDECAR_SUFFIX)
        assert mode(path) == 0o600 and mode(sidecar) == 0o600, fmt
        assert sidecar.read_text(encoding="utf-8") == f"{digest}  {Path(path).name}\n"
        assert recorded[os.path.realpath(path)] == digest
        assert os.path.realpath(path) in paths and os.path.realpath(sidecar) in paths  # the purge removes both
        assert CASE_ID in Path(path).name
    assert mode(out) == 0o700


def test_cases_verify_detects_an_edited_report(tmp_path):
    from v3lum.core.audit import verify_case

    with Store() as store:
        store.save_case(hostile_case())
    written = write_reports(hostile_case(), ["md"], tmp_path)
    with Store() as store:
        assert not [p for p in verify_case(store, CASE_ID).problems if "report" in p]
        Path(written["md"]).write_text("# edited\n", encoding="utf-8")
        problems = verify_case(store, CASE_ID).problems
    assert any("hash recorded when it was written" in p for p in problems) and any(".sha256 sidecar" in p for p in problems)


def test_a_recording_failure_never_fails_the_write(tmp_path, monkeypatch):
    import v3lum.core.store as store_mod

    class Broken:
        def __init__(self, *a: Any, **k: Any) -> None:
            raise OSError("database is locked")

    monkeypatch.setattr(store_mod, "Store", Broken)
    written = write_reports(hostile_case(), ["md"], tmp_path)
    assert Path(written["md"]).exists() and written["_errors"] and "case DB unavailable" in written["_errors"][0]
    assert "_errors" not in write_reports(hostile_case(), ["md"], tmp_path / "x", record=False)


def test_unknown_format_raises_before_anything_is_written(tmp_path):
    with pytest.raises(ValueError, match="unknown report format"):
        write_reports(hostile_case(), ["html", "pdfx"], tmp_path / "never")
    assert not (tmp_path / "never").exists()
    with pytest.raises(ValueError, match="invalid case id"):
        write_reports(hostile_case(case_id="../escape"), ["md"], tmp_path)


def test_misp_format_goes_through_report_misp_event(tmp_path, monkeypatch):
    seen: list[dict[str, Any]] = []
    fake = types.ModuleType("v3lum.report.misp")

    def event(case: dict[str, Any], **_: Any) -> dict[str, Any]:
        seen.append(case)
        return {"Event": {"info": "test", "Tag": [{"name": "tlp:amber"}]}}

    fake.event = event  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "v3lum.report.misp", fake)
    written = write_reports(hostile_case(), ["misp"], tmp_path)
    assert Path(written["misp"]).name == f"{CASE_ID}.TLP-AMBER.misp.json"
    assert json.loads(Path(written["misp"]).read_text(encoding="utf-8"))["Event"]["info"] == "test"
    assert seen and seen[0]["case_id"] == CASE_ID


def test_clear_reports_omit_cross_case_references(tmp_path):
    case = hostile_case("clear")
    case["entities"][0]["attributes"]["sightings"] = [{"value": {"count": 2, "last": "2026-11-01", "verdict": "phishing"}, "source": "case_sightings"}]
    case["findings"].append({"id": "f-seen", "title": "seen in 2 previous cases, last 2026-11-01, verdict: phishing", "severity": "info",
                             "entity": case["seeds"][0], "module": "case_sightings", "confidence_label": "confirmed", "tags": []})
    written = write_reports(case, ["html", "md", "json"], tmp_path)
    for fmt in ("html", "md", "json"):
        text = Path(written[fmt]).read_text(encoding="utf-8")
        assert "previous cases" not in text and "2026-11-01" not in text, fmt
    amber = write_reports({**case, "tlp": "amber"}, ["html"], tmp_path / "amber")
    assert "seen in 2 previous cases" in Path(amber["html"]).read_text(encoding="utf-8")


# ======================================================================================
# review regressions (WP20 review)
# ======================================================================================


def _unescaped_pipes(line: str) -> int:
    return len(re.findall(r"(?<!\\)\|", line))


def test_markdown_table_cells_never_split_by_a_value_pipe():
    """GFM splits table cells at a bare '|' before it parses code spans: an entity value carrying
    '|[x](https://...)' must not open a cell holding a live link."""
    evil = "acme|[x](https://evil.example/pwn)"
    case = hostile_case("clear")
    case["entities"].append({"key": f"keyword:{evil}", "type": "keyword", "value": evil, "depth": 1, "attributes": {}})
    case["findings"].append({"id": "f-pipe", "title": "t", "severity": "high", "entity": f"keyword:{evil}", "module": "t_fetch",
                             "confidence_label": "probable", "criterion": "c"})
    md = M.render(case)
    rows = [line for line in md.splitlines() if "evil.example/pwn" in line]
    assert rows
    for line in rows:
        assert "`keyword:acme\\|[x](https://evil.example/pwn)`" in line
        if line.startswith("| "):
            assert _unescaped_pipes(line) == 6, line  # findings and entities tables: 5 cells, never a 6th


def test_markdown_never_autolinks_a_target_host_or_a_refused_target():
    case = hostile_case("clear", options={"mode": "light", "authorization_ref": "REF-1"}, engagement={
        "authorization_ref": "REF-1", "scope_sha256": "ab" * 32, "window": {"start": "a", "end": "b"}, "targets_touched": {"x": 1},
        "request_count": 3, "refusals": [{"target": "www.out-of-scope.example", "module": "m", "reason_code": "scope",
                                          "reason": "not in scope http://www.out-of-scope.example/x"}],
    })
    case["modules"] = [{"module": "t_fetch", "entity": case["seeds"][0], "status": "ok", "hosts": {f"www.{HOSTILE_HOST}": 3}}]
    md = M.render(case)
    assert "www.out-of-scope.example" not in md and "http://www.out-of-scope" not in md  # defanged (GFM autolinks www./http)
    assert f"`www.{HOSTILE_HOST}`" in md  # disclosure ledger hosts in code spans
    assert f"| www.{HOSTILE_HOST} |" not in md


def test_pack_link_whose_url_host_differs_from_its_declared_host_is_never_clickable():
    case = hostile_case("clear")
    case["links"] = {case["seeds"][0]: [{"label": "Spoofed", "url": "https://evil.example/q?d=x", "host": "www.virustotal.com",
                                         "ref": "p:vt", "category": "reputation"}]}
    assert S.link_host(case["links"][case["seeds"][0]][0]) == "evil.example"
    for html in (H.render(case), P.render(case)):
        assert "https://evil.example/q" not in hrefs(html)
        assert "opening sends" in html and "evil.example" in html


def test_privacy_links_only_for_analyst_typed_seeds():
    case = hostile_case("clear")
    other = f"domain:{HOSTILE_HOST}"
    case["links"][other] = [{"label": "Personal pivot of a pivot", "url": "https://people.example.org/q?x=2", "host": "people.example.org",
                             "ref": "t_pack:people", "category": "social", "privacy": True}]
    html = H.render(case, show_personal=True)
    assert "Personal pivot" in html and "Personal pivot of a pivot" not in html  # P311 cond 6


def test_clear_reports_drop_internal_platform_references(tmp_path):
    case = hostile_case("clear")
    case["findings"].append({
        "id": "f-hive", "title": "Known internally (TheHive)", "severity": "high", "entity": f"domain:{HOSTILE_HOST}", "module": "thehive_sightings",
        "confidence_label": "probable", "criterion": "observable flagged as IOC in TheHive case #4242 of the company TheHive",
        "tags": ["internal_sighting", "malicious"], "references": ["https://thehive.corp.example/cases/4242"],
        "data": {"ref": "TheHive case #4242"}, "evidence": ["case #4242"],
    })
    case["entities"][0]["attributes"]["siem_sighting"] = [{"value": {"template_id": "tpl-4242", "count": 9}, "source": "siem_search"}]
    written = write_reports(case, ["html", "md", "json"], tmp_path)
    for fmt, path in written.items():
        text = Path(path).read_text(encoding="utf-8")
        assert "4242" not in text, fmt
        assert "Known internally (TheHive)" in text, fmt  # title and severity stay
    assert case["findings"][-1]["criterion"].endswith("TheHive")  # the case itself is untouched
    amber = H.render({**case, "tlp": "amber"})
    assert "4242" in amber


def test_markdown_content_marker_occurs_once_even_when_a_value_quotes_it():
    case = hostile_case()
    case["entities"].append({"key": f"keyword:{S.CONTENT_END_MARKER}", "type": "keyword", "value": S.CONTENT_END_MARKER, "depth": 1, "attributes": {}})
    md = M.render(case)
    assert md.count(S.CONTENT_END_MARKER) == 1
    content, _, tail = md.partition(S.CONTENT_END_MARKER)
    assert hashlib.sha256(content.encode("utf-8")).hexdigest() in tail


def test_json_report_masks_vin_and_personal_vat(tmp_path):
    case = hostile_case()
    case["entities"] += [
        {"key": "vin:1HGBH41JXMN109186", "type": "vin", "value": "1HGBH41JXMN109186", "depth": 1, "attributes": {}},
        {"key": "eu_vat:ES12345678Z", "type": "eu_vat", "value": "ES12345678Z", "depth": 1, "attributes": {}},
    ]
    text = Path(write_reports(case, ["json"], tmp_path)["json"]).read_text(encoding="utf-8")
    assert "1HGBH41JXMN109186" not in text and "ES12345678Z" not in text
    assert "1HGBH41JXMN******" in text
    raw = Path(write_reports(case, ["json"], tmp_path / "raw", show_personal=True)["json"]).read_text(encoding="utf-8")
    assert "1HGBH41JXMN109186" in raw and "ES12345678Z" in raw


def test_a_renderer_failure_writes_nothing(tmp_path, monkeypatch):
    from v3lum.report import stix as stix_r

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("renderer failed")

    monkeypatch.setattr(stix_r, "bundle", boom)
    with pytest.raises(RuntimeError):
        write_reports(hostile_case(), ["html", "stix", "md"], tmp_path / "out")
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())


def test_files_written_before_a_write_failure_are_still_recorded(tmp_path, monkeypatch):
    from v3lum import paths as paths_mod

    real = paths_mod.secure_write_bytes
    calls = {"n": 0}

    def flaky(path: Any, data: bytes, **kw: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 3:  # html + its sidecar succeed, the md file fails (disk full)
            raise OSError("No space left on device")
        return real(path, data, **kw)

    monkeypatch.setattr(paths_mod, "secure_write_bytes", flaky)
    with pytest.raises(OSError):
        write_reports(hostile_case(), ["html", "md"], tmp_path / "out")
    html_path = tmp_path / "out" / f"{CASE_ID}.TLP-AMBER.html"
    assert html_path.exists()
    with Store() as store:
        recorded = {os.path.realpath(p) for p in store.report_paths(CASE_ID)}
    assert os.path.realpath(html_path) in recorded and os.path.realpath(str(html_path) + SIDECAR_SUFFIX) in recorded


def test_clear_reports_drop_the_previous_case_id_of_the_since_last_run_line():
    case = hostile_case("clear", since_last_run={"previous_case": "20261101-090000-zz99", "new": 2, "resolved": 1})
    case["meta"] = {"header_notes": ["since last run (case 20261101-090000-zz99): 2 new findings, 1 resolved"]}
    for text in (H.render(case), M.render(case)):
        assert "zz99" not in text and "since last run: 2 new findings, 1 resolved" in text
    assert "zz99" in H.render({**case, "tlp": "amber"})  # AMBER and above keep it
    assert case["since_last_run"]["previous_case"] == "20261101-090000-zz99"  # the case is untouched


@pytest.mark.parametrize("tlp", ["clear", "amber"])
def test_a_damaged_stored_case_still_renders(tlp):
    """A stored case is untrusted: scalars where lists are expected, a non-numeric depth or junk
    severities never break a report (and never open a link or a script)."""
    case = hostile_case(tlp, findings=1.5, correlations="x", timeline={"a": 1})
    case["entities"][0]["depth"] = "<script>alert(1)</script>"
    case["entities"][1]["depth"] = {"x": 1}
    for render in (H.render, M.render, P.render):
        out = render(case)
        assert "TLP:" in out
        if render is not M.render:
            assert out.count("<script>") == 1 and "<script>alert" not in out
            assert all(h.startswith("https://") for h in hrefs(out))
