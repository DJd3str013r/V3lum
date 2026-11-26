"""AR13: no module-provided string can inject rich markup or terminal control sequences.

Covers ``v3lum.ui.safe`` (safe_text, clean_text, safe_href, defang_display, entity_display) and the
terminal renderers (``render_case``, ``render_single``, ``render_detections``, ``LiveFeed``) with
values produced by a real module run through the engine as well as hand-built stored cases.
"""

from __future__ import annotations

import copy
import io
import json

import pytest
from rich.console import Console
from rich.text import Text

from tests.fakes import define_module, make_runtime
from v3lum.core import detect
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity
from v3lum.ui.live import LiveFeed
from v3lum.ui.render import render_case, render_detections, render_single
from v3lum.ui.safe import (
    clean_text,
    defang_display,
    entity_display,
    is_hostile,
    mask_cpf_in_text,
    mask_personal_vat,
    safe_href,
    safe_rich,
    safe_text,
)
from v3lum.ui.theme import THEME, make_console

#: ESC/OSC/CSI payloads a hostile page or provider could return.
HOSTILE = (
    "\x1b]8;;https://evil.example/\x07click me\x1b]8;;\x07"  # OSC 8 hyperlink (BEL terminated)
    "\x1b]0;pwned title\x1b\\"  # OSC 0 window title (ST terminated)
    "\x1b[2J\x1b[31mred\x1b[0m"  # CSI clear screen + SGR
    "\x9b31m"  # 8-bit CSI
    "\x07\x08\r"  # BEL, BS, CR
    "‮exe.txt"  # RIGHT-TO-LEFT OVERRIDE
)
MARKUP = "[/bold] [link=javascript:alert(1)]x[/link] [bold red on white]y [@click=app.quit]z"
CPF = "52998224725"


def _plain_console(width: int = 220) -> Console:
    """No colour, not a terminal: rich itself emits no escape code, so any ESC in the output came
    from the rendered content."""
    return make_console(no_color=True, width=width)


def _render(case: dict, **kw) -> str:
    console = _plain_console()
    with console.capture() as cap:
        render_case(console, case, **kw)
    return cap.get()


def _case(**extra) -> dict:
    case = {
        "schema": "v3lum.case/2", "case_id": "20261126-120000-safe", "tlp": "amber", "seeds": ["domain:evil.example"],
        "inputs": [{"type": "domain", "value": "evil.example", "confidence": 1.0, "reason": "domain " + MARKUP}],
        "options": {"mode": "passive", "depth": 1},
        "summary": {"entities": 1, "findings": 1, "module_runs": 1, "requests": 1, "duration": 0.5},
        "risk": {"score": 40.0, "level": "medium", "entities": {"domain:evil.example": {"score": 40.0, "level": "medium"}}},
        "entities": [{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "display": "evil.example",
                      "depth": 0, "seed": True, "tags": [], "attributes": {"title": [{"value": MARKUP + HOSTILE, "source": "m"}]}}],
        "edges": [],
        "findings": [{"id": "f1", "title": MARKUP + HOSTILE, "severity": "high", "confidence": 0.9, "confidence_label": "confirmed",
                      "criterion": "criterion " + MARKUP + HOSTILE, "description": "desc " + MARKUP + HOSTILE,
                      "entity": "domain:evil.example", "module": "m", "tags": []}],
        "correlations": [{"id": "c1", "rule": "r", "title": "corr " + MARKUP + HOSTILE, "severity": "high", "description": HOSTILE,
                          "entities": ["domain:evil.example"], "confidence": 0.8, "recommendation": "rec " + MARKUP + HOSTILE}],
        "modules": [{"module": "m", "entity": "domain:evil.example", "status": "ok", "hosts": {}}],
        "coverage": {"m": {"status": "blocked", "reason_code": "challenge", "reason": "blocked " + MARKUP + HOSTILE}},
        "answered": {"domain:evil.example": {"applicable": 1, "answered": 0, "could_not_verify": 1, "sources": [{"module": "m" + HOSTILE, "source": "", "status": "blocked", "reason_code": "challenge"}], "reputation_applicable": 1, "reputation_answered": 0}},
        "skips": {}, "links": {}, "timeline": [{"date": "2026-01-01", "entity": "domain:evil.example", "event": "event " + MARKUP + HOSTILE}],
        "notes": ["note " + MARKUP + HOSTILE], "meta": {"header_notes": ["header " + MARKUP + HOSTILE]},
    }
    case.update(extra)
    return case


# ---------------------------------------------------------------------------------------- ui.safe


def test_safe_text_escapes_markup_and_removes_controls():
    text = safe_text("[/bold]" + HOSTILE)
    assert "\x1b" not in text and "\x07" not in text and "\x9b" not in text and "‮" not in text and "\r" not in text
    parsed = Text.from_markup(text)
    assert parsed.spans == []  # nothing interpreted as markup
    # (rich drops a backslash before a non-tag '[' when parsing: cosmetic, and the renderer never
    # parses module text - it builds Text objects from clean_text)
    assert parsed.plain.replace("\\", "") == clean_text("[/bold]" + HOSTILE).replace("\\", "")
    assert Text.from_markup(safe_text(MARKUP)).plain == MARKUP  # literal, no tag interpreted
    assert Text.from_markup(safe_text(MARKUP)).spans == []


def test_controls_are_removed_before_escaping():
    """A control character inside a tag must not hide it from the escaper ('[\\x00bold]')."""
    for raw in ("[\x00bold]x[/\x1bbold]", "[\x1b/bold]", "[b\x07]x"):
        rendered = Text.from_markup(safe_text(raw))
        assert rendered.plain == clean_text(raw) and rendered.spans == []


def test_clean_text_keeps_newline_and_tab_only():
    assert clean_text("a\tb\nc\x00d\x1be\x7ff\x85g\x9fh i⁦j") == "a\tb\ncdefg" + "h i" + "j"
    assert clean_text(None) == "" and clean_text(42) == "42"
    assert safe_rich("x\x1b[31m", "v.text").plain == "x[31m"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)", "JaVaScRiPt:alert(1)", " javascript:alert(1)", "java\tscript:alert(1)", "java\x00script:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=", "file:///etc/passwd", "vbscript:msgbox(1)", "ftp://files.example/x",
        "//evil.example/x", "https://", "https:///path", "https://bank.example@evil.example/", "https://evil.example\\@good.example/",
        'https://x.example/"onmouseover=alert(1)', "https://x.example/<script>", "https://x.example/a b", "https://x.example:99999/",
        "", None, 42,
    ],
)
def test_safe_href_rejects_everything_but_plain_http(url):
    assert safe_href(url) is None


def test_safe_href_accepts_http_and_https():
    assert safe_href("https://www.shodan.io/host/8.8.8.8") == "https://www.shodan.io/host/8.8.8.8"
    assert safe_href("  http://example.com/a?b=1#c ") == "http://example.com/a?b=1#c"
    assert safe_href("HTTPS://EXAMPLE.COM/") == "HTTPS://EXAMPLE.COM/"


def test_defang_display_only_for_hostile_host_values():
    assert defang_display("https://evil.example/login", "url", ["phishing"]) == "hxxps://evil[.]example/login"
    assert defang_display("evil.example", EntityType.DOMAIN, {"c2"}) == "evil[.]example"
    assert defang_display("203.0.113.9", "ipv4", ["malicious"]) == "203[.]0[.]113[.]9"
    assert defang_display("user@evil.example", "email", ["suspicious"]) == "user[@]evil[.]example"
    assert defang_display("evil.example", "domain", ["info"]) == "evil.example"  # not hostile
    assert defang_display("evil.example", "domain", ["phishing"], no_defang=True) == "evil.example"  # --no-defang
    assert defang_display("44d88612fea8a8f36de82e1278abb02f", "md5", ["malicious"]) == "44d88612fea8a8f36de82e1278abb02f"
    assert defang_display("https://ok.example/", "url", [], force=True) == "hxxps://ok[.]example/"
    assert is_hostile(["phishing"]) and is_hostile("c2") and not is_hostile(["benign"]) and not is_hostile(None)


def test_entity_display_masks_cpf_and_personal_vat():
    assert entity_display("cpf", CPF) == "***.982.247-**"
    assert entity_display("cpf", CPF, show_personal=True) == "529.982.247-25"
    assert entity_display("eu_vat", "CZ7103192745") == "CZ*******745"  # birth number: a natural person
    assert entity_display("eu_vat", "CZ7103192745", show_personal=True) == "CZ7103192745"
    assert entity_display("eu_vat", "DE136695976") == "DE136695976"  # company form unchanged
    assert mask_personal_vat("ES12345678Z") == "ES******78Z" and mask_personal_vat("ESA58818501") == "ESA58818501"
    assert entity_display("url", "https://evil.example/x") == "hxxps://evil[.]example/x"  # never a clickable URL
    assert entity_display("url", "https://evil.example/x", no_defang=True) == "https://evil.example/x"
    assert entity_display("no_such_type", "a\x1b[2Jb") == "a[2Jb"


def test_valid_cpfs_inside_free_text_are_masked():
    text = "suspeito 529.982.247-25 / 52998224725; not a cpf 12345678901; ip 529.982.247.25; cnpj 11.222.333/0001-81"
    masked = mask_cpf_in_text(text)
    assert masked.count("***.982.247-**") == 2 and "52998224725" not in masked and "529.982.247-25" not in masked
    assert "12345678901" in masked and "529.982.247.25" in masked and "11.222.333/0001-81" in masked
    assert entity_display("text_blob", "beacon cpf 52998224725 to 203.0.113.7") == "beacon cpf ***.982.247-** to 203.0.113.7"
    assert entity_display("text_blob", "cpf 52998224725", show_personal=True) == "cpf 52998224725"
    assert mask_cpf_in_text(None) == "" and mask_cpf_in_text("") == ""


def test_text_blob_input_with_a_cpf_renders_masked():
    blob = "text_blob:pagamento do cpf 52998224725 para 203.0.113.7"
    case = _case(seeds=[blob], inputs=[{"type": "text_blob", "value": blob.partition(":")[2], "confidence": 1.0, "reason": "free text"}], answered={})
    case["entities"] = [{"key": blob, "type": "text_blob", "value": blob.partition(":")[2], "depth": 0, "seed": True, "tags": [], "attributes": {}}]
    case["findings"] = []
    out = _render(case)
    assert CPF not in out and "***.982.247-**" in out


# ---------------------------------------------------------------------------------------- render_case


def test_markup_in_a_page_title_does_not_abort_rendering():
    out = _render(_case())
    assert "[/bold]" in out and "[link=javascript:alert(1)]x[/link]" in out  # shown literally
    assert "criterion [/bold]" in out and "rec [/bold]" in out


def test_esc_and_osc_sequences_never_reach_the_terminal():
    case = _case()
    out = _render(case, full=True)
    for bad in ("\x1b", "\x07", "\x9b", "\x08", "\r", "‮"):
        assert bad not in out, repr(bad)
    # the same holds on a real colour terminal: only rich's own SGR codes, never the content's
    buf = io.StringIO()
    console = Console(file=buf, width=220, force_terminal=True, color_system="truecolor", theme=THEME)
    render_case(console, case, full=True)
    raw = buf.getvalue()
    assert "\x1b]0;" not in raw and "\x1b[2J" not in raw and "\x07" not in raw and "evil.example/\x07" not in raw
    assert "\x1b]8;;https://evil.example" not in raw


def test_rendering_never_changes_the_case_dict():
    """JSON/STIX exports stay raw: rendering masks and defangs only what it prints."""
    case = _case()
    case["entities"][0]["tags"] = ["phishing"]
    before = copy.deepcopy(case)
    _render(case)
    assert case == before
    assert json.dumps(case)  # still serialisable as it was


def test_malicious_urls_are_defanged():
    url = "https://login.evil.example/verify"
    case = _case(seeds=[f"url:{url}"], inputs=[{"type": "url", "value": url, "confidence": 1.0, "reason": "url"}])
    case["entities"] = [{"key": f"url:{url}", "type": "url", "value": url, "depth": 0, "seed": True, "tags": ["phishing"], "attributes": {}}]
    case["findings"][0]["entity"] = f"url:{url}"
    case["findings"][0]["tags"] = ["phishing"]
    case["answered"] = {}
    out = _render(case)
    assert "hxxps://login[.]evil[.]example/verify" in out
    assert url not in out
    assert url in _render(case, no_defang=True)  # --no-defang shows it as it is


def test_hostile_domain_is_defanged_everywhere_it_is_displayed():
    case = _case()
    case["findings"][0]["tags"] = ["c2"]
    out = _render(case)
    assert "domain:evil[.]example" in out  # input row, findings entity column, entity map
    assert "domain:evil.example" not in out
    assert "evil[.]example:" in out  # the answered line names the defanged seed


def test_cpf_is_masked_unless_show_personal():
    key = f"cpf:{CPF}"
    case = _case(seeds=[key], inputs=[{"type": "cpf", "value": CPF, "confidence": 1.0, "reason": "valid CPF"}])
    case["entities"] = [{"key": key, "type": "cpf", "value": CPF, "display": "***.982.247-**", "depth": 0, "seed": True, "attributes": {}}]
    case["findings"][0]["entity"] = key
    case["answered"] = {}
    out = _render(case)
    assert "***.982.247-**" in out
    assert CPF not in out and "529.982.247-25" not in out
    assert "529.982.247-25" in _render(case, show_personal=True)
    case["options"]["show_personal"] = True  # recorded on the run that produced the case
    assert "529.982.247-25" in _render(case) and CPF not in _render(case, show_personal=False).replace("529.982.247-25", "")
    assert "529.982.247-25" not in _render(case, show_personal=False)


def test_javascript_links_are_never_rendered():
    case = _case(tlp="clear")
    case["links"] = {"domain:evil.example": [
        {"label": "evil", "url": "javascript:alert(document.cookie)", "host": "evil.example", "category": "reputation", "verified": True},
        {"label": "data", "url": "data:text/html,<script>alert(1)</script>", "host": "", "category": "other"},
        {"label": "ok", "url": "https://www.virustotal.com/gui/domain/evil.example", "host": "www.virustotal.com", "category": "reputation", "verified": True},
    ]}
    out = _render(case)
    assert "javascript:alert(document.cookie)" not in out and "data:text/html" not in out
    assert "2 link(s) dropped: not an http(s) URL" in out
    assert "https://www.virustotal.com/gui/domain/evil.example" in out


# ---------------------------------------------------------------------------------------- engine end to end


def test_module_strings_from_a_real_run_are_rendered_safely(clean_registry):
    """A module returns hostile text in every field it controls; the stored case renders without a
    MarkupError and without control sequences, and the CPF pivot stays masked."""

    def run(self, entity, ctx):
        res = self.result(entity)
        res.finding(MARKUP + HOSTILE, Severity.HIGH, "desc " + MARKUP + HOSTILE, criterion="seen " + MARKUP + HOSTILE, tags=("phishing",))
        res.attr("title", MARKUP + HOSTILE)
        res.link("label " + MARKUP + HOSTILE, "https://ok.example/x")
        res.pivot(EntityType.CPF, CPF, "mentions", expand=False)
        return res

    mod = define_module("t_render_hostile", ["domain"], run)
    eng = Engine(make_runtime(), ScanOptions(include={mod.name}, save_evidence=False))
    case = eng.investigate([Entity.make("domain", "evil.example")]).to_dict()
    out = _render(case, full=True)
    assert "[/bold]" in out and "[link=javascript:alert(1)]x[/link]" in out
    for bad in ("\x1b", "\x07", "\x9b", "‮"):
        assert bad not in out
    assert "evil[.]example" in out  # tagged phishing: defanged
    assert CPF not in out and "***.982.247-**" in out


def test_render_single_is_safe_and_masks():
    out_dict = {
        "module": "m" + HOSTILE, "entity": f"cpf:{CPF}", "status": "blocked", "reason_code": "challenge", "error": "err " + MARKUP + HOSTILE,
        "duration": 0.2, "findings": [{"title": MARKUP + HOSTILE, "severity": "high", "criterion": "c " + MARKUP, "description": HOSTILE, "confidence": 0.9}],
        "attributes": {"title": MARKUP + HOSTILE, "list": [MARKUP, HOSTILE]},
        "pivots": [{"entity": f"cpf:{CPF}", "relation": "mentions" + HOSTILE, "confidence": 0.9}],
        "links": [{"label": MARKUP, "url": "javascript:void(window.pwn)"}, {"label": "ok", "url": "https://ok.example/"}],
    }
    console = _plain_console()
    with console.capture() as cap:
        render_single(console, out_dict)
    out = cap.get()
    assert "[/bold]" in out and "blocked: challenge" in out
    for bad in ("\x1b", "\x07", "\x9b"):
        assert bad not in out
    assert CPF not in out and "***.982.247-**" in out
    assert "javascript:void(window.pwn)" not in out and "1 link(s) dropped" in out
    assert "hxxps://ok[.]example/" in out and "opening sends ***.982.247-** to ok.example" in out  # AMBER default


def test_render_detections_is_safe_and_masks_cpf():
    console = _plain_console()
    found = detect.detect(CPF)
    with console.capture() as cap:
        render_detections(console, CPF + "\x1b[2J" + MARKUP, found)
    out = cap.get()
    assert "\x1b" not in out and "[/bold]" in out
    cpf_rows = [line for line in out.splitlines() if line.strip().startswith("cpf")]
    assert cpf_rows and all("***.982.247-**" in row and CPF not in row for row in cpf_rows)
    title = out.splitlines()[0]
    assert title.startswith("detect ***.982.247-**") and CPF not in title  # the echoed input is masked too


# ---------------------------------------------------------------------------------------- live feed


class _Opts:
    mode = type("M", (), {"label": "passive"})()
    depth = 1
    tlp = "amber"
    authorized = False
    show_personal = False
    no_defang = False


def test_live_feed_prints_only_safe_redacted_text():
    console = _plain_console()
    feed = LiveFeed(console, verbosity=2)
    with console.capture() as cap:
        feed("scan_start", {"case_id": "c" + MARKUP, "seeds": [], "options": _Opts()})
        feed("investigate", {"entity": Entity.make("cpf", CPF), "depth": 0, "modules": ["m"]})
        feed("http", {"method": "GET", "url": "https://api.example.test/v1?apikey=SECRETSECRET123&q=1" + HOSTILE, "status": 200, "elapsed": 0.1, "cached": False, "error": "", "egress_profile": "default"})
        feed("log", {"module": "m" + HOSTILE, "message": MARKUP + HOSTILE, "level": "warn"})
        feed("entity", {"entity": Entity.make("url", "https://evil.example/x"), "parent": None, "relation": "rel" + HOSTILE, "module": "m", "depth": 1})
    out = cap.get()
    for bad in ("\x1b", "\x07", "\x9b", "‮"):
        assert bad not in out
    assert "SECRETSECRET123" not in out and "apikey=***" in out
    assert CPF not in out and "***.982.247-**" in out
    assert "[/bold]" in out and "TLP:AMBER" in out
    assert "hxxps://evil[.]example/x" in out  # URLs never clickable in the feed


# ---------------------------------------------------------------------------------------- review additions


def test_bidi_marks_are_removed_too():
    assert clean_text("a\u200eb\u200fc\u061cd\u202ee\u2066f") == "abcdef"


def test_text_blob_display_never_leaves_half_a_cpf():
    """The CPF is masked before the 60-character display cut, so no prefix of it survives."""
    shown = entity_display("text_blob", "x" * 50 + " 529.982.247-25 tail")
    assert "529" not in shown and "982.2" not in shown


def test_entity_display_fails_closed_when_display_value_breaks(monkeypatch):
    from v3lum.core import entities as entities_mod

    def boom(*_a, **_k):
        raise RuntimeError("display bug")

    monkeypatch.setattr(entities_mod, "display_value", boom)
    assert entity_display("cpf", CPF) == "***.982.247-**"
    assert entity_display("vin", "1HGCM82633A004352") == "*** (vin)"
    assert entity_display("domain", "ok.example") == "ok.example"


@pytest.mark.parametrize(
    "path",
    [("risk", "level"), ("risk", "entities", "domain:evil.example", "level"), ("risk", "contributors", 0, "confidence_label"),
     ("findings", 0, "severity"), ("correlations", 0, "severity"), ("summary", "risk_level")],
)
def test_stored_case_levels_and_labels_cannot_carry_controls(path):
    """Risk levels, contributor labels and severities read from a stored case are untrusted too."""
    case = _case()
    case["risk"]["contributors"] = [{"finding_id": "f1", "words": "w", "confidence_label": "confirmed"}]
    target = case
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = MARKUP + HOSTILE
    for full in (False, True):
        out = _render(case, full=full)
        for bad in ("\x1b", "\x07", "\x9b", "\u202e"):
            assert bad not in out, (path, repr(bad))


def test_malformed_edges_do_not_break_rendering():
    case = _case(edges=[{"src": "domain:evil.example", "dst": ["not", "hashable"], "relation": "a"}, {"src": None, "dst": {"x": 1}}, "junk"])
    assert "entity map" in _render(case, full=True)


def test_cpfs_in_module_text_are_masked_unless_show_personal():
    """A module (or an engine note naming an entity key) quoting a CPF never prints it in full."""
    case = _case()
    case["findings"][0].update(title=f"titular {CPF}", criterion=f"criterio {CPF}", description="desc 529.982.247-25")
    case["entities"][0]["attributes"] = {"holder_doc": [{"value": f"doc {CPF}", "source": "m"}]}
    case["correlations"][0].update(title=f"corr {CPF}", recommendation=f"check {CPF}")
    case["coverage"]["m"]["reason"] = f"provider said {CPF}"
    case["notes"] = [f"m on cpf:{CPF}: guard yielded", f"scan deadline (global timeout 5s) reached: partial results for cpf:{CPF}"]
    case["timeline"][0]["event"] = f"seen {CPF}"
    out = _render(case, full=True)
    assert CPF not in out and "529.982.247-25" not in out
    assert out.count("***.982.247-**") >= 8
    shown = _render(case, full=True, show_personal=True)
    assert CPF in shown  # the analyst unmasked this view (recorded by the caller)


def test_render_single_and_live_feed_mask_cpfs_in_module_text():
    out_dict = {"module": "m", "entity": "domain:ok.example", "status": "error", "error": f"failed for {CPF}", "duration": 0.1,
                "findings": [{"title": f"holder {CPF}", "severity": "high", "criterion": f"c {CPF}", "description": f"d {CPF}"}],
                "attributes": {"doc": f"{CPF}"}, "pivots": [], "links": []}
    console = _plain_console()
    with console.capture() as cap:
        render_single(console, out_dict)
    assert CPF not in cap.get() and cap.get().count("***.982.247-**") >= 4
    with console.capture() as cap:
        render_single(console, dict(out_dict, show_personal=True))
    assert CPF in cap.get()

    feed = LiveFeed(console, verbosity=2)
    with console.capture() as cap:
        feed("scan_start", {"case_id": "c", "seeds": [], "options": _Opts()})
        feed("log", {"module": "m", "message": f"lookup {CPF}", "level": "warn"})
        feed("http", {"method": "GET", "url": f"https://api.example.test/v1/{CPF}", "status": 0, "elapsed": 0.1, "cached": False, "error": f"timeout {CPF}"})
    assert CPF not in cap.get() and "***.982.247-**" in cap.get()
