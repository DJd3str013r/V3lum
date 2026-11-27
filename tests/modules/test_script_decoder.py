"""script_decoder (P366, batch p2-G12-2): static, bounded de-obfuscation feeding the P172 extractor.

Fixtures in tests/fixtures/script_decoder/: synthetic encoded samples, one per technique (documentation IPs
and example.* hosts, EICAR hashes), nested 5 and 6 layers, an oversized deflate payload, a binary (MZ-prefixed,
not a real PE) payload, a secret-in-layer sample with FAKE values, a namespace/CDN filter sample and the
ReDoS recipes (redos_candidates.json).
"""

from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Severity, Status
from v3lum.modules.file_analysis import script_decoder as SD
from v3lum.modules.file_analysis.script_decoder import ScriptDecoder, decode_layers, extract_decoded_iocs, render_layer

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "script_decoder"
PAYLOAD_SHA256 = "0f1c39e3940cd68b833e664cfd98e2bd96f3411171ceb91c34cdb341b7031d3b"


def fx(name: str) -> str:
    return module_fixture("script_decoder", name)


def run_text(text: str):
    return run_module(ScriptDecoder, Entity.make(T.TEXT, text))


def values(res, etype=None) -> set[str]:
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


# ------------------------------------------------------------------ c1: static only
def test_module_has_no_dynamic_execution_process_or_network():
    tree = ast.parse(Path(SD.__file__).read_text(encoding="utf-8"))
    banned_calls = {"eval", "exec", "compile", "__import__", "execfile", "breakpoint"}
    banned_modules = {"subprocess", "ctypes", "socket", "urllib.request", "http.client", "requests", "pty", "multiprocessing",
                      "shlex", "importlib", "pickle", "marshal"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in banned_calls, node.func.id
        if isinstance(node, ast.Import):
            assert not {a.name for a in node.names} & banned_modules
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "") not in banned_modules
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
            assert node.attr in {"path"}, f"os.{node.attr}"  # only os.path for the regular-file check
    ctx = make_ctx(ScriptDecoder, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("http://198.51.100.7/stage2.ps1")
    assert ScriptDecoder.disclosure == "none" and ScriptDecoder.default_enabled is True and ScriptDecoder.terms == "open"


# ------------------------------------------------------------------ c2: techniques
@pytest.mark.parametrize("name,technique,needle", [
    ("ps_encodedcommand.txt", "ps_encodedcommand", "http://198.51.100.7/stage2.ps1"),
    ("ps_encodedcommand_caret.txt", "ps_encodedcommand", "https://cdn-update.example.net/a.exe"),
    ("frombase64string.ps1", "frombase64string", "https://update.example.org/payload.bin"),
    ("frombase64string_deflate.ps1", "frombase64string", "$c2='c2.example.org'"),
    ("fromcharcode.js", "char_codes", "'https://login.example.net/verify'"),
    ("unescape.hta", "unescape", "'http://198.51.100.23/b.hta'"),
    ("vbs_chr.vbs", "vbs_chr", '"http://files.example.com/x.exe"'),
    ("hex_blob.txt", "hex_blob", "'https://hex.example.org/dropper.zip'"),
    ("concat.js", "concat", "'http://concat.example.com/x.js'"),
    ("js_escapes.js", "js_escapes", '"http://js.example.com/p"'),
    ("base64_literal.ps1", "base64_literal", "'https://b64.example.net/loader.ps1'"),
])
def test_each_technique(name, technique, needle):
    r = decode_layers(fx(name))
    assert r["layers"] and r["layers"][0]["technique"] == technique
    assert r["layers"][0]["label"].startswith("layer 1: " + SD.SD_TECHNIQUE_LABELS[technique])
    assert any(needle in layer["text"] for layer in r["layers"]), [x["text"][:200] for x in r["layers"]]
    assert r["stop"] == "no_more_encodings"


def test_char_codes_then_concat_and_caret_normalisation():
    r = decode_layers(fx("char_codes.ps1"))
    assert r["path"] == "L1:char_codes>L2:concat"
    assert "'http://203.0.113.50/payload.bin'" in r["layers"][1]["text"]
    c = decode_layers(fx("ps_encodedcommand_caret.txt"))
    assert c["layers"][0]["normalised"] and "after normalising" in c["layers"][0]["label"]


def _enc(script: str) -> str:
    import base64

    return base64.b64encode(script.encode("utf-16-le")).decode()


@pytest.mark.parametrize("wrapper, expected", [
    ('"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoP -w hidden -enc {b}', "{s}"),
    ("%windir%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -w hidden -enc {b}", "{s}"),
    ('cmd.exe /c "powershell -ec {b}"', 'cmd.exe /c "{s}"'),
    ("start powershell -e {b} & del run.bat", "start {s} & del run.bat"),
    ("echo powershell & x.exe -enc {b}", "echo powershell & x.exe {s}"),  # another command owns the flag
    ("Run powershell first, then use -enc {b}", "Run powershell first, then use {s}"),  # prose is kept
])
def test_encodedcommand_layer_is_the_command_powershell_runs(wrapper, expected):
    script = "Write-Output 'fixture'; $u = 'https://203.0.113.10/boleto/nfe.ps1'"
    out = decode_layers(wrapper.format(b=_enc(script)))
    assert out["path"] == "L1:ps_encodedcommand"
    assert out["layers"][0]["text"] == expected.format(s=script)


# ------------------------------------------------------------------ c3: bounds and ReDoS
def test_nested_five_layers_with_provenance_and_pivots():
    raw = fx("nested5.txt")
    res = run_text(raw)
    assert res.status is Status.OK
    assert res.attributes["decode_path"].startswith("L1:ps_encodedcommand>L2:frombase64string>L3:char_codes>L4:concat>L5:hex_blob")
    assert {"http://203.0.113.50/stage3.bin", "c2.example.org", "44d88612fea8a8f36de82e1278abb02f",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"} <= values(res)
    url = next(p for p in res.pivots if p.entity.value == "http://203.0.113.50/stage3.bin")
    assert url.relation == "extracted_from" and "L1:ps_encodedcommand>L2:frombase64string" in url.note and "decoded" in url.note
    assert SD.CRADLE_NOTE in url.note  # c6: never contacted
    cradle = next(f for f in res.findings if f.title == "Download cradle in a decoded script layer")
    assert cradle.severity is Severity.MEDIUM and cradle.criterion and "T1027" in cradle.attack
    assert len(res.raw["layers"]) == 5 and res.raw["layers"][4]["technique"] == "hex_blob"


def test_bounds_layers_output_input_and_time():
    r6 = decode_layers(fx("nested6.txt"))
    assert r6["stop"] == "max_layers" and len(r6["layers"]) == 5
    big = decode_layers(fx("oversized_deflate.ps1"))
    assert big["stop"] == "output_cap" and big["layers"][0]["truncated"]
    assert len(big["layers"][0]["text"].encode()) <= SD.SD_MAX_LAYER_BYTES
    h = decode_layers("Write-Output 'x' " * 70_000)  # ~1.2 MB input
    assert h["input_truncated"] and h["stop"] == "no_more_encodings"
    ticks = iter(range(0, 10_000))
    slow = decode_layers(fx("nested5.txt"), clock=lambda: float(next(ticks)), time_budget_s=5)
    assert slow["stop"] == "time_budget" and len(slow["layers"]) < 5
    assert decode_layers("")["stop"] == "empty" and decode_layers(None)["stop"] == "empty"


@pytest.mark.parametrize("recipe", json.loads((FIX / "redos_candidates.json").read_text()), ids=lambda r: r["unit"][:12])
def test_every_regex_is_linear_on_pathological_input(recipe):
    s = (recipe["unit"] * recipe["repeat"])[:100_000] + recipe["suffix"]
    for rx in SD.PATTERNS_ALL:
        t0 = time.monotonic()
        for _ in rx.finditer(s):
            pass
        assert time.monotonic() - t0 < 0.5, (rx.pattern[:60], recipe["unit"])
    t0 = time.monotonic()
    res = decode_layers(s)
    SD.defang_text(s)
    assert time.monotonic() - t0 < 6.0
    assert res["stop"] in ("no_more_encodings", "max_layers", "output_cap", "time_budget", "empty")


def test_random_fuzz_does_not_raise_or_hang():
    import random

    rnd = random.Random(1234)
    alphabet = "[]()'\"+&,.-%\\xu0123456789abcdefABCDEF :/@^`$;=\n\tChr[char]String.fromCharCode-enc FromBase64String"
    for _ in range(40):
        s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 4000)))
        t0 = time.monotonic()
        decode_layers(s)
        SD.defang_text(s)
        assert time.monotonic() - t0 < 2.0


# ------------------------------------------------------------------ c4: evidence, redaction, rendering
def test_layers_pass_through_the_central_redactor_and_render_defanged():
    res = run_text(fx("secret_in_layer.ps1"))
    layer_text = res.raw["layers"][0]["text"]
    assert "FAKEKEY1234567890" not in layer_text and "FAKE-TOKEN-0000000000" not in layer_text
    blob = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.description for f in res.findings],
                       "p": [p.entity.value for p in res.pivots]})
    assert "FAKEKEY1234567890" not in blob
    line = render_layer(decode_layers(fx("ps_encodedcommand.txt"))["layers"][0], 400)
    assert line.startswith("layer 1: base64 UTF-16LE -EncodedCommand: ")
    assert "hxxp://198[.]51[.]100[.]7/stage2.ps1" in line and "http://198" not in line
    assert render_layer({"label": "layer 1: hex blob", "text": "x" * 500, "bytes": 500}, 50).endswith("... (500 bytes in evidence)")
    preview = res.attributes["decoded_layers"][0]["preview"]
    assert len(preview) < 400 and preview.startswith("layer 1:")


# ------------------------------------------------------------------ c5: P172 hand-off, P169 filter
def test_namespace_and_cdn_urls_are_filtered():
    raw = fx("namespace_filter.ps1")
    out = extract_decoded_iocs(decode_layers(raw), raw)
    vals = {i["entity"].value for i in out["items"]}
    assert any("evil-update.example.net" in v for v in vals)
    for host in ("schemas.microsoft.com", "go.microsoft.com", "www.w3.org", "cdnjs.cloudflare.com"):
        assert not any(host in v for v in vals), host
    assert out["filtered"] >= 4


def test_iocs_visible_in_the_input_are_left_to_the_generic_extractor():
    text = "see http://198.51.100.7/stage2.ps1 first; " + fx("ps_encodedcommand.txt")
    res = run_text(text)
    assert "http://198.51.100.7/stage2.ps1" not in values(res)  # already visible: ioc_extract pivots it


def test_binary_payload_is_hashed_not_inlined():
    res = run_text(fx("binary_payload.ps1"))
    payload = res.raw["layers"][0]["payloads"][0]
    assert payload["pe"] and payload["sha256"] == PAYLOAD_SHA256
    assert "<binary payload: 1028 bytes" in res.raw["layers"][0]["text"]
    assert {PAYLOAD_SHA256, payload["md5"]} <= values(res)
    assert any(f.title == "Binary payload embedded in the script" for f in res.findings)


# ------------------------------------------------------------------ module paths
def test_plain_script_is_empty_never_an_error():
    res = run_text(fx("plain_no_encoding.ps1"))
    assert res.status is Status.EMPTY and "nothing decoded" in res.error


def test_script_file_and_binary_file(tmp_path):
    script = tmp_path / "dropper.vbs"
    script.write_text(fx("vbs_chr.vbs"), encoding="utf-8")
    res = run_module(ScriptDecoder, Entity.make(T.FILE, str(script)))
    assert res.status is Status.OK and "http://files.example.com/x.exe" in values(res)
    utf16 = tmp_path / "enc.ps1"
    utf16.write_bytes(fx("ps_encodedcommand.txt").encode("utf-16"))  # PowerShell files are often UTF-16 with BOM
    assert "http://198.51.100.7/stage2.ps1" in values(run_module(ScriptDecoder, Entity.make(T.FILE, str(utf16))))
    binary = tmp_path / "blob.txt"
    binary.write_bytes(bytes(range(256)) * 64)
    res = run_module(ScriptDecoder, Entity.make(T.FILE, str(binary)))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    image = tmp_path / "x.png"
    image.write_bytes(b"\x89PNG....")
    assert not ScriptDecoder().applies(Entity.make(T.FILE, str(image)), make_ctx(ScriptDecoder))


def test_reusable_api_for_p367():
    out = decode_layers(fx("ps_encodedcommand.txt"), redact=SD.central_redact)
    assert isinstance(out["layers"], list) and out["path"] == "L1:ps_encodedcommand" and out["stop"] == "no_more_encodings"
    assert {"n", "technique", "label", "text"} <= set(out["layers"][0])
