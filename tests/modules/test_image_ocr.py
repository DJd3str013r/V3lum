"""image_ocr (P363, batch p2-G12-2): offline OCR in the file-analysis sandbox, PDF text layer first.

Input images are synthetic rendered-text images generated here with Pillow (c8: URL, PIX payload, boleto line,
CPF to mask, a misread-prone domain). The OCR step itself is replaced by the real tesseract 5.3.4 TSV output
recorded over the same kind of images (tests/fixtures/image_ocr/*.tsv, tessdata_fast por+eng); mixed_pages.pdf
is a synthetic two-page PDF (page 1 with a text layer, page 2 image-only). Documentation values only: the
person 'Fulano de Tal', CPF 123.456.789-09, phone +55 11 5555-0123, example.* hosts and 192.0.2.x.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import make_ctx, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.tools import get_tool
from v3lum.modules.geo_image_meta import image_ocr as OCR
from v3lum.modules.geo_image_meta.image_ocr import ImageOcr

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "image_ocr"


def tsv(name: str) -> str:
    return module_fixture("image_ocr", name)


def render(tmp_path: Path, name: str, lines: list[str], size=(900, 60)) -> str:
    """c8: a synthetic rendered-text PNG (Pillow default font)."""
    from PIL import Image, ImageDraw

    img = Image.new("L", (size[0], size[1] * len(lines)), 255)
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((10, 10 + i * size[1]), line, fill=0)
    path = tmp_path / name
    img.save(path)
    return str(path)


def page_from_tsv(name: str, page: int = 1) -> dict:
    words = [{**w, "page": page} for w in OCR.parse_tesseract_tsv(tsv(name))["words"]]
    text, _ = OCR.ocr_text_and_spans(words)
    mean = round(sum(w["conf"] for w in words) / len(words), 2) if words else None
    return {"page": page, "source": "ocr", "words": words, "text": text, "mean_conf": mean, "error": None}


@pytest.fixture(autouse=True)
def _wrapper_installed(monkeypatch):
    """pytesseract is an optional extra (not in the test venv): run() sees it installed unless a test says otherwise."""
    monkeypatch.setattr(OCR, "package_available", lambda name: True)


@pytest.fixture
def ready(monkeypatch, tmp_path):
    """Binary, models and sandbox in place: the sandbox returns recorded tesseract output."""
    calls: list[dict] = []
    state = {"pages": [page_from_tsv("url_ptbr.tsv")], "result": None}

    def fake_sandbox_run(target, path, *, args=None, **limits):
        calls.append({"target": target, "path": path, "args": args, "limits": limits})
        if target.endswith(":zxing_child"):
            raise OCR.SandboxUnavailable("no QR in this test")
        return {"ok": True, "result": state["result"] or {"kind": args["kind"], "pages": state["pages"]}, "isolation": "full"}

    monkeypatch.setattr(OCR, "sandbox_run", fake_sandbox_run)
    monkeypatch.setattr(ImageOcr, "tesseract_path", staticmethod(lambda ctx: "/usr/bin/tesseract"))
    monkeypatch.setattr(ImageOcr, "tessdata_dir", staticmethod(lambda ctx: str(tmp_path)))
    state["calls"] = calls
    return state


def run_direct(path: str):
    """run() without the readiness gate (pytesseract is an optional extra not installed in the test venv)."""
    ent = Entity.make(T.FILE, path)
    return ImageOcr().run(ent, make_ctx(ImageOcr, entity=ent))


# ------------------------------------------------------------------ c1-c3 metadata and readiness
def test_contract_metadata_models_and_tool():
    cls = ImageOcr
    assert cls.disclosure == "none" and cls.default_enabled is True and cls.terms == "open" and cls.max_tlp.value_str == "red"
    assert cls.requires_packages == ("pytesseract", "PIL") and cls.sources == ("github.image_ocr_tessdata_fast",)
    for name, spec in OCR.OCR_MODELS.items():
        reg = DATASETS[name]
        assert reg["pinned_sha256"] == spec["sha256"] and OCR.TESSDATA_FAST_COMMIT in reg["url"] and reg["licence"] == "Apache-2.0"
    assert get_tool("tesseract").licence == "Apache-2.0"


def test_missing_wrapper_is_unavailable_package(monkeypatch):
    monkeypatch.setattr(OCR, "package_available", lambda name: name != "pytesseract")
    monkeypatch.setattr(ImageOcr, "tesseract_path", staticmethod(lambda ctx: "/usr/bin/tesseract"))
    res = run_module(ImageOcr, Entity.make(T.FILE, str(FIX / "mixed_pages.pdf")))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and "pip install pytesseract" in res.error


def test_missing_binary_gives_the_install_command(tmp_path, monkeypatch):
    monkeypatch.setattr(OCR.shutil, "which", lambda name: None)
    res = run_direct(render(tmp_path, "a.png", ["hello"]))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"
    assert "tesseract binary not found" in res.error and ("apt-get install -y tesseract-ocr" in res.error or "brew" in res.error
                                                           or "winget" in res.error)


def test_missing_models_are_unavailable_dataset(tmp_path, monkeypatch):
    from tests.fakes import make_runtime

    monkeypatch.setattr(ImageOcr, "tesseract_path", staticmethod(lambda ctx: "/usr/bin/tesseract"))
    path = render(tmp_path, "a.png", ["hello"])
    ent = Entity.make(T.FILE, path)
    ctx = make_ctx(ImageOcr, entity=ent, runtime=make_runtime(offline=True))
    from v3lum.core.datasets import DatasetUnavailable

    with pytest.raises(DatasetUnavailable):  # the engine maps it to UNAVAILABLE 'dataset'
        ImageOcr().run(ent, ctx)


def test_no_core_sandbox_is_could_not_verify(tmp_path, monkeypatch):
    monkeypatch.setattr(ImageOcr, "tesseract_path", staticmethod(lambda ctx: "/usr/bin/tesseract"))
    monkeypatch.setattr(ImageOcr, "tessdata_dir", staticmethod(lambda ctx: str(tmp_path)))
    res = run_direct(render(tmp_path, "a.png", ["hello"]))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"
    assert "only inside the file-analysis sandbox" in res.error  # this build: never 'no text'


def test_decompression_bomb_is_refused_before_decoding(ready):
    res = run_direct(str(FIX / "bomb_header.png"))
    assert res.status is Status.ERROR and "too_many_pixels 30000x30000" in res.error
    assert ready["calls"] == []  # nothing reached the sandbox


def test_not_an_image_is_not_applicable(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("plain text")
    assert not ImageOcr().applies(Entity.make(T.FILE, str(p)), make_ctx(ImageOcr))
    assert ImageOcr().applies(Entity.make(T.FILE, str(FIX / "mixed_pages.pdf")), make_ctx(ImageOcr))


# ------------------------------------------------------------------ c5-c7 emission over recorded OCR
def test_url_screenshot_pivots_are_unconfirmed_and_capped(ready, tmp_path):
    path = render(tmp_path, "url.png", ["Atencao: sua conta sera bloqueada hoje!", "https://atualiza-cadastro.example.com/login?id=123",
                                        "Suporte tecnico: 192.0.2.10"])
    res = run_direct(path)
    assert res.status is Status.OK
    call = ready["calls"][0]
    assert call["target"] == "v3lum.modules.geo_image_meta.image_ocr:ocr_child" and call["args"]["max_pages"] == 10
    assert call["limits"]["mem_bytes"] == 1 << 30 and call["limits"]["max_input"] == 100 * 1024 * 1024
    by = {p.entity.value: p for p in res.pivots}
    url = by["https://atualiza-cadastro.example.com/login?id=123"]
    assert url.relation == "extracted_from" and url.expand is False and url.confidence <= 0.6 and OCR.OCR_NOTE in url.note
    assert by["192.0.2.10"].expand is False
    assert all(p.confidence <= 0.6 and p.expand is False for p in res.pivots)
    snips = {s["display"]: s for s in res.attributes["ocr_snippets"]}
    assert "bloqueada" in snips["https://atualiza-cadastro.example.com/login?id=123"]["snippet"]
    assert res.attributes["ocr_summary"]["ocr_pages"] == [1] and res.attributes["ocr_summary"]["isolation"] == "full"
    assert "Atenção:" in res.raw["pages"][0]["text"]  # full text in evidence only
    assert res.findings[0].title == "Text recognised in the file (OCR)"


def test_cpf_is_masked_everywhere_and_never_pivoted(ready, tmp_path):
    ready["pages"] = [page_from_tsv("cpf.tsv")]
    res = run_direct(render(tmp_path, "cpf.png", ["Cliente: Fulano de Tal CPF: 123.456.789-09", "Contato: +55 11 5555-0123"]))
    assert not any(p.entity.type is T.CPF for p in res.pivots)
    blob = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.description for f in res.findings],
                       "p": [(p.entity.value, p.note) for p in res.pivots]}, ensure_ascii=False)
    assert "123.456.789-09" not in blob and "12345678909" not in blob and "***.456.789-**" in blob
    assert any(f.title == "CPF in the recognised text (masked, not pivoted)" for f in res.findings)
    phone = [p for p in res.pivots if p.entity.type is T.PHONE]
    assert phone and phone[0].expand is False


def test_misread_domains_are_flagged_and_never_lookalike_findings(ready, tmp_path):
    ready["pages"] = [page_from_tsv("misread_domain.tsv")]
    res = run_direct(render(tmp_path, "m.png", ["Acesse rnicrosoft-suporte.example.net ou paypa1-seguro.example.org agora"]))
    doms = {p.entity.value: p for p in res.pivots if p.entity.type is T.DOMAIN}
    assert "rnicrosoft-suporte.example.net" in doms and "rn~m" in doms["rnicrosoft-suporte.example.net"].note
    assert all(p.expand is False for p in doms.values())
    for f in res.findings:
        assert not ({"typosquat", "phishing", "tampering_suspected"} & set(f.tags)), f.title
        assert f.severity.value <= 1  # info/low only from OCR text


def test_pix_payload_misread_is_could_not_verify_never_tampering(ready, tmp_path):
    ready["pages"] = [page_from_tsv("pix_payload.tsv")]
    res = run_direct(render(tmp_path, "pix.png", ["Pague com PIX copia e cola:"]))
    pay = [f for f in res.findings if f.title == "Payment code in OCR text could not be verified (OCR)"]
    assert pay and "likely a misread, not tampering" in pay[0].description
    assert all("tampering_suspected" not in f.tags for f in res.findings)
    assert all(f.severity.name in ("INFO",) for f in res.findings)


def test_boleto_line_is_pivoted_with_valid_check_digits(ready, tmp_path):
    ready["pages"] = [page_from_tsv("boleto.tsv")]
    res = run_direct(render(tmp_path, "b.png", ["Linha digitavel: 00190.00009 01234.567897 01234.567178 9 10000000012345"]))
    bol = [p for p in res.pivots if p.entity.type is T.BOLETO]
    assert bol and bol[0].expand is False and "check digits valid" in bol[0].note
    assert res.raw["payments"][0]["checksum_ok"] is True


def test_blank_image_is_empty_never_an_error(ready, tmp_path):
    ready["pages"] = [page_from_tsv("blank.tsv")]
    res = run_direct(render(tmp_path, "blank.png", [""]))
    assert res.status is Status.EMPTY and "no text recognised" in res.error


def test_language_models_missing_inside_the_child_is_unavailable_dataset(ready, tmp_path):
    ready["pages"] = [{"page": 1, "source": "ocr", "error": "lang_missing", "message": "Failed loading language"}]
    res = run_direct(render(tmp_path, "a.png", ["x"]))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_sandbox_timeout_is_error_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(OCR, "sandbox_run", lambda *a, **k: {"ok": False, "reason_code": "timeout", "error": "wall timeout"})
    monkeypatch.setattr(ImageOcr, "tesseract_path", staticmethod(lambda ctx: "/usr/bin/tesseract"))
    monkeypatch.setattr(ImageOcr, "tessdata_dir", staticmethod(lambda ctx: str(tmp_path)))
    res = run_direct(render(tmp_path, "a.png", ["x"]))
    assert res.status is Status.ERROR and res.reason_code == "timeout"


# ------------------------------------------------------------------ the sandbox child (c3-c4), tesseract faked
def test_child_pdf_text_layer_first_then_ocr_of_the_image_only_page(monkeypatch):
    seen = []

    def fake_tsv(image, **kw):
        seen.append((image.size, kw["langs"]))
        return tsv("mixed_pages_p2.tsv")

    monkeypatch.setattr(OCR, "_tesseract_tsv", fake_tsv)
    out = OCR.ocr_child((FIX / "mixed_pages.pdf").read_bytes(), kind="pdf", tessdata_dir="/x", tesseract_cmd="tesseract")
    plan = out["plan"]
    assert plan["text_pages"] == [1] and plan["ocr_pages"] == [2] and plan["coverage_gaps"] == []
    pages = {p["page"]: p for p in out["pages"]}
    assert pages[1]["source"] == "text_layer" and "https://fatura.example.com/2026/11" in pages[1]["text"]
    assert pages[2]["source"] == "ocr" and "00190.00009" in pages[2]["text"]
    assert len(seen) == 1 and seen[0][1] == OCR.LANGS  # one OCR call: only the image-only page


def test_child_image_pixel_cap_and_bad_image(monkeypatch, tmp_path):
    monkeypatch.setattr(OCR, "_tesseract_tsv", lambda image, **kw: tsv("url_ptbr.tsv"))
    good = Path(render(tmp_path, "g.png", ["hello"])).read_bytes()
    out = OCR.ocr_child(good, kind="image", tessdata_dir="/x")
    assert out["pages"][0]["words"] and out["pages"][0]["mean_conf"] > 90
    bomb = OCR.ocr_child((FIX / "bomb_header.png").read_bytes(), kind="image", tessdata_dir="/x")
    assert bomb["pages"][0]["error"].startswith("too_many_pixels")
    broken = OCR.ocr_child(good[:60], kind="image", tessdata_dir="/x")
    assert broken["pages"][0]["error"]


def test_child_reports_tesseract_failures_by_marker(monkeypatch, tmp_path):
    def boom(image, **kw):
        raise RuntimeError(module_fixture("image_ocr", "stderr_lang_missing.txt"))

    monkeypatch.setattr(OCR, "_tesseract_tsv", boom)
    out = OCR.ocr_child(Path(render(tmp_path, "g.png", ["x"])).read_bytes(), kind="image", tessdata_dir="/x")
    assert out["pages"][0]["error"] == "lang_missing"
    assert OCR.tesseract_stderr_marker(module_fixture("image_ocr", "stderr_bad_image.txt")) == "bad_image"
    assert OCR.tesseract_stderr_marker(module_fixture("image_ocr", "stderr_config_missing.txt")) == "config_missing"


# ------------------------------------------------------------------ pure helpers
def test_header_dimensions_without_decoding_and_caps():
    assert OCR.image_header_info((FIX / "bomb_header.png").read_bytes()) == {"format": "png", "width": 30000, "height": 30000}
    assert OCR.pixel_cap_check({"width": 0, "height": 5}) == "zero_size"
    big = {"pages": [{"page": 1, "text": "x" * 900_000, "words": [{"text": "x"}] * 5000}]}
    capped = OCR.cap_ocr_output(big, cap_bytes=200_000)
    assert capped["truncated"] and "words" not in capped["pages"][0] and len(json.dumps(capped)) <= 200_000


def test_tsv_parsing_errors_and_pytesseract_dict_shape():
    assert OCR.parse_tesseract_tsv("")["error"] == "empty"
    assert OCR.parse_tesseract_tsv("<html><body>x</body></html>")["error"] == "html"
    assert OCR.parse_tesseract_tsv("a\tb\n1\t2")["error"] == "bad_header"
    words = OCR.parse_tesseract_tsv(tsv("url_ptbr.tsv"))["words"]
    assert words[0]["text"] == "Atenção:" and 0 <= words[0]["conf"] <= 100
    assert OCR.ocr_confidence(97.3) == 0.6 and OCR.ocr_confidence(31) == 0.31 and OCR.ocr_confidence("x") == 0.0


def test_cpf_masking_tolerates_ocr_confusables_and_keeps_phones():
    masked, n = OCR.mask_cpfs("CPF 123.456.789-O9 e 12345678909 tel 11987654321")
    assert n == 2 and "***.456.789-**" in masked and "11987654321" in masked


def test_brcode_candidates_join_wrapped_lines():
    text = "Pague:\n00020126370014br.gov.bcb.pix\n0115pix@example.com5204000053039865406100.00\n5802BR6304ABCD fim"
    cands = OCR.brcode_candidates(text)
    assert cands and cands[0].startswith("000201") and cands[0].endswith("6304ABCD")
