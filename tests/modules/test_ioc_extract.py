"""ioc_extract (reference offline module): IOC pivots, personal identifiers and withheld secrets.

Fixture tests/fixtures/ioc_extract/incident_note.txt is a sanitised training note with benign or
test values only (EICAR hashes, documentation addresses, a public example wallet, the classic
example CPF 111.444.777-35 and a dummy JWT).
"""

from __future__ import annotations

import json
import os

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.utility.ioc_extract import PERSONAL_NOTE, IocExtract

NOTE = module_fixture("ioc_extract", "incident_note.txt")
CPF = "11144477735"
JWT_PREFIX = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def run_text(text):
    return IocExtract().run(Entity.make("text_blob", text), make_ctx(IocExtract))


# ------------------------------------------------------------------ moved case
def test_ioc_extract_text_and_file(tmp_path):
    text = "C2 hxxp://bad-site[.]xyz/gate and 45.33.32.156\nhash 44d88612fea8a8f36de82e1278abb02f"
    res = run_text(text)
    assert {"45.33.32.156", "44d88612fea8a8f36de82e1278abb02f", "bad-site.xyz"} <= pivots(res)
    f = tmp_path / "notes.log"
    f.write_text(text)
    ent = Entity.make("file", str(f))
    assert IocExtract().applies(ent, make_ctx(IocExtract))
    assert "45.33.32.156" in pivots(IocExtract().run(ent, make_ctx(IocExtract)))
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG....")
    assert not IocExtract().applies(Entity.make("file", str(binary)), make_ctx(IocExtract))


# ------------------------------------------------------------------ v2 pivot rules (AR07, A8, rule 4)
def test_ioc_types_expand_personal_types_do_not():
    res = run_text(NOTE)
    by_value = {p.entity.value: p for p in res.pivots}
    for value in ("45.33.32.156", "bad-site.xyz", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "CVE-2021-44228", "T1566.001", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"):
        assert by_value[value].expand is True, value
    email = by_value["someone@example.com"]
    assert email.expand is False and email.note == PERSONAL_NOTE
    assert all(p.relation == "mentions" for p in res.pivots)


def test_cpf_and_secrets_are_never_pivoted():
    res = run_text(NOTE)
    assert not any(p.entity.type in (T.CPF, T.JWT) for p in res.pivots)
    withheld = res.raw["withheld"]
    assert withheld["cpf"]["count"] == 1 and withheld["jwt"]["count"] == 1
    produced = {  # what the module writes (the seed text itself is the analyst's input)
        "raw": res.raw,
        "findings": [{"title": f.title, "description": f.description, "data": f.data} for f in res.findings],
        "pivots": sorted(pivots(res)),
        "attributes": res.attributes,
    }
    blob = json.dumps(produced)
    assert CPF not in blob and "111.444.777-35" not in blob  # masked previews only
    assert JWT_PREFIX not in blob
    assert any(f.title == "CPF or secrets in the text (not pivoted)" for f in res.findings)


def test_counts_include_withheld_types():
    res = run_text(NOTE)
    counts = next(f for f in res.findings if f.title == "Indicators extracted from text").data["counts"]
    assert counts["cpf"] == 1 and counts["jwt"] == 1 and counts["ipv4"] == 1


def test_offline_module_has_no_network():
    res = run_module(IocExtract, Entity.make("text_blob", NOTE), FakeHttp())
    assert res.status is Status.OK
    assert res.requests == 0
    ctx = make_ctx(IocExtract, FakeHttp())
    with pytest.raises(PolicyError):  # disclosure 'none': ctx.http refuses every request
        ctx.http.get("https://example.com/")


def test_vanished_or_special_files_are_not_applicable(tmp_path):
    """The file can disappear (or be swapped for a FIFO) between detection and the run."""
    ctx = make_ctx(IocExtract)
    note = tmp_path / "gone.txt"
    note.write_text("45.33.32.156")
    ent = Entity.make("file", str(note))
    note.unlink()
    assert not IocExtract().applies(ent, ctx)  # no crash in applies()
    res = run_module(IocExtract, ent, FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe.txt"
        os.mkfifo(fifo)
        assert not IocExtract().applies(Entity(T.FILE, str(fifo)), ctx)  # reading a FIFO would block


def test_unreadable_file_is_an_error_not_an_empty_result(tmp_path, monkeypatch):
    note = tmp_path / "note.txt"
    note.write_text("45.33.32.156")
    ent = Entity.make("file", str(note))

    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    ctx = make_ctx(IocExtract)
    monkeypatch.setattr("v3lum.modules.utility.ioc_extract.open", denied, raising=False)  # shadows the builtin there only
    res = IocExtract().run(ent, ctx)
    assert res.status is Status.ERROR and "Permission denied" in res.error and not res.pivots


def test_fixture_file_is_trimmed_and_benign():
    text = (FIXTURES / "ioc_extract" / "incident_note.txt").read_text(encoding="utf-8")
    assert len(text) < 2000 and "sanitised" in text
