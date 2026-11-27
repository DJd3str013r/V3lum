"""email_header_analyzer_msg (P085 cond 9): Outlook .msg transport headers through the optional olefile.

Fixtures in tests/fixtures/email_header_analyzer_msg/ (synthetic): ``ok.msg`` is a minimal CFB
container holding the stream ``__substg1.0_007D001F`` (checked with olefile 0.47) and
``transport_headers.bin`` the same UTF-16LE stream on its own. Without olefile the module reports
UNAVAILABLE 'package'; a stand-in olefile proves the stream handling and the size caps.
"""

from __future__ import annotations

import importlib.machinery
import io
import sys
import types

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.core.module import package_available
from v3lum.modules.email import email_header_analyzer as eha
from v3lum.modules.email.email_header_analyzer import EmailHeaderAnalyzerMsg

MOD = EmailHeaderAnalyzerMsg
FX = FIXTURES / "email_header_analyzer_msg"
SETTINGS = {"email_header_analyzer_trusted_mta": ["mx.google.com"], "email_header_analyzer_trusted_networks": ["2001:db8:a05::/48"]}


def fake_olefile(stream: bytes | None, *, is_ole: bool = True, broken: bool = False) -> types.ModuleType:
    """A stand-in for the optional olefile package (findable through importlib, like a real install)."""
    mod = types.ModuleType("olefile")
    mod.__spec__ = importlib.machinery.ModuleSpec("olefile", loader=None)

    class OleFileIO:
        def __init__(self, path):
            if broken:
                raise OSError("not a valid OLE structure")
            self.closed = False

        def exists(self, name):
            return stream is not None and name == eha.MSG_TRANSPORT_HEADERS_STREAM

        def openstream(self, name):
            return io.BytesIO(stream or b"")

        def close(self):
            self.closed = True

    mod.isOleFile = lambda path: is_ole
    mod.OleFileIO = OleFileIO
    return mod


@pytest.fixture
def olefile_stub(monkeypatch):
    def install(stream, **kw):
        monkeypatch.setitem(sys.modules, "olefile", fake_olefile(stream, **kw))

    return install


def test_without_olefile_the_module_is_unavailable(monkeypatch):
    if package_available("olefile"):
        pytest.skip("olefile is installed here")
    res = run_module(MOD, f"file:{FX / 'ok.msg'}", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and "olefile" in res.error


def test_transport_headers_are_analysed(olefile_stub):
    olefile_stub((FX / "transport_headers.bin").read_bytes())
    http = FakeHttp()
    res = run_module(MOD, f"file:{FX / 'ok.msg'}", http, settings=SETTINGS)
    assert res.status is Status.OK and http.calls == []
    assert res.attributes["originating_ip"]["ip"] == "2001:db8:4864:20::32"
    assert any(p.relation == "sent_from" for p in res.pivots)


def test_stream_decoding_and_caps(olefile_stub, tmp_path):
    text = eha.decode_msg_transport_headers((FX / "transport_headers.bin").read_bytes())
    assert text.startswith("Delivered-To: ") and not text.endswith("\x00")
    assert eha.decode_msg_transport_headers(b"\xff\xfe" + "X: y".encode("utf-16-le")) == "X: y"
    olefile_stub(b"A" * (eha.MAX_MSG_STREAM_BYTES + 2))
    res = run_module(MOD, f"file:{FX / 'ok.msg'}", FakeHttp())
    assert res.status is Status.ERROR and "larger than 1 MB" in res.error
    huge = tmp_path / "huge.msg"
    with open(huge, "wb") as fh:
        fh.write(eha.CFB_MAGIC)
        fh.truncate(eha.MAX_EMAIL_BYTES + 1)
    res2 = run_module(MOD, f"file:{huge}", FakeHttp())
    assert res2.status is Status.ERROR and "25 MB" in res2.error


def test_malformed_msg_and_missing_stream_are_errors(olefile_stub):
    olefile_stub(None, broken=True)
    res = run_module(MOD, f"file:{FX / 'ok.msg'}", FakeHttp())
    assert res.status is Status.ERROR and "malformed .msg" in res.error
    olefile_stub(None)
    res2 = run_module(MOD, f"file:{FX / 'ok.msg'}", FakeHttp())
    assert res2.status is Status.ERROR and "no transport headers stream" in res2.error


def test_only_cfb_files_apply(olefile_stub, tmp_path):
    olefile_stub(b"")
    eml = tmp_path / "plain.eml"
    eml.write_bytes(b"From: a@example.net\r\nSubject: x\r\nDate: Tue, 24 Nov 2026 13:00:00 +0000\r\n\r\nbody\r\n")
    res = run_module(MOD, f"file:{eml}", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_real_olefile_reads_the_fixture():
    olefile = pytest.importorskip("olefile")  # optional extra (P085 C9)
    ole = olefile.OleFileIO(str(FX / "ok.msg"))
    try:
        assert ole.exists(eha.MSG_TRANSPORT_HEADERS_STREAM)
        assert ole.openstream(eha.MSG_TRANSPORT_HEADERS_STREAM).read() == (FX / "transport_headers.bin").read_bytes()
    finally:
        ole.close()
    res = run_module(MOD, f"file:{FX / 'ok.msg'}", FakeHttp(), settings=SETTINGS)
    assert res.status is Status.OK


def test_metadata():
    assert MOD.requires_packages == ("olefile",) and MOD.disclosure == "none" and MOD.terms == "open"
    assert "email_header_analyzer_trusted_mta" in MOD.settings  # inherited from the base module
