"""Live checks of batch p1-G12-1 (file_type_sniff, document_metadata, apk_triage, archive_listing); run with V3LUM_LIVE=1.

The four modules are offline (disclosure 'none'): they never touch the network, and every check asserts that
they made no request. The live part is the input: the test harness (never the modules) downloads benign public
sample files over HTTPS and each module runs on the real-world bytes:

* the W3C WAI test PDF (``dummy.pdf``);
* Apache POI's public test documents (Apache-2.0): ``SampleDoc.docx``, ``SampleDoc.doc``, ``SampleSS.xls``;
* androguard's ``TestActivity.apk`` (Apache-2.0, a debug-signed test app);
* the ``six`` 1.16.0 wheel (ZIP) and sdist (tar.gz) from PyPI (MIT);
* the local Python interpreter binary (no download).

Nothing is executed, installed or rendered. A 403/429/timeout from this datacenter egress while downloading a
sample skips that check with the reason (could not verify the sample); the modules themselves cannot be blocked.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import requests

from tests.fakes import FakeHttp, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis.apk_triage import ApkTriage
from v3lum.modules.file_analysis.archive_listing import ArchiveListing
from v3lum.modules.file_analysis.document_metadata import DocumentMetadata
from v3lum.modules.file_analysis.file_type_sniff import FileTypeSniff

pytestmark = pytest.mark.live

POI = "https://raw.githubusercontent.com/apache/poi/trunk/test-data"
W3C_PDF = "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"
ANDROGUARD_APK = "https://raw.githubusercontent.com/androguard/androguard/master/tests/data/APK/TestActivity.apk"
SIX_JSON = "https://pypi.org/pypi/six/1.16.0/json"
MAX_SAMPLE = 5 * 1024 * 1024
ANDROGUARD_CERT = "6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d"


def fetch(url: str, tmp_path: Path, name: str) -> str:
    """Download one public sample (GET, size-capped) into tmp_path; skip the check when the egress cannot get it."""
    try:
        with requests.get(url, timeout=30, stream=True) as r:
            if r.status_code != 200:
                pytest.skip(f"sample {name}: HTTP {r.status_code} from this egress (could not verify)")
            data = bytearray()
            for chunk in r.iter_content(65536):
                data += chunk
                if len(data) > MAX_SAMPLE:
                    pytest.skip(f"sample {name}: larger than {MAX_SAMPLE} bytes")
    except requests.RequestException as exc:
        pytest.skip(f"sample {name}: {type(exc).__name__} from this egress (could not verify)")
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return str(path)


def run_offline(cls, path: str):
    http = FakeHttp()
    res = run_module(cls, Entity.make(T.FILE, path), http)
    assert http.calls == [] and res.requests == 0  # offline modules: no request whatever the input
    return res


def severities(res) -> set[str]:
    return {f.severity.label for f in res.findings}


def test_w3c_pdf(tmp_path):
    path = fetch(W3C_PDF, tmp_path, "w3c_dummy.pdf")
    sn = run_offline(FileTypeSniff, path)
    assert sn.status is Status.OK and sn.attributes["file_sniff"]["kind"] == "pdf"
    assert "document_metadata" in sn.attributes["file_sniff"]["routes"] and "high" not in severities(sn)
    doc = run_offline(DocumentMetadata, path)
    assert doc.status is Status.OK and doc.attributes["document_metadata"]["format"] == "pdf"
    assert doc.attributes["document_summary"].startswith("pdf") and "high" not in severities(doc)


@pytest.mark.parametrize(("name", "url", "kind", "fmt"), [
    ("SampleDoc.docx", f"{POI}/document/SampleDoc.docx", "ooxml-docx", "ooxml"),
    ("SampleDoc.doc", f"{POI}/document/SampleDoc.doc", "ole-doc", "ole-doc"),
    ("SampleSS.xls", f"{POI}/spreadsheet/SampleSS.xls", "ole-xls", "ole-xls"),
])
def test_apache_poi_office_documents(tmp_path, name, url, kind, fmt):
    path = fetch(url, tmp_path, name)
    sn = run_offline(FileTypeSniff, path)
    assert sn.status is Status.OK and sn.attributes["file_sniff"]["kind"] == kind
    assert not [f for f in sn.findings if f.severity.label in ("medium", "high")]  # extension matches the content
    doc = run_offline(DocumentMetadata, path)
    assert doc.status is Status.OK and doc.attributes["document_metadata"]["format"] == fmt
    assert "high" not in severities(doc)  # benign test documents: no remote template, auto-exec macro or DDE
    for p in doc.pivots:  # c10: names and accounts from metadata are analyst-selected only
        if p.relation in ("document_author", "local_account"):
            assert p.expand is False


def test_androguard_test_apk(tmp_path):
    path = fetch(ANDROGUARD_APK, tmp_path, "TestActivity.apk")
    res = run_offline(ApkTriage, path)
    assert res.status is Status.OK
    assert res.attributes["apk_manifest"]["package"] == "tests.androguard"
    certs = {p.entity.value for p in res.pivots if p.relation == "signing_certificate"}
    assert ANDROGUARD_CERT in certs and res.attributes["apk_signing"]["verified"] is False
    assert "high" not in severities(res)


def test_pypi_wheel_and_sdist(tmp_path):
    try:
        meta = requests.get(SIX_JSON, timeout=30)
    except requests.RequestException as exc:
        pytest.skip(f"PyPI JSON: {type(exc).__name__} from this egress (could not verify)")
    if meta.status_code != 200:
        pytest.skip(f"PyPI JSON: HTTP {meta.status_code} from this egress (could not verify)")
    urls = {u.get("packagetype"): u.get("url") for u in meta.json().get("urls", []) if isinstance(u, dict)}
    assert urls.get("bdist_wheel") and urls.get("sdist")
    wheel = fetch(urls["bdist_wheel"], tmp_path, "six-1.16.0-py2.py3-none-any.whl")
    res = run_offline(ArchiveListing, wheel)
    assert res.status is Status.OK and res.attributes["archive_summary"]["kind"] == "zip"
    names = {m["name"] for m in res.attributes["archive_members"]}
    assert "six.py" in names and any(n.endswith("/RECORD") for n in names)
    assert [p for p in res.pivots if p.entity.type is T.SHA256 and p.relation == "contains"]  # c7: small members hashed
    assert "high" not in severities(res)
    sdist = fetch(urls["sdist"], tmp_path, "six-1.16.0.tar.gz")
    tgz = run_offline(ArchiveListing, sdist)
    assert tgz.status is Status.OK and tgz.attributes["archive_summary"]["counts"]["members"] > 5
    assert any(m["name"].endswith("six.py") for m in tgz.attributes["archive_members"])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="ELF interpreter expected on Linux only")
def test_local_interpreter_binary():
    exe = str(Path(sys.executable).resolve())
    res = run_offline(FileTypeSniff, exe)
    assert res.status is Status.OK and res.attributes["file_sniff"]["kind"] == "elf"
    assert "high" not in severities(res)
