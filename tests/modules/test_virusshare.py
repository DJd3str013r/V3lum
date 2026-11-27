"""Offline tests of the VirusShare adapter (P177, module virusshare).

``file_ok.json`` is the real research answer for EICAR (the only real P177 success fixture; its
crawler URLs were replaced by documentation values); the APK answer comes from the API reference.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.hash_lookup_keyed import VirusShare, parse_virusshare_file

KEY = "virusshare-test-key-0123456789abcd"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
APK = "036eef46db1f85a5c499d363e0f4d3b40051c9ef81ccd3f2173008c0c5dea4f4"


def url(value: str) -> str:
    return f"https://virusshare.com/apiv2/file?{urlencode({'apikey': KEY, 'hash': value})}"


def run(value: str, http: FakeHttp, **kw: Any) -> Any:
    kw.setdefault("keys", {"virusshare": KEY})
    return run_module(VirusShare, f"sha256:{value}", http, **kw)


def test_real_eicar_answer() -> None:
    http = FakeHttp().add("GET", url(EICAR), json=module_fixture("virusshare", "file_ok.json"))
    res = run(EICAR, http)
    assert res.status is Status.OK, res.error
    vs = res.attributes["virusshare"]
    assert vs["category"] == "malware" and vs["av"]["positives"] == 9 and vs["av"]["scanner"] == "virusshare (not virustotal)"
    assert vs["trid"] == ["EICAR antivirus test file (100.0%)"]
    assert set(vs["exif"]) <= {"FileSize", "FileType", "FileTypeExtension", "MIMEType"}  # technical keys only
    assert res.attributes["known_good"] is True  # the NSRL flag
    assert res.findings[0].title == "VirusShare: AV test file (EICAR)"
    assert all("\r" not in s for s in res.attributes["av_signatures"])  # control characters stripped
    assert [p.entity.value for p in res.pivots if p.relation == "similarity_hash"] == ["3:a+JraNvsgzsVqSwHq9:tJuOgzsko"]
    assert_no_secret(KEY, res.to_dict())  # the apikey URL parameter is masked
    http.assert_hosts_within(VirusShare)


def test_documented_apk_answer_is_a_scanner_detection() -> None:
    res = run(APK, FakeHttp().add("GET", url(APK), json=module_fixture("virusshare", "file_docs_apk.json")))
    assert res.status is Status.OK
    f = res.findings[0]
    assert f.title == "Flagged by a few VirusShare scanners" and f.severity.label == "low" and "not VirusTotal" not in f.title
    assert res.attributes["virusshare"]["extension"] == "apk"
    assert "ZipFileName" not in res.attributes["virusshare"]["exif"]


def test_response_zero_inside_200_is_an_absence() -> None:
    res = run(APK, FakeHttp().add("GET", url(APK), json=module_fixture("virusshare", "file_not_found_docs.json")))
    assert res.status is Status.EMPTY and "response 0" in res.error


def test_204_is_rate_limited_and_403_needs_a_key() -> None:
    res = run(APK, FakeHttp().add("GET", url(APK), status=204, body=b""))
    assert res.status is Status.RATE_LIMITED
    fx = module_fixture("virusshare", "forbidden_403.http.json")["response"]
    assert run(APK, FakeHttp().add("GET", url(APK), status=fx["status"], body=b"")).status is Status.NEEDS_KEY


def test_unknown_codes_malformed_answers_and_5xx_are_errors() -> None:
    assert run(APK, FakeHttp().add("GET", url(APK), json={"response": 7})).status is Status.ERROR
    assert run(APK, FakeHttp().add("GET", url(APK), json={"sha256": APK})).status is Status.ERROR
    assert run(APK, FakeHttp().add("GET", url(APK), text="oops", headers={"content-type": "text/plain"})).status is Status.ERROR
    assert run(APK, FakeHttp().add("GET", url(APK), status=503, text="busy", times=3)).status is Status.ERROR
    assert parse_virusshare_file([1])["status"] == "error"


def test_empty_key_answers_are_never_used() -> None:
    http = FakeHttp()
    assert run(APK, http, keys={"virusshare": ""}).status is Status.NEEDS_KEY and not http.calls
