"""Live checks of batch p2-G10-2 (datajud, rfb_cnpj_bulk importer, dou_search); run with V3LUM_LIVE=1.

Benign public values only, and nothing that would use a source against its terms:

* DataJud (noncommercial terms, off under the corporate profile): the policy gate is checked offline; live,
  the official key page is read and parsed (the key is never printed) and the search endpoint is called
  WITHOUT a key on the public test vector 0700055-10.2018.8.01.0022 (expected: 401 security_exception).
  No keyed query is sent from the build egress.
* RFB WebDAV share: one PROPFIND without credentials (expected: 401 'No Authorization: Basic header',
  token_missing). No token is sent: the official share link must be recorded by a maintainer first.
* DOU: www.in.gov.br forbids all robots and dou_search has no network at all; nothing is fetched.

A 403/429/timeout or a dropped connection from this datacenter egress is an acceptable outcome when it is
reported as could-not-verify.
"""

from __future__ import annotations

import hashlib

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.http import NetworkError, ScopedHttp
from v3lum.modules.brazil_public_data import datajud as dj
from v3lum.modules.brazil_public_data import rfb_import as imp

pytestmark = pytest.mark.live
NUM_DIGITS = "07000551020188010022"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def scope(rt: Runtime, module: str, provider: str, source: str, hosts: tuple[str, ...]) -> ScopedHttp:
    return ScopedHttp(rt.http, module=module, provider=provider, sources=(source,), allowed_hosts=hosts, disclosure="third_party",
                      opsec="passive", max_requests=3, cancel_event=rt.cancel_event, clock=rt.clock)


def test_datajud_key_page_still_publishes_a_key_in_the_expected_form():
    rt = live_runtime()
    http = scope(rt, "datajud", "cnj", dj.SOURCE, dj.DataJud.hosts)
    try:
        resp = http.get(dj.KEY_PAGE, ttl=0, headers={"Accept": "text/html"})
    except NetworkError as exc:
        pytest.skip(f"key page unreachable from this egress: {exc}")
    print(resp.status, resp.headers.get("last-modified"), resp.headers.get("etag"))
    assert resp.status == 200
    key = dj.extract_datajud_key(resp.text)
    assert key, "'APIKey atual' no longer found in the expected form: the module would report NEEDS_KEY"
    print("published key sha256 prefix:", hashlib.sha256(key.encode()).hexdigest()[:12])


def test_datajud_without_key_is_401_security_exception():
    rt = live_runtime()
    http = scope(rt, "datajud", "cnj", dj.SOURCE, dj.DataJud.hosts)
    try:
        resp = http.request("POST", f"{dj.API}/api_publica_tjac/_search", json_body={"query": {"match": {"numeroProcesso": NUM_DIGITS}}, "size": 1},
                            retries=0, timeout=60)
    except NetworkError as exc:
        pytest.skip(f"DataJud unreachable from this egress: {exc}")
    print(resp.status, resp.content[:200])
    assert resp.status == 401
    assert dj.parse_search(resp.content, NUM_DIGITS)["status"] == "auth"


def test_rfb_share_without_credentials_is_token_missing():
    rt = live_runtime()
    http = scope(rt, "rfb_cnpj_bulk", "rfb", imp.SOURCE, (imp.SHARE_HOST,))
    try:
        resp = http.request("PROPFIND", imp.WEBDAV_URL, data=imp.PROPFIND_BODY, headers={"Depth": "0", "Content-Type": "text/xml"},
                            ttl=0, allow_redirects=False, timeout=60)
    except NetworkError as exc:
        pytest.skip(f"RFB share unreachable from this egress: {exc}")
    print(resp.status, resp.content[:200])
    assert imp.webdav_problem(resp.status, dict(resp.headers), resp.content) == "token_missing"


def test_rfb_importer_without_an_official_share_link_never_touches_the_network():
    rt = live_runtime()
    res = imp.import_rfb(rt)
    assert res["status"] == "unavailable" and res["hint"]
