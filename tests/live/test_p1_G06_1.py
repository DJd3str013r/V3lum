"""Live checks of batch p1-G06-1 (phone_parse P126, pivots_phone P128); run with V3LUM_LIVE=1.

Both modules are offline (disclosure 'none'): they never contact a host, so the live check runs them
through the real engine and the installed 'phonenumbers' package on a public organisation number
(Banco do Brasil's published 0800 line) and asserts the parsers and the rendered links. The link
templates themselves were verified by hand on 2026-11-26 (tests/fixtures/pivots_phone/
verified_templates.json): V3LUM never fetches them, and a test never should either (spamcalls.net
counts every page view publicly).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status

pytestmark = pytest.mark.live
PUBLIC_NUMBER = "phone:0800 729 0001"  # Banco do Brasil's published toll-free line


def test_phone_parse_live():
    pytest.importorskip("phonenumbers")
    from v3lum.modules.phone.phone_parse import PhoneParse

    http = FakeHttp()
    res = run_module(PhoneParse, PUBLIC_NUMBER, http)
    assert res.status is Status.OK and http.calls == []
    assert res.attributes["valid"] is True and res.attributes["line_type"] == "toll_free"
    assert res.attributes["phone_br"]["non_geographic"]["class"] == "toll_free"
    text = run_module(PhoneParse, "text_blob:Central de atendimento: 0800 729 0001 (SAC) ou 4004 0001.")
    assert {p.entity.value for p in text.pivots} == {"+558007290001", "+5540040001"}
    assert all(p.expand is False for p in text.pivots)


def test_pivots_phone_live():
    from v3lum.modules.phone.pivots_phone import ABR_URL, PivotsPhone

    http = FakeHttp()
    res = run_module(PivotsPhone, PUBLIC_NUMBER, http, options=ScanOptions(show_personal=True, purpose="live check"), tlp="clear")
    assert res.status is Status.OK and http.calls == []
    assert [url for _label, url in res.links] == ["https://spamcalls.net/en/num/558007290001", ABR_URL]
