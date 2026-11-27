"""url_unwrap (P064, batch p1-G03-1): offline unwrapping, recipient redaction, hand-off decoding.

Fixtures in tests/fixtures/url_unwrap/: the SafeLinks line recorded in the research e-mail sample,
and documentation-value constructions of SafeLinks (with recipient data), Proofpoint v2/v3, Google,
Mimecast, LinkedIn/Facebook/Instagram, a 6-level nesting, malformed wrappers, Unfurl-style values and
WhatsApp/Telegram hand-offs (example.org / example.com / +55 11 5555-01xx documentation values).
"""

from __future__ import annotations

import ast
import json
from datetime import datetime
from pathlib import Path

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links, noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import url_unwrap as U
from v3lum.modules.url_web.url_unwrap import UrlUnwrap

MODULE_FILE = Path(U.__file__)


def fx(name: str) -> str:
    return module_fixture(UrlUnwrap, name)


def text(name: str) -> Entity:
    return Entity.make(T.TEXT, fx(name))


def url(value: str) -> Entity:
    return Entity.make(T.URL, value.strip())


def epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def pivots(res, etype=None):
    return [p for p in res.pivots if etype is None or p.entity.type is etype]


def dump(res) -> str:
    findings = [{k: v for k, v in f.to_dict().items() if k != "entity"} for f in res.findings]  # 'entity' is the analyst's own input
    return json.dumps({"attributes": res.attributes, "raw": res.raw, "findings": findings,
                       "pivots": [p.to_dict() for p in res.pivots], "error": res.error}, default=str)


# ------------------------------------------------------------------ contract and offline guarantees (c1, c2)
def test_metadata_offline_open_default():
    cls = UrlUnwrap
    assert (cls.disclosure, cls.hosts, cls.provider, cls.terms, cls.opsec) == ("none", (), "", "open", Opsec.PASSIVE)
    assert cls.default_enabled is True and cls.trust_tier == "n/a" and cls.shares_input is False
    assert cls.accepts == frozenset({T.URL, T.TEXT})
    assert cls.manual_link == "url_unwrap:unfurl"


def test_module_file_has_no_network_code():
    tree = ast.parse(MODULE_FILE.read_text(encoding="utf-8"))
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module or "")
    assert not mods & {"socket", "ssl", "urllib.request", "http.client", "requests", "subprocess"}
    source = MODULE_FILE.read_text(encoding="utf-8")
    assert "https://dfir.blog" not in source and "hindsig.ht" not in source  # the Unfurl service is a pack link only (c2)


def test_runs_with_no_network_route_at_all():
    http = FakeHttp()  # any request would fail the test (unmatched route)
    res = run_module(UrlUnwrap, text("safelinks_recipient.txt"), http)
    assert res.status is Status.OK and http.calls == [] and res.requests == 0


def test_unfurl_manual_link_is_a_pack_link_only():
    rendered = links.render("url_unwrap:unfurl", url("https://payout.example.org/login"))
    assert rendered is not None and rendered.url.startswith("https://hindsig.ht/unfurl/?url=https%3A%2F%2Fpayout.example.org")
    assert links.render("url_unwrap:unfurl", Entity.make(T.DOMAIN, "example.org")) is None


# ------------------------------------------------------------------ c8: the recorded SafeLinks fixture
def test_safelinks_recorded_fixture():
    res = run_module(UrlUnwrap, text("safelinks_recorded.txt"), FakeHttp())
    assert res.status is Status.OK
    assert res.attributes["unwrapped_url"] == ["https://payout.example.org/login"]
    assert res.attributes["wrapper_hosts"] == ["nam12.safelinks.protection.outlook.com"]
    urls = {p.entity.value: p for p in pivots(res, T.URL)}
    assert set(urls) == {"https://payout.example.org/login"} and urls["https://payout.example.org/login"].relation == "mentions"
    domains = {p.entity.value for p in pivots(res, T.DOMAIN)}
    assert domains == {"payout.example.org"}  # the wrapper host is noise: never pivoted (c4)
    chain = res.attributes["unwrap_chain"][0]
    assert chain["steps"][0]["wrapper"] == "safelinks" and "data=REDACTED" in chain["steps"][0]["wrapped"]


def test_url_input_keeps_the_unwraps_to_relation():
    line = fx("safelinks_recorded.txt").split()[1]
    res = run_module(UrlUnwrap, url(line), FakeHttp())
    rel = {p.entity.value: p.relation for p in pivots(res, T.URL)}
    assert rel == {"https://payout.example.org/login": "unwraps_to"}
    assert [f.title for f in res.findings] == ["URL unwrapped from a link-protection wrapper"]
    assert res.findings[0].severity.label == "info"


# ------------------------------------------------------------------ c5: recipient identifiers are redacted
def test_safelinks_recipient_redaction():
    res = run_module(UrlUnwrap, text("safelinks_recipient.txt"), FakeHttp())
    blob = dump(res)
    for secret in ("victim", "example.com|", "0f0e0d0c0b0a49c8", "00000000aaaa4bbb", "U2lnbmF0dXJl"):
        assert secret not in blob, secret
    assert set(res.attributes["recipient_identifiers"]) >= {"recipient_email", "tenant_id", "message_id"}
    finding = next(f for f in res.findings if f.title.startswith("Recipient identifiers"))
    assert {"recipient_token", "privacy"} <= set(finding.tags)
    dest = pivots(res, T.URL)[0]
    assert dest.entity.value == "https://payout.example.org/login?ref=mail"
    assert dest.expand is True  # the destination itself carries no recipient token (only the wrapper did)
    step = res.attributes["unwrap_chain"][0]["steps"][0]
    assert step["facts"]["safelinks_time"] == "2026-11-24T13:00:05Z"


def test_destination_with_recipient_token_is_redacted_and_not_expanded():
    wrapped = "https://www.google.com/url?q=https%3A%2F%2Fpayout.example.org%2Flogin%3Femail%3Dvictim%2540example.com%26step%3D2"
    res = run_module(UrlUnwrap, url(wrapped), FakeHttp())
    dest = pivots(res, T.URL)[0]
    assert dest.entity.value == "https://payout.example.org/login?email=REDACTED_EMAIL&step=2"
    assert dest.expand is False and "never fetched automatically" in dest.note
    assert "victim" not in dump(res)


# ------------------------------------------------------------------ c1/c8: nesting
def test_safelinks_in_proofpoint_nesting():
    res = run_module(UrlUnwrap, text("safelinks_in_proofpoint.txt"), FakeHttp())
    chain = res.attributes["unwrap_chain"][0]
    assert [s["wrapper"] for s in chain["steps"]] == ["proofpoint_v2", "safelinks"]
    assert chain["final_url"] == "https://payout.example.org/login?ref=nested"
    assert set(res.attributes["wrapper_hosts"]) == {"urldefense.proofpoint.com", "eur02.safelinks.protection.outlook.com"}
    blob = dump(res)
    for secret in ("victim", "0f0e0d0c0b0a49c8", "00000000aaaa4bbb", "Rcpt0Hash", "MsgHash"):
        assert secret not in blob, secret


def test_nested_wrappers_bounded_at_five_levels():
    res = run_module(UrlUnwrap, text("nested_6.txt"), FakeHttp())
    chain = res.attributes["unwrap_chain"][0]
    assert chain["depth"] == 5 and chain["truncated"] is True
    assert "deeper than 5" in res.findings[0].description
    full = U.unwrap_url(fx("nested_6.txt").strip(), max_depth=7)
    assert full["depth"] == 6 and full["final_url"] == "https://payout.example.org/deep"


# ------------------------------------------------------------------ wrapper families
def test_proofpoint_v2_and_v3():
    r2 = U.unwrap_url(fx("proofpoint_v2.txt").strip())
    assert r2["final_url"] == "https://payout.example.org/login?id=42&lang=pt-BR"
    assert "r=REDACTED" in r2["chain"][0]["wrapped_redacted"]
    r3 = U.unwrap_url(fx("proofpoint_v3.txt").strip())
    assert r3["final_url"] == "https://payout.example.org/start!page?k=$$$&lang=pt"
    assert r3["chain"][0]["wrapped_redacted"].endswith("!REDACTED!REDACTED$") and "RcptToken" not in json.dumps(r3["chain"])
    assert U.decode_proofpoint_v3("https://urldefense.com/v3/__https:/payout.example.org/a__;!!X!Y$") == ("https://payout.example.org/a", None)
    assert U.decode_proofpoint_v3("https://urldefense.com/v3/__https://h.example.org/x**C__;JCQkJA!!c!t$") == ("https://h.example.org/x$$$$", None)


def test_google_redirect_forms():
    a, b = U.unwrap_text(fx("google_redirect.txt"))
    assert a["final_url"] == "https://payout.example.org/login" and a["chain"][0]["facts"]["google_ust"] == "2026-11-25T09:46:40Z"
    assert b["final_url"] == "https://payout.example.org/promo"


def test_mimecast_gives_the_destination_domain_only():
    res = run_module(UrlUnwrap, text("mimecast.txt"), FakeHttp())
    assert not pivots(res, T.URL)
    doms = pivots(res, T.DOMAIN)
    assert [p.entity.value for p in doms] == ["payout.example.org"] and "domain only" in doms[0].note
    assert all("/s/REDACTED" in c["steps"][0]["wrapped"] for c in res.attributes["unwrap_chain"])


def test_linkedin_facebook_instagram():
    li, li2, fb, ig = U.unwrap_text(fx("linkedin_facebook.txt"))
    assert li["final_url"] == "https://payout.example.org/login" and li["recipient_token_flag"]
    assert "messageThreadUrn=REDACTED" in li["chain"][0]["wrapped_redacted"]
    assert li2["final_url"] == "https://payout.example.org/jobs"
    assert fb["final_url"] == "https://payout.example.org/promo?fbclid=REDACTED_TOKEN"
    assert "h=REDACTED" in fb["chain"][0]["wrapped_redacted"]
    assert "AT0Example" not in json.dumps({k: v for k, v in fb.items() if not k.endswith("_unredacted")})
    assert ig["final_url"] == "https://payout.example.org/bio"


def test_not_wrapped_url_is_empty():
    res = run_module(UrlUnwrap, url(fx("not_wrapped.txt")), FakeHttp())
    assert res.status is Status.EMPTY and not res.findings and not res.pivots


def test_malformed_wrappers_never_raise():
    out = U.unwrap_text(fx("malformed.txt"))
    assert len(out) == 4
    assert "replacement bytes exhausted" in out[0]["errors"][0] and out[0]["final_url"] is None
    assert "without url parameter" in out[1]["errors"][0] and "victim" not in json.dumps(out[1])
    assert out[3]["final_url"].startswith("https://payout.example.org/")
    for bad in (None, "", "   ", "not a url", "https://", "http://[::1", 42):
        assert U.unwrap_url(bad)["wrapped"] is False


def test_undecodable_wrapper_url_is_an_error_not_empty():
    res = run_module(UrlUnwrap, url("https://nam12.safelinks.protection.outlook.com/?data=05%7C02%7Cvictim%40example.com%7C00&reserved=0"), FakeHttp())
    assert res.status is Status.ERROR and "could not be decoded" in res.error
    assert "victim" not in dump(res)


# ------------------------------------------------------------------ c6: WhatsApp / Telegram hand-offs
def test_wame_and_whatsapp_decode_to_phone():
    res = run_module(UrlUnwrap, text("whatsapp_telegram.txt"), FakeHttp())
    phones = {p.entity.value: p for p in pivots(res, T.PHONE)}
    assert set(phones) == {"+551155550123", "+551155550145", "+551155550177"}
    assert all(p.expand is False for p in res.pivots if p.entity.type in (T.PHONE, T.TELEGRAM_HANDLE, T.TELEGRAM_INVITE))
    assert "region assumed" in phones["+551155550177"].note and "analyst selection" in phones["+551155550123"].note
    handles = {p.entity.value for p in pivots(res, T.TELEGRAM_HANDLE)}
    assert handles == {"example_channel", "example_news"}
    invites = {p.entity.value for p in pivots(res, T.TELEGRAM_INVITE)}
    assert invites == {"AbCdEfGhIjKlMnOp", "AAAAAEexampleInviteCode"}
    assert U.personal_pivot_from_url("https://t.me/share/url?url=x") is None


def test_phone_normalisation():
    assert U.normalise_phone_e164("+55 11 5555-0123") == {"e164": "+551155550123", "region_assumed": False}
    assert U.normalise_phone_e164("(11) 95555-0123") == {"e164": "+5511955550123", "region_assumed": True}
    assert U.normalise_phone_e164("0") is None and U.normalise_phone_e164("abc") is None


# ------------------------------------------------------------------ c1: Unfurl-style decoding
def test_unfurl_style_decoders():
    exp = fx("unfurl_params.expected.json")
    res = U.unwrap_text(fx("unfurl_params.txt"))
    tw, dc, tt, ts, b64e, em, b64u, v1, v7, tok = res
    assert tw["decoded"][0]["kind"] == "twitter_snowflake"
    assert epoch(tw["decoded"][0]["iso"]) * 1000 == exp["twitter_ms"]
    assert [d["kind"] for d in dc["decoded"]] == ["discord_snowflake"] * 3
    assert epoch(tt["decoded"][0]["iso"]) == exp["tiktok_s"]
    assert [d["kind"] for d in ts["decoded"]] == ["unix_seconds", "unix_ms"]
    assert b64e["decoded"] == [{"where": "query:e", "kind": "base64_email", "redacted": True}]
    assert em["final_url"] == "https://payout.example.org/login?email=REDACTED_EMAIL&step=2"
    assert b64u["decoded"][0] == {"where": "query:next", "kind": "base64_url", "value": "https://bank.example.org/login"}
    assert v1["decoded"][0]["kind"] == "uuid_v1" and v1["decoded"][0]["iso"] == "2026-11-24T12:00:00Z"
    assert v7["decoded"][0]["kind"] == "uuid_v7" and tok["decoded"][0]["kind"] == "opaque_token"


def test_url_input_records_decoded_params():
    res = run_module(UrlUnwrap, url("https://payout.example.org/track?ts=1795600000"), FakeHttp())
    assert res.status is Status.OK
    assert res.attributes["url_decoded_params"] == [{"where": "query:ts", "kind": "unix_seconds", "value": "1795600000",
                                                     "iso": "2026-11-25T09:46:40Z", "confidence": "probable"}]


# ------------------------------------------------------------------ c4: wrapper hosts are noise
def test_wrapper_hosts_are_noise():
    for host in ("nam12.safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com", "protect-eu.mimecast.com",
                 "url.uk.m.mimecastprotect.com", "linkprotect.cudasvc.com"):
        assert U.is_wrapper_host(host), host
        assert noise.is_noise(Entity.make(T.DOMAIN, host)), host
    assert not U.is_wrapper_host("payout.example.org") and not U.is_wrapper_host("www.google.com")
    assert U.match_wrapper("https://www.google.com/url?q=https://x.example") == "google_redirect"
    assert U.match_wrapper("https://www.google.com/search?q=x") is None


def test_extract_urls_trims_and_keeps_the_v3_terminator():
    t = "see (https://a.example/x). and https://urldefense.com/v3/__https://b.example/__;!!c!t$. www.c.example/p, wa.me/551155550123"
    assert U.extract_urls(t) == ["https://a.example/x", "https://urldefense.com/v3/__https://b.example/__;!!c!t$",
                                 "https://www.c.example/p", "https://wa.me/551155550123"]


def test_text_without_wrappers_is_empty():
    res = UrlUnwrap().run(Entity.make(T.TEXT, "nothing to see at https://example.org/page"), make_ctx(UrlUnwrap))
    assert res.status is Status.EMPTY


def test_acceptance_golden_url_needs_no_route():
    """AR21 golden path: url_unwrap is offline, so its route file is empty and the run sends nothing."""
    doc = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "acceptance" / "url" / "url_unwrap.json").read_text(encoding="utf-8"))
    assert doc == {"schema": "v3lum.acceptance_routes/1", "module": "url_unwrap", "routes": []}
    http = FakeHttp()
    res = run_module(UrlUnwrap, "url:https://example.com/", http)
    assert http.calls == [] and res.status in (Status.EMPTY, Status.OK)
