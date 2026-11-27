"""Offline tests of telegram_public (P112): presence and kind, the generic page rule, posts, ingestion
scrubbing, indicators, limits, could-not-verify statuses and the shared t.me helpers.

Fixtures: tests/fixtures/telegram_public/ (real t.me captures plus synthetic pages with documentation
values; see the README there). Secret-shaped strings are built here at run time, never committed.
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.username_social import telegram_public as tp
from v3lum.modules.username_social.telegram_public import TelegramPublic

FIX = "telegram_public"
CONTROL = "qz7k2v9m4p1w8n3x5c6b"
#: secret-shaped test values (fake), assembled at run time so no token-like string is committed
BOT_TOKEN = "123456789:" + "AAH" + "exampleEXAMPLE" * 2 + "0000"
WEBHOOK_PATH = "123456789012345678/" + "EXAMPLEexample" * 2 + "EXAMPLE"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\">x</div></body></html>"


def page(name: str) -> str:
    text = module_fixture(FIX, name)
    return text.replace("{{TG_BOT_TOKEN}}", BOT_TOKEN).replace("{{DISCORD_WEBHOOK_PATH}}", WEBHOOK_PATH)


def tme(http: FakeHttp, path: str, name: str | None = None, *, text: str | None = None, status: int = 200, **kw) -> FakeHttp:
    return http.add("GET", "https://t.me/" + path, text=page(name) if name else text, status=status, **kw)


def ioc_channel_http() -> FakeHttp:
    http = FakeHttp()
    tme(http, "examplecti", "examplecti_profile.html")
    tme(http, "s/examplecti", "channel_posts_ioc.html")
    tme(http, "s/examplecti?before=1001", "examplecti_older.html")
    return http


def org() -> OrgProfile:
    return OrgProfile.from_dict({"brands": [{"keyword": "Banco Exemplo"}], "card_bins": ["411111"]})


def dump(res) -> str:
    """Every string a result carries (attributes, raw evidence, findings, pivots, links, errors)."""
    data = {
        "attributes": res.attributes, "raw": res.raw, "error": res.error, "links": res.links,
        "findings": [f.to_dict() for f in res.findings], "pivots": [p.to_dict() for p in res.pivots],
        "source_statuses": res.source_statuses,
    }
    return json.dumps(data, ensure_ascii=False, default=str)


def requested_paths(http: FakeHttp) -> list[str]:
    return [urlsplit(u).path + (("?" + urlsplit(u).query) if urlsplit(u).query else "") for u in http.urls()]


# ======================================================================================
# presence and kind (cond 2-3)
# ======================================================================================


def test_channel_profile_then_two_preview_pages_default_preset():
    http = FakeHttp()
    tme(http, "telegram", "channel.html")
    tme(http, "s/telegram", "channel_posts.html")
    tme(http, "s/telegram?before=441", "channel_posts_truncated.html")
    res = run_module(TelegramPublic, "telegram_handle:telegram", http)
    assert res.status is Status.OK, res.error
    assert res.attributes["presence"]["state"] == "found" and res.attributes["presence"]["marker"] == "tgme_page_title"
    assert res.attributes["account_type"] == "channel" and res.attributes["display_name"] == "Telegram News"
    assert res.attributes["subscribers"] == 9051510 and res.attributes["verified"] is True and res.attributes["has_preview"] is True
    # pages overlap in the fixture: posts are deduplicated by id across pages
    assert res.attributes["posts_read"] == 5
    assert requested_paths(http) == ["/telegram", "/s/telegram", "/s/telegram?before=441"]
    # the official channel only links to Telegram itself: everything is warninglisted
    assert res.pivots == [] and not any(f.title.startswith("Indicators") for f in res.findings)
    assert res.attributes["ioc_summary"]["summary"] == "no indicators in 5 posts"
    http.assert_hosts_within(TelegramPublic)


def test_user_profile_yields_presence_and_display_name_only():
    http = FakeHttp()
    tme(http, "botsupport", "user.html")
    res = run_module(TelegramPublic, "telegram_handle:BotSupport", http)
    assert res.status is Status.OK
    assert set(res.attributes) == {"presence", "account_type", "display_name"}
    assert res.attributes["account_type"] == "user" and res.attributes["display_name"] == "Bot Support"
    assert "Support for Mini App" not in dump(res)  # the bio of a personal profile is never kept (cond 3)
    assert requested_paths(http) == ["/botsupport"]  # posts are read for channels only


def test_bot_and_group_profiles_are_classified_and_never_paged():
    http = FakeHttp()
    tme(http, "botfather", "bot.html")
    tme(http, "pythontelegrambotgroup", "group.html")
    bot = run_module(TelegramPublic, "telegram_handle:BotFather", http)
    assert bot.attributes["account_type"] == "bot" and bot.attributes["monthly_users"] == 7956800
    group = run_module(TelegramPublic, "username:pythontelegrambotgroup", http)
    assert group.attributes["account_type"] == "group"
    assert group.attributes["members"] == 9844 and group.attributes["online_members"] == 731
    assert requested_paths(http) == ["/botfather", "/pythontelegrambotgroup"]


def test_generic_contact_page_is_unknown_never_absent():
    """HTTP 200 for any handle: without tgme_page_title the run is 'could not read' (cond 2)."""
    http = FakeHttp()
    tme(http, CONTROL, "generic_contact.html")
    res = run_module(TelegramPublic, f"telegram_handle:{CONTROL}", http)
    assert res.status is Status.ERROR and res.reason_code == "error"
    assert res.status is not Status.EMPTY
    assert tp.TME_GENERIC_REASON in res.error
    assert res.attributes["presence"]["state"] == "unknown"
    assert "absent" not in dump(res)


def test_private_channel_redirect_is_no_preview():
    """Real capture: t.me/s/<missing or private> answers 302 to the generic page (fixture envelope)."""
    env = module_fixture(FIX, "private_channel.http.json")
    http = FakeHttp()
    http.add("GET", env["request_url"], status=env["history"][0]["status"], redirect_to=env["history"][0]["location"])
    http.add("GET", env["final_url"], text=env["body"])
    ctx = make_ctx(TelegramPublic, http, entity=f"telegram_handle:{CONTROL}")
    parsed = tp.fetch_tme_page(ctx, env["request_url"], kind="posts", handle=CONTROL)
    assert parsed["state"] == "UNKNOWN" and parsed["reason"] == tp.NO_PREVIEW_REASON and parsed["posts"] == []


def test_channel_without_public_preview_redirects_to_profile():
    http = FakeHttp()
    tme(http, "telegram", "channel.html")
    http.add("GET", "https://t.me/s/telegram", redirect_to="https://t.me/telegram")
    res = run_module(TelegramPublic, "telegram_handle:telegram", http)
    assert res.status is Status.OK
    assert res.attributes["has_preview"] is False and "posts_read" not in res.attributes
    assert tp.NO_PREVIEW_REASON in res.error


# ======================================================================================
# posts: scrubbing, digest, pivots, findings (cond 4-9)
# ======================================================================================


def test_channel_posts_scrubbed_digest_pivots_and_findings():
    http = ioc_channel_http()
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http, org_profile=org())
    assert res.status is Status.OK, res.error
    assert res.attributes["posts_read"] == 6
    summary = res.attributes["ioc_summary"]
    assert summary["summary"] == "4 URLs, 5 domains, 2 IPs, 2 wallets, 1 onion, 2 invites from 6 posts"
    assert all(len(v) <= 5 for v in summary["top"].values())
    assert "198[.]51[.]100[.]23" in summary["top"]["ip"]
    got = {(p.entity.type, p.entity.value) for p in res.pivots if p.relation == "mentioned_in_post"}
    assert {
        (T.URL, "https://login-bancoexemplo.example.net/secure/index.php"), (T.URL, "https://secure-bancoexemplo.example.net/login"),
        (T.URL, "https://news.example.com/article/123"), (T.URL, "http://mirror-exemplo.example.org/kit.zip"),
        (T.DOMAIN, "pagamento-exemplo.example.org"), (T.IPV4, "198.51.100.23"), (T.IPV4, "203.0.113.77"),
        (T.BTC, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), (T.ETH, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"),
        (T.ONION, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"),
        (T.TELEGRAM_INVITE, "AbCdEfGhIjKlMnOp"), (T.DISCORD_INVITE, "example123"),
    } <= got
    # warninglisted: Telegram family on every path, big platforms as domains/bare-host URLs (AR06)
    assert not any("t.me" in v or "youtube.com" in v or v == "discord.gg" for _t, v in got)
    # the masked e-mail never yields its domain
    assert (T.DOMAIN, "example.com") not in got
    for p in res.pivots:
        assert p.expand is False  # cond 7/8: never auto-expanded
    mentioned = [p for p in res.pivots if p.relation == "mentioned_in_post"]
    assert all(p.confidence_label.value == "possible" and "never visited" in p.note for p in mentioned)
    fwd = [p for p in res.pivots if p.relation == "forwarded_from"]
    assert [(p.entity.type, p.entity.value) for p in fwd] == [(T.TELEGRAM_HANDLE, "exampleleaks")]
    titles = {f.title: f for f in res.findings}
    assert titles["Indicators in public Telegram posts"].severity.label == "info"
    exposure = titles["Bot tokens or webhook URLs posted in a public channel"]
    assert exposure.severity.label == "medium" and "credential_exposure" in exposure.tags
    assert titles["Payment card numbers posted in a public channel"].data["bins"] == ["411111"]
    assert titles["Organisation card BINs in public Telegram posts"].severity.label == "high"
    assert titles["Leaked personal or credential records posted in a public channel"].data["drop_reasons"] == {
        "leaked record": 3, "combo list line": 1, "credential line": 1}
    assert titles["Organisation brand mentioned in public Telegram posts"].severity.label == "low"
    assert res.attributes["brand_mentions"] == [{"term": "banco exemplo", "posts": [1001, 1005]}]
    assert res.attributes["post_scrubbing"]["pans_truncated"] == 1 and res.attributes["post_scrubbing"]["cpfs_redacted"] == 1
    assert res.attributes["bio"] == "Example channel used by V3LUM tests. Ads: a***@example.com"
    http.assert_hosts_within(TelegramPublic)


def test_no_personal_data_secret_or_media_survives_into_the_result():
    """cond 5/8/9: scrubbing before evidence and reports; secrets as type + SHA-256 prefix only."""
    res = run_module(TelegramPublic, "telegram_handle:examplecti", ioc_channel_http(), org_profile=org())
    blob = dump(res)
    for gone in ("4111111111111111", "4111 1111 1111 1111", "123.456.789-00", "98765432199", "5555-0123", "5555-0199",
                 "victim@example.com", "other@example.com", "ads@example.com", "Senha123", "hunter2", "Fulano", "EXAMPLE HOLDER",
                 BOT_TOKEN, "AAHexample", WEBHOOK_PATH, "api/webhooks", "webhook.site/0000", "telesco.pe", "telegram.org/img",
                 "stealer_logs_example.zip", "Example Person"):
        assert gone not in blob, gone
    exposures = res.attributes["bot_webhook_exposures"]
    assert {e["kind"] for e in exposures} == {"telegram_bot_api_url", "discord_webhook_url", "webhook_url", "telegram_bot_token"}
    token_entry = next(e for e in exposures if e["kind"] == "telegram_bot_token")
    assert token_entry["sha256_prefix"] == hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:12]


def test_evidence_records_excerpts_and_report_quotes_are_capped():
    """cond 6: post id, date, URL, excerpt <= 300 chars each side and <= 1,000 per post, quote <= 200."""
    res = run_module(TelegramPublic, "telegram_handle:examplecti", ioc_channel_http(), org_profile=org())
    records = res.raw["records"]
    assert [r["post_id"] for r in records] == [1001, 1003, 1005, 1000]  # posts without a match are not kept
    for r in records:
        assert set(r) >= {"post_id", "date", "url", "excerpt", "report_quote"}
        assert r["excerpt"] and len(r["excerpt"]) <= tp.EXCERPT_CAP
        assert r["report_quote"] and len(r["report_quote"]) <= tp.QUOTE_CAP
    long_post = next(r for r in records if r["post_id"] == 1005)
    assert len(long_post["excerpt"]) == 1000 and " … " in long_post["excerpt"]
    quote = records[0]["report_quote"]
    assert "198[.]51[.]100[.]23" in quote and "pagamento-exemplo[.]example[.]org" in quote and "https://" not in quote
    assert "[[" not in quote
    assert res.raw["pages"] == ["https://t.me/s/examplecti", "https://t.me/s/examplecti?before=1001"]


def test_only_profile_and_preview_urls_are_ever_requested():
    """cond 1/8/10: no media, file, og:image, link preview or post link is ever fetched."""
    http = ioc_channel_http()
    run_module(TelegramPublic, "telegram_handle:examplecti", http, org_profile=org())
    assert http.urls() == ["https://t.me/examplecti", "https://t.me/s/examplecti", "https://t.me/s/examplecti?before=1001"]
    for url in http.urls():
        assert tp.tme_fetch_allowed(url) and not tp.is_media_url(url)


def test_deep_preset_reads_three_pages_and_default_two():
    http = FakeHttp()
    tme(http, "telegram", "channel.html")
    tme(http, "s/telegram", "channel_posts.html")
    tme(http, "s/telegram?before=441", "examplecti_older.html")
    tme(http, "s/telegram?before=1000", "channel_posts_truncated.html")
    res = run_module(TelegramPublic, "telegram_handle:telegram", http, options=ScanOptions(preset="deep"))
    assert res.status is Status.OK
    assert requested_paths(http) == ["/telegram", "/s/telegram", "/s/telegram?before=441", "/s/telegram?before=1000"]
    assert TelegramPublic.max_requests == 1 + tp.DEEP_PAGES and tp.DEFAULT_PAGES == 2


def test_scrubbed_results_are_cached_in_memory_and_raw_pages_never_reach_the_http_cache():
    http = ioc_channel_http()
    rt = make_runtime(http, cache=True, org_profile=org())
    first = run_module(TelegramPublic, "telegram_handle:examplecti", runtime=rt)
    assert first.requests == 3
    assert rt.http.cache.stats()["entries"] == 0  # cond 5: raw t.me HTML is never cached
    second = run_module(TelegramPublic, "url:https://t.me/s/examplecti", runtime=rt)
    assert second.requests == 0 and second.status is Status.OK  # cond 4: 1 h, scrubbed, in memory
    assert second.attributes["ioc_summary"] == first.attributes["ioc_summary"]
    assert len(http.calls) == 3


# ======================================================================================
# could not verify (rule 5) and limits
# ======================================================================================


def test_rate_limited_profile_is_rate_limited():
    http = FakeHttp()
    tme(http, "examplecti", text="Too Many Requests", status=429)
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_rate_limit_on_page_two_keeps_page_one_partial():
    http = FakeHttp()
    tme(http, "examplecti", "examplecti_profile.html")
    tme(http, "s/examplecti", "channel_posts_ioc.html")
    tme(http, "s/examplecti?before=1001", text="Too Many Requests", status=429)
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http)
    assert res.status is Status.OK and res.partial is True and res.stop_reason == "rate_limited"
    assert res.attributes["posts_read"] == 5 and "preview page 2" in res.error


def test_challenge_page_is_blocked_never_absent():
    http = FakeHttp()
    tme(http, "examplecti", text=CHALLENGE, status=403)
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_server_error_is_error():
    http = FakeHttp()
    tme(http, "examplecti", text="bad gateway", status=502)
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http)
    assert res.status is Status.ERROR


def test_not_a_tme_page_in_a_200_is_could_not_read():
    http = FakeHttp()
    tme(http, "examplecti", text='{"ok": true}')
    res = run_module(TelegramPublic, "telegram_handle:examplecti", http)
    assert res.status is Status.ERROR and "could not read" in res.error
    assert res.attributes["presence"]["state"] == "unknown"


def test_page_over_the_2mb_cap_is_cut_and_flagged():
    big = page("channel.html") + "<!--" + "x" * (tp.TME_PAGE_CAP + 10) + "-->"
    http = FakeHttp()
    tme(http, "botsupport", text=big.replace("Telegram: View @telegram", "Telegram: Contact @BotSupport")
        .replace("subscribers", "").replace("/s/telegram", "/x"))
    res = run_module(TelegramPublic, "telegram_handle:botsupport", http)
    assert res.status is Status.OK and "2 MB" in res.error
    assert http.calls[0]["max_bytes"] == tp.TME_PAGE_CAP


def test_malformed_truncated_page_keeps_partial_posts():
    parsed = tp.parse_tme_channel_posts(page("channel_posts_truncated.html"))
    assert parsed["state"] == "FOUND" and parsed["partial"] is True and "truncated" in parsed["reason"]
    assert [p["post_id"] for p in parsed["posts"]] == [441, 445, 452] and parsed["posts"][-1]["partial"] is True


@pytest.mark.parametrize("raw", [None, 123, b"\xff\xfe\x00", "", "   ", '{"json": 1}', [], {"a": 1},
                                 "<html><body><div class='tgme_page_title'", "<<<>>>"])
def test_parsers_never_raise_on_garbage(raw):
    assert tp.parse_tme_profile(raw)["state"] in ("FOUND", "UNKNOWN")
    assert isinstance(tp.parse_tme_channel_posts(raw)["posts"], list)
    assert tp.scrub_post_text(raw)["text"] in ("", raw)


# ======================================================================================
# inputs and applicability (cond 1, 4)
# ======================================================================================


@pytest.mark.parametrize("value,handle", [
    ("@telegram", "telegram"), ("telegram", "telegram"), ("t.me/telegram", "telegram"), ("https://t.me/s/telegram", "telegram"),
    ("https://telegram.me/telegram", "telegram"), ("https://t.me/telegram/441", "telegram"),
    ("https://t.me/+AbCdEfGhIjKlMnOp", None), ("https://t.me/joinchat/AbCdEfGhIjKl", None), ("https://t.me/addstickers/x", None),
    ("https://example.com/telegram", None), ("abc", None), (None, None),
])
def test_handles_from_typed_values_and_links(value, handle):
    assert tp.tme_handle(value) == handle


def test_username_pivots_are_not_applicable_but_typed_usernames_and_links_are():
    http = FakeHttp()
    pivot = run_module(TelegramPublic, "username:examplecti", http, is_seed=False)
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "not_applicable" and http.calls == []
    invite = run_module(TelegramPublic, "url:https://t.me/+AbCdEfGhIjKlMnOp", http)
    assert invite.status is Status.SKIPPED and http.calls == []  # invites are never fetched (cond 1)
    tme(http, "botsupport", "user.html")
    link = run_module(TelegramPublic, "url:https://t.me/BotSupport", http, is_seed=False)  # t.me links found in the case
    assert link.status is Status.OK


def test_fetch_guard_only_allows_profile_and_preview_urls():
    assert tp.tme_fetch_allowed("https://t.me/examplecti") and tp.tme_fetch_allowed("https://t.me/s/examplecti?before=1001")
    for bad in ("https://cdn4.telesco.pe/file/EXAMPLEMEDIA.jpg", "https://t.me/+AbCdEfGhIjKlMnOp", "https://t.me/examplecti/1001",
                "http://t.me/examplecti", "https://t.me/s/examplecti?q=x", "https://telegram.org/img/emoji/40/F09F9880.png",
                "https://t.me/addstickers/Example", None):
        assert not tp.tme_fetch_allowed(bad), bad
    with pytest.raises(ValueError):
        tp.fetch_tme_page(make_ctx(TelegramPublic, FakeHttp()), "https://cdn4.telesco.pe/file/x.jpg", kind="profile")


def test_parser_never_emits_media_urls():
    """cond 8/10: og:image, avatars, photos, videos, emoji and link-preview images never leave the parser."""
    for name in ("channel.html", "bot.html", "user.html", "group.html", "generic_contact.html", "channel_posts.html",
                 "channel_posts_ioc.html", "channel_posts_truncated.html"):
        raw = page(name)
        assert "telesco.pe" in raw or "telegram.org/img" in raw
        out = json.dumps([tp.parse_tme_profile(raw), tp.parse_tme_channel_posts(raw)], default=str)
        assert "telesco.pe" not in out and "/img/emoji" not in out, name


# ======================================================================================
# shared helpers (P357 reuses them)
# ======================================================================================


def test_scrub_masks_and_drops_personal_data():
    post = tp.parse_tme_channel_posts(page("channel_posts_ioc.html"))["posts"][1]
    sc = tp.scrub_post_text(post["text"])
    assert sc["redactions"] == {"pan": 1, "cpf": 1, "email": 1, "phone": 1}
    assert sc["drop_reasons"] == {"leaked_record": 3, "combo": 1, "credential": 1} and sc["dropped"] == 5
    assert sc["bins"] == ["411111"]
    for kept in ("411111******1111", "***.456.789-**", "[phone ***23]", "v***@example.com", "Fresh CC base"):
        assert kept in sc["text"]
    for gone in ("4111111111111111", "123.456.789-00", "Senha123", "hunter2", "98765432199", "Fulano", "12/29"):
        assert gone not in sc["text"], gone


def test_scrub_secrets_are_type_and_sha256_prefix_only():
    post = tp.parse_tme_channel_posts(page("channel_posts_ioc.html"))["posts"][2]
    sc = tp.scrub_post_text(post["text"])
    assert [s["kind"] for s in sc["exposures"]] == ["telegram_bot_api_url", "discord_webhook_url", "webhook_url", "telegram_bot_token"]
    assert BOT_TOKEN not in sc["text"] and "api/webhooks" not in sc["text"] and sc["text"].count("[removed ") == 4
    assert tp.scrub_post_text("order 1234567890123 shipped")["redactions"]["pan"] == 0  # not Luhn-valid


def test_tme_count_forms():
    assert [tp.tme_count(v) for v in ("9 051 510", "9.05M", "1.75M", "12.3K", "1,5K", "3 400", "950", "x", "", None)] == [
        9051510, 9050000, 1750000, 12300, 1500, 3400, 950, None, None, None]


def test_selftest_reads_the_official_channel():
    http = FakeHttp()
    tme(http, "telegram", "channel.html")
    hc = TelegramPublic.health_check()
    assert hc.offline is False and callable(hc.selftest)
    result = hc.selftest(make_ctx(TelegramPublic, http))
    assert result.status == "ok"
    http2 = FakeHttp()
    tme(http2, "telegram", text="Too Many Requests", status=429)
    assert hc.selftest(make_ctx(TelegramPublic, http2)).status == "blocked"


def test_module_metadata_matches_the_council():
    assert TelegramPublic.default_enabled is True and TelegramPublic.terms == "open"
    assert TelegramPublic.trust_tier == "trusted" and TelegramPublic.hosts == ("t.me",)
    assert TelegramPublic.min_interval >= 2.0 and TelegramPublic.cache_ttl == 3600
    assert TelegramPublic.requires_keys == () and TelegramPublic.optional_keys == ()
