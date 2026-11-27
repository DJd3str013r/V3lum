"""telegram_channel_watch (P357): one bounded watch cycle over public t.me/s previews, local matching, scrubbing.

Fixtures in tests/fixtures/telegram_channel_watch/ (prep batch p2-G09-2): ``tme_s_channel_ok.html`` /
``tme_s_channel_page2_ok.html`` are real captures of the official @telegram channel (2026-11-26; Telegram CDN
tokens replaced by REDACTED, media never fetched); ``tme_generic_contact_page.html`` is the real generic
'Telegram: Contact @x' page of a random missing handle; ``tme_s_redirect_302.json`` records the observed
302 of t.me/s/<missing>. Synthetic by design (P357 cond 8): ``tme_s_post_pan_cpf_docshape.html`` (a post with
a PAN and a CPF - documentation values only: PAN 4111 1111 1111 1111, CPF 123.456.789-09, +55 11 5555-01xx,
example.com/org), ``team_watch_list_docshape.json``, ``org_profile_docshape.json`` and
``deepdarkcti_telegram_list_docshape.md`` (structure-faithful; the GPL list itself is never vendored).
Offline replays use a fake clock (cond 8).
"""

from __future__ import annotations

import datetime as dt
import json

from tests.fakes import FIXTURES, FakeClock, FakeHttp, assert_no_secret, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.darkweb_ransomware import telegram_channel_watch as tw
from v3lum.modules.darkweb_ransomware.telegram_channel_watch import TelegramChannelWatch

FX = FIXTURES / "telegram_channel_watch"
ORG = OrgProfile.from_dict({
    "brands": [{"keyword": "Exemplo Bank", "variants": ["exemplo"]}],
    "domains": [{"name": "example.com", "verification": "txt_verified"}, {"name": "exêmplo.example.net", "verification": "attested",
                                                                            "attested_by": "analyst", "attested_date": "2026-11-01"}],
    "cnpj_roots": ["11222333"],
    "card_bins": ["411111"],
    "suppliers": [{"name": "ACME Pagamentos", "domains": ["acme-pagamentos.example"]}],
    "executives": [{"name": "Fulano de Tal", "opt_in": True, "programme": "VIP protection", "informed_at": "2026-11-01"}],
})
NO_DDC = {"telegram_channel_watch_use_deepdarkcti": False}


def html(name: str) -> dict:
    return {"body": (FX / name).read_bytes(), "headers": {"content-type": "text/html; charset=utf-8"}}


def team_file(tmp_path, data=None) -> str:
    p = tmp_path / "telegram_watch.json"
    p.write_text(json.dumps(data if data is not None else json.loads((FX / "team_watch_list_docshape.json").read_text())), encoding="utf-8")
    return str(p)


def settings(tmp_path, **extra) -> dict:
    return {"telegram_channel_watch_list_path": team_file(tmp_path), **NO_DDC, **extra}


def run(http, tmp_path, clock=None, **kw):
    s = kw.pop("settings", None) or settings(tmp_path)
    return run_module(TelegramChannelWatch, "keyword:exemplo", http, settings=s, org_profile=kw.pop("org_profile", ORG),
                      clock=clock or FakeClock(), **kw)


def fraud_routes(http: FakeHttp) -> FakeHttp:
    http.add("GET", "https://t.me/s/example_fraud_br", **html("tme_s_post_pan_cpf_docshape.html"))
    http.add("GET", "https://t.me/s/example_market", **html("tme_generic_contact_page.html"))
    return http


# ------------------------------------------------------------------ metadata (cond 1, chair rationale)
def test_metadata_watch_only_and_council_values():
    cls = TelegramChannelWatch
    assert {"watch_only", "watch_source"} <= set(cls.tags) and cls.default_enabled is False
    assert cls.terms == "open" and cls.trust_tier == "trusted" and cls.opsec is Opsec.PASSIVE and cls.shares_input is True
    assert cls.hosts == ("t.me",) and cls.min_interval >= tw.TME_MIN_INTERVAL_S and cls.provider == "telegram"
    assert cls.max_requests == tw.WATCH_MAX_CHANNELS * tw.TME_MAX_PAGES
    assert cls.accepts == {T.KEYWORD, T.DOMAIN, T.ORG, T.CARD_BIN, T.CNPJ} and cls.produces == {T.URL, T.DOMAIN, T.BTC, T.ETH}


def test_policy_gate_runs_it_only_inside_watch():
    from tests.fakes import make_runtime
    from v3lum.core.context import RunInfo, ScanOptions
    from v3lum.core.entities import Entity
    from v3lum.core.policy import decide, make_context

    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.KEYWORD, "exemplo")
    run_info = RunInfo(entity=ent, is_seed=True, depth=0, provenance=(), allowed_sources=frozenset(TelegramChannelWatch.sources), tlp="amber")
    scan = decide(TelegramChannelWatch, ent, make_context(rt, ScanOptions(), explicit=("telegram_channel_watch",), path="scan"), run=run_info)
    assert not scan.allowed and scan.reason_code == "not_applicable"
    watch = decide(TelegramChannelWatch, ent, make_context(rt, ScanOptions(), explicit=("telegram_channel_watch",), path="watch"), run=run_info)
    assert watch.rule_id != "POL-01"


# ------------------------------------------------------------------ channel list (cond 2)
def test_team_list_validation_requires_review_and_public_handles():
    doc = json.loads((FX / "team_watch_list_docshape.json").read_text())
    entries, problems = tw.validate_team_watch_list(doc, "2026-11-26")
    assert [e["handle"] for e in entries] == ["example_fraud_br", "example_market"]
    text = " ".join(problems)
    assert "review date 2026-10-01 passed" in text and "invite" in text and "reviewed_by.legal" in text and "justification" in text
    assert tw.validate_team_watch_list({"nope": 1}, "2026-11-26") == ([], ["team list has no 'channels' list"])
    bundled = json.loads((tw.Path(tw.__file__).parents[2] / "data" / tw.TEAM_LIST).read_text())
    assert bundled["channels"] == []  # ships empty: CTI lead and legal add reviewed entries


def test_deepdarkcti_parser_keeps_public_online_or_valid_only():
    parsed = tw.parse_deepdarkcti_telegram((FX / "deepdarkcti_telegram_list_docshape.md").read_bytes())
    picked = [c["handle"] for c in tw.select_deepdarkcti_channels(parsed)]
    assert picked == ["example_fraud_br", "example_market", "example_bins_br", "example_mirror_ch"]  # invites never
    kinds = {e["link_kind"] for e in parsed["entries"]}
    assert {"invite", "private_post", "invalid"} <= kinds and parsed["rows_skipped"] >= 2


def test_plan_rotates_caps_and_skips_paused():
    team = [{"handle": "team_one", "provenance": "team_list"}]
    ddc = [{"handle": f"ddc_chan_{i:03d}", "provenance": "deepdarkcti"} for i in range(120)]
    p0 = tw.plan_watch_cycle(team, ddc, cycle=0)
    p1 = tw.plan_watch_cycle(team, ddc, cycle=1)
    assert len(p0) == 50 and p0[0]["handle"] == "team_one" and p0[1]["handle"] != p1[1]["handle"]
    assert len(tw.plan_watch_cycle(team, ddc, max_channels=500)) == 50
    assert "ddc_chan_000" not in [c["handle"] for c in tw.plan_watch_cycle([], ddc, paused=["ddc_chan_000"])]
    now = dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc)
    assert tw.should_autopause("2026-10-27T00:00:00Z", now) and not tw.should_autopause("2026-11-20T00:00:00Z", now)


def test_next_page_before_bounds():
    posts = [{"post_id": i} for i in (441, 445, 452, 460)]
    assert tw.next_page_before(posts, 441, None, 1) is None  # first run: newest page only
    assert tw.next_page_before(posts, 441, 400, 1) == 441
    assert tw.next_page_before(posts, 441, 400, 3) is None  # <= 3 pages
    assert tw.next_page_before(posts, 441, 450, 1) is None  # older posts already seen


# ------------------------------------------------------------------ rules and matching (cond 4)
def test_rules_come_only_from_org_entries_and_never_from_people():
    rules = tw.build_watch_rules(ORG)
    kinds = sorted(r["kind"] for r in rules)
    assert kinds == ["bin", "brand", "cnpj_root", "domain", "domain", "supplier"]
    assert all(":" in r["id"] and "exemplo" not in r["id"] and "fulano" not in json.dumps(rules).lower() for r in rules)
    assert tw.build_watch_rules(OrgProfile.empty()) == []


def test_matching_is_local_folded_and_bin_needs_luhn_or_keyword():
    rules = tw.build_watch_rules(ORG)
    kinds = lambda text: sorted({h["kind"] for h in tw.match_post(text, rules)})  # noqa: E731
    assert kinds("promo EXÊMPLO bank hoje") == ["brand"]
    assert kinds("veja xn--exmplo-jva.example.net agora") == ["brand", "domain"]  # IDNA -> Unicode, accents folded
    assert kinds("login em https://pix.example.com/x") == ["domain"]
    assert kinds("card 4111 1111 1111 1111") == ["bin"]
    assert kinds("teste 4111 1111 1111 1112") == []  # not Luhn-valid
    assert kinds("lote 411111 sem palavra") == []  # bare digits never match
    assert kinds("BIN: 411111 aprovada") == ["bin"]
    assert kinds("CNPJ 11.222.333/0001-81") == ["cnpj_root"] and kinds("CNPJ 11.222.333/0001-80") == []
    assert kinds("pagamento via ACME Pagamentos") == ["supplier"]
    assert kinds("exemplobank") == []  # alphanumeric boundaries


# ------------------------------------------------------------------ scrubbing and alerts (cond 5, 7)
def test_scrub_reduces_pan_masks_cpf_drops_credentials_and_records():
    text = ("CC full 4111 1111 1111 1111 | 12/29 | 123\nCartao avulso 4111-1111-1111-1111 ok\nTitular CPF 123.456.789-09\n"
            "combo user@example.com:hunter2\nsenha: hunter3\ncliente@example.org | senha123 | 123.456.789-09 | +55 11 5555-0142\n"
            "bot 123456789:AAEexampleexampleexampleexampleexam\nAKIAIOSFODNN7EXAMPLE")
    out = tw.scrub_for_alert(text)
    t = out["text"]
    assert "411111******1111" in t and "4111-1111-1111-1111" not in t and "4111 1111 1111 1111" not in t
    assert "***.456.789-**" in t and "123.456.789-09" not in t
    for secret in ("hunter2", "hunter3", "senha123", "AAEexampleexample", "AKIAIOSFODNN7EXAMPLE", "5555-0142"):
        assert secret not in t
    assert out["dropped"] >= 3 and out["secrets"] >= 1


def test_excerpt_and_digest():
    scrubbed = "intro " * 60 + "Painel novo EXEMPLO BANK liberado" + " fim" * 60
    ex = tw.excerpt_for(scrubbed, "exemplo bank")
    assert len(ex) <= 200 and "EXEMPLO BANK" in ex
    assert tw.excerpt_for("nothing here", "exemplo bank") == tw.REMOVED_MATCH
    post = {"post_id": 7, "date": "2026-11-25T12:00:00Z", "url": "https://t.me/chan_one/7"}
    a1 = tw.make_alert("chan_one", post, {"rule_id": "brand:aa", "kind": "brand", "needle": "x"}, "team_list", "x")
    a2 = tw.make_alert("chan_two", post, {"rule_id": "bin:bb", "kind": "bin", "needle": "x"}, "deepdarkcti", "x")
    lines, keys = tw.digest_lines([a1, a2], seen_keys=[], muted_channels=["@chan_two"])
    assert keys == ["chan_one:7:brand:aa"] and lines[0].startswith("2026-11-25T12:00:00Z t.me/chan_one/7 [team_list] rule=brand:aa")
    assert tw.digest_lines([a1], seen_keys=keys)[0] == []
    assert tw.digest_lines([a1], muted_rules=["brand:aa"])[0] == []


# ------------------------------------------------------------------ the cycle (cond 1-7)
def test_cycle_alerts_scrubbed_pivots_and_could_not_read(tmp_path):
    http = fraud_routes(FakeHttp())
    res = run(http, tmp_path)
    assert res.status is Status.OK
    alerts = res.attributes["telegram_watch_alerts"]
    assert {a["rule_kind"] for a in alerts} == {"brand", "domain", "bin", "supplier", "cnpj_root"}
    assert {a["post_id"] for a in alerts} == {102} and all(a["provenance"] == "team_list" for a in alerts)
    assert all(len(a["excerpt"]) <= 200 for a in alerts) and len(res.attributes["telegram_watch_digest"]) == len(alerts)
    book = res.attributes["telegram_watch_cycle"]
    assert book["channels_read"] == 1 and book["could_not_read"] == ["example_market"] and book["posts_new"] == 3
    assert len(book["team_list_problems"]) == 3
    # nothing personal or secret leaves the scrubber
    blob = json.dumps(res.attributes, ensure_ascii=False)
    for value in ("4111 1111 1111 1111", "4111-1111-1111-1111", "123.456.789-09", "hunter2", "senha123", "fulano@", "5555-0123",
                  "AAEexampleexampleexample", "exemplo bank"):  # 'exemplo bank' = the org rule text: never in results
        assert value not in blob.replace("EXEMPLO BANK", "")
    assert_no_secret("hunter2", res.raw, res.findings, res.attributes)
    # hostile pivots from the matching post only, text only (media never fetched)
    piv = {(p.entity.type, p.entity.value): p for p in res.pivots}
    assert (T.BTC, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") in piv and (T.ETH, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") in piv
    assert all(p.relation == "mentioned_in_post" and p.note.startswith("hostile") for p in res.pivots)
    assert all(p.expand is True for p in res.pivots)  # under the 30/h enrichment cap
    f = res.findings[0]
    assert f.severity.label == "medium" and f.criterion and f.source == "telegram.web_preview"
    assert http.hosts() == {"t.me"} and all("telesco.pe" not in c["url"] for c in http.calls)
    http.assert_hosts_within(TelegramChannelWatch)


def test_second_cycle_reads_only_new_posts_and_respects_the_interval(tmp_path):
    clock = FakeClock()
    s = settings(tmp_path)
    first = run(fraud_routes(FakeHttp()), tmp_path, clock=clock, settings=s)
    assert first.status is Status.OK
    early = run(FakeHttp(), tmp_path, clock=clock, settings=s)
    assert early.status is Status.SKIPPED and "cycle not due" in early.error
    clock.advance(61 * 60)
    http = fraud_routes(FakeHttp())
    again = run(http, tmp_path, clock=clock, settings=s)
    assert again.status is Status.EMPTY  # posts <= last seen id: nothing new, no repeated alert
    assert again.attributes["telegram_watch_cycle"]["posts_new"] == 0


def test_rate_limit_stops_the_cycle_and_backs_off(tmp_path):
    clock = FakeClock()
    s = settings(tmp_path)
    http = FakeHttp().add("GET", "https://t.me/s/example_fraud_br", status=429, text="Too Many Requests")
    res = run(http, tmp_path, clock=clock, settings=s)
    assert res.status is Status.RATE_LIMITED and not any("example_market" in c["url"] for c in http.calls)
    clock.advance(5 * 60)
    http2 = FakeHttp()
    res2 = run(http2, tmp_path, clock=clock, settings=s)
    assert res2.status is Status.RATE_LIMITED and http2.calls == [] and "backing off" in res2.error
    clock.advance(20 * 60)  # back-off (15 min) over: the cycle is retried (it was never recorded as done)
    res3 = run(fraud_routes(FakeHttp()), tmp_path, clock=clock, settings=s)
    assert res3.status is Status.OK


def test_redirect_and_generic_page_are_could_not_read_never_absent(tmp_path):
    redirect = json.loads((FX / "tme_s_redirect_302.json").read_text())
    http = (FakeHttp()
            .add("GET", "https://t.me/s/example_fraud_br", status=302, headers={"location": "https://t.me/example_fraud_br"}, body=b"")
            .add("GET", "https://t.me/s/example_market", **html("tme_generic_contact_page.html")))
    res = run(http, tmp_path)
    assert redirect["status"] == 302
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert sorted(res.attributes["telegram_watch_cycle"]["could_not_read"]) == ["example_fraud_br", "example_market"]
    assert len(http.calls) == 2  # the redirect is never followed


def test_unreachable_for_30_days_is_auto_paused(tmp_path):
    clock = FakeClock()
    s = settings(tmp_path)
    gen = {"https://t.me/s/example_fraud_br": "tme_generic_contact_page.html", "https://t.me/s/example_market": "tme_generic_contact_page.html"}
    for _ in range(2):
        http = FakeHttp()
        for url, name in gen.items():
            http.add("GET", url, **html(name))
        run(http, tmp_path, clock=clock, settings=s)
        clock.advance(31 * 86400)
    http = FakeHttp()
    res = run(http, tmp_path, clock=clock, settings=s)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []
    assert sorted(res.attributes["telegram_watch_cycle"]["paused"]) == ["example_fraud_br", "example_market"]


def test_enrichment_cap_lists_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(tw, "ENRICH_MAX_PER_HOUR", 1)
    res = run(fraud_routes(FakeHttp()), tmp_path)
    expands = [p.expand for p in res.pivots]
    assert expands.count(True) == 1 and expands.count(False) >= 1
    assert any("enrichment cap" in p.note for p in res.pivots if not p.expand)


def test_pages_follow_before_up_to_three_on_later_cycles(tmp_path):
    clock = FakeClock()
    data = {"version": 1, "channels": [{"handle": "telegram", "justification": "official channel (test)", "owner": "cti-team",
                                        "review_date": "2027-05-01", "reviewed_by": {"cti_lead": "2026-11-01", "legal": "2026-11-03"}}]}
    s = {"telegram_channel_watch_list_path": team_file(tmp_path, data), **NO_DDC}
    org = OrgProfile.from_dict({"brands": [{"keyword": "telegram"}]})
    first = run(FakeHttp().add("GET", "https://t.me/s/telegram", **html("tme_s_channel_ok.html")), tmp_path, clock=clock, settings=s, org_profile=org)
    assert first.status is Status.OK and first.attributes["telegram_watch_cycle"]["pages_read"] == 1
    tw_state_last = max(a["post_id"] for a in first.attributes["telegram_watch_alerts"])
    assert tw_state_last == 460
    clock.advance(2 * 3600)
    http = (FakeHttp().add("GET", "https://t.me/s/telegram", **html("tme_s_channel_ok.html")))
    second = run(http, tmp_path, clock=clock, settings=s, org_profile=org)
    assert second.status is Status.EMPTY and len(http.calls) == 1


def test_no_rules_or_no_channels_is_a_configuration_skip(tmp_path):
    res = run(FakeHttp(), tmp_path, org_profile=OrgProfile.empty())
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    s = {"telegram_channel_watch_list_path": team_file(tmp_path, {"channels": []}), **NO_DDC}
    res2 = run(FakeHttp(), tmp_path, settings=s)
    assert res2.status is Status.SKIPPED and res2.reason_code == "config"


def test_deepdarkcti_channels_join_the_cycle(tmp_path, monkeypatch):
    md = (FX / "deepdarkcti_telegram_list_docshape.md").read_text()
    monkeypatch.setattr(tw, "load_deepdarkcti", lambda ctx: (tw.select_deepdarkcti_channels(tw.parse_deepdarkcti_telegram(md)), {"x": "ok"}))
    s = {"telegram_channel_watch_list_path": team_file(tmp_path, {"channels": []}), "telegram_channel_watch_max_channels": 1}
    http = FakeHttp().add("GET", "https://t.me/s/example_fraud_br", **html("tme_s_post_pan_cpf_docshape.html"))
    res = run(http, tmp_path, settings=s)
    assert res.status is Status.OK and {a["provenance"] for a in res.attributes["telegram_watch_alerts"]} == {"deepdarkcti"}
