"""site_contacts (P077, LIGHT) and the shared contact extractor: offline tests.

Fixtures in tests/fixtures/site_contacts/ (prep p9-G03-2): SYNTHETIC pages built from documentation values
(example.com, +55 11 5555-01xx / 95555-01xx, the public placeholder CPF 123.456.789-09, CNPJ 11.222.333/0001-81) -
``home_synthetic.html`` (crawl plan: contact/about/footer links, refused pages), ``contato_synthetic.html`` (role vs
personal e-mails, tel:, wa.me, api.whatsapp, group invite, PIX CNPJ key, CNPJ text, JSON-LD, cfemail, obfuscation),
``fake_store_synthetic.html`` (hostile page: PIX CPF key, BR Code EVP key, personal 'zap'), ``many_links_synthetic.html``
(page cap) and robots.txt variants - plus ``real_role_phishstats.html``, a trimmed real homepage whose role contact
and social profiles are published only in JSON-LD and Cloudflare-encoded.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, add_dns, make_ctx, make_runtime, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import site_contacts as sc
from v3lum.modules.url_web.site_contacts import SiteContacts

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "site_contacts"
HOST = "www.example.com"
BASE = f"https://{HOST}"
IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
MINIMAL = "<html><head><title>Example</title></head><body><p>Texto institucional.</p></body></html>"
HOME_PAGES = ["/sobre-nos", "/institucional/quem-somos", "/contato", "/politica-de-privacidade", "/trabalhe-conosco", "/blog/"]


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def target(http: FakeHttp, host: str = HOST, ip: str = IP) -> None:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])


def target_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns.com" not in c["url"]]


def site(http: FakeHttp, robots: str | None = "robots_allow_all.txt", contato: str = "contato_synthetic.html") -> None:
    target(http)
    if robots is None:
        http.add("GET", f"{BASE}/robots.txt", status=404, text="not found")
    else:
        http.add("GET", f"{BASE}/robots.txt", text=fx(robots), headers={"content-type": "text/plain"})
    http.add("GET", f"{BASE}/", text=fx("home_synthetic.html"))
    for path in HOME_PAGES:
        http.add("GET", BASE + path, text=fx(contato) if path == "/contato" else MINIMAL)


def run(http: FakeHttp, value: str = f"domain:{HOST}", **kw):
    kw.setdefault("options", LIGHT)
    return run_module(SiteContacts, value, http, **kw)


def dump(res) -> str:
    return json.dumps({"a": res.attributes, "p": [(p.entity.type.value, p.entity.value, p.note) for p in res.pivots], "raw": res.raw,
                       "f": [f.title for f in res.findings]}, ensure_ascii=False, default=str)


# ------------------------------------------------------------------ metadata
def test_metadata_light_opt_in():
    cls = SiteContacts
    assert cls.opsec is Opsec.LIGHT and cls.disclosure == "target" and cls.hosts == () and cls.default_enabled is False
    assert cls.run_on == "seeds" and cls.terms == "open" and cls.max_rate == 1.0
    ctx = make_ctx(SiteContacts, FakeHttp(), entity=Entity.make(T.DOMAIN, "example.com"))
    assert cls.health_check().offline is True and cls.health_check().selftest(ctx).status == "ok"


# ------------------------------------------------------------------ crawl, extraction and the third-party policy
def test_role_contacts_kept_personal_contacts_only_counted():
    http = FakeHttp()
    site(http)
    res = run(http)
    assert res.status is Status.OK, res.error
    contacts = res.attributes["site_contacts"]
    emails = {e["address"] for e in contacts["emails"]}
    assert {"contato@example.com", "sac@example.com", "dpo@example.com", "ouvidoria@example.com", "security@example.com",
            "abuse@example.com", "imprensa@example.com", "comercial@example.com"} <= emails
    assert {"+551155550100", "+5540040101", "0800 555 0123"} <= {p["number"] for p in contacts["phones"]}
    assert contacts["whatsapp"] == [{"number": "+5511955550102", "kind": "mobile"}]  # 'WhatsApp atendimento'
    socials = {(s["platform"], s["handle"]) for s in contacts["social"]}
    assert {("instagram", "examplebr"), ("facebook", "examplebr"), ("youtube", "@examplebr"), ("tiktok", "examplebr"),
            ("telegram", "examplebr"), ("linkedin", "company/example-comercio")} <= socials
    assert "11.222.333/0001-81" in contacts["cnpjs"] and "12.345.678/0001-00" not in json.dumps(contacts)
    # FC5: personal e-mails/phones of natural persons on a legitimate site are counted, never stored or pivoted
    assert res.attributes["third_party_counts"] == {"personal_emails": 1, "personal_phones": 2}
    text = dump(res)
    for personal in ("fulana", "95555-0103", "5511955550103", "5511955550104", "fulano-de-tal"):
        assert personal not in text.lower(), personal
    # FC5/FC7: every pivot is expand=False (no mailbox checks, no breach/Gravatar sweeps)
    assert res.pivots and all(p.expand is False for p in res.pivots)
    kinds = {(p.entity.type, p.relation) for p in res.pivots}
    assert (T.EMAIL, "contact_email") in kinds and (T.CNPJ, "company_of") in kinds and (T.SOCIAL_ACCOUNT, "site_social_profile") in kinds
    assert (T.TELEGRAM_INVITE, "site_social_profile") in kinds


def test_crawl_bounds_robots_and_refusals():
    http = FakeHttp()
    site(http)
    res = run(http)
    urls = [c["url"] for c in target_calls(http)]
    assert urls[0] == f"{BASE}/robots.txt"
    assert set(urls[1:]) == {f"{BASE}/"} | {BASE + p for p in HOME_PAGES}
    assert {c["method"] for c in target_calls(http)} == {"GET"}
    for forbidden in ("/login", "/admin", "/minha-conta", "/busca", "/produto", "/newsletter", "loja.example.com", "example.net", ".pdf"):
        assert not [u for u in urls if forbidden in u], forbidden
    refused = {r["url"]: r["reason"] for r in res.attributes["crawl_summary"]["refused"]}
    assert "outside the seed host" in refused["https://loja.example.com/atendimento"]
    assert res.attributes["crawl_summary"]["pages_fetched"] == 7


def test_robots_disallowed_page_is_never_fetched():
    http = FakeHttp()
    site(http, robots="robots_disallow_contato.txt")
    res = run(http)
    assert f"{BASE}/contato" not in [c["url"] for c in target_calls(http)]
    refused = {r["url"]: r["reason"] for r in res.attributes["crawl_summary"]["refused"]}
    assert refused[f"{BASE}/contato"] == "disallowed by robots.txt"
    assert res.attributes.get("third_party_counts", {}) == {}


def test_robots_disallow_all_fetches_nothing():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", text=fx("robots_disallow_all.txt"), headers={"content-type": "text/plain"})
    res = run(http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert [c["url"] for c in target_calls(http)] == [f"{BASE}/robots.txt"]


def test_robots_5xx_is_full_disallow_and_could_not_verify():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=503, text="busy")
    res = run(http)
    assert res.status is Status.ERROR
    assert [c["url"] for c in target_calls(http)] == [f"{BASE}/robots.txt"] * len(target_calls(http))


def test_robots_404_and_html_soft_404_allow_all():
    for robots in (None, "robots_html_200_synthetic.html"):
        http = FakeHttp()
        site(http, robots=robots)
        assert run(http).status is Status.OK


def test_page_cap_is_ten_pages():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http.add("GET", f"{BASE}/", text=fx("many_links_synthetic.html"))
    http.add("GET", re.compile(re.escape(BASE) + r"/(contato|pagina-\d+)$"), text=MINIMAL)
    res = run(http)
    pages = [c["url"] for c in target_calls(http) if not c["url"].endswith("robots.txt")]
    assert len(pages) == 10 and len(set(pages)) == 10
    assert res.attributes["crawl_summary"]["capped"] > 0


# ------------------------------------------------------------------ FC6: own sites and hostile sites
def test_own_site_keeps_personal_contacts_as_privacy_mentions():
    http = FakeHttp()
    site(http)
    own = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    res = run(http, org_profile=own)
    mentions = res.attributes["privacy_mentions"]
    assert {"type": "email", "value": "fulana.de.tal@example.com", "privacy": True} in mentions
    assert all(m["privacy"] for m in mentions)
    assert not [p for p in res.pivots if p.entity.value == "fulana.de.tal@example.com"]


def _fake_store(http: FakeHttp) -> None:
    target(http, "oferta.example.org")
    http.add("GET", "https://oferta.example.org/robots.txt", status=404, text="")
    http.add("GET", "https://oferta.example.org/", text=fx("fake_store_synthetic.html"))


def test_hostile_site_with_recorded_purpose_gives_privacy_pivots_and_masks_cpf():
    http = FakeHttp()
    _fake_store(http)
    res = run(http, "domain:oferta.example.org", options=ScanOptions(mode=Opsec.LIGHT, purpose="fraud case 2026-117 (fake store)"))
    assert res.attributes["crawl_summary"]["site_class"] == "hostile"
    personal = {(p.entity.type, p.entity.value): p for p in res.pivots}
    assert (T.PHONE, "+5511955550199") in personal and (T.EMAIL, "lojaofertas.exemplo@example.net") in personal
    assert (T.PIX, "7d9f0335-8dcc-4054-9bf9-0dbd61d36906") in personal
    assert all(p.expand is False for p in res.pivots)
    assert "privacy" in personal[(T.PHONE, "+5511955550199")].note
    # CPF: never a pivot, only a masked privacy mention
    assert {"type": "pix_cpf", "value": "***.456.789-**", "privacy": True, "masked": True} in res.attributes["privacy_mentions"]
    assert not [p for p in res.pivots if p.entity.type is T.CPF]
    assert "123.456.789-09" not in dump(res) and "12345678909" not in dump(res)
    assert "FULANO" not in dump(res)  # the BR Code merchant name is never kept


def test_hostile_site_without_purpose_only_counts_personal_contacts():
    http = FakeHttp()
    _fake_store(http)
    res = run(http, "domain:oferta.example.org")
    assert res.attributes["crawl_summary"]["site_class"] == "hostile"
    assert not [p for p in res.pivots if p.entity.type in (T.PHONE, T.EMAIL, T.PIX)]
    assert res.attributes["third_party_counts"]["cpf_keys"] == 1
    assert "123.456.789-09" not in dump(res)


def test_real_role_page_json_ld_and_cloudflare_email():
    http = FakeHttp()
    target(http, "phishstats.info")
    http.add("GET", "https://phishstats.info/robots.txt", status=404, text="")
    http.add("GET", "https://phishstats.info/", text=fx("real_role_phishstats.html"))
    res = run(http, "domain:phishstats.info")
    contacts = res.attributes["site_contacts"]
    assert "contact@phishstats.info" in {e["address"] for e in contacts["emails"]}
    assert ("x", "PhishStats") in {(s["platform"], s["handle"]) for s in contacts["social"]}
    assert any(i["kind"] == "telegram_invite" for i in contacts["invites"])


# ------------------------------------------------------------------ rule 5 and AR20 safety expectations
def test_challenge_home_is_blocked():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http.add("GET", f"{BASE}/", status=403, text="<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>")
    res = run(http)
    assert res.status is Status.BLOCKED
    assert len([c for c in target_calls(http) if c["url"] == f"{BASE}/"]) == 1


def test_429_is_rate_limited():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http.add("GET", f"{BASE}/", status=429, text="slow down")
    assert run(http).status is Status.RATE_LIMITED


def test_never_runs_on_a_pivot():
    http = FakeHttp()
    site(http)
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.org", "links_to", "x"),))
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert target_calls(http) == []


def test_kill_switch_stops_before_any_target_request():
    http = FakeHttp()
    site(http)
    rt = make_runtime(http)
    rt.cancel("test kill switch")
    res = run_module(SiteContacts, f"domain:{HOST}", http, options=LIGHT, runtime=rt)
    assert target_calls(http) == []
    assert res.status is not Status.OK or res.partial


def test_redirect_to_a_private_address_is_refused():
    http = FakeHttp()
    target(http)
    target(http, "intranet.example.net", ip="10.1.2.3")
    http.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http.add("GET", f"{BASE}/", redirect_to="https://intranet.example.net/")
    http.add("GET", "https://intranet.example.net/", text="internal")
    res = run(http)
    assert res.status is not Status.OK
    assert "https://intranet.example.net/" not in [c["url"] for c in target_calls(http)]


# ------------------------------------------------------------------ library
def test_plan_refuses_tokens_queries_and_forms():
    facts = {"anchors": [{"href": "/contato?ref=home", "text": "Contato", "footer": False},
                         {"href": "/contato/abcdef1234567890XYZ", "text": "Contato", "footer": False},
                         {"href": "/sobre/maria@example.com", "text": "Sobre", "footer": False},
                         {"href": "/fale-conosco", "text": "Fale conosco", "footer": False}]}
    plan = sc.plan_crawl("https://www.example.com/", facts, seed_host="www.example.com")
    assert plan["pages"] == ["https://www.example.com/", "https://www.example.com/fale-conosco"]
    reasons = " ".join(r["reason"] for r in plan["refused"])
    assert "query string" in reasons and "token-like" in reasons


def test_phone_whatsapp_social_and_brcode_parsers():
    assert sc.normalise_br_phone("(11) 95555-0103") == {"e164": "+5511955550103", "kind": "mobile", "national": "(11) 95555-0103"}
    assert sc.normalise_br_phone("0800 555 0123")["kind"] == "tollfree"
    assert sc.normalise_br_phone("(00) 5555-0100") is None  # invalid DDD
    assert sc.parse_whatsapp_url("https://api.whatsapp.com/send?phone=5511955550104&text=Oi")["e164"] == "+5511955550104"
    assert sc.parse_whatsapp_url("https://chat.whatsapp.com/AbCdEfGhIjKlMn0pQrStUv")["kind"] == "group_invite"
    assert sc.parse_social_url("https://www.linkedin.com/in/fulano/") is None
    assert sc.parse_social_url("https://www.facebook.com/sharer/sharer.php?u=x") is None
    assert sc.parse_social_url("https://t.me/+ExEmPlOiNvItE")["kind"] == "invite"
    payload = re.search(r"000201\S+", fx("fake_store_synthetic.html")).group(0)
    br = sc.parse_brcode(payload)
    assert br["key_type"] == "evp" and br["merchant_name_present"] is True
    assert sc.find_pix_keys("Chave PIX: 123.456.789-09")[0] == {"type": "cpf", "value": "***.456.789-**", "valid": True}
    assert sc.decode_cfemail("42212d2f2730212b232e02273a232f322e276c212d2f") == "comercial@example.com"


def test_parsers_never_raise_on_garbage():
    for junk in (None, b"\x00\xff" * 30, "<<<", 42, [], {"a": 1}, "000201" * 50, "pix " * 100):
        sc.extract_contacts(junk, "https://www.example.com/")
        sc.find_pix_keys(junk)
        sc.robots_decision(junk, "https://www.example.com/x", "*", 200)
        sc.parse_whatsapp_url(junk)
        sc.parse_social_url(junk)
        sc.normalise_br_phone(junk)


@pytest.mark.parametrize("cls", ["role", "personal"])
def test_classify_email(cls):
    addr = "sac.sp@example.com" if cls == "role" else "joao.silva@example.com"
    assert sc.classify_email(addr, "www.example.com")["class"] == cls


# ------------------------------------------------------------------ FC3: the shared safe fetch (review p9-G03-2)
def test_a_homepage_redirect_cached_by_another_light_module_is_followed():
    """The homepage is read through light_fetch.fetch_homepage (the cache rows web_fingerprint and the
    other LIGHT modules share): a cached 301 is followed to the page, never read as an empty homepage
    (which used to end EMPTY with no page crawled)."""
    from v3lum.modules.url_web.light_fetch import fetch_homepage

    http = FakeHttp()
    target(http, "example.com")
    target(http)
    target(http, "loja.example.com")  # a subdomain of the apex seed: inside the LIGHT seed binding
    http.add("GET", "https://loja.example.com/atendimento", text=MINIMAL)
    http.add("GET", "https://example.com/robots.txt", status=404, text="")
    http.add("GET", "https://example.com/", status=301, headers={"Location": f"{BASE}/"}, text="")
    http.add("GET", f"{BASE}/", text=fx("home_synthetic.html"))
    for path in HOME_PAGES:
        http.add("GET", BASE + path, text=fx("contato_synthetic.html") if path == "/contato" else MINIMAL)
    rt = make_runtime(http, cache=True)
    entity = Entity.make(T.DOMAIN, "example.com")
    assert fetch_homepage(make_ctx(SiteContacts, http, runtime=rt, entity=entity, options=LIGHT), entity).status == 200
    res = run_module(SiteContacts, entity, http, options=LIGHT, runtime=rt)
    assert res.status is Status.OK, res.error
    assert "contato@example.com" in {e["address"] for e in res.attributes["site_contacts"]["emails"]}
    assert f"{BASE}/contato" in res.attributes["crawl_summary"]["pages"]


def test_a_crawled_page_that_redirects_off_site_is_not_followed():
    http2 = FakeHttp()
    target(http2)
    http2.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http2.add("GET", f"{BASE}/", text=fx("home_synthetic.html"))
    for path in HOME_PAGES:
        if path == "/contato":
            http2.add("GET", BASE + path, status=302, headers={"Location": "https://forms.crm-vendor.example.net/f/123"}, text="")
        else:
            http2.add("GET", BASE + path, text=MINIMAL)
    http2.add("GET", "https://forms.crm-vendor.example.net/f/123", text="<a href='mailto:sac@crm-vendor.example.net'>x</a>")
    res = run(http2)
    assert "https://forms.crm-vendor.example.net/f/123" not in [c["url"] for c in target_calls(http2)]
    refused = {r["url"]: r["reason"] for r in res.attributes["crawl_summary"]["refused"]}
    assert "not followed" in refused[f"{BASE}/contato"]
    assert "crm-vendor" not in json.dumps(res.attributes.get("site_contacts", {}))


def test_e_mail_and_token_paths_are_never_written_to_the_crawl_summary():
    facts = {"anchors": [{"href": "/sobre/maria.souza@example.com", "text": "Sobre", "footer": False},
                         {"href": "/contato/AbCdEf0123456789XyZ", "text": "Contato", "footer": False},
                         {"href": "https://loja.example.com/u/joao@example.com", "text": "Contato loja", "footer": False}]}
    plan = sc.plan_crawl("https://www.example.com/", facts, seed_host="www.example.com")
    text = json.dumps(plan)
    assert "maria" not in text and "joao" not in text and "AbCdEf0123456789XyZ" not in text
    assert plan["pages"] == ["https://www.example.com/"] and len(plan["refused"]) == 3


def test_a_challenge_on_robots_txt_stops_the_crawl():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=200, text="<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>")
    res = run(http)
    assert res.status is Status.BLOCKED
    assert [c["url"] for c in target_calls(http)] == [f"{BASE}/robots.txt"]


def test_a_rate_limit_mid_crawl_keeps_the_pages_read_and_marks_the_run_partial():
    http = FakeHttp()
    target(http)
    http.add("GET", f"{BASE}/robots.txt", status=404, text="")
    http.add("GET", f"{BASE}/", text=fx("home_synthetic.html"))
    http.add("GET", f"{BASE}/sobre-nos", text=MINIMAL)
    http.add("GET", f"{BASE}/institucional/quem-somos", status=429, text="slow down")
    http.add("GET", re.compile(re.escape(BASE) + r"/.*"), text=fx("contato_synthetic.html"))
    res = run(http)
    assert res.partial and res.stop_reason == "rate_limited"
    assert res.attributes["crawl_summary"]["pages_fetched"] >= 1
    urls = [c["url"] for c in target_calls(http)]
    assert urls.index(f"{BASE}/institucional/quem-somos") == len(urls) - 1  # nothing after the 429


def test_the_request_cap_keeps_the_contacts_already_read():
    class Capped(SiteContacts):  # same module, a tight per-run cap (robots + home + one page)
        max_requests = 3

    http = FakeHttp()
    site(http)
    ctx = make_ctx(Capped, http, entity=Entity.make(T.DOMAIN, HOST), options=LIGHT)
    res = Capped().run(Entity.make(T.DOMAIN, HOST), ctx)
    assert res.partial and res.stop_reason == "request_cap"
    assert "contato@example.com" in {e["address"] for e in res.attributes["site_contacts"]["emails"]}
    assert len(target_calls(http)) == 3
