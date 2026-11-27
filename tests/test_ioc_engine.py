"""P172 IOC extraction engine (v3lum.core.ioc): stage order, decode bounds, span masking,
Brazilian formats, flags, recipient tokens and the privacy floor (CPF, PAN, secrets).

Every value is synthetic or a documented example (EICAR hashes, documentation IP ranges, the
classic example CPF 111.444.777-35, the Visa test card 4111..., synthetic tokens built from pieces).
"""

from __future__ import annotations

import base64
import gzip
import json

import pytest

from v3lum.core import ioc
from v3lum.core import validators as val
from v3lum.core.entities import EntityType as T
from v3lum.core.orgprofile import OrgProfile

GH_TOKEN = "ghp" + "_" + "V3lumSyntheticTokenForTests0123456789"[:36]
PAN = "4111 1111 1111 1111"
CPF = "111.444.777-35"


def keys(text, **kw):
    return [i.entity.key for i in ioc.extract(text, **kw).entities]


def item(result, key):
    return next(i for i in result.entities if i.entity.key == key)


def org():
    return OrgProfile.from_dict({"domains": [{"name": "acme.com.br", "verification": "attested", "attested_by": "soc", "attested_date": "2026-11-01"}]})


def brcode(merchant="LOJA TESTE", key="123e4567-e12b-12d1-a456-426655440000"):
    gui = "0014br.gov.bcb.pix01" + f"{len(key):02d}" + key
    body = ("000201" + "26" + f"{len(gui):02d}" + gui + "52040000" + "5303986" + "5802BR" + "59" + f"{len(merchant):02d}" + merchant
            + "6008BRASILIA" + "62070503***" + "6304")
    return body + format(val.crc16_ccitt(body.encode()), "04X")


# ------------------------------------------------------------------------------- result shape
def test_result_shape_and_provenance():
    text = "first line\nC2 is 45.33.32.156 now"
    res = ioc.extract(text)
    assert isinstance(res, ioc.ExtractionResult) and not res.limit_hit and res.limit == ioc.DEFAULT_LIMIT
    hit = res.entities[0]
    assert isinstance(hit, ioc.ExtractedIOC)
    assert hit.entity.key == "ipv4:45.33.32.156" and hit.line == 2 and text[slice(*hit.span)] == "45.33.32.156"
    assert hit.confidence >= 0.9 and hit.expand and not hit.defanged and hit.occurrences == 1
    assert res.counts == {"ipv4": 1} and res.preview() == "1 IOC: 1 IP"
    assert json.loads(json.dumps(res.to_dict()))["entities"][0]["line"] == 2


def test_odd_input_never_raises():
    for text in ("", "   ", None, 42, "\x00\x01\x02", "a" * 10, "::", "http://", "@@@", "[.]" * 10):
        res = ioc.extract(text)  # type: ignore[arg-type]
        assert isinstance(res, ioc.ExtractionResult)


# ------------------------------------------------------------------------------- stage order
def test_stage_order_scrub_before_decode_before_refang():
    # a base64 block holding a secret and a defanged URL: the secret is fingerprinted (scrub runs on
    # decoded content too), the URL is refanged after decoding.
    inner = f"token {GH_TOKEN} panel hxxps://evil-b64[.]example.net/login"
    res = ioc.extract("blob " + base64.b64encode(inner.encode()).decode() + " end")
    got = {i.entity.key: i for i in res.entities}
    assert "url:https://evil-b64.example.net/login" in got and got["url:https://evil-b64.example.net/login"].source == "base64"
    assert "decoded" in got["url:https://evil-b64.example.net/login"].flags
    secrets = [i for i in res.entities if i.entity.type is T.SECRET]
    assert len(secrets) == 1 and secrets[0].entity.value.startswith("github_token:ghp_…")
    assert GH_TOKEN not in json.dumps(res.to_dict())
    assert res.decoded.get("base64") == 1


def test_refang_variants():
    text = ("hxxps://a-evil[.]example.net/x hXXp://b-evil(.)example.net "
            "c-evil[dot]example.net d-evil{.}example.net user[@]e-evil.example.net f-evil\\.example.net "
            "fxp://g-evil.example.net/f http[:]//h-evil.example.net/ http[://]i-evil.example.net/ "
            "j-evil[.example.net k-evil .example.org")
    got = keys(text)
    for want in ("url:https://a-evil.example.net/x", "url:http://b-evil.example.net/", "domain:c-evil.example.net",
                 "domain:d-evil.example.net", "email:user@e-evil.example.net", "domain:f-evil.example.net",
                 "url:ftp://g-evil.example.net/f", "url:http://h-evil.example.net/", "url:http://i-evil.example.net/",
                 "domain:j-evil.example.net"):
        assert want in got, want
    assert ioc.refang_text("evil[.]com (at) x") == "evil.com@x"


def test_defanged_flag_and_confidence():
    res = ioc.extract("defanged evil[.]zip and plain notes.zip")
    assert item(res, "domain:evil.zip").defanged and item(res, "domain:evil.zip").confidence >= 0.9
    plain = item(res, "domain:notes.zip")
    assert not plain.defanged and plain.low_confidence and "low_confidence_tld" in plain.flags


# ------------------------------------------------------------------------------- decode bounds
def _wrap(text: bytes, times: int) -> str:
    for _ in range(times):
        text = base64.b64encode(text)
    return text.decode()


def test_decode_depth_is_three():
    payload = b"https://deep-layer.example.org/a"
    assert "url:https://deep-layer.example.org/a" in keys("x " + _wrap(payload, 3))
    assert keys("x " + _wrap(payload, 4)) == []


def test_decoded_output_is_capped(monkeypatch):
    monkeypatch.setattr(ioc, "MAX_DECODED_CHARS", 40)
    blocks = " ".join(base64.b64encode(f"https://blk{i}.example.org/aaaa".encode()).decode() for i in range(5))
    res = ioc.extract(blocks)
    assert 0 < res.decoded["base64"] < 5
    assert any("decode budget" in n for n in res.notes)


def test_decode_cap_holds_for_the_block_that_would_cross_it(monkeypatch):
    monkeypatch.setattr(ioc, "MAX_DECODED_CHARS", 40)  # each block decodes to 31 characters
    blocks = " ".join(base64.b64encode(f"https://blk{i}.example.org/aaaa".encode()).decode() for i in range(3))
    res = ioc.extract(blocks)
    assert res.decoded["base64"] == 1 and sum(k.startswith("url:") for k in keys(blocks)) == 1
    assert len([n for n in res.notes if "decode budget" in n]) == 1


def test_relative_decode_cap_is_twice_the_input():
    run = ioc._Run("x" * 100, limit=10, org=None, own_domains=(), aliases=False)
    assert run.decode_budget == 200


def test_archives_and_binary_blocks_are_never_decoded():
    archive = base64.b64encode(gzip.compress(b"https://inside-archive.example.org/x" * 3)).decode()
    zipped = base64.b64encode(b"PK\x03\x04" + b"https://inside-zip.example.org/" * 2).decode()
    res = ioc.extract(f"attachments {archive} {zipped}")
    assert res.entities == [] and any("not decoded or decompressed" in n for n in res.notes)


def test_hashes_are_not_mistaken_for_base64():
    res = ioc.extract("sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert [i.entity.type for i in res.entities] == [T.SHA256] and res.decoded == {}


def test_quoted_printable_and_html_entities_are_decoded_in_place():
    text = "soft=\nbreak see http://qp-evil.example.org/p=3D1 and <a href=\"https://html-evil&#46;example&#46;net/x?a=1&amp;b=2\">"
    res = ioc.extract(text)
    qp = item(res, "url:http://qp-evil.example.org/p=1")
    html_url = item(res, "url:https://html-evil.example.net/x?a=1&b=2")
    assert text[slice(*qp.span)].startswith("http://qp-evil")  # spans map back to the original text
    assert text[slice(*html_url.span)].startswith("https://html-evil&#46;")
    assert {"quoted_printable", "html_entities"} <= set(res.decoded)


# ------------------------------------------------------------------------------- span masking
def test_no_domain_from_inside_an_email_or_a_url():
    got = keys("mail ana@evil-mail.example.com and https://x.example.com/redirect/evil-path.example.net/page")
    assert "email:ana@evil-mail.example.com" in got
    assert "domain:evil-mail.example.com" not in got and "domain:evil-path.example.net" not in got
    assert "domain:x.example.com" in got  # the URL host is listed (from_url)


def test_nested_and_percent_encoded_urls_are_unwrapped():
    text = "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fwrapped.example.net%2Flogin&data=05 done"
    res = ioc.extract(text)
    nested = item(res, "url:https://wrapped.example.net/login")
    assert nested.source == "url_encoding" and "domain:wrapped.example.net" in {i.entity.key for i in res.entities}


def test_ipv4_ipv6_cidr_and_version_strings():
    got = keys("srv 198.51.100.7 net 192.0.2.0/24 v6 2001:db8::1 v6net 2001:db8::/32 time 12:30:45 "
               "mac de:ad:be:ef:00:01 version 10.0.17763.1 lead 010.1.1.1 big 256.1.1.1")
    assert {"ipv4:198.51.100.7", "cidr:192.0.2.0/24", "ipv6:2001:db8::1", "cidr:2001:db8::/32", "mac_address:DE:AD:BE:EF:00:01"} <= set(got)
    assert not any(k.startswith("ipv4:10.0.17763") or k == "ipv4:10.1.1.1" or k.startswith("ipv4:256") for k in got)


def test_hashes_cve_and_attack_validation():
    res = ioc.extract("md5 44d88612fea8a8f36de82e1278abb02f btc? 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb "
                      "T1566.001 T9999 CVE-1990-1234 CVE-2099-12345 CVE-2021-44228 all-zero 00000000000000000000000000000000")
    got = {i.entity.key: i for i in res.entities}
    assert "md5:44d88612fea8a8f36de82e1278abb02f" in got and not any(k.startswith("btc_address") for k in got)
    assert got["mitre_technique:T1566.001"].confidence >= 0.9
    assert "unverified_attack_id" in got["mitre_technique:T9999"].flags and not got["mitre_technique:T9999"].expand
    assert "cve:CVE-2021-44228" in got and "cve:CVE-1990-1234" not in got and "cve:CVE-2099-12345" not in got
    assert not any(k.startswith("md5:0000") for k in got)


def test_md5_looking_strings_are_never_btc_and_wallets_need_checksums():
    got = keys("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
               "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE "
               "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u d41d8cd98f00b204e9800998ecf8427e")
    assert "btc_address:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in got and "btc_address:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in got
    assert "eth_address:0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae" in got and got.count("eth_address:0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae") == 1
    assert "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" in got
    assert "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u" not in got
    assert "md5:d41d8cd98f00b204e9800998ecf8427e" in got and not any(k.startswith("btc_address:d41") for k in got)


# ------------------------------------------------------------------------------- Brazilian scam text
def test_brazilian_phone_formats():
    got = keys("liga (11) 98765-4321 ou 21 3456-7890 ou 0800 123 4567 ou +55 31 99876-5432; "
               "nao: 11987654321 (sem separador), (00) 98765-4321 (DDD invalido), 11 12345-6789 (celular sem 9)")
    assert {"phone:+5511987654321", "phone:+552134567890", "phone:+558001234567", "phone:+5531998765432"} <= set(got)
    assert sum(k.startswith("phone:") for k in got) == 4


def test_international_phones_are_taken_whole():
    # a window that ended a few characters after '+d' used to cut E.164 numbers ('+442079460958' ->
    # '+442079460') or drop them ('+5511987654321', '+12025550143')
    got = keys("a +12025550143 b +1 202 555 0143 c +1 (202) 555-0199 d +442079460958 e +5511987654321 f +351 912 345 678 "
               "g +33 1 23 45 67 89 h +1234567890123456789012345678901234 i +55 11  98765-4321")
    for want in ("phone:+12025550143", "phone:+12025550199", "phone:+442079460958", "phone:+5511987654321",
                 "phone:+351912345678", "phone:+33123456789"):
        assert want in got, want
    assert sum(k.startswith("phone:") for k in got) == 6  # no truncated number, no 34-digit run, no double space


def test_messaging_and_social_links():
    res = ioc.extract("zap wa.me/5511912345678 api https://api.whatsapp.com/send?phone=5521987654321&text=oi "
                      "tg t.me/canal_golpe convite t.me/+AbCdEfGh123 antigo t.me/joinchat/XyZ12345abc "
                      "discord discord.gg/golpe123 insta https://www.instagram.com/loja.fake.br/ x.com/golpista_br")
    got = {i.entity.key: i for i in res.entities}
    for key in ("phone:+5511912345678", "phone:+5521987654321", "telegram_handle:canal_golpe", "telegram_invite:AbCdEfGh123",
                "telegram_invite:XyZ12345abc", "discord_invite:golpe123", "social_account:instagram:loja.fake.br",
                "social_account:x:golpista_br"):
        assert key in got, key
        assert "personal" in got[key].flags and not got[key].expand
    assert "domain:t.me" not in got and "domain:instagram.com" not in got  # account hosts are not IOCs


def test_pix_brcode_and_cnpj():
    code = brcode()
    res = ioc.extract(f"pague: {code} empresa 11.222.333/0001-81 e 11222333000181 nao 11222333000182")
    got = {i.entity.key: i for i in res.entities}
    assert f"pix_brcode:{code}" in got and "personal" in got[f"pix_brcode:{code}"].flags
    assert "cnpj:11222333000181" in got and got["cnpj:11222333000181"].occurrences == 2
    assert not any(k == "cnpj:11222333000182" for k in got)


# ------------------------------------------------------------------------------- privacy floor
def test_cpf_is_masked_counted_and_never_an_entity():
    res = ioc.extract(f"titular CPF {CPF} e cpf: 52998224725, telefone fake 529.982.247-26")
    assert not any(i.entity.type is T.CPF for i in res.entities)
    assert res.masked["cpf"]["count"] == 2 and res.masked["cpf"]["previews"] == ["***.444.777-**", "***.982.247-**"]
    assert res.counts["cpf"] == 2
    blob = json.dumps(res.to_dict())
    assert CPF not in blob and "11144477735" not in blob and "52998224725" not in blob


def test_pan_is_truncated_at_extraction():
    res = ioc.extract(f"cartao {PAN} e 5555555555554444, nao 4111111111111112")
    cards = sorted(i.entity.value for i in res.entities if i.entity.type is T.PAYMENT_CARD)
    assert cards == ["411111…1111", "555555…4444"]
    blob = json.dumps(res.to_dict())
    assert "4111111111111111" not in blob and PAN not in blob and "5555555555554444" not in blob
    assert all("secret" in i.flags and not i.expand for i in res.entities if i.entity.type is T.PAYMENT_CARD)


def test_scrub_masks_cards_and_pattern_secrets_and_is_idempotent():
    dyn = "dt0c01" + "." + "V3LUMSYNTHETICDYNATRACE0" + "." + ("V3LUMSYNTHETICDYNATRACESECRET0" * 3)[:64]
    hits: list[dict] = []
    once = ioc.scrub(f"card {PAN} dyn {dyn} gh {GH_TOKEN}", hits=hits)
    assert "411111…1111" in once and dyn not in once and GH_TOKEN not in once
    assert {h["kind"] for h in hits} >= {"payment_card", "dynatrace_token", "github_token"}
    assert all(PAN.replace(" ", "") not in h["value"] and dyn not in h["value"] for h in hits)
    assert ioc.scrub(once) == once


def test_secrets_are_fingerprinted_and_reported_once():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    bot = "123456789" + ":AA" + "V3lumSyntheticBotTokenForTests0000"[:33]
    res = ioc.extract(f"jwt {jwt} again {jwt} bot {bot} gh {GH_TOKEN}")
    secrets = [i for i in res.entities if i.entity.type in (T.SECRET, T.TELEGRAM_BOT_TOKEN)]
    assert sorted(i.entity.type.value for i in secrets) == ["secret", "secret", "telegram_bot_token"]
    assert all("secret" in i.flags and not i.expand for i in secrets)
    assert len([n for n in res.notes if n.startswith("sensitive data in pasted text")]) == 1
    blob = json.dumps(res.to_dict())
    for raw in (jwt, bot, GH_TOKEN):
        assert raw not in blob


def test_fingerprints_from_an_already_scrubbed_seed_are_recognised():
    scrubbed = ioc.scrub(f"token {GH_TOKEN} and 198.51.100.7")
    res = ioc.extract(scrubbed)
    assert {i.entity.type for i in res.entities} == {T.SECRET, T.IPV4}


def test_cpf_written_with_html_entities_is_masked():
    res = ioc.extract('<a href="https://x.example.com/?doc=529&#46;982&#46;247-25">segunda via</a> cpf&#58; 11144477735')
    blob = json.dumps(res.to_dict())
    assert "529.982.247-25" not in blob and "52998224725" not in blob and "11144477735" not in blob
    assert res.masked["cpf"]["count"] == 2 and not any(i.entity.type is T.CPF for i in res.entities)
    assert "url:https://x.example.com/?doc=" in {i.entity.key for i in res.entities}  # cut like the plain form


@pytest.mark.parametrize("url,raws", [
    ("https://evil.example.net/?t=123456789%3AAA" + "V3lumSyntheticBotTokenForTests0000"[:33], ["123456789%3AAA", "123456789:AA"]),
    ("https://r.example.net/?u=https%3A%2F%2Fpay.example.org%2F%3Fcc%3D4111111111111111&x=1", ["4111111111111111"]),
    ("https://t.example.net/c?e=" + base64.b64encode(b"card 4111111111111111 x").decode() + "&z=1",
     [base64.b64encode(b"card 4111111111111111 x").decode(), "4111111111111111"]),
    ("https://x.example.com/?doc=529%2E982%2E247-25&b=2", ["529%2E982%2E247-25", "529.982.247-25"]),
    ("https://r.example.net/?u=https%3A%2F%2Fadmin%3Ahunter2pass%40in.example.org%2F", ["hunter2pass"]),
])
def test_secrets_cards_and_cpf_hidden_behind_url_encoding_never_reach_an_entity(url, raws):
    """Acceptance (P323 cond 5-7, AR24): no full PAN, raw secret or CPF leaves extraction as an
    entity value, even percent- or base64-encoded inside a URL (the URL is cut before it)."""
    res = ioc.extract(f"link {url} fim")
    blob = json.dumps(res.to_dict())
    for raw in raws:
        assert raw not in blob, raw
    assert all(i.entity.value != url for i in res.entities)
    assert any(n.startswith("sensitive data in pasted text") or n.startswith("CPF found") for n in res.notes)


def test_encoded_card_in_a_nested_url_keeps_the_nested_host():
    res = ioc.extract("https://r.example.net/?u=https%3A%2F%2Fpay.example.org%2F%3Fcc%3D4111111111111111")
    got = {i.entity.key for i in res.entities}
    assert {"payment_card:411111…1111", "domain:pay.example.org", "url:https://pay.example.org/?cc=", "url:https://r.example.net/?u="} <= got


def test_plain_encoded_components_are_untouched():
    url = "https://x.example.com/a%20b/c?q=hello%20world&r=https%3A%2F%2Fwrapped.example.net%2Flogin#frag%2Fx"
    got = keys(url)
    assert f"url:{url}" in got and "url:https://wrapped.example.net/login" in got


def test_iban_is_masked_never_an_entity():
    res = ioc.extract("transferir para DE89 3704 0044 0532 0130 00 hoje")
    assert res.entities == [] and res.masked["iban"]["previews"] == ["DE89 **** **** **** **30 00"]


# ------------------------------------------------------------------------------- flags
def test_bogon_private_and_warninglisted_flags():
    res = ioc.extract("hosts 10.1.2.3 192.168.0.9 fe80::1 203.0.113.9 100.64.1.1 45.33.32.156 resolver 8.8.8.8")
    got = {i.entity.value: i for i in res.entities}
    assert "private" in got["10.1.2.3"].flags and "private" in got["192.168.0.9"].flags and "private" in got["fe80::1"].flags
    assert "bogon" in got["203.0.113.9"].flags and "bogon" in got["100.64.1.1"].flags
    assert got["45.33.32.156"].flags == frozenset() and got["45.33.32.156"].expand
    assert "warninglisted" in got["8.8.8.8"].flags and got["8.8.8.8"].noise and not got["8.8.8.8"].expand
    assert all(not got[v].expand for v in ("10.1.2.3", "203.0.113.9"))


def test_org_domains_and_own_domains_are_flagged():
    res = ioc.extract("portal acme.com.br mail ana@acme.com.br sender evil-sender.example.net", org=org(),
                      own_domains=["evil-sender.example.net"])
    got = {i.entity.key: i for i in res.entities}
    assert "org_domain" in got["domain:acme.com.br"].flags and "org_domain" in got["email:ana@acme.com.br"].flags
    assert "org_domain" in got["domain:evil-sender.example.net"].flags and not got["domain:acme.com.br"].expand


def test_recipient_token_urls_plain_encoded_and_base64():
    b64 = base64.b64encode(b"bob@acme.com.br").decode()
    res = ioc.extract(f"https://t.example.net/a?u=ana@acme.com.br https://t.example.net/b?u=ana%40acme.com.br "
                      f"https://t.example.net/c?e={b64} https://t.example.net/plain", org=org())
    got = {i.entity.value: i for i in res.entities if i.entity.type is T.URL}
    assert all("recipient_token" in got[f"https://t.example.net/{p}"].flags for p in ("a?u=ana@acme.com.br", "b?u=ana%40acme.com.br", f"c?e={b64}"))
    assert "recipient_token" not in got["https://t.example.net/plain"].flags
    assert not any(i.entity.type is T.EMAIL for i in res.entities)  # the recipient's address inside a URL is not listed


def test_email_header_block_is_static_and_recipients_are_not_listed():
    text = ("Received: from mx.bad.example.net (mx.bad.example.net [198.51.100.7])\nFrom: Bad <bad@sender.example.net>\n"
            "To: Victim <victim@acme.com.br>\nCc: other@acme.com.br\nSubject: fatura\nMessage-ID: <abc123@sender.example.net>\n\n"
            "Clique hxxps://pay-bad[.]example.net/x <img src=\"https://tracker.example.net/p.gif\">")
    res = ioc.extract(text)
    got = {i.entity.key for i in res.entities}
    headers = [i for i in res.entities if i.entity.type is T.EMAIL_HEADERS]
    assert len(headers) == 1 and "personal" in headers[0].flags and "fatura" in headers[0].entity.value
    assert "email:bad@sender.example.net" in got and "ipv4:198.51.100.7" in got
    assert "email:victim@acme.com.br" not in got and "email:other@acme.com.br" not in got
    assert "email:abc123@sender.example.net" not in got and "domain:sender.example.net" in got
    assert "url:https://pay-bad.example.net/x" in got
    assert any("recipient address" in n for n in res.notes)


@pytest.fixture()
def known_aliases(tmp_path):
    """Core tests never rely on the alias data the P295 batch bundles: a tmp 'v3lum.aliases/1'
    fragment provides the names (wave-3 integration)."""
    for kind, names in (("malware_family", {"Emotet": "Emotet"}), ("threat_actor", {"APT28": "APT28"})):
        frag = {"schema": ioc.ALIASES_SCHEMA, "kind": kind, "source": "tests", "licence": "CC0-1.0", "names": names}
        (tmp_path / f"t_{kind}.json").write_text(json.dumps(frag), encoding="utf-8")
    ioc.reload_aliases([tmp_path])
    try:
        yield
    finally:
        ioc.reload_aliases()


def test_known_malware_and_actor_names_need_a_distinctive_form_or_context(known_aliases):
    got = keys("APT28 deployed Emotet ransomware; the agent update was quick. Python script and Ghost in the shell.")
    assert "threat_actor:APT28" in got and "malware_family:Emotet" in got
    assert not any(k.startswith("malware_family:") and k not in ("malware_family:Emotet",) for k in got)


# ------------------------------------------------------------------------------- limit
def test_limit_is_reported_when_hit():
    res = ioc.extract(" ".join(f"198.51.100.{i}" for i in range(30)), limit=10)
    assert len(res.entities) == 10 and res.limit_hit
    assert res.notes[-1] == "IOC limit reached: only the first 10 distinct indicators were extracted"
    res = ioc.extract(" ".join(f"198.51.100.{i}" for i in range(5)), limit=10)
    assert not res.limit_hit and not any("limit" in n for n in res.notes)


@pytest.mark.parametrize("dup", [1, 3])
def test_duplicates_count_occurrences(dup):
    res = ioc.extract(" ".join(["45.33.32.156"] * dup))
    assert len(res.entities) == 1 and res.entities[0].occurrences == dup


def test_preview_line_groups_and_low_confidence():
    res = ioc.extract("a.example.net b.example.net 45.33.32.156 hxxp://c[.]example.org/x report.md T9999")
    assert res.preview() == "7 IOCs: 4 domains, 1 IP, 1 URL, 1 ATT&CK id, 2 low-confidence"
