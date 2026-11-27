"""Detection v2 (P333 cond 4, P323 cond 1, P217 cond 5, AR18): the contract-v2 types are typed only
from an explicit TYPE:value prefix, a URL pattern or an unambiguous structure - never from bare hex
or digit length - and known malware/actor aliases beat 'username'."""

from __future__ import annotations

import json

import pytest

from v3lum.core import detect as det
from v3lum.core import ioc
from v3lum.core import validators as val
from v3lum.core.entities import EntityType as T
from v3lum.core.entities import reload_platforms


def best(raw):
    found = det.detect(raw)
    return found[0] if found else None


def types(raw):
    return [d.type for d in det.detect(raw)]


@pytest.fixture
def tmp_aliases(tmp_path):
    frag = {"schema": ioc.ALIASES_SCHEMA, "kind": "malware_family", "source": "tests", "licence": "CC0-1.0",
            "names": {"Quuxbanker": "QuuxBanker", "quux-bank": "QuuxBanker"}}
    (tmp_path / "t_aliases.json").write_text(json.dumps(frag), encoding="utf-8")
    actor = {"schema": ioc.ALIASES_SCHEMA, "kind": "threat_actor", "source": "tests", "licence": "CC0-1.0",
             "names": {"Plugh Panda": "PLUGH SPIDER"}}
    (tmp_path / "t_actor.json").write_text(json.dumps(actor), encoding="utf-8")
    ioc.reload_aliases([tmp_path])
    yield tmp_path
    ioc.reload_aliases()


@pytest.fixture
def tmp_platform(tmp_path):
    frag = {"schema": "v3lum.platforms/1", "platforms": {"quuxsocial": {"title": "QuuxSocial",
            "profile_url_patterns": ["https://quux.example.social/u/{handle}"]}}}
    d = tmp_path / "platforms"
    d.mkdir()
    (d / "t_quux.json").write_text(json.dumps(frag), encoding="utf-8")
    reload_platforms([d])
    yield d
    reload_platforms()


# ------------------------------------------------------------------------------- explicit prefixes
@pytest.mark.parametrize("raw,etype", [
    ("telegram_handle:durov", T.TELEGRAM_HANDLE), ("telegram_invite:AbCdEfGh123", T.TELEGRAM_INVITE),
    ("discord_invite:golpe123", T.DISCORD_INVITE), ("social_account:instagram:loja.fake", T.SOCIAL_ACCOUNT),
    ("imphash:f34d5f2d4577ed6d9ceec516c1f5a744", T.IMPHASH), ("tlsh:T1" + "A" * 70, T.TLSH),
    ("fediverse_handle:@alice@mastodon.social", T.FEDIVERSE_HANDLE), ("bsky_handle:alice.bsky.social", T.BSKY_HANDLE),
])
def test_explicit_prefix_types(raw, etype):
    found = det.detect(raw)
    assert len(found) == 1 and found[0].type is etype and found[0].confidence == 1.0


def test_forced_values_with_failing_checksums_get_low_confidence():
    bad_eth = det.detect("eth_address:0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE")
    assert bad_eth[0].type is T.ETH and bad_eth[0].confidence == 0.4 and "EIP-55" in bad_eth[0].reason
    jwt_like = det.detect("jwt:529.982.247-25")  # carry-forward: JWT stays structure-gated
    assert jwt_like[0].type is T.JWT and jwt_like[0].confidence == 0.4
    assert det.detect("jwt:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc")[0].confidence == 1.0
    assert best("529.982.247-25").type is T.CPF


# ------------------------------------------------------------------------------- URL patterns
@pytest.mark.parametrize("raw,etype,value", [
    ("t.me/golpe_pix_br", T.TELEGRAM_HANDLE, "golpe_pix_br"),
    ("t.me/+AbCdEfGh123", T.TELEGRAM_INVITE, "AbCdEfGh123"),
    ("t.me/joinchat/XyZ12345abc", T.TELEGRAM_INVITE, "XyZ12345abc"),
    ("discord.gg/golpe123", T.DISCORD_INVITE, "golpe123"),
    ("discord.com/invite/golpe123", T.DISCORD_INVITE, "golpe123"),
    ("bsky.app/profile/alice.bsky.social", T.BSKY_HANDLE, "alice.bsky.social"),
    ("steamcommunity.com/id/gabelogannewell", T.STEAM_PROFILE, "id:gabelogannewell"),
    ("wa.me/5511912345678", T.PHONE, "+5511912345678"),
    ("instagram.com/loja.fake.br", T.SOCIAL_ACCOUNT, "instagram:loja.fake.br"),
])
def test_schemeless_account_urls_are_typed(raw, etype, value):
    d = best(raw)
    assert d.type is etype and d.value == value and d.confidence >= 0.9
    assert T.URL in types(raw)  # the link stays available as an alternative


def test_schemed_account_urls_keep_today_precedence():
    found = det.detect("https://t.me/golpe_pix_br")
    assert found[0].type is T.URL and found[0].confidence == 0.98
    alt = [d for d in found if d.type is T.TELEGRAM_HANDLE]
    assert alt and alt[0].confidence < 0.75  # an alternative, never auto-investigated
    assert [d.type for d in det.primary(found)] == [T.URL]


def test_profile_url_of_a_tmp_platform_fragment_is_a_social_account(tmp_platform):
    assert best("quux.example.social/u/someone").type is T.SOCIAL_ACCOUNT
    assert best("quux.example.social/u/someone").value == "quuxsocial:someone"
    got = {i.entity.key for i in ioc.extract("perfil https://quux.example.social/u/someone ativo").entities}
    assert "social_account:quuxsocial:someone" in got


# ------------------------------------------------------------------------------- unambiguous structure
def test_header_block_is_email_headers():
    block = "Received: from mx.example.net\nFrom: Bad <bad@sender.example.net>\nSubject: fatura\nMessage-ID: <1@sender.example.net>"
    d = det.detect(block)
    assert d[0].type is T.EMAIL_HEADERS and d[0].confidence == 0.95 and T.TEXT in [x.type for x in d]
    eml = block + "\n\nCorpo com link hxxp://evil[.]example.net/x"
    d = det.detect(eml)
    assert d[0].type is T.TEXT and T.EMAIL_HEADERS in [x.type for x in d]
    assert det.detect("plain\nmulti-line text")[0].type is T.TEXT


def test_tlsh_fediverse_and_brcode_structures():
    tlsh = "T1" + "0123456789ABCDEF" * 4 + "012345"
    assert best(tlsh).type is T.TLSH
    assert best("@alice@mastodon.social").type is T.FEDIVERSE_HANDLE
    assert best("alice@mastodon.social").type is T.EMAIL  # no leading '@': an e-mail, as today
    gui = "0014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-426655440000"
    body = "000201" + "26" + f"{len(gui):02d}" + gui + "5204000053039865802BR5910LOJA TESTE6008BRASILIA62070503***6304"
    code = body + format(val.crc16_ccitt(body.encode()), "04X")
    assert best(code).type is T.PIX_BRCODE
    broken = code[:-1] + ("0" if code[-1] != "0" else "1")
    assert T.PIX_BRCODE not in types(broken)


# ------------------------------------------------------------------------------- never from bare hex / digits
@pytest.mark.parametrize("raw,forbidden", [
    ("f34d5f2d4577ed6d9ceec516c1f5a744", {T.IMPHASH, T.BTC}),
    ("0123456789abcdef" * 4 + "0123456", {T.TLSH}),
    ("a" * 64, {T.AUTHENTIHASH, T.GIMPHASH}),
    ("76561197960287930", {T.STEAM_PROFILE, T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID}),
    ("52998224725", {T.SNOWFLAKE_ID, T.SOCIAL_ACCOUNT}),
    ("golpe123", {T.DISCORD_INVITE, T.TELEGRAM_INVITE, T.TELEGRAM_HANDLE}),
    ("alice.bsky.social", {T.BSKY_HANDLE}),
])
def test_new_types_never_from_bare_values(raw, forbidden):
    assert not set(types(raw)) & forbidden


def test_checksums_gate_crypto_typing():
    assert best("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe").type is T.ETH
    assert T.ETH not in types("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE")  # EIP-55 mismatch
    assert best("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").type is T.CRYPTO
    assert T.CRYPTO not in types("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u")


# ------------------------------------------------------------------------------- aliases (AR18)
def test_alias_from_a_tmp_fragment_is_malware_family_not_username(tmp_aliases):
    d = det.detect("Quuxbanker")
    assert d[0].type is T.MALWARE and d[0].value == "QuuxBanker" and d[0].confidence == 0.8
    assert T.USERNAME not in [x.type for x in d]
    assert det.detect("quux-bank")[0].value == "QuuxBanker"
    actor = det.detect("Plugh Panda")
    assert actor[0].type is T.THREAT_ACTOR and actor[0].value == "PLUGH SPIDER"
    assert det.detect("@quuxbanker")[0].type is T.USERNAME  # an explicit @handle stays a handle
    assert det.detect("user:quuxbanker")[0].type is T.USERNAME
    got = {i.entity.key for i in ioc.extract("the QuuxBanker trojan hit the bank").entities}
    assert "malware_family:QuuxBanker" in got


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


def test_bundled_alias_index_types_known_names(known_aliases):
    assert best("Emotet").type is T.MALWARE
    assert best("APT28").type is T.THREAT_ACTOR
    assert best("johndoe_99").type is T.USERNAME  # unknown tokens are unchanged


def test_alias_fragment_errors_are_collected(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps({"schema": ioc.ALIASES_SCHEMA, "kind": "other", "names": {}}), encoding="utf-8")
    (tmp_path / "gpl.json").write_text(json.dumps({"schema": ioc.ALIASES_SCHEMA, "kind": "threat_actor", "source": "x",
                                                   "licence": "GPL-3.0", "names": {"Zzyzx": "Zzyzx"}}), encoding="utf-8")
    try:
        ioc.reload_aliases([tmp_path])
        errors = ioc.alias_errors()
        assert any("bad.json" in e for e in errors) and any("gpl.json" in e and "A6" in e for e in errors)
        assert ioc.alias_lookup("Zzyzx") == []
    finally:
        ioc.reload_aliases()
    assert ioc.alias_errors() == []


# ------------------------------------------------------------------------------- sensitive single values
GH = "ghp" + "_" + "V3lumSyntheticTokenForTests0123456789"[:36]
BOT = "123456789" + ":AA" + "V3lumSyntheticBotTokenForTests0000"[:33]


@pytest.mark.parametrize("raw,etype,value", [
    ("4111111111111111", T.PAYMENT_CARD, "411111…1111"),
    ("4111 1111 1111 1111", T.PAYMENT_CARD, "411111…1111"),
    ("378282246310005", T.PAYMENT_CARD, "378282…0005"),  # 15-digit Amex
    ("411111…1111", T.PAYMENT_CARD, "411111…1111"),
    ("AKIA" + "IOSFODNN7EXAMPLE", T.SECRET, None),
    (GH, T.SECRET, None),
    (BOT, T.TELEGRAM_BOT_TOKEN, None),
    ("https://hooks.slack.com/services/" + "T00000000/B00000000/" + "V3lumSyntheticWebhook000", T.SECRET, None),
    ("github_token:ghp_…6789:0123456789abcdef", T.SECRET, "github_token:ghp_…6789:0123456789abcdef"),
])
def test_a_value_that_is_a_secret_or_a_card_is_typed_masked_and_alone(raw, etype, value):
    """P323 cond 5-7: a raw key, token or card number never becomes a username/keyword/URL seed
    (username packs and URL scanners would receive it); it is typed masked, as its only reading."""
    found = det.detect(raw)
    assert len(found) == 1 and found[0].type is etype and found[0].confidence >= 0.9
    if value is not None:
        assert found[0].value == value
    digits = raw.replace(" ", "")
    assert raw not in found[0].value or raw == found[0].value == value
    assert not (digits.isdigit() and digits in found[0].value)


def test_iban_single_value_is_not_investigated_and_lookalikes_keep_their_type():
    assert det.detect("DE89 3704 0044 0532 0130 00") == [] and det.detect("DE89370400440532013000") == []
    assert best("490154203237518").type is T.IMEI  # 15 digits with Luhn: an IMEI, as today
    assert best("11222333000181").type is T.CNPJ
    assert best("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc").type is T.JWT
    assert best("johndoe_99").type is T.USERNAME


def test_text_values_are_stored_scrubbed():
    text = f"linha um 45.33.32.156\ncartao 4111 1111 1111 1111 token {GH}"
    for found in (det.detect(text), det.detect("text_blob:" + text)):
        assert found[0].type is T.TEXT
        assert "4111 1111 1111 1111" not in found[0].value and GH not in found[0].value
        assert "411111…1111" in found[0].value and "45.33.32.156" in found[0].value
    eml = "From: a@sender.example.net\nSubject: x\nMessage-ID: <1@sender.example.net>\n\ncard 4111111111111111"
    assert all("4111111111111111" not in d.value for d in det.detect(eml))


def test_url_userinfo_credentials_are_dropped():
    assert best("https://admin:S3cretPass@evil.example.net/login").value == "https://evil.example.net/login"
    assert best("hxxps://admin:S3cretPass@evil[.]example.net/").value == "https://evil.example.net/"


# ------------------------------------------------------------------------------- extract_iocs wrapper
def test_extract_iocs_is_a_thin_wrapper():
    text = "C2 45.33.32.156 hxxp://bad[.]example.net/x invoice.zip CPF 111.444.777-35 card 4111 1111 1111 1111"
    wrapped = det.extract_iocs(text)
    engine = [e.entity for e in ioc.extract(text).entities if "low_confidence_tld" not in e.flags]
    assert wrapped == engine
    assert not any(e.type is T.CPF for e in wrapped)
    assert [e.value for e in wrapped if e.type is T.PAYMENT_CARD] == ["411111…1111"]
