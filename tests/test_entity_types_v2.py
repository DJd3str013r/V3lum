"""P333 entity types v2, A8 type sets, STIX mapping, AR24 masking, secrets and platform fragments."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from v3lum.core import entities as ent
from v3lum.core.detect import detect
from v3lum.core.entities import (
    COMPANY_ID_TYPES,
    IOC_TYPES,
    NO_AUTO_EXPAND,
    PERSONAL_TYPES,
    SECRET_TYPES,
    SOCIAL_PLATFORMS,
    STIX_SCO,
    TYPE_LABELS,
    Entity,
    EntityType,
    display_value,
    generic_address_kind,
    is_ioc,
    is_personal,
    is_secret,
    normalize,
    platform_for_url,
    redacted_value,
    secret_entity,
    secret_fingerprint,
)

T = EntityType
BR_CODE = (
    "00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-4266554400005204000053039865802BR"
    "5913Fulano de Tal6008BRASILIA62070503***63041D3D"
)
TG_TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"
PAN = "4111111111111111"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3h5ejQ"
TLSH = "T141A022003B0EEE2BA20B00200032E8B00808020E2CE00A3820A020B8C83308803EC228"  # YARAify sample (EICAR)


def _crc(payload: str) -> str:
    from v3lum.core.validators import crc16_ccitt

    return format(crc16_ccitt(payload.encode()), "04X")


def brcode_with_key(key: str) -> str:
    gui = "0014br.gov.bcb.pix" + f"01{len(key):02d}{key}"
    body = f"00020126{len(gui):02d}{gui}52040000530398654041.005802BR5913Fulano de Tal6008BRASILIA62070503***6304"
    return body + _crc(body)


# ---------------------------------------------------------------- members, labels, aliases

NEW_TYPES = {
    "EMAIL_HEADERS": "email_headers", "TELEGRAM_HANDLE": "telegram_handle", "TELEGRAM_INVITE": "telegram_invite",
    "DISCORD_INVITE": "discord_invite", "SOCIAL_ACCOUNT": "social_account", "PIX_BRCODE": "pix_brcode",
    "IMPHASH": "imphash", "TLSH": "tlsh", "TELFHASH": "telfhash", "GIMPHASH": "gimphash", "AUTHENTIHASH": "authentihash",
    "ICON_DHASH": "icon_dhash", "CODE_SIGNING_CERT": "code_signing_cert", "PGP_FINGERPRINT": "pgp_fingerprint",
    "FEDIVERSE_HANDLE": "fediverse_handle", "BSKY_HANDLE": "bsky_handle", "STEAM_PROFILE": "steam_profile",
    "PORT_SERVICE": "port_service", "VIN": "vin", "TELEGRAM_BOT_TOKEN": "telegram_bot_token", "SECRET": "secret",
    "PAYMENT_CARD": "payment_card", "EU_VAT": "eu_vat", "TIKTOK_VIDEO_ID": "tiktok_video_id", "SNOWFLAKE_ID": "snowflake_id",
}


def test_new_members_values_and_labels():
    for name, value in NEW_TYPES.items():
        assert EntityType[name].value == value
    assert set(TYPE_LABELS) == set(EntityType), "every type has a label"
    assert all(TYPE_LABELS[t] for t in EntityType)


@pytest.mark.parametrize(
    "alias,etype",
    [("telegram", T.TELEGRAM_HANDLE), ("tg", T.TELEGRAM_HANDLE), ("discord", T.DISCORD_INVITE), ("pgp", T.PGP_FINGERPRINT),
     ("vin", T.VIN), ("port", T.PORT_SERVICE), ("card", T.PAYMENT_CARD), ("vat", T.EU_VAT), ("snowflake", T.SNOWFLAKE_ID),
     ("social", T.SOCIAL_ACCOUNT), ("bsky", T.BSKY_HANDLE), ("steam", T.STEAM_PROFILE), ("imphash", T.IMPHASH)],
)
def test_aliases(alias, etype):
    assert EntityType.parse(alias) is etype


# ---------------------------------------------------------------- normalisation (positive)


@pytest.mark.parametrize(
    "etype,raw,expected",
    [
        (T.TELEGRAM_HANDLE, "@Durov_Channel", "durov_channel"),
        (T.TELEGRAM_HANDLE, "https://t.me/durovchannel", "durovchannel"),
        (T.TELEGRAM_HANDLE, "t[.]me/s/durovchannel", "durovchannel"),
        (T.TELEGRAM_INVITE, "https://t.me/+AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
        (T.TELEGRAM_INVITE, "t.me/joinchat/AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
        (T.DISCORD_INVITE, "https://discord.gg/AbC123", "AbC123"),
        (T.DISCORD_INVITE, "discord.com/invite/AbC123", "AbC123"),
        (T.SOCIAL_ACCOUNT, "twitter:@JohnDoe", "x:johndoe"),
        (T.SOCIAL_ACCOUNT, "Instagram:John.Doe", "instagram:john.doe"),
        (T.SOCIAL_ACCOUNT, "https://www.instagram.com/John.Doe/?hl=en", "instagram:john.doe"),
        (T.SOCIAL_ACCOUNT, "https://mobile.twitter.com/jack", "x:jack"),
        (T.SOCIAL_ACCOUNT, "https://www.tiktok.com/@john.doe", "tiktok:john.doe"),
        (T.PIX_BRCODE, BR_CODE[:-4] + "1d3d", BR_CODE),
        (T.IMPHASH, "F34D5F2D4577ED6D9CEEC516C1F5A744", "f34d5f2d4577ed6d9ceec516c1f5a744"),
        (T.TLSH, TLSH.lower(), TLSH),
        (T.TELFHASH, "t1" + "ab" * 35, "T1" + "AB" * 35),
        (T.GIMPHASH, "A" * 64, "a" * 64),
        (T.AUTHENTIHASH, "B" * 64, "b" * 64),
        (T.ICON_DHASH, "E0E8C8F0E0E0E0E0", "e0e8c8f0e0e0e0e0"),
        (T.CODE_SIGNING_CERT, "AA:BB:" + "cc" * 18, "aabb" + "cc" * 18),
        (T.CODE_SIGNING_CERT, "serial: 0A:1B ;issuer: CN=Evil  Corp CA", "serial:0a1b;issuer:CN=Evil Corp CA"),
        (T.PGP_FINGERPRINT, "0x" + "ab12 " * 10, "AB12" * 10),
        (T.FEDIVERSE_HANDLE, "@Gargron@Mastodon.Social", "gargron@mastodon.social"),
        (T.FEDIVERSE_HANDLE, "https://mastodon.social/@Gargron", "gargron@mastodon.social"),
        (T.FEDIVERSE_HANDLE, "https://m.cmx.im/@someone", "someone@m.cmx.im"),
        (T.BSKY_HANDLE, "https://bsky.app/profile/Alice.bsky.social", "alice.bsky.social"),
        (T.BSKY_HANDLE, "https://bsky.app/profile/alice.bsky.social/post/3kabc", "alice.bsky.social"),
        (T.BSKY_HANDLE, "@alice.bsky.social", "alice.bsky.social"),
        (T.STEAM_PROFILE, "https://steamcommunity.com/id/GabeLoganNewell/", "id:gabelogannewell"),
        (T.STEAM_PROFILE, "steamcommunity.com/profiles/76561197960287930", "profiles:76561197960287930"),
        (T.STEAM_PROFILE, "76561197960287930", "profiles:76561197960287930"),
        (T.PORT_SERVICE, "Example.COM:443/TCP", "example.com:443/tcp"),
        (T.PORT_SERVICE, "[2001:0db8::1]:53/udp", "[2001:db8::1]:53/udp"),
        (T.PORT_SERVICE, "8.8.8.8:53", "8.8.8.8:53/tcp"),
        (T.VIN, "1hgcm82633a004352", "1HGCM82633A004352"),
        (T.PAYMENT_CARD, "4111 1111 1111 1111", "411111…1111"),
        (T.PAYMENT_CARD, "411111******1111", "411111…1111"),
        (T.PAYMENT_CARD, "411111…1111", "411111…1111"),
        (T.EU_VAT, "DE 136 695 976", "DE136695976"),
        (T.EU_VAT, "VAT: GR094259216", "EL094259216"),
        (T.TIKTOK_VIDEO_ID, "https://www.tiktok.com/@user/video/7301234567890123456", "7301234567890123456"),
        (T.TIKTOK_VIDEO_ID, "7301234567890123456", "7301234567890123456"),
        (T.SNOWFLAKE_ID, "175928847299117063", "175928847299117063"),
    ],
)
def test_normalize_new_types(etype, raw, expected):
    assert normalize(etype, raw) == expected
    assert normalize(etype, expected) == expected  # idempotent


@pytest.mark.parametrize(
    "etype,raw",
    [
        (T.TELEGRAM_HANDLE, "@abc"),  # too short
        (T.TELEGRAM_HANDLE, "https://t.me/+AbCdEfGhIjKlMnOp"),  # an invite, not a handle
        (T.TELEGRAM_HANDLE, "https://t.me/share/url?url=x"),
        (T.TELEGRAM_HANDLE, "https://example.com/durovchannel"),
        (T.TELEGRAM_HANDLE, "1durov"),
        (T.TELEGRAM_INVITE, "https://t.me/durovchannel"),
        (T.TELEGRAM_INVITE, "+short"),
        (T.DISCORD_INVITE, "https://discord.com/channels/1/2"),
        (T.DISCORD_INVITE, "bad code!"),
        (T.SOCIAL_ACCOUNT, "myspace:johndoe"),
        (T.SOCIAL_ACCOUNT, "johndoe"),
        (T.SOCIAL_ACCOUNT, "instagram:john doe"),
        (T.SOCIAL_ACCOUNT, "https://www.instagram.com/p/Cxyz/"),
        (T.SOCIAL_ACCOUNT, "https://example.com/johndoe"),
        (T.SOCIAL_ACCOUNT, "x:..."),  # punctuation only
        (T.SOCIAL_ACCOUNT, "instagram:-"),
        (T.PIX_BRCODE, BR_CODE[:-4] + "0000"),  # wrong CRC
        (T.PIX_BRCODE, "000201" + "x" * 600),
        (T.PIX_BRCODE, BR_CODE.replace("Fulano de Tal", "Fulano\nde Tal")),
        (T.IMPHASH, "f34d5f2d4577ed6d9ceec516c1f5a74"),
        (T.TLSH, "T1" + "ab" * 34),
        (T.TLSH, "ab" * 36),  # 72 hex without the T1 version prefix
        (T.GIMPHASH, "g" * 64),
        (T.ICON_DHASH, "e0e8c8f0e0e0e0e"),
        (T.CODE_SIGNING_CERT, "abcd"),
        (T.CODE_SIGNING_CERT, "serial:zz;issuer:CN=x"),
        (T.PGP_FINGERPRINT, "AB12" * 9),
        (T.FEDIVERSE_HANDLE, "gargron"),
        (T.FEDIVERSE_HANDLE, "@gargron@localhost"),
        (T.BSKY_HANDLE, "https://bsky.app/profile/did:plc:abc123"),
        (T.BSKY_HANDLE, "https://example.com/profile/alice.bsky.social"),
        (T.STEAM_PROFILE, "76561197960265727"),  # below the individual-account range
        (T.STEAM_PROFILE, "profiles:123"),
        (T.STEAM_PROFILE, "https://steamcommunity.com/groups/x"),
        (T.PORT_SERVICE, "example.com:0/tcp"),
        (T.PORT_SERVICE, "example.com:70000/tcp"),
        (T.PORT_SERVICE, "example.com:443/icmp"),
        (T.PORT_SERVICE, "2001:db8::1:443/tcp"),  # IPv6 needs brackets
        (T.PORT_SERVICE, "user@example.com:22/tcp"),  # no userinfo in the host
        (T.VIN, "1HGCM82633A00435"),  # 16 chars
        (T.VIN, "1HGCM82633A00435I"),  # I is never used
        (T.TELEGRAM_BOT_TOKEN, "123:abc"),
        (T.SECRET, "AKIAIOSFODNN7EXAMPLE"),  # raw secrets are refused (use secret_entity)
        (T.PAYMENT_CARD, "4111111111111112"),  # Luhn
        (T.PAYMENT_CARD, "12345"),
        (T.EU_VAT, "DE136695977"),
        (T.EU_VAT, "US123456789"),
        (T.TIKTOK_VIDEO_ID, "https://www.tiktok.com/@user"),
        (T.TIKTOK_VIDEO_ID, "12345"),
        (T.TIKTOK_VIDEO_ID, "0301234567890123456"),  # leading zero: would not normalize to itself
        (T.TIKTOK_VIDEO_ID, "000000000000000123"),
        (T.SNOWFLAKE_ID, "12345"),
        (T.SNOWFLAKE_ID, "99999999999999999999"),  # > 64 bits
        (T.SNOWFLAKE_ID, "000004194304000000"),
        (T.EMAIL_HEADERS, "Subject: hello"),  # a single field
        (T.EMAIL_HEADERS, "X-Foo: 1\nX-Bar: 2"),  # none of From/Received/Message-ID/Subject
        (T.EMAIL_HEADERS, "this is not\na header block"),
    ],
)
def test_normalize_new_types_rejects(etype, raw):
    with pytest.raises(ValueError):
        normalize(etype, raw)


def test_existing_normalizers_unchanged():
    assert normalize(T.JWT, JWT) == JWT  # JWT keeps the raw token
    assert normalize(T.CPF, "529.982.247-25") == "52998224725"  # CPF stays digits
    assert Entity.make("cnpj", "00000000000191").display == "00.000.000/0001-91"
    assert normalize(T.ETH, "0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE") == "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"


# ---------------------------------------------------------------- e-mail headers


def test_email_headers_block():
    raw = (
        "From user@example.com Mon Jan  1 00:00:00 2026\r\n"
        "Received: from mx.example.com\r\n by mail.example.org\r\n"
        "From: Alice <alice@example.com>\r\nSubject: =?UTF-8?B?T2zDoQ==?=\r\nMessage-ID: <1@example.com>\r\n\r\n"
        "body with https://tracker.example/pixel.gif"
    )
    value = normalize(T.EMAIL_HEADERS, raw)
    assert "\r" not in value and "pixel.gif" not in value and not value.startswith("From user")
    assert value.splitlines()[0] == "Received: from mx.example.com"
    assert display_value(T.EMAIL_HEADERS, value) == "Email headers (4 fields): Olá"
    with pytest.raises(ValueError):
        normalize(T.EMAIL_HEADERS, "Subject: x\nFrom: a@b.c\nX-Pad: " + "a" * (256 * 1024))


# ---------------------------------------------------------------- collisions: never inferred from bare hex/digits


@pytest.mark.parametrize(
    "raw,forbidden",
    [
        ("f34d5f2d4577ed6d9ceec516c1f5a744", {T.IMPHASH}),
        ("a" * 64, {T.AUTHENTIHASH, T.GIMPHASH}),
        ("e0e8c8f0e0e0e0e0", {T.ICON_DHASH}),
        ("ab12" * 10, {T.PGP_FINGERPRINT, T.CODE_SIGNING_CERT}),
        ("76561197960287930", {T.STEAM_PROFILE, T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID}),
        ("175928847299117063", {T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID}),
        ("7301234567890123456", {T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID}),
        ("52998224725", {T.STEAM_PROFILE, T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID, T.EU_VAT}),
        ("DE136695976", {T.EU_VAT}),
        ("1HGCM82633A004352", {T.VIN}),
    ],
)
def test_new_types_never_inferred_from_bare_values(raw, forbidden):
    assert not {d.type for d in detect(raw)} & forbidden


def test_md5_sha256_detection_unchanged():
    assert detect("f34d5f2d4577ed6d9ceec516c1f5a744")[0].type is T.MD5
    assert detect("a" * 64)[0].type is T.SHA256


@pytest.mark.parametrize(
    "raw,etype,value",
    [
        ("imphash:F34D5F2D4577ED6D9CEEC516C1F5A744", T.IMPHASH, "f34d5f2d4577ed6d9ceec516c1f5a744"),
        ("authentihash:" + "a" * 64, T.AUTHENTIHASH, "a" * 64),
        ("steam_profile:76561197960287930", T.STEAM_PROFILE, "profiles:76561197960287930"),
        ("snowflake_id:175928847299117063", T.SNOWFLAKE_ID, "175928847299117063"),
        ("tiktok_video_id:7301234567890123456", T.TIKTOK_VIDEO_ID, "7301234567890123456"),
        ("eu_vat:DE136695976", T.EU_VAT, "DE136695976"),
        ("vin:1HGCM82633A004352", T.VIN, "1HGCM82633A004352"),
        ("tg:durovchannel", T.TELEGRAM_HANDLE, "durovchannel"),
        ("card:4111111111111111", T.PAYMENT_CARD, "411111…1111"),
    ],
)
def test_explicit_prefix_types(raw, etype, value):
    found = detect(raw)
    assert len(found) == 1 and found[0].type is etype and found[0].value == value


# ---------------------------------------------------------------- type sets (A8)


def test_type_sets_membership():
    assert {
        T.EMAIL, T.PHONE, T.USERNAME, T.PERSON, T.CPF, T.PIX, T.PLATE_BR, T.IMEI, T.COORDINATES, T.SOCIAL_ACCOUNT,
        T.TELEGRAM_HANDLE, T.TELEGRAM_INVITE, T.DISCORD_INVITE, T.FEDIVERSE_HANDLE, T.BSKY_HANDLE, T.STEAM_PROFILE,
        T.VIN, T.EMAIL_HEADERS, T.PIX_BRCODE, T.PGP_FINGERPRINT,
    } == PERSONAL_TYPES
    assert {
        T.DOMAIN, T.URL, T.IPV4, T.IPV6, T.CIDR, T.ASN, T.MD5, T.SHA1, T.SHA256, T.SHA512, T.SSDEEP, T.CVE, T.MITRE,
        T.ONION, T.BTC, T.ETH, T.XMR, T.CRYPTO, T.FAVICON_HASH, T.CERT_FP, T.ANALYTICS_ID, T.IMPHASH, T.TLSH,
        T.TELFHASH, T.GIMPHASH, T.AUTHENTIHASH, T.ICON_DHASH, T.CODE_SIGNING_CERT, T.PORT_SERVICE,
    } == IOC_TYPES
    assert {T.JWT, T.TELEGRAM_BOT_TOKEN, T.SECRET, T.PAYMENT_CARD} == SECRET_TYPES
    assert {
        T.TEXT, T.FILE, T.KEYWORD, T.PERSON, T.USER_AGENT, T.CPF, T.COORDINATES, T.CARD_BIN, T.IMEI,
        T.EMAIL_HEADERS, T.PORT_SERVICE, T.PIX_BRCODE,
    } | SECRET_TYPES == NO_AUTO_EXPAND
    assert {T.CNPJ, T.EU_VAT} == COMPANY_ID_TYPES
    assert not PERSONAL_TYPES & IOC_TYPES and not SECRET_TYPES & (PERSONAL_TYPES | IOC_TYPES)
    for etype in (T.TIKTOK_VIDEO_ID, T.SNOWFLAKE_ID):  # not personal by themselves (P333 scope extension)
        assert etype not in PERSONAL_TYPES


def test_type_set_helpers_accept_types_names_and_entities():
    assert is_personal(T.EMAIL) and is_personal("social_account") and is_personal(Entity.make("vin", "1HGCM82633A004352"))
    assert is_ioc("imphash") and is_ioc(T.PORT_SERVICE) and not is_ioc(T.EMAIL)
    assert is_secret("jwt") and is_secret(T.PAYMENT_CARD) and not is_secret("bogus")
    assert ent.is_company_id("eu_vat") and ent.is_company_id(T.CNPJ)


# ---------------------------------------------------------------- STIX mapping


def test_stix_sco_covers_every_type():
    assert set(STIX_SCO) == set(EntityType)
    expected = {
        T.DOMAIN: "domain-name", T.URL: "url", T.IPV4: "ipv4-addr", T.IPV6: "ipv6-addr", T.EMAIL: "email-addr",
        T.ASN: "autonomous-system", T.MAC: "mac-addr", T.EMAIL_HEADERS: "email-message",
        T.CERT_FP: "x509-certificate", T.CODE_SIGNING_CERT: "x509-certificate",
    }
    for etype, sco in expected.items():
        assert STIX_SCO[etype] == sco
    for etype in (T.MD5, T.SHA1, T.SHA256, T.SHA512, T.SSDEEP, T.IMPHASH, T.TLSH, T.TELFHASH, T.GIMPHASH,
                  T.AUTHENTIHASH, T.ICON_DHASH):
        assert STIX_SCO[etype] == "file"
    for etype in (T.USERNAME, T.SOCIAL_ACCOUNT, T.TELEGRAM_HANDLE, T.FEDIVERSE_HANDLE, T.BSKY_HANDLE, T.STEAM_PROFILE):
        assert STIX_SCO[etype] == "user-account"
    for etype in SECRET_TYPES | {T.CPF, T.EU_VAT, T.TIKTOK_VIDEO_ID, T.SNOWFLAKE_ID, T.VIN, T.PIX_BRCODE, T.PORT_SERVICE}:
        assert STIX_SCO[etype] is None  # 'no STIX object'
    assert ent.stix_sco_type(T.CIDR, "2001:db8::/32") == "ipv6-addr" and ent.stix_sco_type(T.CIDR, "10.0.0.0/8") == "ipv4-addr"


# ---------------------------------------------------------------- masking (AR24)


def test_cpf_display_mask():
    assert display_value(T.CPF, "52998224725") == "***.982.247-**"
    assert display_value(T.CPF, "12345678909") == "***.456.789-**"
    assert display_value(T.CPF, "52998224725", show_personal=True) == "529.982.247-25"
    assert redacted_value(T.CPF, "52998224725") == "***.982.247-**"
    assert Entity.make("cpf", "529.982.247-25").display == "***.982.247-**"
    assert "52998224725" not in Entity.make("cpf", "52998224725").redacted


def test_vin_partly_masked():
    assert display_value(T.VIN, "1HGCM82633A004352") == "1HGCM82633A******"
    assert display_value(T.VIN, "1HGCM82633A004352", show_personal=True) == "1HGCM82633A004352"
    assert redacted_value(T.VIN, "1HGCM82633A004352") == "1HGCM82633A******"


def test_secret_type_previews_and_redaction():
    assert display_value(T.JWT, JWT) == "eyJh…5ejQ (jwt)"
    assert display_value(T.JWT, JWT, show_personal=True) == "eyJh…5ejQ (jwt)"  # secrets are never shown
    fp = redacted_value(T.JWT, JWT)
    assert fp.startswith("jwt:eyJh…5ejQ:") and JWT not in fp and len(fp.rsplit(":", 1)[1]) == 16
    sec = secret_entity("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    assert sec.type is T.SECRET and sec.value.startswith("aws_access_key:AKIA…MPLE:")
    assert display_value(T.SECRET, sec.value) == "AKIA…MPLE (aws_access_key)"
    assert redacted_value(T.SECRET, sec.value) == sec.value
    card = normalize(T.PAYMENT_CARD, PAN)
    assert display_value(T.PAYMENT_CARD, card) == redacted_value(T.PAYMENT_CARD, card) == "411111…1111"


def test_no_normalizer_stores_a_raw_secret_or_full_pan():
    token = Entity.make("telegram_bot_token", TG_TOKEN)
    assert TG_TOKEN not in token.value and TG_TOKEN.split(":")[1] not in token.key
    assert token.value.startswith("telegram_bot_token:1234…saw1:")
    assert normalize(T.TELEGRAM_BOT_TOKEN, "bot" + TG_TOKEN) == token.value
    assert normalize(T.TELEGRAM_BOT_TOKEN, token.value) == token.value  # fingerprints are accepted as is
    with pytest.raises(ValueError):
        normalize(T.TELEGRAM_BOT_TOKEN, secret_fingerprint("aws", "x" * 20))  # another secret kind
    card = Entity.make("payment_card", "4111-1111-1111-1111")
    assert PAN not in card.key and card.value == "411111…1111"
    with pytest.raises(ValueError) as exc:
        normalize(T.PAYMENT_CARD, "4111111111111112")
    assert "4111111111111112" not in str(exc.value)  # errors never echo the number
    with pytest.raises(ValueError):
        normalize(T.SECRET, "ghp_" + "a" * 36)


def test_an_entity_never_holds_a_raw_secret_or_full_pan():
    """Entities built directly (graph/case keys, careless modules) are coerced like normalize() would."""
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    direct = Entity(T.SECRET, raw_key)
    assert raw_key not in direct.key and direct.value.startswith("secret:AKIA…MPLE:")
    assert ent.parse_fingerprint(direct.value) is not None
    assert Entity(T.TELEGRAM_BOT_TOKEN, TG_TOKEN) == Entity.make("telegram_bot_token", TG_TOKEN)
    assert Entity(T.TELEGRAM_BOT_TOKEN, "bot" + TG_TOKEN) == Entity.make("telegram_bot_token", TG_TOKEN)
    stored = Entity(EntityType("payment_card"), "4111 1111 1111 1111")  # how stored keys are re-read
    assert stored.value == "411111…1111" and PAN not in stored.key
    assert PAN not in Entity(T.PAYMENT_CARD, f"card {PAN} exp 12/27").value
    assert Entity(T.PAYMENT_CARD, "").value == "…"
    sec = secret_entity("aws_access_key", raw_key)
    assert Entity(T.SECRET, sec.value) == sec  # fingerprints are kept as they are
    jwt = Entity(T.JWT, JWT)
    assert jwt.value == JWT and JWT not in jwt.redacted  # JWT keeps the raw token (spec); outputs mask it


@pytest.mark.parametrize("value", ["", "   ", "\x00\x1b[31m", "…", "a" * 5000, "secret:…:0000000000000000", "4111111111111111"])
def test_display_and_redaction_never_raise(value):
    """Renderers and exports call these on stored values of any shape: they must never raise or leak a PAN."""
    for etype in EntityType:
        shown, stored = display_value(etype, value), redacted_value(etype, value)
        assert isinstance(shown, str) and isinstance(stored, str)
        if etype in SECRET_TYPES:
            assert PAN not in shown and PAN not in stored
    assert redacted_value(T.JWT, "") == "" and redacted_value(T.SECRET, "").startswith("secret:")


def test_every_type_has_a_normalizer():
    for etype in EntityType:
        try:
            normalize(etype, "zz")
        except ValueError as exc:
            assert "no normalizer" not in str(exc), etype


def test_secret_fingerprint_format_and_short_secrets():
    fp = secret_fingerprint("GitHub Token!", "ghp_" + "a" * 36)
    assert fp.startswith("github_token:ghp_…aaaa:")
    assert ent.parse_fingerprint(fp)[0] == "github_token"
    assert secret_fingerprint("x", "abcdefghijkl").split(":")[1] == "ab…kl"
    assert secret_fingerprint("x", "short").split(":")[1] == "…"  # nothing revealed
    assert secret_fingerprint("9bad", "a:b cé" * 4).split(":")[0] == "secret"
    assert "*" in secret_fingerprint("k", "a b c d e f g h i j")  # unsafe preview chars are starred
    with pytest.raises(ValueError):
        secret_fingerprint("k", "   ")


def test_pix_brcode_display_masks_a_cpf_key():
    code = normalize(T.PIX_BRCODE, brcode_with_key("52998224725"))
    shown = display_value(T.PIX_BRCODE, code)
    assert "52998224725" not in shown and "***.982.247-**" in shown and "Fulano de Tal" in shown
    assert "52998224725" in display_value(T.PIX_BRCODE, code, show_personal=True)
    redacted = redacted_value(T.PIX_BRCODE, code)
    assert "52998224725" not in redacted and "***982247**" in redacted and len(redacted) == len(code)
    evp = normalize(T.PIX_BRCODE, BR_CODE)
    assert redacted_value(T.PIX_BRCODE, evp) == evp
    assert display_value(T.PIX_BRCODE, evp) == "PIX BR Code: key 123e4567-e12b-12d1-a456-426655440000, Fulano de Tal, BRASILIA"


def test_pix_brcode_redaction_masks_every_copy_of_a_cpf_key():
    key = "52998224725"
    gui = "0014br.gov.bcb.pix" + f"01{len(key):02d}{key}"
    txid = f"05{len(key):02d}{key}"  # the merchant reused the CPF as the transaction id
    body = f"00020126{len(gui):02d}{gui}52040000530398654041.005802BR5913Fulano de Tal6008BRASILIA62{len(txid):02d}{txid}6304"
    code = normalize(T.PIX_BRCODE, body + _crc(body))
    redacted = redacted_value(T.PIX_BRCODE, code)
    assert key not in redacted and redacted.count("***982247**") == 2
    assert key not in display_value(T.PIX_BRCODE, code)


def test_display_of_handles():
    assert display_value(T.TELEGRAM_HANDLE, "durovchannel") == "@durovchannel"
    assert display_value(T.FEDIVERSE_HANDLE, "gargron@mastodon.social") == "@gargron@mastodon.social"
    assert display_value(T.SOCIAL_ACCOUNT, "x:jack") == "x:jack"


# ---------------------------------------------------------------- generic addresses (A4 BR6)


@pytest.mark.parametrize(
    "email,kind",
    [
        ("someone@example.com", "example_domain"),
        ("john@mail.example.org", "example_domain"),
        ("a@corp.test", "example_domain"),
        ("x@host.invalid", "example_domain"),
        ("test@acme.com.br", "test"),
        ("teste123@acme.com.br", "test"),
        ("contato@acme.com.br", "role"),
        ("NoReply+tag@acme.com", "role"),
        ("no-reply@acme.com", "role"),
        ("abuse@acme.com", "role"),
        ("financeiro@acme.com.br", "role"),
        ("joao.silva@acme.com.br", None),
        ("not an email", None),
    ],
)
def test_generic_address_kind(email, kind):
    assert generic_address_kind(email) == kind


def test_generic_addresses_data_file():
    data = json.loads(ent.GENERIC_ADDRESSES_PATH.read_text(encoding="utf-8"))
    assert data["schema"] == "v3lum.generic_addresses/1"
    for part in ("test", "info", "contato", "contact", "sac", "admin", "noreply", "no-reply", "suporte", "support",
                 "vendas", "financeiro", "rh", "webmaster", "postmaster", "abuse"):
        assert part in data["local_parts"]
    assert data["domains"] == ["example.com", "example.net", "example.org"]
    assert data["domain_suffixes"] == [".example", ".test", ".invalid", ".localhost"]
    assert generic_address_kind(Entity.make("email", "info@acme.com")) == "role"


# ---------------------------------------------------------------- EU VAT, snowflakes, TikTok


@pytest.mark.parametrize(
    "vat",
    ["ATU13585627", "BE0403019261", "BG175074752", "CY10259033P", "CZ25123891", "DE136695976", "DK13585628",
     "EE100931558", "EL094259216", "ESA13585625", "ES54362315K", "FI20774740", "FR40303265045", "HR33392005961",
     "HU12892312", "IE6433435F", "IE6433435OA", "IE8Z49289F", "IT00743110157", "LT119511515", "LT100001919017",
     "LU15027442", "LV40003521600", "MT11679112", "NL004495445B01", "PL8567346215", "PT501964843", "RO18547290",
     "SE123456789701", "SI50223054", "SK2022749619", "XI980780684"],
)
def test_eu_vat_checksums(vat):
    assert normalize(T.EU_VAT, vat) == vat
    last = vat[-1]
    mutated = vat[:-1] + (str((int(last) + 1) % 10) if last.isdigit() else ("B" if last != "B" else "C"))
    if vat[:2] not in ("NL", "SE"):  # their last two digits are a suffix, not the check digit
        with pytest.raises(ValueError):
            normalize(T.EU_VAT, mutated)


def test_p3_slip_types_display_stix_and_privacy_class():
    assert display_value(T.EU_VAT, "DE136695976") == redacted_value(T.EU_VAT, "DE136695976") == "DE136695976"
    assert display_value(T.TIKTOK_VIDEO_ID, "7301234567890123456") == "7301234567890123456"
    assert display_value(T.SNOWFLAKE_ID, "175928847299117063") == "175928847299117063"
    for etype in (T.EU_VAT, T.TIKTOK_VIDEO_ID, T.SNOWFLAKE_ID):
        assert STIX_SCO[etype] is None and TYPE_LABELS[etype]
        assert etype not in PERSONAL_TYPES and etype not in IOC_TYPES
    assert ent.is_company_id(T.EU_VAT) and not ent.is_company_id(T.SNOWFLAKE_ID)  # EU VAT is treated like CNPJ (A8 BR4)


def test_snowflake_and_tiktok_timestamps():
    assert ent.snowflake_timestamp("175928847299117063") == datetime(2016, 4, 30, 11, 18, 25, 796000, tzinfo=timezone.utc)
    ms = int(datetime(2023, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp() * 1000)
    x_id = (ms - 1288834974657) << 22
    assert ent.snowflake_timestamp(str(x_id), epoch="twitter") == datetime(2023, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        ent.snowflake_timestamp("1", epoch="myspace")
    from v3lum.core.validators import tiktok_id_timestamp

    tiktok = (int(datetime(2023, 11, 14, tzinfo=timezone.utc).timestamp()) << 32) | 12345
    assert tiktok_id_timestamp(str(tiktok)) == datetime(2023, 11, 14, tzinfo=timezone.utc)


# ---------------------------------------------------------------- social platforms and fragments


def test_core_platforms():
    core = {
        "instagram", "tiktok", "x", "facebook", "linkedin", "youtube", "github", "gitlab", "reddit", "threads",
        "pinterest", "twitch", "kwai", "snapchat",
    }
    assert core == set(ent.CORE_PLATFORMS)
    assert core <= SOCIAL_PLATFORMS  # module-batch fragments (v3lum/data/platforms/) only add platforms
    assert ent.platform_errors() == []
    assert "x" in SOCIAL_PLATFORMS and "twitter" not in SOCIAL_PLATFORMS and ent.resolve_platform("Twitter") == "x"
    assert len(ent.CORE_PLATFORMS) == 14 and sorted(ent.CORE_PLATFORMS)[0] == "facebook"
    assert SOCIAL_PLATFORMS & {"x", "myspace"} == {"x"}


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.instagram.com/John.Doe/", ("instagram", "john.doe")),
        ("instagram.com/john_doe?igsh=abc", ("instagram", "john_doe")),
        ("https://x.com/jack", ("x", "jack")),
        ("https://twitter.com/jack/", ("x", "jack")),
        ("https://www.youtube.com/@MrBeast", ("youtube", "mrbeast")),
        ("https://www.linkedin.com/in/john-doe-123/", ("linkedin", "john-doe-123")),
        ("https://github.com/octocat", ("github", "octocat")),
        ("https://www.reddit.com/user/spez", ("reddit", "spez")),
        ("https://www.twitch.tv/somestreamer", ("twitch", "somestreamer")),
        ("https://www.snapchat.com/add/someone", ("snapchat", "someone")),
        ("hxxps://www[.]tiktok[.]com/@john.doe", ("tiktok", "john.doe")),
        ("https://www.instagram.com/p/Cxyz/", None),
        ("https://www.facebook.com/profile.php?id=4", None),
        ("https://twitter.com/home", None),
        ("https://github.com/orgs", None),
        ("https://www.tiktok.com/@john.doe/video/7301234567890123456", None),
        ("https://www.youtube.com/channel/UCX6OQ3DkcsbYNE6H8uQQuVA", None),  # case-sensitive id, not a handle
        ("https://example.com/johndoe", None),
        ("ftp://github.com/octocat", None),
        ("not a url", None),
    ],
)
def test_platform_for_url(url, expected):
    assert platform_for_url(url) == expected


def test_platform_added_by_tmp_fragment(tmp_path):
    fragment = {
        "schema": "v3lum.platforms/1",
        "platforms": {
            "mastodon_social": {
                "title": "mastodon.social",
                "aliases": ["msocial"],
                "profile_url_patterns": ["https://mastodon.social/@{handle}"],
                "reserved_handles": ["explore"],
            },
            "x": {"aliases": [], "profile_url_patterns": ["https://xcancel.com/{handle}"]},  # adds a mirror pattern
        },
    }
    (tmp_path / "batch_g04.json").write_text(json.dumps(fragment), encoding="utf-8")
    before = len(SOCIAL_PLATFORMS)  # the core set plus the bundled batch fragments
    try:
        ent.reload_platforms(extra_dirs=[tmp_path])
        assert "mastodon_social" in SOCIAL_PLATFORMS and len(SOCIAL_PLATFORMS) == before + 1
        assert ent.platform_errors() == []
        assert normalize(T.SOCIAL_ACCOUNT, "mastodon_social:Gargron") == "mastodon_social:gargron"
        assert normalize(T.SOCIAL_ACCOUNT, "msocial:gargron") == "mastodon_social:gargron"
        assert platform_for_url("https://mastodon.social/@Gargron") == ("mastodon_social", "gargron")
        assert platform_for_url("https://mastodon.social/@explore") is None
        assert platform_for_url("https://xcancel.com/jack") == ("x", "jack")
        assert ent.platforms()["x"].title == "X (Twitter)"  # first title wins
    finally:
        ent.reload_platforms()
    assert "mastodon_social" not in SOCIAL_PLATFORMS
    with pytest.raises(ValueError):
        normalize(T.SOCIAL_ACCOUNT, "mastodon_social:gargron")


def test_invalid_platform_fragments_are_reported(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps({
        "schema": "v3lum.platforms/1",
        "platforms": {
            "Bad-Name": {"title": "x"},
            "newsite": {"aliases": ["twitter"], "profile_url_patterns": ["https://newsite.example/{user}", "javascript:{handle}"]},
        },
    }), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "wrong_schema.json").write_text(json.dumps({"schema": "v3lum.platforms/9", "platforms": {}}), encoding="utf-8")
    try:
        ent.reload_platforms(extra_dirs=[tmp_path])
        errors = "\n".join(ent.platform_errors())
        assert "invalid platform name 'Bad-Name'" in errors
        assert "alias 'twitter' already belongs to platform 'x'" in errors
        assert "exactly one {handle}" in errors and "https://<host>" in errors
        assert "broken.json: unreadable" in errors and "wrong_schema.json" in errors
        assert ent.resolve_platform("twitter") == "x"  # the conflicting alias was ignored
        assert "newsite" in SOCIAL_PLATFORMS
    finally:
        ent.reload_platforms()
    assert ent.platform_errors() == []


def test_register_platforms_programmatically():
    try:
        errs = ent.register_platforms({"schema": "v3lum.platforms/1", "platforms": {"vk": {
            "title": "VK", "profile_url_patterns": ["https://vk.com/{handle}"]}}}, origin="test")
        assert errs == [] and platform_for_url("https://vk.com/durov") == ("vk", "durov")
    finally:
        ent.reload_platforms()
    assert platform_for_url("https://vk.com/durov") is None


# ---------------------------------------------------------------- defang / refang (AR13)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://evil.com/path.php", "hxxp://evil[.]com/path.php"),
        ("https://evil.com/a?b=c.d", "hxxps://evil[.]com/a?b=c.d"),
        ("HTTPS://EVIL.COM/", "hxxps://EVIL[.]COM/"),
        ("https://user:pw@evil.com:8443/x", "hxxps://user:pw[@]evil[.]com:8443/x"),
        ("ftp://evil.com/f", "fxp://evil[.]com/f"),
        ("wss://evil.com", "wss[://]evil[.]com"),
        ("evil.com", "evil[.]com"),
        ("attacker@evil.ru", "attacker[@]evil[.]ru"),
        ("185.220.101.4", "185[.]220[.]101[.]4"),
        ("44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f"),
    ],
)
def test_defang_values(value, expected):
    assert ent.defang(value) == expected
    assert ent.defang(expected) == expected  # idempotent
    if "://" in value and not value.startswith(("wss", "HTTPS")):
        assert ent.refang(expected) == value


def test_refang_and_coordinates_are_linear_on_pathological_text():
    """Pasted text is attacker-controlled (P172 cond 5): whitespace runs must not trigger backtracking."""
    import time

    assert ent.refang("evil dot com and a  DOT  b") == "evil.com and a.b"
    assert ent.refang("x dot dot y") == "x.dot y"
    assert normalize(T.COORDINATES, "-23.5505 \t -46.6333") == "-23.550500,-46.633300"
    with pytest.raises(ValueError):
        normalize(T.COORDINATES, "-23.5\t-46.6")  # a tab alone is not a separator (unchanged behaviour)
    start = time.perf_counter()
    ent.refang(" " * 1_000_000)
    ent.refang("\t\n" * 500_000 + "dot")
    with pytest.raises(ValueError):
        normalize(T.COORDINATES, "1" + " " * 200_000 + "x")
    assert time.perf_counter() - start < 2.0
