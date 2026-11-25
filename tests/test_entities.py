import pytest

from v3lum.core.entities import Entity, EntityType, defang, normalize, refang, url_host


@pytest.mark.parametrize(
    "etype,raw,expected",
    [
        (EntityType.EMAIL, " John.Doe@Example.COM ", "john.doe@example.com"),
        (EntityType.EMAIL, "mailto:a@b.co", "a@b.co"),
        (EntityType.EMAIL, "user[at]evil[.]ru", "user@evil.ru"),
        (EntityType.DOMAIN, "WWW.Example.com.", "www.example.com"),
        (EntityType.DOMAIN, "https://sub.example.org/path?x=1", "sub.example.org"),
        (EntityType.DOMAIN, "evil[.]com", "evil.com"),
        (EntityType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
        (EntityType.URL, "hxxps://Evil[.]COM:443/login", "https://evil.com/login"),
        (EntityType.URL, "example.com", "http://example.com/"),
        (EntityType.IPV4, "8.8.8[.]8", "8.8.8.8"),
        (EntityType.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        (EntityType.CIDR, "10.1.2.3/8", "10.0.0.0/8"),
        (EntityType.ASN, "as15169", "AS15169"),
        (EntityType.ASN, "15169", "AS15169"),
        (EntityType.MD5, "44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f"),
        (EntityType.CVE, "cve-2021-44228", "CVE-2021-44228"),
        (EntityType.MITRE, "t1059.001", "T1059.001"),
        (EntityType.USERNAME, "@JohnDoe", "johndoe"),
        (EntityType.CNPJ, "00.000.000/0001-91", "00000000000191"),
        (EntityType.CNPJ, "12.abc.345/01de-35", "12ABC34501DE35"),
        (EntityType.CPF, "529.982.247-25", "52998224725"),
        (EntityType.CEP, "01001-000", "01001000"),
        (EntityType.MAC, "de-ad-be-ef-00-01", "DE:AD:BE:EF:00:01"),
        (EntityType.COORDINATES, "-23.5505, -46.6333", "-23.550500,-46.633300"),
        (EntityType.PHONE, "+1 (415) 555-2671", "+14155552671"),
        (EntityType.PHONE, "(11) 98765-4321", "+5511987654321"),
        (EntityType.ETH, "0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE", "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"),
        (EntityType.PLATE_BR, "abc-1d23", "ABC1D23"),
        (EntityType.ANALYTICS_ID, "ua-1234567-1", "UA-1234567-1"),
    ],
)
def test_normalize(etype, raw, expected):
    assert normalize(etype, raw) == expected


@pytest.mark.parametrize(
    "etype,raw",
    [
        (EntityType.EMAIL, "not-an-email"),
        (EntityType.DOMAIN, "localhost"),
        (EntityType.DOMAIN, "1.2.3.4"),
        (EntityType.IPV4, "999.1.1.1"),
        (EntityType.IPV4, "::1"),
        (EntityType.CVE, "CVE-21-1"),
        (EntityType.CPF, "111.111.111-11"),
        (EntityType.CARD_BIN, "4111111111111111"),
        (EntityType.COORDINATES, "123.0, 10.0"),
        (EntityType.FILE, "/definitely/not/here.txt"),
    ],
)
def test_normalize_rejects(etype, raw):
    with pytest.raises(ValueError):
        normalize(etype, raw)


def test_entity_identity_and_display():
    a = Entity.make("email", "A@B.com")
    b = Entity.make(EntityType.EMAIL, "a@b.com")
    assert a == b and a.key == "email:a@b.com" and hash(a) == hash(b)
    assert Entity.make("cnpj", "00000000000191").display == "00.000.000/0001-91"
    assert Entity.try_make("ipv4", "nope") is None


def test_parse_aliases():
    assert EntityType.parse("ip") is EntityType.IPV4
    assert EntityType.parse("user") is EntityType.USERNAME
    assert EntityType.parse("SHA256") is EntityType.SHA256
    with pytest.raises(ValueError):
        EntityType.parse("bogus")


def test_refang_defang_roundtrip():
    assert refang("hxxps://evil[.]com/x") == "https://evil.com/x"
    assert refang("a(at)b(dot)com") == "a@b.com"
    d = defang("http://evil.com/path.php")
    assert d == "hxxp://evil[.]com/path.php"
    assert refang(d) == "http://evil.com/path.php"


def test_url_host():
    assert url_host("https://user@Example.com:8443/x") == "example.com"
    assert url_host("http://[2001:db8::1]/x") == "2001:db8::1"
