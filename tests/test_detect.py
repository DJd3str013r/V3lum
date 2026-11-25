import pytest

from v3lum.core.detect import best, detect, extract_iocs, primary
from v3lum.core.entities import EntityType as T


@pytest.mark.parametrize(
    "raw,etype,value",
    [
        ("john@acme.com", T.EMAIL, "john@acme.com"),
        ("example.com", T.DOMAIN, "example.com"),
        ("hxxps://evil[.]com/login", T.URL, "https://evil.com/login"),
        ("8.8.8.8", T.IPV4, "8.8.8.8"),
        ("2001:4860:4860::8888", T.IPV6, "2001:4860:4860::8888"),
        ("10.0.0.0/8", T.CIDR, "10.0.0.0/8"),
        ("AS15169", T.ASN, "AS15169"),
        ("44d88612fea8a8f36de82e1278abb02f", T.MD5, "44d88612fea8a8f36de82e1278abb02f"),
        ("3395856ce81f2b7382dee72602f798b642f14140", T.SHA1, "3395856ce81f2b7382dee72602f798b642f14140"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", T.SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
        ("CVE-2021-44228", T.CVE, "CVE-2021-44228"),
        ("T1059.001", T.MITRE, "T1059.001"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", T.BTC, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", T.BTC, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", T.ETH, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"),
        ("+14155552671", T.PHONE, "+14155552671"),
        ("(11) 98765-4321", T.PHONE, "+5511987654321"),
        ("00.000.000/0001-91", T.CNPJ, "00000000000191"),
        ("12.ABC.345/01DE-35", T.CNPJ, "12ABC34501DE35"),
        ("529.982.247-25", T.CPF, "52998224725"),
        ("01001-000", T.CEP, "01001000"),
        ("ABC1D23", T.PLATE_BR, "ABC1D23"),
        ("@johndoe", T.USERNAME, "johndoe"),
        ("Acme Tecnologia Ltda", T.ORG, "Acme Tecnologia Ltda"),
        ("João da Silva", T.PERSON, "João da Silva"),
        ("UA-12345678-1", T.ANALYTICS_ID, "UA-12345678-1"),
        ("-23.5505, -46.6333", T.COORDINATES, "-23.550500,-46.633300"),
        ("DE:AD:BE:EF:00:01", T.MAC, "DE:AD:BE:EF:00:01"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc", T.JWT, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", T.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", T.ONION, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"),
        ("G0007", T.THREAT_ACTOR, "G0007"),
    ],
)
def test_detect_best(raw, etype, value):
    d = best(raw)
    assert d is not None
    assert d.type is etype, detect(raw)
    assert d.value == value


def test_forced_type_prefix():
    d = detect("email:SOMEONE@EXAMPLE.COM")
    assert len(d) == 1 and d[0].type is T.EMAIL and d[0].confidence == 1.0
    assert detect("user:johndoe")[0].type is T.USERNAME
    assert detect("ipv4:not-an-ip") == []
    # URL schemes are never mistaken for a type prefix
    assert best("http://example.com").type is T.URL


def test_ambiguous_cpf_vs_phone_offers_both():
    found = detect("52998224725")
    types = [d.type for d in found]
    assert types[0] is T.CPF and T.PHONE in types
    assert [d.type for d in primary(found)] == [T.CPF]


def test_formatted_documents_are_not_phones():
    assert all(d.type is not T.PHONE for d in detect("529.982.247-25"))
    assert all(d.type is not T.PHONE for d in detect("01001-000"))


def test_multiline_is_text_blob():
    d = detect("line one evil.com\nline two 1.2.3.4")
    assert d[0].type is T.TEXT


def test_existing_file_is_file(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text("hello")
    assert best(str(p)).type is T.FILE


def test_lowercase_phrase_prefers_keyword():
    found = detect("random words here")
    assert found[0].type is T.KEYWORD


def test_extract_iocs_defanged_and_filters():
    text = (
        "Phish at hxxps://login-micros0ft[.]com/auth from 185.220.101[.]4 mail attacker[at]evil[.]ru\n"
        "sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f exploits CVE-2023-4966 via T1190.\n"
        "BTC bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, CNPJ 00.000.000/0001-91; attachments invoice.zip, report.pdf"
    )
    keys = {e.key for e in extract_iocs(text)}
    assert "url:https://login-micros0ft.com/auth" in keys
    assert "domain:login-micros0ft.com" in keys
    assert "ipv4:185.220.101.4" in keys
    assert "email:attacker@evil.ru" in keys
    assert "cve:CVE-2023-4966" in keys
    assert "mitre_technique:T1190" in keys
    assert "btc_address:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in keys
    assert "cnpj:00000000000191" in keys
    assert "domain:invoice.zip" not in keys  # file name, not a domain
    assert not any(k.endswith("report.pdf") for k in keys)


def test_extract_iocs_dedup_and_limit():
    text = " ".join(["8.8.8.8"] * 50 + [f"10.0.0.{i}" for i in range(20)])
    ents = extract_iocs(text, limit=5)
    assert len(ents) == 5
    assert ents[0].value == "8.8.8.8"
