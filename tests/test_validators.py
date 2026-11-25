from v3lum.core import validators as v


def test_cpf_valid_and_invalid():
    assert v.cpf_valid("529.982.247-25")
    assert v.cpf_valid("52998224725")
    assert not v.cpf_valid("529.982.247-26")
    assert not v.cpf_valid("111.111.111-11")
    assert not v.cpf_valid("123")
    assert v.cpf_check_digits("529982247") == "25"


def test_cpf_region():
    # 9th digit of 529.982.247-25 is 7 -> ES/RJ fiscal region
    assert v.cpf_region("529.982.247-25") == "ES, RJ"
    assert v.cpf_region("bad") == ""


def test_cnpj_numeric():
    assert v.cnpj_valid("00.000.000/0001-91")
    assert v.cnpj_valid("11.222.333/0001-81")
    assert not v.cnpj_valid("11.222.333/0001-82")
    assert not v.cnpj_valid("00000000000000")
    assert v.cnpj_check_digits("112223330001") == "81"


def test_cnpj_alphanumeric_2026_format():
    # Official example from the Receita Federal alphanumeric CNPJ material: 12.ABC.345/01DE-35
    assert v.cnpj_check_digits("12ABC34501DE") == "35"
    assert v.cnpj_valid("12.ABC.345/01DE-35")
    assert v.cnpj_valid("12abc34501de35")
    assert not v.cnpj_valid("12.ABC.345/01DE-36")
    assert v.cnpj_is_alphanumeric("12.ABC.345/01DE-35")
    assert not v.cnpj_is_alphanumeric("11.222.333/0001-81")


def test_cnpj_headquarters():
    hq = v.cnpj_headquarters("11.222.333/0002-62")
    assert hq.startswith("112223330001")
    assert v.cnpj_valid(hq)


def test_luhn():
    assert v.luhn_valid("4111111111111111")
    assert v.luhn_valid("490154203237518")  # IMEI example
    assert not v.luhn_valid("4111111111111112")


def test_bitcoin_addresses():
    assert v.btc_address_info("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == {"network": "mainnet", "type": "P2PKH (legacy)"}
    assert v.btc_address_info("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")["type"].startswith("P2SH")
    assert v.btc_address_info("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")["type"].startswith("P2WPKH")
    assert v.btc_address_info("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")["type"] == "P2TR (taproot)"
    assert not v.btc_address_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")  # bad checksum
    assert not v.btc_address_valid("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx")
    assert not v.btc_address_valid("hello")


def test_onion_v3_checksum():
    assert v.onion_valid("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
    assert not v.onion_valid("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczaa.onion")
    assert not v.onion_valid("3g2upl4pq6kufc4m.onion")  # v2 is obsolete


def test_plates():
    assert v.plate_br_valid("ABC-1234")
    assert v.plate_br_valid("ABC1D23")
    assert not v.plate_br_valid("AB12345")
    conv = v.plate_br_convert("ABC1234")
    assert conv == {"format": "old", "old": "ABC1234", "mercosul": "ABC1C34"}
    assert v.plate_br_convert("ABC1C34")["old"] == "ABC1234"


def test_jwt_decode():
    header, payload = v.jwt_decode_unverified("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig")
    assert header == {"alg": "HS256"}
    assert payload == {"sub": "1234"}
