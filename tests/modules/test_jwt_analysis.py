"""jwt_analysis (P316, batch p2-G12-2): offline JWT decode, structural checks, redaction and the scoped
known-default check.

Fixtures in tests/fixtures/jwt_analysis/: ok_jwtio_demo.jwt (the public jwt.io demo vector, 'John Doe' is
its placeholder), alg_none(.jwt|_upper.jwt) (crafted unsigned tokens), third_party_hs256.jwt (a third-party
issuer signed with a listed public default: the check must skip it), rs256_external_keys.jwt
(documentation hosts, placeholder person 'Fulano de Tal', CPF/phone documentation values),
hs512_in_scope_not_default.jwt, malformed.txt and text_blob.txt (four tokens in a pasted request log).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Severity, Status
from v3lum.modules.utility.jwt_analysis import (
    JWT_TEXT_RE,
    KNOWN_DEFAULTS_MAX,
    JwtAnalysis,
    claims_attr,
    decode_jwt,
    find_jwts,
    header_attr,
)

CLOCK = "2026-11-26T12:00:00Z"
DEMO = module_fixture("jwt_analysis", "ok_jwtio_demo.jwt").strip()
NONE = module_fixture("jwt_analysis", "alg_none.jwt").strip()
NONE_UPPER = module_fixture("jwt_analysis", "alg_none_upper.jwt").strip()
THIRD = module_fixture("jwt_analysis", "third_party_hs256.jwt").strip()
RS256 = module_fixture("jwt_analysis", "rs256_external_keys.jwt").strip()
HS512 = module_fixture("jwt_analysis", "hs512_in_scope_not_default.jwt").strip()
MALFORMED = module_fixture("jwt_analysis", "malformed.txt").splitlines()
BLOB = module_fixture("jwt_analysis", "text_blob.txt")
ORG = {"org": {"name": "Example Org"}, "domains": [{"name": "example.com", "verification": "txt_verified"}]}
DEMO_DEFAULT = "your-256-bit-secret"  # list entry 1 (jwt.io): only used to build the in-scope test token


def b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def sign_hs256(header: dict, payload: dict, key: str) -> str:
    signing = b64(header) + "." + b64(payload)
    sig = hmac.new(key.encode(), signing.encode(), hashlib.sha256).digest()
    return signing + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def run(token: str, **kw):
    return run_module(JwtAnalysis, Entity.make(T.JWT, token), clock=FakeClock(CLOCK), **kw)


def codes(res) -> dict[str, Severity]:
    return {f.data["code"]: f.severity for f in res.findings if isinstance(f.data, dict) and "code" in f.data}


def produced(res) -> list:
    """What the module wrote (the run entity itself is the analyst's input)."""
    findings = [{"t": f.title, "d": f.description, "c": f.criterion, "data": f.data, "tags": list(f.tags)} for f in res.findings]
    return [res.attributes, res.raw, findings, [p.entity.value for p in res.pivots], [p.note for p in res.pivots], res.error]


# ------------------------------------------------------------------ c6 detection
def test_regex_is_the_spec_regex_with_ascii():
    assert JWT_TEXT_RE.pattern == r"^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$"
    assert JWT_TEXT_RE.match(DEMO) and JWT_TEXT_RE.match(NONE)
    assert not JWT_TEXT_RE.match("eyJé.eyJa.b")  # Unicode \w is not accepted (ASCII)


def test_tokens_found_in_a_text_blob():
    found = find_jwts(BLOB)
    assert DEMO in found and THIRD in found and HS512 in found and NONE in found
    assert len(found) == 4  # the bare header fragment is not a JWT


def test_text_blob_findings_never_pivot_or_echo_tokens():
    res = run_module(JwtAnalysis, Entity.make(T.TEXT, BLOB), clock=FakeClock(CLOCK))
    assert res.status is Status.OK
    assert not any(p.entity.type is T.JWT for p in res.pivots)  # SECRET_TYPES are never pivoted
    assert any(f.title == "JWTs found in the text (not pivoted)" for f in res.findings)
    assert any(f.severity is Severity.CRITICAL for f in res.findings)  # the alg=none token
    for token in (DEMO, THIRD, HS512):
        assert_no_secret(token.split(".")[2], *produced(res))
    assert len(res.attributes["jwt_redacted"]) == 4


def test_text_without_tokens_is_empty():
    res = run_module(JwtAnalysis, Entity.make(T.TEXT, "fragmento eyJhbGciOiJIUzI1NiJ9 (nao e JWT)"), clock=FakeClock(CLOCK))
    assert res.status is Status.EMPTY


# ------------------------------------------------------------------ c3 structural checks + c2 redaction
def test_jwtio_demo_third_party_skips_check_and_reports_missing_exp_and_pii():
    res = run(DEMO)
    assert res.status is Status.OK
    assert codes(res) == {"missing_exp": Severity.MEDIUM, "pii_claims": Severity.LOW}
    assert res.attributes["jwt_known_default_check"] == {"status": "skipped", "reason": "third_party"}
    red = res.attributes["jwt_redacted"]
    assert red["claims"]["name"] == "*** (8 chars)" and red["signature"]["b64_length"] == 43
    assert red["sha256"] == hashlib.sha256(DEMO.encode()).hexdigest()
    assert_no_secret(DEMO.split(".")[2], *produced(res))
    assert_no_secret("John Doe", *produced(res))
    pii = next(f for f in res.findings if f.data.get("code") == "pii_claims")
    assert "claims: name" in pii.description and pii.attack == ["T1528"]


def test_in_scope_token_signed_with_a_public_default_never_reveals_it():
    token = sign_hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "svc-0001", "iss": "https://api.example.com", "iat": 1795651200,
                                                        "exp": 1795654800}, DEMO_DEFAULT)
    res = run(token, org_profile=ORG)
    hit = next(f for f in res.findings if f.title == "JWT signed with a publicly known default secret")
    assert hit.severity is Severity.HIGH and hit.attack == ["T1606"] and hit.criterion
    assert "signed with a publicly known default secret (list entry 1)" in hit.description
    assert res.attributes["jwt_known_default_check"] == {"status": "matched", "entry": 1}
    assert "own_asset" in hit.tags
    assert_no_secret(DEMO_DEFAULT, *produced(res))
    assert_no_secret(token.split(".")[2], *produced(res))


def test_third_party_token_signed_with_a_listed_default_is_skipped():
    res = run(THIRD, org_profile=ORG)  # iss login.thirdparty.example is not an org asset
    assert res.attributes["jwt_known_default_check"] == {"status": "skipped", "reason": "third_party"}
    assert not any("default" in f.title for f in res.findings)
    assert {p.entity.value for p in res.pivots} == {"https://login.thirdparty.example/", "login.thirdparty.example"}
    assert all(p.expand is False and p.relation == "jwt_issuer" for p in res.pivots)


def test_alg_none_is_critical_and_never_secret_checked():
    res = run(NONE)
    c = codes(res)
    assert c["alg_none"] is Severity.CRITICAL and c["expired"] is Severity.INFO
    assert res.attributes["jwt_known_default_check"]["reason"] == "not_hmac"
    assert res.attributes["jwt_header"]["alg"] == "none"
    crit = next(f for f in res.findings if f.data.get("code") == "alg_none")
    assert crit.attack == ["T1606"] and crit.criterion
    assert codes(run(NONE_UPPER))["alg_none"] is Severity.CRITICAL


def test_rs256_external_keys_lifetime_pii_and_pivots():
    res = run(RS256)
    c = codes(res)
    assert c["external_key_url"] is Severity.HIGH and c["excessive_lifetime"] is Severity.MEDIUM and c["pii_claims"] is Severity.LOW
    assert sum(1 for f in res.findings if f.data.get("code") == "external_key_url") == 3  # jku, x5u and a URL kid
    assert res.attributes["jwt_known_default_check"]["reason"] == "not_hmac"
    urls = {p.entity.value: p for p in res.pivots if p.entity.type is T.URL}
    assert "https://keys.example.net/.well-known/jwks.json" in urls and urls["https://keys.example.net/.well-known/jwks.json"].relation == "jwt_key_url"
    assert "https://sso.example.com/" in urls and urls["https://sso.example.com/"].relation == "jwt_issuer"
    assert all(p.expand is False and "never fetched" in p.note for p in res.pivots)
    red = res.attributes["jwt_redacted"]
    assert red["claims"]["email"] == "f***@example.com" and red["claims"]["sub"] == "***.456.789-**"
    for personal in ("Fulano de Tal", "fulano@example.com", "123.456.789-09", "+55 11 5555-0123"):
        assert_no_secret(personal, *produced(res))
    claims = res.attributes["jwt_claims"]
    assert claims["iss"] == "https://sso.example.com" and isinstance(claims["exp"], int) and claims["has_email"] is True


def test_hs512_in_scope_with_a_non_default_value_is_not_matched():
    res = run(HS512, org_profile=ORG)
    assert res.attributes["jwt_known_default_check"]["status"] == "not_matched"
    assert 0 < res.attributes["jwt_known_default_check"]["checked"] <= KNOWN_DEFAULTS_MAX


def test_lifetime_setting_is_configurable():
    assert "excessive_lifetime" not in codes(run(HS512))  # one hour
    assert "excessive_lifetime" in codes(run(HS512, settings={"jwt_analysis_max_lifetime_s": 600}))


@pytest.mark.parametrize("line", MALFORMED[:3] + [MALFORMED[3]])
def test_malformed_tokens_are_errors_never_empty(line):
    ent = Entity.try_make(T.JWT, line)
    if ent is None:  # the entity layer refuses it already (JWE with 5 parts, missing signature segment, bad chars)
        assert decode_jwt(line)["ok"] is False
        return
    res = run_module(JwtAnalysis, ent, clock=FakeClock(CLOCK))
    assert res.status is Status.ERROR and "could not be decoded" in res.error


def test_cr22_rule_reads_the_attributes():
    from v3lum.correlations.web_hygiene import _jwt_issues

    none_issues = _jwt_issues(header_attr(decode_jwt(NONE)), claims_attr(decode_jwt(NONE)), public=False)
    assert any("alg 'none'" in text for _, text in none_issues)
    rs_issues = _jwt_issues(header_attr(decode_jwt(RS256)), claims_attr(decode_jwt(RS256)), public=False)
    assert any("jku points to a key URL outside the issuer" in text for _, text in rs_issues)


def test_bundled_list_is_bounded_and_sourced():
    with open("v3lum/data/jwt_analysis/known_default_hmac_keys.json", encoding="utf-8") as fh:
        data = json.load(fh)
    assert 0 < len(data["entries"]) <= KNOWN_DEFAULTS_MAX
    assert all(e["source"].strip() for e in data["entries"])
    assert data["entries"][0]["value"] == DEMO_DEFAULT


def test_offline_module_never_touches_the_network():
    ctx = make_ctx(JwtAnalysis, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://jwt.io/")
    assert JwtAnalysis.disclosure == "none" and JwtAnalysis.default_enabled is True and JwtAnalysis.terms == "open"
