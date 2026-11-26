"""Web hygiene pack (P084: CR17-CR24): one test per final condition beyond the graph fixtures.

The fixtures under tests/fixtures/rules/{weak_or_expired_tls,login_page_without_hsts,
insecure_session_cookie,cors_credentialed_reflection,secret_in_public_asset,jwt_weak_configuration,
sensitive_file_exposed,public_cloud_bucket}/ run through tests/test_rule_fixtures.py. These tests pin
ownership scoping (cond 3, 11), hostile hosts (cond 4), TLS interception (cond 5), the ACTIVE-only
CORS rule (cond 6), secret masking and public-by-design keys (cond 7), static JWT analysis (cond 8),
content signatures (cond 9), bucket attribution (cond 10) and the phishing-kit regression (cond 12).
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Opsec, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import web_hygiene as wh

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PACK_RULES = (wh.RULE_TLS, wh.RULE_HSTS, wh.RULE_COOKIE, wh.RULE_CORS, wh.RULE_SECRET, wh.RULE_JWT, wh.RULE_FILE, wh.RULE_BUCKET)
CODES = dict(zip(PACK_RULES, ("CR17", "CR18", "CR19", "CR20", "CR21", "CR22", "CR23", "CR24")))
PROFILE = {"org": {"name": "Acme Pagamentos S.A."}, "domains": [{"name": "acmepay.com.br", "verification": "txt_verified"},
                                                                {"name": "acme-seeded.com.br", "verification": "seeded"}]}
SCOPE = {
    "authorization_ref": "PENTEST-2026-042", "owner": "Client S.A. - information security", "contacts": ["soc@client.example"],
    "ticket": "SEC-1234", "window_start": "2026-11-26T09:00:00Z", "window_end": "2026-11-27T18:00:00Z",
    "targets": {"domains": ["api.client.example"]},
}
OWN_URL = "https://portal.acmepay.com.br/login"
THIRD_URL = "https://shop.thirdparty.example/login"
HOSTILE_URL = "https://acmepay-login.example/kit/login.php"
EXPIRED = {"subject": "x", "issuer": "Example DV CA", "not_before": "2025-11-01T00:00:00Z", "not_after": "2026-11-01T00:00:00Z",
           "self_signed": False, "hostname_match": True, "key_type": "rsa", "key_bits": 2048, "signature_hash": "sha256",
           "chain_verified": True}
FACTS = {
    wh.RULE_TLS: {"tls_certificate": EXPIRED},
    wh.RULE_HSTS: {"login_form": True, "hsts": {"present": False}},
    wh.RULE_COOKIE: {"cookie_flags": [{"name": "SESSIONID", "secure": False, "httponly": True, "samesite": "lax"}]},
    wh.RULE_FILE: {"sensitive_files": [{"path": "/.git/HEAD", "status": 200, "size": 23, "signature": "ref: refs/heads/",
                                        "sha256": "ab" * 32}]},
    wh.RULE_BUCKET: {"cloud_buckets": [{"bucket": "acme-assets", "provider": "s3", "state": "public_listing", "attribution": "js",
                                        "evidence": "referenced by app.js"}]},
}


def ctx(*, mode: Opsec = Opsec.PASSIVE, profile: bool = True, meta: dict | None = None, **opts) -> RuleContext:
    return RuleContext(now=NOW, org=OrgProfile.from_dict(PROFILE) if profile else None, options=ScanOptions(mode=mode, **opts),
                       meta=dict(meta or {}))


def web(url: str, attrs: dict, *, seed: bool = False, module: str = "web_module", tags=(), graph: Graph | None = None) -> tuple[Graph, Entity]:
    g = graph or Graph(noise_check=False)
    ent = Entity.make("url", url)
    node, _ = g.add_node(ent, 0 if seed else 1, seed=seed)
    node.tags.update(tags)
    for name, value in attrs.items():
        g.add_attributes(ent, {name: value}, module)
    return g, ent


def secret_finding(entity: Entity, *, rule: str = "aws-access-token", kind: str = "aws_key", preview: str = "AKIA…Q2XZ",
                   entropy: float | None = 4.6, tags=("credential_exposure",), path: str = "") -> Finding:
    data = {"rule": rule, "kind": kind, "masked": {"type": kind, "preview": preview, "sha256": "69" * 32},
            "locations": [{"path": path or entity.value, "line": 12}], "count": 1}
    if entropy is not None:
        data["entropy"] = entropy
    return Finding(title=f"Secret exposed: {rule}", severity=Severity.HIGH, criterion="pattern", tags=list(tags), entity=entity,
                   module="js_endpoints_live", data=data)


def run(g: Graph, *rules: str, rc: RuleContext | None = None):
    return run_rules(g, [], only=set(rules or PACK_RULES), rctx=rc or ctx())


# ------------------------------------------------------------------ registration (cond 1)
def test_pack_rules_are_registered_with_criteria_and_fixtures():
    correlate.load_rules()
    for rid in PACK_RULES:
        info = correlate.RULES[rid]
        assert info.origin.startswith("v3lum.correlations.web_hygiene.") and info.code == CODES[rid]
        assert info.takes_context and not info.legacy and rid not in correlate.RULE_ERRORS
        assert info.criterion and info.attack and info.references and info.false_positives
        assert info.fixtures and all(Path(f).is_file() for f in info.fixtures), rid


# ------------------------------------------------------------------ cond 3 + 11: ownership scoping
@pytest.mark.parametrize("rule_id", [wh.RULE_TLS, wh.RULE_HSTS, wh.RULE_COOKIE])
def test_own_assets_keep_severity_and_third_parties_are_info_context(rule_id):
    g, _ = web(OWN_URL, FACTS[rule_id])
    [own] = run(g, rule_id)
    assert own.severity > Severity.INFO and "own_asset" in own.tags and "context_only" not in own.tags
    assert wh.DISCLOSURE not in own.recommendation
    g2, _ = web(THIRD_URL, FACTS[rule_id])
    [third] = run(g2, rule_id)
    assert third.severity is Severity.INFO and {"third_party", "context_only"} <= set(third.tags)
    assert third.recommendation == wh.DISCLOSURE  # stops at the manual, approved disclosure process
    assert "lowered to INFO" in third.criterion


@pytest.mark.parametrize("rule_id", [wh.RULE_FILE, wh.RULE_BUCKET])
def test_third_party_exposures_are_capped_at_medium(rule_id):
    g, _ = web(OWN_URL, FACTS[rule_id])
    assert run(g, rule_id)[0].severity is Severity.HIGH
    g2, _ = web(THIRD_URL, FACTS[rule_id])
    [third] = run(g2, rule_id)
    assert third.severity is Severity.MEDIUM and "third_party" in third.tags and third.recommendation == wh.DISCLOSURE


def test_unverified_profile_entries_do_not_keep_the_strict_severity():
    """cond 3: CR17-CR20/CR22 keep their severity only for VERIFIED own assets (txt_verified/attested)."""
    g, ent = web("https://www.acme-seeded.com.br/login", {**FACTS[wh.RULE_TLS], **FACTS[wh.RULE_FILE]})
    assert wh.asset_scoping(g, g.get(ent), ctx()).kind == "own_unverified"
    by_rule = {c.rule: c for c in run(g, wh.RULE_TLS, wh.RULE_FILE)}
    assert by_rule[wh.RULE_TLS].severity is Severity.INFO and "not verified" in by_rule[wh.RULE_TLS].criterion
    assert by_rule[wh.RULE_FILE].severity is Severity.MEDIUM
    for corr in by_rule.values():
        assert "own_asset" in corr.tags and "third_party" not in corr.tags and wh.DISCLOSURE not in corr.recommendation
    # an explicit assessment of the typed seed keeps the severity
    g.get(ent).seed = True
    assert run(g, wh.RULE_TLS, rc=ctx(mode=Opsec.LIGHT))[0].severity is Severity.HIGH


def test_explicit_web_assessment_and_in_scope_targets_keep_severity():
    g, _ = web(THIRD_URL, FACTS[wh.RULE_TLS], seed=True)
    assert run(g, wh.RULE_TLS)[0].severity is Severity.INFO  # passive scan of a typed seed: still context
    [assessed] = run(g, wh.RULE_TLS, rc=ctx(mode=Opsec.LIGHT))
    assert assessed.severity is Severity.HIGH and "third_party" in assessed.tags
    assert assessed.recommendation == wh.DISCLOSURE  # cond 11: a third party's recommendation stops at disclosure
    g2, _ = web("https://api.client.example/v1/me", FACTS[wh.RULE_TLS])
    [scoped] = run(g2, wh.RULE_TLS, rc=ctx(mode=Opsec.ACTIVE, authorized=True, scope=SCOPE))
    assert scoped.severity is Severity.HIGH and "in-scope target" in scoped.description
    assert scoped.recommendation.startswith("Renew or replace") and scoped.recommendation.endswith(wh.DISCLOSURE)


def test_asset_scoping_kinds():
    g, own = web(OWN_URL, {})
    web(THIRD_URL, {}, graph=g, seed=True)
    rc = ctx(mode=Opsec.LIGHT)
    assert wh.asset_scoping(g, g.get(own), rc).kind == "own_asset"
    assert wh.asset_scoping(g, g.get(Entity.make("url", THIRD_URL)), rc).kind == "assessment"
    assert wh.asset_scoping(g, g.get(Entity.make("url", THIRD_URL)), ctx()).kind == "third_party"
    assert wh.asset_scoping(g, g.get(own), ctx(profile=False)).kind == "third_party"


def test_an_unconfirmed_seed_is_not_an_explicit_web_assessment():
    """cond 3: only an analyst-typed seed makes a web assessment; seeds extracted from text and not confirmed do not."""
    g, ent = web(THIRD_URL, FACTS[wh.RULE_HSTS], seed=True)
    assert run(g, wh.RULE_HSTS, rc=ctx(mode=Opsec.LIGHT))[0].severity is Severity.MEDIUM
    [corr] = run(g, wh.RULE_HSTS, rc=ctx(mode=Opsec.LIGHT, unconfirmed_seeds={ent.key}))
    assert corr.severity is Severity.INFO and "third_party" in corr.tags and "context_only" in corr.tags
    assert wh.asset_scoping(g, g.get(ent), ctx(mode=Opsec.LIGHT, unconfirmed_seeds={ent.key})).kind == "third_party"


# ------------------------------------------------------------------ cond 4: hostile hosts are INFO for every rule
@pytest.mark.parametrize("rule_id", [wh.RULE_TLS, wh.RULE_HSTS, wh.RULE_COOKIE, wh.RULE_FILE, wh.RULE_BUCKET])
def test_hostile_hosts_give_info_context_only(rule_id):
    g, ent = web(HOSTILE_URL, FACTS[rule_id], seed=True)
    dom = Entity.make("domain", "acmepay-login.example")
    g.add_node(dom, 0)
    g.add_finding(Finding(title="Listed as phishing", severity=Severity.HIGH, criterion="feed", tags=["phishing"], entity=dom,
                          module="url_domain_blocklists"))
    [corr] = run(g, rule_id, rc=ctx(mode=Opsec.ACTIVE, authorized=True))
    assert corr.severity is Severity.INFO and "context_only" in corr.tags
    assert corr.recommendation.startswith("Hostile host")


def test_analyst_false_positive_override_removes_the_hostile_label():
    g, ent = web(OWN_URL, FACTS[wh.RULE_TLS])
    f = Finding(title="Listed", severity=Severity.HIGH, criterion="feed", tags=["malicious"], entity=ent, module="feed")
    f.override = {"verdict": "false_positive"}
    g.add_finding(f)
    assert run(g, wh.RULE_TLS)[0].severity is Severity.HIGH


def test_phishing_kit_yields_no_medium_or_higher_hygiene_finding():
    """cond 12: every hygiene fact of a phishing kit stays INFO context, even in an authorized ACTIVE run."""
    fx = load_graph_fixture(FIXTURES / wh.RULE_SECRET / "positive_phishing_kit_info_only.json")
    contexts = [fx.rctx, RuleContext(now=NOW, org=fx.rctx.org, meta={}, options=ScanOptions(
        mode=Opsec.ACTIVE, authorized=True, authorization_ref="PENTEST-2026-042",
        scope={**SCOPE, "targets": {"domains": ["acmepay-login.example", "api.client.example"]}}))]
    for rc in contexts:
        corrs = run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=rc)
        assert len({c.rule for c in corrs}) >= 6  # the kit carries facts for (almost) every rule
        assert all(c.severity < Severity.MEDIUM for c in corrs), [(c.rule, c.severity.label) for c in corrs]
        assert all("context_only" in c.tags or c.severity is Severity.INFO for c in corrs)


# ------------------------------------------------------------------ cond 5: TLS interception
@pytest.mark.parametrize("rule_id", [wh.RULE_TLS, wh.RULE_HSTS, wh.RULE_COOKIE])
def test_tls_interception_makes_cr17_to_cr19_inconclusive(rule_id):
    g, _ = web(OWN_URL, FACTS[rule_id])
    [corr] = run(g, rule_id, rc=ctx(meta={"tls_interception": {"issuer": "Corp Proxy Inspection CA"}}))
    assert corr.severity is Severity.INFO and corr.label is Confidence.POSSIBLE and "inconclusive" in corr.tags
    assert corr.criterion.startswith("inconclusive - TLS interception by Corp Proxy Inspection CA")
    g2, ent = web(OWN_URL, FACTS[rule_id])
    g2.add_attributes(ent, {"intercepted_by": "Corp Proxy"}, "tls_inspect")
    assert "inconclusive" in run(g2, rule_id)[0].tags


def test_tls_interception_leaves_other_rules_alone():
    g, _ = web(OWN_URL, FACTS[wh.RULE_FILE])
    [corr] = run(g, wh.RULE_FILE, rc=ctx(meta={"tls_interception": True}))
    assert corr.severity is Severity.HIGH and "inconclusive" not in corr.tags
    assert wh.interception(ctx(meta={"tls_interception": True})) == "detected"
    assert wh.interception(ctx()) == ""


def test_could_not_test_protocols_are_never_findings():
    g, _ = web(OWN_URL, {"tls_protocols": {"SSLv3": "could_not_test", "TLSv1": "refused", "TLSv1.3": "accepted"}})
    assert run(g, wh.RULE_TLS) == []
    g2, _ = web(OWN_URL, {"tls_protocols": {"SSLv3": "accepted", "TLSv1.1": "accepted"}})
    [corr] = run(g2, wh.RULE_TLS)
    assert corr.severity is Severity.HIGH and "SSLv3 accepted" in corr.criterion


def test_hsts_unknown_is_never_missing():
    g, _ = web(OWN_URL, {"login_form": True})
    assert run(g, wh.RULE_HSTS) == []  # no header facts: never conclude 'missing'
    g2, _ = web(OWN_URL, {"login_form": True, "hsts": {"present": True, "max_age": 86400}})
    assert run(g2, wh.RULE_HSTS)[0].severity is Severity.LOW
    g3, _ = web("http://portal.acmepay.com.br/login", {"login_form": True})
    assert run(g3, wh.RULE_HSTS)[0].severity is Severity.MEDIUM


def test_cookie_values_are_never_read_and_non_session_cookies_ignored():
    g, _ = web(OWN_URL, {"cookie_flags": [{"name": "theme", "secure": False, "httponly": False, "value": "dark"}]})
    assert run(g, wh.RULE_COOKIE) == []
    g2, _ = web(OWN_URL, {"cookie_flags": [{"name": "auth_token", "secure": True, "httponly": True, "samesite": "None",
                                             "value": "s3cr3t-cookie-value"}]})
    [corr] = run(g2, wh.RULE_COOKIE)
    assert corr.severity is Severity.LOW and "s3cr3t-cookie-value" not in json.dumps(corr.to_dict())


# ------------------------------------------------------------------ cond 6: CR20 only from the ACTIVE cors_probe in scope
CORS_ROW = {"endpoint": "https://api.client.example/v1/me", "origin_kind": "arbitrary", "acao_reflected": True, "acac": True,
            "user_data": True, "acao": "https://x7k2.v3lum-probe.invalid"}


def cors_graph(module: str = "cors_probe", attr: str = "cors_results") -> Graph:
    g, _ = web("https://api.client.example/v1/me", {attr: [CORS_ROW] if attr == "cors_results" else "*"}, seed=True, module=module)
    return g


def test_cr20_needs_the_active_probe_an_authorization_and_the_scope():
    active = ctx(mode=Opsec.ACTIVE, authorized=True, scope=SCOPE)
    [corr] = run(cors_graph(), wh.RULE_CORS, rc=active)
    assert corr.severity is Severity.HIGH and "arbitrary Origin reflected with credentials" in corr.criterion
    assert run(cors_graph(), wh.RULE_CORS, rc=ctx(mode=Opsec.LIGHT, scope=SCOPE)) == []  # not an ACTIVE run
    assert run(cors_graph(), wh.RULE_CORS, rc=ctx(mode=Opsec.ACTIVE, scope=SCOPE)) == []  # no authorization
    assert run(cors_graph(), wh.RULE_CORS, rc=ctx(mode=Opsec.ACTIVE, authorized=True)) == []  # no scope
    out = {**SCOPE, "targets": {"domains": ["www.client.example"]}}
    assert run(cors_graph(), wh.RULE_CORS, rc=ctx(mode=Opsec.ACTIVE, authorized=True, scope=out)) == []  # out of scope


def test_cr20_never_from_light_data_or_other_modules():
    active = ctx(mode=Opsec.ACTIVE, authorized=True, scope=SCOPE)
    assert run(cors_graph(module="web_fingerprint"), wh.RULE_CORS, rc=active) == []
    assert run(cors_graph(module="web_fingerprint", attr="cors_acao"), wh.RULE_CORS, rc=active) == []


def test_cr20_reflection_without_credentials_is_lower():
    g, _ = web("https://api.client.example/v1/me", {"cors_results": [{**CORS_ROW, "acac": False}]}, seed=True, module="cors_probe")
    [corr] = run(g, wh.RULE_CORS, rc=ctx(mode=Opsec.ACTIVE, authorized=True, scope=SCOPE))
    assert corr.severity is Severity.MEDIUM


# ------------------------------------------------------------------ cond 7: CR21 masked, entropy-gated, never validated
def test_cr21_reports_masked_preview_sha_and_location_only():
    g, ent = web("https://portal.acmepay.com.br/static/app.js", {})
    g.add_finding(secret_finding(ent))
    [corr] = run(g, wh.RULE_SECRET)
    assert corr.severity is Severity.HIGH and "own_asset" in corr.tags
    assert "AKIA…Q2XZ" in corr.title and "sha256:" + "69" * 8 in corr.evidence[0]
    assert "app.js:12" in corr.evidence[0] and "never validated" in corr.description
    assert corr.entity_keys() == [ent.key]  # never a pivot to the secret


def test_cr21_entropy_gate_and_generic_matches():
    g, ent = web("https://portal.acmepay.com.br/static/app.js", {})
    g.add_finding(secret_finding(ent, entropy=2.1))
    g.add_finding(secret_finding(ent, rule="generic-api-key", kind="generic", preview="a1b2…c3d4"))
    g.add_finding(secret_finding(ent, rule="slack-token", kind="slack", preview="xoxb…0000", tags=("credential_exposure", "weak_signal")))
    assert run(g, wh.RULE_SECRET) == []


@pytest.mark.parametrize(("rule", "kind", "preview"), [
    ("gcp-api-key", "google_api_key", "AIza…x9Q0"),
    ("stripe-publishable-key", "stripe", "pk_live…abcd"),
    ("sentry-dsn", "sentry_dsn", "http…/123"),
    ("mapbox-token", "mapbox", "pk.e…J9xY"),
])
def test_cr21_public_by_design_keys_are_low(rule, kind, preview):
    g, ent = web("https://portal.acmepay.com.br/static/app.js", {})
    g.add_finding(secret_finding(ent, rule=rule, kind=kind, preview=preview))
    [corr] = run(g, wh.RULE_SECRET)
    assert corr.severity is Severity.LOW and "public by design" in corr.criterion
    assert wh.public_by_design(rule, kind, preview)


def test_cr21_reads_the_secret_scanner_shape_and_reports_passwords_without_a_digest():
    """secret_scanner / archive_mining write masked {rule, kind, display, sha256, length}; passwords keep no digest."""
    g, ent = web("https://portal.acmepay.com.br/static/app.js", {})
    token = {"rule": "aws-access-token", "rules": ["aws-access-token"], "kind": "token", "count": 1,
             "masked": {"rule": "aws-access-token", "kind": "token", "display": "AKIA…Q2XZ", "sha256": "69" * 32, "length": 20},
             "locations": [{"path": ent.value, "line": 3}]}
    password = {"rule": "v3lum-smtp-password", "rules": ["v3lum-smtp-password"], "kind": "password", "count": 1,
                "masked": {"rule": "v3lum-smtp-password", "kind": "password", "display": "[password redacted]", "sha256": None,
                           "length": None},
                "locations": [{"path": ent.value, "line": 9}]}
    for data in (token, password):
        g.add_finding(Finding(title=f"Secret exposed: {data['rule']}", severity=Severity.HIGH, criterion="pattern",
                              tags=["credential_exposure"], entity=ent, module="secret_scanner", data=data))
    by_line = {c.evidence[0].rsplit(":", 1)[-1]: c for c in run(g, wh.RULE_SECRET)}
    assert set(by_line) == {"3", "9"}
    assert "AKIA…Q2XZ" in by_line["3"].title and "sha256:" + "69" * 8 in by_line["3"].evidence[0]
    assert "[password redacted]" in by_line["9"].title and "sha256" not in by_line["9"].evidence[0]
    assert by_line["9"].severity is Severity.HIGH and by_line["9"].id != by_line["3"].id


@pytest.mark.parametrize(("raw", "shown"), [
    ("AKIA…Q2XZ", "AKIA…Q2XZ"), ("[redacted]", "[redacted]"), ("sk_l...wxyz", "sk_l...wxyz"),
    ("AKIAIOSFODNN7EXAMPLEKEY0123", "****"), ("", ""),
])
def test_cr21_never_prints_a_preview_that_is_not_masked(raw, shown):
    assert wh._masked_preview(raw) == shown
    if raw.startswith("AKIAIOSF"):
        g, ent = web("https://portal.acmepay.com.br/static/app.js", {})
        g.add_finding(secret_finding(ent, preview=raw))
        [corr] = run(g, wh.RULE_SECRET)
        assert raw not in json.dumps(corr.to_dict()) and "****" in corr.evidence[0]


def test_cr21_ignores_local_text_and_third_parties_are_medium():
    g = Graph(noise_check=False)
    blob = Entity.make("text_blob", "pasted config snippet")
    g.add_node(blob, 0, seed=True)
    g.add_finding(secret_finding(blob, path=""))
    assert run(g, wh.RULE_SECRET) == []
    g2, ent = web("https://cdn.thirdparty.example/app.js", {})
    g2.add_finding(secret_finding(ent))
    [corr] = run(g2, wh.RULE_SECRET)
    assert corr.severity is Severity.MEDIUM and "third_party" in corr.tags


# ------------------------------------------------------------------ cond 8: CR22 static analysis only
def jwt_fixture(header: dict, claims: dict, *, linked: bool = True):
    fx = load_graph_fixture(FIXTURES / wh.RULE_JWT / "positive_own_alg_none_high.json")
    node = next(n for n in fx.graph.nodes.values() if n.entity.type.value == "jwt")
    node.attributes["jwt_header"] = [(header, "jwt_analysis")]
    node.attributes["jwt_claims"] = [(claims, "jwt_analysis")]
    if not linked:
        fx.graph.edges[:] = [e for e in fx.graph.edges if e.dst != node.key]
    return fx


@pytest.mark.parametrize(("header", "claims", "severity", "text"), [
    ({"alg": "none"}, {"exp": 1, "iat": 0}, Severity.HIGH, "alg 'none'"),
    ({"alg": "HS256"}, {"exp": 3600, "iat": 0}, Severity.MEDIUM, "HS256 (shared-secret HMAC)"),
    ({"alg": "RS256", "jku": "https://keys.evil.example/jwks.json"}, {"iss": "https://portal.acmepay.com.br", "exp": 3600, "iat": 0},
     Severity.MEDIUM, "jku points to a key URL outside the issuer"),
    ({"alg": "RS256", "kid": "../../dev/null"}, {"exp": 3600, "iat": 0}, Severity.MEDIUM, "kid with path"),
    ({"alg": "RS256"}, {"iat": 0}, Severity.LOW, "no expiry"),
    ({"alg": "RS256"}, {"iat": 0, "exp": 90 * 86400}, Severity.LOW, "very long lifetime"),
])
def test_cr22_static_checks(header, claims, severity, text):
    fx = jwt_fixture(header, claims)
    [corr] = run_rules(fx.graph, fx.results, only={wh.RULE_JWT}, rctx=fx.rctx)
    assert corr.severity is severity and text in corr.criterion
    assert "never verified, cracked or replayed" in corr.description


def test_cr22_healthy_token_and_hs_outside_public_assets():
    fx = jwt_fixture({"alg": "RS256", "kid": "2026-key-1"}, {"exp": 3600, "iat": 0, "iss": "https://portal.acmepay.com.br"})
    assert run_rules(fx.graph, fx.results, only={wh.RULE_JWT}, rctx=fx.rctx) == []
    fx2 = jwt_fixture({"alg": "HS256"}, {"exp": 3600, "iat": 0}, linked=False)
    assert run_rules(fx2.graph, fx2.results, only={wh.RULE_JWT}, rctx=fx2.rctx) == []  # not in a public asset


# ------------------------------------------------------------------ cond 9: CR23 content signature, never the status
def test_cr23_needs_a_content_signature_and_keeps_no_body():
    g, _ = web(OWN_URL, {"sensitive_files": [{"path": "/.env", "status": 200, "size": 120}]})
    assert run(g, wh.RULE_FILE) == []
    row = {"path": "/.env", "status": 200, "size": 120, "signature": "KEY=VALUE lines", "sha256": "cd" * 32,
           "body": "DB_PASSWORD=hunter2"}
    g2, _ = web(OWN_URL, {"sensitive_files": [row]})
    [corr] = run(g2, wh.RULE_FILE)
    assert corr.severity is Severity.HIGH and "KEY=VALUE lines" in corr.criterion and "sha256:" + "cd" * 8 in corr.evidence[0]
    assert "hunter2" not in json.dumps(corr.to_dict())


@pytest.mark.parametrize(("path", "severity"), [("/server-status", Severity.MEDIUM), ("/static/app.js.map", Severity.LOW),
                                                ("/backup.sql.gz", Severity.HIGH)])
def test_cr23_severity_by_path(path, severity):
    g, _ = web(OWN_URL, {"sensitive_files": [{"path": path, "status": 200, "signature": "sig", "sha256": "ef" * 32}]})
    assert run(g, wh.RULE_FILE)[0].severity is severity


# ------------------------------------------------------------------ cond 10: CR24 attributed buckets only
@pytest.mark.parametrize(("row", "severity", "text"), [
    ({"state": "exists_private", "attribution": "cname"}, Severity.LOW, "bucket exists, private; ownership not verified"),
    ({"state": "public_listing", "attribution": "page"}, Severity.HIGH, "allows a public listing"),
    ({"state": "public_listing", "attribution": "permutation"}, Severity.INFO, "unattributed, existence only, no listing"),
    ({"state": "exists_private"}, Severity.INFO, "unattributed"),
])
def test_cr24_attribution_and_states(row, severity, text):
    g, _ = web(OWN_URL, {"cloud_buckets": [{"bucket": "acme-assets", "provider": "s3", **row}]})
    [corr] = run(g, wh.RULE_BUCKET)
    assert corr.severity is severity and text in corr.criterion
    assert "Nothing was written to or downloaded from the bucket" in corr.description


@pytest.mark.parametrize("state", ["absent", "could_not_verify", ""])
def test_cr24_absent_or_unverified_buckets_are_silent(state):
    g, _ = web(OWN_URL, {"cloud_buckets": [{"bucket": "acme-assets", "provider": "s3", "state": state, "attribution": "dns"}]})
    assert run(g, wh.RULE_BUCKET) == []


# ------------------------------------------------------------------ cond 2: the rules only read the graph
def test_rules_never_add_entities_or_edges():
    fx = load_graph_fixture(FIXTURES / wh.RULE_SECRET / "positive_phishing_kit_info_only.json")
    before = (sorted(fx.graph.nodes), len(fx.graph.edges))
    run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
    assert (sorted(fx.graph.nodes), len(fx.graph.edges)) == before
