"""Batch p9-G01-1 - P013 domain_ownership (v3lum/correlations/ownership.py).

Synthetic graphs only (documentation values: *.example domains, the test CNPJ 11.222.333/0001-81,
the root 99888777 for "another company", the RFB alphanumeric example 12.ABC.345/01DE-35 and the seed
CPF 12355501000 whose check digits fail on purpose). One test per verdict level, the copied-footer and
the RDAP-contradicted-footer cases (FC8), the person path (FC6) and the no-network guarantee (FC1).
"""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from v3lum.core import correlate
from v3lum.core.lint import blocking, lint_module_source
from v3lum.correlations import ownership as own

RULES = (own.RULE_VERDICT, own.RULE_MISMATCH, own.RULE_INVALID, own.RULE_PERSON)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rules"
SOURCE = Path(own.__file__)
NOW = "2026-11-26T12:00:00Z"
ORG = {
    "name": "Exemplo Comércio Ltda",
    "cnpj_roots": ["11222333"],
    "domains": [{"name": "exemplo.example", "verification": "txt_verified"},
                {"name": "exemplo-interno.example", "verification": "confirmed"}],
    "app_ids": [{"kind": "m365_tenant", "value": "00000000-0000-4000-8000-000000000001"}],
}
ORG_CNPJ = "11.222.333/0001-81"
TENANT = "00000000-0000-4000-8000-000000000001"
SEED_CPF = "12355501000"  # check digits fail on purpose: never a real person's CPF


# ------------------------------------------------------------------ helpers
def a(value: Any, source: str) -> list[dict[str, Any]]:
    return [{"value": value, "source": source}]


def rdap(*, roots=None, kind="org", org=None, created="2015-03-04T12:00:00Z", age=None, registered=True) -> dict[str, Any]:
    out = {"registered": a(registered, "rdap"), "registrant_kind": a(kind, "rdap"), "created": a(created, "rdap")}
    if roots:
        out["cnpj_roots"] = a(roots, "rdap")
    if org:
        out["registrant"] = a(org, "rdap")
    if age is not None:
        out["domain_age_days"] = a(age, "rdap")
    return out


def node(key: str, *, depth: int = 1, seed: bool = False, attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"key": key, "depth": depth, "seed": seed, "attributes": attrs or {}}


def homepage(cnpjs: list[str], source: str = "web_archives", **extra: Any) -> dict[str, Any]:
    return {"homepage_indicators": a({"source": "wayback", "captured_at": "2026-11-20T00:00:00Z", "cnpjs": cnpjs, **extra}, source)}


def load(tmp_path: Path, nodes: list[dict[str, Any]], *, org: dict[str, Any] | None = ORG, mode: str = "passive",
         purpose: str = "", edges=(), results=(), settings=None, meta=None, unconfirmed=()) -> correlate.GraphFixture:
    doc: dict[str, Any] = {"schema": "v3lum.graph_fixture/1", "now": NOW,
                           "options": {"mode": mode, "purpose": purpose, "unconfirmed_seeds": list(unconfirmed)},
                           "nodes": nodes, "edges": list(edges), "results": list(results)}
    if org:
        doc["org_profile"] = org
    if settings:
        doc["settings"] = settings
    if meta:
        doc["meta"] = meta
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return correlate.load_graph_fixture(path)


def run(fx: correlate.GraphFixture, rule_id: str) -> list[Any]:
    correlate.load_rules()
    before = dict(correlate.RULE_ERRORS)
    out = correlate.run_rules(fx.graph, fx.results, only={rule_id}, rctx=fx.rctx)
    assert before == correlate.RULE_ERRORS, correlate.RULE_ERRORS
    return out


def verdicts(fx: correlate.GraphFixture, domain: str) -> dict[str, dict[str, Any]]:
    """subject key -> verdict of one domain (direct use of the rule's pure layer)."""
    out = {}
    for n, subject, verdict in own.evaluate(fx.graph, fx.results, fx.rctx):
        if subject is not None and n.entity.value == domain:
            out[subject.key] = verdict
    return out


def facts_of(fx: correlate.GraphFixture, domain: str) -> dict[str, Any]:
    n = fx.graph.get(f"domain:{domain}")
    assert n is not None
    return own.domain_facts(fx.graph, n, fx.results, fx.rctx)


# ------------------------------------------------------------------ registration and fixtures
def test_rules_registered_without_errors() -> None:
    correlate.load_rules()
    for rule_id in RULES:
        assert rule_id in correlate.RULES
        assert rule_id not in correlate.RULE_ERRORS
        info = correlate.RULES[rule_id]
        assert info.takes_context and not info.legacy
        for fixture in info.fixtures:
            assert (FIXTURES.parent.parent.parent / fixture).is_file(), fixture


@pytest.mark.parametrize("rule_id", RULES)
def test_rule_graph_fixtures(rule_id: str) -> None:
    files = sorted((FIXTURES / rule_id).glob("*.json"))
    assert any(f.name.startswith("positive_") for f in files) and any(f.name.startswith("negative_") for f in files)
    for path in files:
        assert correlate.check_fixture(rule_id, path) == [], path.name


# ------------------------------------------------------------------ FC1: a rule, no network
def test_source_has_no_network_client_and_passes_the_p327_lint() -> None:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names}
    forbidden = {"socket", "ssl", "http", "urllib", "urllib.request", "requests", "httpx", "subprocess",
                 "v3lum.core.http", "v3lum.core.net", "v3lum.core.dns", "v3lum.core.context"}
    assert not imported & forbidden, imported & forbidden
    assert blocking(lint_module_source(SOURCE, profile="code")) == []
    assert blocking(lint_module_source(SOURCE)) == []


def test_rules_make_zero_network_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(repr(args)[:80])
        raise AssertionError("domain_ownership must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", spy)
    monkeypatch.setattr(socket, "create_connection", spy)
    monkeypatch.setattr(socket, "getaddrinfo", spy)
    fx = load(tmp_path, [
        node("domain:exemplo-store.example", depth=0, seed=True, attrs={**rdap(kind="individual", age=10),
                                                                       **homepage([ORG_CNPJ], commercial=True)}),
        node("domain:exemplo-ofertas.example", attrs={"mx": a(["mx1.exemplo.example"], "dns_records")}),
    ], mode="light")
    total = sum(len(run(fx, r)) for r in RULES)
    assert total >= 2 and calls == []


# ------------------------------------------------------------------ helpers of the pure layer
def test_cnpj_helpers_alphanumeric_and_roots() -> None:
    assert own.cnpj_normalize("12.abc.345/01de-35") == "12ABC34501DE35"
    assert own.cnpj_normalize("12.345") is None and own.cnpj_normalize(None) is None
    assert own.cnpj_root("11.222.333/0001-81") == "11222333"
    assert own.cnpj_root("1222333") == "01222333"  # roots that lost their leading zero
    assert own.cnpj_root("12ABC345") == "12ABC345"
    facts = own.site_cnpj_facts({"cnpjs": ["12.ABC.345/01DE-35", ORG_CNPJ, {"value": "11.222.333/0001-82"}, "garbage", 7],
                                 "commerce_markers": ["carrinho", "pix"]})
    assert facts["valid"] == {"12ABC34501DE35", "11222333000181"}
    assert facts["invalid"] == {"11222333000182"}
    assert facts["commercial"] is True and facts["marker"] is None
    assert own.site_cnpj_facts({"cnpjs": [], "status": 403})["marker"] == "http_403"
    assert own.site_cnpj_facts("not a mapping") == {"valid": set(), "invalid": set(), "commercial": False, "marker": None}


def test_org_name_matching_is_exact_after_corporate_forms() -> None:
    assert own.org_names_match("Exemplo Comércio Ltda", "EXEMPLO COMERCIO LTDA.")
    assert own.org_names_match("Exemplo Comercio S/A", "exemplo comercio")
    assert not own.org_names_match("Exemplo", "Exemplo Pagamentos Ltda")  # containment is not a match
    assert not own.org_names_match("ABC Ltda", "ABC")  # key shorter than 4 characters
    assert not own.org_names_match("", "")


def test_parse_dn_forms() -> None:
    attrs = own.parse_dn('CN=www.exemplo.example,O=Exemplo\\, Comercio Ltda,C=BR')
    assert ("O", "Exemplo, Comercio Ltda") in attrs and ("CN", "www.exemplo.example") in attrs
    assert ("O", "Exemplo Ltda") in own.parse_dn({"organizationName": "Exemplo Ltda"})
    assert ("O", "Exemplo Ltda") in own.parse_dn(((("organizationName", "Exemplo Ltda"),),))
    assert own.parse_dn(None) == [] and own.parse_dn(42) == []


def test_cpf_compatibility_on_visible_digits_only() -> None:
    assert own.cpf_mask_compatible("***.555.010-**", SEED_CPF)
    assert not own.cpf_mask_compatible("***.555.011-**", SEED_CPF)
    assert not own.cpf_mask_compatible("***.***.***-**", SEED_CPF)  # too few visible digits
    assert not own.cpf_mask_compatible("***.555.010-**", "123")


def test_label_boundary_membership() -> None:
    assert own.host_in("mx1.exemplo.example", ["exemplo.example"])
    assert not own.host_in("mx.evilexemplo.example", ["exemplo.example"])
    assert not own.host_in("", ["exemplo.example"])


# ------------------------------------------------------------------ FC2/FC3/FC8: one test per level
def test_confirmed_from_rdap_cnpj_root_marks_and_proposes(tmp_path: Path) -> None:
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    fx = load(tmp_path, [node("domain:exemplo-pagamentos.example", attrs=rdap(roots=["11222333"], org="EXEMPLO COMERCIO LTDA"))],
              results=[{"module": "rdap", "entity": "domain:exemplo-pagamentos.example", "status": "ok", "evidence_sha256": sha}])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "confirmed" and corr.severity.label == "info"
    assert {"own_asset", "known_good", "org_seed_candidate"} <= set(corr.tags)
    assert "[ev:a1b2c3d4e5f6] RDAP CNPJ = org CNPJ root (11222333)" in corr.criterion
    assert "v3lum org seed" in corr.recommendation and "never becomes an ACTIVE scope" in corr.recommendation
    verdict = verdicts(fx, "exemplo-pagamentos.example")["org"]
    assert verdict["org_seed_proposal"]["requires_analyst_confirmation"] is True
    assert verdict["org_seed_proposal"]["scope_effect"] is None and verdict["active_scope"] is False


def test_confirmed_own_domain_needs_no_proposal_and_never_leaks_the_profile(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:loja.exemplo.example", depth=0, seed=True)])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "confirmed" and "org_seed_candidate" not in corr.tags
    assert "exemplo.example, txt_verified" in corr.description
    assert "exemplo-interno.example" not in json.dumps(corr.to_dict())  # other profile entries never shown (A11)


def test_profile_domains_are_repeated_only_for_analyst_seeds(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo.example", depth=1), node("domain:www.exemplo.example", depth=2)])
    assert run(fx, own.RULE_VERDICT) == []
    assert verdicts(fx, "exemplo.example")["org"]["level"] == "CONFIRMED"


def test_probable_from_ov_certificate_o_only(tmp_path: Path) -> None:
    cert = {"o": "EXEMPLO COMERCIO LTDA", "validation": "OV", "names": ["exemplo-ofertas.example"], "source": "censys"}
    fx = load(tmp_path, [node("domain:exemplo-ofertas.example", attrs={"cert_organizations": a([cert], "ct_logs")})])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "probable" and corr.confidence == pytest.approx(0.6)
    assert not {"own_asset", "known_good"} & set(corr.tags)  # only CONFIRMED marks
    assert "CT O= matches" in corr.criterion


def test_probable_strengthened_by_tenancy_but_never_confirmed(tmp_path: Path) -> None:
    cert = {"o": "Exemplo Comércio Ltda", "validation": "EV", "names": ["www.exemplo-ofertas.example"]}
    fx = load(tmp_path, [node("domain:exemplo-ofertas.example", attrs={
        "cert_organizations": a([cert], "ct_logs"), "m365_tenant_id": a(TENANT, "m365_tenant"),
        **homepage([ORG_CNPJ])})], mode="light")
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "probable" and corr.confidence == pytest.approx(0.75)
    assert "MX in the same M365 tenant as the org" in corr.criterion


def test_dv_or_untrusted_certificates_never_give_o(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-ofertas.example", attrs={
        "cert_organizations": a([{"o": "Exemplo Comercio Ltda", "validation": "DV"}], "ct_logs"),
        "tls_certificate": a({"subject": "CN=exemplo-ofertas.example,O=Exemplo Comercio Ltda", "chain_verified": False,
                              "self_signed": True}, "tls_inspect")})])
    assert run(fx, own.RULE_VERDICT) == []


def test_trusted_tls_handshake_subject_o_counts_as_ov(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-ofertas.example", depth=0, seed=True, attrs={
        "tls_certificate": a({"subject": "CN=exemplo-ofertas.example,O=Exemplo Comercio Ltda,C=BR", "chain_verified": True,
                              "self_signed": False, "hostname_match": True}, "tls_inspect")})], mode="light")
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "probable"


def test_possible_from_tenancy_alone(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-eventos.example", attrs={
        "mx": a(["mx1.exemplo.example"], "dns_records"),
        "spf_includes": a([{"domain": "_spf.exemplo.example", "vendor": None, "depth": 1, "via": "include"}], "email_security_posture")})])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "possible" and "unconfirmed link" in corr.title
    assert "MX hosted on a domain of the org (mx1.exemplo.example)" in corr.criterion
    assert "SPF includes a domain of the org (_spf.exemplo.example)" in corr.criterion


def test_no_evidence_is_silent_for_the_org(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:sem-dados.example", depth=0, seed=True),
                         node("domain:outra.example", attrs=rdap(roots=["99888777"]))])
    assert run(fx, own.RULE_VERDICT) == []
    assert verdicts(fx, "sem-dados.example")["org"]["label"] == "no ownership evidence"
    assert verdicts(fx, "outra.example")["org"]["label"] == "registered to another company"


def test_shared_mail_provider_is_never_evidence(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-promo.example", attrs={
        "mx": a(["exemplo-promo-example.mail.protection.outlook.com"], "dns_records"),
        "spf": a("v=spf1 include:spf.protection.outlook.com -all", "dns_records")})])
    verdict = verdicts(fx, "exemplo-promo.example")["org"]
    assert verdict["level"] is None
    assert any("shared provider (microsoft 365)" in n for n in verdict["notes"])


# ------------------------------------------------------------------ FC3/FC4/FC8: site CNPJ cases
def test_site_cnpj_never_confirms_even_with_tenancy(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-store.example", depth=0, seed=True, attrs={
        **rdap(kind="individual", created="2019-05-10T00:00:00Z"), **homepage([ORG_CNPJ]),
        "mx": a(["mx1.exemplo.example"], "dns_records")})], mode="light")
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "possible" and corr.confidence == pytest.approx(0.45)
    assert "a displayed CNPJ never confirms ownership" in corr.criterion
    assert "natural person" in corr.description


def test_copied_footer_on_a_new_domain(tmp_path: Path) -> None:
    """FC8 copied footer: an individual registered the domain 25 days ago; the archived homepage shows
    the org's CNPJ -> verdict POSSIBLE (unconfirmed link) + MEDIUM 'CNPJ displayed does not match registrant'."""
    fx = load(tmp_path, [node("domain:exemplo-ofertas-novas.example", depth=0, seed=True, attrs={
        **rdap(kind="individual", created="2026-11-01T12:00:00Z", age=25), **homepage([ORG_CNPJ], commercial=True)})], mode="light")
    [verdict] = run(fx, own.RULE_VERDICT)
    assert verdict.label.value == "possible" and "unconfirmed link" in verdict.title
    [finding] = run(fx, own.RULE_MISMATCH)
    assert finding.severity.label == "medium" and finding.label.value == "possible"
    assert set(finding.tags) == {"fraud", "clone_indicator"}
    assert "registered 25 day(s) ago" in finding.criterion
    # the copied CNPJ is the victim's: named in the text, never an entity scored by a fraud correlation
    assert finding.entity_keys() == ["domain:exemplo-ofertas-novas.example"]
    assert "CNPJ displayed: 11.222.333/0001-81" in finding.description


def test_rdap_contradicted_footer(tmp_path: Path) -> None:
    """FC8 RDAP-contradicted footer: the registry names root 99888777, the site prints the org's CNPJ
    -> the site CNPJ is voided, MEDIUM mismatch (probable); against a queried company the verdict
    reads 'registered to another company'."""
    fx = load(tmp_path, [
        node("cnpj:11222333000181", depth=0, seed=True, attrs={"legal_name": a("EXEMPLO COMERCIO LTDA", "cnpj_lookup")}),
        node("domain:exemplo-outlet.example", depth=0, seed=True, attrs={
            **rdap(roots=["99888777"], org="OUTRA EMPRESA EXEMPLO LTDA"),
            "site_contacts": a({"cnpjs": [ORG_CNPJ]}, "site_contacts")}),
    ], org=None, mode="light")
    [finding] = run(fx, own.RULE_MISMATCH)
    assert finding.label.value == "probable" and "differ from the RDAP registrant root(s) 99888777" in finding.criterion
    [verdict] = run(fx, own.RULE_VERDICT)
    assert verdict.title.endswith("registered to another company") and verdict.label.value == "probable"
    assert "cnpj:11222333000181" in verdict.entity_keys()
    raw = verdicts(fx, "exemplo-outlet.example")["cnpj:11222333"]
    assert raw["level"] is None
    assert {c["kind"] for c in raw["contra"]} == {"rdap_cnpj_other", "site_cnpj_contradicted"}


def test_registry_contradiction_caps_probable_at_possible(tmp_path: Path) -> None:
    cert = {"o": "Exemplo Comercio Ltda", "validation": "OV"}
    fx = load(tmp_path, [node("domain:exemplo-ofertas.example", attrs={**rdap(roots=["99888777"]), "cert_organizations": a([cert], "ct_logs")})])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "possible"
    assert "capped at POSSIBLE" in corr.description


def test_footer_matching_registrant_or_old_domain_raises_nothing(tmp_path: Path) -> None:
    fx = load(tmp_path, [
        node("domain:exemplo-loja.example", depth=0, seed=True, attrs={**rdap(roots=["11222333"], age=6), **homepage([ORG_CNPJ])}),
        node("domain:exemplo-antigo.example", depth=0, seed=True, attrs={**rdap(kind="individual", age=5443), **homepage([ORG_CNPJ])}),
    ], mode="light")
    assert run(fx, own.RULE_MISMATCH) == []


def test_own_profile_domain_showing_the_org_cnpj_is_never_a_clone(tmp_path: Path) -> None:
    """A brand-new org-profile domain (thin registry, no CNPJ) printing the org's own CNPJ is the org's
    site (FC2 authoritative), not a copied footer; another company's CNPJ on it still raises the finding."""
    own_new = {**rdap(kind=None, age=12), **homepage([ORG_CNPJ])}
    fx = load(tmp_path, [node("domain:exemplo-interno.example", depth=0, seed=True, attrs=own_new)], mode="light")
    assert run(fx, own.RULE_MISMATCH) == []
    other = {**rdap(kind=None, age=12), **homepage(["12.ABC.345/01DE-35"])}
    fx2 = load(tmp_path, [node("domain:exemplo-interno.example", depth=0, seed=True, attrs=other)], mode="light")
    [finding] = run(fx2, own.RULE_MISMATCH)
    assert finding.severity.label == "medium" and "12ABC345" in finding.criterion


def test_homepage_source_refused_is_could_not_verify(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-store.example", depth=0, seed=True, attrs=rdap(kind="individual", age=10))],
              mode="light", results=[{"module": "web_archives", "entity": "domain:exemplo-store.example", "status": "rate_limited",
                                      "reason_code": "rate_limited"}])
    verdict = verdicts(fx, "exemplo-store.example")["org"]
    assert verdict["homepage_evidence"] == "could_not_verify:rate_limited"
    assert "Homepage evidence could not be verified (rate_limited): no site facts used" in verdict["notes"]
    assert not any(n.startswith("No homepage evidence was available") for n in verdict["notes"])


def test_unknown_age_is_noted_never_guessed(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-store.example", depth=0, seed=True, attrs={
        "registered": a(True, "rdap"), "registrant_kind": a("individual", "rdap"), **homepage([ORG_CNPJ])})], mode="light")
    assert run(fx, own.RULE_MISMATCH) == []
    assert facts_of(fx, "exemplo-store.example")["rdap"]["age_days"] is None


def test_invalid_cnpj_on_commercial_site_is_low_suspicious(tmp_path: Path) -> None:
    fx = load(tmp_path, [
        node("domain:loja-barata.example", depth=0, seed=True, attrs=homepage(["11.222.333/0001-82"], commerce_markers=["carrinho", "frete"])),
        node("domain:blog-pessoal.example", depth=0, seed=True, attrs=homepage(["11.222.333/0001-82"])),
    ], org=None, mode="light")
    [corr] = run(fx, own.RULE_INVALID)
    assert corr.severity.label == "low" and corr.tags == ["suspicious"]
    assert corr.entities[0].value == "loja-barata.example"
    assert "11.222.333/0001-82" in corr.criterion


# ------------------------------------------------------------------ FC5/FC7: homepage gating and wording
def test_passive_mode_excludes_homepage_and_says_so(tmp_path: Path) -> None:
    nodes = [node("domain:exemplo-store.example", depth=0, seed=True, attrs={**rdap(kind="individual", age=10), **homepage([ORG_CNPJ])})]
    fx = load(tmp_path, nodes)
    assert run(fx, own.RULE_VERDICT) == [] and run(fx, own.RULE_MISMATCH) == []
    verdict = verdicts(fx, "exemplo-store.example")["org"]
    assert verdict["homepage_evidence"] == "excluded_passive_mode"
    assert "No homepage evidence used (passive mode: RDAP/CT/DNS facts only)" in verdict["notes"]
    # the architect's switch admits archived snapshots in passive mode
    fx2 = load(tmp_path, nodes, settings={own.ARCHIVE_IN_PASSIVE_SETTING: True})
    assert [c.label.value for c in run(fx2, own.RULE_VERDICT)] == ["possible"]
    assert len(run(fx2, own.RULE_MISMATCH)) == 1


def test_no_homepage_note_when_nothing_was_available(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:exemplo-pagamentos.example", attrs=rdap(roots=["11222333"]))])
    [corr] = run(fx, own.RULE_VERDICT)
    assert "No homepage evidence was available" in corr.description


def test_live_homepage_only_for_analyst_typed_seeds(tmp_path: Path) -> None:
    attrs = {**rdap(kind="individual", age=10), "site_contacts": a({"cnpjs": [ORG_CNPJ]}, "site_contacts")}
    fx = load(tmp_path, [node("domain:exemplo-store.example", depth=1, attrs=attrs)], mode="light")
    assert verdicts(fx, "exemplo-store.example")["org"]["homepage_evidence"] == "ignored_not_seed"
    assert run(fx, own.RULE_MISMATCH) == []
    # a seed the analyst left unconfirmed is not analyst-typed either
    fx2 = load(tmp_path, [node("domain:exemplo-store.example", depth=0, seed=True, attrs=attrs)], mode="light",
               unconfirmed=["domain:exemplo-store.example"])
    assert verdicts(fx2, "exemplo-store.example")["org"]["homepage_evidence"] == "ignored_not_seed"
    fx3 = load(tmp_path, [node("domain:exemplo-store.example", depth=0, seed=True, attrs=attrs)], mode="light")
    assert verdicts(fx3, "exemplo-store.example")["org"]["homepage_evidence"] == "used"


def test_challenge_page_and_unknown_sources_are_unusable(tmp_path: Path) -> None:
    fx = load(tmp_path, [
        node("domain:a-exemplo.example", depth=0, seed=True, attrs=homepage([ORG_CNPJ], marker="challenge:cloudflare_challenge")),
        node("domain:b-exemplo.example", depth=0, seed=True, attrs=homepage([ORG_CNPJ], source="some_scanner")),
    ], mode="light")
    assert verdicts(fx, "a-exemplo.example")["org"]["homepage_evidence"] == "unusable:challenge:cloudflare_challenge"
    assert verdicts(fx, "b-exemplo.example")["org"]["homepage_evidence"] == "ignored_source"
    assert run(fx, own.RULE_VERDICT) == []


def test_archived_homepage_on_root_url_and_cnpj_pivots(tmp_path: Path) -> None:
    fx = load(tmp_path, [
        node("domain:exemplo-store.example", depth=0, seed=True, attrs=rdap(kind="individual", age=12)),
        node("url:https://www.exemplo-store.example/", depth=1, attrs=homepage([])),
        node("cnpj:11222333000181", depth=2),
    ], edges=[{"src": "url:https://www.exemplo-store.example/", "dst": "cnpj:11222333000181", "relation": "company_of",
               "module": "web_archives", "confidence": 0.4}], mode="light")
    facts = facts_of(fx, "exemplo-store.example")
    assert facts["homepage"]["state"] == "used" and facts["homepage"]["valid_roots"] == ["11222333"]
    assert len(run(fx, own.RULE_MISMATCH)) == 1


# ------------------------------------------------------------------ registry states, subjects, robustness
def test_rdap_blocked_is_could_not_verify_never_a_contradiction(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("cnpj:11222333000181", depth=0, seed=True), node("domain:exemplo-x.example", depth=0, seed=True)],
              org=None, results=[{"module": "rdap", "entity": "domain:exemplo-x.example", "status": "blocked", "reason_code": "blocked"}])
    verdict = verdicts(fx, "exemplo-x.example")["cnpj:11222333"]
    assert verdict["contra"] == [] and verdict["level"] is None
    assert "RDAP could not be verified (blocked): registry ownership not checked" in verdict["notes"]
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.title.endswith(own.LABEL_UNVERIFIED) and "no ownership evidence" not in corr.title
    assert "re-run rdap later" in corr.recommendation


def test_not_registered_for_a_queried_company(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("cnpj:11222333000181", depth=0, seed=True),
                         node("domain:exemplo-livre.example", depth=0, seed=True, attrs={"registered": a(False, "rdap")})], org=None)
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.title.endswith("not registered") and corr.label.value == "confirmed"


def test_queried_company_and_org_get_separate_verdicts(tmp_path: Path) -> None:
    fx = load(tmp_path, [
        node("cnpj:99888777000100", depth=0, seed=True),
        node("domain:outra-empresa.example", depth=0, seed=True, attrs=rdap(roots=["99888777"], org="OUTRA EMPRESA EXEMPLO LTDA")),
        node("domain:exemplo-pagamentos.example", attrs=rdap(roots=["11222333"])),
    ])
    corrs = run(fx, own.RULE_VERDICT)
    titles = sorted(c.title for c in corrs)
    assert "Domain ownership (queried company): outra-empresa.example - confirmed owner" in titles
    assert "Domain ownership (org): exemplo-pagamentos.example - confirmed owner" in titles
    company = next(c for c in corrs if "queried company" in c.title and "outra-empresa" in c.title)
    assert company.tags == ["ownership", "known_good"]  # a queried company's domain is never 'own_asset'
    assert len({c.id for c in corrs}) == len(corrs)


def test_registry_vetted_registrant_organisation_name_is_probable(tmp_path: Path) -> None:
    attrs = {**rdap(org="Exemplo Comércio Ltda."), "rdap_server": a("rdap.registro.br", "rdap")}
    fx = load(tmp_path, [node("domain:exemplo-global.example", attrs=attrs)])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "probable" and "RDAP registrant organisation = org name" in corr.criterion
    assert "holder vetted by the registry" in corr.criterion and "org_seed_candidate" in corr.tags
    assert own.registry_verifies_holder("loja.com.br") and not own.registry_verifies_holder("loja.example", "rdap.verisign.com")


def test_self_declared_registrant_organisation_is_only_an_unconfirmed_link(tmp_path: Path) -> None:
    """A gTLD registrant organisation is typed by whoever registers the name (a clone can use the
    victim's name): never PROBABLE on its own and never an org seed proposal."""
    attrs = {**rdap(org="Exemplo Comércio Ltda."), "rdap_server": a("rdap.example-registry.example", "rdap")}
    fx = load(tmp_path, [node("domain:exemplo-global.example", attrs=attrs)])
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "possible" and "unconfirmed link" in corr.title
    assert "self-declared at the registrar" in corr.criterion and "org_seed_candidate" not in corr.tags
    # with a CA-vetted OV certificate O= it becomes PROBABLE (0.75): the certificate carries the level
    cert = {"o": "Exemplo Comercio Ltda", "validation": "OV", "names": ["exemplo-global.example"]}
    fx2 = load(tmp_path, [node("domain:exemplo-global.example", attrs={**attrs, "cert_organizations": a([cert], "ct_logs")})])
    [corr2] = run(fx2, own.RULE_VERDICT)
    assert corr2.label.value == "probable" and corr2.confidence == pytest.approx(0.75)


def test_subject_names_come_from_cnpj_lookup_legal_names(tmp_path: Path) -> None:
    org = {**ORG, "name": ""}
    cert = {"o": "EXEMPLO COMERCIO E SERVICOS LTDA", "validation": "OV"}
    fx = load(tmp_path, [node("cnpj:11222333000181", depth=1, attrs={"legal_name": a("Exemplo Comercio e Servicos Ltda", "cnpj_lookup")}),
                         node("domain:exemplo-servicos.example", attrs={"cert_organizations": a([cert], "ct_logs")})], org=org)
    [corr] = run(fx, own.RULE_VERDICT)
    assert corr.label.value == "probable"


def test_registry_confirmed_domains_anchor_tenancy(tmp_path: Path) -> None:
    other_tenant = "00000000-0000-4000-8000-0000000000aa"
    fx = load(tmp_path, [
        node("cnpj:99888777000100", depth=0, seed=True),
        node("domain:outra-empresa.example", attrs={**rdap(roots=["99888777"]), "m365_tenant_id": a(other_tenant, "m365_tenant")}),
        node("domain:outra-marca.example", attrs={"m365_tenant_id": a(other_tenant, "m365_tenant")}),
    ], org=None)
    verdict = verdicts(fx, "outra-marca.example")["cnpj:99888777"]
    assert verdict["level"] == "POSSIBLE" and verdict["evidence"][0]["kind"] == "m365_tenant"


def test_malformed_facts_never_crash(tmp_path: Path) -> None:
    fx = load(tmp_path, [node("domain:estranho.example", depth=0, seed=True, attrs={
        "cnpj_roots": a(12345678, "rdap"), "registrant_kind": a(["org"], "rdap"), "created": a("not a date", "rdap"),
        "cert_organizations": a("O=Exemplo", "ct_logs"), "tls_certificate": a(["x"], "tls_inspect"),
        "homepage_indicators": a(["not", "a", "dict"], "web_archives"), "site_contacts": a({"cnpjs": "11222333000181"}, "site_contacts"),
        "mx": a([None, 3, "mx..bad"], "dns_records"), "spf": a(12, "dns_records"), "m365_tenant_id": a("not-a-guid", "m365_tenant"),
        "domain_age_days": a(True, "rdap")})], mode="light")
    for rule_id in RULES:
        run(fx, rule_id)  # no exception, no RULE_ERRORS entry


# ------------------------------------------------------------------ FC6: person ownership
PERSON_FACTS = {"domain": "fulano.example", "rdap": {"status": "ok", "registrant_kind": "individual",
                                                     "registrant_person": {"name": "Fulano de Tal", "cpf_masked": "***.555.010-**"}}}


def test_person_probable_with_compatible_masked_cpf_never_leaks_the_seed_cpf() -> None:
    verdict = own.assess_person_ownership(PERSON_FACTS, "Fulano de Tal", seed_cpfs=[SEED_CPF], purpose="case INC-0001")
    assert verdict["level"] == "PROBABLE" and verdict["tags"] == ["privacy"]
    assert verdict["expand"] is False and verdict["pivots"] == [] and verdict["retention"] == "case"
    assert verdict["registrant_cpf_display"] == "***.555.010-**"
    assert SEED_CPF not in json.dumps(verdict) and "123.555.010-00" not in json.dumps(verdict)


def test_person_homonym_and_privacy_floor() -> None:
    homonym = own.assess_person_ownership(PERSON_FACTS, "Fulano de Tal", seed_cpfs=["98766601099"], purpose="case INC-0001")
    assert homonym["level"] is None and homonym["contra"][0]["kind"] == "rdap_cpf_incompatible"
    assert own.assess_person_ownership(PERSON_FACTS, "Fulano de Tal", purpose="")["reason_code"] == "privacy"
    contained = own.assess_person_ownership({**PERSON_FACTS, "rdap": {"status": "ok", "registrant_person": {"name": "Fulano Silva de Tal"}}},
                                            "Fulano de Tal", purpose="case")
    assert contained["level"] == "POSSIBLE"
    minimised = own.assess_person_ownership({"domain": "x.example", "rdap": {"status": "ok", "registrant_kind": "individual"}},
                                            "Fulano de Tal", purpose="case")
    assert minimised["level"] is None and "no person comparison possible" in minimised["notes"][0]


def test_person_iv_certificate_only_for_its_own_domain() -> None:
    cert = {"validation": "IV", "given_name": "Fulano", "surname": "de Tal", "names": ["outro-site.example"], "module": "ct_logs"}
    facts = {"domain": "fulano.example", "registrable_domain": "fulano.example", "rdap": {"status": "ok"}, "certs": [cert]}
    assert own.assess_person_ownership(facts, "Fulano de Tal", purpose="case")["level"] is None
    facts["certs"] = [{**cert, "names": ["www.fulano.example"]}]
    assert own.assess_person_ownership(facts, "Fulano de Tal", purpose="case")["level"] == "POSSIBLE"


def test_person_unmasked_registry_cpf_is_masked_on_output() -> None:
    facts = {"domain": "fulano.example", "rdap": {"status": "ok", "registrant_person": {"name": "Fulano de Tal", "cpf_masked": SEED_CPF}}}
    verdict = own.assess_person_ownership(facts, "Fulano de Tal", seed_cpfs=[SEED_CPF], purpose="case")
    assert verdict["registrant_cpf_display"] == "***.555.010-**" and SEED_CPF not in json.dumps(verdict)


def test_person_rule_only_for_analyst_typed_seed_with_purpose(tmp_path: Path) -> None:
    person_domain = {**rdap(kind="individual"), "registrant_person": a({"name": "Fulano de Tal", "cpf_masked": "***.555.010-**"}, "rdap")}
    nodes = [node("person_name:Fulano de Tal", depth=0, seed=True), node("domain:fulano.example", depth=0, seed=True, attrs=person_domain)]
    fx = load(tmp_path, nodes, org=None, purpose="fraud investigation INC-0001 (documentation value)")
    [corr] = run(fx, own.RULE_PERSON)
    assert corr.tags == ["privacy", "ownership", "natural_person"] and corr.label.value == "possible"
    assert correlate.RULES[own.RULE_PERSON].person is True  # P258 cap declared (WP22)
    assert "person_name:Fulano de Tal" in corr.entity_keys()
    assert "Fulano" not in corr.key and "Fulano" not in corr.title
    assert run(load(tmp_path, nodes, org=None, purpose=""), own.RULE_PERSON) == []
    unconfirmed = load(tmp_path, nodes, org=None, purpose="case", unconfirmed=["person_name:Fulano de Tal"])
    assert run(unconfirmed, own.RULE_PERSON) == []
    pivoted = [node("person_name:Fulano de Tal", depth=1), node("domain:fulano.example", depth=0, seed=True, attrs=person_domain)]
    assert run(load(tmp_path, pivoted, org=None, purpose="case"), own.RULE_PERSON) == []
