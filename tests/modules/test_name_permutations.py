"""name_permutations (P251) and its shared helper v3lum.modules.person_name.permute.

Fixtures in tests/fixtures/name_permutations/ are SYNTHETIC (no real person): ``vectors.json`` holds the
council's fixture name 'Jose Carlos de Oliveira Junior' with and without accents plus placeholder names;
``observed_addresses.json`` holds commit-e-mail / public-page shaped addresses at the documentation
domain example.com (placeholder names).
"""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.person_name import permute as P
from v3lum.modules.person_name.name_permutations import NamePermutations

VECTORS = {c["id"]: c["name"] for c in module_fixture("name_permutations", "vectors.json")["cases"]}
EXPECTED = module_fixture("name_permutations", "vectors.json")["expected"]["fc_fixture"]
OBSERVED = module_fixture("name_permutations", "observed_addresses.json")["samples"]
ORG = OrgProfile.from_dict({"org": {"name": "Exemplo S.A."}, "domains": [{"name": "example.com.br", "verification": "confirmed"}]})


def values(cands):
    return [c["value"] for c in cands]


def test_metadata_is_offline_and_never_default():
    assert NamePermutations.disclosure == "none" and NamePermutations.hosts == () and NamePermutations.terms == "open"
    assert NamePermutations.default_enabled is False and NamePermutations.run_on == "seeds"  # cond 5 / A3 BR2
    assert NamePermutations.category == "person_name" and NamePermutations.trust_tier == "n/a"


def test_fixture_name_with_and_without_accents_gives_the_same_ordered_list():
    plain = values(P.username_candidates(VECTORS["fc_fixture_plain"]))
    accented = values(P.username_candidates(VECTORS["fc_fixture_accents"]))
    assert plain == accented == EXPECTED  # cond 1/5: accents, particles, suffix and order
    assert not any("junior" in v or v.startswith("de") or ".de." in v for v in plain)
    parts = P.name_parts(VECTORS["fc_fixture_accents"])
    assert parts["first"] == "jose" and parts["last"] == "oliveira" and parts["middles"] == ["carlos"]
    assert parts["suffix"] == "junior" and parts["particles_dropped"] == ["de"]


def test_cap_order_and_offered_first():
    many = P.username_candidates(VECTORS["two_middles"])
    assert len(many) == P.CANDIDATE_CAP == 15  # two middle names would give 21: capped at 15
    assert many[0]["value"] == "anasantos" and P.name_parts(VECTORS["two_middles"])["suffix"] == "neto"
    assert [c["offered_first"] for c in many[:4]] == [True, True, True, False]
    assert all(c["label"] == "generated" and c["expand"] is False and c["verified"] is False for c in many)
    two = values(P.username_candidates(VECTORS["two_tokens"]))
    assert two[:9] == ["fulanosilva", "fulano.silva", "fulano_silva", "fulano-silva", "fsilva", "f.silva", "silvafulano",
                       "silva.fulano", "fulanos"]
    assert two[9:] == ["_fulanosilva", "fulanosilva_", "_silvafulano", "silvafulano_", "silva_fulano", "silva-fulano"]  # maigret strict
    assert P.maigret_strict_permutations(["a", "b"])[:6] == ["ab", "_ab", "ab_", "a_b", "a-b", "a.b"]


def test_edge_names():
    assert values(P.username_candidates(VECTORS["single_token"])) == ["sicrano"]
    assert P.username_candidates(VECTORS["empty"]) == []
    assert values(P.username_candidates(VECTORS["only_particles"]))[:1] == ["deda"]  # particles kept only when nothing else is left
    assert P.name_parts(VECTORS["punctuation"])["last"] == "davila"


def test_email_format_inference_counts_samples():
    fmt = P.infer_email_format(OBSERVED, "example.com")
    assert fmt["format"] == "first.last" and fmt["samples"] == 3  # 2 named + 1 shape-only; roles, +tags and other domains handled
    assert fmt["counts"]["flast"] == 1 and fmt["ambiguous"] is False
    out = P.email_candidates("Joana Santos", ["example.com", "gmail.com", "unrelated.example"], ["example.com"], samples=OBSERVED)
    assert out["candidates"][0]["value"] == "joana.santos@example.com" and out["candidates"][0]["format_samples"] == 3
    assert {r["domain"] for r in out["refused"]} == {"gmail.com", "unrelated.example"}
    assert len(out["candidates"]) <= P.CANDIDATE_CAP


def test_generated_values_never_reach_oracles():
    mail = P.email_candidates("Joana Santos", ["example.com"], ["example.com"])["candidates"][0]
    handle = P.username_candidates("Joana Santos")[0]
    for sink in ("breach", "infostealer", "reputation", "email_validation", "smtp", "login", "signup", "password_reset"):
        assert P.generated_sink_reason(mail, sink)  # cond 4
    assert P.generated_sink_reason(handle, "username_check")  # only after the analyst selects it
    assert P.generated_sink_reason(dict(handle, selected_by_analyst=True), "username_check") is None
    assert P.generated_sink_reason(handle, "smtp")


def test_module_lists_candidates_as_unexpanded_pivots_never_findings():
    http = FakeHttp()
    options = ScanOptions(purpose="case 2026-0042", seed_tlp={"person_name:José Carlos de Oliveira Júnior": "amber",
                                                               "domain:example.com": "amber", "email:fulano.souza@example.com": "amber"})
    res = run_module(NamePermutations, "person_name:José Carlos de Oliveira Júnior", http, options=options, org_profile=ORG)
    assert res.status is Status.OK and http.calls == []
    assert not res.findings  # cond 3: never findings, never scored
    users = res.attributes["username_candidates"]
    assert [u["value"] for u in users] == EXPECTED and all(u["label"] == "generated" for u in users)
    mails = res.attributes["email_candidates"]
    assert mails[0]["value"] == "jose.oliveira@example.com" and mails[0]["format_samples"] == 1
    assert {m["value"].split("@")[1] for m in mails} == {"example.com", "example.com.br"}  # case seed + org_profile domains only
    assert len(mails) <= 15 and res.attributes["email_formats"]["example.com"]["format"] == "first.last"
    assert all(p.expand is False and p.confidence_label == "possible" and p.relation == "generated_candidate" for p in res.pivots)
    assert all("generated (unverified guess)" in p.note for p in res.pivots)
    assert {p.entity.type for p in res.pivots} == {T.USERNAME, T.EMAIL}
    email_notes = [p.note for p in res.pivots if p.entity.type is T.EMAIL]
    assert all("never sent to breach" in n for n in email_notes)


def test_without_case_or_org_domains_no_email_is_generated():
    res = run_module(NamePermutations, "person_name:Fulano da Silva", FakeHttp())
    assert res.status is Status.OK
    assert "email_candidates" not in res.attributes and res.raw["email_state"] == "no case or org_profile domain"
    assert len(res.attributes["username_candidates"]) == 15


def test_names_without_tokens_are_empty():
    res = run_module(NamePermutations, "person_name:'' ...", FakeHttp())
    assert res.status is Status.EMPTY
