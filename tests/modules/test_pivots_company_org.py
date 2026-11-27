"""P231 pivots_company_org: the company_org pack (data only, no module class).

OpenSanctions, Companies House, OpenCorporates, GLEIF and ViewDNS reverse WHOIS. Person-name and e-mail templates
are privacy=true: rendered only for analyst-typed seeds of a case with a recorded purpose that opted in, never for
discovered QSA partners, registrants, employees or customers (cond 10). The engine test uses the QSA partner case
tests/fixtures/pivots_company_org/qsa_partner_case.json (documentation names) with the offline kit tests/fakes.py.
V3LUM never fetches these URLs."""

from __future__ import annotations

from tests.fakes import FakeHttp, define_module, make_runtime, module_fixture
from v3lum.core import links
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.modules.utility import pivot_pack_render as pr

CASE = module_fixture("pivots_company_org", "qsa_partner_case.json")
VERIFIED = module_fixture("pivots_company_org", "verified_templates.json")
PERSON_LINKS = {"company_org:opensanctions_person", "company_org:viewdns_rwhois_person"}


def refs(entity, *, include_privacy=False):
    return [r.ref for r in links.pivot_links_for(entity, include_privacy=include_privacy) if r.ref.startswith("company_org:")]


def test_company_and_domain_links_are_unrestricted_in_curated_order():
    company = refs(Entity.make("company_name", "Banco do Brasil"))
    assert company == ["company_org:opensanctions_company", "company_org:companies_house_search", "company_org:viewdns_rwhois_org",
                       "company_org:opencorporates_search", "company_org:gleif_search"]  # verified first (P311), file order inside
    assert refs(Entity.make("domain", "example.com")) == ["company_org:viewdns_rwhois_org"]


def test_reverse_whois_is_labelled_ownership_candidates_and_never_reverseip():
    link = links.get_link("company_org:viewdns_rwhois_org")
    assert "ownership candidates" in link.label and "never scope or own-asset evidence" in link.notes
    for item in pr.pack_data("company_org")["links"]:
        assert not pr.VIEWDNS_EXCLUDED_RE.match(item["template"])


def test_person_and_email_links_need_the_opt_in():
    person = Entity.make("person_name", "Beltrana Exemplo")
    mail = Entity.make("email", "analista.teste@example.com")
    assert refs(person) == [] and refs(mail) == []
    assert set(refs(person, include_privacy=True)) == PERSON_LINKS
    assert refs(mail, include_privacy=True) == ["company_org:viewdns_rwhois_person"]
    assert links.links_for(person) == []  # the legacy view never shows privacy links


def test_manual_alternatives_are_unverified_and_opencorporates_antibot():
    oc = links.get_link("company_org:opencorporates_search")
    gleif = links.get_link("company_org:gleif_search")
    assert not oc.verified and oc.antibot and not gleif.verified
    assert links.render(gleif, Entity.make("company_name", "Banco do Brasil")).url == \
        "https://search.gleif.org/#/search/simpleSearch=Banco%20do%20Brasil"


def test_verified_records_match():
    for check in VERIFIED["checks"]:
        if check["link"]:
            etype, value = check["entity"].split(":", 1)
            assert links.render(check["link"], Entity.make(etype, value)).url == check["url"]


def test_qsa_partner_case_end_to_end(clean_registry):
    """cond 10 through the real engine: the CNPJ seed's QSA partner and RDAP registrant (discovered) never get the
    person links, even in an opted-in case; the analyst-typed person and e-mail seeds do."""
    pivots = [e for e in CASE["entities"] if e["provenance"] == "pivot"]
    relation = {"cnpj_name": "legal_name", "qsa_partner": "partner", "rdap_registrant": "registrant", "rdap_domain": "related"}

    def qsa(self, entity, ctx):
        res = self.result(entity)
        for item in pivots:
            res.pivot(T(item["type"]), item["value"], relation[item["relation"]])
        return res

    define_module("t_g14_qsa", [T.CNPJ], qsa)
    seeds = [Entity.make(e["type"], e["value"]) for e in CASE["entities"] if e["provenance"] == "seed"]
    opts = ScanOptions(include={"t_g14_qsa"}, show_personal=True, purpose=CASE["case"]["purpose"], tlp=CASE["case"]["tlp"])
    case = Engine(make_runtime(FakeHttp()), opts).investigate(seeds)
    by_value = {}
    for key, items in case.links.items():
        by_value[key.split(":", 1)[1]] = {i.get("ref") for i in items}
    assert {"person_name:FULANO DE TAL", "email:contato@example.com"} <= set(case.graph.nodes)  # the discovered entities exist
    for value, expected in CASE["expected_privacy_links"].items():
        got = {ref.split(":", 1)[1] for ref in by_value.get(Entity.make("email" if "@" in value else "person_name", value).value, set())
               if ref in PERSON_LINKS}
        assert got == set(expected), value
    company = by_value.get(Entity.make("company_name", "BANCO DO BRASIL SA").value, set())
    assert "company_org:opensanctions_company" in company  # the discovered company name keeps the unrestricted links


def test_without_the_opt_in_even_typed_person_seeds_get_no_person_links(clean_registry):
    seeds = [Entity.make("person_name", "BELTRANA EXEMPLO")]
    case = Engine(make_runtime(FakeHttp()), ScanOptions(purpose="due diligence")).investigate(seeds)
    refs_seen = {i.get("ref") for items in case.links.values() for i in items}
    assert not refs_seen & PERSON_LINKS
