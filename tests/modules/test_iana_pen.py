"""iana_pen (P228): IANA Private Enterprise Numbers registry, matched offline.

Fixtures in tests/fixtures/iana_pen/ (prep capture 2026-11-26, minimised): ``ok.txt`` is the real registry
header and 22 real records (organisations, numbers and e-mail DOMAINS as published) with every contact name
and local part replaced by synthetic values; record 3591 is a fully synthetic individual registrant on a
webmail domain. ``truncated.txt`` (cut mid-record), ``empty_registry.txt`` (header, no record),
``html_error_synthetic.html`` (an HTML page in place of the file) and ``oid_text_synthetic.txt`` (certificate
and SNMP text for the reverse lookup) complete the set.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.company_org import iana_pen as P
from v3lum.modules.company_org.iana_pen import IanaPen

FIX = FIXTURES / "iana_pen"
SYNTHETIC_CONTACT_STRINGS = ("Contact Example", "pen-contact", "fulano.de.tal", "Fulano de Tal", "Internet Assigned Numbers Authority")


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def install(body: bytes | None = None, *, age_days: float = 0.0) -> None:
    path = paths.datasets_dir() / P.DATASET
    path.write_bytes(fx("ok.txt") if body is None else body)
    if age_days:
        when = time.time() - age_days * 86400
        os.utime(path, (when, when))


def run(value: str, **kw):
    http = kw.pop("http", None) or FakeHttp()  # no routes: any download attempt fails the test
    kw.setdefault("runtime", make_runtime(http))
    res = run_module(IanaPen, value, **kw)
    http.assert_hosts_within(IanaPen)
    assert not http.urls()  # offline: the module never sends a request
    return res


def dump(res) -> str:
    return json.dumps({"raw": res.raw, "attrs": res.attributes, "findings": [f.to_dict() for f in res.findings],
                       "pivots": [(p.entity.value, p.note) for p in res.pivots], "error": res.error}, default=str)


# ======================================================================================
# parser and legal floor (FC1, FC2)
# ======================================================================================


def test_parse_keeps_organisation_level_data_only():
    parsed = P.parse_pen_registry(fx("ok.txt"))
    assert parsed["updated"] == "2026-11-25" and parsed["complete"] and not parsed["errors"]
    by = {r["number"]: r for r in parsed["records"]}
    assert len(by) == 22
    assert by[311]["organization"] == "Microsoft" and by[311]["email_domains"] == ["microsoft.com"]
    assert by[0]["placeholder"] and by[622]["placeholder"] and by[4378]["placeholder"]
    # FC2: an individual registrant's "organisation" is a person's name: withheld; webmail never kept as a domain
    assert by[3591]["individual"] and by[3591]["organization"] is None and by[3591]["email_domains"] == []
    assert by[3591]["webmail_only"]


def test_no_contact_name_or_full_address_survives_parsing():
    parsed = P.parse_pen_registry(fx("ok.txt"))
    text = json.dumps(parsed)
    for needle in SYNTHETIC_CONTACT_STRINGS:
        assert needle not in text
    assert "@" not in text and "&" not in text.replace("AT&T", "")
    index = P.build_pen_index(parsed)
    blob = json.dumps({"n": index.by_number, "d": index.by_domain, "k": index.by_name}, default=str)
    for needle in SYNTHETIC_CONTACT_STRINGS:
        assert needle not in blob


@pytest.mark.parametrize(("line", "domains"), [
    ("pen-contact&&jolt.mpx.com.au", ["jolt.mpx.com.au"]),
    ("&pen-contact&synchronet.com", ["synchronet.com"]),
    ("mailto:pen-contact&mn.man.de", ["mn.man.de"]),
    ("pen-contact1&mail.viggen.com, pen-contact2&mail.viggen.com", ["mail.viggen.com"]),
    ("pen-contact&intranet", []),
    ("+55 11 5555-0100", []),
    ("---none---", []),
])
def test_email_line_gives_domains_only(line, domains):
    assert P.pen_email_domains(line) == domains


def test_webmail_detection_uses_both_lists():
    assert P.is_webmail_domain("gmail.com") and P.is_webmail_domain("bol.com.br") and P.is_webmail_domain("proton.me")
    assert not P.is_webmail_domain("bancobrasil.com.br")


def test_registry_problem_refuses_bad_copies():
    assert P.registry_problem(fx("ok.txt"), min_records=10) == ""
    assert "too few records" in P.registry_problem(fx("ok.txt"))  # the production floor
    assert "truncated" in P.registry_problem(fx("truncated.txt"), min_records=1)
    assert "HTML" in P.registry_problem(fx("html_error_synthetic.html"), min_records=1)
    assert "too few records" in P.registry_problem(fx("empty_registry.txt"), min_records=1)
    assert P.registry_problem(b"") == "empty file"


def test_validator_raises_so_the_previous_copy_stays(tmp_path):
    bad = tmp_path / "pen.txt"
    bad.write_bytes(fx("truncated.txt"))
    with pytest.raises(ValueError, match="truncated"):
        P.validate_pen_registry(bad)


def test_dataset_registration():
    reg = DATASETS[P.DATASET]
    assert reg["url"] == "https://www.iana.org/assignments/enterprise-numbers.txt"
    assert reg["source"] == P.SOURCE and reg["terms_class"] == "open" and reg["large"] is True
    assert reg["ttl"] == 30 * 86400


def test_truncated_copy_parses_what_is_complete():
    parsed = P.parse_pen_registry(fx("truncated.txt"))
    assert not parsed["complete"] and parsed["records"]


# ======================================================================================
# reverse lookup helpers (FC4)
# ======================================================================================


def test_extract_enterprise_oids_forms_and_near_misses():
    hits = P.extract_enterprise_oids(fx("oid_text_synthetic.txt"))
    assert [h["number"] for h in hits] == [311, 11129, 9, 44363, 999999999]
    forms = {h["number"]: h["form"] for h in hits}
    assert forms[9] == "snmp_mib" and forms[44363] == "numeric"
    assert 6168 not in forms  # 'enterprise=6168' is not an OID
    assert P.extract_enterprise_oids("iso.org.dod.internet.private.enterprise.2.1") == [
        {"number": 2, "match": "iso.org.dod.internet.private.enterprise.2", "form": "textual"}]


def test_pen_lookup_and_reverse_lookup_helpers():
    assert P.pen_lookup(311) is None  # no copy installed: nothing, never a guess
    install()
    hit = P.pen_lookup(311)
    assert hit == {"number": 311, "oid": "1.3.6.1.4.1.311", "organization": "Microsoft", "status": "assigned",
                   "match": "number", "email_domains": ["microsoft.com"]}
    assert P.pen_lookup(3591)["organization"] is None and P.pen_lookup(3591)["status"] == "individual"
    assert P.pen_lookup(123456) is None and P.pen_lookup("x") is None
    rev = {h["number"]: h for h in P.pen_reverse_lookup(fx("oid_text_synthetic.txt"))}
    assert rev[11129]["organization"] == "Google, Inc." and rev[999999999]["status"] == "unassigned"


# ======================================================================================
# the module (FC2, FC3, FC5)
# ======================================================================================


def test_company_name_exact_match_with_domain_pivot():
    install()
    res = run("company_name:Banco do Brasil")
    assert res.status is Status.OK
    hits = res.attributes["iana_pen"]
    assert hits[0]["number"] == 6168 and hits[0]["match"] == "exact"
    pivots = {(p.entity.value, p.relation): p for p in res.pivots}
    pv = pivots[("bancobrasil.com.br", "iana_pen_contact_domain")]
    assert pv.expand is False and pv.entity.type.value == "domain"
    f = res.findings[0]
    assert f.severity.name == "INFO" and f.source == P.SOURCE and "registry as of 2026-11-25" in f.description
    assert res.attributes["iana_pen_registry"]["updated"] == "2026-11-25"
    assert any(c["name"] == P.DATASET for c in res.datasets)


def test_legal_suffixes_and_url_noise_do_not_block_an_exact_match():
    install()
    assert run("company_name:Microsoft Corporation").attributes["iana_pen"][0]["number"] == 311
    ibm = run("company_name:IBM").attributes["iana_pen"]
    assert ibm[0]["number"] == 2 and ibm[0]["match"] == "exact"
    uqam = run("company_name:Université du Québec à Montréal").attributes["iana_pen"]
    assert uqam[0]["number"] == 4136


def test_possible_match_is_worded_possible():
    install()
    res = run("company_name:Itau")
    hits = {h["number"]: h for h in res.attributes["iana_pen"]}
    assert hits[15212]["match"] == "exact" and hits[15213]["match"] == "possible" and hits[15213]["score"] >= 0.9
    possible = [f for f in res.findings if f.data.get("number") == 15213][0]
    assert possible.title == "Possible IANA Private Enterprise Number match" and possible.confidence_label == "possible"
    assert "name_only_match" in possible.tags and "verify before attributing" in possible.description
    assert run("company_name:Nexalis").status is Status.EMPTY  # one word never matches a longer name


def test_individual_registrant_is_never_matched_by_name():
    install()
    res = run("company_name:Fulano de Tal")
    assert res.status is Status.EMPTY and "no IANA PEN registration" in res.error
    assert "fulano" not in dump(res).lower().replace("fulano de tal", "")


def test_domain_lookup_exact_and_subdomain():
    install()
    cisco = run("domain:cisco.com")
    assert cisco.status is Status.OK and [h["number"] for h in cisco.attributes["iana_pen"]] == [9]
    ibm = run("domain:ibm.com")
    assert ibm.attributes["iana_pen"][0]["match"] == "domain_suffix"
    assert {p.entity.value for p in ibm.pivots} == {"us.ibm.com"}
    itau = run("domain:itau-unibanco.com.br")
    assert sorted(h["number"] for h in itau.attributes["iana_pen"]) == [15212, 15213]
    assert not itau.pivots  # the only contact domain is the subject itself


def test_webmail_domain_is_never_queried_or_pivoted():
    install()
    res = run("domain:gmail.com")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res2 = run("keyword:pen:3591")
    assert res2.status is Status.OK
    assert res2.attributes["iana_pen"][0]["status"] == "individual" and not res2.pivots
    assert "individual registrant (name withheld)" in res2.findings[0].description


def test_keyword_and_text_reverse_lookup():
    install()
    res = run("keyword:1.3.6.1.4.1.11129.2.4.2")
    assert res.attributes["iana_pen"][0]["organization"] == "Google, Inc."
    assert res.findings[0].title == "Enterprise OID resolved to its IANA PEN registrant"
    text = run("text_blob:" + fx("oid_text_synthetic.txt").decode())
    nums = {h["number"]: h["status"] for h in text.attributes["iana_pen"]}
    assert nums == {311: "assigned", 11129: "assigned", 9: "assigned", 44363: "assigned", 999999999: "unassigned"}
    assert len(text.findings) == 4  # the unassigned number is listed, never a finding
    assert {p.entity.value for p in text.pivots} == {"microsoft.com", "google.com", "cisco.com", "cloudflare.com"}


def test_placeholder_number_reads_placeholder_and_unknown_number_reads_empty():
    install()
    res = run("keyword:pen:0")
    assert res.attributes["iana_pen"][0]["status"] == "placeholder" and not res.pivots  # never iana.org
    assert run("keyword:pen:5").status is Status.EMPTY


def test_inputs_without_an_enterprise_number_are_not_applicable():
    install()
    assert run("keyword:hello world").status is Status.SKIPPED
    assert run("text_blob:no oid here 2.5.29.17").status is Status.SKIPPED


def test_missing_dataset_is_unavailable_never_empty():
    res = run("company_name:Microsoft")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "v3lum data update iana_enterprise_numbers.txt" in res.error


def test_empty_local_copy_is_an_error_never_empty():
    install(fx("empty_registry.txt"))
    res = run("company_name:Microsoft")
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_stale_copy_is_flagged():
    install(age_days=90)
    res = run("company_name:Cloudflare")
    assert res.status is Status.OK and res.attributes["iana_pen_registry"]["stale"] is True
    assert "older than 62 days" in res.attributes["dataset_age"][0]


def test_result_holds_no_contact_data():
    install()
    for value in ("company_name:Banco do Brasil", "domain:cisco.com", "text_blob:" + fx("oid_text_synthetic.txt").decode()):
        blob = dump(run(value))
        for needle in ("Contact Example", "pen-contact", "fulano.de.tal"):
            assert needle not in blob
