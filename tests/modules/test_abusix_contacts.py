"""abusix_contacts (P041): one DoH TXT query, role mailboxes pivoted, rule 5 for DNS failures.

Fixtures in tests/fixtures/abusix_contacts/ are real DoH answers recorded on 2026-11-26 through
dns.google (8.8.8.8, 1.1.1.1, the IPv6 nibble name of 2001:4860:4860::8888, and the NXDOMAIN answer
captured for 192.0.2.1) plus two labelled synthetic answers (a SERVFAIL shape, and a quoted
multi-string TXT mixing a role and a person-like address on a documentation domain).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, DeadHttp, FakeHttp, add_dns_failure, doh_url, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.abusix_contacts import (
    REPORT_REFERENCE,
    SOURCE,
    AbusixContacts,
    addresses_in,
    is_role_address,
    query_name,
)

V6 = "2001:4860:4860::8888"
V6_QNAME = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.abuse-contacts.abusix.zone"


def serve(http, ip, fixture, *, provider="google"):
    http.add("GET", doh_url(query_name(ip), "TXT", provider=provider), json=module_fixture("abusix_contacts", fixture))
    return http


def emails(res):
    return {p.entity.value: p for p in res.pivots if p.entity.type is T.EMAIL}


# ------------------------------------------------------------------ query name (c1)
def test_query_name_reverses_ipv4_octets_and_ipv6_nibbles():
    assert query_name("8.8.8.8") == "8.8.8.8.abuse-contacts.abusix.zone"
    assert query_name("1.2.3.4") == "4.3.2.1.abuse-contacts.abusix.zone"
    assert query_name(V6) == V6_QNAME
    # the IPv6 query name is the one the recorded answer was captured for
    assert module_fixture("abusix_contacts", "ok_ipv6_2001-4860-4860--8888.json")["Question"][0]["name"] == V6_QNAME + "."
    assert query_name("::ffff:8.8.8.8") == "8.8.8.8.abuse-contacts.abusix.zone"  # IPv4-mapped -> IPv4
    for private in ("10.0.0.1", "192.0.2.1", "2001:db8::1", "127.0.0.1", "not-an-ip"):
        assert query_name(private) is None


def test_role_address_detection():
    for role in ("network-abuse@google.com", "arin-contact@google.com", "helpdesk@apnic.net", "abuse@quad9.net",
                 "noc@example.net", "abuse_desk@example.org", "ip-admin@example.com"):
        assert is_role_address(role), role
    for person in ("ana.souza@example.net", "j.smith@example.com", "billingsley@example.org"):
        assert not is_role_address(person), person
    assert addresses_in(['"abuse@example.net" "ana.souza@example.net"', "mailto:abuse@example.net"]) == [
        "abuse@example.net", "ana.souza@example.net"]


# ------------------------------------------------------------------ answers (c2)
def test_ipv4_contact_becomes_attribute_record_and_role_pivot():
    http = serve(FakeHttp(), "8.8.8.8", "ok_8.8.8.8.json")
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    assert res.attributes["abuse_contact"] == "network-abuse@google.com"
    record = res.attributes["abuse_contacts"][0]
    assert record["email"] == "network-abuse@google.com" and record["kind"] == "abusix_contact"
    assert record["authority_rank"] == 3 and record["source"] == SOURCE and record["resource"] == "8.8.8.8"
    assert record["ttl"] == 300 and record["report_reference"] == REPORT_REFERENCE
    pivot = emails(res)["network-abuse@google.com"]
    assert pivot.relation == "contact_email" and pivot.expand is False
    assert "abuse_contact_non_role" not in res.attributes
    assert res.raw["query"] == "8.8.8.8.abuse-contacts.abusix.zone"
    http.assert_hosts_within(AbusixContacts)  # only the core DoH resolvers were contacted
    assert set(res.hosts) <= {"dns.google", "cloudflare-dns.com"}


def test_ipv6_nibble_query():
    http = serve(FakeHttp(), V6, "ok_ipv6_2001-4860-4860--8888.json")
    res = run_module(AbusixContacts, f"ipv6:{V6}", http)
    assert res.status is Status.OK
    assert res.attributes["abuse_contact"] == "arin-contact@google.com"
    assert set(emails(res)) == {"arin-contact@google.com"}
    assert any(V6_QNAME in url for url in http.urls())


def test_rir_helpdesk_answer():
    res = run_module(AbusixContacts, "ipv4:1.1.1.1", serve(FakeHttp(), "1.1.1.1", "ok_rir_1.1.1.1.json"))
    assert res.status is Status.OK and set(emails(res)) == {"helpdesk@apnic.net"}


def test_non_role_address_is_kept_as_attribute_and_never_pivoted():
    res = run_module(AbusixContacts, "ipv4:9.9.9.9", serve(FakeHttp(), "9.9.9.9", "non_role_synthetic.json"))
    assert res.status is Status.OK
    assert set(emails(res)) == {"abuse@example.net"}
    assert res.attributes["abuse_contact"] == "abuse@example.net"
    assert res.attributes["abuse_contact_non_role"] == ["ana.souza@example.net"]
    assert [r["email"] for r in res.attributes["abuse_contacts"]] == ["abuse@example.net"]


def test_only_non_role_addresses_still_no_pivot():
    http = FakeHttp().add("GET", doh_url(query_name("9.9.9.9"), "TXT"), json={
        "Status": 0, "Answer": [{"name": "9.9.9.9.abuse-contacts.abusix.zone.", "type": 16, "TTL": 60, "data": "ana.souza@example.net"}]})
    res = run_module(AbusixContacts, "ipv4:9.9.9.9", http)
    assert res.status is Status.OK and not res.pivots
    assert res.attributes["abuse_contact"] == "ana.souza@example.net"
    assert res.attributes["abuse_contact_non_role"] == ["ana.souza@example.net"]
    assert "abuse_contacts" not in res.attributes


# ------------------------------------------------------------------ absence and rule 5 (c3)
def test_nxdomain_means_no_contact_published():
    # the real NXDOMAIN answer (captured for 192.0.2.1, which the module itself never queries)
    res = run_module(AbusixContacts, "ipv4:8.8.4.4", serve(FakeHttp(), "8.8.4.4", "nxdomain.json"))
    assert res.status is Status.EMPTY and "no abuse contact published" in res.error
    assert not res.pivots and "abuse_contact" not in res.attributes


def test_nodata_means_no_contact_published():
    http = FakeHttp().add("GET", doh_url(query_name("8.8.4.4"), "TXT"), json={"Status": 0, "Answer": []})
    assert run_module(AbusixContacts, "ipv4:8.8.4.4", http).status is Status.EMPTY


def test_servfail_is_could_not_verify_never_empty():
    res = run_module(AbusixContacts, "ipv4:9.9.9.10", serve(FakeHttp(), "9.9.9.10", "servfail_synthetic.json"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.source_statuses[SOURCE]["status"] == "error"


@pytest.mark.parametrize("kind", ["http500", "http429", "challenge"])
def test_resolver_failures_are_could_not_verify(kind):
    http = FakeHttp()
    add_dns_failure(http, query_name("8.8.8.8"), "TXT", kind=kind, provider="all")
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and res.status is not Status.EMPTY


def test_timeout_maps_to_reason_timeout():
    http = FakeHttp()
    add_dns_failure(http, query_name("8.8.8.8"), "TXT", kind="timeout", provider="all")
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_dead_network_is_could_not_verify():
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", DeadHttp())
    assert res.status is Status.ERROR


def test_txt_without_an_address_is_could_not_verify():
    http = FakeHttp().add("GET", doh_url(query_name("8.8.8.8"), "TXT"), json={
        "Status": 0, "Answer": [{"name": "8.8.8.8.abuse-contacts.abusix.zone.", "type": 16, "TTL": 300, "data": "v=spf1 -all"}]})
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", http)
    assert res.status is Status.ERROR and "without an e-mail address" in res.error


def test_private_and_documentation_addresses_are_never_queried():
    http = FakeHttp()
    for value in ("ipv4:10.1.2.3", "ipv4:192.0.2.1", "ipv6:2001:db8::5"):
        res = run_module(AbusixContacts, value, http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def _replay(etype, module):
    """FakeHttp with the AR21 golden-path routes of tests/fixtures/acceptance/<etype>/<module>.json."""
    import base64

    doc = json.loads((FIXTURES / "acceptance" / etype / f"{module}.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == module
    http = FakeHttp()
    for route in doc["routes"]:
        if "json" in route:
            body = {"json": route["json"]}
        elif "body_b64" in route:
            body = {"body": base64.b64decode(route["body_b64"])}
        else:
            body = {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers") or {}, **body)
    return http, doc


def test_acceptance_routes_of_the_golden_ipv4():
    http, doc = _replay("ipv4", "abusix_contacts")
    res = run_module(AbusixContacts, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and res.attributes["abuse_contact"] == "network-abuse@google.com"
    assert len(http.calls) == len(doc["routes"])
