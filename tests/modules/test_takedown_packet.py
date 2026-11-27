"""takedown_packet (P345, batch p2-G03-1): report exporter over the case graph, no network.

Fixtures: ``tests/fixtures/takedown_packet/iana_registrar_ids_min.csv`` (a slice of the live IANA
registrar-ids CSV of 2026-11-26) and synthetic case graphs built below (documentation hosts and IPs:
registrar + RIR + Abusix contacts, a .br case, a CDN-fronted case, a single-source hit). The automatic
announcement is the rule ``g03_takedown_packet_ready`` (graph fixtures in tests/fixtures/rules/).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, DeadHttp
from v3lum.modules.url_web import takedown_packet as tp

URL = "https://examplebank-secure.example/acesso/login.php?email=victim%40example.com&t=5f3c1a9e8b7d6c5f4e3d2c1b0a998877"
SHA_A = "a" * 64
SHA_B = "b" * 64


def ent(key: str, **attrs) -> dict:
    etype, value = key.split(":", 1)
    return {"key": key, "type": etype, "value": value, "tags": attrs.pop("tags", []), "noise_kind": attrs.pop("noise_kind", ""),
            "attributes": {k: [{"value": v, "source": s} for v, s in vals] for k, vals in attrs.items()}}


def finding(entity: str, source: str, module: str, tags=("phishing",), severity="high", **extra) -> dict:
    f = {"id": f"{module}-{source}-{entity}", "title": "x", "severity": severity, "tags": list(tags), "entity": entity, "module": module,
         "source": source, "criterion": "source verdict", "suppressed_by": [], "override": None}
    f.update(extra)
    return f


def case(findings, *, extra_entities=(), modules=(), tlp="amber") -> dict:
    entities = [
        ent(f"url:{URL}"),
        ent("domain:examplebank-secure.example", registrar=[("Example Registrar, Inc.", "rdap")], registrar_iana_id=[("292", "rdap")],
            abuse_contact=[("abuse@registrar.example", "rdap")], abuse_phone=[("+1.5555550100", "rdap")]),
        ent("ipv4:198.51.100.10", country=[("US", "ripestat")], abuse_contacts=[([
            {"email": "abuse@hosting.example", "kind": "hosting_abuse_c", "authority": "RIR abuse-c (ARIN)", "source": "ripestat.data_api", "retrieved_at": "2026-11-26T10:00:00Z"},
            {"email": "network-abuse@hosting.example", "kind": "abusix_contact", "authority": "Abusix", "source": "abusix.contacts", "retrieved_at": "2026-11-26T10:00:05Z"},
            {"email": "abuse@registrar.example", "kind": "abusix_contact", "authority": "Abusix", "source": "abusix.contacts", "retrieved_at": "2026-11-26T10:00:05Z"},
        ], "ripestat")]),
        *extra_entities,
    ]
    return {"schema": "v3lum.case/2", "case_id": "case-g03", "created": "2026-11-26T12:00:00Z", "tlp": tlp, "entities": entities,
            "edges": [{"src": f"url:{URL}", "dst": "domain:examplebank-secure.example", "relation": "url_host"},
                      {"src": "domain:examplebank-secure.example", "dst": "ipv4:198.51.100.10", "relation": "resolves_to"}],
            "findings": list(findings), "modules": list(modules)}


CONSENSUS = [finding(f"url:{URL}", "phishstats.api", "phishstats"), finding(f"url:{URL}", "google_webrisk.uris_search", "google_safe_browsing", ("phishing", "malicious"))]
EVIDENCE = [{"module": "phishstats", "entity": f"url:{URL}", "evidence": "", "evidence_sha256": SHA_A},
            {"module": "google_safe_browsing", "entity": f"url:{URL}", "evidence": "", "evidence_sha256": SHA_B},
            {"module": "urlscan_search", "entity": f"url:{URL}", "evidence": "", "evidence_sha256": "not-a-hash"}]
REGS = tp.parse_iana_registrar_csv((FIXTURES / "takedown_packet" / "iana_registrar_ids_min.csv").read_bytes())["registrars"]


def test_consensus_packet_ranks_registrar_rir_abusix():
    packet = tp.build_takedown_packet(case(CONSENSUS, modules=EVIDENCE), now="2026-11-26T15:00:00Z", registrars=REGS)
    assert packet["generated"] and packet["gate"]["automatic"]
    assert packet["gate"]["families"] == ["google_safe_browsing", "phishstats"]
    kinds = [c["kind"] for c in packet["contacts"]]
    assert kinds == ["registrar_abuse", "rir_abuse_c", "abusix"]
    reg = packet["contacts"][0]
    assert reg["email"] == "abuse@registrar.example" and reg["registrar_rdap"] == "https://rdap.markmonitor.com/rdap/"
    assert all(c["reason"] and c["sources"] for c in packet["contacts"])
    # the Abusix duplicate of the registrar address is merged into the most authoritative entry
    assert len([c for c in packet["contacts"] if c["email"] == "abuse@registrar.example"]) == 1
    assert packet["tlp"] == "TLP:AMBER" and packet["cert_br"] is None
    names = [lk["name"] for lk in packet["manual_links"]]
    assert names[:2] == ["Google Safe Browsing report_phish", "Netcraft report"]


def test_minimisation_and_dual_timestamps():
    packet = tp.build_takedown_packet(case(CONSENSUS, modules=EVIDENCE), now="2026-11-26T15:00:00Z", registrars=REGS)
    text = json.dumps(packet)
    assert "victim" not in text and "5f3c1a9e8b7d6c5f4e3d2c1b0a998877" not in text  # c6
    assert packet["target"]["report_url"] == "https://examplebank-secure.example/acesso/login.php"
    assert packet["target"]["url_defanged"].startswith("hxxps://examplebank-secure[.]example/")
    assert [e["sha256"] for e in packet["evidence"]] == [SHA_A, SHA_B] and packet["evidence_rejected"] == 1
    ev = packet["evidence"][0]
    assert ev["captured_at_utc"] == "2026-11-26T12:00:00Z" and ev["captured_at_sao_paulo"] == "2026-11-26T09:00:00-03:00"
    assert packet["created_sao_paulo"] == "2026-11-26T12:00:00-03:00"
    for lang in ("pt-BR", "en"):
        assert SHA_A in packet["templates"][lang] and SHA_B in packet["templates"][lang]
        assert "TLP:AMBER" in packet["templates"][lang]
    assert "never sends" in packet["disclosure_note"]


def test_single_source_hit_never_generates():
    single = [finding(f"url:{URL}", "phishstats.api", "phishstats"), finding(f"url:{URL}", "phishstats.api", "phishstats", key="2")]
    packet = tp.build_takedown_packet(case(single), registrars=REGS)
    assert packet["generated"] is False and "single-source" in packet["gate"]["reason"]
    requested = tp.build_takedown_packet(case(single), requested=True, registrars=REGS)
    assert requested["generated"] is True and requested["gate"]["automatic"] is False


def test_medium_hit_and_false_positive_do_not_count():
    medium = [finding(f"url:{URL}", "phishstats.api", "phishstats", severity="medium"), finding(f"url:{URL}", "google_webrisk.uris_search", "google_safe_browsing", severity="medium")]
    assert tp.build_takedown_packet(case(medium))["generated"] is False
    fp = [dict(f, override={"verdict": "false_positive", "analyst": "x"}) for f in CONSENSUS]
    assert tp.build_takedown_packet(case(fp))["generated"] is False
    context = [dict(f, tags=["phishing", "context_only"]) for f in CONSENSUS]
    assert tp.build_takedown_packet(case(context))["generated"] is False


def test_br_case_cert_br_guidance_and_platform_links():
    br_url = "https://pagamento-boleto.example.com.br/pix"
    doc = {"schema": "v3lum.case/2", "case_id": "c-br", "created": "2026-11-26T12:00:00Z", "tlp": "amber+strict",
           "entities": [ent(f"url:{br_url}"), ent("domain:pagamento-boleto.example.com.br"), ent("telegram_handle:golpe_pix_example"),
                        ent("url:https://wa.me/5511555501234")],
           "edges": [], "modules": [],
           "findings": [finding(f"url:{br_url}", "phishstats.api", "phishstats", override={"verdict": "true_positive", "analyst": "a"})]}
    packet = tp.build_takedown_packet(doc, now="2026-11-26T15:00:00Z", registrars={})
    assert packet["generated"] and packet["gate"]["reason"] == "analyst confirmation"
    assert packet["cert_br"]["cc"] == "cert@cert.br"
    assert "Cc: cert@cert.br" in packet["templates"]["pt-BR"] and "Cc: cert@cert.br" in packet["templates"]["en"]
    platforms = {lk.get("platform") for lk in packet["manual_links"]}
    assert {"telegram", "whatsapp"} <= platforms
    assert packet["tlp"] == "TLP:AMBER+STRICT"
    assert packet["contacts"] == []
    assert "no abuse contact in the case" in tp.render_packet_markdown(packet)


def test_br_hosted_ip_adds_cert_br():
    extra = case(CONSENSUS)
    extra["entities"][2]["attributes"]["country"] = [{"value": "BR", "source": "ripestat"}]
    assert tp.build_takedown_packet(extra, registrars={})["cert_br"] is not None


def test_cdn_portal_with_origin_hints_ranked_after_abusix():
    doc = case(CONSENSUS, extra_entities=[ent("ipv4:203.0.113.5", tags=["cdn"], noise_kind="cdn", asn=[("AS13335", "ipinfo")])])
    doc["edges"].append({"src": "domain:examplebank-secure.example", "dst": "ipv4:203.0.113.5", "relation": "resolves_to"})
    packet = tp.build_takedown_packet(doc, registrars={})
    cdn = [c for c in packet["contacts"] if c["kind"] == "cdn_portal"]
    assert cdn and cdn[0]["url"] == "https://abuse.cloudflare.com/" and cdn[0]["origin_hints"] == ["198.51.100.10"]
    assert packet["contacts"][-1]["kind"] == "cdn_portal" and packet["target"]["behind_cdn"] is True


def test_security_txt_only_for_compromised_legit_sites():
    contacts = [{"kind": "security_txt", "email": "security@victim-site.example", "source": "security_txt"},
                {"kind": "rir_abuse_c", "email": "abuse@hosting.example", "source": "ripestat.data_api"},
                {"kind": "person", "email": "someone@example.com"}]
    assert [c["kind"] for c in tp.rank_contacts(contacts)] == ["rir_abuse_c"]
    assert [c["kind"] for c in tp.rank_contacts(contacts, compromised_legit_site=True)] == ["rir_abuse_c", "security_txt"]


def test_no_network_at_report_time():
    # the exporter has no HTTP client: a dead network changes nothing
    DeadHttp()
    packet = tp.build_takedown_packet(case(CONSENSUS, modules=EVIDENCE), registrars=REGS)
    assert packet["generated"]


def test_iana_registrar_csv_parser():
    out = tp.parse_iana_registrar_csv((FIXTURES / "takedown_packet" / "iana_registrar_ids_min.csv").read_bytes())
    assert out["error"] is None
    assert out["registrars"]["292"] == {"name": "MarkMonitor Inc.", "status": "Accredited", "rdap": "https://rdap.markmonitor.com/rdap/"}
    assert out["registrars"]["93"]["rdap"] is None
    assert tp.parse_iana_registrar_csv("<html>blocked</html>")["error"] == "html instead of csv"
    assert tp.parse_iana_registrar_csv("a,b\n1,2")["error"] == "unexpected header"


def test_render_markdown_lists_everything():
    packet = tp.build_takedown_packet(case(CONSENSUS, modules=EVIDENCE), now="2026-11-26T15:00:00Z", registrars=REGS)
    text = tp.render_packet_markdown(packet)
    assert text.startswith("TLP:AMBER") and "abuse@registrar.example" in text and SHA_A in text
    assert "## Template (pt-BR)" in text and "never sends" in text
    refused = tp.render_packet_markdown(tp.build_takedown_packet(case([])))
    assert "not generated" in refused


@pytest.mark.parametrize("value,utc,sp", [("2026-01-15T12:00:00Z", "2026-01-15T12:00:00Z", "2026-01-15T09:00:00-03:00"),
                                          ("2026-11-26T02:30:00+00:00", "2026-11-26T02:30:00Z", "2026-11-25T23:30:00-03:00")])
def test_dual_timestamps(value, utc, sp):
    out = tp.dual_timestamps(value)
    assert out == {"utc": utc, "sao_paulo": sp}
