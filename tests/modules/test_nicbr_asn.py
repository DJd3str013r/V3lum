"""nicbr_asn (P038): NIC.br ASN block list - parser, shared index, owner pivots, provider guard.

Fixtures in tests/fixtures/nicbr_asn/: ``ok.txt`` is a trimmed real copy of nicbr-asn-blk-latest.txt
(2026-11-26; company owners only), ``cp1252.txt`` the same lines re-encoded, ``tolerance.txt`` real
lines plus synthetic comment, garbage, CPF and invalid lines (documentation values) and ``empty.txt``.
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import datasets
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network import nicbr_asn as nb
from v3lum.modules.ip_network.cloud_ranges import RangeIndex
from v3lum.modules.ip_network.nicbr_asn import NicbrAsn

FIX = FIXTURES / "nicbr_asn"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def install(body: bytes | None = None) -> None:
    (paths.datasets_dir() / nb.DATASET).write_bytes((FIX / "ok.txt").read_bytes() if body is None else body)


def run(value: str, **kw):
    kw.setdefault("runtime", make_runtime(FakeHttp(), offline=True))  # local copy only
    return run_module(NicbrAsn, value, **kw)


def pivots(res, relation=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ IP -> owner (cond 1-4)
def test_ip_in_registrant_block_pivots_to_owner_cnpj():
    install()
    res = run("ipv4:170.66.10.1")  # Banco do Brasil AS11993, 170.66.0.0/16
    assert res.status is Status.OK
    a = res.attributes
    assert a["asn"] == "AS11993" and a["prefix"] == "170.66.0.0/16" and a["as_org"] == "BANCO DO BRASIL S.A."
    assert a["owner_kind"] == "registrant" and a["owner_cnpj"] == "00.000.000/0001-91"
    cnpj = pivots(res, "registrant")[(T.CNPJ, "00000000000191")]
    assert cnpj.expand is True and cnpj.confidence_label.value == "confirmed"
    assert pivots(res, "belongs_to_asn")[(T.ASN, "AS11993")].expand is True  # analyst-typed seed
    assert pivots(res, "in_network")[(T.CIDR, "170.66.0.0/16")].expand is False
    assert res.datasets and res.datasets[0]["name"] == nb.DATASET


def test_ip_in_isp_block_never_pivots_into_the_provider_company():
    install()
    res = run("ipv4:200.210.1.1")  # Claro AS4230 customer space
    a = res.attributes
    assert a["owner_kind"] == "network_provider" and a["owner_basis"] == "bundled provider list (ASN)"
    assert a["isp"] == "CLARO S.A." and a["owner_cnpj"] == "40.432.544/0706-09"  # attribute only
    assert not [p for p in res.pivots if p.entity.type is T.CNPJ]
    asn = pivots(res, "network_provider")[(T.ASN, "AS4230")]
    assert asn.expand is False and "customer space" in asn.note
    assert all(not p.expand for p in res.pivots)


@pytest.mark.parametrize(
    ("value", "basis"),
    [("ipv4:200.234.200.1", "bundled provider list (ASN)"),  # Locaweb
     ("ipv6:2804:5330::1", "bundled provider list (ASN)"),  # Cogent
     ("ipv4:200.130.1.1", "bundled provider list (ASN)")],  # RNP (NREN)
)
def test_bundled_providers(value, basis):
    install()
    res = run(value)
    assert res.attributes["owner_kind"] == "network_provider" and res.attributes["owner_basis"] == basis
    assert not [p for p in res.pivots if p.relation == "registrant"]


def test_ip_reached_as_a_pivot_lists_the_asn_without_expanding_it():
    install()
    res = run("ipv4:170.66.10.1", is_seed=False, depth=1)
    assert pivots(res, "belongs_to_asn")[(T.ASN, "AS11993")].expand is False
    assert pivots(res, "registrant")[(T.CNPJ, "00000000000191")].expand is True  # cond 3: the IP -> CNPJ link stays


def test_cidr_input_and_not_in_list():
    install()
    res = run("cidr:200.160.2.0/24")
    assert res.attributes["asn"] == "AS22548" and res.attributes["prefix"] == "200.160.0.0/20"
    assert run("ipv4:8.8.8.8").status is Status.EMPTY  # the list answered: not a NIC.br block


# ------------------------------------------------------------------ ASN -> owner + prefixes (cond 3-4)
def test_asn_registrant_lists_owner_and_prefixes():
    install()
    res = run("asn:AS11993")
    assert res.attributes["as_org"] == "BANCO DO BRASIL S.A." and res.attributes["owner_kind"] == "registrant"
    assert pivots(res, "registrant")[(T.CNPJ, "00000000000191")].expand is True
    announces = [p for p in res.pivots if p.relation == "announces"]
    # IPv4 first, larger blocks first; only the first EXPAND_CAP prefixes of a seed expand
    assert [p.entity.value for p in announces] == ["170.66.0.0/16", "201.33.144.0/20", "198.184.161.0/24", "2801:8e::/32"]
    assert [p.expand for p in announces] == [i < nb._expand_cap(T.CIDR) for i in range(4)]
    assert res.attributes["registered_prefix_counts"] == {"total": 4, "ipv4": 3, "ipv6": 1, "pivoted": 4, "capped": False}


def test_provider_asn_reached_as_pivot_never_expands_its_company():
    install()
    seed = run("asn:AS4230")
    pivot = run("asn:AS4230", is_seed=False, depth=2)
    assert pivots(seed, "registrant")[(T.CNPJ, "40432544070609")].expand is True  # the analyst typed the ASN
    company = pivots(pivot, "registrant")[(T.CNPJ, "40432544070609")]
    assert company.expand is False and "reached as a pivot" in company.note
    assert all(not p.expand for p in pivot.pivots if p.relation == "announces")


def test_unknown_asn_is_empty():
    install()
    assert run("asn:AS15169").status is Status.EMPTY


# ------------------------------------------------------------------ CNPJ -> networks (cond 3, 5)
def test_cnpj_lists_candidate_netblocks_capped_at_50():
    install()
    res = run("cnpj:05506560000136")  # NIC.br: 15 ASNs and 47 prefixes in the trimmed copy
    owned = res.attributes["owned_networks"]
    assert owned["match"] == "exact" and owned["capped"] is True
    assert owned["candidate_own_netblocks"] is True and owned["scope_eligible"] is False
    assert len(res.pivots) == nb.PIVOT_CAP
    assert all(p.relation == "owns_network" and "never joins an ACTIVE scope" in p.note for p in res.pivots)
    assert [p.entity.type for p in res.pivots][:owned["total_asns"]] == [T.ASN] * owned["total_asns"]  # ASNs first
    expanded = [p for p in res.pivots if p.expand]
    assert len([p for p in expanded if p.entity.type is T.ASN]) == nb._expand_cap(T.ASN)
    assert len([p for p in expanded if p.entity.type is T.CIDR]) == nb._expand_cap(T.CIDR)
    assert res.findings[0].title == "Networks registered to the company (NIC.br)"


def test_cnpj_root_match_is_probable():
    install()
    res = run("cnpj:40432544000147")  # Claro head office; the list names branch 0706-09
    assert res.attributes["owned_networks"]["match"] == "cnpj_root"
    assert {p.confidence_label.value for p in res.pivots} == {"probable"}
    assert run("cnpj:11222333000181").status is Status.EMPTY


# ------------------------------------------------------------------ rule 4 / LGPD (cond 6)
def test_parser_tolerance_and_owner_id_rules():
    parsed = nb.parse_nicbr_asn_blk((FIX / "tolerance.txt").read_bytes())
    stats = parsed.stats
    assert stats["bom"] is True and stats["comments"] == 2 and stats["blank"] == 2
    assert stats["malformed_lines"] == 2  # garbage line + ASX12
    by_asn = {r.asn: r for r in parsed.records}
    person = by_asn[64497]  # CPF-shaped owner id: id and name dropped, never pivoted
    assert person.owner_id_status == "discarded_cpf" and person.owner == "" and person.cnpj == ""
    invalid = by_asn[64496]  # invalid CNPJ: id dropped, organisation name kept; 999.1.1.0/24 skipped
    assert invalid.owner_id_status == "discarded_invalid" and invalid.owner == "EXEMPLO INVALIDO LTDA" and invalid.prefixes == ("192.0.2.0/24",)
    masked = by_asn[64498]
    assert masked.owner == "EXEMPLO DA SILVA ***.***.***-**" and masked.cnpj == "11222333000181"
    assert stats["discarded_cpf"] == 1 and stats["masked_names"] == 1 and stats["invalid_prefixes"] == 1
    assert "11111111111" not in repr(parsed.records) and "111.111.111-11" not in repr(parsed.records)


def test_discarded_owner_ids_are_never_pivoted():
    install((FIX / "tolerance.txt").read_bytes())
    res = run("ipv4:198.51.100.10", runtime=make_runtime(FakeHttp(), offline=True))
    assert res.status is Status.SKIPPED  # documentation space is not applicable (never matched)
    idx = nb.build_index(nb.parse_nicbr_asn_blk((FIX / "tolerance.txt").read_bytes()))
    assert "" not in idx.by_cnpj and all(r.cnpj for rs in idx.by_cnpj.values() for r in rs)


def test_individual_entrepreneur_registrant_is_listed_not_expanded():
    line = "AS64511|12.345.678 FULANO DE TAL|11.222.333/0001-81|177.10.0.0/22\n"
    install(((FIX / "ok.txt").read_text(encoding="utf-8") + line).encode("utf-8"))
    res = run("ipv4:177.10.1.1")
    cnpj = pivots(res, "registrant")[(T.CNPJ, "11222333000181")]
    assert cnpj.expand is False and "individual entrepreneur" in cnpj.note


def test_encoding_fallback_and_empty_file():
    utf8 = nb.parse_nicbr_asn_blk((FIX / "ok.txt").read_bytes())
    latin = nb.parse_nicbr_asn_blk((FIX / "cp1252.txt").read_bytes())
    assert latin.stats["encoding"] == "cp1252" and utf8.stats["encoding"] == "utf-8"
    assert [r.owner for r in latin.records] == [r.owner for r in utf8.records]
    assert [(r.asn, r.cnpj, r.prefixes) for r in latin.records] == [(r.asn, r.cnpj, r.prefixes) for r in utf8.records]
    empty = nb.parse_nicbr_asn_blk((FIX / "empty.txt").read_bytes())
    assert empty.records == [] and "too few records" in nb.validate_list(empty)
    assert "HTML" in nb.parse_nicbr_asn_blk(CHALLENGE).error


def test_trimmed_real_fixture_parses_completely():
    parsed = nb.parse_nicbr_asn_blk((FIX / "ok.txt").read_bytes())
    assert parsed.stats["malformed_lines"] == 0 and len(parsed.records) == 24
    isc = next(r for r in parsed.records if r.asn == 275327)
    assert isc.owner_id_status == "discarded_invalid" and isc.cnpj == "" and isc.owner == "Internet Systems Consortium"
    nic = next(r for r in parsed.records if r.asn == 22548)
    assert nic.cnpj == "05506560000136" and nic.prefixes == ("200.160.0.0/20", "2001:12ff::/32")


def test_classify_owner_order():
    providers = nb.ProviderList(frozenset({7738}), frozenset({"40432544"}))
    rec = nb.NicbrRecord
    assert nb.classify_owner(rec(7738, "V tal", "02041460000193", "cnpj", ()), providers)[1] == "bundled provider list (ASN)"
    assert nb.classify_owner(rec(1, "Claro S/A", "40432544000147", "cnpj", ()), providers)[1] == "bundled provider list (CNPJ root)"
    assert nb.classify_owner(rec(2, "ACME LTDA", "", "missing", ()), providers, peeringdb_type="Cable/DSL/ISP")[0] == "network_provider"
    assert nb.classify_owner(rec(3, "Exemplo Telecomunicações Ltda", "", "missing", ()), providers)[1].startswith("owner-name keyword TELECOM")
    assert nb.classify_owner(rec(4, "MEGA NET LTDA", "", "missing", ()), providers)[1] == "owner-name keyword NET"
    assert nb.classify_owner(rec(5, "BANCO EXEMPLO S.A.", "", "missing", ()), providers)[0] == "registrant"


def test_bundled_provider_list_loads():
    doc = datasets.DataStore.bundled_json(nb.PROVIDERS_FILE)
    providers = nb.provider_list(doc)
    assert {4230, 7738, 18881, 27715, 1916} <= providers.asns and "40432544" in providers.cnpj_roots
    assert nb.provider_list({"providers": [{"asns": ["x"], "cnpj_roots": [1]}]}) == nb.ProviderList()


# ------------------------------------------------------------------ dataset (cond 1-2)
def test_missing_dataset_is_unavailable_never_no_brazilian_owner():
    res = run("ipv4:170.66.10.1")
    assert res.status is Status.UNAVAILABLE and res.reason_code in ("dataset", "offline")
    assert "could not verify" in res.error and not res.pivots


def _big_valid_list(n: int = 5200) -> bytes:
    lines = [(FIX / "ok.txt").read_text(encoding="utf-8")]
    for i in range(n):  # synthetic filler records (documentation-like owners, a valid example CNPJ)
        lines.append(f"AS{400000 + i}|EXEMPLO {i} LTDA|11.222.333/0001-81|45.{(i // 250) % 250}.{i % 250}.0/24\n")
    return "".join(lines).encode("utf-8")


def test_download_is_validated_before_it_replaces_the_index():
    big = _big_valid_list()
    assert len(big) >= nb.MIN_BYTES
    http = FakeHttp().add("GET", nb.DATASET_URL, body=big, headers={"content-type": "text/plain"})
    res = run_module(NicbrAsn, "ipv4:170.66.10.1", http)
    assert res.status is Status.OK and res.attributes["asn"] == "AS11993"
    assert (paths.datasets_dir() / nb.DATASET).read_bytes() == big
    assert http.calls[0]["headers"].get("Accept") == "text/plain"


@pytest.mark.parametrize(
    "route",
    [
        {"body": (FIX / "ok.txt").read_bytes(), "headers": {"content-type": "text/plain"}},  # far below 300 KB
        {"status": 403, "text": CHALLENGE},
        {"status": 200, "text": CHALLENGE * 3000},  # an HTML page of the right size
        {"status": 503, "text": "maintenance"},
    ],
)
def test_bad_downloads_leave_no_index_and_say_could_not_verify(route):
    http = FakeHttp().add("GET", nb.DATASET_URL, **route)
    res = run_module(NicbrAsn, "ipv4:170.66.10.1", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert not (paths.datasets_dir() / nb.DATASET).exists()


def test_validator_ratio_and_record_floor():
    parsed = nb.parse_nicbr_asn_blk(_big_valid_list(5100))
    assert nb.validate_list(parsed) == ""
    garbage = nb.parse_nicbr_asn_blk(_big_valid_list(5100) + b"garbage\n" * 400)
    assert "too many malformed lines" in nb.validate_list(garbage)


def test_dataset_registration_and_shared_index():
    reg = datasets.DATASETS[nb.DATASET]
    assert reg["source"] == "registrobr.asn_blocks" and reg["terms_class"] == "open" and reg["ttl"] == 86400
    assert reg["min_bytes"] == nb.MIN_BYTES and reg["essential"] is True
    idx = nb.build_index(nb.parse_nicbr_asn_blk((FIX / "ok.txt").read_bytes()))
    assert isinstance(idx.ranges, RangeIndex)  # cond 2: the shared P034 index, no private radix tree
    prefix, rec = idx.ranges.lookup("200.160.2.3")[0]
    assert (prefix, rec.asn) == ("200.160.0.0/20", 22548)


def test_local_lookup_reads_the_local_copy_only():
    assert nb.local_lookup("170.66.10.1") is None  # no copy: never a download
    install()
    found = nb.local_lookup("200.210.1.1")
    assert found and found["asn"] == 4230 and found["owner_kind"] == "network_provider"
