"""br_public_spending_br (P246 cond 2-3): Compras.gov.br SICAF supplier record and PNCP, BR egress only.

Fixtures in tests/fixtures/br_public_spending_br/ (prep capture 2026-11-26 from a non-BR datacenter egress):
``compras_fornecedor_ok.json`` (BB supplier record with the required ativo=true; masked partner names replaced by
two synthetic masked names, e-mail and phone by documentation values), ``compras_fornecedor_empty.json`` (all-zero
placeholder CNPJ: resultado []), ``compras_fornecedor_missing_param_404.http.json`` (the 404 'Resource not found' the
research misread as egress filtering), ``pncp_empty_reply.http.json`` and ``pncp_timeout.http.json`` (PNCP from a
non-BR egress: curl 52 empty reply and a 20 s timeout).
"""

from __future__ import annotations

import json

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum.core import links
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import br_public_spending as S
from v3lum.modules.brazil_public_data.br_public_spending import BrPublicSpendingBr

FIX = FIXTURES / "br_public_spending_br"
BB = "00000000000191"


def fx(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def run(cnpj: str, http: FakeHttp, **kw):
    res = run_module(BrPublicSpendingBr, f"cnpj:{cnpj}", http, **kw)
    http.assert_hosts_within(BrPublicSpendingBr)
    assert "pncp.gov.br" not in http.hosts()  # PNCP: manual link only until a BR-egress capture exists
    return res


def manual_links(res) -> set[str]:
    return {url for _label, url in res.links}


def test_sicaf_supplier_record_without_partners_or_contacts():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), json=fx("compras_fornecedor_ok.json"))
    res = run(BB, http)
    assert res.status is Status.OK
    sicaf = res.attributes["sicaf_supplier"]
    assert sicaf["active"] is True and sicaf["qualified"] is True and sicaf["supply_lines"] == ["Serviço Bancário"]
    blob = json.dumps({"a": res.attributes, "r": res.raw, "f": [f.to_dict() for f in res.findings]})
    assert "socios" not in blob and "contato@example.com" not in blob and "1155550100" not in blob and "F***** D* T**" not in blob
    assert res.findings[0].title == "Registered supplier in SICAF (Compras.gov.br)"
    assert f"https://pncp.gov.br/app/contratos?q={BB}" in manual_links(res)
    assert res.source_statuses["pncp.pncp_search"]["status"] == "skipped"
    assert res.source_statuses["pncp.pncp_search"]["reason_code"] == "config"
    assert "ativo=true" in http.urls()[0]


def test_no_supplier_record_is_empty_with_manual_links():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), json=fx("compras_fornecedor_empty.json"))
    res = run(BB, http)
    assert res.status is Status.EMPTY and "no active SICAF supplier record" in res.error
    assert len(manual_links(res)) == 2


def test_resource_not_found_is_a_query_error_never_an_absence():
    ex = fx("compras_fornecedor_missing_param_404.http.json")["response"]
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), status=404, body=ex["body"].encode(),
                          headers={"content-type": "application/json"})
    res = run(BB, http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_resource_not_found_in_a_200_body_is_a_query_error():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), json={"statusCode": 404, "message": "Resource not found"})
    res = run(BB, http)
    assert res.status is Status.ERROR and "never an absence" in res.error


def test_empty_reply_is_blocked_geo_block_could_not_verify():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), error=NetworkError(
        "ConnectionError contacting dadosabertos.compras.gov.br: ('Connection aborted.', RemoteDisconnected('Remote end closed "
        "connection without response'))", kind="ConnectionError"))
    res = run(BB, http)
    assert res.status is Status.BLOCKED and res.reason_code == "geo_block" and "Brazilian egress" in res.error
    assert len(manual_links(res)) == 2


def test_timeout_is_error_timeout():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), error=NetworkError("ReadTimeout reading", kind="ReadTimeout",
                                                                                 reason_code="timeout"))
    res = run(BB, http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_403_and_challenge_are_blocked():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), status=403, text="<html><body>Forbidden</body></html>")
    assert run(BB, http).status is Status.BLOCKED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", S.compras_fornecedor_url(BB), status=200, text=page)
    assert run(BB, http2).status is Status.BLOCKED


def test_429_is_rate_limited():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), status=429, text="too many")
    assert run(BB, http).status is Status.RATE_LIMITED


def test_malformed_json_is_an_error():
    http = FakeHttp().add("GET", S.compras_fornecedor_url(BB), status=200, body=b'{"resultado": [', headers={"content-type": "application/json"})
    assert run(BB, http).status is Status.ERROR


def test_br_egress_declaration_and_manual_link():
    assert BrPublicSpendingBr.requires_egress == frozenset({"BR"}) and BrPublicSpendingBr.default_enabled is False
    assert BrPublicSpendingBr.hosts == ("dadosabertos.compras.gov.br",)
    rendered = links.render_manual(BrPublicSpendingBr.manual_link, Entity.make(T.CNPJ, BB), include_privacy=True)
    assert rendered is not None and rendered.url == f"https://pncp.gov.br/app/contratos?q={BB}"


def test_pncp_fixtures_document_the_non_br_egress_failure():
    assert fx("pncp_empty_reply.http.json")["response"] is None
    assert "Empty reply" in fx("pncp_empty_reply.http.json")["transport_error"]
    assert fx("pncp_timeout.http.json")["response"] is None


def test_policy_gate_skips_without_brazilian_egress_and_allows_with_it():
    ent = Entity.make(T.CNPJ, BB)
    outside = Engine(make_runtime(FakeHttp()), ScanOptions()).decide_single(BrPublicSpendingBr, ent)
    assert outside.allowed is False and outside.reason_code == "egress_country" and outside.status is Status.SKIPPED
    inside = Engine(make_runtime(FakeHttp(), settings={"egress_country": "BR"}), ScanOptions()).decide_single(BrPublicSpendingBr, ent)
    assert inside.allowed is True, (inside.reason_code, inside.reason)
