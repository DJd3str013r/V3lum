"""pivots_brazil: Brazilian company pages, manual links only (P250, batch p2-G14-2).

Disclosure ``none``: the module only builds URLs; V3LUM never requests these pages (P250 cond 1). The pack is
``v3lum/data/pivot_links/brazil.json``:

* core pack links, rendered by the engine and by ``v3lum links``: Portal da Transparencia ``/busca?termo=``
  with the formatted CNPJ (``{cnpj_fmt}``, P250 cond 8) or the company name, Reclame Aqui (labelled 'consumer
  complaints: context, not proof', cond 12), Jusbrasil and Escavador (CNPJ or company name), Receita Federal's
  Comprovante de Inscricao (``{cnpj_digits}``; the analyst solves the CAPTCHA in the browser) and Casa dos
  Dados. Challenge-walled sites ship unverified with antibot=true (cond 10-11). CNPJ templates are
  privacy=true (frozen P311 lint: company identifiers), so they render for analyst-typed CNPJ seeds of a case
  that opted in.
* static ``x_module_links`` emitted here for analyst-typed seeds: consumidor.gov.br (its company search is a
  JavaScript autocomplete without a GET URL) and the national SINTEGRA portal (a frameset linking each state's
  lookup, no CNPJ parameter). They carry no value: the analyst types it on the page (A9 manual links).

Rule 4 (legal floor, cond 9): no template ever takes a CPF and no person-name or people-search template exists
(the batch lint refuses any type other than cnpj and company_name). A2: at TLP:AMBER and above the label says
that opening sends nothing and typing the value sends it to the host; at RED nothing is emitted.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_pack_render as pr

PACK = "brazil"
STATIC_LINKS = ("consumidor_gov_busca", "sintegra_portal")  # P250 cond 6 order


@register
class PivotsBrazil(Module):
    name = "pivots_brazil"
    title = "Brazilian company pages (manual links)"
    description = (
        "Static manual links for an analyst-typed CNPJ or company name: consumidor.gov.br complaints search and the "
        "SINTEGRA state-registration portal (the analyst types the value). Portal da Transparencia, Reclame Aqui, "
        "Jusbrasil, Escavador, Receita and Casa dos Dados come from the brazil pack. V3LUM never fetches them."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG}
    produces = frozenset()
    run_on = "seeds"
    reference = "https://www.consumidor.gov.br/"
    tags = {"offline", "brazil"}
    notice = (
        "Manual links only (never fetched); CNPJ and company names only, never a CPF or a person (rule 4). Consumer "
        "complaints are context, not proof."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.01
    timeout = 10.0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bool(getattr(ctx, "is_seed", False))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = pr.tlp_level(ctx)
        red = pr.hidden_reason(None, level)
        if red:
            return res.mark(Status.SKIPPED, red, reason_code="tlp")
        found = pr.module_links(PACK)
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        for link_id in STATIC_LINKS:
            ml = found.get(link_id)
            if ml is None:
                hidden.append({"id": link_id, "reason": "link not loaded (see module_link_errors)"})
                continue
            if entity.type not in ml.link.entity_types:
                continue
            rendered = pr.render(ml, entity)
            if rendered is None:
                hidden.append({"id": link_id, "reason": "did not render (lint or tier)"})
                continue
            shown.append(pr.emit(res, entity, level, rendered, ml=ml))
        res.raw = {"tlp": level.value_str, "links": shown, "hidden": hidden}
        if not shown:
            return res.mark(Status.EMPTY)
        return res
