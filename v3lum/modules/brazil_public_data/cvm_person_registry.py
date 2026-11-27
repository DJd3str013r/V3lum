"""cvm_person_registry (P360 FC9): CVM registries of natural-person professionals, explicit due diligence only.

Batch p1-G10-3. Is an analyst-typed full name registered with CVM as a portfolio manager
(administrador de carteira) or securities adviser (consultor de valores mobiliarios)? Offline matching
(disclosure 'none') against the local copies of ``cad_adm_cart_pf.csv`` and
``cad_consultor_vlmob_pf.csv`` loaded by the shared CVM loader
(:mod:`v3lum.modules.brazil_public_data.cvm_registries`).

P360 FC9 and rule 4 / LGPD minimisation:

* matched only in explicit due diligence: ``default_enabled=False`` (``-M cvm_person_registry`` or
  ``--preset deep``), ``run_on='seeds'`` (analyst-typed names only, never pivots or names found in text)
  and a recorded ``--purpose`` (SKIPPED 'privacy' without one);
* the exact normalised full name is the only key: a CPF (or CPF-shaped digits) is never a lookup key,
  a single word is never matched, and the files carry no CPF column (a future one would be kept masked);
* every hit is POSSIBLE ('the same name does not prove identity'), context only (never scored), with no
  pivots; only the registry, segment, category and status are reported.

The datasets are non-essential (``v3lum data update cvm_adm_cart_pf.csv cvm_consultor_vlmob_pf.csv``),
never downloaded during a scan, and use their own registry source (``cvm.cvm_person_registry_pf``) so
they never gate ``bcb_authorized_institutions``. Attribution: CVM (dados.cvm.gov.br, ODbL).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.datasets import DatasetError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import cvm_registries as cvm

SOURCE = cvm.SOURCE_PF
MAX_SHOWN = 10
DATASET_NAMES = tuple(cvm.REGISTRIES[k].dataset for k in cvm.PF_REGISTRIES)


@register
class CvmPersonRegistry(Module):
    name = "cvm_person_registry"
    title = "CVM licensed professionals (due diligence)"
    description = (
        "Explicit due diligence only: exact-name matches of an analyst-typed full name in the CVM registries of natural-person "
        "portfolio managers and securities advisers (local copies, POSSIBLE only, never keyed by CPF)."
    )
    category = "brazil_public_data"
    accepts = {T.PERSON}
    produces: Any = frozenset()
    tags = {"offline", "free", "brazil"}
    reference = "https://dados.cvm.gov.br/dataset/adm_cart-cad"
    notice = (
        "Natural-person registries are matched only in explicit due diligence (P360 FC9, LGPD minimisation): off by default, "
        "analyst-typed seeds only and a recorded --purpose; the exact full name is the only key (never a CPF) and every hit is "
        "POSSIBLE - the same name does not prove identity. Source: CVM open data (dados.cvm.gov.br, ODbL)."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    run_on = "seeds"
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    max_pivots = 0
    default_enabled = False  # explicit due diligence only (FC9)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not cvm.clean(getattr(ctx, "purpose", "")):
            return res.mark(Status.SKIPPED, "natural-person registries need explicit due diligence: record a --purpose (P360 FC9)", reason_code="privacy")
        declared = getattr(ctx, "allowed_sources", None)
        if SOURCE not in frozenset(self.sources if declared is None else declared):
            return res.mark(Status.SKIPPED, "the CVM natural-person registries are not allowed in this run (licence profile)", reason_code="licence")
        try:
            rows, metas, missing = cvm.load_people(ctx.data)
        except DatasetError as exc:
            return res.mark(Status.UNAVAILABLE, f"not screened against the CVM natural-person registries - {exc}", reason_code="dataset")
        if not metas:
            return res.mark(Status.UNAVAILABLE, "not screened against the CVM natural-person registries - run v3lum data update "
                            + " ".join(missing or DATASET_NAMES), reason_code="dataset")
        match = cvm.due_diligence_match(entity.value, rows, purpose=str(ctx.purpose))
        if not match["ok"]:
            return res.mark(Status.SKIPPED, match["error"], reason_code="not_applicable")
        dates = sorted(str(m.get("date")) for m in metas if m.get("date"))
        as_of = dates[0] if dates else "?"
        note = f" ({', '.join(missing)} not installed)" if missing else ""
        hits = match["matches"]
        res.raw = {
            "matches": len(hits),
            "datasets": [{k: m.get(k) for k in ("name", "sha256", "date", "rows", "stale")} for m in metas],
            "missing_datasets": list(missing),
            "attribution": cvm.ATTRIBUTION,
        }
        if not hits:
            res.source_status(SOURCE, Status.EMPTY, reason=f"no exact-name match in the CVM natural-person registries as of {as_of}{note}")
            return res.mark(Status.EMPTY)
        shown = [{k: h.get(k) for k in ("registry", "segment", "category", "status", "status_since")} for h in hits[:MAX_SHOWN]]
        res.attr("cvm_person_registrations", shown)
        active = sorted({str(h.get("segment")) for h in hits if h.get("status") == "active"})
        res.finding(
            "Possible CVM registration of a natural person (same name)",
            "info",
            f"{len(hits)} registration(s) in the CVM natural-person registries carry exactly this full name"
            + (f" (active: {', '.join(active)})" if active else " (none active)")
            + f", as of {as_of}{note}. The same name does not prove identity: confirm through the CVM register before relying on it.",
            confidence="possible",
            criterion="exact normalised full name equal to a name in the CVM registries of natural-person portfolio managers or securities advisers",
            data={"registrations": shown, "matches": len(hits), "as_of": as_of, "attribution": cvm.ATTRIBUTION},
            tags=["context_only", "info"],
            source=SOURCE,
        )
        res.source_status(SOURCE, Status.OK, reason=f"CVM natural-person registries as of {as_of}{note}")
        return res
