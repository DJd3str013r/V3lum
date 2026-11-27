"""Brazilian identifier validators and the BR entity rule set (P232), fully offline.

* CNPJ, numeric and alphanumeric (IN RFB 2.229/2024, issued from July 2026): check digits with
  char value ord(c)-48, the 8-character root, the order (0001 = head office) and the head-office
  CNPJ derived from the root (cond 2); 'check digits valid (format only)' never means existence or
  registration (cond 4);
* CPF (rule 4 floor, cond 3): validated offline only, never a lookup key, never generated,
  enumerated or completed from masked forms; masked ``***.456.789-**`` with the core masking function
  (AR24, cond 5) and never pivoted; the fiscal-region digit is an info-only cross-check worded 'CPF
  issued in fiscal region N (UFs)', never residence (cond 4);
* plates: validation and old <-> Mercosul conversion only, both forms kept for text search, never
  an owner lookup; CEP format with an approximate UF hint; PIX key types (cond 9);
* text: the BR rule set of ``br_parsers`` (regex candidates, then checksum gating; priority BR Code >
  boleto > CNJ > CNPJ > PIX key > CPF > phone, with the phone/CPF typing gate of cond 7). The rule set
  belongs to the shared P172 extraction engine once WP17 lands (cond 8); CPFs found in text are
  counted and shown masked only.

Disclosure 'none': no network at all (``ctx.http`` refuses every request), allowed at TLP:RED (cond 1).
PIS/NIS, titulo de eleitor, RENAVAM, CNS and CNH are never accepted, detected or pivoted (cond 6): their
masking lives in ``br_parsers.mask_national_id`` and their validators wait for official test vectors
(docs/backlog/p1-G10-1.md).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data.br_parsers import (
    CEP_WORDING,
    FORMAT_ONLY_WORDING,
    cep_info,
    cnpj_info,
    cpf_region,
    cpf_valid,
    extract_br_entities,
    mask_cpf,
    pix_key_type,
    plate_info,
)

PERSONAL_NOTE = "personal identifier from text: analyst selection required"
OTHER_NOTE = "found in text: analyst selection required"
#: Scanning bound for one text input (the pasted or typed blob; files are not accepted here).
MAX_TEXT_CHARS = 5 * 1024 * 1024
#: Entities listed in the br_entities attribute (pivots are capped by max_pivots).
MAX_LISTED = 200
#: br_entities type -> (entity type, relation note) for pivots; CPF and masked CPFs are never pivoted.
_PIVOT_TYPES = {"cnpj": (T.CNPJ, OTHER_NOTE), "phone": (T.PHONE, PERSONAL_NOTE), "boleto": (T.BOLETO, OTHER_NOTE)}
_PIX_KEY_PIVOTS = {"email": T.EMAIL, "phone": T.PHONE, "cnpj": T.CNPJ, "evp": T.PIX}


def _entity_summary(item: dict[str, Any]) -> dict[str, Any]:
    """The listed form of one extracted entity (CPF values are already masked by the rule set)."""
    out = {k: item.get(k) for k in ("type", "value", "display", "rule", "confidence", "checksum_ok", "span")}
    if item.get("key_type"):
        out["key_type"] = item["key_type"]
    return out


@register
class BrValidators(Module):
    name = "br_validators"
    title = "Brazilian identifier validators (offline)"
    description = (
        "Offline check digits and structure of CNPJ (alphanumeric included, head-office CNPJ from the root), CPF (format only, "
        "masked, never looked up), plates (old <-> Mercosul), CEP and PIX keys, plus the BR entity rule set for text (BR Code, "
        "boleto, CNJ, CNPJ, PIX key, masked CPF, phone with the phone/CPF typing gate). No network."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.CPF, T.PLATE_BR, T.TEXT, T.CEP, T.PIX}
    produces = {T.CNPJ, T.PHONE, T.EMAIL, T.BOLETO, T.PIX_BRCODE, T.PIX}
    tags = {"offline", "brazil", "free"}
    notice = (
        "Offline: no network at all. 'Check digits valid' means format only, never existence or registration. CPF is validated "
        "offline only, shown masked (***.456.789-**) and never pivoted or looked up (rule 4, LGPD). Plates are converted, never "
        "looked up. PIS/NIS, titulo de eleitor, RENAVAM, CNS and CNH are never detected or pivoted."
    )
    terms = "open"  # offline algorithms, no registry source (A1)
    opsec = Opsec.PASSIVE
    disclosure = "none"  # ctx.http refuses every request; allowed at TLP:RED
    hosts = ()
    access_model = "offline"
    max_pivots = 200
    timeout = 30.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        etype = entity.type
        if etype is T.CNPJ:
            return self._cnpj(entity, res)
        if etype is T.CPF:
            return self._cpf(entity, res)
        if etype is T.PLATE_BR:
            return self._plate(entity, res)
        if etype is T.CEP:
            return self._cep(entity, res)
        if etype is T.PIX:
            return self._pix_key(entity, res)
        return self._text(entity, res)

    # ------------------------------------------------------------------ identifiers
    @staticmethod
    def _cnpj(entity: Entity, res: ModuleResult) -> ModuleResult:
        info = cnpj_info(entity.value)
        if not info["valid"]:  # Entity normalisation already refuses invalid CNPJs: defensive only
            return res.mark("error", "invalid CNPJ check digits: not a CNPJ")
        res.attr("valid", True)
        res.attr("validity_note", FORMAT_ONLY_WORDING)
        res.attr("formatted_value", info["formatted"])
        res.attr("cnpj_structure", {k: info[k] for k in ("root", "order", "is_headquarters", "hq_cnpj", "alphanumeric")})
        if not info["is_headquarters"] and info["hq_cnpj"]:
            res.pivot(T.CNPJ, info["hq_cnpj"], "headquarters", confidence=0.9, expand=False,
                      note="head office of the same 8-character root (computed offline; existence not checked)")
        res.raw = {"cnpj": info}
        return res

    @staticmethod
    def _cpf(entity: Entity, res: ModuleResult) -> ModuleResult:
        # Rule 4: offline validation only; the full CPF never appears in the result (AR24).
        if not cpf_valid(entity.value):
            return res.mark("error", "invalid CPF check digits")
        res.attr("valid", True)
        res.attr("validity_note", FORMAT_ONLY_WORDING)
        res.attr("masked_value", mask_cpf(entity.value))
        region = cpf_region(entity.value)
        if region:
            res.attr("cpf_fiscal_region", region["text"])
        res.raw = {"cpf": {"valid": True, "masked": mask_cpf(entity.value), "fiscal_region": region["region"] if region else None}}
        return res

    @staticmethod
    def _plate(entity: Entity, res: ModuleResult) -> ModuleResult:
        info = plate_info(entity.value)
        if info is None:
            return res.mark("error", "not a Brazilian plate (old ABC1234 or Mercosul ABC1D23)")
        res.attr("valid", True)
        res.attr("validity_note", "plate format valid (format only; never an owner lookup)")
        res.attr("plate_forms", info)
        res.raw = {"plate": info}
        return res

    @staticmethod
    def _cep(entity: Entity, res: ModuleResult) -> ModuleResult:
        info = cep_info(entity.value)
        if not info["valid"]:
            return res.mark("error", "invalid CEP format")
        res.attr("valid", True)
        res.attr("validity_note", CEP_WORDING)
        res.attr("formatted_value", info["formatted"])
        res.attr("cep_uf_hint", info["uf_hint"])
        res.raw = {"cep": info}
        return res

    @staticmethod
    def _pix_key(entity: Entity, res: ModuleResult) -> ModuleResult:
        kt = pix_key_type(entity.value)
        if kt is None:
            return res.mark("error", "not a PIX key")
        res.attr("valid", True)
        res.attr("pix_key_type", kt)
        res.attr("validity_note", "PIX key format valid (format only; no DICT lookup: the holder is never resolved)")
        res.raw = {"pix_key": {"type": kt}}
        return res

    # ------------------------------------------------------------------ text (BR rule set)
    def _text(self, entity: Entity, res: ModuleResult) -> ModuleResult:
        text = entity.value[:MAX_TEXT_CHARS]
        found = extract_br_entities(text)
        if not found:
            return res  # nothing passed the checksum gates: EMPTY
        counts: dict[str, int] = {}
        for item in found:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
            self._pivot(res, item)
        listed = [_entity_summary(item) for item in found[:MAX_LISTED]]
        res.attr("br_entities", listed)
        summary = ", ".join(f"{n} {t}" for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
        res.finding(
            "Brazilian identifiers found in text",
            "info",
            f"{len(found)} entities passed the BR rule set (checksum-gated): {summary}.",
            data={"counts": counts},
            tags=["info"],
        )
        cpfs = counts.get("cpf", 0) + counts.get("masked_cpf", 0)
        if cpfs:
            res.finding(
                "CPF in the text (masked, not pivoted)",
                "info",
                "CPFs are validated offline only, shown masked and never pivoted or looked up (rule 4, LGPD); masked CPFs are never completed.",
                data={"cpf": counts.get("cpf", 0), "masked_cpf": counts.get("masked_cpf", 0)},
                tags=["info", "privacy"],
            )
        res.raw = {"br_entities": listed, "counts": counts}
        return res

    @staticmethod
    def _pivot(res: ModuleResult, item: dict[str, Any]) -> None:
        etype = item["type"]
        conf = float(item.get("confidence") or 0.5)
        if etype in _PIVOT_TYPES:
            target, note = _PIVOT_TYPES[etype]
            res.pivot(target, item["value"], "mentions", confidence=conf, expand=False, note=note)
        elif etype == "pix_key":
            target = _PIX_KEY_PIVOTS.get(str(item.get("key_type") or ""))
            if target is not None:  # a CPF key is never pivoted (rule 4)
                note = OTHER_NOTE if target is T.CNPJ else PERSONAL_NOTE
                res.pivot(target, item["value"], "mentions", confidence=conf, expand=False, note=note)
        elif etype == "brcode" and item.get("crc_ok") and item.get("key_type") != "cpf":
            res.pivot(T.PIX_BRCODE, item["value"], "mentions", confidence=conf, expand=False, note=PERSONAL_NOTE)
        # cpf / masked_cpf / cnj: never pivots (cpf: rule 4; cnj: no entity type)
