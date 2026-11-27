"""Correlation rules of batch p1-G06-1 (phone): DDD region vs CPF fiscal region, CEP UF and address UF.

P126 FC5: a phone whose DDD region (attribute ``phone_ddd.ufs``, from the bundled Anatel table) shares no
state with a directly linked CPF's fiscal region (9th digit, ``validators.cpf_region``, offline), CEP or
company address UF (attribute ``region`` of the linked CEP/CNPJ node) is a WEAK consistency signal:
people move and keep their numbers, numbers are ported and companies use numbers of other DDDs. The
rule says so in every correlation: severity info, confidence POSSIBLE, tags ``weak_signal`` and
``context_only`` - never a fraud verdict and never scored. Linked = a direct edge between the phone and
the other entity, or both linked to the same parent (e.g. a company with its phone and its CEP).
Multi-state DDDs (61: DF and GO) count as consistent with any of their states. The CPF is shown masked.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity
from v3lum.core.validators import cpf_region

RULE_ID = "phone_ddd_region_consistency"
UFS = frozenset({
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI",
    "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO",
})
#: Linked entity types and the label of the comparison.
KINDS: dict[EntityType, str] = {EntityType.CPF: "CPF fiscal region", EntityType.CEP: "CEP state", EntityType.CNPJ: "company address state"}
WEAK = "weak consistency signal (people move, numbers are ported): never evidence of fraud"


def phone_ufs(node: Node) -> set[str]:
    """States of the phone's DDD from ``phone_ddd`` (phone_parse)."""
    out: set[str] = set()
    for value, _src in node.attributes.get("phone_ddd", []):
        if isinstance(value, dict):
            out.update(u for u in value.get("ufs") or [] if isinstance(u, str) and u in UFS)
    return out


def other_ufs(node: Node) -> set[str]:
    """States of a linked CPF (fiscal region of its 9th digit) or CEP/CNPJ node (attribute ``region``)."""
    if node.entity.type is EntityType.CPF:
        return {u.strip() for u in cpf_region(node.entity.value).split(",") if u.strip() in UFS}
    return {str(v).strip().upper() for v, _src in node.attributes.get("region", []) if isinstance(v, str) and v.strip().upper() in UFS}


def linked(graph: Graph, phone: Node) -> list[Node]:
    """CPF/CEP/CNPJ nodes linked to ``phone`` directly or through one shared parent (noise nodes skipped)."""
    seen: dict[str, Node] = {}
    for near in graph.neighbors(phone.key, direction="both"):
        if near.noise:
            continue
        if near.entity.type in KINDS:
            seen.setdefault(near.key, near)
        for far in graph.neighbors(near.key, direction="both"):
            if far.key != phone.key and not far.noise and far.entity.type in KINDS:
                seen.setdefault(far.key, far)
    return [seen[k] for k in sorted(seen)]


@rule(
    RULE_ID,
    "Phone DDD region differs from a linked CPF, CEP or address state (weak signal)",
    "A phone whose DDD states share none with the fiscal region of a linked CPF, a linked CEP's state or a linked "
    "company's address state. People move and keep their numbers and numbers are ported: context only, never a "
    "fraud verdict (P126 cond 5).",
    version="1",
    severity="info",
    criterion="phone_ddd.ufs (bundled Anatel DDD table) has no state in common with the CPF fiscal region (9th digit) "
    "or the 'region' state of a CEP/CNPJ node linked directly or through one shared parent",
    false_positives="Expected whenever someone moved, kept an old number, uses a ported or corporate number, or a "
    "company uses a call-centre number of another DDD.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_ID}/positive_cpf_region_differs.json",
        f"tests/fixtures/rules/{RULE_ID}/positive_company_and_cep_differ.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_same_state.json",
        f"tests/fixtures/rules/{RULE_ID}/negative_multi_state_ddd_and_unlinked.json",
    ),
)
def phone_ddd_region_consistency(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for phone in graph.of_type(EntityType.PHONE):
        if phone.noise:
            continue
        ddd_states = phone_ufs(phone)
        if not ddd_states:
            continue
        for other in linked(graph, phone):
            states = other_ufs(other)
            if not states or ddd_states & states:
                continue
            kind = KINDS[other.entity.type]
            ddd = ", ".join(sorted(ddd_states))
            theirs = ", ".join(sorted(states))
            yield Correlation(
                rule=RULE_ID,
                title=f"Phone DDD region differs from the linked {kind}",
                severity=Severity.INFO,
                description=(
                    f"The DDD of {phone.entity.display} is in {ddd}; the linked {other.entity.display} points to {theirs}. "
                    f"This is a {WEAK}."
                ),
                entities=[phone.entity, other.entity],
                confidence="possible",
                evidence=[f"DDD states: {ddd}", f"{kind}: {theirs}"],
                recommendation="Context only: do not read it as fraud or identity evidence; ask how the number is used when it matters.",
                tags=["weak_signal", "context_only"],
                criterion="DDD states share none with the linked entity's state(s); " + WEAK,
                key=f"{other.entity.type.value}:{hashlib.sha256(other.key.encode()).hexdigest()[:16]}",  # never the raw CPF
            )
