"""Correlation rules of batch p1-G10-2 (Brazilian company registry and sanctions).

``g10_homonym_name_match`` (P252 cond 1): every name-only match (a finding tagged ``name_only_match`` or
with ``data['match_type'] == 'name_only'``) about a person name is lowered by the documented homonym
curve of ``ibge_name_frequency`` (first-name frequency from the offline IBGE ranking, or from the
module's ``first_name_frequency`` attribute on the node; common surnames). It is offline, makes no
request, works at TLP:RED and emits no correlation of its own: the finding is downgraded through the
named rule (``Finding.downgrade``) and its numeric confidence follows the curve. Findings whose module
already applied the curve (``data['homonym_applied']``) and company names are left alone.

``g10_sanction_dedup`` (P239 cond 4, P240 cond 4): findings tagged ``sanctions`` that carry the same
``data['dedup_key']`` = '<list>|<cnpj>|<sanction id>' on one entity are one listing. A finding without
a sanction id (the TCU certificate exposes none) joins the listing of the same list and CNPJ. The
strongest finding stays the finding of record and lists every source; the others become INFO context
(``context_only``, original severity kept in ``data``), so one sanction never inflates the score
(no noisy-OR). One INFO correlation per merged listing documents the merge. Analyst overrides are never
crossed.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Severity
from v3lum.modules.person_name.ibge_name_frequency import apply_homonym_curve, first_name, homonym_risk, offline_table

RULE_HOMONYM = "g10_homonym_name_match"
RULE_DEDUP = "g10_sanction_dedup"


# --------------------------------------------------------------------------------------
# homonym score of name-only matches (P252)
# --------------------------------------------------------------------------------------


def _name_only(f: Finding) -> bool:
    data = f.data if isinstance(f.data, dict) else {}
    return "name_only_match" in (f.tags or ()) or data.get("match_type") == "name_only"


def _subject_name(node: Any, f: Finding) -> str | None:
    data = f.data if isinstance(f.data, dict) else {}
    if data.get("name_type") == "company_name":
        return None
    if node.entity.type is EntityType.PERSON:
        return str(node.entity.value)
    if data.get("name_type") == "person_name":
        name = data.get("query_name") or data.get("matched_name")
        return str(name) if isinstance(name, str) and name.strip() else None
    return None


def _node_frequency(node: Any, name: str) -> int | None:
    """First-name frequency recorded on the node by ibge_name_frequency (online lookup), when it is the
    same first name."""
    fn = first_name(name)
    for value, _source in node.attributes.get("first_name_frequency", []) or []:
        if isinstance(value, dict) and value.get("first_name") == fn and isinstance(value.get("frequency"), int):
            return int(value["frequency"])
    return None


@rule(
    RULE_HOMONYM,
    "Homonym risk lowers name-only matches",
    "A name-only match about a person is lowered by the homonym curve (IBGE first-name frequency, common surnames): "
    "very common names make name-only matches unreliable. No correlation is emitted; the finding is downgraded.",
    version="1",
    severity="info",
    criterion="finding tagged name_only_match (or data.match_type name_only) about a person name, homonym curve of P252",
    false_positives="None by design: the rule only lowers confidence; a rare name keeps its confidence.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_HOMONYM}/positive_common_name_lowered.json",
        f"tests/fixtures/rules/{RULE_HOMONYM}/negative_identifier_match.json",
    ),
)
def homonym_name_match(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    table: dict[str, int] | None = None
    for node in graph.nodes.values():
        for f in node.findings:
            if not _name_only(f):
                continue
            data = f.data if isinstance(f.data, dict) else None
            if data is None or data.get("homonym_applied") or any(s.get("rule") == RULE_HOMONYM for s in f.suppressed_by):
                continue
            name = _subject_name(node, f)
            if not name:
                continue
            if table is None:
                table = offline_table()
            h = homonym_risk(name, frequency=_node_frequency(node, name), table=table)
            data["homonym"] = {k: h[k] for k in ("risk", "factor", "phrase")}
            data["homonym_applied"] = True
            new = apply_homonym_curve(f.confidence, h)
            if new >= float(f.confidence):
                continue
            f.downgrade(RULE_HOMONYM, h["phrase"], to=Confidence.from_value(new))
            if not f.override:
                f.confidence = min(float(f.confidence), new)
    return []


# --------------------------------------------------------------------------------------
# one sanction = one finding (P239 / P240 cond 4)
# --------------------------------------------------------------------------------------

#: finding of record among equal-severity duplicates: the bulk file (sanction id, dates) first
_MODULE_ORDER = {"cgu_sanctions_bulk": 0, "portal_transparencia_api": 1, "tcu_certidoes": 2}


def _key_parts(f: Finding) -> tuple[str, str, str] | None:
    data = f.data if isinstance(f.data, dict) else {}
    key = data.get("dedup_key")
    if not isinstance(key, str) or "sanctions" not in (f.tags or ()):
        return None
    parts = key.split("|")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1], parts[2]


@rule(
    RULE_DEDUP,
    "One sanction listing reported by several sources",
    "Sanction findings with the same (list, CNPJ, sanction id) on one entity are one listing: the strongest finding is "
    "kept and lists every source, the others become INFO context so the score is not inflated.",
    version="1",
    severity="info",
    criterion="two or more sanctions findings sharing data.dedup_key '<list>|<cnpj>|<sanction id>' (a key without sanction id "
    "joins the listing of the same list and CNPJ)",
    false_positives="Two different sanctions of the same list without ids would merge; the bulk file always carries the id.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_DEDUP}/positive_bulk_file_and_tcu_certificate.json",
        f"tests/fixtures/rules/{RULE_DEDUP}/negative_different_lists.json",
    ),
)
def sanction_dedup(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.nodes.values():
        groups: dict[tuple[str, str], list[tuple[str, Finding]]] = {}
        for f in node.findings:
            parts = _key_parts(f)
            if parts is not None:
                groups.setdefault((parts[0], parts[1]), []).append((parts[2], f))
        for (lst, cnpj), items in sorted(groups.items()):
            by_id: dict[str, list[Finding]] = {}
            for sid, f in items:
                if sid:
                    by_id.setdefault(sid, []).append(f)
            no_id = [f for sid, f in items if not sid]
            clusters = [by_id[k] for k in sorted(by_id)]
            if no_id:
                if clusters:
                    clusters[0] = clusters[0] + no_id
                else:
                    clusters.append(no_id)
            for members in clusters:
                if len(members) < 2:
                    continue
                primary = max(members, key=lambda f: (int(f.severity), bool((_key_parts(f) or ("", "", ""))[2]),
                                                      -_MODULE_ORDER.get(f.module, 9)))
                merged = []
                for f in members:
                    if f is primary or f.override:
                        continue
                    if any(s.get("rule") == RULE_DEDUP for s in f.suppressed_by):
                        merged.append(f)  # merged by an earlier run (a reloaded case): counted, never lowered twice
                        continue
                    before = f.severity.label
                    f.downgrade(RULE_DEDUP, f"same listing as the {primary.module} finding {primary.id}: one sanction, several sources")
                    f.data["merged_into"] = primary.id
                    f.data["severity_before_merge"] = before
                    f.severity = Severity.INFO
                    if "context_only" not in f.tags:
                        f.tags.append("context_only")
                    merged.append(f)
                if not merged:
                    continue
                sources = sorted({m.module or m.source for m in members if m.module or m.source})
                if isinstance(primary.data, dict):
                    primary.data["sources"] = sorted(set(primary.data.get("sources") or []) | set(sources))
                sid = (_key_parts(primary) or ("", "", ""))[2]
                yield Correlation(
                    rule=RULE_DEDUP,
                    title=f"One {lst.upper()} listing reported by {len(members)} sources",
                    severity=Severity.INFO,
                    description=f"{', '.join(sources)} report the same {lst.upper()} listing of {node.entity.display}"
                    + (f" (sanction {sid})" if sid else "") + f": the finding of record is '{primary.title}' ({primary.module}); "
                    "the other reports are kept as context and not scored again.",
                    entities=[node.entity],
                    confidence="confirmed",
                    evidence=[m.id for m in members],
                    recommendation="Read the finding of record; the other sources confirm the same listing.",
                    tags=["sanctions"],
                    criterion=f"findings sharing the dedup key {lst}|{cnpj}|{sid}",
                    key=f"{lst}|{cnpj}|{sid}",
                )


__all__ = ["RULE_DEDUP", "RULE_HOMONYM", "homonym_name_match", "sanction_dedup"]
