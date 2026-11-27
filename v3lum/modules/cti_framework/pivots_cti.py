"""pivots_cti: MITRE ATT&CK, Malpedia and D3FEND reference pages, manual links only (P300, batch p2-G14-2).

Disclosure ``none``: the module only builds URLs; V3LUM never requests these pages (P300 cond 1). The pack is
``v3lum/data/pivot_links/cti.json``: ``cti:d3fend_technique`` is a core pack link (rendered by the engine and
``v3lum links``); the ATT&CK and Malpedia pages are ``x_module_links`` rendered here because they need a value
transformation the frozen core placeholders cannot express:

* cond 8 - ``attack.mitre.org/techniques/{mitre_path}/``: the technique id is validated
  (``attack_index.normalise_attack_id``, techniques only) and the sub-technique dot becomes a slash
  (T1059.001 -> T1059/001; the dotted path answers 404). A revoked id links its replacement
  (``v3lum.core.attack.canonical``, T1656 -> T1684.001) and the label says 'revoked -> replaced by'. Group and
  software pages use the G id (threat_actor) or S id (malware_family) of the P295 alias index
  (``actor_alias_index.resolve``; the index carries the P292 ATT&CK ids): an umbrella cluster, several ids or an
  ambiguous name give no link.
* cond 9 - Malpedia pages use the id the P295 alias index holds (galaxy refs), never the raw name: families
  ``/details/<platform>.<name>``, actors ``/actor/<id>`` (``/details/apt28`` answers 404, so actors use
  ``/actor/``). No id or several ids: no link.
* cond 10 - D3FEND ``/offensive-technique/attack/{id}/`` for mitre_technique entities (core pack link).
* A2 - at TLP:AMBER and above every label carries 'opening sends <value> to <host>'; at RED nothing is emitted.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core import attack as _attack
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_pack_render as pr

PACK = "cti"
_TECHNIQUE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$")
_MALPEDIA_FAMILY = re.compile(r"^[a-z0-9]+\.[a-z0-9_]{1,80}$")
_MALPEDIA_ACTOR = re.compile(r"^[a-z0-9][a-z0-9_]{0,80}$")


def technique_id(value: Any) -> str | None:
    """Canonical ATT&CK technique id ('T1059' / 'T1059.001') from 't1059.001', 'T1059/001'...; None for
    anything else (tactics, mitigations, groups, malformed values)."""
    try:
        from v3lum.modules.cti_framework.attack_index import normalise_attack_id
    except ImportError:  # pragma: no cover - the ATT&CK index ships with the core modules
        normalise_attack_id = None
    if not isinstance(value, str) or any(c.isspace() for c in value.strip()) or re.search(r"[\x00-\x1f]", value):
        return None
    tid = normalise_attack_id(value.strip()) if normalise_attack_id else value.strip().upper()
    return tid if tid and _TECHNIQUE.match(tid) else None


def mitre_path(value: Any) -> str | None:
    """``{mitre_path}``: T1059.001 -> 'T1059/001', T1059 -> 'T1059'; None when not a technique id."""
    tid = technique_id(value)
    return tid.replace(".", "/") if tid else None


def replacement(tid: str) -> str:
    """The usable replacement of a revoked technique id ('' when not revoked or unknown)."""
    try:
        canonical = _attack.canonical(tid)
    except Exception:  # noqa: BLE001 - the bundled ATT&CK index is optional data here
        return ""
    return canonical if canonical != tid and _TECHNIQUE.match(canonical or "") else ""


def alias_ids(value: str, namespace: str) -> tuple[list[str], list[str], str]:
    """(ATT&CK ids, Malpedia ids, note) of the unambiguous, non-umbrella P295 cards of ``value`` in
    ``namespace`` ('actor' or 'malware'). Raises LookupError when the alias index is unusable."""
    from v3lum.modules.cti_framework import actor_alias_index as aai

    res = aai.resolve(value)
    if res is None:
        raise LookupError("the P295 alias index is unusable")
    cards = aai.namespace_cards(res, namespace)
    if not cards:
        status = str(res.get("status") or "")
        return [], [], "ambiguous name: no link" if status == "ambiguous" else "not in the alias index"
    if any(card.get("umbrella") for card in cards):
        return [], [], "umbrella name (several clusters): no link"
    prefix = "G" if namespace == "actor" else "S"
    mitre = sorted({m for card in cards for m in card.get("mitre_ids") or [] if isinstance(m, str) and m.startswith(prefix)})
    malpedia = sorted({m for card in cards for m in card.get("malpedia_ids") or [] if isinstance(m, str)})
    return mitre, malpedia, f"resolved to {', '.join(sorted({str(c.get('canonical')) for c in cards}))}"


def malpedia_value(ids: list[str], namespace: str) -> str | None:
    """The single Malpedia id of the namespace (actors carry the index's 'actor:' prefix); None otherwise."""
    if namespace == "actor":
        found = [i.split(":", 1)[1] for i in ids if i.startswith("actor:")]
        found = [i for i in found if _MALPEDIA_ACTOR.match(i)]
    else:
        found = [i for i in ids if not i.startswith("actor:") and _MALPEDIA_FAMILY.match(i)]
    return found[0] if len(found) == 1 else None


@register
class PivotsCti(Module):
    name = "pivots_cti"
    title = "ATT&CK, Malpedia and D3FEND reference pages (manual links)"
    description = (
        "Manual reference links: the ATT&CK technique page ({mitre_path}: T1059.001 -> /techniques/T1059/001/), the "
        "ATT&CK group/software page and the Malpedia actor/family page from the ids of the P295 alias index (never the "
        "raw name). D3FEND technique pages come from the cti pack. V3LUM never fetches them."
    )
    category = "cti_framework"
    accepts = {T.MITRE, T.THREAT_ACTOR, T.MALWARE}
    produces = frozenset()
    reference = "https://attack.mitre.org/"
    tags = {"offline"}
    notice = (
        "Manual links only (never fetched). Actor and malware names resolve through the alias index: vendor "
        "assessments, not identity; umbrella or ambiguous names get no link. Manual Malpedia browsing is unaffected by "
        "its API's CC BY-NC-SA licence."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 10.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        level = pr.tlp_level(ctx)
        red = pr.hidden_reason(None, level)
        if red:
            return res.mark(Status.SKIPPED, red, reason_code="tlp")
        found = pr.module_links(PACK)
        shown: list[dict[str, Any]] = []
        hidden: list[dict[str, str]] = []
        note = ""

        def add(link_id: str, values: dict[str, str], label_note: str = "") -> None:
            ml = found.get(link_id)
            rendered = pr.render(ml, entity, values) if ml is not None else None
            if rendered is None:
                hidden.append({"id": link_id, "reason": "did not render (lint, tier or value)"})
            else:
                sent = next(iter(values.values()), "")
                shown.append(pr.emit(res, entity, level, rendered, ml=ml, note=label_note, sent=sent))

        if entity.type is T.MITRE:
            tid = technique_id(entity.value)
            if tid is None:
                note = "not an ATT&CK technique id (tactic, mitigation or data source): no technique page"
            else:
                target = replacement(tid)
                label_note = f"revoked -> replaced by {target}" if target else tid
                add("attack_technique", {"mitre_path": (target or tid).replace(".", "/")}, label_note)
        else:
            namespace = "actor" if entity.type is T.THREAT_ACTOR else "malware"
            try:
                mitre, malpedia, note = alias_ids(entity.value, namespace)
            except (LookupError, ImportError) as exc:
                res.raw = {"tlp": level.value_str, "links": [], "hidden": []}
                return res.mark(Status.UNAVAILABLE, f"alias index unavailable: {exc}", reason_code="dataset")
            attack_link = "attack_group" if namespace == "actor" else "attack_software"
            if len(mitre) == 1:
                add(attack_link, {"attack_id": mitre[0]}, mitre[0])
            elif mitre:
                hidden.append({"id": attack_link, "reason": f"several ATT&CK ids ({', '.join(mitre)}): no link"})
            malp = malpedia_value(malpedia, namespace)
            malp_link = "malpedia_actor" if namespace == "actor" else "malpedia_family"
            if malp:
                add(malp_link, {"malpedia_id": malp}, malp)
            elif malpedia:
                hidden.append({"id": malp_link, "reason": "no single Malpedia id: no link"})
        res.raw = {"tlp": level.value_str, "note": note, "links": shown, "hidden": hidden}
        if not shown:
            return res.mark(Status.EMPTY, note) if note else res.mark(Status.EMPTY)
        return res
