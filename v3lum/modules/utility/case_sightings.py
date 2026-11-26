"""Cross-case sightings from the V3LUM case database (P375): 'seen in N previous cases'.

Offline lookup (disclosure 'none', allowed at TLP:RED) in the local case DB through the lookup the
application installs on the runtime - ``ctx.runtime.meta['sightings_lookup']`` =
``Store.sightings_for(entity, *, case_id, case_tlp)`` (WP13 App, the same callable the policy's
hostile-host guard reads). Without it the module ends UNAVAILABLE 'offline' ('case DB not
available'). The engine schedules it first among the passive runs of every entity (A12).

* IOC types are looked up by value; personal identifiers (PERSONAL_TYPES) only when setting
  ``sightings_personal`` is on and the case has a recorded purpose (A4/A8), and then by their keyed
  HMAC only. Noise entities and own org assets are not looked up (they are never indexed).
* TLP (A2): the lookup runs with the entity's TLP, so only cases with TLP <= it are listed; higher
  AMBER/AMBER+STRICT cases are only counted ('restricted'), RED and LIGHT/ACTIVE engagement cases
  above it never surface.
* Output: attribute ``sightings`` = ``{count, last, verdict, restricted, verdicts}`` (no case ids:
  stored cases and exports never carry cross-case references) and one info finding
  'seen in N previous cases, last <date>, verdict: <v>' (criterion 'case DB sighting', key
  'sightings'). Findings of other cases are never copied. Rule ``recurrent_infrastructure``
  (v3lum/correlations/sightings.py) reads the attribute.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any

from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, Entity
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

#: Key of the lookup callable in ``runtime.meta`` (installed by the application, WP13).
LOOKUP_KEY = "sightings_lookup"
#: Reason shown when no case DB lookup is installed (UNAVAILABLE 'offline').
NO_CASE_DB = "case DB not available"
#: Criterion and key of the one finding this module emits.
CRITERION = "case DB sighting"
FINDING_KEY = "sightings"


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def call_lookup(lookup: Callable[..., Any], entity: Entity, *, case_id: str, case_tlp: str) -> Any:
    """Call the installed lookup with ``case_id=`` / ``case_tlp=`` when it declares them (the
    protocol of the policy guard); a lookup without a TLP parameter cannot filter, so its answer is
    trusted only as far as it goes."""
    try:
        params = inspect.signature(lookup).parameters
    except (TypeError, ValueError):
        params = {}
    kwargs: dict[str, Any] = {}
    if "case_id" in params:
        kwargs["case_id"] = case_id
    if "case_tlp" in params:
        kwargs["case_tlp"] = case_tlp
    return lookup(entity, **kwargs)


def summary_parts(summary: Any) -> tuple[list[Mapping[str, Any]], int]:
    """(visible rows, restricted count) of a SightingsSummary or an equivalent mapping."""
    if isinstance(summary, Mapping):
        rows, restricted = summary.get("visible"), summary.get("restricted_count")
    else:
        rows, restricted = getattr(summary, "visible", None), getattr(summary, "restricted_count", 0)
    visible = [r for r in rows or () if isinstance(r, Mapping)]
    try:
        count = max(0, int(restricted or 0))
    except (TypeError, ValueError):
        count = 0
    return visible, count


@register
class CaseSightings(Module):
    name = "case_sightings"
    title = "Case-DB sightings"
    description = (
        "Earlier V3LUM cases in which the same indicator appeared (local case DB, TLP-filtered): "
        "'seen in N previous cases, last <date>, verdict: <v>'. Never copies findings across cases."
    )
    category = "utility"
    accepts = frozenset(IOC_TYPES | PERSONAL_TYPES)
    produces = frozenset()
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    tags = {"offline", "core"}
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """IOC types always; personal identifiers only with setting sightings_personal and a recorded
        purpose (A4). Noise entities and own org assets are never indexed, so never looked up."""
        if entity.type in PERSONAL_TYPES:
            if not (_truthy(ctx.setting("sightings_personal", False)) and str(ctx.purpose or "").strip()):
                return False
        elif entity.type not in IOC_TYPES:
            return False
        try:
            from v3lum.core import noise

            if noise.is_noise(entity) or noise.warninglists(entity):
                return False
        except Exception:  # noqa: BLE001 - an unusable list never blocks the lookup
            pass
        org = getattr(ctx, "org", None)
        try:
            if org is not None and getattr(org.owns(entity), "own", False):
                return False
        except Exception:  # noqa: BLE001
            pass
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        meta = getattr(ctx.runtime, "meta", None)
        lookup = meta.get(LOOKUP_KEY) if isinstance(meta, Mapping) else None
        if not callable(lookup):
            return res.mark("unavailable", NO_CASE_DB, reason_code="offline")
        try:
            summary = call_lookup(lookup, entity, case_id=str(ctx.case_id or ""), case_tlp=str(ctx.tlp or ""))
        except Exception as exc:  # noqa: BLE001 - a broken case DB means could not verify (rule 5)
            return res.mark("error", f"case DB lookup failed: {type(exc).__name__}")
        if summary is None:
            return res.mark("unavailable", NO_CASE_DB, reason_code="offline")
        visible, restricted = summary_parts(summary)
        if not visible and not restricted:
            return res  # never seen in an earlier case the entity's TLP may see (EMPTY)
        attribute = _attribute(summary, visible, restricted)
        res.attr("sightings", attribute)
        title, description = _texts(attribute)
        res.finding(
            title,
            "info",
            description,
            confidence="confirmed",
            criterion=CRITERION,
            data=dict(attribute),
            tags=["info"],
            key=FINDING_KEY,
        )
        return res


def _attribute(summary: Any, visible: list[Mapping[str, Any]], restricted: int) -> dict[str, Any]:
    builder = getattr(summary, "attribute", None)
    if callable(builder):
        data = builder()
        if isinstance(data, Mapping):
            return dict(data)
    rows = sorted(visible, key=lambda r: (str(r.get("created") or ""), str(r.get("case_id") or "")), reverse=True)
    verdict = next((str(r.get("verdict")) for r in rows if r.get("verdict")), "")
    verdicts: dict[str, int] = {}
    for r in rows:
        if r.get("verdict"):
            verdicts[str(r["verdict"])] = verdicts.get(str(r["verdict"]), 0) + 1
    last = max((str(r.get("created") or "")[:10] for r in rows if r.get("created")), default="")
    return {"count": len(rows), "last": last, "verdict": verdict, "restricted": restricted, "verdicts": dict(sorted(verdicts.items()))}


def _texts(attribute: Mapping[str, Any]) -> tuple[str, str]:
    """(finding title, description) of a sightings attribute (P375 cond 6: one line)."""
    count, restricted = int(attribute.get("count") or 0), int(attribute.get("restricted") or 0)
    if count:
        title = (
            f"seen in {count} previous case{'s' if count != 1 else ''}, last {attribute.get('last') or 'unknown'}, "
            f"verdict: {attribute.get('verdict') or 'none'}"
        )
        description = "Earlier V3LUM cases with the same indicator (local case DB; only cases with a TLP not above this one are listed)."
        if restricted:
            description += f" Also seen in {restricted} restricted case{'s' if restricted != 1 else ''} (higher TLP: no ids, dates or verdicts)."
    else:
        title = f"seen in {restricted} restricted case{'s' if restricted != 1 else ''}"
        description = "Earlier V3LUM cases with a higher TLP contain the same indicator: they are counted only (no ids, dates or verdicts, A2)."
    description += " Open them with `v3lum cases list --search` at the right TLP; findings are never copied across cases."
    return title, description
