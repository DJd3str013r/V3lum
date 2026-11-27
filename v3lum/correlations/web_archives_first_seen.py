"""Combined first-seen date of a domain (P059 cond 8, batch p1-G01-2).

``first_seen = min(RDAP created, first CT not_before, first archive capture)``: the rule reads the graph
attributes ``created`` (RDAP, P003), ``first_cert_seen`` (CT logs, P001) and ``archive_first``
(web_archives / web_archives_deep, P059) and reports the earliest date with the source that gave it.
It fires only when at least two of those facts exist (one fact alone is already shown by its module).
An archive capture is a lower bound of web presence, never a registration date, and the absence of
captures never makes a domain 'new'. The rule makes no network call and changes nothing.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_ID = "web_archives_first_seen"
#: graph attribute -> what it measures
INPUTS: tuple[tuple[str, str], ...] = (
    ("created", "RDAP registration date"),
    ("first_cert_seen", "first CT certificate (not_before)"),
    ("archive_first", "first web-archive capture"),
)


def _parse(value: Any) -> datetime | None:
    """ISO date/datetime (or a 4-14 digit Wayback timestamp) -> aware UTC datetime; None for junk."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.isdigit() and 4 <= len(text) <= 14 and len(text) % 2 == 0:
        text = (text + "0101000000"[len(text) - 4:])[:14] if len(text) < 14 else text
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def first_seen(values: dict[str, Iterable[Any]]) -> tuple[str, datetime, dict[str, datetime]] | None:
    """(winning attribute, earliest datetime, earliest per attribute) or None when nothing parses."""
    earliest: dict[str, datetime] = {}
    for attr, items in values.items():
        dates = [d for d in (_parse(v) for v in items) if d is not None and d.year >= 1985]
        if dates:
            earliest[attr] = min(dates)
    if not earliest:
        return None
    winner = min(earliest, key=lambda k: earliest[k])
    return winner, earliest[winner], earliest


@rule(
    RULE_ID,
    "Combined first-seen date (RDAP, CT, web archives)",
    "first_seen = min(RDAP created, first CT not_before, first archive capture) for a domain with at least two of those facts.",
    severity="info",
    criterion="earliest of RDAP created, first CT certificate not_before and first archive capture (P059 cond 8)",
    false_positives="Archive captures and certificates can predate a re-registration of the same name (dropped and re-registered domains).",
)
def web_archives_first_seen(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    for node in graph.of_type(EntityType.DOMAIN):
        values = {attr: node.attr_values(attr) for attr, _label in INPUTS}
        found = first_seen(values)
        if found is None:
            continue
        winner, when, per_attr = found
        if len(per_attr) < 2:
            continue
        labels = dict(INPUTS)
        evidence = [f"{labels[a]}: {per_attr[a].strftime('%Y-%m-%d')}" for a, _label in INPUTS if a in per_attr]
        note = ""
        if "created" in per_attr and when < per_attr["created"]:
            note = " The name was on the web (or certified) before its current registration date: probably re-registered."
        yield Correlation(
            rule=RULE_ID,
            title="Combined first-seen date",
            severity=Severity.INFO,
            description=(
                f"{node.entity.display} was first seen on {when.strftime('%Y-%m-%d')} ({labels[winner]}). Archive captures are a "
                "lower bound of web presence, never a registration date, and missing captures never make a domain new." + note
            ),
            entities=[node.entity],
            confidence="probable",
            evidence=evidence,
            recommendation="Use the earliest date as the domain's first-seen; read a capture or certificate older than the "
            "registration as a sign of a re-registered (dropped) name.",
            tags=["info"],
            criterion="min(RDAP created, first CT not_before, first archive capture)",
            key=node.key,
        )
