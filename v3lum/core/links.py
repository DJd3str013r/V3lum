"""Manual pivot links: web tools without an API, pre-filled with the entity.

Templates live in ``v3lum/data/pivot_links.json`` as a list of
``{"name", "category", "types": [entity types], "url": "...{q}...", "description", "source"}``.
Placeholders: ``{q}`` URL-encoded value, ``{qp}`` quote_plus value, ``{raw}`` raw value,
``{domain}`` email domain / URL host / the domain itself, ``{user}`` email local part.
"""

from __future__ import annotations

import functools
from typing import Any
from urllib.parse import quote, quote_plus

from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity, EntityType, url_host


@functools.lru_cache(maxsize=1)
def templates() -> list[dict[str, Any]]:
    if not DataStore.bundled_exists("pivot_links.json"):
        return []
    data = DataStore.bundled_json("pivot_links.json")
    items = data.get("links", data) if isinstance(data, dict) else data
    return [t for t in items if isinstance(t, dict) and t.get("url") and t.get("types")]


def _fill(template: str, entity: Entity) -> str:
    value = entity.value
    domain = value
    user = value
    if entity.type is EntityType.EMAIL:
        user, domain = value.split("@", 1)
    elif entity.type is EntityType.URL:
        domain = url_host(value)
    return template.format(
        q=quote(value, safe=""),
        qp=quote_plus(value),
        raw=value,
        domain=quote(domain, safe=""),
        user=quote(user, safe=""),
    )


def links_for(entity: Entity, categories: set[str] | None = None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for t in templates():
        if entity.type.value not in t.get("types", []):
            continue
        if categories and t.get("category") not in categories:
            continue
        try:
            out.append((str(t.get("name")), _fill(str(t["url"]), entity)))
        except (KeyError, IndexError, ValueError):
            continue
    return out
