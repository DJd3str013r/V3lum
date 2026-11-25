"""Manual pivot links: web tools without an API, pre-filled with the entity.

Templates live in ``v3lum/data/pivot_links/*.json`` (one file per area) and optionally
``v3lum/data/pivot_links.json``. Each file holds a list (or ``{"links": [...]}``) of
``{"name", "category", "types": [entity types], "url": "...{q}...", "description", "source"}``.
Placeholders: ``{q}`` URL-encoded value, ``{qp}`` quote_plus value, ``{raw}`` raw value,
``{domain}`` email domain / URL host / the domain itself, ``{user}`` email local part.
"""

from __future__ import annotations

import functools
import json
from importlib import resources
from typing import Any
from urllib.parse import quote, quote_plus

from v3lum.core.entities import Entity, EntityType, url_host


def _load_items(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    items = data.get("links", data) if isinstance(data, dict) else data
    return [t for t in items if isinstance(t, dict) and t.get("url") and t.get("types")] if isinstance(items, list) else []


@functools.lru_cache(maxsize=1)
def templates() -> list[dict[str, Any]]:
    root = resources.files("v3lum.data")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    sources = []
    single = root.joinpath("pivot_links.json")
    if single.is_file():
        sources.append(single)
    folder = root.joinpath("pivot_links")
    if folder.is_dir():
        sources.extend(sorted((p for p in folder.iterdir() if p.name.endswith(".json")), key=lambda p: p.name))
    for src in sources:
        for item in _load_items(src.read_text(encoding="utf-8")):
            sig = f"{item['url']}|{','.join(sorted(item['types']))}"
            if sig not in seen:
                seen.add(sig)
                out.append(item)
    return out


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
