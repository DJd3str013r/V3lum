"""P252 ``ibge_name_frequency`` - IBGE first-name frequency and the homonym score of name-only matches.

Council P252 final conditions, as implemented here:

1. The homonym score is a shared, offline helper (``homonym_risk`` / ``apply_homonym_curve`` below,
   the stand-in for ``core/namematch.py`` until the core owns it) plus the correlation rule
   ``g10_homonym_name_match`` (``v3lum/correlations/p1_g10_2.py``) that lowers the confidence of every
   name-only match (findings tagged ``name_only_match``) by the documented curve. It emits no findings,
   makes no request and works at TLP:RED.
2. Offline data: the IBGE first-name rankings (national, and per sex for a wider top list; aggregate
   Census statistics, open data with attribution) are datasets fetched by ``v3lum data update`` (never
   bundled), plus ``COMMON_SURNAMES``, a curated list of the most common Brazilian surnames (IBGE covers
   first names only).
3. The online lookup ``censos/nomes/{first_name}`` runs only inside this module, through ``ctx.http``
   and the policy gate: only the normalised first name, only for a name missing from the offline table,
   never at TLP:RED; answers are kept 365 days in ``ctx.state`` (the HTTP cache is capped at 24 h).
4. This module (person seeds) is opt-in (``default_enabled=False``); the helper does not depend on it:
   names missing from the offline table get a neutral 'frequency unknown' score. An empty IBGE answer
   means 'rare/unknown name', never an error.
5. Output: one short phrase ('very common name: name-only matches are unreliable') and the total count;
   the frequency is never used to infer anything about the person (no per-UF origin, sex or age).

The documented curve: first-name factor 0.4 (>= 1,000,000 bearers), 0.6 (>= 100,000), 0.8 (>= 10,000),
1.0 (< 10,000 or an empty IBGE answer), 1.0 (frequency unknown, neutral); x 0.8 when a surname is in
``COMMON_SURNAMES``. Risk: high at factor <= 0.5, medium at <= 0.8, else low ('unknown' when nothing
is known). ``apply_homonym_curve(confidence, h) = confidence x factor``.
"""

from __future__ import annotations

import json
import re
import threading
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.core.context import StateError
from v3lum.core.datasets import DataStore, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "ibge.nomes"
IBGE_URL = "https://servicodados.ibge.gov.br/api/v2/censos/nomes/{name}"
RANKING_URL = "https://servicodados.ibge.gov.br/api/v2/censos/nomes/ranking"
ATTRIBUTION = "IBGE - Instituto Brasileiro de Geografia e Estatistica, Censo Demografico 2010 (API de nomes), open data"
LICENCE = "IBGE open data (free reuse with attribution of the source)"
#: P252 cond 3: online answers are kept 365 days (Census 2010 data never changes)
STATE_TTL_DAYS = 365
STATE_KEY = "first_names"
STATE_MAX_NAMES = 5000

COMMON_SURNAMES = frozenset({
    "SILVA", "SANTOS", "OLIVEIRA", "SOUZA", "SOUSA", "RODRIGUES", "FERREIRA", "ALVES", "PEREIRA", "LIMA", "GOMES", "COSTA", "RIBEIRO",
    "MARTINS", "CARVALHO", "ALMEIDA", "LOPES", "SOARES", "FERNANDES", "VIEIRA", "BARBOSA", "ROCHA", "DIAS", "NASCIMENTO", "ANDRADE",
    "MOREIRA", "NUNES", "MARQUES", "MACHADO", "MENDES", "FREITAS", "CARDOSO", "RAMOS", "GONCALVES", "SANTANA", "TEIXEIRA", "ARAUJO",
    "MELO", "CASTRO", "CAVALCANTE",
})
NAME_PARTICLES = frozenset({"DA", "DE", "DO", "DAS", "DOS", "E", "D"})
HONORIFICS = frozenset({"DR", "DRA", "SR", "SRA", "PROF", "PROFA", "ENG"})
#: P252 cond 4: names missing from the offline table get a neutral factor
UNKNOWN_FACTOR = 1.0
#: (minimum bearers, factor, tier) from the most common down
FIRST_NAME_TIERS = ((1_000_000, 0.4, "very_common"), (100_000, 0.6, "common"), (10_000, 0.8, "moderate"))
COMMON_SURNAME_FACTOR = 0.8
HOMONYM_PHRASES = {
    "high": "very common name: name-only matches are unreliable",
    "medium": "common name: a name-only match needs another identifier",
    "low": "uncommon name",
    "unknown": "name frequency unknown",
}


def _validate_ranking(path: Path) -> bool:
    """A ranking download must be the JSON list of {localidade, res: [{nome, frequencia, ranking}]}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("IBGE ranking: not a non-empty JSON list")
    entries = [x for block in data if isinstance(block, dict) for x in (block.get("res") or []) if isinstance(x, dict)]
    if len(entries) < 5 or not all(isinstance(x.get("nome"), str) and isinstance(x.get("frequencia"), int) for x in entries):
        raise ValueError("IBGE ranking: unexpected entries")
    return True


#: P252 cond 2: the national ranking plus the per-sex rankings (the API returns 20 names per list; the
#: union of the three is the offline first-name table). Only the totals are kept: nothing about sex.
RANKING_DATASETS = {
    "ibge_name_frequency.ranking.json": RANKING_URL,
    "ibge_name_frequency.ranking_f.json": RANKING_URL + "?sexo=F",
    "ibge_name_frequency.ranking_m.json": RANKING_URL + "?sexo=M",
}
for _name, _url in RANKING_DATASETS.items():
    register_dataset(
        _name, _url, ttl=365 * 86400, description="IBGE Census 2010 first-name ranking (top 20, totals only) for the homonym score (P252)",
        licence=LICENCE, terms_class="open", attribution=ATTRIBUTION, provider="ibge", source=SOURCE, validate=_validate_ranking,
        min_bytes=100, expect="json", max_bytes=1_000_000, large=False, essential=True,
    )


# --------------------------------------------------------------------------------------
# the homonym helper (stand-in for core/namematch.py; offline, no request)
# --------------------------------------------------------------------------------------


def fold(text: Any) -> str:
    t = unicodedata.normalize("NFKD", str(text or ""))
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t).strip().upper()


def name_tokens(full_name: Any) -> list[str]:
    return [t for t in re.sub(r"[^A-Z ]", " ", fold(full_name)).split() if t not in HONORIFICS]


def first_name(full_name: Any) -> str | None:
    """The normalised first name: the only part of a name that ever leaves the machine (P252 cond 3)."""
    toks = name_tokens(full_name)
    return toks[0] if toks else None


def homonym_risk(full_name: Any, frequency: int | None = None, table: dict[str, int] | None = None) -> dict[str, Any]:
    """Homonym score of a name for name-only matches (P252 cond 1, 4, 5): the documented curve of the
    module docstring. ``frequency`` (IBGE bearers of the first name; 0 = empty IBGE answer) wins over
    ``table`` (the offline first-name table). Nothing else is inferred about the person."""
    toks = name_tokens(full_name)
    fn = toks[0] if toks else None
    f = frequency
    if f is None and table is not None and fn in table:
        f = table[fn]
    common_surname = any(s in COMMON_SURNAMES for s in toks[1:] if s not in NAME_PARTICLES)
    base, tier = UNKNOWN_FACTOR, "unknown"
    if f is not None:
        base, tier = 1.0, "rare"
        for minimum, factor, label in FIRST_NAME_TIERS:
            if f >= minimum:
                base, tier = factor, label
                break
    factor = round(base * (COMMON_SURNAME_FACTOR if common_surname else 1.0), 3)
    if tier == "unknown" and not common_surname:
        risk = "unknown"
    else:
        risk = "high" if factor <= 0.5 else "medium" if factor <= 0.8 else "low"
    return {"first_name": fn, "first_name_frequency": f, "first_name_tier": tier, "common_surname": common_surname, "factor": factor,
            "risk": risk, "phrase": HOMONYM_PHRASES[risk]}


def apply_homonym_curve(confidence: Any, homonym: dict[str, Any] | None) -> float:
    """Lower a name-only match confidence by the homonym factor (P252 cond 1)."""
    try:
        c = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        return 0.0
    try:
        factor = float((homonym or {}).get("factor", UNKNOWN_FACTOR))
    except (TypeError, ValueError):
        factor = UNKNOWN_FACTOR
    return round(c * max(0.0, min(1.0, factor)), 3)


def parse_ranking(obj: Any) -> dict[str, int]:
    """censos/nomes/ranking -> {NAME: frequency} (national blocks only)."""
    out: dict[str, int] = {}
    for block in obj if isinstance(obj, list) else []:
        if not isinstance(block, dict) or block.get("localidade") not in (None, "BR"):
            continue
        for x in block.get("res") or []:
            if not isinstance(x, dict):
                continue
            name, freq = fold(x.get("nome")), x.get("frequencia")
            if name and isinstance(freq, int) and not isinstance(freq, bool) and freq >= 0:
                out[name] = max(out.get(name, 0), freq)
    return out


def parse_ibge_nomes(obj: Any) -> dict[str, Any] | None:
    """censos/nomes/{name} -> {empty, total} or None when the answer is not the documented list. [] is
    a rare/unknown name (never an error). A groupBy=UF answer only gives its national sum: the per-UF
    split is never kept (P252 cond 5)."""
    if not isinstance(obj, list):
        return None
    if not obj:
        return {"empty": True, "total": 0}
    total = 0
    seen = False
    for item in obj:
        if not isinstance(item, dict) or not isinstance(item.get("res"), list):
            return None  # not the documented shape: could not verify, never 'rare'
        for x in item["res"]:
            freq = x.get("frequencia") if isinstance(x, dict) else None
            if isinstance(freq, int) and not isinstance(freq, bool) and freq >= 0:
                total += freq
                seen = True
    return {"empty": not seen, "total": total}


_TABLE_LOCK = threading.Lock()
_TABLE_MEMO: dict[tuple[str, ...], dict[str, int]] = {}


def offline_table(store: Any = None, *, used: list[dict[str, Any]] | None = None) -> dict[str, int]:
    """The offline first-name table from the local ranking datasets (never downloads; {} when they were
    never fetched). ``store`` is a DataStore (``ctx.data.store`` in modules; a read-only
    ``DataStore(None)`` by default); ``used`` receives the citations of the copies read."""
    store = store if store is not None else DataStore(None)
    paths: list[tuple[str, Path, Any]] = []
    for name in RANKING_DATASETS:
        try:
            info = store.info(name)
        except (ValueError, OSError):
            continue
        if not getattr(info, "present", False):
            continue
        path = store.path(name)
        if path.is_file():
            paths.append((name, path, info))
    key = tuple(f"{n}:{getattr(i, 'sha256', '')}" for n, _p, i in paths)
    with _TABLE_LOCK:
        hit = _TABLE_MEMO.get(key)
    if hit is None:
        table: dict[str, int] = {}
        for _name, path, _info in paths:
            try:
                part = parse_ranking(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
            for k, v in part.items():
                table[k] = max(table.get(k, 0), v)
        with _TABLE_LOCK:
            _TABLE_MEMO[key] = table
        hit = table
    if used is not None:
        for name, _path, info in paths:
            if not any(isinstance(c, dict) and c.get("name") == name for c in used):
                used.append({"name": name, "sha256": getattr(info, "sha256", ""), "fetched_at": getattr(info, "fetched_at", ""),
                             "licence": getattr(info, "licence", "")})
    return dict(hit)


# --------------------------------------------------------------------------------------
# the opt-in module (person seeds)
# --------------------------------------------------------------------------------------


@register
class IbgeNameFrequency(Module):
    name = "ibge_name_frequency"
    title = "IBGE first-name frequency (homonym risk)"
    description = (
        "How common the first name of a typed person is (IBGE Census first-name statistics, offline ranking first, the IBGE "
        "nomes API for names missing from it) and the homonym risk of name-only matches for that name."
    )
    category = "person_name"
    accepts = {T.PERSON}
    produces: set[Any] = set()
    tags = {"brazil", "free"}
    reference = "https://servicodados.ibge.gov.br/api/docs/nomes?versao=2"
    notice = (
        "Aggregate Census statistics only: just the normalised first name is ever sent to IBGE, never at TLP:RED, and the "
        "frequency is never used to infer anything about the person (no origin, sex or age). Opt-in (person_name)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("servicodados.ibge.gov.br",)
    provider = "ibge"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    run_on = "seeds"
    max_requests = 1
    expected_latency = 0.5
    timeout = 15.0
    min_interval = 1.0
    cache_ttl = 86400
    default_enabled = False  # A3: person_name modules are never default (P252 cond 4)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return first_name(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = str(entity.value)
        fn = first_name(name)
        if fn is None:
            return res.mark(Status.SKIPPED, "no first name to look up", reason_code="not_applicable")
        table = offline_table(ctx.data.store, used=ctx.data.used)
        if fn in table:
            return self._emit(res, name, fn, table[fn], "IBGE Census 2010 ranking (offline dataset)")
        cached = self._cached(ctx, fn)
        if cached is not None:
            return self._emit(res, name, fn, cached, "IBGE nomes API (kept 365 days)")
        if str(ctx.tlp).lower() == "red":
            res.attr("homonym_risk", homonym_risk(name))
            return res.mark(Status.SKIPPED, "the online IBGE lookup never runs at TLP:RED (offline table only)", reason_code="tlp")
        data = ctx.http.get_json(IBGE_URL.format(name=fn.lower()), source=SOURCE)
        parsed = parse_ibge_nomes(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected IBGE answer (not the documented list): could not verify")
        self._remember(ctx, fn, int(parsed["total"]))
        return self._emit(res, name, fn, int(parsed["total"]), "IBGE nomes API")

    # ------------------------------------------------------------------ helpers
    def _emit(self, res: ModuleResult, name: str, fn: str, frequency: int, origin: str) -> ModuleResult:
        h = homonym_risk(name, frequency=frequency)
        res.attr("first_name_frequency", {"first_name": fn, "frequency": frequency, "source": origin})
        res.attr("homonym_risk", {k: h[k] for k in ("risk", "factor", "phrase", "first_name_tier", "common_surname")})
        res.raw = {"first_name": fn, "frequency": frequency, "source": origin}
        return res

    def _cached(self, ctx: Any, fn: str) -> int | None:
        try:
            names = ctx.state.get(STATE_KEY, {})
        except (StateError, OSError, ValueError):
            return None
        row = names.get(fn) if isinstance(names, dict) else None
        if not isinstance(row, dict) or not isinstance(row.get("frequency"), int):
            return None
        try:
            fetched = datetime.fromisoformat(str(row.get("fetched_at")).replace("Z", "+00:00"))
        except ValueError:
            return None
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        if ctx.now() - fetched > timedelta(days=STATE_TTL_DAYS):
            return None
        return int(row["frequency"])

    def _remember(self, ctx: Any, fn: str, frequency: int) -> None:
        try:
            names = ctx.state.get(STATE_KEY, {})
            names = names if isinstance(names, dict) else {}
            names[fn] = {"frequency": frequency, "fetched_at": ctx.now().isoformat()}
            if len(names) > STATE_MAX_NAMES:
                for old in sorted(names, key=lambda k: str(names[k].get("fetched_at")))[: len(names) - STATE_MAX_NAMES]:
                    names.pop(old, None)
            ctx.state.set(STATE_KEY, names)
        except (StateError, OSError, ValueError, AttributeError):
            pass  # a one-token name equal to the seed is refused by ctx.state: the answer is simply not kept


__all__ = [
    "COMMON_SURNAMES",
    "HOMONYM_PHRASES",
    "RANKING_DATASETS",
    "IbgeNameFrequency",
    "apply_homonym_curve",
    "first_name",
    "homonym_risk",
    "offline_table",
    "parse_ibge_nomes",
    "parse_ranking",
]
