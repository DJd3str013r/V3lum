"""Shared offline name matcher and homonym score (P219 cond 6, cond 9; P252 cond 1).

Stand-in for ``v3lum/core/namematch.py`` (P219 cond 6 names the core file; module batches cannot add
core files, so the matcher ships here and the move is a core request of batch p1-G10-1). P240,
P244, P254 and P221 reuse it: ``from v3lum.modules.company_org.namematch import match_name``.

* normalisation (:func:`name_tokens`): NFKD accent strip, casefold, punctuation folding (``S.A.``,
  ``S/A``, ``CO., LTD.``), legal-suffix removal for organisations (LTDA, S.A., EIRELI, ME, EPP, LLC,
  LTD, OOO, the Russian long form...), particle removal (da, de, do, dos, van...) - never emptying a name;
* scoring (:func:`token_set_jw`): deterministic token-set Jaro-Winkler in pure Python: tokens paired one
  to one, greedily by descending Jaro-Winkler (ties broken lexicographically), the score is the mean of
  both sides' length-weighted coverage, so unmatched tokens on either side lower it (a one-word query
  does not match a long name). rapidfuzz (MIT) is only an optional accelerator of the per-pair
  Jaro-Winkler with identical scores (``v3lum/data/extras/rapidfuzz.json``); both paths are tested;
* blocking (:func:`build_name_index`): a token + 3-character-prefix index built once per list version,
  so one query scores at most :data:`MAX_SCORED_ALIASES` aliases (< 300 ms per name on 50k aliases);
* :func:`match_name`: entries scoring >= :data:`NAME_MATCH_THRESHOLD` (0.90), best alias per entry, at
  most :data:`MAX_CANDIDATES` per list; persons are only compared with persons, organisations with
  organisations;
* :func:`homonym_risk` / :func:`homonym_curve`: an offline mirror of the P252 homonym score (the 20 most
  frequent Brazilian first names of the IBGE Censo 2010 ranking and the most common surnames;
  aggregate statistics only, never used to infer anything about the person) and its documented curve
  (confidence x factor). ``sanctions_lists`` prefers the P252 helper of ``ibge_name_frequency``
  (batch p1-G10-2, backed by the IBGE ranking dataset) when it is installed; both move to
  core/namematch.py with the matcher.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from typing import Any

__all__ = [
    "COMMON_NAME_RISK",
    "MAX_CANDIDATES",
    "MAX_SCORED_ALIASES",
    "NAME_MATCH_THRESHOLD",
    "accelerator_name",
    "build_name_index",
    "first_name_floor",
    "homonym_curve",
    "homonym_risk",
    "jaro",
    "jaro_winkler",
    "jaro_winkler_py",
    "match_name",
    "name_tokens",
    "normalized_name",
    "strip_accents",
    "token_set_jw",
]

def _words(text: str) -> frozenset[str]:
    """A frozenset of the space-separated words of ``text`` (readable constant tables)."""
    return frozenset(text.split())


#: P219 cond 8: a name match needs a score >= 0.90 (named constant; calibration notes in the backlog).
NAME_MATCH_THRESHOLD = 0.90
#: P219 cond 9: at most 5 candidates per list.
MAX_CANDIDATES = 5
#: Blocking bound: aliases scored per query (performance, P219 cond 13).
MAX_SCORED_ALIASES = 600
#: Homonym risk level at which a person hit stays INFO (P219 cond 9: common-name hits stay INFO).
COMMON_NAME_RISK = "high"

LEGAL_SUFFIXES = _words(
    "ltda ltd limitada sa eireli me epp mei ss llc inc incorporated corp corporation co company cia gmbh ag kg plc srl sro spa sas "
    "sarl sl bv nv oy oyj ab as asa pte pty jsc ojsc pjsc cjsc ooo zao oao pao fze fzco fzllc fzc dmcc llp lp lda limited ou sae "
    "saog wll"
)
LEADING_LEGAL_FORMS = _words("ooo zao oao pao ojsc pjsc cjsc jsc")
LEGAL_PHRASES = (
    "obshchestvo s ogranichennoi otvetstvennostyu", "obshchestvo s ogranichennoy otvetstvennostyu", "limited liability company",
    "sociedade anonima", "sociedad anonima", "sociedade limitada", "empresa individual de responsabilidade limitada",
    "public joint stock company", "joint stock company",
)
NAME_PARTICLES = _words("da de do das dos e y del della di du van von der den la le")


def strip_accents(text: Any) -> str:
    """NFKD and drop combining marks."""
    return "".join(c for c in unicodedata.normalize("NFKD", str(text if text is not None else "")) if not unicodedata.combining(c))


_INNER_PUNCT = re.compile(r"(?<=\w)[.'’`´](?=\w)")
_SLASH_PAIR = re.compile(r"(?<![\w])(\w)/(\w)(?![\w])")
_NON_WORD = re.compile(r"[\W_]+")
_PHRASES = tuple(re.compile(r"(?:^| )" + phrase + r"(?= |$)") for phrase in LEGAL_PHRASES)


def name_tokens(name: Any, kind: str = "entity") -> tuple[str, ...]:
    """Normalise a name into tokens (P219 cond 6). ``kind`` 'person' | 'individual' keeps legal words;
    for organisations legal phrases and trailing/leading legal forms are removed (a name is never
    emptied); particles are removed when at least two tokens remain."""
    s = strip_accents(name).casefold()
    s = s.replace("&", " and ")
    s = _INNER_PUNCT.sub("", s)  # J.P. -> jp, O'BRIEN -> obrien, S.A -> sa
    s = _SLASH_PAIR.sub(r"\1\2", s)  # S/A -> sa, A/S -> as
    s = _NON_WORD.sub(" ", s).strip()
    person = kind in ("person", "individual")
    if not person:
        for rx in _PHRASES:
            s = rx.sub(" ", s).strip()
    tokens = s.split()
    if not person and tokens:
        stripped = list(tokens)
        while len(stripped) > 1 and stripped[-1] in LEGAL_SUFFIXES:
            stripped.pop()
        while len(stripped) > 1 and stripped[0] in LEADING_LEGAL_FORMS:
            stripped.pop(0)
        tokens = stripped
    kept = [t for t in tokens if t not in NAME_PARTICLES]
    if len(kept) >= 2 or (kept and len(tokens) <= 2):
        tokens = kept
    return tuple(tokens)


def normalized_name(name: Any, kind: str = "entity") -> str:
    """The normalised tokens joined by spaces (for exact comparisons)."""
    return " ".join(name_tokens(name, kind))


# --------------------------------------------------------------------------------------
# Jaro-Winkler (pure Python reference; rapidfuzz only as an accelerator with identical scores)
# --------------------------------------------------------------------------------------


def jaro(s1: str, s2: str) -> float:
    """Jaro similarity (integer half-transpositions, as rapidfuzz and jellyfish)."""
    if s1 == s2:
        return 1.0
    l1, l2 = len(s1), len(s2)
    if not l1 or not l2:
        return 0.0
    window = max(max(l1, l2) // 2 - 1, 0)
    m1 = [False] * l1
    m2 = [False] * l2
    matches = 0
    for i, c in enumerate(s1):
        lo = max(0, i - window)
        hi = min(i + window + 1, l2)
        for j in range(lo, hi):
            if not m2[j] and s2[j] == c:
                m1[i] = m2[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    trans = 0
    k = 0
    for i in range(l1):
        if m1[i]:
            while not m2[k]:
                k += 1
            if s1[i] != s2[k]:
                trans += 1
            k += 1
    trans //= 2
    return (matches / l1 + matches / l2 + (matches - trans) / matches) / 3.0


def jaro_winkler_py(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """Jaro-Winkler: the common prefix (at most 4) boosts only when Jaro > 0.7 (rapidfuzz semantics)."""
    sim = jaro(s1, s2)
    if sim > 0.7:
        prefix = 0
        for a, b in zip(s1[:4], s2[:4]):
            if a != b:
                break
            prefix += 1
        sim += prefix * prefix_weight * (1.0 - sim)
    return sim


def _load_accelerator() -> Callable[[str, str], float] | None:
    try:  # optional extra (MIT): identical scores, faster per pair
        from rapidfuzz.distance import JaroWinkler  # type: ignore[import-not-found]
    except ImportError:
        return None
    similarity = getattr(JaroWinkler, "similarity", None)
    return similarity if callable(similarity) else None


_ACCEL: Callable[[str, str], float] | None = _load_accelerator()


def accelerator_name() -> str:
    """'rapidfuzz' when the optional accelerator is in use, else 'pure-python'."""
    return "rapidfuzz" if _ACCEL is not None else "pure-python"


def jaro_winkler(s1: str, s2: str) -> float:
    """Jaro-Winkler through the accelerator when installed, else the pure-Python reference (same score)."""
    if _ACCEL is not None:
        return float(_ACCEL(s1, s2))
    return jaro_winkler_py(s1, s2)


def token_set_jw(a_tokens: Iterable[str], b_tokens: Iterable[str]) -> float:
    """Deterministic token-set Jaro-Winkler (P219 cond 6): de-duplicated sorted tokens, one-to-one
    greedy pairing by descending score (ties broken lexicographically), mean of both sides'
    length-weighted coverage."""
    a = sorted(set(a_tokens or ()))
    b = sorted(set(b_tokens or ()))
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    pairs = sorted(((jaro_winkler(x, y), x, y) for x in a for y in b), key=lambda t: (-t[0], t[1], t[2]))
    used_a: set[str] = set()
    used_b: set[str] = set()
    cover_a = cover_b = 0.0
    for score, x, y in pairs:
        if x in used_a or y in used_b or score <= 0.0:
            continue
        used_a.add(x)
        used_b.add(y)
        cover_a += len(x) * score
        cover_b += len(y) * score
    total_a = sum(len(x) for x in a)
    total_b = sum(len(y) for y in b)
    return (cover_a / total_a + cover_b / total_b) / 2.0


# --------------------------------------------------------------------------------------
# blocking index and matching
# --------------------------------------------------------------------------------------


def _block_keys(tokens: Iterable[str]) -> set[str]:
    keys: set[str] = set()
    for t in tokens:
        if len(t) >= 2:
            keys.add("t:" + t)
            keys.add("p:" + t[:3])
    return keys


def _kind(value: Any) -> str:
    """'person' (person/individual), 'vessel', 'aircraft' or 'entity' (organisations and the rest):
    only aliases of the same kind are ever compared."""
    if value in ("person", "individual"):
        return "person"
    if value in ("vessel", "aircraft"):
        return str(value)
    return "entity"


def build_name_index(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Build the token blocking index once per list version (P219 cond 6).

    ``records``: dicts {entry_id, name, kind ('person' | 'individual' | anything else = entity),
    alias_type}. Returns {aliases: [(entry_id, name, tokens, kind, alias_type)], blocks: {key: [ix]}}.
    """
    aliases: list[tuple[Any, str, tuple[str, ...], str, str]] = []
    blocks: dict[str, list[int]] = {}
    for rec in records or ():
        if not isinstance(rec, dict) or not isinstance(rec.get("name"), str) or not rec["name"].strip():
            continue
        kind = _kind(rec.get("kind"))
        tokens = name_tokens(rec["name"], kind)
        if not tokens:
            continue
        ix = len(aliases)
        aliases.append((rec.get("entry_id"), rec["name"], tokens, kind, str(rec.get("alias_type") or "primary")))
        for key in _block_keys(tokens):
            blocks.setdefault(key, []).append(ix)
    return {"aliases": aliases, "blocks": blocks}


def match_name(
    query: Any,
    index: dict[str, Any] | None,
    *,
    kind: str = "entity",
    threshold: float = NAME_MATCH_THRESHOLD,
    limit: int = MAX_CANDIDATES,
    max_scored: int = MAX_SCORED_ALIASES,
) -> list[dict[str, Any]]:
    """At most ``limit`` entries scoring >= ``threshold``: [{entry_id, matched_alias, alias_type, score}],
    the best alias per entry, sorted by (-score, entry_id). Only aliases of the same kind are compared
    (persons with persons, organisations with organisations)."""
    if not index or not isinstance(query, str) or not query.strip():
        return []
    want = _kind(kind)
    q = name_tokens(query, want)
    if not q:
        return []
    points: dict[int, int] = {}
    blocks = index.get("blocks", {})
    for key in _block_keys(q):
        weight = 2 if key.startswith("t:") else 1
        for ix in blocks.get(key, ()):
            points[ix] = points.get(ix, 0) + weight
    aliases = index.get("aliases", [])
    ranked = sorted(points.items(), key=lambda kv: (-kv[1], kv[0]))[:max_scored]
    best: dict[Any, dict[str, Any]] = {}
    for ix, _pts in ranked:
        entry_id, alias_name, tokens, akind, alias_type = aliases[ix]
        if akind != want:
            continue
        score = token_set_jw(q, tokens)
        if score >= threshold:
            prev = best.get(entry_id)
            if prev is None or score > prev["score"]:
                best[entry_id] = {"entry_id": entry_id, "matched_alias": alias_name, "alias_type": alias_type, "score": round(score, 4)}
    return sorted(best.values(), key=lambda r: (-r["score"], str(r["entry_id"])))[: max(0, int(limit))]


# --------------------------------------------------------------------------------------
# homonym score (P219 cond 9; interim mirror of the P252 curve until it lands in core)
# --------------------------------------------------------------------------------------

#: IBGE Censo 2010 'Nomes no Brasil' ranking (aggregate statistics): the 10 most frequent first names,
#: each with more than 1,000,000 bearers...
COMMON_FIRST_NAMES_TIER1 = _words("maria jose ana joao antonio francisco carlos paulo pedro lucas")
#: ... and ranks 11-20 (more than 100,000 bearers each).
COMMON_FIRST_NAMES_TIER2 = _words("luiz marcos luis gabriel rafael francisca daniel marcelo bruno eduardo")
#: The most common Brazilian surnames (curated list, as P252 cond 2).
COMMON_SURNAMES = _words(
    "silva santos oliveira souza sousa rodrigues ferreira alves pereira lima gomes costa ribeiro martins carvalho almeida lopes "
    "soares fernandes vieira barbosa rocha dias nascimento andrade moreira nunes marques machado mendes freitas cardoso ramos "
    "goncalves santana teixeira araujo melo castro cavalcante"
)
#: The P252 documented curve: first-name factor 0.4 (>= 1,000,000 bearers), 0.6 (>= 100,000), 1.0 when
#: unknown (neutral); x 0.8 with a common surname; risk high at <= 0.5, medium at <= 0.8.
FIRST_NAME_FACTORS = {1: (0.4, "very_common"), 2: (0.6, "common")}
COMMON_SURNAME_FACTOR = 0.8
HOMONYM_PHRASES = {
    "high": "very common name: name-only matches are unreliable",
    "medium": "common name: a name-only match needs another identifier",
    "low": "uncommon name",
    "unknown": "name frequency unknown",
}


def first_name_floor(name: Any) -> int | None:
    """A lower bound of the IBGE Censo 2010 bearers of the first name (1,000,000 for the top 10,
    100,000 for ranks 11-20), or None when the embedded table does not know it."""
    tokens = name_tokens(name, "person")
    first = tokens[0] if tokens else ""
    if first in COMMON_FIRST_NAMES_TIER1:
        return 1_000_000
    if first in COMMON_FIRST_NAMES_TIER2:
        return 100_000
    return None


def homonym_risk(name: Any) -> dict[str, Any]:
    """Offline homonym score of a person name in the P252 shape {risk high | medium | low | unknown,
    factor (multiplier: 1.0 neutral, lower = more homonyms), phrase, first_name_tier, common_surname}
    (P219 cond 9). Names absent from the tables are 'unknown' (neutral), never 'rare'. Aggregate
    statistics only: nothing is inferred about the person (P256)."""
    tokens = name_tokens(name, "person")
    first = tokens[0] if tokens else ""
    common_surname = any(t in COMMON_SURNAMES for t in tokens[1:])
    tier_no = 1 if first in COMMON_FIRST_NAMES_TIER1 else 2 if first in COMMON_FIRST_NAMES_TIER2 else 0
    base, tier = FIRST_NAME_FACTORS.get(tier_no, (1.0, "unknown"))
    factor = round(base * (COMMON_SURNAME_FACTOR if common_surname else 1.0), 3)
    if tier == "unknown" and not common_surname:
        risk = "unknown"
    else:
        risk = "high" if factor <= 0.5 else "medium" if factor <= 0.8 else "low"
    return {"risk": risk, "factor": factor, "phrase": HOMONYM_PHRASES[risk], "first_name_tier": tier, "common_surname": common_surname}


def homonym_curve(confidence: float, homonym: dict[str, Any] | None) -> float:
    """The P252 curve: confidence x factor (a missing or unreadable factor is neutral)."""
    try:
        factor = float((homonym or {}).get("factor", 1.0))
    except (TypeError, ValueError):
        factor = 1.0
    return round(max(0.0, min(1.0, float(confidence))) * max(0.0, min(1.0, factor)), 4)
