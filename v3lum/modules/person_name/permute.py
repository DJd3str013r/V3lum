"""Shared offline name -> username / corporate e-mail permutation helper (P251 cond 1).

The council asked for one shared core helper (``core/permute.py``) reused by the e-mail pattern
modules; module batches never add core files, so it lives here until the core adopts it (core request
recorded in the batch manifest p3-G05-3). It is pure, offline and deterministic: no V3LUM network API,
no I/O. Import it as ``from v3lum.modules.person_name.permute import username_candidates,
email_candidates, infer_email_format, generated_sink_reason``.

Rules (P251 final conditions):

* cond 1 - NFKD accent stripping (plus a small transliteration table); the particles {de, da, do,
  das, dos, e, di, du, del, van, von} are dropped; the suffixes {junior, jr, filho, neto, sobrinho} are
  recognised and never used as a surname or inside a handle; the LAST surname is the primary one;
  order = declared handles, then the Ceos priority patterns (f+l, f.l, f_l, f-l, f[0]+l, ...), then the
  maigret Permute 'strict' permutations, deduplicated in that order.
* cond 2 - at most 15 candidates per person and kind (username list, e-mail list); corporate e-mail
  candidates only for domains of the case or the org_profile (free-mail domains refused), ranked by the
  domain's format inferred from observed addresses, each showing the number of samples behind it.
* cond 3 - every candidate is a hypothesis: label 'generated', expand False, verified False, never a
  finding, never scored; the top 3 are 'offered first'.
* cond 4 - :func:`generated_sink_reason`: generated e-mails never reach breach, stealer, reputation or
  validation services and nothing generated is ever validated by SMTP, login, sign-up or reset flows;
  generated handles reach username_check only after the analyst selected them.

Adapted code (A6 BR5): :func:`maigret_strict_permutations` adapts the 'strict' branch of
maigret/permutator.py (Permute by balestek, https://github.com/balestek), https://github.com/soxoj/maigret
commit 50e62c45e17b03fd3f059622d38a4cdb3ec2eab4, MIT License, Copyright (c) 2020-2026 Soxoj (notice
v3lum/data/notices/maigret_permutator.json). The identical code in Blackbird is labelled GPLv3: only the
MIT copy from maigret was used. The Ceos patterns are team-owned (ceos/variacoes.py); recon-ng
(GPL-3.0) and NAMINT were read as ideas only - no code was copied.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from typing import Any

PARTICLES = frozenset({"de", "da", "do", "das", "dos", "e", "di", "du", "del", "van", "von"})  # cond 1
SUFFIXES = frozenset({"junior", "jr", "filho", "neto", "sobrinho"})  # cond 1
CANDIDATE_CAP = 15  # cond 2 (per person and kind)
OFFERED_FIRST = 3  # cond 3
LABEL = "generated"
_TRANSLIT = str.maketrans({"ß": "ss", "æ": "ae", "Æ": "ae", "ø": "o", "Ø": "o", "đ": "d", "Đ": "d", "ł": "l",
                           "Ł": "l", "œ": "oe", "Œ": "oe", "þ": "th", "ı": "i"})
_MAX_NAME_CHARS = 200
_MAX_TOKENS = 8

#: Free-mail domains: corporate address patterns never apply to them (cond 2).
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.com.br", "outlook.com", "outlook.com.br", "live.com",
    "msn.com", "yahoo.com", "yahoo.com.br", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "yandex.ru", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "globo.com", "globomail.com",
    "r7.com", "zipmail.com.br", "tutanota.com", "tuta.io", "fastmail.com", "hey.com",
})
#: Role/test local parts excluded from format inference (A4 BR6 list plus common Brazilian role boxes).
GENERIC_LOCAL_PARTS = frozenset({
    "test", "teste", "info", "contato", "contact", "sac", "admin", "noreply", "no-reply", "suporte", "support",
    "vendas", "financeiro", "rh", "webmaster", "postmaster", "abuse", "hostmaster", "privacy", "privacidade",
    "dpo", "ouvidoria", "comercial", "atendimento", "marketing", "jobs", "careers", "vagas", "press",
    "imprensa", "security", "seguranca", "help", "ajuda", "billing", "cobranca", "faleconosco", "nfe",
})

#: Sinks that must never receive a generated e-mail (cond 4: an answer is an existence oracle by proxy).
FORBIDDEN_SINKS_FOR_GENERATED = frozenset({
    "breach", "breach_leak", "infostealer", "stealer", "reputation", "email_reputation", "email_validation",
    "validation", "smtp", "login", "signup", "password_reset",
})
#: Sinks that must never receive anything generated (cond 4).
NEVER_SINKS = frozenset({"smtp", "login", "signup", "password_reset"})


# ---------------------------------------------------------------------------------------------- names


def fold_token(token: Any) -> str:
    """NFKD accent stripping + small transliteration, a-z only ('João' -> 'joao', "D'Ávila" -> 'davila')."""
    s = unicodedata.normalize("NFKD", str(token or "").translate(_TRANSLIT))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z]", "", s)


def name_parts(name: Any) -> dict[str, Any]:
    """cond 1: significant tokens (particles and suffixes dropped; particles kept only when nothing else is
    left), first, middles, last (the LAST surname is primary), suffix and the dropped particles."""
    text = str(name or "")[:_MAX_NAME_CHARS]
    tokens = [t for t in (fold_token(t) for t in re.split(r"[\s,;/]+", text)) if t][: _MAX_TOKENS * 2]
    sig = [t for t in tokens if t not in PARTICLES and t not in SUFFIXES]
    if not sig:
        sig = [t for t in tokens if t not in SUFFIXES]
    sig = sig[:_MAX_TOKENS]
    suffix = next((t for t in reversed(tokens) if t in SUFFIXES), None)
    return {"tokens": tokens, "significant": sig, "first": sig[0] if sig else None,
            "middles": sig[1:-1] if len(sig) > 2 else [], "last": sig[-1] if len(sig) >= 2 else None,
            "suffix": suffix, "particles_dropped": [t for t in tokens if t in PARTICLES]}


def ceos_handle_patterns(parts: dict[str, Any]) -> list[tuple[str, str]]:
    """Ceos priority patterns (team-owned ceos/variacoes.py handles_candidatos), in order: f+l, f.l, f_l, f-l,
    f[0]+l, f[0].l, l+f, l.f, f+l[0]; then per middle m: f+m, f.m, f[0]+m[0]+l, f+m[0]+l, f+m+l, f.m.l.
    -> [(handle, pattern_id)]."""
    f, last = parts.get("first"), parts.get("last")
    if not f:
        return []
    if not last:
        return [(f, "first")]
    out = [(f + last, "firstlast"), (f"{f}.{last}", "first.last"), (f"{f}_{last}", "first_last"),
           (f"{f}-{last}", "first-last"), (f[0] + last, "flast"), (f"{f[0]}.{last}", "f.last"),
           (last + f, "lastfirst"), (f"{last}.{f}", "last.first"), (f + last[0], "firstl")]
    for m in parts.get("middles") or []:
        out += [(f + m, "firstmiddle"), (f"{f}.{m}", "first.middle"), (f[0] + m[0] + last, "fmlast"),
                (f + m[0] + last, "firstmlast"), (f + m + last, "firstmiddlelast"),
                (f"{f}.{m}.{last}", "first.middle.last")]
    return out


def maigret_strict_permutations(elements: Iterable[str], limit: int = 200) -> list[str]:
    """maigret Permute.gather('strict') (MIT, see the module header): every ordered subset of >= 2 elements
    joined by '', '_', '-', '.', plus '_'+perm and perm+'_' for the '' separator; single elements are
    excluded. Deterministic order = itertools.permutations order x separator order; stops at ``limit``."""
    seen: dict[str, None] = {}
    elems = [e for e in elements if e][:_MAX_TOKENS]
    for i in range(2, len(elems) + 1):
        for subset in itertools.permutations(elems, i):
            for sep in ("", "_", "-", "."):
                perm = sep.join(subset)
                seen.setdefault(perm, None)
                if sep == "":
                    seen.setdefault("_" + perm, None)
                    seen.setdefault(perm + "_", None)
                if len(seen) >= limit:
                    return list(seen)[:limit]
    return list(seen)


def _candidate(value: str, rank: int, pattern: str, origin: str, kind: str, **extra: Any) -> dict[str, Any]:
    out = {"value": value, "rank": rank, "pattern": pattern, "origin": origin, "kind": kind, "label": LABEL,
           "expand": False, "verified": False, "offered_first": rank <= OFFERED_FIRST}
    out.update(extra)
    return out


def username_candidates(name: Any, declared: Iterable[Any] = (), cap: int = CANDIDATE_CAP) -> list[dict[str, Any]]:
    """cond 1-3: at most 15 username hypotheses for one person, deterministic order: declared handles (if
    any) > Ceos priority patterns > maigret 'strict' permutations of the significant tokens."""
    cap = max(0, min(int(cap), CANDIDATE_CAP))
    parts = name_parts(name)
    seq: list[tuple[str, str, str]] = []
    for d in declared or ():
        h = str(d or "").strip().lstrip("@").lower()
        if re.fullmatch(r"[a-z0-9._-]{1,30}", h):
            seq.append((h, "declared", "declared by the subject"))
    seq += [(h, pid, "name pattern (Ceos)") for h, pid in ceos_handle_patterns(parts)]
    seq += [(h, "strict", "maigret permute strict (MIT)") for h in maigret_strict_permutations(parts["significant"])]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value, pid, origin in seq:
        if len(out) >= cap:
            break
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(_candidate(value, len(out) + 1, pid, origin, "username"))
    return out


# ---------------------------------------------------------------------------------------------- e-mail

#: Default corporate order (cond 2 ranks by the observed format first).
EMAIL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("first.last", "{first}.{last}"), ("flast", "{f}{last}"), ("first", "{first}"), ("firstlast", "{first}{last}"),
    ("f.last", "{f}.{last}"), ("first_last", "{first}_{last}"), ("firstl", "{first}{l}"),
    ("last.first", "{last}.{first}"), ("lastf", "{last}{f}"), ("first-last", "{first}-{last}"),
    ("lastfirst", "{last}{first}"), ("fmlast", "{f}{m}{last}"), ("first.m.last", "{first}.{m}.{last}"),
    ("first.middle.last", "{first}.{middle}.{last}"), ("last", "{last}"), ("f_last", "{f}_{last}"),
    ("last_first", "{last}_{first}"), ("first.l", "{first}.{l}"),
)
EMAIL_PATTERN_IDS: tuple[str, ...] = tuple(p for p, _ in EMAIL_PATTERNS)
_TEMPLATES = dict(EMAIL_PATTERNS)
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise_domain(value: Any) -> str | None:
    """Lower-case DNS name without a trailing dot, or None."""
    dom = str(value or "").strip().lower().rstrip(".")
    return dom if _DOMAIN_RE.match(dom) else None


def email_local_part(parts: dict[str, Any], pattern_id: str) -> str | None:
    """One corporate local part for a pattern id; None when the name lacks the needed tokens."""
    tpl = _TEMPLATES.get(pattern_id)
    f, last = parts.get("first"), parts.get("last")
    if not tpl or not f:
        return None
    if ("{last}" in tpl or "{l}" in tpl) and not last:
        return None
    mids = parts.get("middles") or []
    if ("{m}" in tpl or "{middle}" in tpl) and not mids:
        return None
    return tpl.format(first=f, f=f[0], last=last or "", l=(last or " ")[0], m=mids[0][0] if mids else "",
                      middle=mids[0] if mids else "")


def _shape_pattern(local: str) -> str | None:
    """Unnamed sample -> pattern id by shape, only when unambiguous enough (a single token is not)."""
    if re.fullmatch(r"[a-z]{2,}\.[a-z]{2,}", local):
        return "first.last"
    if re.fullmatch(r"[a-z]\.[a-z]{2,}", local):
        return "f.last"
    if re.fullmatch(r"[a-z]{2,}_[a-z]{2,}", local):
        return "first_last"
    if re.fullmatch(r"[a-z]{2,}-[a-z]{2,}", local):
        return "first-last"
    if re.fullmatch(r"[a-z]{2,}\.[a-z]\.[a-z]{2,}", local):
        return "first.m.last"
    return None


def _sample(item: Any) -> tuple[Any, Any]:
    if isinstance(item, dict):
        return item.get("address"), item.get("name")
    if isinstance(item, (tuple, list)) and len(item) == 2:
        return item[1], item[0]
    return item, None


def infer_email_format(samples: Iterable[Any], domain: Any) -> dict[str, Any]:
    """cond 2: a domain's address format from observed addresses (commit e-mails, public pages).

    ``samples``: 'addr' strings, (name, addr) tuples or {address, name} dicts. Only addresses at exactly
    ``domain`` count; role/test local parts and '+tags' are excluded. Named samples are matched against
    every pattern (exact); unnamed ones count only for unambiguous shapes. -> {domain, format, samples (the
    number of addresses behind the format), used, counts, ambiguous, basis}."""
    dom = normalise_domain(domain) or ""
    counts: Counter[str] = Counter()
    used = named = 0
    for item in samples or ():
        addr, nm = _sample(item)
        if not isinstance(addr, str) or "@" not in addr:
            continue
        local, _, d = addr.strip().lower().rpartition("@")
        if d != dom or not local:
            continue
        local = local.split("+", 1)[0]
        if local in GENERIC_LOCAL_PARTS or re.sub(r"[^a-z]", "", local) in GENERIC_LOCAL_PARTS:
            continue
        pid = None
        if isinstance(nm, str) and nm.strip():
            parts = name_parts(nm)
            pid = next((cand for cand in EMAIL_PATTERN_IDS if email_local_part(parts, cand) == local), None)
            if pid:
                named += 1
        if pid is None:
            pid = _shape_pattern(local)
        if pid:
            counts[pid] += 1
            used += 1
    if not counts:
        return {"domain": dom, "format": None, "samples": 0, "used": 0, "counts": {}, "ambiguous": False, "basis": None}
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], EMAIL_PATTERN_IDS.index(kv[0])))
    best, n = ranked[0]
    return {"domain": dom, "format": best, "samples": n, "used": used, "counts": dict(ranked),
            "ambiguous": len(ranked) > 1 and ranked[1][1] == n,
            "basis": "named" if named == used else ("shape" if named == 0 else "mixed")}


def email_candidates(name: Any, domains: Iterable[Any] | str, allowed_domains: Iterable[Any], samples: Iterable[Any] = (),
                     cap: int = CANDIDATE_CAP) -> dict[str, Any]:
    """cond 2-4: corporate e-mail hypotheses for one person.

    Only domains in the case or the org_profile (``allowed_domains``) are used; free-mail domains are
    refused. Per domain, candidates are ranked by the observed format counts, then the default corporate
    order; across domains they are interleaved by rank; at most 15. -> {state: ok|empty|refused,
    candidates, formats, refused}."""
    cap = max(0, min(int(cap), CANDIDATE_CAP))
    allowed = {d for d in (normalise_domain(x) for x in (allowed_domains or ())) if d}
    doms = [domains] if isinstance(domains, str) else list(domains or ())
    parts = name_parts(name)
    refused: list[dict[str, str]] = []
    per_domain: list[list[tuple[str, str, int]]] = []
    formats: dict[str, Any] = {}
    seen_domains: set[str] = set()
    sample_list = list(samples or ())
    for d in doms:
        dom = normalise_domain(d)
        if not dom or dom in seen_domains:
            continue
        seen_domains.add(dom)
        if dom in FREE_MAIL_DOMAINS:
            refused.append({"domain": dom, "reason": "free-mail domain: corporate patterns do not apply"})
            continue
        if dom not in allowed:
            refused.append({"domain": dom, "reason": "domain not in the case or org_profile"})
            continue
        fmt = infer_email_format(sample_list, dom)
        formats[dom] = fmt
        order = sorted(EMAIL_PATTERN_IDS, key=lambda p: (-fmt["counts"].get(p, 0), EMAIL_PATTERN_IDS.index(p)))
        rows: list[tuple[str, str, int]] = []
        seen_local: set[str] = set()
        for pid in order:
            lp = email_local_part(parts, pid)
            if not lp or lp in seen_local:
                continue
            seen_local.add(lp)
            rows.append((f"{lp}@{dom}", pid, int(fmt["counts"].get(pid, 0))))
        per_domain.append(rows)
    out: list[dict[str, Any]] = []
    for row in itertools.zip_longest(*per_domain):
        for item in row:
            if item is None or len(out) >= cap:
                continue
            addr, pid, n = item
            out.append(_candidate(addr, len(out) + 1, pid, "corporate pattern", "email", format_samples=n))
    state = "ok" if out else ("refused" if refused and not per_domain else "empty")
    return {"state": state, "candidates": out, "formats": formats, "refused": refused}


def generated_sink_reason(candidate: Any, sink_category: Any) -> str | None:
    """cond 3/4: None when a value may be sent to a module of ``sink_category``, else the refusal reason.

    Generated e-mails never go to breach/stealer/reputation/validation sinks (not even after selection);
    nothing generated goes to SMTP/login/sign-up/reset flows; generated handles reach username_check only
    after the analyst selected them."""
    if not isinstance(candidate, dict) or candidate.get("label") != LABEL:
        return None
    cat = str(sink_category or "").lower()
    kind = candidate.get("kind")
    if cat in NEVER_SINKS:
        return "generated candidates are never validated by SMTP, login, sign-up or reset flows"
    if kind == "email" and cat in FORBIDDEN_SINKS_FOR_GENERATED:
        return "generated e-mail candidates are never sent to breach, stealer, reputation or validation services"
    if kind == "username" and cat == "username_check" and not candidate.get("selected_by_analyst"):
        return "generated handles reach username_check only after the analyst selects them"
    return None
