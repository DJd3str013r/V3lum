"""Public Suffix List + IANA TLD helpers (bundled data, no network)."""

from __future__ import annotations

import functools
from importlib import resources


@functools.lru_cache(maxsize=1)
def _tlds() -> frozenset[str]:
    text = resources.files("v3lum.data").joinpath("iana_tlds.txt").read_text(encoding="utf-8")
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _to_ascii(rule: str) -> str:
    out = []
    for label in rule.split("."):
        if label in ("*",) or label.startswith("!"):
            prefix = "!" if label.startswith("!") else ""
            core = label.lstrip("!")
            try:
                core = core.encode("idna").decode("ascii") if core != "*" else core
            except UnicodeError:
                pass
            out.append(prefix + core)
            continue
        try:
            out.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            out.append(label)
    return ".".join(out).lower()


@functools.lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    text = resources.files("v3lum.data").joinpath("public_suffix_list.dat").read_text(encoding="utf-8")
    exact, wild, exc = set(), set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = _to_ascii(line)
        if rule.startswith("!"):
            exc.add(rule[1:])
        elif rule.startswith("*."):
            wild.add(rule[2:])
        else:
            exact.add(rule)
    return frozenset(exact), frozenset(wild), frozenset(exc)


def is_known_tld(tld: str) -> bool:
    t = tld.lower().strip(".")
    try:
        t = t.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return t in _tlds()


def public_suffix(domain: str) -> str:
    """Public suffix of a domain (e.g. 'com.br' for 'shop.example.com.br')."""
    labels = domain.lower().strip(".").split(".")
    exact, wild, exc = _rules()
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in exc:
            return ".".join(labels[i + 1 :])
        if cand in exact:
            return cand
        rest = ".".join(labels[i + 1 :])
        if rest and rest in wild:
            return cand
    return labels[-1]


def registrable_domain(domain: str) -> str | None:
    """eTLD+1 ('example.com.br' for 'a.b.example.com.br'); None if the domain *is* a suffix."""
    d = domain.lower().strip(".")
    suffix = public_suffix(d)
    if d == suffix:
        return None
    head = d[: -len(suffix) - 1] if suffix else d
    return f"{head.split('.')[-1]}.{suffix}" if suffix else head


def is_subdomain(domain: str) -> bool:
    reg = registrable_domain(domain)
    return reg is not None and reg != domain.lower().strip(".")
