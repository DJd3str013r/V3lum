"""Shared typosquat permutation helper (P012 conditions 1-4): candidate generation, ranking and the
offline reverse lookalike matcher.

Used by the ``typosquat`` and ``typosquat_dnstwister`` modules and meant for ``nrd_feeds`` (P005) and
``v3lum watch`` (P030): import :func:`generate`, :func:`rank`, :func:`build_protected_index` and
:func:`reverse_match` from here (no Module class lives in this file). Pure functions, standard library
plus the ``idna`` package (a dependency of ``requests``) for UTS-46 and the core PSL helper; no network,
no I/O, never raises on odd input.

* Every candidate is validated through IDNA/UTS-46 (:func:`idna_ascii`) and the dnstwist
  ``VALID_FQDN`` expression **before** anything may query it (P012 c1).
* Fuzzers: addition, bitsquatting, homoglyph, hyphenation, insertion, omission, repetition,
  replacement, subdomain, transposition, vowel-swap, dictionary, combo (P012 c3) and TLD swap; the
  dnstwist cyrillic, plural and various fuzzers are optional (:data:`OPTIONAL_FUZZERS`).
* .br names use the registro.br IDN accent set only (a/á/â/ã/à, e/é/ê, i/í, o/ó/ô/õ, u/ú/ü, c/ç); the
  ASCII glyphs include rn/m, vv/w, l/1, o/0 (P012 c3).
* :func:`rank` keeps the top 150 (500 with --preset deep or watch) with family quotas so a default
  scan stays diverse (P012 c5).

NOTICE - third-party code (A6, Apache-2.0)
------------------------------------------
The fuzzer algorithms (addition, bitsquatting, cyrillic, homoglyph, hyphenation, insertion, omission,
plural, repetition, replacement, subdomain, transposition, vowel-swap, dictionary, tld-swap, various),
the glyph and keyboard tables and the VALID_FQDN expression are adapted from dnstwist:

    https://github.com/elceef/dnstwist
    commit 341395377f40761fe4152f43fd18eea757b6069a (dnstwist version 20250130)
    Copyright (c) Marcin Ulikowski
    Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

Changes from the original: ported to pure functions over the label; the domain is split with the
bundled public-suffix list; the .br accent set is limited to the registro.br IDN characters; combo-squats
over the pt-BR lure list; candidate ranking with family quotas; UTS-46 validation; the reverse lookalike
matcher (new code). The notice fragment is v3lum/data/notices/dnstwist.json.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

try:  # UTS-46 / IDNA 2008 (requests depends on idna)
    import idna as _idna
except ImportError:  # pragma: no cover - stdlib IDNA 2003 fallback
    _idna = None  # type: ignore[assignment]

from v3lum.core import psl

__all__ = [
    "ABUSED_TLDS",
    "DEFAULT_FUZZERS",
    "FAMILY_OF",
    "FUZZER_WEIGHT",
    "OPTIONAL_FUZZERS",
    "TLD_SWAP_EXTRA",
    "TLD_SWAP_PRIMARY",
    "VALID_FQDN",
    "build_protected_index",
    "fold",
    "generate",
    "idna_ascii",
    "idna_unicode",
    "is_br",
    "rank",
    "reverse_match",
    "skeleton",
    "split_domain",
]

#: dnstwist's domain expression (case-insensitive): 4-253 characters, LDH labels, a 2-63 char TLD.
VALID_FQDN = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)", re.I)

# dnstwist fallback second levels plus the registro.br categories (x.com.br splits as x|com.br) - used
# only when the PSL cannot split a name.
_COMMON_2LD = frozenset({
    "org", "com", "net", "gov", "edu", "co", "mil", "nom", "ac", "info", "biz", "ne",
    "adm", "adv", "agr", "am", "app", "arq", "art", "ato", "bio", "blog", "eco", "emp", "eng", "esp",
    "etc", "eti", "far", "fm", "ind", "inf", "jor", "jus", "leg", "log", "med", "mp", "mus", "not",
    "ntr", "odo", "ong", "pro", "psc", "psi", "radio", "rec", "seg", "srv", "tmp", "trd", "tur", "tv", "vet",
})

#: P012 c3 TLD swaps (ranked first) and extra abused / BR-relevant TLDs.
TLD_SWAP_PRIMARY: tuple[str, ...] = ("com.br", "net.br", "app.br", "online", "site", "top", "xyz", "shop", "vip")
TLD_SWAP_EXTRA: tuple[str, ...] = ("com", "net", "org", "info", "store", "live", "click", "link", "icu", "cc", "br.com")
ABUSED_TLDS = frozenset({"online", "site", "top", "xyz", "shop", "vip", "store", "live", "click", "link", "icu", "cc"})

# ----------------------------------------------------------------------- dnstwist tables (Apache-2.0)
_GLYPHS_UNICODE: dict[str, tuple[str, ...]] = {
    "2": ("ƻ",), "3": ("ʒ",), "5": ("ƽ",),
    "a": ("ạ", "ă", "ȧ", "ɑ", "å", "ą", "â", "ǎ", "á", "ə", "ä", "ã", "ā", "à"),
    "b": ("ḃ", "ḅ", "ƅ", "ʙ", "ḇ", "ɓ"),
    "c": ("č", "ᴄ", "ċ", "ç", "ć", "ĉ", "ƈ"),
    "d": ("ď", "ḍ", "ḋ", "ɖ", "ḏ", "ɗ", "ḓ", "ḑ", "đ"),
    "e": ("ê", "ẹ", "ę", "è", "ḛ", "ě", "ɇ", "ė", "ĕ", "é", "ë", "ē", "ȩ"),
    "f": ("ḟ", "ƒ"),
    "g": ("ǧ", "ġ", "ǵ", "ğ", "ɡ", "ǥ", "ĝ", "ģ", "ɢ"),
    "h": ("ȟ", "ḫ", "ḩ", "ḣ", "ɦ", "ḥ", "ḧ", "ħ", "ẖ", "ⱨ", "ĥ"),
    "i": ("ɩ", "ǐ", "í", "ɪ", "ỉ", "ȋ", "ɨ", "ï", "ī", "ĩ", "ị", "î", "ı", "ĭ", "į", "ì"),
    "j": ("ǰ", "ĵ", "ʝ", "ɉ"),
    "k": ("ĸ", "ǩ", "ⱪ", "ḵ", "ķ", "ᴋ", "ḳ"),
    "l": ("ĺ", "ł", "ɫ", "ļ", "ľ"),
    "m": ("ᴍ", "ṁ", "ḿ", "ṃ", "ɱ"),
    "n": ("ņ", "ǹ", "ń", "ň", "ṅ", "ṉ", "ṇ", "ꞑ", "ñ", "ŋ"),
    "o": ("ö", "ó", "ȯ", "ỏ", "ô", "ᴏ", "ō", "ò", "ŏ", "ơ", "ő", "õ", "ọ", "ø"),
    "p": ("ṗ", "ƿ", "ƥ", "ṕ"),
    "q": ("ʠ",),
    "r": ("ʀ", "ȓ", "ɍ", "ɾ", "ř", "ṛ", "ɽ", "ȑ", "ṙ", "ŗ", "ŕ", "ɼ", "ṟ"),
    "s": ("ṡ", "ș", "ŝ", "ꜱ", "ʂ", "š", "ś", "ṣ", "ş"),
    "t": ("ť", "ƫ", "ţ", "ṭ", "ṫ", "ț", "ŧ"),
    "u": ("ᴜ", "ų", "ŭ", "ū", "ű", "ǔ", "ȕ", "ư", "ù", "ů", "ʉ", "ú", "ȗ", "ü", "û", "ũ", "ụ"),
    "v": ("ᶌ", "ṿ", "ᴠ", "ⱴ", "ⱱ", "ṽ"),
    "w": ("ᴡ", "ẇ", "ẅ", "ẃ", "ẘ", "ẉ", "ⱳ", "ŵ", "ẁ"),
    "x": ("ẋ", "ẍ"),
    "y": ("ŷ", "ÿ", "ʏ", "ẏ", "ɏ", "ƴ", "ȳ", "ý", "ỿ", "ỵ"),
    "z": ("ž", "ƶ", "ẓ", "ẕ", "ⱬ", "ᴢ", "ż", "ź", "ʐ"),
    "ae": ("æ",), "oe": ("œ",),
}

_GLYPHS_ASCII: dict[str, tuple[str, ...]] = {
    "0": ("o",), "1": ("l", "i"), "3": ("8",), "6": ("9",), "8": ("3",), "9": ("6",),
    "b": ("d", "lb"), "c": ("e",), "d": ("b", "cl", "dl"), "e": ("c",), "g": ("q",), "h": ("lh",),
    "i": ("1", "l"), "k": ("lc",), "l": ("1", "i"), "m": ("n", "nn", "rn"), "n": ("m", "r"),
    "o": ("0",), "q": ("g",), "u": ("v",), "v": ("u",), "w": ("vv",), "rn": ("m",), "cl": ("d",),
}

#: P012 c3: accent homoglyphs for .br names (the registro.br IDN set: à á â ã é ê í ó ô õ ú ü ç).
_GLYPHS_BR: dict[str, tuple[str, ...]] = {
    "a": ("á", "â", "ã", "à"), "e": ("é", "ê"), "i": ("í",), "o": ("ó", "ô", "õ"), "u": ("ú", "ü"), "c": ("ç",),
}

_LATIN_TO_CYRILLIC: dict[str, str] = {
    "a": "а", "b": "ь", "c": "с", "d": "ԁ", "e": "е", "g": "ԍ", "h": "һ", "i": "і", "j": "ј", "k": "к",
    "l": "ӏ", "m": "м", "o": "о", "p": "р", "q": "ԛ", "s": "ѕ", "t": "т", "v": "ѵ", "w": "ԝ", "x": "х", "y": "у",
}

_QWERTY = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5", "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8",
    "o": "0plki9", "p": "lo0", "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy",
    "j": "ikmnhu", "k": "olmji", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_QWERTZ = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7zt5", "7": "8uz6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6zgfr5", "z": "7uhgt6", "u": "8ijhz7", "i": "9okju8",
    "o": "0plki9", "p": "lo0", "a": "qwsy", "s": "edxyaw", "d": "rfcxse", "f": "tgvcdr", "g": "zhbvft", "h": "ujnbgz",
    "j": "ikmnhu", "k": "olmji", "l": "kop", "y": "asx", "x": "ysdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_AZERTY = {
    "1": "2a", "2": "3za1", "3": "4ez2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "a": "2zq1", "z": "3esqa2", "e": "4rdsz3", "r": "5tfde4", "t": "6ygfr5", "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8",
    "o": "0plki9", "p": "lo0m", "q": "zswa", "s": "edxwqz", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy",
    "j": "iknhu", "k": "olji", "l": "kopm", "m": "lp", "w": "sxq", "x": "wsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhj",
}
_KEYBOARDS = (_QWERTY, _QWERTZ, _AZERTY)

#: Combo-squats on .com and the abused TLDs use only the top lure words (bounded growth).
_COMBO_TOP_LURES_OTHER_TLDS = 10

DEFAULT_FUZZERS: tuple[str, ...] = (
    "addition", "bitsquatting", "homoglyph", "hyphenation", "insertion", "omission", "repetition",
    "replacement", "subdomain", "transposition", "vowel-swap", "dictionary", "combo", "tld-swap",
)
OPTIONAL_FUZZERS: tuple[str, ...] = ("cyrillic", "plural", "various")

#: Ranking weights (P012 c5 'top-ranked'): Brazilian phishing patterns first.
FUZZER_WEIGHT: dict[str, int] = {
    "*original": 0, "combo": 90, "homoglyph": 85, "tld-swap": 80, "omission": 72, "transposition": 72,
    "replacement": 70, "repetition": 68, "hyphenation": 62, "vowel-swap": 58, "dictionary": 55,
    "addition": 50, "insertion": 45, "bitsquatting": 40, "subdomain": 35, "cyrillic": 30, "plural": 30,
    "various": 30,
}

FAMILY_OF: dict[str, str] = {
    "combo": "combo", "dictionary": "combo", "tld-swap": "tld-swap", "homoglyph": "homoglyph", "cyrillic": "homoglyph",
    "omission": "typo", "transposition": "typo", "repetition": "typo", "replacement": "typo", "vowel-swap": "typo",
    "hyphenation": "typo",
}
#: Share of a capped selection per family (unused quota flows to the best remaining candidates).
_FAMILY_QUOTA = (("combo", 0.40), ("homoglyph", 0.14), ("tld-swap", 0.13), ("typo", 0.27), ("other", 0.06))


# ----------------------------------------------------------------------- IDNA, folding, split
def idna_ascii(name: Any) -> str | None:
    """IDNA/UTS-46 ASCII form of ``name`` (lower case), or None when it is not a valid name."""
    if not isinstance(name, str) or not name or len(name) > 512:
        return None
    try:
        if _idna is not None:
            return _idna.encode(name, uts46=True).decode("ascii").lower()
        return name.encode("idna").decode("ascii").lower()  # pragma: no cover
    except Exception:  # idna raises several error types: any failure means invalid
        return None


def idna_unicode(name: Any) -> str:
    """Unicode form of an ASCII/punycode name (the input when it cannot be decoded)."""
    if not isinstance(name, str):
        return ""
    try:
        if _idna is not None:
            return _idna.decode(name)
        return name.encode("ascii").decode("idna")  # pragma: no cover
    except Exception:
        return name


def fold(text: Any) -> str:
    """Lower-case, NFKD, combining marks removed (itaú -> itau, ç -> c)."""
    if not isinstance(text, str):
        return ""
    s = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def is_br(tld: str) -> bool:
    """True for 'br' and the second-level .br suffixes (com.br, app.br...)."""
    return tld == "br" or tld.endswith(".br")


def split_domain(fqdn: Any) -> tuple[str, str, str]:
    """(subdomain, label, public suffix) of a host: ``www.itau.com.br`` -> ('www', 'itau', 'com.br').

    Uses the bundled public-suffix list; the dnstwist fallback (second-level 'com', 'net', the
    registro.br categories...) applies when the PSL cannot split the name. Unicode labels are kept.
    """
    d = str(fqdn or "").strip().rstrip(".").lower()
    if not d:
        return "", "", ""
    parts = d.split(".")
    if len(parts) == 1:
        return "", parts[0], ""
    suffix = ""
    try:
        ascii_name = idna_ascii(d) or d
        ps = psl.public_suffix(ascii_name)
        if ps and ps != ascii_name and ascii_name.endswith("." + ps):
            n = ps.count(".") + 1
            suffix = ".".join(parts[-n:])
    except Exception:  # the PSL helper never decides validity here: fall back below
        suffix = ""
    if suffix and len(parts) > suffix.count(".") + 1:
        n = suffix.count(".") + 1
        return ".".join(parts[: -n - 1]), parts[-n - 1], suffix
    if len(parts) == 2:
        return "", parts[0], parts[1]
    if parts[-2] in _COMMON_2LD or ".".join(parts[-2:]) == "br.com":
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    return ".".join(parts[:-2]), parts[-2], parts[-1]


# ----------------------------------------------------------------------- fuzzers (label level)
def _addition(label: str) -> set[str]:
    chars = [chr(i) for i in (*range(48, 58), *range(97, 123))]
    out = {label + ch for ch in chars}
    if "-" in label:
        parts = label.split("-")
        out |= {"-".join(parts[:p]) + ch + "-" + "-".join(parts[p:]) for ch in chars for p in range(1, len(parts))}
    return out


def _bitsquatting(label: str) -> set[str]:
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    out = set()
    for i, c in enumerate(label):
        for mask in (1, 2, 4, 8, 16, 32, 64, 128):
            b = chr(ord(c) ^ mask)
            if b in allowed:
                out.add(label[:i] + b + label[i + 1:])
    return out


def _cyrillic(label: str) -> set[str]:
    c = label
    for lat, cyr in _LATIN_TO_CYRILLIC.items():
        c = c.replace(lat, cyr)
    return set() if any(a == b for a, b in zip(c, label)) else {c}


def _homoglyph(label: str, tld: str) -> set[str]:
    idn = _GLYPHS_BR if is_br(tld) else _GLYPHS_UNICODE
    glyphs = {k: set(_GLYPHS_ASCII.get(k, ())) | set(idn.get(k, ())) for k in set(_GLYPHS_ASCII) | set(idn)}

    def mix(domain: str) -> Iterable[str]:
        for i, c in enumerate(domain):
            for g in glyphs.get(c, ()):
                yield domain[:i] + g + domain[i + 1:]
        for i in range(len(domain) - 1):
            win = domain[i:i + 2]
            for c in {win[0], win[1], win}:
                for g in glyphs.get(c, ()):
                    yield domain[:i] + win.replace(c, g) + domain[i + 2:]

    first = set(mix(label))
    second: set[str] = set()
    for r in first:
        second.update(mix(r))
    return (first | second) - {label}


def _hyphenation(label: str) -> set[str]:
    return {label[:i] + "-" + label[i:] for i in range(1, len(label))}


def _insertion(label: str) -> set[str]:
    out = set()
    for i in range(0, len(label) - 1):
        pre, orig, suf = label[:i], label[i], label[i + 1:]
        for c in (c for kb in _KEYBOARDS for c in kb.get(orig, "")):
            out.add(pre + c + orig + suf)
            out.add(pre + orig + c + suf)
    return out


def _omission(label: str) -> set[str]:
    return {label[:i] + label[i + 1:] for i in range(len(label))}


def _plural(label: str) -> set[str]:
    return {label[:i + 1] + ("es" if label[i] in "sxz" else "s") + label[i + 1:] for i in range(2, len(label) - 2)}


def _repetition(label: str) -> set[str]:
    return {label[:i] + c + label[i:] for i, c in enumerate(label)}


def _replacement(label: str) -> set[str]:
    out = set()
    for i, c in enumerate(label):
        for kb in _KEYBOARDS:
            for r in kb.get(c, ""):
                out.add(label[:i] + r + label[i + 1:])
    return out


def _subdomain(label: str) -> set[str]:
    return {label[:i] + "." + label[i:] for i in range(1, len(label) - 1) if label[i] not in "-." and label[i - 1] not in "-."}


def _transposition(label: str) -> set[str]:
    return {label[:i] + label[i + 1] + label[i] + label[i + 2:] for i in range(len(label) - 1)}


def _vowel_swap(label: str) -> set[str]:
    vowels = "aeiou"
    return {label[:i] + v + label[i + 1:] for i in range(len(label)) if label[i] in vowels for v in vowels}


def _dictionary(label: str, words: Iterable[str]) -> set[str]:
    out = set()
    words = list(words)
    for w in words:
        if not (label.startswith(w) and label.endswith(w)):
            out |= {label + "-" + w, label + w, w + "-" + label, w + label}
    if "-" in label:
        parts = label.split("-")
        for w in words:
            out |= {"-".join(parts[:-1]) + "-" + w, w + "-" + "-".join(parts[1:])}
    return out


def _combo(label: str, lures: Iterable[str]) -> dict[str, int]:
    """P012 c3 combo-squats: {brand}-{word}, {word}-{brand}, {brand}{word} (value = lure rank)."""
    out: dict[str, int] = {}
    for rank_, w in enumerate(lures):
        for cand in (f"{label}-{w}", f"{w}-{label}", f"{label}{w}"):
            out.setdefault(cand, rank_)
    return out


_LABEL_FUZZERS = {
    "addition": _addition, "bitsquatting": _bitsquatting, "cyrillic": _cyrillic, "hyphenation": _hyphenation,
    "insertion": _insertion, "omission": _omission, "plural": _plural, "repetition": _repetition,
    "replacement": _replacement, "subdomain": _subdomain, "transposition": _transposition, "vowel-swap": _vowel_swap,
}


# ----------------------------------------------------------------------- generation and ranking
def _glyph_changes(orig: str, variant: str) -> int:
    if len(orig) == len(variant):
        return sum(1 for a, b in zip(orig, variant) if a != b)
    return 1 + abs(len(orig) - len(variant))


def _score(fuzzer: str, tld: str, lure_rank: int | None = None, base_tld: str | None = None, changes: int = 1) -> int:
    s = FUZZER_WEIGHT.get(fuzzer, 20)
    if base_tld is not None and tld == base_tld:
        s += 3  # the seed's own suffix first (itau-seguranca.com.br before .net.br)
    if changes > 1:
        s -= 8 * (changes - 1)  # single-glyph homoglyphs before double ones
    if is_br(tld):
        s += 6
    if tld in TLD_SWAP_PRIMARY:
        s += 4
    if tld in ABUSED_TLDS:
        s += 3
    if lure_rank is not None:
        s += max(0, 10 - lure_rank // 5)
    return s


def _keyword_labels(seed: str) -> list[str]:
    """Labels of a brand keyword: spaces/punctuation removed, accented and folded forms."""
    raw = re.sub(r"[\s_.'\"/\\]+", "", seed.strip().lower())
    labels = {raw, fold(raw)}
    return sorted(lab for lab in labels if lab and re.fullmatch(r"[\w-]+", lab))


def generate(
    seed: Any,
    fuzzers: Iterable[str] | None = None,
    lures: Iterable[str] = (),
    dictionary: Iterable[str] = (),
    tlds: Iterable[str] | None = None,
    keyword_tlds: Iterable[str] = ("com.br",),
) -> list[dict[str, Any]]:
    """Every valid candidate for a seed domain or brand keyword (P012 c1-c3).

    Deduplicated by ASCII domain (the best-scored fuzzer label is kept); each name passed UTS-46 and
    VALID_FQDN before it is returned. A seed without a dot is a brand keyword, expanded on
    ``keyword_tlds`` (default com.br) in its accented and folded forms. Returns
    ``[{fuzzer, domain (ASCII), domain_unicode, score}]`` (unsorted; see :func:`rank`). The seed itself
    is returned with fuzzer ``'*original'``.
    """
    if not isinstance(seed, str) or not seed.strip():
        return []
    fuzz = tuple(fuzzers) if fuzzers else DEFAULT_FUZZERS
    lure_list = [w for w in (lures or ()) if isinstance(w, str) and w]
    dict_list = [w for w in (dictionary or ()) if isinstance(w, str) and w]
    tld_list = tuple(tlds) if tlds is not None else TLD_SWAP_PRIMARY + TLD_SWAP_EXTRA
    s = idna_unicode(seed.strip().rstrip(".").lower())
    bases: list[tuple[str, str, str]] = []
    if "." not in s:
        for lab in _keyword_labels(s):
            for t in keyword_tlds:
                bases.append(("", lab, t))
    else:
        sub, label, tld = split_domain(s)
        if label and tld:
            bases.append((sub, idna_unicode(label), tld))
    best: dict[str, dict[str, Any]] = {}
    originals = {idna_ascii(".".join(x for x in base if x)) for base in bases}

    def add(fuzzer: str, sub: str, label: str, tld: str, lure_rank: int | None = None, base_tld: str | None = None, changes: int = 1) -> None:
        name = ".".join(x for x in (sub, label, tld) if x)
        ascii_name = idna_ascii(name)
        if not ascii_name or not VALID_FQDN.match(ascii_name):
            return
        if fuzzer != "*original" and ascii_name in originals:
            return  # a fuzzer that gives the seed back (vowel-swap a->a...) is not a candidate
        sc = _score(fuzzer, tld, lure_rank, base_tld, changes)
        cur = best.get(ascii_name)
        if cur is None or sc > cur["score"]:
            best[ascii_name] = {"fuzzer": fuzzer, "domain": ascii_name, "domain_unicode": idna_unicode(ascii_name), "score": sc}

    for sub, label, tld in bases:
        add("*original", sub, label, tld)
        for f in fuzz:
            if f in _LABEL_FUZZERS:
                for v in _LABEL_FUZZERS[f](label):
                    add(f, sub, v, tld, base_tld=tld)
            elif f == "homoglyph":
                for v in _homoglyph(label, tld):
                    add(f, sub, v, tld, base_tld=tld, changes=_glyph_changes(label, v))
            elif f == "dictionary" and dict_list:
                for v in _dictionary(label, dict_list):
                    add(f, sub, v, tld, base_tld=tld)
            elif f == "combo" and lure_list:
                for v, rank_ in _combo(label, lure_list).items():
                    add("combo", sub, v, tld, rank_, base_tld=tld)
                for t in ("com", *TLD_SWAP_PRIMARY):  # top lures on .com and the abused TLDs
                    if t != tld:
                        for v, rank_ in _combo(label, lure_list[:_COMBO_TOP_LURES_OTHER_TLDS]).items():
                            add("combo", sub, v, t, rank_)
            elif f == "tld-swap":
                for t in tld_list:
                    if t != tld:
                        add("tld-swap", sub, label, t)
            elif f == "various":
                if "." in tld:
                    add("various", sub, label, tld.split(".")[-1])
                    add("various", sub, label + tld.replace(".", ""), tld)
                else:
                    add("various", sub, label + tld, tld)
                if tld != "com" and "." not in tld:
                    add("various", sub, label + "-" + tld, "com")
                    add("various", sub, label + tld, "com")
    return list(best.values())


def _rank_key(c: Mapping[str, Any]) -> tuple[int, str]:
    return (-int(c.get("score", 0)), str(c.get("domain", "")))


def rank(candidates: Iterable[Mapping[str, Any]], limit: int = 150, include_original: bool = False) -> tuple[list[dict[str, Any]], bool]:
    """Top-``limit`` candidates (P012 c5: 150 by default, 500 with --preset deep or watch).

    Family quotas keep a capped selection diverse (combo-squats 40 %, homoglyphs 14 %, TLD swaps 13 %,
    typos 27 %, other fuzzers 6 %); inside a family the fuzzers are interleaved by score and unused quota
    flows to the best remaining candidates. Deterministic (score, then name). Returns
    ``(selected, cap_hit)``; ``cap_hit`` is True when candidates were left out.
    """
    pool = [dict(c) for c in candidates if isinstance(c, Mapping) and (include_original or c.get("fuzzer") != "*original")]
    pool.sort(key=_rank_key)
    limit = max(0, int(limit))
    if len(pool) <= limit:
        return pool, False
    groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for c in pool:
        fam = FAMILY_OF.get(str(c.get("fuzzer")), "other")
        groups.setdefault(fam, {}).setdefault(str(c.get("fuzzer")), []).append(c)
    chosen: list[dict[str, Any]] = []
    chosen_set: set[str] = set()
    for fam, share in _FAMILY_QUOTA:
        quota = int(round(limit * share))
        by_fuzzer = groups.get(fam, {})
        order = sorted(by_fuzzer, key=lambda f: _rank_key(by_fuzzer[f][0]))
        taken, i = 0, 0
        while taken < quota and any(i < len(by_fuzzer[f]) for f in order):
            for f in order:
                if taken >= quota:
                    break
                if i < len(by_fuzzer[f]):
                    c = by_fuzzer[f][i]
                    chosen.append(c)
                    chosen_set.add(c["domain"])
                    taken += 1
            i += 1
    for c in pool:  # unused quota: the best remaining candidates
        if len(chosen) >= limit:
            break
        if c["domain"] not in chosen_set:
            chosen.append(c)
            chosen_set.add(c["domain"])
    chosen = chosen[:limit]
    chosen.sort(key=_rank_key)
    return chosen, True


# ----------------------------------------------------------------------- reverse mode (P012 c4)
_CYR_TO_LAT = {v: k for k, v in _LATIN_TO_CYRILLIC.items()}
_SKEL_SINGLE = {"0": "o", "1": "l", "i": "l", "|": "l"}
_SKEL_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))

#: Technique scores of a reverse match (the lure word adds 5).
TECHNIQUE_SCORE: dict[str, int] = {
    "brand-label": 88, "homoglyph": 95, "homoglyph+tld-swap": 92, "tld-swap": 90, "combo": 85, "omission": 80,
    "transposition": 80, "replacement": 78, "repetition": 78, "insertion": 76, "addition": 76, "vowel-swap": 76,
    "bitsquatting": 74, "typo": 70, "hyphenation": 75, "subdomain": 70, "contains-brand": 50,
}
#: Protected-entry sources matched leniently (the analyst's own profile); others (BCB, gov.br,
#: suppliers) are matched strictly: combos need a lure word, edit-distance typos >= 5 characters.
OWN_SOURCES = frozenset({"org_profile"})


def skeleton(label: Any) -> str:
    """Confusable skeleton (a simplified UTS #39): accents folded, Cyrillic look-alikes mapped to
    Latin, 0->o, 1/i/|->l, rn->m, vv->w, cl->d."""
    s = "".join(_CYR_TO_LAT.get(c, c) for c in str(label or "").lower())
    s = fold(s)
    s = "".join(_SKEL_SINGLE.get(c, c) for c in s)
    for a, b in _SKEL_MULTI:
        s = s.replace(a, b)
    return s


def _osa(a: str, b: str, limit: int = 1) -> int:
    """Optimal string alignment distance with early exit above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _typo_kind(q: str, p: str) -> str:
    if len(q) == len(p) - 1:
        return "omission"
    if len(q) == len(p) + 1:
        for i in range(len(q)):
            if q[:i] + q[i + 1:] == p:
                if (i > 0 and q[i] == q[i - 1]) or (i + 1 < len(q) and q[i] == q[i + 1]):
                    return "repetition"
                return "addition" if i == len(q) - 1 else "insertion"
        return "insertion"
    if len(q) != len(p):
        return "typo"
    diff = [i for i in range(len(q)) if q[i] != p[i]]
    if len(diff) == 2 and q[diff[0]] == p[diff[1]] and q[diff[1]] == p[diff[0]]:
        return "transposition"
    if len(diff) == 1:
        a, b = q[diff[0]], p[diff[0]]
        if a in "aeiou" and b in "aeiou":
            return "vowel-swap"
        if bin(ord(a) ^ ord(b)).count("1") == 1:
            return "bitsquatting"
        return "replacement"
    return "typo"


def build_protected_index(protected: Iterable[Mapping[str, Any]] = (), brands: Iterable[Mapping[str, Any]] = ()) -> list[dict[str, Any]]:
    """Precompute protected entries once per run (org_profile domains/brands, BCB DominiosVerificados
    P360, suppliers, gov.br P009). ``protected``: ``[{domain, source, ...}]``; ``brands``:
    ``[{keyword, source, ...}]``. Sources other than ``'org_profile'`` are matched strictly."""
    idx: list[dict[str, Any]] = []
    for p in protected or ():
        if not isinstance(p, Mapping):
            continue
        dom = idna_unicode(str(p.get("domain", "")).strip().rstrip(".").lower())
        if "." not in dom:
            continue
        _sub, label, tld = split_domain(dom)
        if not label or not tld:
            continue
        lab = idna_unicode(label)
        idx.append({
            "entry": dict(p), "registrable": f"{lab}.{tld}", "label": fold(lab), "tld": tld, "skel": skeleton(lab),
            "kind": "domain", "strict": p.get("source") not in OWN_SOURCES,
        })
    for b in brands or ():
        if not isinstance(b, Mapping):
            continue
        kw = fold(re.sub(r"[\s_.'\"/\\]+", "", str(b.get("keyword", "")).strip().lower()))
        if len(kw) >= 3:
            idx.append({
                "entry": dict(b), "registrable": None, "label": kw, "tld": None, "skel": skeleton(kw), "kind": "brand",
                "strict": b.get("source") not in OWN_SOURCES,
            })
    return idx


def _match_one(e: Mapping[str, Any], sub: str, sub_labels: list[str], raw_label: str, lab: str, tld: str, qskel: str, lure_set: set[str]) -> tuple[str | None, str | None]:
    """Technique for one protected entry, or (None, None)."""
    p_label, p_reg, strict = e["label"], e["registrable"], e["strict"]
    if e["kind"] == "domain" and raw_label == p_label and tld != e["tld"]:
        return "tld-swap", None
    if e["kind"] == "brand" and raw_label == p_label:
        return "brand-label", None
    if raw_label != p_label and qskel == e["skel"]:
        return ("homoglyph" if (e["kind"] == "brand" or tld == e["tld"]) else "homoglyph+tld-swap"), None
    if "-" in lab and lab.replace("-", "") == p_label:
        return "hyphenation", None
    if len(p_label) >= (5 if strict else 4) and _osa(qskel, e["skel"]) == 1:
        return _typo_kind(skeleton(lab), e["skel"]), None
    tokens = lab.split("-")
    if len(tokens) > 1 and p_label in tokens:
        lure = next((t for t in tokens if t != p_label and t in lure_set), None)
        if lure or (not strict and len(p_label) >= 4):  # third-party lists and short labels need a lure
            return "combo", lure
    if len(p_label) >= 2 and lab != p_label:
        for t in tokens:
            if t != p_label and t.startswith(p_label) and t[len(p_label):] in lure_set:
                return "combo", t[len(p_label):]
            if t != p_label and t.endswith(p_label) and t[: -len(p_label)] in lure_set:
                return "combo", t[: -len(p_label)]
    if sub_labels:
        if p_reg and ("." + p_reg + ".") in ("." + sub + "."):
            return "subdomain", None
        if len(p_label) >= 4 and p_label in sub_labels:
            return "subdomain", None
    if e["kind"] == "brand" and not strict and len(p_label) >= 4 and any(
        t != p_label and (t.startswith(p_label) or t.endswith(p_label)) for t in tokens
    ):
        return "contains-brand", None  # prefix/suffix only: 'capitaurbano' never matches 'itau'
    return None, None


def reverse_match(domain: Any, index: Iterable[Mapping[str, Any]], lures: Iterable[str] = ()) -> dict[str, Any]:
    """Is ``domain`` (the INPUT) a lookalike of a protected domain/brand? (P012 c4, offline, < 1 s).

    Returns ``{own_asset: entry | None, matches: [{protected, source, technique, score, lure, entry}]}``
    sorted by score. ``own_asset`` is set when the input is a protected registrable domain or a
    subdomain of one (never reported as its own lookalike). Labels shorter than 4 characters and
    third-party lists (BCB, gov.br, suppliers) only match strong techniques: TLD swap, homoglyph,
    hyphenation, a combo with a lure word, subdomain impersonation, or an edit distance of 1 on labels
    of >= 5 characters.
    """
    d = idna_unicode(str(domain or "").strip().rstrip(".").lower())
    if "." not in d:
        return {"own_asset": None, "matches": []}
    sub, label, tld = split_domain(d)
    raw_label = idna_unicode(label).lower()
    lab = fold(raw_label)
    reg = f"{raw_label}.{tld}" if tld else raw_label
    qskel = skeleton(raw_label)
    lure_set = {str(w) for w in (lures or ())}
    sub_labels = [fold(x) for x in sub.split(".") if x] if sub else []
    own: Mapping[str, Any] | None = None
    matches: list[dict[str, Any]] = []
    for e in index or ():
        p_reg = e.get("registrable")
        if e.get("kind") == "domain" and p_reg and (d == p_reg or d.endswith("." + p_reg) or reg == p_reg):
            own = own or e.get("entry")
            continue
        tech, lure = _match_one(e, sub, sub_labels, raw_label, lab, tld, qskel, lure_set)
        if tech:
            entry = e.get("entry") or {}
            matches.append({
                "protected": p_reg or entry.get("keyword"), "source": entry.get("source"), "technique": tech,
                "score": TECHNIQUE_SCORE.get(tech, 60) + (5 if lure else 0), "lure": lure, "entry": entry, "kind": e.get("kind"),
            })
    if own is not None:
        return {"own_asset": dict(own), "matches": []}
    matches.sort(key=lambda m: (-m["score"], 0 if m["kind"] == "domain" else 1, str(m["protected"])))  # domains before keywords
    return {"own_asset": None, "matches": matches}
