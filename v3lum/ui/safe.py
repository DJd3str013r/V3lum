"""Safe rendering of untrusted data (AR13): the one place that neutralises module-derived text.

Everything a module, a provider or a stored case hands to a renderer (finding titles and
descriptions, attribute values, entity displays, reasons, link labels, page titles...) is untrusted:
a page title of ``[/bold]`` aborted the v1 report with a rich ``MarkupError`` and ESC/OSC sequences
in a banner reached the analyst's terminal. The helpers below are shared by the terminal
(``ui/render.py``, ``ui/live.py``) and the report writers (``report/summary.py`` now, HTML/Markdown in
wave 4):

* :func:`safe_text` - ``rich.markup.escape`` of the value with C0/C1 control characters removed
  (newline and tab kept): for every *markup* context (a ``str`` handed to ``console.print``, a table
  cell, a panel or table title). Bidirectional override/isolate controls (U+202A-U+202E,
  U+2066-U+2069) and bidi marks (U+061C, U+200E, U+200F), which reorder the rest of a line ('Trojan
  Source' spoofing), are removed as well, and U+2028/U+2029 become spaces.
* :func:`clean_text` - the same character removal without markup escaping: for media that escape
  their own syntax and for :class:`rich.text.Text` objects (never parsed as markup).
* :func:`safe_rich` - a :class:`rich.text.Text` built from :func:`clean_text` (the Text form of
  :func:`safe_text`: the same characters are removed and markup is never interpreted).
* :func:`display_text` - :func:`clean_text` plus every valid CPF inside the text masked unless
  ``show_personal`` (AR24): for module-derived free text (finding titles, descriptions, criteria,
  attribute values, notes, errors, log lines) - a module or an engine note quoting a CPF never
  prints it in full on the terminal.
* :func:`safe_href` - the URL when it may become a link (http/https only, no whitespace, control,
  quote or angle-bracket characters, no backslash, no userinfo), else None. ``javascript:``,
  ``data:``, ``file:``, ``vbscript:`` and every other scheme are refused. HTML/Markdown anchors and
  terminal hyperlinks use it.
* :func:`defang_display` - ``hxxps://evil[.]com`` for entities tagged malicious/phishing/c2/suspicious
  (and the other hostile tags of the policy's GUARD-01: phishing_kit_exfil, crypto_scam, fraud,
  hijacked_netblock): the display is non-clickable. ``no_defang=True`` (``--no-defang``) shows the
  value as it is. JSON/STIX exports never call it: they stay raw.
* :func:`entity_display` - the masked display of an entity (``entities.display_value``: CPF
  ``***.456.789-**`` unless ``show_personal``), personal-form EU VAT numbers masked (AR24 'other
  national ids'), valid CPFs inside text-blob/file/e-mail-header displays masked
  (:func:`mask_cpf_in_text`), defanged when hostile (and URLs always, unless ``no_defang``: the investigated URL
  is never a clickable link, P311 cond 8), control characters removed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from rich.markup import escape as _escape
from rich.text import Text

from v3lum.core import entities as _entities
from v3lum.core import validators as _validators
from v3lum.core.entities import EntityType

__all__ = [
    "DEFANG_TAGS",
    "DEFANG_TYPES",
    "HREF_SCHEMES",
    "MAX_HREF",
    "clean_text",
    "defang_display",
    "display_text",
    "entity_display",
    "is_hostile",
    "mask_cpf_in_text",
    "mask_personal_vat",
    "safe_href",
    "safe_rich",
    "safe_text",
]

#: Entity/finding tags that make an entity display defanged and non-clickable (AR13: malicious,
#: phishing, c2, suspicious; the other GUARD-01 hostile tags count the same way).
DEFANG_TAGS: frozenset[str] = frozenset({
    "malicious", "phishing", "c2", "suspicious", "phishing_kit_exfil", "crypto_scam", "fraud", "hijacked_netblock",
})
#: Entity types whose display can be defanged (host-bearing values).
DEFANG_TYPES: frozenset[EntityType] = frozenset({
    EntityType.DOMAIN, EntityType.URL, EntityType.IPV4, EntityType.IPV6, EntityType.EMAIL, EntityType.CIDR, EntityType.ONION,
})
#: The only schemes :func:`safe_href` accepts.
HREF_SCHEMES: frozenset[str] = frozenset({"http", "https"})
#: Longer URLs never become links.
MAX_HREF = 8192

# C0 controls except TAB (\x09) and LF (\x0a), DEL, C1 controls, bidi marks (ALM, LRM, RLM) and
# bidi embedding/override/isolate controls.
_CONTROL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_LINE_SEP_RE = re.compile("[  ]")
# characters that never belong in a link target (whitespace, controls, quotes, angle brackets,
# backticks, backslashes: browsers read '\' as '/', which can move the host)
_HREF_BAD_RE = re.compile(r"[\s\x00-\x1f\x7f-\x9f\"'<>`\\‪-‮⁦-⁩  ]")

# a CPF written inside free text (11 digits, optionally punctuated 000.000.000-00), not part of a longer
# number; a URL path segment counts ('/v1/52998224725/'), a dotted quad or a longer id does not
_CPF_IN_TEXT_RE = re.compile(r"(?<![\d.\-])(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?![\d\-]|\.\d)")
#: Entity types whose display is free text: valid CPFs inside it are masked unless show_personal.
_FREE_TEXT_TYPES: frozenset[EntityType] = frozenset({EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS})

#: EU VAT numbers whose national part is a natural person's identifier (birth number, EGN, DNI/NIE,
#: personal code, personnummer): masked unless show_personal (AR24 'other national ids').
_PERSONAL_VAT: dict[str, Any] = {
    "CZ": lambda n: len(n) in (9, 10),  # rodne cislo (8 digits = legal entity)
    "BG": lambda n: len(n) == 10,  # EGN / PNF (9 digits = legal entity)
    "ES": lambda n: bool(n) and (n[0].isdigit() or n[0] in "XYZKLM"),  # DNI, NIE, special NIF of individuals
    "LV": lambda n: bool(n) and n[0] in "0123",  # personal code (legal entities start with 4-9)
    "SE": lambda n: len(n) == 12 and n[2] in "01",  # personnummer-based (organisation numbers: 3rd digit >= 2)
}


def clean_text(value: Any) -> str:
    """``str(value)`` with C0/C1 control characters (newline and tab kept), DEL and bidi
    override/isolate controls removed and U+2028/U+2029 turned into spaces. None -> ''.

    Use it for :class:`rich.text.Text` objects and for media that escape their own syntax (the HTML
    and Markdown writers); markup strings take :func:`safe_text`."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL_RE.sub("", text)
    return _LINE_SEP_RE.sub(" ", text)


def safe_text(value: Any) -> str:
    """``rich.markup.escape(str(value))`` with control characters removed first (see
    :func:`clean_text`): safe inside any rich markup string. Removal comes before escaping, so a
    control character can never hide a tag from the escaper (``'[\\x00bold]'`` stays literal)."""
    return _escape(clean_text(value))


def safe_rich(value: Any, style: str = "") -> Text:
    """A :class:`rich.text.Text` of the value: the Text form of :func:`safe_text` (same characters
    removed; a Text is never parsed as markup, so nothing needs escaping)."""
    return Text(clean_text(value), style=style)


def display_text(value: Any, *, show_personal: bool = False) -> str:
    """Module-derived free text for display: :func:`clean_text`, then every *valid* CPF in it masked
    (``***.456.789-**``, :func:`mask_cpf_in_text`) unless ``show_personal`` (AR24: the full CPF
    never reaches a screen or report the analyst did not unmask). No markup escaping (wrap with
    :func:`safe_text`, or use a :class:`rich.text.Text`)."""
    text = clean_text(value)
    return text if show_personal else mask_cpf_in_text(text)


def safe_href(url: Any) -> str | None:
    """The URL when it may become a clickable link (anchor, Markdown link, terminal hyperlink),
    else None.

    Only ``http``/``https`` URLs with a host qualify; ``javascript:``, ``data:``, ``file:``,
    ``vbscript:``, scheme-relative and every other form are refused, as are URLs carrying
    whitespace, control, quote, angle-bracket, backtick or backslash characters, userinfo
    (``https://bank.example@evil.example/``) or more than :data:`MAX_HREF` characters. The accepted
    URL is returned unchanged (surrounding whitespace stripped)."""
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text or len(text) > MAX_HREF or _HREF_BAD_RE.search(text):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in HREF_SCHEMES or not parts.netloc or not host:
        return None
    if "@" in parts.netloc:
        return None
    return text


def _etype(etype: Any) -> EntityType | None:
    if isinstance(etype, EntityType):
        return etype
    try:
        return EntityType(str(etype))
    except ValueError:
        return None


def is_hostile(tags: Iterable[Any] | None) -> bool:
    """Do these tags make an entity hostile for display (any of :data:`DEFANG_TAGS`)?"""
    if not tags:
        return False
    if isinstance(tags, str):
        tags = (tags,)
    return any(str(t) in DEFANG_TAGS for t in tags)


def defang_display(value: Any, etype: Any, tags: Iterable[Any] | None = (), *, no_defang: bool = False, force: bool = False) -> str:
    """The display of a value, defanged (``hxxps://evil[.]com/x``, ``evil[.]com``, ``1[.]2[.]3[.]4``)
    when ``tags`` hold a hostile tag (:data:`DEFANG_TAGS`) - or when ``force`` - and the entity type
    bears a host (:data:`DEFANG_TYPES`; an unknown type string is defanged too). ``no_defang=True``
    (``--no-defang``) returns the value unchanged; JSON/STIX exports never call this function."""
    text = "" if value is None else str(value)
    if no_defang or not text:
        return text
    et = _etype(etype)
    if et is not None and et not in DEFANG_TYPES:
        return text
    if force or is_hostile(tags):
        return _entities.defang(text)
    return text


def mask_personal_vat(value: Any) -> str:
    """An EU VAT number whose national part is a natural person's identifier (CZ birth numbers, BG
    EGN, ES DNI/NIE, LV personal codes, SE personnummer-based numbers) with every character but the
    country prefix and the last three replaced by '*' (``CZ*******234``); company forms unchanged."""
    text = "" if value is None else str(value)
    country, number = text[:2].upper(), text[2:]
    test = _PERSONAL_VAT.get(country)
    if test is None or not number:
        return text
    try:
        personal = bool(test(number))
    except (IndexError, TypeError, ValueError):
        personal = True  # an unreadable personal-form candidate stays masked
    if not personal:
        return text
    keep = 3 if len(number) > 4 else 1
    return country + "*" * (len(number) - keep) + number[-keep:]


def mask_cpf_in_text(value: Any) -> str:
    """Free text with every *valid* CPF (check digits verified offline, team rule 4) replaced by its
    masked form ``***.456.789-**``; other numbers are left alone. Used for text-blob, file-name and
    e-mail-header displays (an analyst-typed text shown back on the first screen, AR24)."""
    text = "" if value is None else str(value)
    if not text:
        return text

    def _sub(match: re.Match[str]) -> str:
        raw = match.group(1)
        return _entities.mask_cpf(raw) if _validators.cpf_valid(raw) else raw

    return _CPF_IN_TEXT_RE.sub(_sub, text)


#: Types whose display ``entities.display_value`` masks: if it ever fails, the fallback stays masked.
_MASKED_TYPES: frozenset[EntityType] = frozenset({EntityType.CPF, EntityType.VIN, EntityType.PIX_BRCODE}) | frozenset(_entities.SECRET_TYPES)


def _masked_fallback(et: EntityType, raw: str, show_personal: bool) -> str:
    """The display when ``entities.display_value`` raised: fail closed for masked types."""
    if et in _entities.SECRET_TYPES:
        return f"*** ({et.value})"
    if et is EntityType.CPF:
        return raw if show_personal else _entities.mask_cpf(raw)
    if et in _MASKED_TYPES and not show_personal:
        return f"*** ({et.value})"
    return raw if show_personal else mask_cpf_in_text(raw)


def entity_display(
    etype: Any,
    value: Any,
    *,
    show_personal: bool = False,
    tags: Iterable[Any] | None = (),
    no_defang: bool = False,
    defang_urls: bool = True,
) -> str:
    """The terminal/report display of an entity value.

    ``entities.display_value`` masks CPF (``***.456.789-**``), VIN, secrets and the CPF key of a
    PIX BR Code unless ``show_personal`` (the caller records the unmasked view); personal-form EU VAT
    numbers are masked the same way (:func:`mask_personal_vat`); hostile entities are defanged
    (:func:`defang_display`) and URLs are always defanged when ``defang_urls`` (the investigated URL
    is never a clickable link, P311 cond 8), unless ``no_defang``. Control characters are removed;
    markup is not escaped (wrap with :func:`safe_text` for markup strings)."""
    raw = "" if value is None else str(value)
    et = _etype(etype)
    if et is None:
        display = raw if show_personal else mask_cpf_in_text(raw)  # unknown type: still no full CPF
    else:
        if et in _FREE_TEXT_TYPES and not show_personal:
            raw = mask_cpf_in_text(raw)  # before display_value shortens the text (no half CPF left)
        try:
            display = _entities.display_value(et, raw, show_personal=show_personal)
        except Exception:  # noqa: BLE001 - a display problem must never break a report
            display = _masked_fallback(et, raw, show_personal)
        if et is EntityType.EU_VAT and not show_personal:
            display = mask_personal_vat(display)
        elif et in _FREE_TEXT_TYPES and not show_personal:
            display = mask_cpf_in_text(display)
    force = bool(defang_urls and et is EntityType.URL)
    return clean_text(defang_display(display, et if et is not None else str(etype or ""), tags, no_defang=no_defang, force=force))
