"""Traffic Light Protocol (FIRST TLP 2.0) values, parsing, ordering and the per-module ceiling.

* :class:`TLP` orders the five TLP 2.0 labels: CLEAR < GREEN < AMBER < AMBER+STRICT < RED.
* :func:`parse` accepts the TLP 2.0 values, ``TLP:``/``TLP-`` prefixes, ``amber_strict`` /
  ``amber-strict`` and the TLP 1.0 ``white`` (-> CLEAR), case-insensitively.
* :func:`max_tlp` derives the highest TLP a module may receive from its disclosure class, the
  provider trust tier and the publishes/reuses flags (A2, P332 cond 7). Modules never set it by hand.
"""

from __future__ import annotations

import enum
from typing import Any

#: Canonical string values, lowest first.
TLP_VALUES: tuple[str, ...] = ("clear", "green", "amber", "amber+strict", "red")

_COLORS = {0: "#FFFFFF", 1: "#33FF00", 2: "#FFC000", 3: "#FFC000", 4: "#FF2B2B"}


class TLP(enum.IntEnum):
    """FIRST TLP 2.0 label; the integer value gives the order (higher = more restricted)."""

    CLEAR = 0
    GREEN = 1
    AMBER = 2
    AMBER_STRICT = 3
    RED = 4

    @property
    def value_str(self) -> str:
        """Canonical setting/JSON value: 'clear' | 'green' | 'amber' | 'amber+strict' | 'red'."""
        return TLP_VALUES[int(self)]

    @property
    def label(self) -> str:
        """Marking text, e.g. 'TLP:AMBER+STRICT'."""
        return "TLP:" + self.value_str.upper()

    @property
    def file_tag(self) -> str:
        """File-name safe marking, e.g. 'TLP-AMBER+STRICT' (report names: <case>.TLP-AMBER.html)."""
        return "TLP-" + self.value_str.upper()

    @property
    def color(self) -> str:
        """FIRST TLP 2.0 colour (hex, meant for display on a black background)."""
        return _COLORS[int(self)]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value_str


_ALIASES = {
    "clear": TLP.CLEAR,
    "white": TLP.CLEAR,
    "green": TLP.GREEN,
    "amber": TLP.AMBER,
    "amber+strict": TLP.AMBER_STRICT,
    "amber_strict": TLP.AMBER_STRICT,
    "amber-strict": TLP.AMBER_STRICT,
    "red": TLP.RED,
}


def parse(value: Any) -> TLP:
    """Parse a TLP value (TLP member, 0-4, or text such as 'amber', 'TLP:AMBER+STRICT', 'white').

    Raises ValueError for anything else (an empty value included).
    """
    if isinstance(value, TLP):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return TLP(value)
        except ValueError:
            raise ValueError(f"invalid TLP value: {value!r}") from None
    if not isinstance(value, str):
        raise ValueError(f"invalid TLP value: {value!r}")
    text = value.strip().lower()
    for prefix in ("tlp:", "tlp-"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    found = _ALIASES.get(text)
    if found is None:
        raise ValueError(f"invalid TLP value: {value!r} (expected one of {', '.join(TLP_VALUES)})")
    return found


def highest(*values: Any) -> TLP:
    """The most restrictive of the given values (None/'' are ignored; nothing given -> CLEAR)."""
    best = TLP.CLEAR
    for value in values:
        if value is None or value == "":
            continue
        current = parse(value)
        if current > best:
            best = current
    return best


def max_tlp(disclosure: str, tier: str, *, publishes_queries: bool, reuses_queries: bool) -> TLP | None:
    """Highest TLP a module may receive (A2, P332 cond 7). None = never (it publishes lookups).

    * publishes_queries -> None (team rule 7: never receives an investigated value);
    * disclosure 'none' / 'internal' -> RED;
    * 'target' -> AMBER (RED only for verified own assets, see :func:`max_tlp_for_target`);
    * 'third_party': reuses_queries or tier 'unknown' -> GREEN; 'community' -> AMBER;
      'trusted' -> AMBER+STRICT.
    """
    if publishes_queries:
        return None
    disclosure = (disclosure or "").strip().lower()
    if disclosure in ("none", "internal"):
        return TLP.RED
    if disclosure == "target":
        return TLP.AMBER
    if disclosure == "third_party":
        if reuses_queries:
            return TLP.GREEN
        tier = (tier or "").strip().lower()
        if tier == "trusted":
            return TLP.AMBER_STRICT
        if tier == "community":
            return TLP.AMBER
        return TLP.GREEN
    raise ValueError(f"unknown disclosure class {disclosure!r} (expected none, internal, third_party or target)")


def max_tlp_for_target(own_asset_verified: bool, third_party_hosted: bool) -> TLP:
    """Ceiling for target contact: RED only on verified own assets that are not third-party hosted."""
    return TLP.RED if own_asset_verified and not third_party_hosted else TLP.AMBER
