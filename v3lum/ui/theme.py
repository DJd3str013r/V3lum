"""Color theme and console factory.

Dark-web look, but readable first: every color carries meaning and every status has a
text label too (works with NO_COLOR / monochrome terminals and screen readers).

TLP markings use the FIRST TLP 2.0 colours on black (styles ``tlp.clear``, ``tlp.green``,
``tlp.amber``, ``tlp.amber_strict``, ``tlp.red``; :func:`tlp_style` maps a TLP value to its style);
the ``quota`` status has its own style and icon; readings ``risk.no_findings`` and
``risk.inconclusive`` replace the v1 ``risk.clean`` on screen (the style stays for old callers).
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.theme import Theme

from v3lum.core import tlp as _tlp

PALETTE = {
    "neon": "#00ff9f",  # primary / ok
    "acid": "#b4ff39",  # secondary green
    "violet": "#bd5cff",  # accent
    "magenta": "#ff3caa",  # glitch accent
    "cyan": "#00d7ff",  # info
    "amber": "#ffb000",  # warning / medium
    "orange": "#ff6b2b",  # high
    "blood": "#ff2e4d",  # critical / error
    "steel": "#7d8b94",  # secondary text
    "ghost": "#4a555c",  # very dim
    "bone": "#d6e2e4",  # main text
}

THEME = Theme(
    {
        "v.title": f"bold {PALETTE['neon']}",
        "v.accent": f"bold {PALETTE['violet']}",
        "v.glitch": PALETTE["magenta"],
        "v.text": PALETTE["bone"],
        "v.dim": PALETTE["steel"],
        "v.ghost": PALETTE["ghost"],
        "v.ok": f"bold {PALETTE['neon']}",
        "v.info": PALETTE["cyan"],
        "v.warn": f"bold {PALETTE['amber']}",
        "v.err": f"bold {PALETTE['blood']}",
        "v.entity": PALETTE["cyan"],
        "v.type": PALETTE["violet"],
        "v.module": PALETTE["acid"],
        "v.url": f"underline {PALETTE['cyan']}",
        "v.prompt": f"bold {PALETTE['neon']}",
        "sev.info": PALETTE["cyan"],
        "sev.low": PALETTE["acid"],
        "sev.medium": f"bold {PALETTE['amber']}",
        "sev.high": f"bold {PALETTE['orange']}",
        "sev.critical": f"bold white on {PALETTE['blood']}",
        "risk.clean": f"bold {PALETTE['neon']}",  # v1 name, kept for old callers (never printed as a word)
        "risk.no_findings": f"bold {PALETTE['bone']}",
        "risk.inconclusive": f"bold {PALETTE['amber']}",
        "risk.low": f"bold {PALETTE['acid']}",
        "risk.medium": f"bold {PALETTE['amber']}",
        "risk.high": f"bold {PALETTE['orange']}",
        "risk.critical": f"bold white on {PALETTE['blood']}",
        "status.ok": PALETTE["neon"],
        "status.empty": PALETTE["steel"],
        "status.error": PALETTE["blood"],
        "status.skipped": PALETTE["ghost"],
        "status.needs_key": PALETTE["amber"],
        "status.rate_limited": PALETTE["amber"],
        "status.quota": PALETTE["amber"],
        "status.blocked": PALETTE["magenta"],
        "status.unavailable": PALETTE["ghost"],
        "status.not_run": PALETTE["ghost"],
        "conf.confirmed": f"bold {PALETTE['bone']}",
        "conf.probable": PALETTE["bone"],
        "conf.possible": PALETTE["steel"],
        "v.defanged": PALETTE["steel"],
        # FIRST TLP 2.0 colours on black (tlp.TLP.color)
        "tlp.clear": f"bold {_tlp.TLP.CLEAR.color} on #000000",
        "tlp.green": f"bold {_tlp.TLP.GREEN.color} on #000000",
        "tlp.amber": f"bold {_tlp.TLP.AMBER.color} on #000000",
        "tlp.amber_strict": f"bold {_tlp.TLP.AMBER_STRICT.color} on #000000",
        "tlp.red": f"bold {_tlp.TLP.RED.color} on #000000",
    }
)

SEVERITY_ICON = {"info": "·", "low": "▪", "medium": "▲", "high": "◆", "critical": "☠"}
STATUS_ICON = {
    "ok": "[+]",
    "empty": "[~]",
    "error": "[x]",
    "skipped": "[-]",
    "needs_key": "[k]",
    "rate_limited": "[!]",
    "quota": "[$]",
    "blocked": "[#]",
    "unavailable": "[-]",
    "not_run": "[ ]",
}
#: Text icons of the confidence labels (P322): every finding shows one.
CONFIDENCE_ICON = {"confirmed": "●", "probable": "◐", "possible": "○"}


def tlp_style(value: object) -> str:
    """The theme style of a TLP value ('amber+strict' -> 'tlp.amber_strict'); an unreadable value gets
    the RED style (fail closed, like the marking itself)."""
    try:
        return "tlp." + _tlp.parse(value).value_str.replace("+", "_")
    except ValueError:
        return "tlp.red"


def risk_style(level: object) -> str:
    """The theme style of a reading ('no findings' -> 'risk.no_findings', 'inconclusive' ->
    'risk.inconclusive', v1 'clean' -> 'risk.no_findings')."""
    text = str(level or "").strip().lower().replace(" ", "_")
    if text in ("", "clean", "none"):
        text = "no_findings"
    return f"risk.{text}" if text in ("no_findings", "inconclusive", "low", "medium", "high", "critical") else "v.text"


def make_console(no_color: bool = False, *, stderr: bool = False, width: int | None = None) -> Console:
    no_color = no_color or bool(os.environ.get("NO_COLOR"))
    return Console(
        theme=THEME,
        no_color=no_color,
        highlight=False,
        stderr=stderr,
        width=width,
        soft_wrap=False,
        emoji=False,
        force_terminal=None if sys.stdout.isatty() else False,
    )
