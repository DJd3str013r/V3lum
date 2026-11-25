"""Color theme and console factory.

Dark-web look, but readable first: every color carries meaning and every status has a
text label too (works with NO_COLOR / monochrome terminals and screen readers).
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.theme import Theme

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
        "risk.clean": f"bold {PALETTE['neon']}",
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
        "status.blocked": PALETTE["magenta"],
        "status.unavailable": PALETTE["ghost"],
        "status.not_run": PALETTE["ghost"],
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
    "blocked": "[#]",
    "unavailable": "[-]",
    "not_run": "[ ]",
}


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
