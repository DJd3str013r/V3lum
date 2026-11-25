"""Banner and boot sequence."""

from __future__ import annotations

import random
import time

from rich.console import Console
from rich.text import Text

from v3lum import __codename__, __version__

LOGO = [
    "██╗   ██╗██████╗ ██╗     ██╗   ██╗███╗   ███╗",
    "██║   ██║╚════██╗██║     ██║   ██║████╗ ████║",
    "██║   ██║ █████╔╝██║     ██║   ██║██╔████╔██║",
    "╚██╗ ██╔╝ ╚═══██╗██║     ██║   ██║██║╚██╔╝██║",
    " ╚████╔╝ ██████╔╝███████╗╚██████╔╝██║ ╚═╝ ██║",
    "  ╚═══╝  ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝",
]
_GRADIENT = ["#00ff9f", "#00f0b5", "#00d7ff", "#6f9bff", "#9a6bff", "#bd5cff"]
_GLITCH = "▓▒░█▚▞▙▟#$%&@!?/\\<>"


def logo_text(glitch: float = 0.0, seed: int | None = None) -> Text:
    rnd = random.Random(seed)
    out = Text()
    for line, color in zip(LOGO, _GRADIENT):
        chars = []
        for ch in line:
            if glitch and ch not in " " and rnd.random() < glitch:
                chars.append(rnd.choice(_GLITCH))
            else:
                chars.append(ch)
        out.append("  " + "".join(chars) + "\n", style=f"bold {color}")
    return out


def tagline() -> Text:
    t = Text("  ")
    t.append(f"{__codename__}", style="v.accent")
    t.append("  ::  ", style="v.ghost")
    t.append("osint · cti · recon multikit", style="v.text")
    t.append("  ::  ", style="v.ghost")
    t.append(f"v{__version__}", style="v.dim")
    return t


def print_banner(console: Console, *, fx: bool = True, status: list[tuple[str, str, str]] | None = None) -> None:
    """Print the logo (with a short glitch-in if fx and a TTY) and an optional status line."""
    if fx and console.is_terminal and not console.no_color:
        try:
            for g in (0.35, 0.18, 0.06):
                console.print(logo_text(g, seed=int(g * 100)), end="")
                time.sleep(0.05)
                console.control(*[_cursor_up() for _ in range(len(LOGO))])
        except Exception:  # pragma: no cover - cosmetic only
            pass
    console.print(logo_text(0.0), end="")
    console.print(tagline())
    if status:
        line = Text("  ")
        for label, value, style in status:
            line.append("[", style="v.ghost")
            line.append(f"{label}:", style="v.dim")
            line.append(f"{value}", style=style)
            line.append("] ", style="v.ghost")
        console.print(line)
    console.print()


def _cursor_up():
    from rich.control import Control

    return Control.move(0, -1)
