"""Decentralised command registry of the CLI and the interactive shell (AR15, WP13).

Operator commands live in their own modules, ``v3lum/commands/<name>.py``, and register themselves
with the :func:`command` decorator::

    from v3lum.commands import command

    @command("cases", "stored investigations", aliases=("case",))
    class Cases:
        @staticmethod
        def add_arguments(parser):          # an argparse sub-parser of `v3lum cases`
            parser.add_argument("case_id", nargs="?")

        @staticmethod
        def run(args, app, console) -> int:  # the exit code (0 = success)
            ...
            return 0

:func:`load_commands` imports every ``v3lum.commands.<module>`` (modules whose name starts with
``_`` are skipped). An import error never breaks the CLI: it is recorded in :func:`load_errors` (shown
by ``v3lum doctor``) and that module's commands are simply absent. ``v3lum.cli.build_parser()`` adds
one sub-parser per registered command (``CommandSpec.add_arguments``) and ``v3lum.cli.dispatch()``
routes it to ``CommandSpec.run(args, app, console)``; the shell lists registered commands in its
command table and completion.

Names: lower-case ``^[a-z][a-z0-9-]{1,31}$``, unique across commands and aliases, and never one of
the commands the CLI keeps inline (:data:`INLINE_COMMANDS`).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("v3lum.commands")

__all__ = [
    "COMMANDS",
    "INLINE_COMMANDS",
    "CommandError",
    "CommandSpec",
    "command",
    "load_commands",
    "load_errors",
    "lookup",
    "note_error",
    "register",
]

#: Commands implemented inline by ``v3lum/cli.py`` (and the shell built-ins): a registered command
#: may not take one of these names or aliases.
INLINE_COMMANDS: frozenset[str] = frozenset({
    "version", "detect", "run", "scan", "modules", "info", "extract", "feedback", "cache", "config", "shell",
    # shell built-ins
    "help", "set", "show", "clear", "exit", "quit", "history", "paste",
})

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


class CommandError(ValueError):
    """A command that cannot be registered (bad name, duplicate, missing callable)."""


@dataclass(frozen=True)
class CommandSpec:
    """One registered operator command.

    ``add_arguments(parser) -> None`` declares the command's arguments on its argparse sub-parser;
    ``run(args, app, console) -> int`` executes it (``app`` is the ``v3lum.app.App``, ``console`` the
    rich console) and returns the exit code. ``aliases`` are extra sub-command names. ``module`` is
    the defining module (filled by :func:`command`), ``description`` the long help (default: the
    docstring of the decorated class).
    """

    name: str
    help: str
    add_arguments: Callable[[Any], None]
    run: Callable[[Any, Any, Any], int]
    aliases: tuple[str, ...] = ()
    module: str = field(default="", compare=False)
    description: str = field(default="", compare=False)

    @property
    def names(self) -> tuple[str, ...]:
        """The name followed by its aliases."""
        return (self.name, *self.aliases)


#: name -> CommandSpec of every registered command (aliases are not keys; see :func:`lookup`).
COMMANDS: dict[str, CommandSpec] = {}
_ERRORS: dict[str, str] = {}
_LOCK = threading.RLock()


def _check_name(name: Any, what: str) -> str:
    text = str(name or "")
    if not _NAME_RE.match(text):
        raise CommandError(f"invalid {what} {text!r}: lower-case letters, digits and '-' (2-32 characters, starting with a letter)")
    if text in INLINE_COMMANDS:
        raise CommandError(f"{what} {text!r} is an inline CLI/shell command and cannot be registered")
    return text


def register(spec: CommandSpec) -> CommandSpec:
    """Add ``spec`` to :data:`COMMANDS` (validated). Re-registering a name from the same module
    (a module reload) replaces it; a name or alias taken by another module raises CommandError."""
    if not isinstance(spec, CommandSpec):
        raise CommandError(f"expected a CommandSpec, got {type(spec).__name__}")
    name = _check_name(spec.name, "command name")
    aliases = tuple(_check_name(a, "command alias") for a in spec.aliases)
    if name in aliases or len(set(aliases)) != len(aliases):
        raise CommandError(f"command {name!r}: duplicate alias")
    if not str(spec.help or "").strip():
        raise CommandError(f"command {name!r}: a one-line help text is required")
    if not callable(spec.add_arguments) or not callable(spec.run):
        raise CommandError(f"command {name!r}: add_arguments and run must be callable")
    with _LOCK:
        for other in COMMANDS.values():
            if other.name == name and other.module == spec.module:
                continue  # the same module re-registers (reload)
            clash = set(other.names) & set(spec.names)
            if clash:
                where = f" (registered by {other.module})" if other.module else ""
                raise CommandError(f"command name {sorted(clash)[0]!r} is already taken by {other.name!r}{where}")
        COMMANDS[name] = spec
    return spec


def command(name: str, help: str, *, aliases: tuple[str, ...] | list[str] = ()) -> Callable[[type], type]:
    """Class decorator registering a command whose class exposes static ``add_arguments(parser)``
    and ``run(args, app, console) -> int``. The class gets ``spec`` (its CommandSpec) and is returned
    unchanged otherwise."""

    def decorate(cls: type) -> type:
        add = getattr(cls, "add_arguments", None)
        run = getattr(cls, "run", None)
        if not callable(add) or not callable(run):
            raise CommandError(f"command {name!r}: {getattr(cls, '__name__', cls)!r} must define static add_arguments(parser) and run(args, app, console)")
        doc = (getattr(cls, "__doc__", "") or "").strip()
        spec = CommandSpec(
            name=name,
            help=help,
            add_arguments=add,
            run=run,
            aliases=tuple(aliases or ()),
            module=str(getattr(cls, "__module__", "") or ""),
            description=doc,
        )
        register(spec)
        try:
            cls.spec = spec  # type: ignore[attr-defined]
        except (AttributeError, TypeError):  # pragma: no cover - exotic classes with __slots__
            pass
        return cls

    return decorate


def _module_names() -> list[str]:
    try:
        return sorted(m.name for m in pkgutil.iter_modules(__path__) if not m.name.startswith("_"))
    except Exception as exc:  # noqa: BLE001 - a broken package path never breaks the CLI
        _ERRORS["<package>"] = f"{type(exc).__name__}: {exc}"
        return []


def load_commands() -> dict[str, CommandSpec]:
    """Import every ``v3lum.commands.<module>`` once and return a copy of :data:`COMMANDS`.

    Import errors (syntax errors, missing optional packages, registration conflicts) are recorded
    in :func:`load_errors` - never raised: the CLI keeps working without that module's commands.
    Calling it again imports only modules that were added or failed before.
    """
    with _LOCK:
        for mod in _module_names():
            qualified = f"{__name__}.{mod}"
            try:
                importlib.import_module(qualified)
            except Exception as exc:  # noqa: BLE001 - recorded for doctor, never fatal
                _ERRORS[mod] = f"{type(exc).__name__}: {exc}"
                log.warning("command module %s failed to load: %s", qualified, exc)
            else:
                _ERRORS.pop(mod, None)
        return dict(COMMANDS)


def load_errors() -> dict[str, str]:
    """module name -> error text of the command modules that failed to import or to declare their
    arguments (``v3lum doctor``)."""
    with _LOCK:
        return dict(_ERRORS)


def note_error(module: str, text: str) -> None:
    """Record a problem of a command module found after its import (e.g. ``add_arguments`` raised
    while the CLI parser was built): the command is left out and doctor lists the error."""
    with _LOCK:
        _ERRORS[str(module or "<unknown>")] = str(text)


def lookup(name: str) -> CommandSpec | None:
    """The CommandSpec registered under ``name`` or one of its aliases (None when unknown)."""
    with _LOCK:
        spec = COMMANDS.get(name)
        if spec is not None:
            return spec
        for candidate in COMMANDS.values():
            if name in candidate.aliases:
                return candidate
    return None
