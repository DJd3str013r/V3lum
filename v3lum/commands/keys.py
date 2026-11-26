"""``v3lum keys``: API keys of the key registry (list / set / unset), with their recorded plan.

Keys come from ``config.key_registry()``: the legacy ``KNOWN_KEYS`` table merged with the ``keys``
blocks of the provider fragments (e.g. ``misp``, ``opencti``) and their environment aliases, plus
every key a module declares and every key stored in ``config.json``. Values are never printed in
full (``config.mask``) and are registered with the central redactor when loaded or set.

``keys set <name> [value] --plan business|free`` records the key's plan in the setting
``key_plans`` (A1: a 'key-terms' source runs under the corporate licence profile only when the key
that unlocks it is recorded with a business plan). With ``--plan`` and no value, a key that is
already configured (environment or config file) only gets its plan recorded. Wave 5 adds
``keys setup`` / ``keys test`` (P379).

``App.keys_table`` / ``App.set_key`` delegate here (:func:`keys_table`, :func:`set_key`).
"""

from __future__ import annotations

import getpass
from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from v3lum import paths
from v3lum.commands import command
from v3lum.config import KEY_PLANS, key_registry, mask

__all__ = ["Keys", "keys_table", "record_plan", "set_key"]


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _module_keys() -> dict[str, list[str]]:
    """key name -> modules using it ('name*' = optional key)."""
    from v3lum.core.module import REGISTRY

    needed: dict[str, list[str]] = {}
    for cls in REGISTRY.values():
        for k in getattr(cls, "requires_keys", ()) or ():
            needed.setdefault(str(k), []).append(cls.name)
        for k in getattr(cls, "optional_keys", ()) or ():
            needed.setdefault(str(k), []).append(cls.name + "*")
    return needed


def keys_table(app: Any) -> Table:
    """Every known key (registry + module keys + stored keys): masked value and its origin, the
    recorded plan, the modules that use it and where to get it (description, sign-up URL, env vars)."""
    config = app.config
    registry = key_registry()
    needed = _module_keys()
    names = sorted(set(registry) | set(needed) | set(getattr(config, "file_keys", {}) or {}))
    t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]⚿ API keys[/]", title_justify="left")
    t.add_column("name", style="v.module", no_wrap=True)
    t.add_column("status", no_wrap=True)
    t.add_column("plan", no_wrap=True)
    t.add_column("used by", style="v.dim", overflow="fold", ratio=2)
    t.add_column("what / where to get it", style="v.text", overflow="fold", ratio=3)
    configured = 0
    for name in names:
        value = config.key(name)
        source = config.key_source(name)
        if value:
            configured += 1
        status = Text(f"{mask(value)} ({source})", style="status.ok") if value else Text("missing", style="v.ghost")
        plan = config.key_plan(name) if hasattr(config, "key_plan") else ""
        spec = registry.get(name)
        if plan:
            plan_cell = Text(plan, style="v.ok" if plan == "business" else "v.dim")
        elif spec is not None and getattr(spec, "plan_hint", ""):
            plan_cell = Text(f"? ({_clean(spec.plan_hint)[:40]})", style="v.ghost")
        else:
            plan_cell = Text("-", style="v.ghost")
        env = [f"V3LUM_KEY_{name.upper()}", *(spec.env if spec is not None else ())]
        what = []
        if spec is not None and spec.description:
            what.append(_clean(spec.description))
        if spec is not None and spec.signup_url:
            what.append(_clean(spec.signup_url))
        what.append("env " + " / ".join(dict.fromkeys(env)))
        used = ", ".join(sorted(needed.get(name, [])))[:200] or "-"
        t.add_row(Text(_clean(name)), status, plan_cell, Text(used), Text("\n".join(what)))
    t.caption = (
        f"{configured} of {len(names)} configured · set: v3lum keys set <name> [--plan business|free]   "
        "(* = optional key; key-terms sources run under the corporate licence profile only with --plan business, A1)"
    )
    return t


def record_plan(config: Any, name: str, plan: str) -> None:
    """Record ``key_plans.<name> = plan`` ('business' | 'free') without touching the key value."""
    if plan not in KEY_PLANS:
        raise ValueError(f"unknown key plan {plan!r} (expected one of {', '.join(KEY_PLANS)})")
    plans = dict(config.get("key_plans") or {})
    plans[str(name).strip().lower()] = plan
    config.set("key_plans", plans)


def set_key(app: Any, name: str, value: str | None = None, *, plan: str | None = None) -> None:
    """Store a key 0600 in ``config.json`` (prompted hidden when ``value`` is empty) and record its
    plan when given. With a plan and no value, an already configured key only gets its plan."""
    config = app.config
    console = app.console
    key_name = str(name or "").strip().lower()
    if not key_name:
        raise _user_error("give a key name (see `v3lum keys list`)")
    if plan is not None and plan not in KEY_PLANS:
        raise _user_error(f"unknown key plan {plan!r} (expected one of {', '.join(KEY_PLANS)})")
    known = key_name in key_registry() or key_name in _module_keys()
    if not value and plan is not None and config.key(key_name):
        try:
            record_plan(config, key_name, plan)
        except ValueError as exc:
            raise _user_error(str(exc)) from exc
        console.print(Text(f"[✓] plan of {key_name} recorded: {plan} (the key value is unchanged)", style="v.ok"))
        return
    if not value:
        try:  # hidden prompt in a terminal; a pipe (`... | v3lum keys set NAME`) keeps it out of the shell history
            value = getpass.getpass(f"value for {key_name} (hidden): ")
        except (EOFError, KeyboardInterrupt):
            raise _user_error("no key value given: nothing stored") from None
    if not str(value or "").strip():
        raise _user_error("empty key not stored")
    try:
        config.set_key(key_name, value, plan=plan)
    except ValueError as exc:
        raise _user_error(str(exc)) from exc
    suffix = f", plan {plan}" if plan else ""
    console.print(Text(f"[✓] {key_name} stored in {paths.config_file()} ({mask(str(value).strip())}{suffix})", style="v.ok"))
    if not known:
        console.print(Text(f"[i] {key_name} is not a key any registered module or provider declares: stored anyway", style="v.dim"))


@command("keys", "manage API keys (stored with 0600 permissions) and their plans")
class Keys:
    """List, store and remove API keys; ``--plan`` records whether a key's plan allows business use."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        sub = parser.add_subparsers(dest="keys_cmd", metavar="<action>")
        sub.add_parser("list", help="list keys, their plan and which modules use them")
        s = sub.add_parser("set", help="store a key (prompted hidden if VALUE is omitted)")
        s.add_argument("name")
        s.add_argument("value", nargs="?")
        s.add_argument(
            "--plan", choices=KEY_PLANS,
            help="record the key's plan: business (key-terms sources then run under the corporate licence profile, A1) or free",
        )
        u = sub.add_parser("unset", help="remove a stored key (and its recorded plan)")
        u.add_argument("name")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        action = getattr(args, "keys_cmd", None) or "list"
        if action == "list":
            console.print(keys_table(app))
            return 0
        if action == "set":
            set_key(app, args.name, args.value, plan=getattr(args, "plan", None))
            return 0
        if action == "unset":
            name = str(args.name or "").strip().lower()
            ok = app.config.unset_key(name)
            console.print(Text(f"[✓] {name} removed" if ok else f"{name} was not stored in the config file", style="v.ok" if ok else "v.dim"))
            return 0
        raise _user_error(f"unknown keys action {action!r}")
