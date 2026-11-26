"""``v3lum links <input>``: manual pivot links (P311), rendered under the rules of TLP (A2).

V3LUM never fetches these links. The command renders the bundled pivot packs
(``core.links.pivot_links_for``) for the detected entity and prints them grouped by analyst question
(``links.LINK_CATEGORIES``: reputation, history, passive DNS, code/paste, social...), verified links
first, unverified ones and unknown-tier hosts with their badges ('unverified', 'unknown operator').

TLP (``--tlp``, default setting ``tlp``):

* CLEAR/GREEN: the URL is printed as is;
* AMBER and above: each URL is printed as non-clickable text (defanged) with
  ``opening sends <value> to <host>``;
* RED: third-party links appear only here (reports hide them), with the disclosure warning.

``--open N`` opens one link in the browser: at AMBER and above (and for any link that touches the
target) only after an interactive confirmation naming the host; a non-interactive session is
refused. Entities flagged hostile (case-DB sightings with a hostile verdict, hostile-shaped names:
``policy.hostile_reasons``) show the contact warning first, and their ``touches_target`` links are
hidden unless ``--all`` is given (P311 cond 8). ``privacy`` links (person, phone, e-mail, company
values) appear only with ``--show-personal`` (P311 cond 6: the input is analyst-typed). CPF values
never appear in a link (team rule 4).
"""

from __future__ import annotations

import json
import sys
import webbrowser
from typing import Any

from rich.markup import escape
from rich.prompt import Confirm
from rich.text import Text

from v3lum.commands import command
from v3lum.core import tlp as _tlp

__all__ = ["Links", "collect_links", "render_links"]

TLP_CHOICES = ("clear", "green", "amber", "amber+strict", "red")


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _hostile(app: Any, entity: Any, level: Any) -> list[str]:
    """Why the entity is flagged hostile (case-DB sightings with a hostile verdict, hostile-shaped
    names, org-brand lookalikes): ``policy.hostile_reasons`` over a context with the case-DB
    sightings lookup. [] when nothing is known (or the lookup is unavailable)."""
    try:
        from v3lum.core import policy
        from v3lum.core.context import ScanOptions

        rt = app.runtime()
        lookup = getattr(app.store, "sightings_for", None)
        if callable(lookup):
            rt.meta["sightings_lookup"] = lookup
        pctx = policy.make_context(rt, ScanOptions(tlp=level.value_str, offline=True), path="scan")
        return list(policy.hostile_reasons(entity, pctx))
    except Exception:  # noqa: BLE001 - the warning is best effort; links are never fetched anyway
        return []


def collect_links(app: Any, raw: str, etype: Any, *, level: Any, show_personal: bool = False, expand: bool = False) -> list[dict[str, Any]]:
    """Entities detected in ``raw`` with their rendered links, grouped and ranked.

    Returns ``[{entity, display, flagged: [reasons], hidden: int, links: [row...]}]`` where each row
    is ``{entity, label, url, host, category, verified, badge, touches_target, privacy, tier,
    clickable, disclosure, ref}``; rows are ordered by ``links.LINK_CATEGORIES`` and verified first.
    """
    from v3lum.core import detect as det
    from v3lum.core import links as linklib

    scrub = getattr(app, "scrub_input", None)
    value = scrub(raw, etype) if callable(scrub) else raw
    found = det.detect(value, explicit=etype)
    if not found:
        raise _user_error(f"could not interpret {_clean(str(value))[:80]!r}")
    order = {name: i for i, name in enumerate(linklib.LINK_CATEGORIES)}
    restricted = level >= _tlp.TLP.AMBER
    out: list[dict[str, Any]] = []
    for detection in det.primary(found):
        entity = detection.entity
        flagged = _hostile(app, entity, level)
        rendered = linklib.pivot_links_for(entity, include_privacy=bool(show_personal))
        rendered.sort(key=lambda r: (order.get(r.category, len(order)), not r.verified, r.label.lower()))
        rows = []
        hidden = 0
        for link in rendered:
            if link.touches_target and flagged and not expand:
                hidden += 1
                continue
            rows.append({
                "entity": entity.key,
                "label": link.label,
                "url": link.url,
                "host": link.host,
                "category": link.category,
                "verified": link.verified,
                "badge": link.badge,
                "touches_target": link.touches_target,
                "privacy": link.privacy,
                "tier": link.tier,
                "ref": link.ref,
                "clickable": not restricted and not link.touches_target,
                "disclosure": linklib.disclosure_note(entity, link),
            })
        out.append({
            "entity": entity.key, "etype": entity.type.value, "display": entity.display, "flagged": flagged, "hidden": hidden, "links": rows,
        })
    return out


def _shown_value(group: dict[str, Any]) -> str:
    """The investigated value as the terminal shows it: a URL is always defanged (P311 cond 8: the
    investigated URL is never a clickable link), any host-bearing value of a flagged entity too."""
    display = str(group.get("display") or "")
    etype = str(group.get("etype") or str(group.get("entity") or "").partition(":")[0])
    force = etype == "url" or bool(group.get("flagged"))
    try:
        from v3lum.ui.safe import defang_display

        return defang_display(display, etype, force=force)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: plain defang
        from v3lum.core.entities import defang

        return defang(display) if force else display


def _shown_url(row: dict[str, Any]) -> str:
    from v3lum.core.entities import defang

    return row["url"] if row["clickable"] else defang(row["url"])


def render_links(console: Any, groups: list[dict[str, Any]], *, level: Any) -> list[dict[str, Any]]:
    """Print the groups of :func:`collect_links` (terminal form) and return the numbered rows."""
    numbered: list[dict[str, Any]] = []
    restricted = level >= _tlp.TLP.AMBER
    console.print(Text(level.label, style="v.accent"))
    if level >= _tlp.TLP.RED:
        console.print(Text(
            "[!] TLP:RED - third-party links are listed only here (reports hide them): opening one sends the value to that third party",
            style="v.warn",
        ), soft_wrap=True)
    for group in groups:
        shown = _shown_value(group)
        console.print(Text.assemble(("\n◈ ", "v.accent"), (_clean(shown), "v.entity")))
        if group["flagged"]:
            console.print(Text(
                "[!] flagged: " + "; ".join(_clean(r) for r in group["flagged"][:4])
                + " - do not open links that touch the target from this machine",
                style="v.warn",
            ), soft_wrap=True)
        if group["hidden"]:
            console.print(Text(f"    {group['hidden']} link(s) that touch the target are hidden for a flagged entity (--all shows them)", style="v.dim"))
        if not group["links"]:
            console.print(Text("    no pivot links for this type yet", style="v.dim"))
            continue
        category = None
        for row in group["links"]:
            if row["category"] != category:
                category = row["category"]
                console.print(Text(f"  {category.replace('_', ' ')}", style="v.dim"))
            numbered.append(row)
            badges = [b for b in str(row["badge"] or "").split(", ") if b]
            if row["touches_target"]:
                badges.append("touches target")
            line = Text.assemble(
                (f"{len(numbered):3} ", "v.dim"),
                (f"{_clean(row['label'])[:40]:40} ", "v.text"),
                (_clean(_shown_url(row)), "v.url" if row["clickable"] else "v.dim"),
            )
            if badges:
                line.append(f"  [{', '.join(badges)}]", style="v.warn")
            console.print(line, soft_wrap=True)
            if restricted or row["touches_target"]:
                raw = str(group.get("display") or "")
                note = _clean(str(row["disclosure"]).replace(raw, shown, 1) if raw and raw != shown else row["disclosure"])
                if row["touches_target"]:
                    note += " (it opens the target or makes a third party fetch it live)"
                console.print(Text(f"      {note}", style="v.warn"), soft_wrap=True)
    if restricted:
        console.print(Text("\n  links are shown as non-clickable text at TLP:AMBER and above · --open N asks for confirmation", style="v.ghost"))
    else:
        console.print(Text("\n  opening a link contacts that site from your machine · --open N to launch one", style="v.ghost"))
    return numbered


def _open(console: Any, row: dict[str, Any], *, level: Any) -> int:
    needs_confirmation = level >= _tlp.TLP.AMBER or row["touches_target"]
    if needs_confirmation:
        if not _tty():
            raise _user_error(
                f"--open at {level.label} needs an interactive confirmation naming the host "
                f"({row['host']}): refused in a non-interactive session"
            )
        etype, _, raw = str(row.get("entity") or "").partition(":")
        note = str(row["disclosure"])
        shown = _shown_value({"display": raw, "etype": etype})
        if raw and shown != raw:
            note = note.replace(raw, shown, 1)  # the investigated URL is never clickable, prompt included
        question = f"[v.warn]open {escape(_clean(row['host']))}? {escape(_clean(note))}[/]"
        if not Confirm.ask(question, default=False, console=console):
            console.print(Text("not opened", style="v.dim"))
            return 0
    webbrowser.open(row["url"])
    console.print(Text(f"opened {row['host']}", style="v.dim"))
    return 0


@command("links", "manual pivot links for an input (web tools pre-filled; never fetched by V3LUM)")
class Links:
    """Manual pivot links grouped by analyst question, with TLP-aware rendering."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        parser.add_argument("input")
        parser.add_argument("-t", "--type", help="force entity type")
        parser.add_argument("--tlp", choices=TLP_CHOICES, help="TLP of the value (default: setting tlp, amber): AMBER and above print non-clickable links with a disclosure note")
        parser.add_argument("--open", type=int, metavar="N", help="open link number N in the browser (confirmation at TLP:AMBER and above)")
        parser.add_argument("--show-personal", action="store_true", help="include privacy links (person, phone, e-mail, company values) for this analyst-typed input")
        parser.add_argument("--all", action="store_true", help="also list links that touch the target for an entity flagged hostile")
        parser.add_argument("--json", action="store_true")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        from v3lum.app import entity_type_or_none

        try:
            level = _tlp.parse(args.tlp or app.config.get("tlp") or "amber")
        except ValueError as exc:
            raise _user_error(str(exc)) from exc
        groups = collect_links(
            app, args.input, entity_type_or_none(args.type), level=level, show_personal=bool(getattr(args, "show_personal", False)),
            expand=bool(getattr(args, "all", False)),
        )
        rows = [row for group in groups for row in group["links"]]
        if args.json:
            payload = [{**row, "tlp": level.value_str, "flagged": bool(group["flagged"])} for group in groups for row in group["links"]]
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            rows = render_links(console, groups, level=level)
        if args.open is not None:
            if not 1 <= args.open <= len(rows):
                raise _user_error(f"--open must be between 1 and {len(rows)}" if rows else "--open: no links to open")
            return _open(console, rows[args.open - 1], level=level)
        return 0
