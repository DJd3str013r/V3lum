"""memory.lol X/Twitter screen-name history (P106): account ids that used a handle and their other screen names.

* Endpoint (cond 1): ``GET api.memory.lol/v1/tw/<handle>`` (keyless). The service also takes comma-joined
  batches of <= 20 handles (``batch_url``); the engine runs one entity at a time, so the module sends one handle
  per request and parses both the single and the batch answer shapes. The ``*`` prefix search,
  ``/v1/tw/id/<id>`` and ``/v1/login/*`` are never used; handles are validated (``^[A-Za-z0-9_]{1,15}$``) because
  the service answers ``{'accounts': []}`` even for invalid ones.
* Terms 'unknown' (cond 2): disabled in every licence profile until legal records a class (A1);
  default_enabled False. Keyless only: the login/device flow is never run and no key is declared (an optional
  'memorylol' key waits for an approved account, backlog).
* Empty answers (cond 3): ``{'accounts': []}``, ``{}`` or a batch without the handle read 'no observation in the
  public 60-day window', never 'no previous handles'.
* Only analyst-typed handles that are case subjects (cond 4, ``run_on='seeds'``). Previous screen names (with
  their first/last observation dates) become ``uses_username`` username pivots with expand=False, fed to
  username_check only on analyst selection; the numeric account id is the ``account_id`` attribute and a
  ``uses_username`` snowflake-id pivot when it is a valid X snowflake (old pre-2013 ids are not).
* Handle history is personal data (cond 5): case-bound, never kept beyond retention_days (core retention; no
  ctx.state). 429/5xx = could not verify; an HTML login page is BLOCKED login_wall, never data.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import day, to_int, to_str

SOURCE = "memory_lol.screen_names"
BASE = "https://api.memory.lol/v1/tw/"
BATCH = 20
EMPTY_WORDING = "no observation in the public 60-day window"
WINDOW = "public 60-day window (anonymous access)"
MAX_ACCOUNTS = 10
MAX_NAMES = 50
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")


def handle_ok(value: Any) -> bool:
    """X/Twitter screen name: 1-15 of [A-Za-z0-9_]; the '*' prefix search and other characters are refused."""
    return isinstance(value, str) and bool(_HANDLE_RE.match(value.strip().lstrip("@")))


def lookup_url(handle: str) -> str:
    return BASE + handle.strip().lstrip("@")


def batch_url(handles: Any) -> list[str]:
    """cond 1: comma-joined batches of <= 20 valid handles, de-duplicated case-insensitively."""
    seen: set[str] = set()
    clean: list[str] = []
    for h in handles or ():
        if not handle_ok(h):
            continue
        v = h.strip().lstrip("@")
        if v.lower() not in seen:
            seen.add(v.lower())
            clean.append(v)
    return [BASE + ",".join(clean[i:i + BATCH]) for i in range(0, len(clean), BATCH)]


def handle_of(entity: Entity) -> str | None:
    if entity.type is T.USERNAME:
        return entity.value
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
        return handle if platform == "x" else None
    if entity.type is T.URL:
        hit = platform_for_url(entity.value)
        return hit[1] if hit and hit[0] == "x" else None
    return None


def _accounts(raw: Any, handle: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for acc in raw[:MAX_ACCOUNTS] if isinstance(raw, list) else []:
        if not isinstance(acc, dict):
            continue
        acc_id = to_str(acc.get("id_str"), 30) or to_str(acc.get("id-str"), 30)
        if not acc_id and to_int(acc.get("id")) is not None:
            acc_id = str(to_int(acc.get("id")))
        if acc_id and not acc_id.isdigit():
            acc_id = None
        names_raw = acc.get("screen_names", acc.get("screen-names"))
        names: list[dict[str, Any]] = []
        for name, dates in (names_raw.items() if isinstance(names_raw, dict) else []):
            if not isinstance(name, str) or not _HANDLE_RE.match(name) or len(names) >= MAX_NAMES:
                continue
            ds = sorted(d for d in (day(x) for x in (dates if isinstance(dates, list) else [])[:10]) if d)
            names.append({"name": name, "first_seen": ds[0] if ds else None, "last_seen": ds[-1] if ds else None})
        names.sort(key=lambda n: (n["first_seen"] or "0000", n["name"].lower()))
        out.append({"account_id": acc_id, "screen_names": names,
                    "previous": [n for n in names if n["name"].lower() != handle.lower()]})
    return out


def parse_answer(data: Any, handle: str) -> tuple[str, list[dict[str, Any]], str]:
    """(state ok|empty|error, accounts, reason). Single shape {'accounts': [...]}, batch shape {handle: {...}}
    (case-insensitive) and the older 'screen-names'/'id-str' keys; {} and a batch without the handle are empty."""
    if not isinstance(data, dict):
        return "error", [], "unexpected memory.lol answer (not a JSON object): could not verify"
    if "accounts" in data:
        if not isinstance(data["accounts"], list):
            return "error", [], "memory.lol 'accounts' is not a list: could not verify"
        accounts = _accounts(data["accounts"], handle)
    elif not data:
        accounts = []
    elif any(isinstance(v, dict) and "accounts" in v for v in data.values()):
        lower = {str(k).lower(): v for k, v in data.items() if isinstance(v, dict)}
        entry = lower.get(handle.lower())
        accounts = _accounts(entry.get("accounts") if isinstance(entry, dict) else [], handle)
    elif "error" in data or "message" in data:
        return "error", [], f"memory.lol error in 200: {str(data.get('error') or data.get('message'))[:120]}"
    else:
        return "error", [], "unexpected memory.lol answer shape: could not verify"
    accounts = [a for a in accounts if a["account_id"] or a["screen_names"]]
    return ("ok" if accounts else "empty"), accounts, "" if accounts else EMPTY_WORDING


@register
class MemoryLol(Module):
    name = "memory_lol"
    title = "memory.lol X/Twitter screen-name history"
    description = (
        "Account ids that used an X/Twitter handle and every screen name seen for them, with dates, from memory.lol "
        "(keyless; anonymous access covers facts observed in the last 60 days)."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.USERNAME, T.SNOWFLAKE_ID})
    run_on = "seeds"  # cond 4: analyst-typed handles that are case subjects
    terms = "unknown"  # cond 2: off in every licence profile until legal records a class
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "memory_lol"
    sources = (SOURCE,)
    hosts = ("api.memory.lol",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 0.5
    timeout = 15.0
    min_interval = 2.0
    cache_ttl = 86400  # personal data, case-bound (cond 5)
    daily_quota = 200
    max_pivots = 40
    default_enabled = False  # cond 2
    reference = "https://github.com/travisbrown/memory.lol"
    tags = frozenset({"free"})
    error_markers = (
        {"id": "memory_lol_login_wall", "statuses": [200, 401, 403], "regex": r"(?i)/v1/login/(?:github|google)",
         "maps_to": "blocked", "reason_code": "login_wall",
         "reason": "memory.lol: login page instead of data (the login/device flow is never run): could not verify"},
        {"id": "memory_lol_error_in_200", "statuses": [200], "json_path": "error", "regex": ".",
         "maps_to": "error", "reason_code": "error", "reason": "memory.lol: error object instead of data (could not verify)"},
    )
    notice = (
        "Terms 'unknown' (no published service terms): disabled in every licence profile until legal records a class. "
        "Anonymous access covers the public 60-day window only: an empty answer is 'no observation in the public 60-day "
        "window', never 'no previous handles'. Handle history is personal data: case-bound, kept only within retention_days."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.USERNAME, "octocat", expect="empty")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return handle_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = handle_of(entity)
        if not handle or not handle_ok(handle):
            return res.mark("skipped", "not an X/Twitter screen name (1-15 letters, digits or underscores)", reason_code="not_applicable")
        data = ctx.http.get_json(lookup_url(handle), source=SOURCE)
        state, accounts, reason = parse_answer(data, handle)
        if state == "error":
            return res.mark("error", reason)
        if state == "empty":
            res.error = f"{EMPTY_WORDING} for @{handle} (memory.lol)"
            return res.mark("empty")
        res.raw = {"handle": handle, "window": WINDOW, "accounts": accounts}
        res.attr("x_handle_history", {"window": WINDOW, "accounts": [{"account_id": a["account_id"], "screen_names": a["screen_names"]} for a in accounts]})
        ids = [a["account_id"] for a in accounts if a["account_id"]]
        res.attr("account_id", ids[0] if len(ids) == 1 else ids)
        res.attr("data_notices", [f"memory.lol: {WINDOW}; an absent name means no observation in that window, not no history"])
        for acc in accounts:
            acc_id = acc["account_id"]
            if acc_id:
                res.pivot(T.SNOWFLAKE_ID, acc_id, "uses_username", confidence="probable", expand=False,
                          note=f"numeric X account id that used @{handle} (memory.lol, {WINDOW})")
            for n in acc["previous"]:
                when = f"{n['first_seen']}..{n['last_seen']}" if n["first_seen"] else "undated"
                res.pivot(T.USERNAME, n["name"], "uses_username", confidence="probable", expand=False,
                          note=f"screen name of the same X account id {acc_id or '?'} (observed {when}): run username checks only on analyst selection")
        lines = []
        for acc in accounts:
            names = ", ".join(f"@{n['name']} ({n['first_seen'] or 'undated'}..{n['last_seen'] or ''})".replace("..)", ")") for n in acc["screen_names"][:10])
            lines.append(f"id {acc['account_id'] or '?'}: {names}")
        res.finding(
            "X/Twitter screen-name history",
            "info",
            f"memory.lol links @{handle} to {len(accounts)} account id(s): " + "; ".join(lines)
            + f". Anonymous access covers the {WINDOW}: older names are not shown, absences prove nothing.",
            confidence="probable",
            criterion="memory.lol lists the account id(s) that used the screen name and their other screen names with observation dates",
            data={"handle": handle, "account_ids": ids},
            tags=["identity", "historical"],
            source=SOURCE,
            observed_last=max((n["last_seen"] for a in accounts for n in a["screen_names"] if n["last_seen"]), default=None),
        )
        return res
