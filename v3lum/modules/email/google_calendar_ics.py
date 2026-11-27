"""Google Calendar public ICS of an analyst-typed address (P093), opt-in.

``GET https://calendar.google.com/calendar/ical/<urlencoded address>/public/basic.ics`` (cond 1).

* **Opt-in, seeds only** (cond 1): ``default_enabled=False``, ``run_on='seeds'``; the module repeats the
  check (SKIPPED ``privacy`` for pivots).
* **Stored facts only** (cond 2): that a public calendar exists, the event count (recurring events
  counted once), the date range and the time zone. SUMMARY, DESCRIPTION, LOCATION, ATTENDEE and
  ORGANIZER (and the calendar name/description and UIDs) are never read into the result, so they never
  reach evidence or reports - no 'unless the analyst asks' exception.
* **No raw body in the HTTP cache** (cond 3): ``cache_ttl=0`` and the provider profile ttl 0 (no-store).
  The analyst opens the feed manually through the privacy-tagged pivot link
  ``email_keys_calendar:gcal_public_ics`` (P311; for analyst-typed seeds only).
* **Bounded parsing** (cond 4): 1 MB cap (provider ``max_bytes``), RFC 5545 line unfolding, no RRULE
  expansion. A 404 is EMPTY with the note 'private or nonexistent' (Google answers 404 for both: it is
  not an existence signal). Google's CAPTCHA interstitial is BLOCKED ``challenge`` and a sign-in page
  (or a redirect to accounts.google.com) BLOCKED ``login_wall`` - never retried or bypassed (A9).
* **Privacy tag** (cond 5) on every finding. The holiday-calendar fixture is a trimmed live capture of
  Google's public 'Feriados no Brasil' calendar.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.email.pgp_keyservers import normalise_email

SOURCE = "google_calendar.public_ics"
HOST = "calendar.google.com"
MAX_BYTES = 1_048_576  # cond 4
ABSENT_TEXT = "private or nonexistent (Google answers 404 for both: not an existence signal)"
DROPPED_PROPERTIES = ("SUMMARY", "DESCRIPTION", "LOCATION", "ATTENDEE", "ORGANIZER")
_TZ = re.compile(r"^[A-Za-z0-9_+/-]{1,64}$")


def gcal_ics_url(email: Any) -> str:
    """The public ICS feed URL of an address (cond 1). ValueError for anything that is not an address."""
    addr = normalise_email(email)
    if addr is None:
        raise ValueError("gcal: not an e-mail address")
    return f"https://{HOST}/calendar/ical/{quote(addr, safe='')}/public/basic.ics"


def ics_unfold(text: str) -> str:
    """RFC 5545 unfolding: a line break followed by one space or tab continues the previous line."""
    return re.sub(r"\r?\n[ \t]", "", text)


def _ics_date(value: str) -> str | None:
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(?:T\d{6}Z?)?$", value.strip())
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def parse_ics_summary(body: bytes | str, *, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """Public calendar -> stored facts only (cond 2/4): {is_calendar, event_count, recurring_event_count,
    first_event_date, last_event_date, timezone, truncated, complete}. Only BEGIN/END, DTSTART, RRULE (as
    a flag), X-WR-TIMEZONE and VTIMEZONE TZID are read; SUMMARY, DESCRIPTION, LOCATION, ATTENDEE,
    ORGANIZER, X-WR-CALNAME/CALDESC and UIDs never are. Recurrences are never expanded; only complete
    top-level VEVENTs count (VALARM and other nested blocks are ignored)."""
    raw = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    out: dict[str, Any] = {"is_calendar": False, "event_count": 0, "recurring_event_count": 0, "first_event_date": None,
                           "last_event_date": None, "timezone": None, "truncated": len(raw) > max_bytes, "complete": False}
    text = raw[:max_bytes].decode("utf-8", "replace").lstrip("﻿")
    if "BEGIN:VCALENDAR" not in text[:4096].upper():
        return out
    out["is_calendar"] = True
    stack: list[str] = []
    event: dict[str, Any] | None = None
    dates: list[str] = []
    tzids: list[str] = []
    for line in ics_unfold(text).splitlines():
        if ":" not in line:
            continue
        head, value = line.split(":", 1)
        name = head.split(";", 1)[0].strip().upper()
        if name == "BEGIN":
            comp = value.strip().upper()
            stack.append(comp)
            if stack == ["VCALENDAR", "VEVENT"]:
                event = {"start": None, "rrule": False}
            continue
        if name == "END":
            comp = value.strip().upper()
            if stack and stack[-1] == comp:
                stack.pop()
                if comp == "VEVENT" and event is not None and stack == ["VCALENDAR"]:
                    out["event_count"] += 1
                    out["recurring_event_count"] += 1 if event["rrule"] else 0
                    if event["start"]:
                        dates.append(event["start"])
                    event = None
                if comp == "VCALENDAR" and not stack:
                    out["complete"] = True
            continue
        if stack == ["VCALENDAR", "VEVENT"] and event is not None:
            if name == "DTSTART":
                event["start"] = _ics_date(value)
            elif name == "RRULE":
                event["rrule"] = True  # counted once, never expanded (cond 4)
        elif stack == ["VCALENDAR"] and name == "X-WR-TIMEZONE" and _TZ.match(value.strip()):
            out["timezone"] = value.strip()
        elif stack == ["VCALENDAR", "VTIMEZONE"] and name == "TZID" and _TZ.match(value.strip()):
            tzids.append(value.strip())
    if out["timezone"] is None and tzids:
        out["timezone"] = tzids[0]
    if dates:
        out["first_event_date"], out["last_event_date"] = min(dates), max(dates)
    return out


@register
class GoogleCalendarIcs(Module):
    name = "google_calendar_ics"
    title = "Google Calendar public ICS"
    description = (
        "Whether an analyst-typed address has a public Google Calendar feed: event count, date range and time zone "
        "only - never event titles, descriptions, locations or attendees."
    )
    category = "email"
    accepts = {T.EMAIL}
    produces = frozenset()
    run_on = "seeds"
    reference = "https://support.google.com/calendar/answer/37083"
    notice = (
        "Opt-in; analyst-typed seeds only. Calendar entries can reveal sensitive data (LGPD art. 11): only the existence "
        "of a public calendar, the event count, date range and time zone are stored; the raw feed is never cached. "
        "A 404 means private OR nonexistent."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "google_calendar"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # 'private or nonexistent' (cond 4)
    max_requests = 1
    expected_latency = 0.3
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = 0  # cond 3: no-store
    max_pivots = 0
    manual_link = "email_keys_calendar:gcal_public_ics"
    default_enabled = False  # cond 1
    error_markers = (
        {"id": "gcal_unusual_traffic", "statuses": [200, 302, 403, 429, 503], "regex": "/sorry/index|unusual traffic from your computer",
         "maps_to": "blocked", "reason_code": "challenge",
         "reason": "Google: 'unusual traffic' CAPTCHA page instead of the public calendar (never solved or bypassed)"},
        {"id": "gcal_sign_in", "statuses": [200], "regex": "(?i)<title>\\s*Sign in|accounts\\.google\\.com/(?:v3/)?signin|ServiceLogin",
         "maps_to": "blocked", "reason_code": "login_wall", "reason": "Google: sign-in page instead of the public calendar feed"},
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return normalise_email(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", False) or int(getattr(ctx, "depth", 0) or 0) != 0:
            return res.mark(Status.SKIPPED, "public calendar lookups run on analyst-typed seed addresses only", reason_code="privacy")
        url = gcal_ics_url(entity.value)
        resp = ctx.http.get(url, source=SOURCE, ttl=0, max_bytes=MAX_BYTES, allow_redirects=False,
                            headers={"Accept": "text/calendar, text/plain;q=0.5"})
        if 300 <= resp.status < 400:
            location = str(resp.headers.get("location", ""))
            host = (urlsplit(location).hostname or "").lower() if location else ""
            if host.endswith("accounts.google.com") or "/sorry/" in location:
                code = "challenge" if "/sorry/" in location else "login_wall"
                return res.mark(Status.BLOCKED, f"Google redirected to {host or 'another page'} instead of the public feed", reason_code=code)
            return res.mark(Status.ERROR, f"unexpected HTTP {resp.status} redirect from Google Calendar: could not verify")
        if resp.status == 404 and getattr(resp, "classification", None) is None:
            res.raw = {"public_calendar": False}
            res.error = ABSENT_TEXT
            return res.mark(Status.EMPTY)
        ctx.http.check(resp)  # 403/429/5xx, CAPTCHA and sign-in pages: could not verify
        facts = parse_ics_summary(resp.content)
        if not facts["is_calendar"]:
            return res.mark(Status.ERROR, "Google did not answer with an iCalendar body: could not verify")
        truncated = bool(facts["truncated"] or getattr(resp, "truncated", False))
        stored = {"exists": True, "event_count": facts["event_count"], "recurring_event_count": facts["recurring_event_count"],
                  "first_event_date": facts["first_event_date"], "last_event_date": facts["last_event_date"],
                  "timezone": facts["timezone"], "truncated": truncated, "complete": facts["complete"] and not truncated}
        res.raw = {"public_calendar": True, **stored}
        res.attr("public_calendar", stored)
        span = (f" from {stored['first_event_date']} to {stored['last_event_date']}" if stored["first_event_date"] else "")
        partial = " (feed above the 1 MB cap or cut: counts are a lower bound)" if not stored["complete"] else ""
        res.finding(
            "Public Google Calendar feed",
            "info",
            f"The address publishes a public calendar: {stored['event_count']} event(s){span}"
            f"{', time zone ' + stored['timezone'] if stored['timezone'] else ''}{partial}. Event contents are never stored; "
            "open the feed manually (privacy link) only for an analyst-typed address.",
            confidence="confirmed",
            criterion="calendar.google.com served an iCalendar body for /calendar/ical/<address>/public/basic.ics",
            data={k: stored[k] for k in ("event_count", "recurring_event_count", "first_event_date", "last_event_date", "timezone")},
            tags=["privacy", "exposure"],
            source=SOURCE,
            observed_first=stored["first_event_date"],
            observed_last=stored["last_event_date"],
        )
        return res
