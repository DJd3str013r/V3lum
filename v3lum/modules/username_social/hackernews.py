"""Hacker News account, activity and organisation mentions (P109): Firebase user API + HN Search by Algolia.

* Username seeds (cond 1/2): validated against ``[A-Za-z0-9_-]{2,15}`` before any request, then
  ``hacker-news.firebaseio.com/v0/user/<u>.json`` - HTTP 200 with the body ``null`` is ABSENT, decided from the
  JSON and never from the status - and, for an existing account, one page of
  ``hn.algolia.com/api/v1/search_by_date?tags=author_<u>`` for activity. Hacker News ids are case-sensitive while
  V3LUM usernames are lower-cased: an exact-case id is checked through a profile URL
  (``news.ycombinator.com/user?id=<Id>``). ``users/<u>`` on Algolia is never used (it answers HTTP 500 for unknown
  users).
* 'about' is HTML-unescaped; its URLs, e-mails and Keybase profile links become pivots with expand=False (cond 2).
* Minimisation (cond 3): counts, account creation (the first-activity bound), last activity, submitted stories
  (title, link, date) and the items that mention an org-profile brand or domain (a <= 200-character quote).
  Unmatched comments are counted only: no thread titles, links or text; the Firebase 'submitted' id list is
  never kept.
* Mentions (cond 1): ``search?query="<term>"`` only for organisation-profile domains and brands (a domain or
  keyword seed that the org profile does not own is not applicable); hit authors are never kept or pivoted.
* Algolia's 10,000 requests/hour per IP is the provider quota block (P334, cond 3); 429/5xx = could not verify.
* Providers hacker_news (Y Combinator) and algolia: tier trusted, terms open; personal_data_review comes before
  default use (cond 4).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import (
    Problems,
    attempt,
    excerpt,
    extract_emails,
    extract_urls,
    fold,
    host_of,
    html_text_and_links,
    iso,
    json_body,
    org_domains,
    org_terms,
    quote_if_mentioned,
    report_problems,
    safe_url,
    to_int,
    to_str,
)

SOURCE_FIREBASE = "hacker_news.firebase_api"
SOURCE_ALGOLIA = "algolia.hn_search"
FIREBASE = "https://hacker-news.firebaseio.com/v0/user/{u}.json"
ALGOLIA = "https://hn.algolia.com/api/v1/"
HITS = 20
MAX_STORIES = 10
MAX_MENTIONS = 20
_HN_USER_RE = re.compile(r"^[A-Za-z0-9_-]{2,15}$")
_KEYBASE_RE = re.compile(r"^https?://(?:www\.)?keybase\.io/([A-Za-z0-9_]{2,16})(?:[/?#]|$)", re.I)
_HN_HOSTS = ("news.ycombinator.com",)


def hn_username_ok(value: Any) -> bool:
    """cond 2: [A-Za-z0-9_-]{2,15} before any request."""
    return isinstance(value, str) and bool(_HN_USER_RE.match(value))


def user_url(username: str) -> str:
    return FIREBASE.format(u=quote(username, safe=""))


def author_url(username: str, hits: int = HITS) -> str:
    return ALGOLIA + "search_by_date?" + urlencode({"tags": f"author_{username}", "hitsPerPage": max(1, min(hits, 100))})


def mentions_url(term: str, hits: int = HITS) -> str:
    return ALGOLIA + "search?" + urlencode({"query": '"' + term.replace('"', "") + '"', "hitsPerPage": max(1, min(hits, 100))})


def profile_url(username: str) -> str:
    return "https://news.ycombinator.com/user?id=" + quote(username, safe="")


def username_from_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if (parts.hostname or "").lower() not in _HN_HOSTS or parts.path.rstrip("/") != "/user":
        return None
    ids = parse_qs(parts.query).get("id") or []
    return ids[0] if ids and hn_username_ok(ids[0]) else None


def parse_about(about: Any) -> dict[str, Any]:
    """cond 2: HTML-unescaped text, URLs, e-mails (plain and [at]/[dot] forms) and Keybase profile names."""
    text, links = html_text_and_links(about if isinstance(about, str) else "")
    urls: list[str] = []
    for u in [safe_url(x) for x in links] + extract_urls(text):
        if u and u not in urls:
            urls.append(u)
    keybase: list[str] = []
    for u in urls:
        m = _KEYBASE_RE.match(u)
        if m and m.group(1).lower() not in keybase:
            keybase.append(m.group(1).lower())
    return {"text": text, "urls": urls[:20], "emails": extract_emails(text)[:10], "keybase": keybase[:5]}


def parse_user(data: Any) -> dict[str, Any] | None:
    """Firebase user -> facts (counts and dates only, never the submitted id list), or None when unusable."""
    if not isinstance(data, dict) or not to_str(data.get("id"), 20):
        return None
    about = parse_about(data.get("about"))
    submitted = data.get("submitted") if isinstance(data.get("submitted"), list) else []
    uid = to_str(data.get("id"), 20) or ""
    return {"id": uid, "created": iso(to_int(data.get("created"))), "karma": to_int(data.get("karma")),
            "submitted_count": len(submitted), "about": about, "about_excerpt": excerpt(about["text"], 300),
            "profile_url": profile_url(uid)}


def parse_search(data: Any, terms: list[str], mode: str) -> dict[str, Any] | None:
    """cond 1/3: one HN Search page -> count, last activity, stories, links and matched items (quotes <= 200)."""
    if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
        return None
    out: dict[str, Any] = {"count": to_int(data.get("nbHits")) or 0, "stories": [], "matched": [], "links": [],
                           "unmatched_comments": 0, "last_activity": None}
    dates: list[str] = []
    for h in data["hits"][:100]:
        if not isinstance(h, dict):
            continue
        tags = h.get("_tags") if isinstance(h.get("_tags"), list) else []
        kind = "comment" if "comment" in tags else "story" if "story" in tags else "item"
        oid = to_str(str(h.get("objectID") or ""), 20)
        created = iso(h.get("created_at") or to_int(h.get("created_at_i")))
        if created:
            dates.append(created)
        title = to_str(h.get("title"), 300)
        link = safe_url(h.get("url"))
        body = h.get("comment_text") or h.get("story_text") or ""
        body_text, body_links = html_text_and_links(body if isinstance(body, str) else "")
        permalink = f"https://news.ycombinator.com/item?id={oid}" if oid and oid.isdigit() else None
        item = {"id": oid, "kind": kind, "created": created, "title": title, "url": link, "permalink": permalink}
        q = quote_if_mentioned(" ".join(x for x in (title or "", link or "", body_text) if x), terms) if terms else None
        if q:
            out["matched"].append({"source": "hn", "id": oid, "kind": kind, "permalink": permalink, "created": created, "quote": q})
        if mode == "author" and kind == "comment":
            if not q:
                out["unmatched_comments"] += 1  # counted only: no thread title, link or text (cond 3)
            continue
        if kind == "story" or mode == "mentions":
            out["stories"].append(item)
        for u in [link] + [safe_url(x) for x in body_links]:
            if u and u not in out["links"] and host_of(u) not in _HN_HOSTS:
                out["links"].append(u)
    out["last_activity"] = max(dates) if dates else None
    return out


@register
class HackerNews(Module):
    name = "hackernews"
    title = "Hacker News account, activity and organisation mentions"
    description = (
        "Hacker News Firebase user API (account, karma, creation date, 'about' links) and HN Search by Algolia (activity "
        "of the account; mentions of organisation-profile domains and brands), keyless."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.URL, T.DOMAIN, T.KEYWORD})
    produces = frozenset({T.URL, T.EMAIL, T.SOCIAL_ACCOUNT, T.DOMAIN})
    run_on = "seeds"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hacker_news"
    sources = (SOURCE_FIREBASE, SOURCE_ALGOLIA)
    hosts = ("hacker-news.firebaseio.com", "hn.algolia.com")
    access_model = "free_noauth_limited"
    max_requests = 2  # Firebase user + one Algolia page, or one mention search
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 40
    default_enabled = True
    reference = "https://github.com/HackerNews/API"
    tags = frozenset({"free"})
    error_markers = (
        {"id": "hackernews_firebase_error", "statuses": [200, 400, 401], "json_path": "error", "regex": ".",
         "maps_to": "error", "reason_code": "error", "reason": "Hacker News Firebase API: error object instead of data (could not verify)"},
    )
    notice = (
        "Keeps links, dates and items relevant to the case (counts, first/last activity, items that mention the organisation), "
        "never full comment histories. Usernames are personal data: personal_data_review comes before default use (A3 BR8)."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.USERNAME, "octocat", expect="ok")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            return username_from_url(entity.value) is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type in (T.DOMAIN, T.KEYWORD):
            return self._mentions(res, ctx, entity)
        username = username_from_url(entity.value) if entity.type is T.URL else entity.value
        if not username or not hn_username_ok(username):
            return res.mark("skipped", "not a Hacker News username ([A-Za-z0-9_-]{2,15})", reason_code="not_applicable")
        return self._account(res, ctx, username, exact_case=entity.type is T.URL)

    # ------------------------------------------------------------------------------------------ account
    def _account(self, res: ModuleResult, ctx: Any, username: str, *, exact_case: bool) -> ModuleResult:
        raw = ctx.http.get_json(user_url(username), source=SOURCE_FIREBASE)
        data, why = json_body(raw) if raw is not None else (None, None)
        if raw is None:  # the literal JSON null: absent, decided from the body (cond 1)
            res.presence("absent", marker=f"HTTP 200 with body null from v0/user/{username}.json (exact, case-sensitive id)",
                         url=profile_url(username), checked_at=ctx.now(), source=SOURCE_FIREBASE)
            res.error = (f"no Hacker News user '{username}'"
                         + ("" if exact_case else " (ids are case-sensitive: check another casing with a news.ycombinator.com/user?id= URL)"))
            return res.mark("empty")
        user = parse_user(data) if why is None else None
        if user is None:
            return res.mark("error", f"unexpected Hacker News answer ({why or 'no user id'}): could not verify")
        problems: Problems = {}
        terms = org_terms(ctx)
        res.raw = {"id": user["id"], "created": user["created"], "karma": user["karma"], "submitted_count": user["submitted_count"]}
        res.presence("found", marker=f"v0/user/{username}.json returned the account", url=user["profile_url"], checked_at=ctx.now(), source=SOURCE_FIREBASE)
        res.attr("hn_account", {"id": user["id"], "created": user["created"], "karma": user["karma"], "submitted_count": user["submitted_count"],
                                "about_urls": user["about"]["urls"], "about_email_count": len(user["about"]["emails"]), "profile_url": user["profile_url"]})
        res.attr("created", user["created"])
        res.attr("profile_url", user["profile_url"])
        if terms:
            res.attr("bio", quote_if_mentioned(user["about"]["text"], terms))  # 'about' text only when it names the organisation
        self._about_pivots(res, user)
        search = attempt(problems, SOURCE_ALGOLIA, "HN Search author page", lambda: ctx.http.get_json(author_url(user["id"]), source=SOURCE_ALGOLIA))
        activity = parse_search(search, terms, "author") if search is not None else None
        if search is not None and activity is None:
            problems.setdefault(SOURCE_ALGOLIA, []).append((Status.ERROR, "error", "HN Search author page: unexpected answer (no hits[])"))
        if activity is not None:
            res.attr("hn_activity", {"items_total": activity["count"], "last_activity": activity["last_activity"],
                                     "first_activity_bound": user["created"], "stories": activity["stories"][:MAX_STORIES],
                                     "unmatched_comments": activity["unmatched_comments"], "links": activity["links"][:20]})
            res.attr("last_activity", activity["last_activity"])
            res.raw["activity_items"] = activity["count"]
            for link in activity["links"][:10]:
                res.pivot(T.URL, link, "links_to", confidence="possible", expand=False,
                          note="link submitted by the Hacker News account (context: owner-chosen, not identity evidence)")
            self._mentions_finding(res, activity["matched"], f"items by {user['id']}")
        report_problems(res, problems)
        res.finding(
            "Hacker News account",
            "info",
            f"Hacker News account {user['id']}" + (f", created {user['created'][:10]}" if user["created"] else "")
            + (f", karma {user['karma']}" if user["karma"] is not None else "") + f", {user['submitted_count']} submitted items"
            + (f"; {activity['count']} items in HN Search, last {activity['last_activity'][:10]}" if activity and activity["last_activity"] else "")
            + ". Same handle elsewhere does not prove the same person.",
            confidence="confirmed",
            criterion="the Firebase user API returned the account (HTTP 200 with a user object)",
            data={"id": user["id"], "created": user["created"], "karma": user["karma"]},
            tags=["account"],
            references=[user["profile_url"]],
            source=SOURCE_FIREBASE,
            observed_first=user["created"],
        )
        return res

    def _about_pivots(self, res: ModuleResult, user: dict[str, Any]) -> None:
        about = user["about"]
        for u in about["urls"]:
            if _KEYBASE_RE.match(u):
                continue
            res.pivot(T.URL, u, "link_on_profile", confidence="possible", expand=False,
                      note="link in the Hacker News 'about' text (owner-written): analyst selection required")
        for e in about["emails"]:
            res.pivot(T.EMAIL, e, "email_on_profile", confidence="possible", expand=False,
                      note="e-mail in the Hacker News 'about' text (owner-written personal data): analyst selection required")
        for k in about["keybase"]:
            res.pivot(T.SOCIAL_ACCOUNT, f"keybase:{k}", "linked_account_on_profile", confidence="possible", expand=False,
                      note="Keybase profile linked in the Hacker News 'about' text (owner-written)")

    # ------------------------------------------------------------------------------------------ mentions
    def _mentions(self, res: ModuleResult, ctx: Any, entity: Entity) -> ModuleResult:
        term = self._org_term(ctx, entity)
        if term is None:
            return res.mark("skipped", "HN mention search runs only for organisation-profile domains and brands (P109 cond 1)",
                            reason_code="not_applicable")
        data = ctx.http.get_json(mentions_url(term), source=SOURCE_ALGOLIA)
        parsed = parse_search(data, [term, *org_terms(ctx)], "mentions")
        if parsed is None:
            return res.mark("error", "unexpected HN Search answer (no hits[]): could not verify")
        res.raw = {"query": term, "count": parsed["count"]}
        if not parsed["stories"] and not parsed["matched"]:
            res.error = f"no Hacker News items mention {term!r}"
            return res.mark("empty")
        # phrase-search hits whose visible fields do not show the term are listed without a quote (cond 3)
        items = parsed["matched"] or [{"source": "hn", "id": s["id"], "kind": s["kind"], "permalink": s["permalink"], "created": s["created"],
                                       "quote": None} for s in parsed["stories"]]
        self._mentions_finding(res, items, f"HN Search for {term!r} ({parsed['count']} hits)")
        res.attr("last_activity", parsed["last_activity"])
        return res

    @staticmethod
    def _org_term(ctx: Any, entity: Entity) -> str | None:
        value = entity.value.strip()
        if entity.type is T.DOMAIN:
            owned = False
            try:
                owned = bool(ctx.org.owns(entity).own)
            except Exception:  # noqa: BLE001 - no profile means no ownership
                owned = False
            return value.lower() if owned or value.lower() in org_domains(ctx) else None
        folded = fold(value).strip()
        return value if len(folded) >= 3 and folded in org_terms(ctx) else None

    @staticmethod
    def _mentions_finding(res: ModuleResult, matched: list[dict[str, Any]], where: str) -> None:
        if not matched:
            return
        res.attr("org_mentions", matched[:MAX_MENTIONS])
        res.finding(
            "Hacker News items mention the organisation",
            "info",
            f"{len(matched)} Hacker News item(s) in {where} mention an organisation brand or domain; newest: "
            + "; ".join(f"{m['created'][:10] if m.get('created') else '?'} {m['permalink']}" for m in matched[:5]) + ".",
            confidence="probable",
            criterion="the item title, link or text contains an org-profile brand or domain (accent- and case-insensitive)",
            data={"items": matched[:MAX_MENTIONS]},
            tags=["context_only"],
            references=[m["permalink"] for m in matched[:5] if m.get("permalink")],
            source=SOURCE_ALGOLIA,
            observed_last=max((m["created"] for m in matched if m.get("created")), default=None),
        )
