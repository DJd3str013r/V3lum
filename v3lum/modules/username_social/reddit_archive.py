"""Arctic Shift Reddit archive (P108): archived posts and comments of a handle, reduced to counts and dates.

* Endpoints (cond 1): ``arctic-shift.photon-reddit.com/api/posts/search?author=<u>&limit=100`` and
  ``/api/comments/search?author=<u>&limit=100``, one page each. Keyword search needs a scope - the API refuses
  ``query`` without ``author`` or ``subreddit`` (HTTP 400, verified) - so a keyword seed runs only over the
  analyst-configured subreddits of setting ``reddit_archive_subreddits`` (at most 3, one page of 25 each); without
  them it is SKIPPED ``config``. Never ``users/interactions``, aggregations, ``users/aggregate_flairs``,
  ``users/search`` or ``comments/tree``.
* Terms 'unknown' (cond 2): disabled in every licence profile until legal records a class; default_enabled False.
* Case subjects only (cond 3, ``run_on='seeds'``). Records are reduced to id, subreddit, created_utc, permalink and
  a <= 500-character excerpt before ``res.raw``/evidence; reports quote <= 200 characters and only when an
  org-profile brand or domain is mentioned.
* No subreddit-participation profile (cond 4, LGPD art. 11): the report shows post/comment counts, first/last
  activity and linked domains only; no per-subreddit count or ranking is ever computed.
* Items deleted by their authors (cond 5) are labelled 'deleted by author', never quoted and keep no excerpt or
  linked domain; moderator removals are 'removed'.
* Errors (cond 6): an error JSON inside a 200 (or a 4xx) and 'Query timed out' are P321 error markers (ERROR,
  reason ``timeout`` for the latter); 429 is RATE_LIMITED; per-call timeout 10 s and module deadline 30 s; any
  failure is 'could not verify'. The doctor self-test is a benign handle lookup (``health_check``).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import (
    Problems,
    attempt,
    excerpt,
    extract_urls,
    host_of,
    iso,
    org_terms,
    quote_if_mentioned,
    report_problems,
    safe_url,
    to_int,
    to_str,
)

SOURCE = "arctic_shift.search"
BASE = "https://arctic-shift.photon-reddit.com/api/"
LIMIT = 100
KEYWORD_LIMIT = 25
MAX_SUBREDDITS = 3
CALL_TIMEOUT = 10.0  # cond 6: per call
EXCERPT_CAP = 500
DELETED_LABEL = "deleted by author"
REDDIT_INTERNAL = ("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com")
PLACEHOLDERS = frozenset({"[deleted]", "[removed]", "[deleted by user]", "[removed by reddit]", "[ removed by reddit ]"})
_AUTHOR_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
_SUB_RE = re.compile(r"^[A-Za-z0-9_]{2,21}$")
SETTING_SUBREDDITS = "reddit_archive_subreddits"


def author_ok(value: Any) -> bool:
    return isinstance(value, str) and bool(_AUTHOR_RE.match(value))


def search_url(kind: str, author: str, limit: int = LIMIT) -> str:
    """cond 1: posts|comments search by author, one page, limit clamped to 1..100."""
    return f"{BASE}{kind}/search?" + urlencode({"author": author, "limit": max(1, min(int(limit), LIMIT))})


def keyword_url(term: str, subreddit: str, limit: int = KEYWORD_LIMIT) -> str:
    return f"{BASE}posts/search?" + urlencode({"query": term, "subreddit": subreddit, "limit": max(1, min(int(limit), LIMIT))})


def author_of(entity: Entity) -> str | None:
    if entity.type is T.USERNAME:
        return re.sub(r"^/?u/", "", entity.value)
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
        return handle if platform == "reddit" else None
    if entity.type is T.URL:
        hit = platform_for_url(entity.value)
        return hit[1] if hit and hit[0] == "reddit" else None
    return None


def _deleted(item: dict[str, Any], text: str) -> tuple[bool, bool]:
    meta = item.get("_meta") if isinstance(item.get("_meta"), dict) else {}
    rbc = str(item.get("removed_by_category") or "").lower()
    removal = str(meta.get("removal_type") or "").lower()
    by_author = (text == "[deleted]" or rbc in ("deleted", "author") or removal == "deleted"
                 or (meta.get("was_deleted_later") is True and removal in ("", "deleted"))
                 or (item.get("author") == "[deleted]" and text != "[removed]"))
    removed = not by_author and (text == "[removed]" or rbc in ("moderator", "reddit", "anti_evil_ops", "automod_filtered",
                                                                 "copyright_takedown", "content_takedown", "community_ops")
                                 or removal.startswith("removed"))
    return by_author, removed


def reduce_item(item: Any, kind: str) -> dict[str, Any] | None:
    """cond 3/5: id, subreddit, created_utc, permalink and a <= 500-character excerpt; author-deleted items keep no
    text and no linked domain."""
    if not isinstance(item, dict):
        return None
    rid = to_str(str(item.get("id") or ""), 20)
    if not rid or not re.fullmatch(r"[a-z0-9]{1,20}", rid):
        return None
    if kind == "post":
        title = item.get("title") if isinstance(item.get("title"), str) else ""
        text = (item.get("selftext") if isinstance(item.get("selftext"), str) else "").strip()
        full = "\n".join(x for x in (title.strip(), text) if x and x.lower() not in PLACEHOLDERS)
    else:
        text = (item.get("body") if isinstance(item.get("body"), str) else "").strip()
        full = "" if text.lower() in PLACEHOLDERS else text
    by_author, removed = _deleted(item, text)
    sub = to_str(item.get("subreddit"), 40)
    sub = sub if sub and _SUB_RE.match(sub) else None
    perma = to_str(item.get("permalink"), 400)
    if perma and perma.startswith("/"):
        perma = "https://www.reddit.com" + perma
    elif not safe_url(perma or ""):
        link = str(item.get("link_id") or "").replace("t3_", "")
        if kind == "post" and sub:
            perma = f"https://www.reddit.com/r/{sub}/comments/{rid}/"
        elif sub and re.fullmatch(r"[a-z0-9]{1,20}", link):
            perma = f"https://www.reddit.com/r/{sub}/comments/{link}/_/{rid}/"
        else:
            perma = None
    created = to_int(item.get("created_utc"))
    linked: list[str] = []
    if not by_author:
        candidates = [item.get("url")] if kind == "post" and not item.get("is_self") else []
        candidates.extend(extract_urls(full))
        for u in candidates:
            h = host_of(u) if safe_url(u) else None
            if h and not any(h == d or h.endswith("." + d) for d in REDDIT_INTERNAL):
                h = h[4:] if h.startswith("www.") else h
                if h not in linked:
                    linked.append(h)
    return {"id": rid, "kind": kind, "subreddit": sub, "created_utc": created, "created": iso(created), "permalink": perma,
            "excerpt": None if by_author else excerpt(full, EXCERPT_CAP), "deleted_by_author": by_author,
            "label": DELETED_LABEL if by_author else None, "removed": removed, "linked_domains": linked[:10]}


def parse_page(data: Any, kind: str) -> tuple[list[dict[str, Any]], bool] | None:
    """One search page -> (reduced items, page_full) or None when the answer is not {'data': [...]}."""
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return None
    items = [r for r in (reduce_item(x, kind) for x in data["data"][:LIMIT]) if r]
    return items, len(data["data"]) >= LIMIT


def summarise(posts: list[dict[str, Any]], comments: list[dict[str, Any]], posts_full: bool, comments_full: bool) -> dict[str, Any]:
    """cond 4: counts, first/last activity and linked domains only - never a per-subreddit count or ranking."""
    everything = posts + comments
    times = [i["created_utc"] for i in everything if isinstance(i.get("created_utc"), int)]
    domains: list[str] = []
    for i in everything:
        for d in i["linked_domains"]:
            if d not in domains:
                domains.append(d)
    return {"posts": len(posts), "posts_at_least": posts_full, "comments": len(comments), "comments_at_least": comments_full,
            "first_activity": iso(min(times)) if times else None,
            "first_activity_bound": "upper_bound" if (posts_full or comments_full) else "exact",
            "last_activity": iso(max(times)) if times else None, "linked_domains": sorted(domains)[:50],
            "deleted_by_author": sum(1 for i in everything if i["deleted_by_author"]), "removed": sum(1 for i in everything if i["removed"])}


def org_matches(items: list[dict[str, Any]], terms: list[str]) -> list[dict[str, Any]]:
    """cond 3/5: <= 200-character quotes of items that mention an org-profile brand/domain; deleted items never."""
    out = []
    for i in items:
        if i["deleted_by_author"] or not i["excerpt"]:
            continue
        q = quote_if_mentioned(i["excerpt"], terms)
        if q:
            out.append({"source": "reddit", "id": i["id"], "kind": i["kind"], "permalink": i["permalink"], "created": i["created"], "quote": q})
    return out


@register
class RedditArchive(Module):
    name = "reddit_archive"
    title = "Arctic Shift Reddit archive (activity of a handle)"
    description = (
        "Archived Reddit posts and comments of a handle from the Arctic Shift archive (Pushshift successor, keyless): counts, "
        "first/last activity and linked domains, plus quotes of items that mention the organisation."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL, T.KEYWORD})
    produces = frozenset({T.DOMAIN, T.URL})
    run_on = "seeds"  # cond 3: analyst-typed handles/keywords that are case subjects
    terms = "unknown"  # cond 2
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "arctic_shift"
    sources = (SOURCE,)
    hosts = ("arctic-shift.photon-reddit.com",)
    access_model = "free_noauth_limited"
    max_requests = 3  # posts + comments, or up to 3 configured subreddits for a keyword
    expected_latency = 3.0  # 1.0-1.7 s per call observed, two calls
    timeout = 30.0  # cond 6: module deadline
    min_interval = 2.0
    cache_ttl = 86400
    daily_quota = 500
    max_pivots = 30
    default_enabled = False  # cond 2
    reference = "https://github.com/ArthurHeitmann/arctic_shift/blob/master/api/README.md"
    tags = frozenset({"free"})
    settings = {SETTING_SUBREDDITS: []}
    error_markers = (
        {"id": "arctic_shift_query_timeout", "statuses": [200, 400, 500, 503, 504], "regex": r"(?i)\"error\"\s*:\s*\"[^\"]{0,200}timed out",
         "maps_to": "error", "reason_code": "timeout", "reason": "Arctic Shift: query timed out (could not verify)"},
        {"id": "arctic_shift_error_object", "statuses": [200, 400, 422], "json_path": "error", "regex": ".",
         "maps_to": "error", "reason_code": "error", "reason": "Arctic Shift: error object instead of data (could not verify)"},
    )
    notice = (
        "Terms 'unknown' (volunteer archive without published terms): disabled in every licence profile until legal records a "
        "class. Counts, first/last activity and linked domains only (never a subreddit-participation profile, LGPD art. 11); "
        "items deleted by their authors are labelled and never quoted."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.USERNAME, "octocat", expect="ok")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return entity.type is T.KEYWORD or author_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.KEYWORD:
            return self._keyword(res, ctx, entity.value.strip())
        author = author_of(entity)
        if not author or not author_ok(author):
            return res.mark("skipped", "not a Reddit username (3-20 letters, digits, '_' or '-')", reason_code="not_applicable")
        problems: Problems = {}
        first = parse_page(ctx.http.get_json(search_url("posts", author), source=SOURCE, timeout=CALL_TIMEOUT), "post")
        if first is None:
            return res.mark("error", "unexpected Arctic Shift answer (no data[] list): could not verify")
        posts, posts_full = first
        got = attempt(problems, SOURCE, "comments search", lambda: ctx.http.get_json(search_url("comments", author), source=SOURCE, timeout=CALL_TIMEOUT))
        second = parse_page(got, "comment") if got is not None else None
        if got is not None and second is None:
            problems.setdefault(SOURCE, []).append((Status.ERROR, "error", "comments search: unexpected answer (no data[] list)"))
        comments, comments_full = second or ([], False)
        report_problems(res, problems)
        if not posts and not comments:
            if problems:
                status, code, reason = next(iter(problems.values()))[0]
                return res.mark(status, f"posts: none archived; {reason}"[:300], reason_code=code)
            res.error = f"no archived posts or comments for u/{author} in Arctic Shift (an archive gap is possible)"
            return res.mark("empty")
        summary = summarise(posts, comments, posts_full, comments_full and second is not None)
        res.raw = {"author": author, "posts": posts, "comments": comments}  # reduced records only (cond 3)
        res.attr("reddit_activity", summary)
        res.attr("last_activity", summary["last_activity"])
        matches = org_matches(posts + comments, org_terms(ctx))
        res.attr("org_mentions", matches[:20])
        for d in summary["linked_domains"][:20]:
            res.pivot(T.DOMAIN, d, "links_to", confidence="possible", expand=False,
                      note=f"domain linked in archived Reddit items of u/{author} (owner-chosen context, not identity evidence)")
        res.finding(
            "Archived Reddit activity",
            "info",
            f"u/{author} in the Arctic Shift archive: {summary['posts']}{'+' if summary['posts_at_least'] else ''} posts and "
            f"{summary['comments']}{'+' if summary['comments_at_least'] else ''} comments"
            + (f", first activity {'on or before ' if summary['first_activity_bound'] == 'upper_bound' else ''}{(summary['first_activity'] or '')[:10]}"
               if summary["first_activity"] else "")
            + (f", last {summary['last_activity'][:10]}" if summary["last_activity"] else "")
            + (f"; {summary['deleted_by_author']} item(s) {DELETED_LABEL}" if summary["deleted_by_author"] else "")
            + ". Counts and dates only: no subreddit profile is built.",
            confidence="probable",
            criterion="Arctic Shift returned archived items whose author is the handle (archive of public Reddit data)",
            data={k: summary[k] for k in ("posts", "comments", "first_activity", "last_activity")},
            tags=["account", "historical"],
            source=SOURCE,
            observed_first=summary["first_activity"],
            observed_last=summary["last_activity"],
        )
        if matches:
            self._mentions_finding(res, matches, f"items of u/{author}")
        return res

    def _keyword(self, res: ModuleResult, ctx: Any, term: str) -> ModuleResult:
        subs = [s.lstrip("r/").strip() for s in (ctx.setting(SETTING_SUBREDDITS) or []) if isinstance(s, str)]
        subs = [s for s in subs if _SUB_RE.match(s)][:MAX_SUBREDDITS]
        if not subs:
            return res.mark("skipped", f"keyword search needs analyst-chosen subreddits (setting {SETTING_SUBREDDITS}): the archive "
                                       "refuses unscoped keyword queries", reason_code="config")
        if len(term) < 3 or len(term) > 100:
            return res.mark("skipped", "keyword too short or too long for an archive search", reason_code="not_applicable")
        problems: Problems = {}
        items: list[dict[str, Any]] = []
        answered = 0
        for sub in subs:
            got = attempt(problems, SOURCE, f"r/{sub} search", lambda s=sub: ctx.http.get_json(keyword_url(term, s), source=SOURCE, timeout=CALL_TIMEOUT))
            page = parse_page(got, "post") if got is not None else None
            if page is not None:
                answered += 1
                items.extend(page[0])
        report_problems(res, problems)
        if not answered:
            status, code, reason = next(iter(problems.values()))[0] if problems else (Status.ERROR, "error", "no answer")
            return res.mark(status, f"no configured subreddit could be searched: {reason}"[:300], reason_code=code)
        if not items:
            res.error = f"no archived posts mention {term!r} in the configured subreddits"
            return res.mark("empty")
        res.raw = {"query": term, "subreddits": subs, "posts": items}
        live = [i for i in items if not i["deleted_by_author"]]
        times = [i["created_utc"] for i in live if isinstance(i.get("created_utc"), int)]
        res.attr("reddit_activity", {"posts": len(items), "posts_at_least": False, "comments": 0, "comments_at_least": False,
                                     "first_activity": iso(min(times)) if times else None, "first_activity_bound": "exact",
                                     "last_activity": iso(max(times)) if times else None,
                                     "linked_domains": sorted({d for i in live for d in i["linked_domains"]})[:50],
                                     "deleted_by_author": len(items) - len(live), "removed": sum(1 for i in items if i["removed"])})
        matches = org_matches(items, [term.casefold(), *org_terms(ctx)])
        if matches:
            self._mentions_finding(res, matches, f"posts matching {term!r} in {len(subs)} configured subreddit(s)")
        return res

    @staticmethod
    def _mentions_finding(res: ModuleResult, matches: list[dict[str, Any]], where: str) -> None:
        res.attr("org_mentions", matches[:20])
        res.finding(
            "Archived Reddit items mention the organisation",
            "info",
            f"{len(matches)} archived Reddit item(s) in {where} mention an organisation brand or domain; newest: "
            + "; ".join(f"{(m['created'] or '?')[:10]} {m['permalink']}" for m in sorted(matches, key=lambda m: m["created"] or "", reverse=True)[:5])
            + ".",
            confidence="probable",
            criterion="the item text contains an org-profile brand or domain (accent- and case-insensitive); quotes <= 200 characters",
            data={"items": matches[:20]},
            tags=["context_only"],
            references=[m["permalink"] for m in matches[:5] if m["permalink"]],
            source=SOURCE,
            observed_last=max((m["created"] for m in matches if m["created"]), default=None),
        )
