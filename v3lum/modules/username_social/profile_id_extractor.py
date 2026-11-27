"""Profile id and metadata extraction from pages a module already holds (P107, batch p2-G05-2).

A shared helper, **not a fetching module** (P107 cond 1): ``username_check`` (P113) and the profile
enrichers (github_user, gitlab_user, dockerhub, bluesky, telegram_public...) call
:func:`extract_profile_ids` on a response body they already fetched and :func:`apply_profile_ids` to
record the facts on their own result. It makes no request, so the caller's disclosure, TLP and
host allow-list are unchanged. The final home named by the council is ``v3lum/core/profile_ids.py``;
core files belong to the core team, so the helper lives here until it is moved (core request).

Conditions served:

* cond 1/2 - schemes adapted from socid-extractor 0.1.2 (MIT) for the enabled platforms only, each
  pinned to its page host **and** path (:func:`scheme_for_url`): a GitHub ``/search/users`` body
  carries the GitHub API flags but is not a profile. The library is **not imported**: its import runs
  every ``~/.socid_extractor/plugins/*.py`` file and loads entry-point plugins (code execution that
  bypasses AR12), its ``My Mail.ru`` scheme fetches ``http://appsmail.ru`` inside ``extract()``, its
  ``json.loads`` is unguarded and its debug path writes extracted personal data to the working
  directory. The stdlib port below reproduces the 0.1.2 field mappings of the enabled schemes, runs
  regexes only on a body capped at 2 MB (:data:`MAX_BODY_BYTES`), never calls a fetching helper and
  never fetches an extracted URL.
* cond 3 - stable ids (uid, gravatar_id...), creation dates, counters and flags become attributes of
  that profile (``profile_ids``); extracted usernames pass :func:`is_plausible_username` (maigret,
  MIT).
* cond 4/5 - extracted identifiers are listed as 'linked accounts found on profile' with the source
  page and pivot with ``expand=False``; :func:`plan_profile_expansion` holds them in the default
  preset and allows depth <= 1, PROBABLE+ links, ``--preset deep`` or analyst selection and at most
  two auto-expanded handles per seed, one request each to the platform's own enricher; bare usernames
  never go to the username packs without the analyst.
* cond 6 - names, e-mails and phones stay attributes of that profile (``profile_personal``, POSSIBLE)
  and pivot only with ``expand=False`` and a note: never into person_name, breach or stealer modules.
* cond 7 - every extracted value is owner-written (attacker-controlled when the subject is an actor):
  passive use only. One trimmed saved page per enabled scheme is under
  ``tests/fixtures/profile_id_extractor/``.

Adapted code (A6 header): field mappings and postprocessors from socid-extractor
(https://github.com/soxoj/socid-extractor, release 0.1.2, socid_extractor/schemes.py and
postprocessor.py, MIT License, Copyright (c) 2020 Soxoj); ``is_plausible_username`` from maigret
(https://github.com/soxoj/maigret, commit 50e62c45e17b03fd3f059622d38a4cdb3ec2eab4,
maigret/utils.py, MIT License, Copyright (c) 2020-2026 Soxoj). Notices:
``v3lum/data/notices/profile_ids_socid_extractor.json`` and
``profile_ids_maigret_plausible_username.json``.
"""

from __future__ import annotations

import ast
import html as html_lib
import json
import re
from collections.abc import Callable, Iterable
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote, urlsplit

from v3lum.core.entities import EntityType as T

__all__ = [
    "ENABLED_SCHEMES",
    "MAX_AUTO_EXPANSIONS",
    "MAX_BODY_BYTES",
    "NOT_ENABLED_SCHEMES",
    "PLATFORM_ENRICHERS",
    "account_from_url",
    "apply_profile_ids",
    "cap_body",
    "extract_profile_fields",
    "extract_profile_ids",
    "implausible_reason",
    "is_plausible_username",
    "normalise_profile_ids",
    "plan_profile_expansion",
    "scheme_for_url",
]

#: cond 2: bodies are capped at 2 MB before any scheme regex runs.
MAX_BODY_BYTES = 2 * 1024 * 1024
#: cond 4: at most two auto-expanded handles per seed (deep preset, PROBABLE+ links, depth <= 1).
MAX_AUTO_EXPANSIONS = 2
_LITERAL_CAP = 64 * 1024
_MAX_LIST = 50

# Enabled schemes: socid-extractor 0.1.2 scheme name -> page host(s) + path pinned, the platform and the
# V3LUM caller that already holds the page (cond 1/2).
ENABLED_SCHEMES: dict[str, dict[str, Any]] = {
    "GitHub API": {"hosts": ("api.github.com",), "path": r"^/users/[A-Za-z0-9-]{1,39}/?$", "platform": "github",
                   "caller": "github_user (P111)"},
    "Gitlab API": {"hosts": ("gitlab.com",), "path": r"^/api/v4/users/?$", "platform": "gitlab",
                   "caller": "gitlab_user (P103)"},
    "Docker Hub API": {"hosts": ("hub.docker.com",), "path": r"^/v2/users/[^/]+/?$", "platform": "dockerhub",
                       "caller": "dockerhub (P102)"},
    "Bluesky API": {"hosts": ("public.api.bsky.app", "api.bsky.app"), "path": r"^/xrpc/app\.bsky\.actor\.getProfile$",
                    "platform": "bluesky", "caller": "bluesky (P099)"},
    "HuggingFace API": {"hosts": ("huggingface.co",), "path": r"^/api/users/[^/]+/overview/?$", "platform": "huggingface",
                        "caller": "Hugging Face enricher (P100)"},
    "Gravatar": {"hosts": ("en.gravatar.com", "gravatar.com", "www.gravatar.com"), "path": r"^/[^/]+\.json$",
                 "platform": "gravatar", "caller": "username_check (P113) Gravatar site"},
    "Telegram": {"hosts": ("t.me",), "path": r"^/[A-Za-z0-9_]{4,32}/?$", "platform": "telegram", "caller": "telegram_public (P112)"},
    "Dribbble profile": {"hosts": ("dribbble.com",), "path": r"^/[A-Za-z0-9_-]+/?$", "platform": "dribbble",
                         "caller": "username_check (P113)"},
    "Linktree": {"hosts": ("linktr.ee",), "path": r"^/[A-Za-z0-9_.]+/?$", "platform": "linktree", "caller": "username_check (P113)"},
    "Keybase API": {"hosts": ("keybase.io",), "path": r"^/_/api/1\.0/user/lookup\.json$", "platform": "keybase",
                    "caller": "keybase (P104, P3: runs only once that module ships)"},
}

#: Schemes that never run in V3LUM (cond 2) with the reason.
NOT_ENABLED_SCHEMES: dict[str, str] = {
    "My Mail.ru": "its field lambda calls utils.get_mymail_uid(): a plain-HTTP GET to appsmail.ru during extract()",
    "About.me profile": "stale: current about.me pages lack the 'aboutme_prod:page' flag and nest the name under mainEntity",
    "HackerNews": "HTML scheme; V3LUM reads Hacker News through the Firebase JSON API (P109)",
    "Gitea / Forgejo": "HTML scheme; V3LUM uses the Codeberg/Gitea JSON API",
    "GitHub Social Accounts API": "/users/{u}/social_accounts is not in P111's endpoint list",
}

#: cond 5: the platform's own enricher (one request for an owner-linked account).
PLATFORM_ENRICHERS: dict[str, str] = {
    "github": "github_user", "gitlab": "gitlab_user", "dockerhub": "dockerhub", "bluesky": "bluesky",
    "telegram": "telegram_public", "codeberg": "codeberg_user", "huggingface": "huggingface_user", "keybase": "keybase",
}


# ---------------------------------------------------------------------------------------------
# body cap and scheme selection (cond 1/2)
# ---------------------------------------------------------------------------------------------


def cap_body(raw: Any, limit: int = MAX_BODY_BYTES) -> tuple[str, bool]:
    """cond 2: a held body (bytes or text) capped at ``limit`` bytes -> (text, truncated)."""
    if isinstance(raw, str):
        data = raw.encode("utf-8", "replace")
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
    else:
        return "", False
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data[:limit].decode("utf-8", "ignore"), len(data) > limit


def _host(url: Any) -> str:
    try:
        return (urlsplit(str(url)).hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


def scheme_for_url(url: Any) -> str | None:
    """cond 1/2: the one enabled scheme allowed on the page fetched from ``url`` (host and path pinned)."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").rstrip(".").lower()
    path = parts.path or "/"
    for name, spec in ENABLED_SCHEMES.items():
        if host in spec["hosts"] and re.match(spec["path"], path):
            return name
    return None


# ---------------------------------------------------------------------------------------------
# a minimal DOM (html.parser) for the two HTML schemes
# ---------------------------------------------------------------------------------------------

_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})


class _Node:
    __slots__ = ("attrs", "children", "parent", "tag")

    def __init__(self, tag: str, attrs: dict[str, str], parent: _Node | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.children: list[Any] = []
        self.parent = parent

    def classes(self) -> list[str]:
        return (self.attrs.get("class") or "").split()


class _DomBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#root", {}, None)
        self.cur = self.root

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, {k: (v or "") for k, v in attrs}, self.cur)
        self.cur.children.append(node)
        if tag not in _VOID:
            self.cur = node

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.cur.children.append(_Node(tag, {k: (v or "") for k, v in attrs}, self.cur))

    def handle_endtag(self, tag: str) -> None:
        node: _Node | None = self.cur
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.cur = node.parent

    def handle_data(self, data: str) -> None:
        self.cur.children.append(data)


def _dom(text: str) -> _Node:
    builder = _DomBuilder()
    try:
        builder.feed(text)
        builder.close()
    except Exception:  # noqa: BLE001 - html.parser rarely raises; keep what was built
        pass
    return builder.root


def _nodes(node: _Node) -> Iterable[_Node]:
    stack: list[Any] = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, _Node):
            yield n
            stack.extend(reversed([c for c in n.children if isinstance(c, _Node)]))


def _find(node: _Node | None, tag: str, cls: str | None = None) -> _Node | None:
    if node is None:
        return None
    for n in _nodes(node):
        if n.tag == tag and (cls is None or cls in n.classes()):
            return n
    return None


def _text(node: _Node | None, sep: str = "") -> str | None:
    if node is None:
        return None
    out: list[str] = []
    stack: list[Any] = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, str):
            out.append(n)
        elif n.tag not in ("script", "style"):
            stack.extend(reversed(n.children))
    return sep.join(out)


def _meta(root: _Node, key: str, attr: str = "property") -> str | None:
    for n in _nodes(root):
        if n.tag == "meta" and n.attrs.get(attr) == key:
            return n.attrs.get("content")
    return None


# ---------------------------------------------------------------------------------------------
# stdlib port of the enabled socid-extractor 0.1.2 schemes (MIT, see the module docstring)
# ---------------------------------------------------------------------------------------------


def _e0(x: Any) -> Any:
    return x["entry"][0]


def _them(x: Any) -> Any:
    return x["them"][0]


def _proof(group: str) -> Callable[[Any], Any]:
    return lambda x: _them(x)["proofs_summary"]["by_presentation_group"].get(group, [{}])[0].get("nametag")


def _hf_image(x: Any) -> Any:
    url = x.get("avatarUrl")
    if not url:
        return None
    return url if str(url).startswith("http") else "https://huggingface.co" + str(url)


_SCHEME_FIELDS: dict[str, dict[str, Callable[[Any], Any]]] = {
    "GitHub API": {
        "uid": lambda x: x.get("id"), "image": lambda x: x.get("avatar_url"), "created_at": lambda x: x.get("created_at"),
        "location": lambda x: x.get("location"), "follower_count": lambda x: x.get("followers"),
        "following_count": lambda x: x.get("following"), "fullname": lambda x: x.get("name"),
        "public_gists_count": lambda x: x.get("public_gists"), "public_repos_count": lambda x: x.get("public_repos"),
        "twitter_username": lambda x: x.get("twitter_username"), "is_looking_for_job": lambda x: x.get("hireable"),
        "gravatar_id": lambda x: x.get("gravatar_id"), "bio": lambda x: x["bio"].strip() if x.get("bio", "") else None,
        "company": lambda x: x.get("company"), "blog_url": lambda x: x.get("blog"),
    },
    "Gitlab API": {
        "uid": lambda x: x.get("id"), "fullname": lambda x: x.get("name"), "username": lambda x: x.get("username"),
        "state": lambda x: x.get("state"), "image": lambda x: x.get("avatar_url"), "website": lambda x: x.get("web_url") or None,
        "email": lambda x: x.get("public_email") or None,
        "emails": lambda x: [x["public_email"]] if x.get("public_email") else None,
    },
    "Docker Hub API": {
        "uid": lambda x: x.get("id"), "username": lambda x: x.get("username"), "full_name": lambda x: x.get("full_name"),
        "location": lambda x: x.get("location"), "company": lambda x: x.get("company"),
        "created_at": lambda x: x.get("date_joined"),  # socid 0.1.2 reads 'data_joined' (a typo): fixed here
        "type": lambda x: x.get("type"), "image": lambda x: x.get("gravatar_url"),
    },
    "Bluesky API": {
        "uid": lambda x: x.get("did"),
        "username": lambda x: str(x["handle"]).removesuffix(".bsky.social") if x.get("handle") else None,
        "fullname": lambda x: x.get("displayName"), "bio": lambda x: x.get("description"), "image": lambda x: x.get("avatar"),
        "image_bg": lambda x: x.get("banner"), "created_at": lambda x: x.get("createdAt"),
        "follower_count": lambda x: x.get("followersCount"), "following_count": lambda x: x.get("followsCount"),
        "posts_count": lambda x: x.get("postsCount"),
    },
    "HuggingFace API": {
        "uid": lambda x: x.get("_id"), "username": lambda x: x.get("user"), "fullname": lambda x: x.get("fullname") or None,
        "bio": lambda x: x.get("details") or None, "image": _hf_image, "is_pro": lambda x: x.get("isPro"),
        "follower_count": lambda x: x.get("numFollowers"), "following_count": lambda x: x.get("numFollowing"),
        "likes_count": lambda x: x.get("numLikes"), "upvotes_count": lambda x: x.get("numUpvotes"),
        "created_at": lambda x: x.get("createdAt"), "huggingface_models": lambda x: x.get("numModels"),
        "huggingface_datasets": lambda x: x.get("numDatasets"), "huggingface_spaces": lambda x: x.get("numSpaces"),
        "huggingface_papers": lambda x: x.get("numPapers"),
    },
    "Gravatar": {
        "gravatar_id": lambda x: _e0(x)["id"], "image": lambda x: _e0(x)["thumbnailUrl"],
        "username": lambda x: _e0(x)["preferredUsername"], "fullname": lambda x: _e0(x).get("name", {}).get("formatted"),
        "name": lambda x: _e0(x)["displayName"], "location": lambda x: _e0(x).get("currentLocation"),
        "emails": lambda x: [y["value"] for y in _e0(x).get("emails", [])],
        "links": lambda x: [y["url"] for y in _e0(x).get("accounts", [])] + [y["value"] for y in _e0(x).get("urls", [])],
        "bio": lambda x: _e0(x).get("aboutMe"),
    },
    "Keybase API": {
        "uid": lambda x: _them(x)["id"], "username": lambda x: _them(x)["basics"]["username"],
        "name": lambda x: _them(x).get("profile", {}).get("full_name"),
        "location": lambda x: _them(x).get("profile", {}).get("location"), "bio": lambda x: _them(x).get("profile", {}).get("bio"),
        "twitter_username": _proof("twitter"), "github_username": _proof("github"), "reddit_username": _proof("reddit"),
        "hackernews_username": _proof("hackernews"),
    },
    "Linktree": {
        "id": lambda x: x.get("account", {}).get("id"), "username": lambda x: x.get("username"),
        "image": lambda x: x.get("profilePictureUrl"), "is_active": lambda x: x.get("account", {}).get("isActive"),
        "is_verified": lambda x: x.get("isProfileVerified"), "bio": lambda x: x.get("description"),
        "tier": lambda x: x.get("account", {}).get("tier"),
        "social_links": lambda x: {(s["type"].lower() if not s["type"].startswith("EMAIL") else "email"): s["url"]
                                   for s in x.get("socialLinks", [])},
        "links": lambda x: [y.get("url") for y in x.get("account", {}).get("links", [])],
    },
}

_SCHEME_SPEC: dict[str, dict[str, Any]] = {
    "GitHub API": {"flags": ("gists_url", "received_events_url"), "regex": r"^({[\S\s]+?})$"},
    "Gitlab API": {"flags": ("avatar_url", '"web_url"', '"state"'), "regex": r"^\[({[\S\s]+?})\]$"},
    "Docker Hub API": {"flags": ('{"id":"', '"type":"User"}'), "regex": r"^({[\S\s]+?})$"},
    "Bluesky API": {"flags": ('"did":', '"handle":', '"followersCount"'), "regex": r"^(\{[\s\S]+\})$"},
    "HuggingFace API": {"flags": ('"numModels":', '"numDatasets":', '"numSpaces":'), "regex": r"^(\{[\s\S]+\})$"},
    "Gravatar": {"flags": ("gravatar.com\\/avatar", "thumbnailUrl"), "regex": r"^(.+?)$"},
    "Keybase API": {"flags": ('{"status":{"code":0,"name":"OK"},"them":',), "regex": r'^(.+?"them":\[{.+?}\]})$'},
    "Telegram": {"flags": ("tgme_page_title",)},
    "Dribbble profile": {"flags": ("dribbble.com", "og:type", "Dribbble", "profile")},
    "Linktree": {"flags": ("linktr.ee", "__NEXT_DATA__"),
                 "regex": r'id="__NEXT_DATA__" type="application\/json"[^>]*>(.+?)<\/script>'},
}

_GRAVATAR_HASH_RE = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})(?![0-9a-f])", re.I)


def _socid_value(value: Any) -> str:
    """socid map_fields semantics: str(value) unless None, [] or {} (dropped later)."""
    if value is None or value == [] or value == {}:
        return ""
    return str(value)


def _json_by_regex(page: str, pattern: str) -> tuple[Any, str | None]:
    m = re.search(pattern, page, re.MULTILINE)
    if not m:
        return None, "regex_no_match"
    try:
        return json.loads(m.group(1)), None
    except (ValueError, RecursionError):
        return None, "malformed_json"


def _html_fields(name: str, page: str) -> dict[str, str]:
    root = _dom(page)
    out: dict[str, Any] = {}
    if name == "Telegram":
        title = _find(root, "div", "tgme_page_title")
        img = _find(root, "img", "tgme_page_photo_image")
        desc = _find(root, "div", "tgme_page_description")
        span = _find(title, "span")
        out = {"fullname": _text(span), "image": img.attrs.get("src") if img is not None else None, "bio": _text(desc, "\n")}
    elif name == "Dribbble profile":
        m = re.search(r"dribbble\.com/([^/?#]+)", _meta(root, "og:url") or "")
        out = {"username": m.group(1) if m else None, "fullname": _meta(root, "og:title"),
               "bio": _meta(root, "description", "name"), "image": _meta(root, "og:image")}
    return {k: ("" if v is None else str(v)) for k, v in out.items()}


def _postprocess(values: dict[str, str]) -> dict[str, str]:
    """The socid POSTPROCESSORS that matter for the enabled schemes (Gravatar hash, e-mail local part)."""
    out = dict(values)
    for key in ("gravatar_url", "image"):
        v = out.get(key)
        if isinstance(v, str) and re.match(r"^https?://(www\.)?gravatar\.com/?$", v.strip()):
            out[key] = ""
    img = out.get("image")
    if img:
        m = _GRAVATAR_HASH_RE.search(img)
        if m:
            h = m.group(1).lower()
            out["gravatar_url"] = f"https://gravatar.com/{h}"
            out["gravatar_email_md5_hash" if len(h) == 32 else "gravatar_email_sha256_hash"] = h
    for key, v in list(out.items()):
        if v and isinstance(v, str) and v[0] not in "'[{\"" and "email" in key and "@" in v:
            out[key + "_username"] = v.split("@")[0]
    return out


def extract_profile_fields(page: Any, url: str | None = None) -> dict[str, str]:
    """Run the one enabled scheme pinned to ``url`` over ``page`` (cond 1/2).

    Returns socid-shaped fields (string values; lists/dicts as Python reprs) plus ``_extractor`` (the
    scheme), or ``{}`` when no enabled scheme applies or its flags are missing. Broken JSON behind
    matching flags gives ``{'_extractor': name, '_error': 'malformed_json'}`` (socid raises there).
    Never fetches anything.
    """
    text, truncated = cap_body(page)
    name = scheme_for_url(url) if url else None
    spec = _SCHEME_SPEC.get(name or "")
    if not name or not spec or not all(flag in text for flag in spec["flags"]):
        return {}
    extra = {"_truncated": "True"} if truncated else {}
    if name in ("Telegram", "Dribbble profile"):
        values = _html_fields(name, text)
    else:
        data, err = _json_by_regex(text, spec["regex"])
        if err:
            return {"_extractor": name, "_error": err, **extra}
        if name == "Linktree":
            try:
                data = data["props"]["pageProps"]
            except (KeyError, TypeError, IndexError):
                data = None
        if not isinstance(data, dict):
            return {"_extractor": name, "_error": "unexpected_shape", **extra}
        values = {}
        for field, getter in _SCHEME_FIELDS[name].items():
            try:
                values[field] = _socid_value(getter(data))
            except (AttributeError, KeyError, IndexError, TypeError, ValueError):
                continue
    values = _postprocess(values)
    result = {k: html_lib.unescape(v) for k, v in values.items() if isinstance(v, str) and v}
    if result:
        result["_extractor"] = name
        result.update(extra)
    return result


# ---------------------------------------------------------------------------------------------
# plausible usernames (maigret utils.is_plausible_username, MIT)
# ---------------------------------------------------------------------------------------------


def implausible_reason(value: Any) -> str | None:
    """Why ``value`` is not a plausible username ('empty', 'url', 'path', 'whitespace', 'email'), or None."""
    if not isinstance(value, str) or not value.strip():
        return "empty"
    s = value.strip()
    if "://" in s or s.startswith(("http://", "https://", "www.", "//")):
        return "url"
    if "/" in s:
        return "path"
    if any(c.isspace() for c in s):
        return "whitespace"
    if "@" in s and "." in s:
        return "email"
    return None


def is_plausible_username(value: Any) -> bool:
    """cond 3: maigret's plausible-username check (rejects URLs, paths, whitespace and e-mail-like values)."""
    return implausible_reason(value) is None


# ---------------------------------------------------------------------------------------------
# normaliser: socid fields -> V3LUM facts and pivot plans (cond 3-7)
# ---------------------------------------------------------------------------------------------

_HANDLE_PLATFORMS = {
    "twitter": "x", "x": "x", "github": "github", "gitlab": "gitlab", "bluesky": "bluesky", "linkedin": "linkedin",
    "youtube": "youtube", "twitch": "twitch", "facebook": "facebook", "instagram": "instagram", "reddit": "reddit",
    "hackernews": "hackernews", "telegram": "telegram", "keybase": "keybase", "medium": "medium", "tiktok": "tiktok",
    "dockerhub": "dockerhub", "huggingface": "huggingface", "codeberg": "codeberg", "devto": "devto",
}
_URL_ACCOUNT_RULES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("github.com", "www.github.com"), "github", r"^/([A-Za-z0-9-]{1,39})/?$"),
    (("gitlab.com",), "gitlab", r"^/([A-Za-z0-9_.-]{1,255})/?$"),
    (("twitter.com", "www.twitter.com", "x.com", "www.x.com", "mobile.twitter.com"), "x", r"^/@?([A-Za-z0-9_]{1,15})/?$"),
    (("instagram.com", "www.instagram.com"), "instagram", r"^/([A-Za-z0-9_.]{1,30})/?$"),
    (("t.me", "telegram.me"), "telegram", r"^/([A-Za-z0-9_]{4,32})/?$"),
    (("bsky.app",), "bluesky", r"^/profile/([A-Za-z0-9.:-]{3,253})/?$"),
    (("www.linkedin.com", "linkedin.com"), "linkedin", r"^/in/([A-Za-z0-9_%-]{3,100})/?$"),
    (("www.youtube.com", "youtube.com"), "youtube", r"^/@([A-Za-z0-9_.-]{3,30})/?$"),
    (("www.reddit.com", "reddit.com"), "reddit", r"^/(?:u|user)/([A-Za-z0-9_-]{3,20})/?$"),
    (("keybase.io",), "keybase", r"^/([A-Za-z0-9_]{2,16})/?$"),
    (("huggingface.co",), "huggingface", r"^/([A-Za-z0-9_.-]{2,96})/?$"),
    (("codeberg.org",), "codeberg", r"^/([A-Za-z0-9_.-]{1,40})/?$"),
    (("hub.docker.com",), "dockerhub", r"^/u/([a-z0-9]{4,30})/?$"),
    (("dev.to",), "devto", r"^/([A-Za-z0-9_]{2,30})/?$"),
    (("linktr.ee",), "linktree", r"^/([A-Za-z0-9_.]{2,30})/?$"),
    (("medium.com",), "medium", r"^/@([A-Za-z0-9_.]{1,50})/?$"),
    (("www.tiktok.com", "tiktok.com"), "tiktok", r"^/@([A-Za-z0-9_.]{2,24})/?$"),
    (("dribbble.com",), "dribbble", r"^/([A-Za-z0-9_-]{2,40})/?$"),
    (("gravatar.com", "en.gravatar.com"), "gravatar", r"^/([A-Za-z0-9_.-]{2,60})/?$"),
)
_PERSONAL_KEYS = frozenset({"fullname", "full_name", "name", "first_name", "last_name", "location", "bio", "about",
                            "birthday", "gender", "company"})
_EMAIL_KEYS = frozenset({"email", "emails", "business_email", "public_email"})
_PHONE_KEYS = frozenset({"phone", "phones", "phone_number"})
_LINK_KEYS = frozenset({"links", "website", "blog_url", "external_url", "channel_url", "link", "url", "homepage", "social_links"})
_IMAGE_KEYS = frozenset({"image", "image_bg", "avatar", "profile_image"})
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _parse_value(value: Any) -> Any:
    """socid values are strings; lists/dicts arrive as Python reprs: literal_eval (literals only, 64 KB cap)."""
    if not isinstance(value, str):
        return value
    s = value.strip()
    if s[:1] in ("[", "{") and len(s) <= _LITERAL_CAP:
        try:
            return ast.literal_eval(s)
        except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
            return value
    return value


def _strings(value: Any) -> list[str]:
    v = _parse_value(value)
    if isinstance(v, (list, tuple, set)):
        items = list(v)
    elif isinstance(v, dict):
        items = list(v.values())
    else:
        items = [v]
    return [str(x).strip() for x in items[:_MAX_LIST] if isinstance(x, (str, int)) and not isinstance(x, bool) and str(x).strip()]


def account_from_url(url: Any) -> dict[str, str] | None:
    """An http(s) profile URL of a known platform -> {platform, handle, url}, else None (never fetched)."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower()
    for hosts, platform, rx in _URL_ACCOUNT_RULES:
        if host in hosts:
            m = re.match(rx, parts.path or "")
            if m and is_plausible_username(unquote(m.group(1))):
                return {"platform": platform, "handle": unquote(m.group(1)), "url": url.strip()}
    return None


def _bad_host(host: str) -> bool:
    return not host or "." not in host or ":" in host or bool(_IPV4_RE.match(host))


def normalise_profile_ids(fields: Any, source_url: str, platform: str | None = None) -> dict[str, Any]:
    """socid-shaped fields of one profile page -> V3LUM facts (cond 3-7).

    Keys: ``scheme``, ``source_page``, ``platform``, ``attributes`` (stable ids, creation date, counters
    and flags of THAT profile), ``personal`` (names, location, bio, e-mails, phones: POSSIBLE, never
    auto-pivoted), ``own_username``, ``linked_accounts`` ('linked accounts found on profile', each with
    ``source_page``), ``links`` (other owner-written URLs, never fetched), ``avatar_urls`` and
    ``gravatar_hashes`` (local comparison only, P114 cond 7), ``rejected`` ([key, value, reason]) and
    ``error``.
    """
    out: dict[str, Any] = {"scheme": None, "source_page": source_url, "platform": platform, "attributes": {}, "personal": {},
                           "own_username": None, "linked_accounts": [], "links": [], "avatar_urls": [], "gravatar_hashes": [],
                           "rejected": [], "error": None}
    if not isinstance(fields, dict):
        out["error"] = "not_a_dict"
        return out
    out["scheme"] = fields.get("_extractor")
    if fields.get("_error"):
        out["error"] = str(fields["_error"])
    if out["platform"] is None and out["scheme"] in ENABLED_SCHEMES:
        out["platform"] = ENABLED_SCHEMES[out["scheme"]]["platform"]
    seen: set[tuple[Any, str]] = set()

    def add_account(plat: str | None, handle: str, url: str | None, key: str) -> None:
        k = (plat, handle.lower())
        if k in seen or len(out["linked_accounts"]) >= _MAX_LIST:
            return
        seen.add(k)
        out["linked_accounts"].append({"platform": plat, "handle": handle, "url": url, "qualified": plat is not None,
                                       "source_page": source_url, "key": key})

    def add_hash(h: str) -> None:
        entry = {"algo": "md5" if len(h) == 32 else "sha256", "hash": h}
        if entry not in out["gravatar_hashes"]:
            out["gravatar_hashes"].append(entry)

    for key, raw in fields.items():
        if not isinstance(key, str) or key.startswith("_"):
            continue
        lkey = key.lower()
        if lkey in ("gravatar_email_md5_hash", "gravatar_email_sha256_hash"):
            if isinstance(raw, str) and re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", raw.strip().lower()):
                add_hash(raw.strip().lower())
            continue
        if lkey == "gravatar_url":
            out["attributes"]["gravatar_profile_url"] = raw
            continue
        if "email" in lkey and lkey.endswith("_username"):
            out["rejected"].append([key, raw, "derived_from_email"])
            continue
        if lkey in _IMAGE_KEYS:
            for v in _strings(raw):
                if v.startswith(("http://", "https://")) and v not in out["avatar_urls"]:
                    out["avatar_urls"].append(v)
                    m = _GRAVATAR_HASH_RE.search(v)
                    if m:
                        add_hash(m.group(1).lower())
            continue
        if lkey == "username":
            reason = implausible_reason(raw)
            if reason:
                out["rejected"].append([key, raw, reason])
            else:
                out["own_username"] = str(raw).strip()
            continue
        if lkey.endswith("_usernames") or lkey.endswith("_username"):
            base = lkey[: -len("_usernames")] if lkey.endswith("_usernames") else lkey[: -len("_username")]
            plat = _HANDLE_PLATFORMS.get(base)
            for v in _strings(raw):
                reason = implausible_reason(v)
                if reason:
                    out["rejected"].append([key, v, reason])
                    acc = account_from_url(v) if reason == "url" else None
                    if acc:
                        add_account(acc["platform"], acc["handle"], acc["url"], key)
                    continue
                add_account(plat, v.lstrip("@"), None, key)
            continue
        if lkey in _EMAIL_KEYS:
            for v in _strings(raw):
                if _EMAIL_RE.match(v):
                    emails = out["personal"].setdefault("emails", [])
                    if v.lower() not in [e.lower() for e in emails]:
                        emails.append(v)
                else:
                    out["rejected"].append([key, v, "not_an_email"])
            continue
        if lkey in _PHONE_KEYS:
            out["personal"].setdefault("phones", []).extend(_strings(raw))
            continue
        if lkey in _PERSONAL_KEYS:
            out["personal"][lkey] = raw
            continue
        if lkey in _LINK_KEYS:
            for v in _strings(raw):
                if v.lower().startswith("mailto:"):
                    addr = unquote(v[7:]).split("?")[0]
                    if _EMAIL_RE.match(addr):
                        emails = out["personal"].setdefault("emails", [])
                        if addr.lower() not in [e.lower() for e in emails]:
                            emails.append(addr)
                    continue
                if not v.lower().startswith(("http://", "https://")):
                    out["rejected"].append([key, v, "not_http_url"])
                    continue
                acc = account_from_url(v)
                if acc:
                    add_account(acc["platform"], acc["handle"], acc["url"], key)
                    continue
                if _bad_host(_host(v)):
                    out["rejected"].append([key, v, "ip_or_bad_host"])
                    continue
                if v not in out["links"] and len(out["links"]) < _MAX_LIST:
                    out["links"].append(v)
            continue
        out["attributes"][lkey] = raw  # stable ids, created_at, counters, flags (cond 3)
    own = (out["platform"], (out["own_username"] or "").lower())
    out["linked_accounts"] = [a for a in out["linked_accounts"] if (a["platform"], a["handle"].lower()) != own]
    return out


def extract_profile_ids(url: str, body: Any, *, platform: str | None = None) -> dict[str, Any] | None:
    """cond 1: the profile facts of a page the caller already holds, or None when no enabled scheme is
    pinned to ``url``. Never fetches anything (not ``url``, not any extracted URL)."""
    if scheme_for_url(url) is None:
        return None
    return normalise_profile_ids(extract_profile_fields(body, url), url, platform)


# ---------------------------------------------------------------------------------------------
# recording on the caller's result (cond 3, 4, 6, 7)
# ---------------------------------------------------------------------------------------------

_OWNER_NOTE = "owner-written on {page}: passive use only, analyst selection required"
_PLATFORM_TYPES = {"bluesky": T.BSKY_HANDLE, "telegram": T.TELEGRAM_HANDLE}


def _account_pivot(res: Any, acc: dict[str, Any], note: str) -> Any:
    platform, handle = acc.get("platform"), str(acc.get("handle") or "")
    if platform in _PLATFORM_TYPES:
        made = res.pivot(_PLATFORM_TYPES[platform], handle, "linked_account_on_profile", confidence="possible", expand=False, note=note)
        if made is not None:
            return made
    if platform:
        made = res.pivot(T.SOCIAL_ACCOUNT, f"{platform}:{handle}", "linked_account_on_profile", confidence="possible",
                         expand=False, note=note)
        if made is not None:
            return made
        if acc.get("url"):
            return res.pivot(T.URL, acc["url"], "linked_account_on_profile", confidence="possible", expand=False, note=note)
        return None
    return res.pivot(T.USERNAME, handle, "linked_account_on_profile", confidence="possible", expand=False,
                     note=note + "; a bare handle goes to the username packs only as an analyst-typed seed")


def apply_profile_ids(res: Any, info: dict[str, Any] | None) -> int:
    """Record the facts of :func:`extract_profile_ids` on the caller's result; returns the pivot count.

    Attributes: ``profile_ids`` (cond 3), ``linked_accounts`` (cond 4), ``profile_personal`` (cond 6).
    Every pivot is ``expand=False`` and POSSIBLE with an owner-written note (cond 4, 6, 7): names never
    reach person_name modules and e-mails/phones never reach breach or stealer modules automatically.
    Avatar URLs and Gravatar hashes are left to the caller and to avatar_correlation (P114).
    """
    if not isinstance(info, dict) or not info.get("scheme"):
        return 0
    page = str(info.get("source_page") or "")
    note = _OWNER_NOTE.format(page=page or "the profile page")
    fields = {k: v for k, v in (info.get("attributes") or {}).items() if v not in (None, "")}
    if fields:
        res.attr("profile_ids", {"scheme": info["scheme"], "source_page": page, "fields": fields})
    linked = [{"platform": a.get("platform"), "handle": a.get("handle"), "url": a.get("url"), "source_page": page}
              for a in info.get("linked_accounts") or []]
    if linked:
        res.attr("linked_accounts", linked)
    personal = {k: v for k, v in (info.get("personal") or {}).items() if v not in (None, "", [])}
    if personal:
        res.attr("profile_personal", {"source_page": page, "confidence": "possible", **personal})
    made = 0
    for acc in info.get("linked_accounts") or []:
        made += _account_pivot(res, acc, note) is not None
    for addr in personal.get("emails") or []:
        made += res.pivot(T.EMAIL, addr, "email_on_profile", confidence="possible", expand=False,
                          note=note + "; never sent to breach or stealer modules automatically") is not None
    for phone in personal.get("phones") or []:
        made += res.pivot(T.PHONE, phone, "phone_on_profile", confidence="possible", expand=False, note=note) is not None
    for key in ("fullname", "full_name", "name"):
        value = personal.get(key)
        if isinstance(value, str) and value.strip():
            made += res.pivot(T.PERSON, value.strip(), "name_on_profile", confidence="possible", expand=False,
                              note=note + "; never investigated by person_name modules automatically") is not None
            break
    for link in info.get("links") or []:
        made += res.pivot(T.URL, link, "link_on_profile", confidence="possible", expand=False, note=note) is not None
    return made


# ---------------------------------------------------------------------------------------------
# expansion plan (cond 4/5)
# ---------------------------------------------------------------------------------------------


def plan_profile_expansion(
    linked_accounts: Iterable[dict[str, Any]] | None,
    *,
    preset: str = "quick",
    link_confidence: str = "possible",
    analyst_selected: Iterable[str] = (),
    depth: int = 0,
    max_auto: int = MAX_AUTO_EXPANSIONS,
) -> dict[str, list[Any]]:
    """What may be expanded from 'linked accounts found on profile' (cond 4/5).

    * a page reached by an expansion (``depth >= 1``) expands nothing again (recursion depth <= 1);
    * default preset: nothing automatic; deep preset: only PROBABLE+ links, at most ``max_auto`` per seed;
    * analyst selection always enriches a platform-qualified account (one request to its enricher);
    * a bare handle never reaches the username packs without the analyst: once selected it is promoted
      to an analyst-typed seed (A5 packs run only on typed seeds).

    Returns ``{'enrich': [(platform, handle, enricher)], 'promote_to_seed': [handle],
    'needs_confirmation': [handle], 'held': [(tag, reason)]}``.
    """
    plan: dict[str, list[Any]] = {"enrich": [], "promote_to_seed": [], "needs_confirmation": [], "held": []}
    selected = {str(s).lower() for s in analyst_selected or ()}
    level = str(link_confidence or "").lower()
    auto = 0
    for acc in linked_accounts or []:
        if not isinstance(acc, dict):
            continue
        handle = str(acc.get("handle") or "")
        platform = acc.get("platform")
        tag = f"{platform}:{handle}".lower() if platform else handle.lower()
        chosen = tag in selected or handle.lower() in selected
        if not handle:
            continue
        if depth >= 1:
            plan["held"].append((tag, "depth"))
        elif not platform:
            plan["promote_to_seed" if chosen else "needs_confirmation"].append(handle)
        elif PLATFORM_ENRICHERS.get(platform) is None:
            plan["held"].append((tag, "no_platform_enricher"))
        elif chosen:
            plan["enrich"].append((platform, handle, PLATFORM_ENRICHERS[platform]))
        elif preset != "deep":
            plan["held"].append((tag, "default_preset_expand_false"))
        elif level not in ("probable", "confirmed"):
            plan["held"].append((tag, "link_below_probable"))
        elif auto >= max_auto:
            plan["held"].append((tag, "auto_cap"))
        else:
            auto += 1
            plan["enrich"].append((platform, handle, PLATFORM_ENRICHERS[platform]))
    return plan
