"""Mastodon / fediverse accounts on a known-instance list (P105): WebFinger + accounts/lookup, read-only GETs.

* Known instances only (cond 1): the module contacts only the hosts of the bundled list
  ``v3lum/data/mastodon/fediverse_instances.json`` (large public instances, each with a provider registry entry
  recording its tier and terms; maintainers refresh it). ``Module.hosts`` and ``sources`` are generated from that
  file at import time, so a host added without a provider entry fails registration (fail closed). Remote
  accounts are resolved through a listed instance with ``/api/v1/accounts/lookup?acct=user@host``; that answer
  comes from the listed instance's federation cache: a 404 there means 'not known to <instance>', never absent.
* Inputs (cond 2): explicit ``@user@instance`` seeds (fediverse_handle), fediverse profile URLs
  (``https://host/@user``, ``https://host/@user@remote``, ``https://host/users/user``), e-mail-shaped inputs only
  when the domain is on the list, and plain usernames (one lookup per listed instance). An unlisted e-mail or
  company domain is never sent a WebFinger or nodeinfo request: that would contact the target's own server.
  Keywords are not accepted: unauthenticated v2 search is not used (cond 4).
* The LIGHT ``mastodon_instance`` module (cond 3: an analyst-typed ``@user@host`` on an unlisted instance, with
  ``--mode light`` after the passive results, P376 + SSRF guard) is built in the LIGHT/ACTIVE phase after the
  AR20 safety suite (backlog); this passive module never contacts an unlisted host.
* Endpoints (cond 4): ``/.well-known/webfinger?resource=acct:user@host`` (listed home instances only, as a
  confirmation of a found account) and ``/api/v1/accounts/lookup?acct=``; at most 2 requests per instance per
  input (cond 4 allows 3), min_interval 1 s per instance (provider profiles). 404 'Record not found' on the home
  instance and 410 are ABSENT; 403/429 = could not verify.
* Fields (cond 5): rel=me fields with ``verified_at`` are CONFIRMED links to that website, shown with the
  verification date (URL pivots for passive modules only: LIGHT/ACTIVE modules never run on pivots, POL-10);
  unverified fields and bio links are claims (POSSIBLE, expand=False); link-less field text (location,
  pronouns) is not kept.
* The report lists every instance host actually contacted (cond 6): the core disclosure ledger (``res.hosts``)
  plus the ``disclosed_to`` attribute. personal_data_review comes before default use (A3 BR8).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import (
    Problems,
    attempt,
    day,
    excerpt,
    extract_urls,
    host_of,
    html_text_and_links,
    iso,
    json_body,
    normalise_host,
    report_problems,
    safe_url,
    to_bool,
    to_int,
    to_str,
)

INSTANCES_FILE = Path(__file__).resolve().parents[2] / "data" / "mastodon" / "fediverse_instances.json"
SOURCE_SUFFIX = "accounts_api"
_USER_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?$")
MAX_FIELDS = 16


def load_instances(path: Path = INSTANCES_FILE) -> dict[str, Any]:
    """The bundled known-instance list -> {'hosts': (...), 'providers': {host: provider}, 'resolver': host}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"hosts": (), "providers": {}, "resolver": ""}
    providers: dict[str, str] = {}
    for ent in data.get("instances", []) if isinstance(data, dict) else []:
        host = normalise_host(ent.get("host")) if isinstance(ent, dict) else None
        prov = ent.get("provider") if isinstance(ent, dict) else None
        if host and isinstance(prov, str) and re.fullmatch(r"[a-z][a-z0-9_]{1,63}", prov):
            providers[host] = prov
    resolver = normalise_host(data.get("resolver")) if isinstance(data, dict) else None
    return {"hosts": tuple(sorted(providers)), "providers": providers, "resolver": resolver if resolver in providers else ""}


INSTANCES = load_instances()


def source_for(host: str) -> str:
    return f"{INSTANCES['providers'][host]}.{SOURCE_SUFFIX}"


def lookup_url(instance: str, acct: str) -> str:
    return f"https://{instance}/api/v1/accounts/lookup?" + urlencode({"acct": acct}, safe="@")


def webfinger_url(user: str, host: str) -> str:
    return f"https://{host}/.well-known/webfinger?" + urlencode({"resource": f"acct:{user}@{host}"}, safe=":@")


def parse_seed(entity: Entity) -> dict[str, Any]:
    """cond 2: {'kind' handle|email_shaped|profile_url|plain_username|invalid, 'user', 'host', 'via_host'}."""
    out: dict[str, Any] = {"kind": "invalid", "user": None, "host": None, "via_host": None}
    value = entity.value.strip()
    if entity.type is T.USERNAME:
        if _USER_RE.match(value):
            out.update(kind="plain_username", user=value)
        return out
    if entity.type is T.URL:
        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError:
            return out
        host = normalise_host(parts.hostname or "")
        if not host or port not in (None, 443) or parts.username or parts.password or parts.scheme != "https":
            return out
        segs = [s for s in parts.path.split("/") if s]
        user, rhost = None, host
        if segs and segs[0].startswith("@"):
            handle = segs[0][1:]
            if "@" in handle:
                user, rh = handle.split("@", 1)
                rhost = normalise_host(rh)
            else:
                user = handle
        elif len(segs) >= 2 and segs[0] == "users":
            user = segs[1]
        if user and rhost and _USER_RE.match(user):
            out.update(kind="profile_url", user=user, host=rhost, via_host=host if rhost != host else None)
        return out
    if "@" in value:
        user, _, h = value.lstrip("@").rpartition("@")
        host = normalise_host(h)
        if host and _USER_RE.match(user):
            out.update(kind="handle" if entity.type is T.FEDIVERSE_HANDLE else "email_shaped", user=user, host=host)
    return out


def plan(seed: dict[str, Any], instances: dict[str, Any] = INSTANCES) -> dict[str, Any]:
    """FC1-FC4 routing: {'lookups': [(instance, acct, home)], 'webfinger': bool, 'skip': (code, reason) | None}."""
    hosts = instances["hosts"]
    kind = seed["kind"]
    if kind == "invalid":
        return {"lookups": [], "webfinger": False, "skip": ("not_applicable", "not a fediverse handle, profile URL or username")}
    if kind == "plain_username":
        if not hosts:
            return {"lookups": [], "webfinger": False, "skip": ("config", "the known-instance list is empty")}
        return {"lookups": [(h, seed["user"], True) for h in hosts], "webfinger": False, "skip": None}
    host = seed["host"]
    if host in hosts:
        return {"lookups": [(host, seed["user"], True)], "webfinger": True, "skip": None}
    if kind == "email_shaped":
        return {"lookups": [], "webfinger": False,
                "skip": ("not_applicable", f"{host} is not on the known-instance list: an e-mail domain is never sent a WebFinger "
                                           "request (that would contact the target's own server, P105 cond 2)")}
    resolver = seed["via_host"] if seed.get("via_host") in hosts else instances["resolver"]
    if not resolver:
        return {"lookups": [], "webfinger": False, "skip": ("config", "no listed resolver instance")}
    return {"lookups": [(resolver, f"{seed['user']}@{host}", False)], "webfinger": False, "skip": None}


def _field(field: dict[str, Any]) -> dict[str, Any]:
    text, links = html_text_and_links(field.get("value") if isinstance(field.get("value"), str) else "")
    urls = [u for u in (safe_url(x) for x in links) if u] or extract_urls(text)
    verified = iso(field.get("verified_at"))
    # minimisation: the free text of link-less fields (location, pronouns...) is not kept
    return {"name": to_str(field.get("name"), 100) or "", "urls": urls[:5], "verified": verified is not None, "verified_at": verified}


def parse_account(data: Any, instance: str) -> dict[str, Any] | None:
    """Account JSON -> facts (cond 5); None when the object is not an account."""
    if not isinstance(data, dict) or not to_str(str(data.get("id") or ""), 40):
        return None
    username = to_str(data.get("username"), 64)
    acct = to_str(data.get("acct"), 300) or username
    if not username or not acct:
        return None
    url = safe_url(data.get("url"))
    home = acct.rsplit("@", 1)[1].lower() if "@" in acct else instance
    acct_full = acct if "@" in acct else f"{username}@{home}"
    fields = [_field(f) for f in (data.get("fields") if isinstance(data.get("fields"), list) else [])[:MAX_FIELDS] if isinstance(f, dict)]
    note_text, note_links = html_text_and_links(data.get("note") if isinstance(data.get("note"), str) else "")
    bio_urls: list[str] = []
    for u in [safe_url(x) for x in note_links] + extract_urls(note_text):
        if u and u not in bio_urls and host_of(u) not in (home, instance):
            bio_urls.append(u)
    moved = data.get("moved") if isinstance(data.get("moved"), dict) else None
    moved_to = to_str(moved.get("acct"), 300) if moved else None
    if moved_to and "@" not in moved_to:
        mhost = host_of(moved.get("url")) if moved else None
        moved_to = f"{moved_to}@{mhost}" if mhost else None
    return {
        "id": str(data.get("id"))[:40],
        "acct": acct_full.lower(),
        "username": username,
        "home_host": home,
        "display_name": to_str(data.get("display_name"), 100),
        "url": url,
        "created_at": iso(data.get("created_at")),
        "last_status_at": day(data.get("last_status_at")),
        "counts": {"followers": to_int(data.get("followers_count")), "following": to_int(data.get("following_count")),
                   "statuses": to_int(data.get("statuses_count"))},
        "flags": {k: to_bool(data.get(k)) for k in ("bot", "group", "locked", "discoverable", "suspended", "limited") if to_bool(data.get(k)) is not None},
        "moved_to": moved_to.lower() if moved_to else None,
        "fields": fields,
        "bio": excerpt(note_text, 300),
        "bio_urls": bio_urls[:10],
    }


def parse_webfinger(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    subject = to_str(data.get("subject"), 300) or ""
    acct = subject[5:].lower() if subject.lower().startswith("acct:") else None
    profile = None
    for ln in data.get("links") if isinstance(data.get("links"), list) else []:
        if isinstance(ln, dict) and ln.get("rel") == "http://webfinger.net/rel/profile-page":
            profile = safe_url(ln.get("href"))
            break
    return {"subject": acct, "profile_page": profile}


@register
class Mastodon(Module):
    name = "mastodon"
    title = "Mastodon / fediverse account on known instances"
    description = (
        "Mastodon accounts through the REST API and WebFinger of a bundled list of large public instances (keyless, read-only): "
        "profile facts, rel=me verified links, moved accounts; remote accounts are resolved through a listed instance."
    )
    category = "username_social"
    accepts = frozenset({T.FEDIVERSE_HANDLE, T.URL, T.EMAIL, T.USERNAME})
    produces = frozenset({T.URL, T.FEDIVERSE_HANDLE})
    run_on = "seeds"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = INSTANCES["providers"].get(INSTANCES["resolver"], "mastodon_ggmbh")
    sources = tuple(sorted({f"{p}.{SOURCE_SUFFIX}" for p in INSTANCES["providers"].values()}))
    hosts = INSTANCES["hosts"]
    access_model = "free_noauth_limited"
    max_requests = 6  # a plain username: one lookup per listed instance (5); a handle: lookup + WebFinger
    expected_latency = 1.0
    timeout = 30.0
    min_interval = 1.0  # per instance (cond 4)
    cache_ttl = 86400
    max_pivots = 40
    default_enabled = True
    reference = "https://docs.joinmastodon.org/methods/accounts/#lookup"
    tags = frozenset({"free"})
    notice = (
        "Contacts only the instances of v3lum/data/mastodon/fediverse_instances.json (never an e-mail or company domain to find "
        "out whether it is an instance). rel=me verified links are CONFIRMED with their verification date; other fields and bio "
        "links are claims. Fediverse handles are personal data: personal_data_review comes before default use (A3 BR8)."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.EMAIL, "someone@example.com", expect="skipped")  # never contacts an unlisted domain (cond 2)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return parse_seed(entity)["kind"] != "invalid"

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        seed = parse_seed(entity)
        route = plan(seed)
        if route["skip"]:
            code, reason = route["skip"]
            return res.mark("skipped", reason, reason_code=code)
        problems: Problems = {}
        found: list[tuple[dict[str, Any], str, bool]] = []
        absent_on: list[str] = []
        not_known: list[str] = []
        contacted: list[str] = []
        sweep = seed["kind"] == "plain_username"
        for instance, acct, home in route["lookups"]:
            contacted.append(instance)
            if sweep:
                got = attempt(problems, source_for(instance), f"lookup on {instance}", lambda i=instance, a=acct: self._lookup(ctx, i, a))
            else:
                got = self._lookup(ctx, instance, acct)
            if got is None:
                continue
            state, payload = got
            if state == "missing":
                (absent_on if home else not_known).append(instance)
            elif state == "error":
                if not sweep:
                    return res.mark("error", payload)
                problems.setdefault(source_for(instance), []).append((Status.ERROR, "error", payload))
            else:
                found.append((payload, instance, home))
        if found and route["webfinger"]:
            account, instance, _ = found[0]
            wf = attempt(problems, source_for(instance), f"WebFinger on {instance}",
                         lambda: self._webfinger(ctx, account["username"], instance))
            if wf:
                account["webfinger"] = {"subject": wf["subject"], "matches": wf["subject"] == account["acct"], "profile_page": wf["profile_page"]}
        res.attr("disclosed_to", sorted(set(contacted)))
        report_problems(res, problems)
        if not found:
            return self._nothing(res, ctx, seed, absent_on, not_known, problems)
        self._emit(res, ctx, entity, found)
        return res

    # ------------------------------------------------------------------------------------------ requests
    @staticmethod
    def _lookup(ctx: Any, instance: str, acct: str) -> tuple[str, Any]:
        """('found', account) | ('missing', '') | ('error', reason); 403/429/5xx/challenges raise (could not verify)."""
        resp = ctx.http.get(lookup_url(instance, acct), source=source_for(instance))
        if resp.status in (404, 410) and resp.classification is None:
            return "missing", ""
        ctx.http.check(resp)
        data, why = json_body(resp.content)
        if why:
            return "error", f"unexpected answer from {instance} ({why}): could not verify"
        if isinstance(data, dict) and data.get("error") and not data.get("id"):
            return "error", f"{instance}: error in 200 ({str(data['error'])[:120]}): could not verify"
        account = parse_account(data, instance)
        if account is None:
            return "error", f"{instance}: answer is not an account object: could not verify"
        return "found", account

    @staticmethod
    def _webfinger(ctx: Any, user: str, host: str) -> dict[str, Any] | None:
        resp = ctx.http.get(webfinger_url(user, host), source=source_for(host), headers={"Accept": "application/jrd+json"})
        if resp.status == 404 and resp.classification is None:
            return None
        ctx.http.check(resp)
        data, why = json_body(resp.content)
        if why:
            raise ValueError(why)
        return parse_webfinger(data)

    # ------------------------------------------------------------------------------------------ outcomes
    def _nothing(self, res: ModuleResult, ctx: Any, seed: dict[str, Any], absent_on: list[str], not_known: list[str], problems: Problems) -> ModuleResult:
        if problems and not absent_on and not not_known:
            first = next(iter(problems.values()))[0]
            return res.mark(first[0], f"no listed instance could be verified: {first[2]}"[:300], reason_code=first[1])
        if absent_on and not problems:
            where = ", ".join(absent_on)
            url = f"https://{absent_on[0]}/@{seed['user']}"
            res.presence("absent", marker=f"HTTP 404 'Record not found' from accounts/lookup on {where}", url=url,
                         checked_at=ctx.now(), source=source_for(absent_on[0]))
            res.error = f"no local account '{seed['user']}' on {where}"
            return res.mark("empty")
        if not_known:
            res.error = (f"{seed['user']}@{seed['host']} is not known to {', '.join(not_known)} (its federation cache only: not absent; "
                         "the home instance is not on the known-instance list and is never contacted by the passive module)")
            return res.mark("empty")
        res.error = f"no local account '{seed['user']}' on {', '.join(absent_on)}; other instances could not be verified"
        return res.mark("empty")

    def _emit(self, res: ModuleResult, ctx: Any, entity: Entity, found: list[tuple[dict[str, Any], str, bool]]) -> None:
        accounts = []
        for account, instance, home in found:
            accounts.append({**{k: account[k] for k in ("acct", "id", "home_host", "display_name", "created_at", "last_status_at",
                                                         "counts", "flags", "moved_to", "fields")},
                             "resolved_via": None if home else instance, "webfinger": account.get("webfinger")})
        res.raw = {"accounts": [{k: a[k] for k in ("acct", "id", "home_host", "resolved_via", "created_at")} for a in accounts]}
        res.attr("fediverse_account", accounts[0] if len(accounts) == 1 else accounts)
        first = found[0][0]
        if len(found) == 1:
            res.attr("display_name", first["display_name"])
            res.attr("bio", first["bio"])
            res.attr("created", first["created_at"])
            res.attr("followers", first["counts"]["followers"])
            res.attr("following", first["counts"]["following"])
            res.attr("profile_url", first["url"])
            res.attr("last_activity", first["last_status_at"])
        res.presence("found", marker="accounts/lookup returned the account", url=first["url"] or "", checked_at=ctx.now(),
                     source=source_for(found[0][1]))
        for account, instance, home in found:
            self._pivots(res, entity, account, instance, home)
            self._findings(res, account, instance, home, sweep=len(found) > 1 or entity.type is T.USERNAME)

    def _pivots(self, res: ModuleResult, entity: Entity, account: dict[str, Any], instance: str, home: bool) -> None:
        conf = "confirmed" if home else "probable"
        res.pivot(T.FEDIVERSE_HANDLE, account["acct"], "has_account", confidence=conf, expand=False,
                  note=f"fediverse account ({'home instance' if home else 'resolved through ' + instance + ' cache'})")
        if account["url"]:
            res.pivot(T.URL, account["url"], "has_account", confidence=conf, expand=False, note="fediverse profile page")
        seen: set[str] = set()
        for f in account["fields"]:
            for u in f["urls"]:
                if u in seen:
                    continue
                seen.add(u)
                if f["verified"]:
                    res.pivot(T.URL, u, "verified_profile_link", confidence="confirmed", expand=True,
                              note=f"rel=me verified link to {host_of(u)} (verified {(f['verified_at'] or '')[:10]}), field '{f['name']}': passive modules only")
                else:
                    res.pivot(T.URL, u, "link_on_profile", confidence="possible", expand=False,
                              note=f"unverified profile link (claim), field '{f['name']}'")
        for u in account["bio_urls"]:
            if u not in seen:
                seen.add(u)
                res.pivot(T.URL, u, "link_on_profile", confidence="possible", expand=False, note="link in the account bio (claim)")
        if account["moved_to"]:
            res.pivot(T.FEDIVERSE_HANDLE, account["moved_to"], "moved_to", confidence="probable", expand=False,
                      note="the account declares it moved to this account")

    @staticmethod
    def _findings(res: ModuleResult, account: dict[str, Any], instance: str, home: bool, *, sweep: bool) -> None:
        verified = [(u, f["verified_at"]) for f in account["fields"] if f["verified"] for u in f["urls"]]
        where = f"home instance {instance}" if home else f"the federation cache of {instance}"
        res.finding(
            "Fediverse account",
            "info",
            f"{account['acct']} found on {where}" + (f", created {account['created_at'][:10]}" if account["created_at"] else "")
            + (f", last post {account['last_status_at']}" if account["last_status_at"] else "")
            + (f"; moved to {account['moved_to']}" if account["moved_to"] else "")
            + (". Same handle elsewhere does not prove the same person." if sweep else "."),
            confidence="confirmed" if home else "probable",
            criterion="accounts/lookup answered with the account object" + ("" if home else " from a listed instance's federation cache"),
            data={"acct": account["acct"], "instance": instance},
            tags=["account"],
            references=[account["url"]] if account["url"] else [],
            source=source_for(instance),
            observed_first=account["created_at"],
            key=account["acct"],
        )
        if verified:
            res.finding(
                "rel=me verified profile links",
                "info",
                f"{account['acct']}: " + "; ".join(f"{host_of(u)} (verified {(v or '')[:10]})" for u, v in verified[:10])
                + ". The linked page links back to the profile (rel=me): a CONFIRMED link to that website.",
                confidence="confirmed",
                criterion="profile field with verified_at set by the instance (rel=me verification)",
                data={"links": [{"url": u, "verified_at": v} for u, v in verified[:20]]},
                tags=["identity"],
                source=source_for(instance),
                key=account["acct"],
            )
