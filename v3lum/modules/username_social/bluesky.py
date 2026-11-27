"""Bluesky AppView + PLC directory (P099): profile, verified custom-domain handle, handle history.

* Hosts public.api.bsky.app and plc.directory only (cond 1). Endpoints: app.bsky.actor.getProfile,
  com.atproto.identity.resolveHandle, app.bsky.actor.searchActors and plc.directory/{did}/log/audit.
  ``https://<handle>/.well-known/atproto-did`` and did:web documents are never fetched (cond 6: a server
  the subject controls, LIGHT); DID syntax is validated (did:plc:<24 base32>) before plc.directory is
  called and did:web DIDs are never resolved.
* Inputs (cond 3, ``run_on='seeds'``): usernames (normalised to {u}.bsky.social when there is no dot),
  bsky handles and bsky.app profile URLs (P333 bsky_handle), domains (resolveHandle(domain) -> DID ->
  profile, the 'official account') and keywords (searchActors only).
* Statuses (cond 4): HTTP 400 {'error':'InvalidRequest','message':'Profile not found'} = ABSENT (EMPTY,
  presence absent); 'Unable to resolve handle' = no account claims the domain; any other 400 (invalid
  identifier) = SKIPPED not_applicable; 429, 5xx and timeouts = could not verify.
* A custom-domain handle is a CONFIRMED domain link only when getProfile returns that same handle (not
  'handle.invalid') and resolveHandle returns the same DID, re-checked with the core DoH TXT
  _atproto.<domain> (a missing TXT record does not downgrade: the handle may be verified over HTTPS; a
  different DID does). 'handle.invalid' or any mismatch = POSSIBLE. checked_at is recorded (cond 5).
  The CONFIRMED domain pivot expands for passive modules only: pivots never reach LIGHT/ACTIVE modules
  (those run on analyst-typed seeds only, POL-10) (cond 8).
* PLC audit log (cond 7): capped at 200 entries (oldest 100 + newest 100), stored as (handle, PDS, date)
  tuples (signatures and keys dropped) and shown as a dated timeline; previous handles of the same DID
  become username pivots with expand=False (fed to username_check only on analyst confirmation).
* searchActors (cond 8): only for analyst-typed keyword/domain seeds; top 10 'candidate accounts named
  like X', POSSIBLE, expand=False, never identity links. Handle history is case-bound (retention_days).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import attempt, iso_utc, load_json, report_problems, to_int, to_str

SOURCE_APPVIEW = "bluesky.appview"
SOURCE_PLC = "bluesky.plc_audit"
APPVIEW = "https://public.api.bsky.app/xrpc/"
PLC = "https://plc.directory/"
HANDLE_INVALID = "handle.invalid"
PLC_AUDIT_CAP = 200  # cond 7
SEARCH_TOP = 10  # cond 8
PROFILE_TTL = 21600  # handles can be transferred
PLC_TTL = 86400
SEARCH_TTL = 3600
_HANDLE_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DID_PLC_RE = re.compile(r"^did:plc:[a-z2-7]{24}$")
_DID_ANY_RE = re.compile(r"^did:[a-z]+:[A-Za-z0-9._:%-]{1,2000}$")
_DISALLOWED_TLDS = frozenset({"alt", "arpa", "example", "internal", "invalid", "local", "localhost", "onion"})
_HOSTED_SUFFIX = ".bsky.social"
_KEYWORD_MAX = 100


def is_valid_handle(value: Any) -> bool:
    """AT Protocol handle syntax (lower-cased); handle.invalid and disallowed TLDs are not valid inputs."""
    if not isinstance(value, str):
        return False
    h = value.strip().lower()
    return h != HANDLE_INVALID and bool(_HANDLE_RE.match(h)) and h.rsplit(".", 1)[-1] not in _DISALLOWED_TLDS


def is_did_plc(value: Any) -> bool:
    return isinstance(value, str) and bool(_DID_PLC_RE.match(value.strip()))


def is_custom_domain(handle: Any) -> bool:
    return is_valid_handle(handle) and not str(handle).lower().endswith(_HOSTED_SUFFIX)


def normalise_actor(value: Any) -> dict[str, Any]:
    """cond 3/6: username -> {u}.bsky.social when there is no dot; bsky.app profile URLs and at:// URIs ->
    handle or DID; did:plc kept; did:web refused. {'actor', 'kind': 'handle'|'did', 'reason'}; actor None
    = SKIPPED not_applicable (no request is sent for a syntax the AppView would reject)."""
    out: dict[str, Any] = {"actor": None, "kind": None, "reason": None}
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        out["reason"] = "empty or oversized input"
        return out
    s = value.strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?bsky\.app/profile/([^/?#\s]+)", s, re.I)
    if m:
        s = m.group(1)
    elif s.lower().startswith("at://"):
        s = s[5:].split("/", 1)[0]
    s = s.lstrip("@").strip()
    low = s.lower()
    if low.startswith("did:"):
        if is_did_plc(low):
            out.update(actor=low, kind="did")
        elif low.startswith("did:web:"):
            out["reason"] = "did:web identities are never resolved (cond 6: subject-controlled host)"
        else:
            out["reason"] = "unsupported or malformed DID"
        return out
    h = low.rstrip(".")
    if "." not in h:
        if not _LABEL_RE.match(h):
            out["reason"] = "invalid handle syntax"
            return out
        h += _HOSTED_SUFFIX
    if not is_valid_handle(h):
        out["reason"] = "invalid handle syntax"
        return out
    out.update(actor=h, kind="handle")
    return out


def xrpc_url(method: str, **params: Any) -> str:
    """The only AppView URLs (getProfile / resolveHandle / searchActors), encoded deterministically."""
    q = "&".join(f"{k}={quote(str(v), safe=':.-_')}" for k, v in params.items() if v is not None)
    return f"{APPVIEW}{method}" + (f"?{q}" if q else "")


def plc_audit_url(did: Any) -> str | None:
    """plc.directory/{did}/log/audit only for a syntactically valid did:plc (cond 6/7)."""
    return f"{PLC}{did.strip()}/log/audit" if is_did_plc(did) else None


def parse_profile(raw: Any) -> dict[str, Any]:
    """getProfile -> normalised facts; 'handle.invalid' gives handle_valid False (cond 5). Avatars, banners,
    status embeds and pinned posts are not kept."""
    res: dict[str, Any] = {"ok": False, "reason": None, "did": None, "handle": None, "handle_valid": False, "custom_domain": False,
                           "display_name": None, "description": None, "created_at": None, "indexed_at": None, "followers": None,
                           "follows": None, "posts": None, "labels": [], "verified_status": None, "profile_url": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict):
        res["reason"] = why or "unexpected JSON shape"
        return res
    did = to_str(obj.get("did"), 2048)
    if not did or not _DID_ANY_RE.match(did):
        res["reason"] = f"error object: {str(obj.get('message'))[:120]}" if obj.get("error") else "profile without DID"
        return res
    handle = (to_str(obj.get("handle"), 253) or "").lower() or None
    valid = is_valid_handle(handle)
    labels = obj.get("labels") if isinstance(obj.get("labels"), list) else []
    ver = obj.get("verification") if isinstance(obj.get("verification"), dict) else {}
    res.update(ok=True, did=did, handle=handle, handle_valid=valid, custom_domain=bool(valid and is_custom_domain(handle)),
               display_name=to_str(obj.get("displayName"), 200), description=to_str(obj.get("description"), 2000),
               created_at=iso_utc(obj.get("createdAt")), indexed_at=iso_utc(obj.get("indexedAt")),
               followers=to_int(obj.get("followersCount")), follows=to_int(obj.get("followsCount")), posts=to_int(obj.get("postsCount")),
               labels=[lab["val"][:64] for lab in labels[:20] if isinstance(lab, dict) and isinstance(lab.get("val"), str)],
               verified_status=to_str(ver.get("verifiedStatus"), 30))
    res["profile_url"] = "https://bsky.app/profile/" + (handle if valid else did)
    return res


def parse_resolved_did(raw: Any) -> str | None:
    obj, why = load_json(raw)
    did = to_str(obj.get("did"), 2048) if not why and isinstance(obj, dict) else None
    return did if did and _DID_ANY_RE.match(did) else None


def parse_atproto_txt(records: Any) -> list[str]:
    """'did=<did>' values of TXT _atproto.<domain> records (quotes and split strings tolerated)."""
    dids: list[str] = []
    for t in records if isinstance(records, (list, tuple)) else []:
        if not isinstance(t, str):
            continue
        s = t.strip()
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1].replace('" "', "")
        m = re.fullmatch(r"did=(did:[a-z]+:[A-Za-z0-9._:%-]{1,2000})", s)
        if m and m.group(1) not in dids:
            dids.append(m.group(1))
    return dids


def domain_link(profile: dict[str, Any], resolved_did: str | None, domain: str, txt_dids: list[str] | None, checked_at: str) -> dict[str, Any]:
    """cond 5: CONFIRMED only when getProfile returns that same handle (not handle.invalid) and resolveHandle
    returns the same DID; a TXT _atproto DID that differs downgrades, a missing TXT record does not (the
    handle may be verified over HTTPS, which is never fetched). Anything else is POSSIBLE."""
    handle = (profile.get("handle") or "").lower()
    basis: list[str] = []
    problems: list[str] = []
    if handle == HANDLE_INVALID or not profile.get("handle_valid"):
        problems.append("the AppView shows the handle as handle.invalid")
    elif handle != domain:
        problems.append(f"the profile handle {handle} differs from {domain}")
    else:
        basis.append("getProfile handle")
    if resolved_did and resolved_did == profile.get("did"):
        basis.append("resolveHandle DID")
    else:
        problems.append("resolveHandle DID " + ("could not be verified" if resolved_did is None else "differs"))
    if txt_dids is None:
        pass  # DNS could not be verified: neither basis nor problem
    elif profile.get("did") in txt_dids:
        basis.append("DNS TXT _atproto")
    elif txt_dids:
        problems.append("DNS TXT _atproto DID differs")
    return {"domain": domain, "did": profile.get("did"), "handle": handle or None, "confidence": "possible" if problems else "confirmed",
            "basis": basis, "problems": problems, "checked_at": checked_at}


def _plc_entry(e: dict[str, Any]) -> dict[str, Any] | None:
    op = e.get("operation") if isinstance(e.get("operation"), dict) else {}
    typ = op.get("type")
    date = iso_utc(e.get("createdAt"))
    if typ == "plc_tombstone":
        return {"tombstone": True, "date": date}
    if typ == "create":  # legacy genesis format
        h = to_str(op.get("handle"), 253)
        return {"handle": h.lower() if h else None, "pds": to_str(op.get("service"), 300), "date": date}
    if typ == "plc_operation":
        aka = [a for a in (op.get("alsoKnownAs") if isinstance(op.get("alsoKnownAs"), list) else []) if isinstance(a, str) and a.startswith("at://")]
        h = aka[0][5:].lower()[:253] if aka else None
        services = op.get("services") if isinstance(op.get("services"), dict) else {}
        svc = services.get("atproto_pds") if isinstance(services.get("atproto_pds"), dict) else {}
        return {"handle": h, "pds": to_str(svc.get("endpoint"), 300), "date": date}
    return None


def _self_hosted(pds: Any) -> bool:
    try:
        host = (urlsplit(pds).hostname or "") if isinstance(pds, str) else ""
    except ValueError:
        return False
    return bool(host) and not (host == "bsky.social" or host.endswith(".bsky.network") or host.endswith(".bsky.social"))


def parse_plc_audit(raw: Any, current_handle: str | None = None, cap: int = PLC_AUDIT_CAP) -> dict[str, Any]:
    """cond 7: audit log capped at 200 entries (oldest 100 + newest 100 when longer), nullified operations
    skipped, stored as (handle, PDS endpoint, date) tuples, consecutive duplicates collapsed."""
    res: dict[str, Any] = {"ok": False, "reason": None, "entries_total": 0, "truncated": False, "dropped": 0, "nullified_skipped": 0,
                           "timeline": [], "previous_handles": [], "first_seen": {}, "tombstoned_at": None, "self_hosted_pds": []}
    obj, why = load_json(raw)
    if why or not isinstance(obj, list):
        res["reason"] = why or "unexpected JSON shape"
        return res
    entries = [e for e in obj if isinstance(e, dict)]
    res["entries_total"] = len(entries)
    if len(entries) > cap:
        res.update(truncated=True, dropped=len(entries) - cap)
        entries = entries[: cap // 2] + entries[-(cap - cap // 2):]
    res["ok"] = True
    last: tuple[Any, Any] | None = None
    for e in entries:
        if e.get("nullified") is True:
            res["nullified_skipped"] += 1
            continue
        t = _plc_entry(e)
        if t is None:
            continue
        if t.get("tombstone"):
            res["tombstoned_at"] = t["date"]
            continue
        key = (t["handle"], t["pds"])
        if key == last:
            continue
        last = key
        res["timeline"].append(t)
    cur = (current_handle or "").lower() or (res["timeline"][-1]["handle"] if res["timeline"] else None)
    for t in res["timeline"]:
        h = t["handle"]
        if h:
            res["first_seen"].setdefault(h, t["date"])
        if h and h != cur and h != HANDLE_INVALID and h not in res["previous_handles"]:
            res["previous_handles"].append(h)
        if t["pds"] and _self_hosted(t["pds"]) and t["pds"] not in res["self_hosted_pds"]:
            res["self_hosted_pds"].append(t["pds"])
    if not res["timeline"]:
        res["reason"] = "no usable operations"
    return res


def parse_search(raw: Any, top: int = SEARCH_TOP) -> dict[str, Any]:
    """cond 8: searchActors -> top 10 candidates {handle, did, display_name, created}."""
    res: dict[str, Any] = {"ok": False, "reason": None, "returned": 0, "candidates": []}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not isinstance(obj.get("actors"), list):
        res["reason"] = why or "unexpected JSON shape"
        return res
    res["ok"] = True
    actors = [a for a in obj["actors"][:100] if isinstance(a, dict) and to_str(a.get("did"))]
    res["returned"] = len(actors)
    for a in actors[:top]:
        h = (to_str(a.get("handle"), 253) or "").lower() or None
        res["candidates"].append({"handle": h if is_valid_handle(h) else None, "did": to_str(a.get("did"), 200),
                                  "display_name": to_str(a.get("displayName"), 200), "created": iso_utc(a.get("createdAt"))})
    return res


@register
class Bluesky(Module):
    name = "bluesky"
    title = "Bluesky account, verified domain handle and handle history"
    description = (
        "Bluesky AppView profile (keyless), DID-consistent custom-domain handle check, the official account of a domain, "
        "PLC directory handle/PDS history and name-search candidates for typed keywords."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.BSKY_HANDLE, T.URL, T.DOMAIN, T.KEYWORD})
    produces = frozenset({T.USERNAME, T.DOMAIN, T.URL, T.BSKY_HANDLE})
    run_on = "seeds"  # cond 3/8: analyst-typed usernames, keywords and domains
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "bluesky"
    sources = (SOURCE_APPVIEW, SOURCE_PLC)
    hosts = ("public.api.bsky.app", "plc.directory")
    access_model = "free_noauth_limited"
    max_requests = 4  # profile + resolveHandle + PLC audit (+ searchActors for domain seeds)
    expected_latency = 1.0
    timeout = 20.0
    min_interval = 0.5
    cache_ttl = PROFILE_TTL
    max_pivots = 40
    default_enabled = True
    reference = "https://docs.bsky.app/docs/api/app-bsky-actor-get-profile"
    tags = frozenset({"free"})
    notice = (
        "Never fetches https://<handle>/.well-known/atproto-did or did:web documents (subject-controlled hosts). A custom-domain "
        "handle counts as CONFIRMED only when the AppView, resolveHandle (and DNS when it answers) agree on the DID; handle "
        "history and search candidates are case-bound weak signals. personal_data_review comes before default use."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            try:
                host = (urlsplit(entity.value).hostname or "").lower()
            except ValueError:
                return False
            return host in ("bsky.app", "www.bsky.app")
        if entity.type is T.KEYWORD:
            return 0 < len(entity.value) <= _KEYWORD_MAX
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.DOMAIN:
            return self._domain(res, ctx, entity.value.lower())
        if entity.type is T.KEYWORD:
            return self._keyword(res, ctx, entity.value)
        norm = normalise_actor(entity.value)
        if not norm["actor"]:
            return res.mark("skipped", f"not a Bluesky handle or DID: {norm['reason']}", reason_code="not_applicable")
        return self._account(res, ctx, norm["actor"])

    # ------------------------------------------------------------------ XRPC helper (cond 4)
    @staticmethod
    def _xrpc(ctx: Any, url: str, ttl: int) -> tuple[str, Any]:
        """('ok', body) | ('absent', message) | ('invalid', message). 400 InvalidRequest bodies are read here;
        429, 5xx, challenges and other failures raise through the core classifier (could not verify)."""
        resp = ctx.http.get(url, source=SOURCE_APPVIEW, ttl=ttl)
        if resp.status == 400 and resp.classification is None:
            obj, _why = load_json(resp.content)
            if isinstance(obj, dict) and isinstance(obj.get("error"), str):
                msg = str(obj.get("message") or obj.get("error"))[:200]
                if msg in ("Profile not found", "Unable to resolve handle"):
                    return "absent", msg
                return "invalid", msg
        ctx.http.check(resp)
        return "ok", resp.content

    # ------------------------------------------------------------------ handle / DID / username
    def _account(self, res: ModuleResult, ctx: Any, actor: str) -> ModuleResult:
        url = xrpc_url("app.bsky.actor.getProfile", actor=actor)
        state, body = self._xrpc(ctx, url, PROFILE_TTL)
        profile_page = f"https://bsky.app/profile/{actor}"
        if state == "invalid":
            return res.mark("skipped", f"the AppView refused the identifier ({body}): not applicable", reason_code="not_applicable")
        if state == "absent":
            res.presence("absent", marker="HTTP 400 InvalidRequest 'Profile not found' from app.bsky.actor.getProfile", url=profile_page,
                         checked_at=ctx.now(), source=SOURCE_APPVIEW)
            res.error = "no Bluesky profile with this handle"
            return res.mark("empty")
        prof = parse_profile(body)
        if not prof["ok"]:
            return res.mark("error", f"unexpected Bluesky answer ({prof['reason']}): could not verify")
        checked_at = ctx.now().isoformat()
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        raw: dict[str, Any] = {"did": prof["did"], "handle": prof["handle"], "checked_at": checked_at}
        res.raw = raw
        res.presence("found", marker="HTTP 200 app.bsky.actor.getProfile", url=prof["profile_url"], checked_at=ctx.now(), source=SOURCE_APPVIEW)
        self._profile_attrs(res, prof, checked_at)
        requested_domain = actor if is_custom_domain(actor) else None
        link = None
        domain = requested_domain or (prof["handle"] if prof["custom_domain"] else None)
        if domain:
            link = self._verify_domain(res, ctx, prof, domain, checked_at, problems)
            raw["domain_link"] = link["confidence"]
            if link["confidence"] == "confirmed":
                res.pivot(T.DOMAIN, domain, "handle_domain", confidence="confirmed", expand=True,
                          note=f"Bluesky handle verified for this domain (AppView + resolveHandle{' + DNS' if 'DNS TXT _atproto' in link['basis'] else ''}, "
                               f"checked {checked_at[:10]}): passive modules only")
            else:
                res.pivot(T.DOMAIN, domain, "handle_domain", confidence="possible", expand=False,
                          note="Bluesky handle claims this domain but the check did not hold: " + "; ".join(link["problems"]))
        self._history(res, ctx, prof, problems, raw)
        report_problems(res, problems)
        res.finding(
            "Bluesky account",
            "info",
            f"Bluesky account {prof['handle'] or prof['did']} ({prof['did']})"
            + (f", created {prof['created_at'][:10]}" if prof["created_at"] else "")
            + (f"; custom-domain handle {domain}: {link['confidence'].upper()}" if link else "")
            + ". Same handle elsewhere does not prove the same person.",
            confidence="confirmed",
            criterion="app.bsky.actor.getProfile answered with the account (DID)",
            data={"did": prof["did"], "handle": prof["handle"], "checked_at": checked_at},
            tags=["account"],
            references=[prof["profile_url"]],
            source=SOURCE_APPVIEW,
        )
        return res

    def _profile_attrs(self, res: ModuleResult, prof: dict[str, Any], checked_at: str, relation: str = "has_account", confidence: str = "confirmed") -> None:
        res.attr("bsky_profile", {"did": prof["did"], "handle": prof["handle"], "handle_valid": prof["handle_valid"],
                                  "custom_domain": prof["custom_domain"], "posts": prof["posts"], "labels": prof["labels"],
                                  "verified_status": prof["verified_status"], "indexed_at": prof["indexed_at"], "checked_at": checked_at})
        res.attr("display_name", prof["display_name"])
        res.attr("bio", prof["description"])
        res.attr("followers", prof["followers"])
        res.attr("following", prof["follows"])
        res.attr("created", prof["created_at"])
        res.attr("profile_url", prof["profile_url"])
        res.pivot(T.URL, prof["profile_url"], relation, confidence=confidence, expand=False, note=f"Bluesky profile (checked {checked_at[:10]})")
        if prof["handle_valid"]:
            res.pivot(T.BSKY_HANDLE, prof["handle"], relation, confidence=confidence, expand=False,
                      note=f"Bluesky handle of DID {prof['did']} (handles can be transferred; checked {checked_at[:10]})")

    def _verify_domain(self, res: ModuleResult, ctx: Any, prof: dict[str, Any], domain: str, checked_at: str,
                       problems: dict[str, Any], resolved: str | None = None) -> dict[str, Any]:
        """cond 5: resolveHandle(domain) must return the profile's DID; the DNS TXT _atproto re-check runs
        through the core DoH resolvers (not counted in max_requests)."""
        if resolved is None:
            got = attempt(problems, SOURCE_APPVIEW, "resolveHandle", lambda: self._xrpc(ctx, xrpc_url("com.atproto.identity.resolveHandle", handle=domain), PROFILE_TTL))
            if got is not None:
                state, body = got
                resolved = parse_resolved_did(body) if state == "ok" else None
                if state == "ok" and resolved is None:
                    problems.setdefault(SOURCE_APPVIEW, []).append((Status.ERROR, "error", "resolveHandle: no DID in the answer"))
        txt_dids: list[str] | None = None
        try:
            ans = ctx.dns.query(f"_atproto.{domain}", "TXT")
            if ans.ok:
                txt_dids = parse_atproto_txt(list(ans.records or []))
            elif ans.nxdomain or ans.nodata:
                txt_dids = []
        except Exception:  # noqa: BLE001 - the DNS re-check is optional (cond 5)
            txt_dids = None
        link = domain_link(prof, resolved, domain, txt_dids, checked_at)
        res.attr("bsky_domain_link", link)
        return link

    def _history(self, res: ModuleResult, ctx: Any, prof: dict[str, Any], problems: dict[str, Any], raw: dict[str, Any]) -> None:
        """cond 6/7: PLC audit log of a did:plc (did:web never resolved)."""
        url = plc_audit_url(prof["did"])
        if not url:
            return
        got = attempt(problems, SOURCE_PLC, "PLC audit log", lambda: ctx.http.get_json(url, source=SOURCE_PLC, ttl=PLC_TTL, absent={404}))
        if got is None:
            if SOURCE_PLC not in problems:
                raw["plc"] = "DID not registered on plc.directory"
            return
        audit = parse_plc_audit(got, prof["handle"] if prof["handle_valid"] else None)
        if not audit["ok"]:
            problems.setdefault(SOURCE_PLC, []).append((Status.ERROR, "error", f"PLC audit log: {audit['reason']}: could not verify"))
            return
        history = {k: audit[k] for k in ("timeline", "entries_total", "truncated", "dropped", "nullified_skipped", "tombstoned_at")}
        res.attr("handle_history", history)
        res.attr("self_hosted_pds", audit["self_hosted_pds"])
        raw["plc_entries"] = audit["entries_total"]
        for h in audit["previous_handles"][:20]:
            since = audit["first_seen"].get(h)
            when = f" (first seen {since[:10]})" if since else ""
            if h.endswith(_HOSTED_SUFFIX):
                res.pivot(T.USERNAME, h[: -len(_HOSTED_SUFFIX)], "previous_handle", confidence="probable", expand=False,
                          note=f"previous Bluesky handle {h} of the same DID{when}: historical, run username checks only after analyst confirmation")
            else:
                res.pivot(T.USERNAME, h, "previous_handle", confidence="possible", expand=False,
                          note=f"previous custom-domain handle {h} claimed by the same DID{when} (self-asserted, not re-checkable): historical")

    # ------------------------------------------------------------------ domain seed (cond 3/5/8)
    def _domain(self, res: ModuleResult, ctx: Any, domain: str) -> ModuleResult:
        if not is_custom_domain(domain):
            return res.mark("skipped", "not a domain a Bluesky handle can use", reason_code="not_applicable")
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        checked_at = ctx.now().isoformat()
        raw: dict[str, Any] = {"domain": domain, "checked_at": checked_at}
        res.raw = raw
        state, body = self._xrpc(ctx, xrpc_url("com.atproto.identity.resolveHandle", handle=domain), PROFILE_TTL)
        if state == "invalid":
            return res.mark("skipped", f"the AppView refused the domain ({body}): not applicable", reason_code="not_applicable")
        found_account = False
        if state == "absent":
            res.presence("absent", marker="HTTP 400 InvalidRequest 'Unable to resolve handle' from com.atproto.identity.resolveHandle",
                         url=f"https://bsky.app/profile/{domain}", checked_at=ctx.now(), source=SOURCE_APPVIEW)
            raw["official_account"] = None
        else:
            did = parse_resolved_did(body)
            if did is None:
                return res.mark("error", "unexpected resolveHandle answer (no DID): could not verify")
            got = attempt(problems, SOURCE_APPVIEW, "getProfile", lambda: self._xrpc(ctx, xrpc_url("app.bsky.actor.getProfile", actor=did), PROFILE_TTL))
            prof = parse_profile(got[1]) if got is not None and got[0] == "ok" else None
            if prof is None or not prof["ok"]:
                if got is not None:
                    problems.setdefault(SOURCE_APPVIEW, []).append((Status.ERROR, "error", "getProfile of the resolved DID: could not verify"))
                raw["official_account"] = did
            else:
                found_account = True
                link = self._verify_domain(res, ctx, prof, domain, checked_at, problems, resolved=did)
                conf = link["confidence"]
                res.presence("found", marker=f"resolveHandle -> {did} -> getProfile", url=prof["profile_url"], checked_at=ctx.now(), source=SOURCE_APPVIEW)
                self._profile_attrs(res, prof, checked_at, relation="official_account", confidence=conf)
                raw.update(official_account=did, confidence=conf)
                self._history(res, ctx, prof, problems, raw)
                res.finding(
                    "Bluesky account uses this domain as its handle",
                    "info",
                    f"Bluesky account {prof['handle'] or did} ({did}) resolves from {domain}: {conf.upper()} "
                    f"({', '.join(link['basis']) or 'no consistent basis'}{'; ' + '; '.join(link['problems']) if link['problems'] else ''}). "
                    "Handles can be transferred: checked " + checked_at[:10] + ".",
                    confidence=conf,
                    criterion="custom-domain handle: getProfile handle and resolveHandle DID (and DNS TXT _atproto when it answers) agree",
                    data={"link": link},
                    tags=["account", "identity"],
                    references=[prof["profile_url"]],
                    source=SOURCE_APPVIEW,
                )
        self._search(res, ctx, domain, problems)
        report_problems(res, problems)
        if not found_account and not res.pivots and not res.attributes.get("candidate_accounts"):
            res.error = res.error or "no Bluesky account claims this domain"
            return res.mark("empty") if res.status is Status.OK else res
        return res

    # ------------------------------------------------------------------ keyword seed (cond 8)
    def _keyword(self, res: ModuleResult, ctx: Any, term: str) -> ModuleResult:
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        self._search(res, ctx, term, problems, raise_errors=True)
        if not res.attributes.get("candidate_accounts"):
            res.error = f"no candidate accounts named like {term!r}"
            return res.mark("empty")
        return res

    def _search(self, res: ModuleResult, ctx: Any, term: str, problems: dict[str, Any], raise_errors: bool = False) -> None:
        url = xrpc_url("app.bsky.actor.searchActors", q=term, limit=SEARCH_TOP)
        if raise_errors:
            body = ctx.http.get_json(url, source=SOURCE_APPVIEW, ttl=SEARCH_TTL)
        else:
            body = attempt(problems, SOURCE_APPVIEW, "searchActors", lambda: ctx.http.get_json(url, source=SOURCE_APPVIEW, ttl=SEARCH_TTL))
            if body is None:
                return
        parsed = parse_search(body)
        if not parsed["ok"]:
            if raise_errors:
                res.mark("error", f"unexpected searchActors answer ({parsed['reason']}): could not verify")
            else:
                problems.setdefault(SOURCE_APPVIEW, []).append((Status.ERROR, "error", f"searchActors: {parsed['reason']}"))
            return
        if not parsed["candidates"]:
            return
        label = f"candidate accounts named like {term}"
        res.attr("candidate_accounts", {"label": label, "returned": parsed["returned"], "candidates": parsed["candidates"]})
        known = {p.entity.value for p in res.pivots if p.entity.type is T.BSKY_HANDLE}  # the official account is no candidate
        for c in parsed["candidates"]:
            if c["handle"] and c["handle"] not in known:
                res.pivot(T.BSKY_HANDLE, c["handle"], "named_like", confidence="possible", expand=False,
                          note=f"{label}: a name-search candidate, never an identity link")
