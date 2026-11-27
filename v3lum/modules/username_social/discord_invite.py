"""Discord invite resolver (P101) and Discord webhook IOCs.

* One request only (cond 1): ``GET https://discord.com/api/v10/invites/{code}?with_counts=true&with_expiration=true``,
  keyless. Never POST (join/accept), never a bot or user token.
* Codes come only from discord.gg/{code}, discord.com/invite/{code} and discordapp.com/invite/{code} URLs
  or the P333 discord_invite entity, typed by the analyst or found in an IOC context (kits, configs,
  channels: a text/file/IOC/channel parent); they are validated against ``^[A-Za-z0-9-]{2,32}$`` before
  any request (cond 2). An invite found on a personal profile is not resolved (SKIPPED not_applicable).
* Statuses (cond 3): 404 with code 10006 'Unknown Invite' = EMPTY 'invalid or expired invite' (never 'no
  such server'); 429 honours retry_after: Discord sends it in the JSON body and as Retry-After, and the core
  client waits and retries once when it is <= 15 s; a 429 that reaches the module is RATE_LIMITED with the
  provider's retry_after; other failures = could not verify.
* Output (cond 4): guild id, name, member/presence counts and expiry; guild and inviter snowflakes are
  decoded to creation dates by the shared core decoder (``entities.snowflake_timestamp``, P314);
  inviter id/username become pivots with expand=False; avatars are never downloaded (hashes dropped).
* Discord webhook URLs (cond 5) are never requested: the token is a third-party credential. They are
  reported as an exfiltration-channel IOC (tags c2, phishing_kit_exfil) with the webhook id kept and the
  token only as type + first 4/last 4 + SHA-256, listed for the abuse/takedown report.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.entities import IOC_TYPES, Entity, refang, snowflake_timestamp
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.sanitize import mask_secret
from v3lum.modules.username_social.dev_registries import iso_utc, load_json, to_int, to_str

SOURCE = "discord.invites"
API = "https://discord.com/api/v10/invites/{code}?with_counts=true&with_expiration=true"
CODE_RE = re.compile(r"^[A-Za-z0-9-]{2,32}$")  # cond 2
_INVITE_HOSTS = {"discord.gg": 0, "www.discord.gg": 0, "discord.com": 1, "www.discord.com": 1, "discordapp.com": 1, "www.discordapp.com": 1}
_WEBHOOK_RE = re.compile(r"^/api(?:/v\d{1,2})?/webhooks/(\d{17,20})/([A-Za-z0-9_-]{30,120})/?$")
_WEBHOOK_HOSTS = frozenset({"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com", "ptb.discordapp.com", "canary.discordapp.com"})
_FEATURES_KEPT = ("VERIFIED", "PARTNERED", "COMMUNITY", "DISCOVERABLE", "VANITY_URL", "NEWS")
#: parents whose context makes an invite an IOC (cond 2): IOC values, text/file/e-mail-header extraction,
#: public channels and CTI objects; personal profiles (usernames, e-mails, people) are not
_IOC_CONTEXT = frozenset(IOC_TYPES) | {T.TEXT, T.FILE, T.EMAIL_HEADERS, T.TELEGRAM_HANDLE, T.TELEGRAM_INVITE, T.MALWARE,
                                       T.THREAT_ACTOR, T.DISCORD_INVITE}


def invite_code(entity: Entity) -> str | None:
    """cond 2: the validated code of a discord_invite entity or of a discord.gg / discord(app).com/invite URL."""
    if entity.type is T.DISCORD_INVITE:
        return entity.value if CODE_RE.match(entity.value) else None
    if entity.type is not T.URL:
        return None
    try:
        sp = urlsplit(refang(entity.value).strip())
    except ValueError:
        return None
    kind = _INVITE_HOSTS.get((sp.hostname or "").lower())
    segs = [s for s in (sp.path or "").split("/") if s]
    if kind == 0 and len(segs) == 1:
        code = segs[0]
    elif kind == 1 and len(segs) == 2 and segs[0].lower() == "invite":
        code = segs[1]
    else:
        return None
    return code if CODE_RE.match(code) else None


def webhook_of(entity: Entity) -> tuple[str, str] | None:
    """cond 5: (webhook id, token) of a Discord webhook URL; the URL is never requested."""
    if entity.type is not T.URL:
        return None
    try:
        sp = urlsplit(refang(entity.value).strip())
    except ValueError:
        return None
    if (sp.hostname or "").lower() not in _WEBHOOK_HOSTS:
        return None
    m = _WEBHOOK_RE.match(sp.path or "")
    return (m.group(1), m.group(2)) if m else None


def _snowflake(value: Any) -> str | None:
    s = str(value) if isinstance(value, (int, str)) and not isinstance(value, bool) else ""
    return s if re.fullmatch(r"[1-9]\d{14,19}", s) else None


def snowflake_created(value: str) -> str | None:
    """Creation date of a Discord snowflake through the shared core decoder (P314; no local copy)."""
    try:
        when = snowflake_timestamp(value, "discord")
    except (TypeError, ValueError):
        return None
    return iso_utc(when.isoformat()) if when is not None else None


def parse_invite(raw: Any) -> dict[str, Any]:
    """cond 4: guild id/name/description/features, channel, counts, expiry, inviter; avatars dropped."""
    res: dict[str, Any] = {"ok": False, "reason": None, "code": None, "invite_type": None, "guild": None, "channel": None, "members": None,
                           "presence": None, "expires_at": None, "permanent": None, "inviter": None, "snowflakes": []}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict):
        res["reason"] = why or "unexpected JSON shape"
        return res
    if "guild" not in obj and "channel" not in obj:
        res["reason"] = f"error object: {str(obj.get('message'))[:120]}" if obj.get("message") else "no guild or channel in the answer"
        return res
    res["ok"] = True
    res["code"] = to_str(obj.get("code"), 32)
    res["invite_type"] = {0: "guild", 1: "group_dm", 2: "friend"}.get(to_int(obj.get("type")))
    g = obj.get("guild") if isinstance(obj.get("guild"), dict) else None
    if g:
        features = g.get("features") if isinstance(g.get("features"), list) else []
        res["guild"] = {"id": _snowflake(g.get("id")), "name": to_str(g.get("name"), 200), "description": to_str(g.get("description"), 500),
                        "vanity_url_code": to_str(g.get("vanity_url_code"), 32), "verification_level": to_int(g.get("verification_level")),
                        "nsfw": g.get("nsfw") is True, "nsfw_level": to_int(g.get("nsfw_level")),
                        "features": [f for f in features if f in _FEATURES_KEPT]}
        if res["guild"]["id"]:
            res["snowflakes"].append({"role": "guild", "id": res["guild"]["id"]})
    ch = obj.get("channel") if isinstance(obj.get("channel"), dict) else None
    if ch:
        res["channel"] = {"id": _snowflake(ch.get("id")), "name": to_str(ch.get("name"), 100), "type": to_int(ch.get("type"))}
    res["members"] = to_int(obj.get("approximate_member_count"))
    res["presence"] = to_int(obj.get("approximate_presence_count"))
    res["expires_at"] = iso_utc(obj.get("expires_at"))
    res["permanent"] = "expires_at" in obj and obj.get("expires_at") is None
    inv = obj.get("inviter") if isinstance(obj.get("inviter"), dict) else None
    if inv and _snowflake(inv.get("id")):
        res["inviter"] = {"id": _snowflake(inv.get("id")), "username": to_str(inv.get("username"), 64),
                          "global_name": to_str(inv.get("global_name"), 64), "bot": inv.get("bot") is True}
        res["snowflakes"].append({"role": "inviter", "id": res["inviter"]["id"]})
    return res


def _retry_after(resp: Any) -> float | None:
    obj, _ = load_json(resp.content)
    ra = obj.get("retry_after") if isinstance(obj, dict) else None
    if isinstance(ra, bool) or not isinstance(ra, (int, float)) or ra != ra or ra < 0:
        return None
    return float(ra)


@register
class DiscordInvite(Module):
    name = "discord_invite"
    title = "Discord invite resolver"
    description = (
        "Resolves a Discord invite code (keyless GET /api/v10/invites/{code}): server id, name, member/presence counts, expiry "
        "and inviter, with creation dates decoded from the snowflakes; Discord webhook URLs are reported masked, never called."
    )
    category = "username_social"
    accepts = frozenset({T.DISCORD_INVITE, T.URL})
    produces = frozenset({T.KEYWORD, T.USERNAME, T.SOCIAL_ACCOUNT})
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "discord"
    sources = (SOURCE,)
    hosts = ("discord.com",)
    access_model = "free_noauth_limited"
    max_requests = 2  # the lookup + the core's single retry after a short retry_after (cond 3)
    expected_latency = 0.4
    timeout = 20.0
    min_interval = 2.0
    cache_ttl = 21600  # counts and expiry change
    max_pivots = 10
    default_enabled = True
    reference = "https://discord.com/developers/docs/resources/invite#get-invite"
    tags = frozenset({"free"})
    notice = (
        "GET of the public invite resolver only: never joins, accepts or uses a token; webhook URLs are never called (their token "
        "is a third-party credential). Guild names are written by the server owner. personal_data_review comes before default use."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if webhook_of(entity) is not None:
            return True
        if invite_code(entity) is None:
            return False
        if getattr(ctx, "is_seed", True):
            return True
        prov = getattr(ctx, "provenance", ()) or ()
        parent = prov[-1][0] if prov and isinstance(prov[-1], (list, tuple)) and prov[-1] else ""
        try:
            parent_type = T(str(parent).split(":", 1)[0])
        except ValueError:
            return False
        return parent_type in _IOC_CONTEXT  # cond 2: IOC contexts only (never an invite from a personal profile)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        hook = webhook_of(entity)
        if hook is not None:
            return self._webhook(res, *hook)
        code = invite_code(entity)
        if not code:
            return res.mark("skipped", "not a Discord invite code or URL", reason_code="not_applicable")
        url = API.format(code=code)
        resp = ctx.http.get(url, source=SOURCE)
        if resp.status == 429:
            # cond 3: Discord sends retry_after in the JSON body and as a Retry-After header; the core client
            # waits and retries once when it is <= 15 s (and backs the provider off otherwise), so a 429
            # reaching the module is final: RATE_LIMITED with the provider's retry_after
            ra = _retry_after(resp)
            return res.mark("rate_limited", f"Discord rate limit (retry_after {ra:.1f} s): could not verify" if ra is not None
                            else "Discord rate limit without JSON retry_after (edge limit): could not verify")
        if resp.status == 404 and resp.classification is None:
            obj, _ = load_json(resp.content)
            if isinstance(obj, dict) and to_int(obj.get("code")) == 10006:
                res.presence("absent", marker="HTTP 404 {code: 10006, 'Unknown Invite'}", url=f"https://discord.gg/{code}",
                             checked_at=ctx.now(), source=SOURCE)
                res.error = "invalid or expired invite"
                return res.mark("empty")
        ctx.http.check(resp)  # any other failure: could not verify
        inv = parse_invite(resp.content)
        if not inv["ok"]:
            return res.mark("error", f"unexpected Discord answer ({inv['reason']}): could not verify")
        self._report(res, ctx, code, inv)
        return res

    # ------------------------------------------------------------------ invite (cond 4)
    @staticmethod
    def _report(res: ModuleResult, ctx: Any, code: str, inv: dict[str, Any]) -> None:
        dates = [{"role": s["role"], "id": s["id"], "created": snowflake_created(s["id"])} for s in inv["snowflakes"]]
        res.raw = {"code": inv["code"] or code, "guild_id": (inv["guild"] or {}).get("id"), "members": inv["members"]}
        res.presence("found", marker="HTTP 200 invite object", url=f"https://discord.gg/{code}", checked_at=ctx.now(), source=SOURCE)
        res.attr("discord_invite", {k: inv[k] for k in ("code", "invite_type", "guild", "channel", "members", "presence", "expires_at",
                                                        "permanent", "inviter")})
        res.attr("snowflake_dates", dates)
        res.attr("members", inv["members"])
        res.attr("online_members", inv["presence"])
        res.attr("expires", inv["expires_at"])
        guild = inv["guild"] or {}
        guild_created = next((d["created"] for d in dates if d["role"] == "guild"), None)
        if guild.get("name"):
            res.pivot(T.KEYWORD, guild["name"], "invite_guild", confidence="confirmed", expand=False,
                      note=f"name of Discord server {guild.get('id') or '?'} (server-owner text)")
        inviter = inv["inviter"]
        if inviter:
            if inviter["username"]:
                res.pivot(T.USERNAME, inviter["username"], "invite_creator", confidence="confirmed", expand=False,
                          note=f"Discord account {inviter['id']} that created the invite (expand only on analyst selection)")
            res.pivot(T.SOCIAL_ACCOUNT, f"discord:{inviter['id']}", "invite_creator", confidence="confirmed", expand=False,
                      note="Discord user id of the invite creator")
        expiry = f"expires {inv['expires_at'][:10]}" if inv["expires_at"] else ("permanent" if inv["permanent"] else "expiry unknown")
        res.finding(
            "Discord invite resolves to a server",
            "info",
            f"Invite {code} -> server {guild.get('name') or '?'} ({guild.get('id') or '?'}"
            + (f", created {guild_created[:10]}" if guild_created else "") + f"), {inv['members'] if inv['members'] is not None else '?'} "
            f"members, {inv['presence'] if inv['presence'] is not None else '?'} online, {expiry}"
            + (f"; created by {inviter['username'] or inviter['id']}" if inviter else "") + ".",
            confidence="confirmed",
            criterion="discord.com/api/v10/invites answered with the invite object",
            data={"guild_id": guild.get("id"), "guild_created": guild_created, "members": inv["members"], "presence": inv["presence"],
                  "expires_at": inv["expires_at"], "features": guild.get("features")},
            tags=["account"],
            references=[f"https://discord.gg/{code}"],
            source=SOURCE,
        )

    # ------------------------------------------------------------------ webhook (cond 5)
    @staticmethod
    def _webhook(res: ModuleResult, webhook_id: str, token: str) -> ModuleResult:
        masked = mask_secret(token, "discord_webhook_token")
        channel = {"kind": "discord_webhook", "channel_id": webhook_id, "fingerprint": masked, "requested": False,
                   "created": snowflake_created(webhook_id)}
        res.raw = {"webhook_id": webhook_id, "requested": False}
        res.attr("exfil_channels", [channel])
        res.finding(
            "Discord webhook exfiltration channel",
            "medium",
            f"Discord webhook {webhook_id} (token {masked['preview']}, SHA-256 {masked['sha256'][:16]}...) found in an IOC context: "
            "a write-only channel commonly used to exfiltrate phishing-kit or stealer data. It was not requested (the token is a "
            "third-party credential); report it to Discord for takedown.",
            confidence="probable",
            criterion="Discord webhook URL (discord.com/api/webhooks/{id}/{token}) in the investigated value; never requested",
            data={"exfil_channel": channel},
            tags=["c2", "phishing_kit_exfil"],
            source=SOURCE,
            key=webhook_id,
        )
        return res
