"""Correlation rules of batch p2-G05-2: avatar reuse across accounts (P114).

The module ``avatar_correlation`` records ``avatar_dhash`` / ``avatar_sha256`` / ``avatar_ignored`` on
each avatar URL it hashed. A profile is linked to its avatar by an edge ``has_avatar`` (profile ->
avatar URL) or by its ``avatar_url`` attribute. These rules only read the graph:

* ``p2g05_avatar_reuse`` - two accounts whose non-default avatars are within Hamming distance 8 get
  'same avatar image (dHash distance N)' (P114 cond 5): POSSIBLE alone, PROBABLE only together with
  another identity signal between the two accounts (an identity edge between them, or both found
  from the same handle or profile), never CONFIRMED and never worded as the same person. Nothing is
  reported unless at least two accounts carry a hashed, usable avatar (cond 1). An image shared by more
  than three accounts in the case or in case-DB sightings is reported once as 'same image' context and
  is no identity signal (cond 6). Flat and placeholder avatars are ignored (cond 5).
* ``p2g05_avatar_brand_logo`` - an avatar equal to an organisation brand logo is 'uses <brand> logo',
  an impersonation signal, never an identity link (cond 6). Logo dHashes come from org_profile brands
  (``logo_dhash`` / ``logo_dhashes`` when the profile schema carries them) and from the module setting
  ``avatar_correlation_brand_logos`` (``{brand: [dhash, ...]}``) until it does.
* ``p2g05_gravatar_email_match`` - the MD5/SHA-256 of a case e-mail (computed locally, cond 7) equal
  to the Gravatar hash inside an avatar URL found on another account: that avatar was registered by
  that address. Nothing is sent to Gravatar by this rule or by avatar_correlation.

Reports are text only: profile URLs, avatar URLs and distances, never thumbnails (cond 9).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_AVATAR_REUSE = "p2g05_avatar_reuse"
RULE_AVATAR_BRAND_LOGO = "p2g05_avatar_brand_logo"
RULE_GRAVATAR_EMAIL = "p2g05_gravatar_email_match"
DHASH_MATCH_MAX = 8
COMMON_IMAGE_MIN_ACCOUNTS = 4  # cond 6: seen on more than 3 unrelated accounts
BRAND_LOGO_SETTING = "avatar_correlation_brand_logos"
#: Relations that already link two accounts (the 'another identity signal' of cond 5).
IDENTITY_RELATIONS = frozenset({"same_person", "linked_account_on_profile", "uses_email", "commit_email", "gpg_uid_email",
                                "noreply_account", "email_on_profile", "has_account", "uses_username"})
#: Relations from one parent that put two accounts on the same handle or profile.
SHARED_PARENT_RELATIONS = frozenset({"has_account", "uses_username", "linked_account_on_profile"})
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_GRAVATAR_HASH = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})(?![0-9a-f])", re.I)

_FIX = "tests/fixtures/rules/{rule}/{name}.json"


def hamming(a: Any, b: Any) -> int:
    try:
        return bin(int(str(a), 16) ^ int(str(b), 16)).count("1")
    except (TypeError, ValueError):
        return 64


def _url_key(value: Any) -> str | None:
    ent = Entity.try_make(T.URL, value) if isinstance(value, str) else None
    return ent.key if ent is not None else None


def _label(node: Node) -> str:
    return str(node.entity.value)


def avatar_records(graph: Graph) -> list[dict[str, Any]]:
    """One record per (account, hashed avatar): {account, avatar, dhash, sha256, ignored}.

    The account is every node linked to the avatar URL (``has_avatar`` edge or ``avatar_url``
    attribute); an avatar URL nobody links (an analyst-typed avatar URL) stands for its own account.
    """
    by_url: dict[str, set[str]] = {}
    for node in graph.nodes.values():
        for value in node.attr_values("avatar_url"):
            key = _url_key(value)
            if key and key != node.entity.key:
                by_url.setdefault(key, set()).add(node.entity.key)
    records: list[dict[str, Any]] = []
    for node in graph.nodes.values():
        if node.entity.type is not T.URL:
            continue
        dhash = node.attr("avatar_dhash")
        if not isinstance(dhash, str) or not _HEX16.match(dhash.lower()):
            continue
        owners = {e.src for e in graph.in_edges(node.entity.key, "has_avatar")} | by_url.get(node.entity.key, set())
        owners.discard(node.entity.key)
        ignored = node.attr("avatar_ignored")
        sha = node.attr("avatar_sha256")
        for owner in sorted(owners or {node.entity.key}):
            records.append({"account": owner, "avatar": node.entity.key, "dhash": dhash.lower(),
                            "sha256": sha if isinstance(sha, str) else "", "ignored": ignored if isinstance(ignored, str) else ""})
    return records


def brand_logos(rctx: Any) -> list[dict[str, str]]:
    """Logo dHashes per brand: org_profile brands (``logo_dhash``/``logo_dhashes``) + the module setting."""
    out: list[dict[str, str]] = []
    org = getattr(rctx, "org", None) if rctx is not None else None
    for brand in getattr(org, "brands", None) or []:
        values = getattr(brand, "logo_dhashes", None) or [getattr(brand, "logo_dhash", None)]
        for value in values:
            if isinstance(value, str) and _HEX16.match(value.lower()):
                out.append({"brand": str(getattr(brand, "keyword", "") or "brand"), "dhash": value.lower()})
    setting = rctx.setting(BRAND_LOGO_SETTING, {}) if rctx is not None else {}
    if isinstance(setting, dict):
        for brand, values in setting.items():
            for value in values if isinstance(values, (list, tuple)) else [values]:
                if isinstance(value, str) and _HEX16.match(value.lower()):
                    out.append({"brand": str(brand), "dhash": value.lower()})
    return out


def _logo_for(record: dict[str, Any], logos: list[dict[str, str]]) -> dict[str, str] | None:
    return next((lg for lg in logos if hamming(record["dhash"], lg["dhash"]) <= DHASH_MATCH_MAX), None)


def _sightings(graph: Graph, avatar_key: str, rctx: Any) -> int:
    """Other cases that saw the same avatar URL (case-DB sightings; restricted cases count too)."""
    lookup = (getattr(rctx, "meta", None) or {}).get("sightings_lookup") if rctx is not None else None
    node = graph.get(avatar_key)
    if not callable(lookup) or node is None:
        return 0
    try:
        summary = lookup(node.entity)
    except Exception:  # noqa: BLE001 - sightings are optional context: a failing lookup counts nothing
        return 0
    try:
        return max(0, int(getattr(summary, "total", 0) or 0))
    except (TypeError, ValueError):
        return 0


def other_identity_signal(graph: Graph, a: str, b: str) -> str:
    """cond 5: the identity signal already linking accounts ``a`` and ``b`` ('' when there is none)."""
    for edge in graph.edges:
        if {edge.src, edge.dst} == {a, b} and edge.relation in IDENTITY_RELATIONS:
            return f"{edge.relation} edge between the two accounts ({edge.module})"
    parents_a = {(e.src, e.relation) for e in graph.in_edges(a) if e.relation in SHARED_PARENT_RELATIONS}
    parents_b = {e.src for e in graph.in_edges(b) if e.relation in SHARED_PARENT_RELATIONS}
    for parent, relation in sorted(parents_a):
        if parent in parents_b and parent not in (a, b):
            node = graph.get(parent)
            return f"both accounts reached from {node.entity.display if node else parent} ({relation})"
    return ""


def _entities(graph: Graph, keys: Iterable[str]) -> list[Entity]:
    out: list[Entity] = []
    for key in keys:
        node = graph.get(key)
        if node is not None and node.entity not in out:
            out.append(node.entity)
    return out


@rule(
    RULE_AVATAR_REUSE,
    "Same avatar image on two accounts",
    "Two accounts whose non-default avatars have a 64-bit whole-image dHash within Hamming distance 8: an identity signal "
    "(POSSIBLE alone, PROBABLE with another identity signal), never proof of the same person. Images used by more than "
    "three accounts are reported once as common images.",
    version="1",
    severity="info",
    criterion="dHash Hamming distance <= 8 between non-flat, non-placeholder avatars of two accounts; at least two accounts "
    "with hashed avatars in the case (P114 cond 1/5)",
    false_positives="Stock images, memes, team or brand logos and default avatars of platforms not yet in the bundled "
    "placeholder list; two people sharing a photo.",
    fixtures=(
        _FIX.format(rule=RULE_AVATAR_REUSE, name="positive_same_avatar_two_profiles"),
        _FIX.format(rule=RULE_AVATAR_REUSE, name="positive_same_handle_is_probable"),
        _FIX.format(rule=RULE_AVATAR_REUSE, name="negative_one_profile_or_defaults"),
        _FIX.format(rule=RULE_AVATAR_REUSE, name="negative_different_images"),
    ),
)
def avatar_reuse(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    logos = brand_logos(rctx)
    usable = [r for r in avatar_records(graph) if not r["ignored"] and _logo_for(r, logos) is None]
    if len({r["account"] for r in usable}) < 2:  # cond 1: fewer than two accounts with usable avatars
        return
    sightings = {r["avatar"]: _sightings(graph, r["avatar"], rctx) for r in usable}
    common: set[int] = set()
    for i, rec in enumerate(usable):
        accounts = {o["account"] for o in usable if hamming(rec["dhash"], o["dhash"]) <= DHASH_MATCH_MAX}
        if len(accounts) + sightings.get(rec["avatar"], 0) >= COMMON_IMAGE_MIN_ACCOUNTS:
            common.add(i)
    reported_clusters: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for i, a in enumerate(usable):
        for j in range(i + 1, len(usable)):
            b = usable[j]
            if a["account"] == b["account"]:
                continue
            distance = hamming(a["dhash"], b["dhash"])
            if distance > DHASH_MATCH_MAX:
                continue
            if i in common or j in common:
                cluster = [o for o in usable if hamming(o["dhash"], a["dhash"]) <= DHASH_MATCH_MAX]
                cid = min(o["dhash"] for o in cluster)
                if cid in reported_clusters:
                    continue
                reported_clusters.add(cid)
                accounts = sorted({o["account"] for o in cluster})
                extra = max(sightings.get(o["avatar"], 0) for o in cluster)
                yield Correlation(
                    rule=RULE_AVATAR_REUSE,
                    title="Same image on many accounts (common image)",
                    severity=Severity.INFO,
                    description=f"The same avatar image (dHash {cid}) is used by {len(accounts)} accounts in this case"
                    + (f" and seen in {extra} other case(s)" if extra else "")
                    + ": " + ", ".join(accounts[:10]) + ". A logo, meme or stock image: 'same image', not an identity signal.",
                    entities=_entities(graph, accounts),
                    confidence="possible",
                    evidence=sorted({o["avatar"] for o in cluster}),
                    recommendation="Do not link these accounts on the avatar; look for other signals.",
                    tags=["common_image", "context_only"],
                    criterion=f"one dHash cluster (distance <= {DHASH_MATCH_MAX}) on more than {COMMON_IMAGE_MIN_ACCOUNTS - 1} accounts "
                    "in the case or in sightings (P114 cond 6)",
                    key=f"common:{cid}",
                )
                continue
            pair = tuple(sorted((a["account"], b["account"])))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            signal = other_identity_signal(graph, pair[0], pair[1])
            node_a, node_b = graph.get(pair[0]), graph.get(pair[1])
            label_a = _label(node_a) if node_a else pair[0]
            label_b = _label(node_b) if node_b else pair[1]
            yield Correlation(
                rule=RULE_AVATAR_REUSE,
                title=f"same avatar image (dHash distance {distance})",
                severity=Severity.INFO,
                description=f"{label_a} and {label_b} show the same avatar image (whole-image dHash distance {distance} of 64; "
                f"avatars {a['avatar'].split(':', 1)[1]} and {b['avatar'].split(':', 1)[1]}). "
                + (f"Another identity signal links them: {signal}. " if signal else "No other identity signal links them yet. ")
                + "A matching avatar is an identity signal, never proof of the same person.",
                entities=_entities(graph, [pair[0], pair[1], a["avatar"], b["avatar"]]),
                confidence="probable" if signal else "possible",
                evidence=[a["avatar"], b["avatar"]],
                recommendation="Compare the accounts' creation dates, linked accounts and writing before linking them.",
                tags=["same_avatar", "weak_signal"],
                criterion=f"dHash distance {distance} <= {DHASH_MATCH_MAX}; "
                + ("plus " + signal if signal else "no other identity signal (POSSIBLE)"),
                key="|".join(pair),
            )


@rule(
    RULE_AVATAR_BRAND_LOGO,
    "Account avatar uses an organisation brand logo",
    "An avatar whose dHash is within distance 8 of an organisation brand logo: 'uses <brand> logo', an impersonation "
    "signal for brand-protection review, never an identity link.",
    version="1",
    severity="low",
    criterion="avatar dHash within Hamming distance 8 of an org_profile brand logo dHash (P114 cond 6)",
    false_positives="The organisation's own official accounts, partners and resellers allowed to use the logo.",
    fixtures=(
        _FIX.format(rule=RULE_AVATAR_BRAND_LOGO, name="positive_logo_avatar"),
        _FIX.format(rule=RULE_AVATAR_BRAND_LOGO, name="negative_no_logo_configured"),
    ),
)
def avatar_brand_logo(graph: Graph, results: list[ModuleResult], rctx: Any = None) -> Iterable[Correlation]:
    logos = brand_logos(rctx)
    if not logos:
        return
    for rec in avatar_records(graph):
        if rec["ignored"]:
            continue
        logo = _logo_for(rec, logos)
        if logo is None:
            continue
        node = graph.get(rec["account"])
        label = _label(node) if node else rec["account"]
        distance = hamming(rec["dhash"], logo["dhash"])
        yield Correlation(
            rule=RULE_AVATAR_BRAND_LOGO,
            title=f"uses {logo['brand']} logo",
            severity=Severity.LOW,
            description=f"{label} uses the {logo['brand']} logo as its avatar (dHash distance {distance} of 64; avatar "
            f"{rec['avatar'].split(':', 1)[1]}): an impersonation signal to review, not an identity link.",
            entities=_entities(graph, [rec["account"], rec["avatar"]]),
            confidence="possible",
            evidence=[rec["avatar"]],
            recommendation="Check whether the account is official; if not, route it to brand-protection takedown review.",
            tags=["brand_abuse"],
            criterion=f"avatar dHash within distance {distance} <= {DHASH_MATCH_MAX} of the {logo['brand']} logo",
            key=f"{rec['account']}|{logo['brand']}",
        )


def _gravatar_hashes(email: str) -> dict[str, str]:
    value = email.strip().lower()
    return {hashlib.md5(value.encode()).hexdigest(): "md5",  # noqa: S324 - Gravatar's public legacy hash format
            hashlib.sha256(value.encode()).hexdigest(): "sha256"}


@rule(
    RULE_GRAVATAR_EMAIL,
    "Gravatar avatar on an account matches a case e-mail",
    "The MD5/SHA-256 of a case e-mail, computed locally, equals the Gravatar hash inside an avatar URL found on another "
    "account: that avatar was registered at Gravatar by that address.",
    version="1",
    severity="info",
    criterion="md5 or sha256 of the trimmed, lower-cased e-mail equals the hash in a gravatar.com/avatar/<hash> URL of "
    "another account (P114 cond 7; computed locally, nothing sent to Gravatar)",
    false_positives="An account that embeds someone else's Gravatar URL on purpose (rare; the URL itself is public).",
    fixtures=(
        _FIX.format(rule=RULE_GRAVATAR_EMAIL, name="positive_gitlab_avatar_hash"),
        _FIX.format(rule=RULE_GRAVATAR_EMAIL, name="negative_own_node_and_other_hash"),
    ),
)
def gravatar_email_match(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    hashes: dict[str, tuple[str, str]] = {}
    for node in graph.of_type(T.EMAIL):
        for digest, algo in _gravatar_hashes(str(node.entity.value)).items():
            hashes[digest] = (node.entity.key, algo)
    if not hashes:
        return
    found: dict[tuple[str, str], tuple[str, str]] = {}
    for node in graph.nodes.values():
        urls = [str(v) for v in node.attr_values("avatar_url")]
        if node.entity.type is T.URL:
            urls.append(str(node.entity.value))
        for url in urls:
            m = _GRAVATAR_HASH.search(url)
            if not m:
                continue
            digest = m.group(1).lower()
            if digest not in hashes:
                continue
            email_key, algo = hashes[digest]
            owners = [node.entity.key]
            if node.entity.type is T.URL:  # an avatar URL node: its accounts are the profiles linking it
                linked = [e.src for e in graph.in_edges(node.entity.key, "has_avatar")]
                owners = linked or owners
            for owner in owners:
                if owner != email_key:
                    found.setdefault((email_key, owner), (url, algo))
    for (email_key, owner), (url, algo) in sorted(found.items()):
        email_node, owner_node = graph.get(email_key), graph.get(owner)
        yield Correlation(
            rule=RULE_GRAVATAR_EMAIL,
            title="Gravatar avatar matches a case e-mail",
            severity=Severity.INFO,
            description=f"The avatar of {_label(owner_node) if owner_node else owner} is the Gravatar of "
            f"{email_node.entity.display if email_node else email_key} ({algo} of the address, computed locally, equals the "
            f"hash in {url}). Gravatar was not queried.",
            entities=_entities(graph, [email_key, owner]),
            confidence="probable",
            evidence=[url],
            recommendation="Treat the account as linked to the address; confirm with a second signal before attribution.",
            tags=["identity"],
            criterion=f"{algo}(trim(lower(e-mail))) equals the Gravatar hash in the avatar URL of another account",
            key=f"{email_key}|{owner}",
        )


__all__ = [
    "COMMON_IMAGE_MIN_ACCOUNTS",
    "DHASH_MATCH_MAX",
    "RULE_AVATAR_BRAND_LOGO",
    "RULE_AVATAR_REUSE",
    "RULE_GRAVATAR_EMAIL",
    "avatar_brand_logo",
    "avatar_records",
    "avatar_reuse",
    "brand_logos",
    "gravatar_email_match",
    "other_identity_signal",
]
