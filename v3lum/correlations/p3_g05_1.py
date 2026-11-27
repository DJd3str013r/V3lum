"""Correlation rules of batch p3-G05-1 (username_social).

* ``p3g051_keybase_proof_corroborated`` (P104 cond 3): a Keybase proof whose proof state is OK is PROBABLE on the
  Keybase answer alone (the service is frozen and the remote proof post may be gone). It rises to CONFIRMED only
  when another module of the case corroborates it:

  - the proved account publishes the same OpenPGP fingerprint as the Keybase account (e.g. ``github_user``,
    P111, ``gpg_keys`` or a ``pgp_key`` edge to the same ``pgp_fingerprint`` node);
  - the proved account links back to the Keybase account (an edge from another module to
    ``social_account:keybase:<user>`` or ``url:https://keybase.io/<user>``);
  - a dns/https proof's domain carries the ``keybase-site-verification`` TXT record seen by another module
    (``dns_records`` attribute ``txt``).

  Revoked or broken proofs never rise (P104 cond 4). The rule only reads the graph: no request, no pivot, no
  scheduling.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.correlate import rule
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_KEYBASE = "p3g051_keybase_proof_corroborated"
KEYBASE = "keybase"
_PLATFORMS = {"github": "github", "twitter": "x", "reddit": "reddit", "facebook": "facebook"}
_WEB_TYPES = frozenset({"generic_web_site", "web", "https", "http"})
_TXT_MARK = "keybase-site-verification="


def _values(node: Any, attr: str, *, from_module: str | None = None, not_module: str | None = None) -> list[Any]:
    out: list[Any] = []
    for value, source in node.attributes.get(attr, []):
        if from_module is not None and source != from_module:
            continue
        if not_module is not None and source == not_module:
            continue
        out.extend(value if isinstance(value, list) else [value])
    return out


def _keybase_users(node: Any) -> dict[str, set[str]]:
    """Keybase username -> its PGP fingerprints (upper-case), from the keybase module's attributes."""
    users: dict[str, set[str]] = {}
    for prof in _values(node, "keybase_profile", from_module=KEYBASE):
        if isinstance(prof, Mapping) and isinstance(prof.get("username"), str):
            fprs = {str(f).upper() for f in prof.get("pgp_fingerprints") or [] if isinstance(f, str)}
            users.setdefault(prof["username"].lower(), set()).update(fprs)
    return users


def _proof_targets(proof: Mapping[str, Any]) -> list[str]:
    """Graph keys of the account or domain an OK proof names."""
    ptype = str(proof.get("proof_type") or "").lower()
    tag = str(proof.get("nametag") or "").strip().lower()
    if not tag:
        return []
    if ptype in _PLATFORMS:
        return [f"social_account:{_PLATFORMS[ptype]}:{tag}"]
    if ptype == "dns":
        return [f"domain:{tag}"]
    if ptype in _WEB_TYPES:
        host = ""
        try:
            host = (urlsplit(str(proof.get("service_url") or "")).hostname or "").lower()
        except ValueError:
            host = ""
        host = host or tag
        keys = [f"domain:{host}"]
        if host.startswith("www."):
            keys.append(f"domain:{host[4:]}")
        return keys
    return []


def _corroboration(graph: Graph, target: Any, user: str, fprs: set[str]) -> list[str]:
    basis: list[str] = []
    for key in _values(target, "gpg_keys", not_module=KEYBASE):
        fp = key.get("fingerprint") if isinstance(key, Mapping) else None
        if isinstance(fp, str) and fp.upper() in fprs:
            basis.append(f"same OpenPGP key {fp.upper()} published on {target.key}")
    backlinks = {f"social_account:keybase:{user}", f"url:https://keybase.io/{user}", f"url:https://keybase.io/{user}/"}
    for edge in graph.out_edges(target.key):
        if edge.module == KEYBASE:
            continue
        if edge.relation == "pgp_key" and edge.dst.split(":", 1)[-1].upper() in fprs:
            basis.append(f"{edge.module}: {target.key} publishes the Keybase PGP key {edge.dst.split(':', 1)[-1].upper()}")
        if edge.dst in backlinks:
            basis.append(f"{edge.module}: {target.key} links back to the Keybase account ({edge.dst})")
    for txt in _values(target, "txt", not_module=KEYBASE):
        if isinstance(txt, str) and _TXT_MARK in txt.replace('"', ""):
            basis.append(f"DNS TXT {_TXT_MARK}... on {target.key}")
    return list(dict.fromkeys(basis))


@rule(
    RULE_KEYBASE,
    "Keybase proof corroborated by another source",
    "A Keybase identity proof in state OK is corroborated by another module of the case: the proved account publishes "
    "the same OpenPGP key, links back to the Keybase account, or the proved domain carries the keybase-site-verification "
    "TXT record. The link rises from PROBABLE (Keybase alone, frozen service) to CONFIRMED (P104 cond 3).",
    severity="info",
    criterion="an OK Keybase proof plus an independent observation by another module (same PGP fingerprint, link back, or TXT record)",
    false_positives="A shared or reused team PGP key; a stale link back on a transferred account. Revoked and broken proofs "
                    "never rise.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_KEYBASE}/positive_same_pgp_key_on_github.json",
        f"tests/fixtures/rules/{RULE_KEYBASE}/positive_link_back_and_dns_txt.json",
        f"tests/fixtures/rules/{RULE_KEYBASE}/negative_keybase_only.json",
        f"tests/fixtures/rules/{RULE_KEYBASE}/negative_revoked_proof.json",
    ),
)
def p3g051_keybase_proof_corroborated(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    nodes = getattr(graph, "nodes", None)
    if not isinstance(nodes, dict):
        return
    for node in list(nodes.values()):
        users = _keybase_users(node)
        if not users:
            continue
        for proof in _values(node, "keybase_proofs", from_module=KEYBASE):
            if not isinstance(proof, Mapping) or proof.get("ok") is not True:
                continue  # revoked/broken proofs never rise (cond 4)
            user = str(proof.get("username") or "").lower()
            if user not in users:
                continue
            for key in _proof_targets(proof):
                target = graph.get(key)
                if target is None:
                    continue
                basis = _corroboration(graph, target, user, users[user])
                if not basis:
                    continue
                yield Correlation(
                    rule=RULE_KEYBASE,
                    title="Keybase proof corroborated by another source",
                    severity=Severity.INFO,
                    description=(f"Keybase user {user} signed an OK proof for {proof.get('proof_type')} {proof.get('nametag')} "
                                 f"({proof.get('wording') or 'Keybase-verified proof'}), and another source confirms the link: "
                                 + "; ".join(basis[:3]) + ". The identity link is CONFIRMED (Keybase alone would be PROBABLE)."),
                    entities=[node.entity, target.entity],
                    confidence="confirmed",
                    evidence=[f"{node.key}: keybase proof {proof.get('proof_type')} {proof.get('nametag')} state ok", *basis[:5]],
                    recommendation="Treat the Keybase account and the proved account or domain as one identity; keep the proof date in "
                                   "mind (Keybase is in maintenance mode).",
                    tags=["identity"],
                    criterion="OK Keybase proof + independent corroboration: " + basis[0],
                    key=f"{node.key}|{user}|{key}",
                )
