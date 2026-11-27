"""Correlation rules of batch p2-G05-1 (username_social).

* ``p2g051_shared_key_fingerprint`` (P103 cond 3): a public SSH key (OpenSSH SHA-256 fingerprint) or
  OpenPGP key fingerprint published on a GitHub account (``github_user``, P111) equals one published on a
  GitLab.com account (``gitlab_user``): a PROBABLE cross-platform link between the two accounts. Both
  modules parse .keys/.gpg with the same helpers, so fingerprints compare byte for byte. The rule only
  reads the graph: no request, no pivot, no scheduling.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.correlate import rule
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, ModuleResult, Severity

RULE_SHARED_KEY = "p2g051_shared_key_fingerprint"
GITHUB_MODULE = "github_user"
GITLAB_MODULE = "gitlab_user"
_KEY_ATTRIBUTES = (("ssh_keys", "ssh"), ("gpg_keys", "gpg"))


def key_fingerprints(node: Any, module: str) -> set[tuple[str, str]]:
    """{(kind, fingerprint)} a node holds from ``module`` (attributes ssh_keys / gpg_keys)."""
    out: set[tuple[str, str]] = set()
    for attr, kind in _KEY_ATTRIBUTES:
        for value, source in node.attributes.get(attr, []):
            if source != module:
                continue
            for key in value if isinstance(value, list) else [value]:
                fp = key.get("fingerprint") if isinstance(key, Mapping) else None
                if isinstance(fp, str) and 8 <= len(fp) <= 128:
                    out.add((kind, fp.strip()))
    return out


@rule(
    RULE_SHARED_KEY,
    "Same public key on a GitHub and a GitLab.com account",
    "A public SSH or OpenPGP key published on a GitHub account (github_user) has the same fingerprint as one published on a "
    "GitLab.com account (gitlab_user): a PROBABLE cross-platform link between the two accounts (P103 cond 3).",
    severity="info",
    criterion="an OpenSSH SHA-256 or OpenPGP fingerprint in ssh_keys/gpg_keys of github_user equals one of gitlab_user",
    false_positives="A key shared by a team or a deploy key reused by several people; a published example key. The link is "
                    "PROBABLE, never CONFIRMED.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_SHARED_KEY}/positive_same_ssh_and_gpg_key.json",
        f"tests/fixtures/rules/{RULE_SHARED_KEY}/positive_same_handle_one_node.json",
        f"tests/fixtures/rules/{RULE_SHARED_KEY}/negative_different_keys.json",
        f"tests/fixtures/rules/{RULE_SHARED_KEY}/negative_same_module_only.json",
    ),
)
def p2g051_shared_key_fingerprint(graph: Graph, results: list[ModuleResult]) -> Iterable[Correlation]:
    github: dict[tuple[str, str], set[str]] = {}
    gitlab: dict[tuple[str, str], set[str]] = {}
    nodes: dict[str, Any] = {}
    for node in graph.nodes.values() if isinstance(getattr(graph, "nodes", None), dict) else []:
        for fp in key_fingerprints(node, GITHUB_MODULE):
            github.setdefault(fp, set()).add(node.key)
            nodes[node.key] = node
        for fp in key_fingerprints(node, GITLAB_MODULE):
            gitlab.setdefault(fp, set()).add(node.key)
            nodes[node.key] = node
    pairs: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for fp in sorted(set(github) & set(gitlab)):
        for gh in sorted(github[fp]):
            for gl in sorted(gitlab[fp]):
                pairs.setdefault((gh, gl), []).append(fp)
    for (gh, gl), fps in sorted(pairs.items()):
        entities = [nodes[gh].entity] + ([nodes[gl].entity] if gl != gh else [])
        shown = ", ".join(f"{kind} {fp}" for kind, fp in fps[:5]) + (", ..." if len(fps) > 5 else "")
        same = gh == gl
        yield Correlation(
            rule=RULE_SHARED_KEY,
            title="Same public key on a GitHub and a GitLab.com account",
            severity=Severity.INFO,
            description=(f"{nodes[gh].entity.display} (GitHub)" + ("" if same else f" and {nodes[gl].entity.display} (GitLab.com)")
                         + (" publishes" if same else " publish") + f" the same public key ({shown})"
                         + (" on both GitHub and GitLab.com" if same else "")
                         + ": the two accounts are PROBABLY held by the same person or team."),
            entities=entities,
            confidence="probable",
            evidence=[f"{gh}: github_user {kind} {fp}" for kind, fp in fps[:10]] + [f"{gl}: gitlab_user {kind} {fp}" for kind, fp in fps[:10]],
            recommendation="Treat the GitHub and GitLab.com accounts as one identity for the investigation only after an analyst "
                           "review (a shared team or deploy key also matches).",
            tags=["identity"],
            criterion=f"{len(fps)} key fingerprint(s) published by both accounts",
            key=f"{gh}|{gl}",
        )
