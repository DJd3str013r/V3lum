"""E-mail hygiene (P088): offline disposable / free-provider / role-account / relay classification.

This file holds the ONE set of e-mail hygiene data of V3LUM (P088 C1, the architect's floor):

* the CC0 disposable-email-domains blocklist and the MIT AfterShip email-verifier free-provider and
  role-account lists, bundled unmodified in ``v3lum/data/email_hygiene/`` and registered as
  refreshable datasets (``v3lum data update``) with the bundled copy as the fallback (C2);
* the V3LUM supplement ``v3lum/data/email_hygiene/local_supplement.json``: missing temp-mail
  domains, Brazilian webmail domains, the former hard-coded ``email_basics.FREE_PROVIDERS`` set and
  the forwarding/alias relay services (C3, C4);
* role local parts are ONE list with the A4 generic-address file ``v3lum/data/generic_addresses.json``:
  the A4 list is read through ``entities.generic_address_kind`` and merged with the AfterShip roles.

``email_basics`` reads its free-provider flag through :func:`is_free_provider` (no second copy).

The classifier never touches the network (disclosure 'none', TLP:RED-safe): it reads the local copy
of each dataset when ``v3lum data update`` has fetched one, else the bundled copy, and never triggers
a download itself. Matching is PSL-aware: the address domain and its parents down to (and including)
the registrable domain are checked, never a public suffix (``x.0-mailer.dynv6.net`` matches the list
entry ``0-mailer.dynv6.net``, never ``dynv6.net``). Relay services are never disposable and never
scored (C4). There is no SMTP check of any kind (C6, P096). Online second opinions live in the
separate opt-in module ``email_hygiene_online`` (C5).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v3lum.core import psl
from v3lum.core.datasets import DataStore, DatasetError, register_dataset
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

__all__ = [
    "DISPOSABLE_DATASET",
    "FREE_DATASET",
    "HygieneLists",
    "ROLE_DATASET",
    "candidate_domains",
    "classify_address",
    "classify_domain",
    "free_domains",
    "hygiene_lists",
    "is_free_provider",
    "normalise_domain",
    "parse_domain_list",
    "parse_go_string_set",
]

SRC_DISPOSABLE = "github.email_hygiene_disposable"
SRC_FREE = "github.email_hygiene_aftership_free"
SRC_ROLE = "github.email_hygiene_aftership_role"

BUNDLED_DIR = "email_hygiene"
BUNDLED_DISPOSABLE = f"{BUNDLED_DIR}/disposable_email_blocklist.conf"
BUNDLED_FREE = f"{BUNDLED_DIR}/aftership_metadata_free.go"
BUNDLED_ROLE = f"{BUNDLED_DIR}/aftership_metadata_role.go"
BUNDLED_SUPPLEMENT = f"{BUNDLED_DIR}/local_supplement.json"
SUPPLEMENT_SCHEMA = "v3lum.email_hygiene_supplement/1"

#: Smallest sane list sizes (live 2026-11-26: 10,455 disposable domains, 4,535 free domains, 892 roles).
MIN_DISPOSABLE = 5000
MIN_FREE = 1000
MIN_ROLES = 200
WEEK = 7 * 86400
_HUGE_TTL = 10.0**12  # read the local copy as it is: the classifier never triggers a download

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_GO_MAP_TRUE_RE = re.compile(r'"([^"\\\n]{1,253})"\s*:\s*(?:true|struct\s*\{\s*\}\s*\{\s*\}|\{\s*\})')
_GO_STR_RE = re.compile(r'"([^"\\\n]{1,253})"')
_HTML_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html|<head|<body|<\?xml|<title)", re.I)


# --------------------------------------------------------------------------------------
# parsing (pure, defensive: never raises on odd input)
# --------------------------------------------------------------------------------------


def normalise_domain(value: Any) -> str | None:
    """Lower-case, strip dots/whitespace, IDNA -> punycode, label syntax check; None if invalid."""
    d = str(value or "").strip().strip(".").lower()
    if not d or len(d) > 253 or any(c.isspace() for c in d) or "@" in d or "/" in d or ":" in d:
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    return d


def parse_domain_list(text: Any) -> frozenset[str]:
    """One domain per line ('#' comments) -> set of normalised domains (the CC0 blocklist format)."""
    out: set[str] = set()
    if not isinstance(text, str):
        return frozenset()
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            dom = normalise_domain(item)
            if dom:
                out.add(dom)
    return frozenset(out)


def parse_go_string_set(source: Any) -> frozenset[str]:
    """AfterShip metadata Go source: ``"x": true`` map literals (or plain string slices) -> lower-case set."""
    if not isinstance(source, str):
        return frozenset()
    keys = _GO_MAP_TRUE_RE.findall(source)
    if not keys:
        body = source.split("{", 1)[1] if "{" in source else ""
        keys = _GO_STR_RE.findall(body)
    return frozenset(k.strip().lower() for k in keys if k.strip())


def _read(path: Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _validate_domain_list(path: Path) -> bool:
    """AR10 ``validate=``: an HTML page, an error body or a truncated list never replaces a good copy."""
    text = _read(path)
    if _HTML_RE.match(text[:4096]):
        raise DatasetError("an HTML page came back instead of the domain list")
    count = len(parse_domain_list(text))
    if count < MIN_DISPOSABLE:
        raise DatasetError(f"only {count} domains (expected >= {MIN_DISPOSABLE})")
    return True


def _validate_go_set(path: Path, minimum: int) -> bool:
    text = _read(path)
    if _HTML_RE.match(text[:4096]):
        raise DatasetError("an HTML page came back instead of the Go metadata file")
    count = len(parse_go_string_set(text))
    if count < minimum:
        raise DatasetError(f"only {count} entries (expected >= {minimum})")
    return True


def _validate_free(path: Path) -> bool:
    return _validate_go_set(path, MIN_FREE)


def _validate_role(path: Path) -> bool:
    return _validate_go_set(path, MIN_ROLES)


DISPOSABLE_DATASET = register_dataset(
    "email_hygiene_disposable.conf",
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
    ttl=WEEK,
    description="disposable-email-domains blocklist (one domain per line); bundled fallback v3lum/data/email_hygiene/disposable_email_blocklist.conf",
    licence="CC0-1.0",
    terms_class="open",
    attribution="disposable-email-domains (https://github.com/disposable-email-domains/disposable-email-domains), CC0 1.0",
    provider="github",
    source=SRC_DISPOSABLE,
    validate=_validate_domain_list,
    min_bytes=50_000,
    expect="text",
    max_bytes=2_000_000,
    essential=True,
)
FREE_DATASET = register_dataset(
    "email_hygiene_aftership_free.go",
    "https://raw.githubusercontent.com/AfterShip/email-verifier/master/metadata_free.go",
    ttl=WEEK,
    description="AfterShip email-verifier free e-mail providers (Go map literal); bundled fallback v3lum/data/email_hygiene/aftership_metadata_free.go",
    licence="MIT",
    terms_class="open",
    attribution="AfterShip email-verifier (https://github.com/AfterShip/email-verifier), MIT License, Copyright (c) 2020 AfterShip",
    provider="github",
    source=SRC_FREE,
    validate=_validate_free,
    min_bytes=20_000,
    expect="text",
    max_bytes=2_000_000,
    essential=True,
)
ROLE_DATASET = register_dataset(
    "email_hygiene_aftership_role.go",
    "https://raw.githubusercontent.com/AfterShip/email-verifier/master/metadata_role.go",
    ttl=WEEK,
    description="AfterShip email-verifier role-account local parts (Go map literal); bundled fallback v3lum/data/email_hygiene/aftership_metadata_role.go",
    licence="MIT",
    terms_class="open",
    attribution="AfterShip email-verifier (https://github.com/AfterShip/email-verifier), MIT License, Copyright (c) 2020 AfterShip",
    provider="github",
    source=SRC_ROLE,
    validate=_validate_role,
    min_bytes=2_000,
    expect="text",
    max_bytes=1_000_000,
    essential=True,
)


# --------------------------------------------------------------------------------------
# the merged lists
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HygieneLists:
    """Merged hygiene lists. ``roles`` are the AfterShip role local parts; the A4 roles are read
    through ``entities.generic_address_kind`` (one list, P088 C2). ``origin`` says, per list, whether
    the local dataset copy or the bundled copy was used."""

    disposable: frozenset[str]
    free: frozenset[str]
    relay: frozenset[str]
    roles: frozenset[str]
    origin: dict[str, str] = field(default_factory=dict)


_PARSED: dict[tuple[str, str], frozenset[str]] = {}
_PARSED_LOCK = threading.Lock()


def _parsed(kind: str, text: str, parser: Any) -> frozenset[str]:
    key = (kind, hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest())
    with _PARSED_LOCK:
        hit = _PARSED.get(key)
    if hit is not None:
        return hit
    value = parser(text)
    with _PARSED_LOCK:
        if len(_PARSED) > 32:
            _PARSED.clear()
        _PARSED[key] = value
    return value


def _bundled_text(ctx: Any, name: str) -> str:
    data = getattr(ctx, "data", None) if ctx is not None else None
    if data is not None:
        try:
            return data.bundled_text(name)
        except (OSError, ValueError):
            pass
    try:
        return DataStore.bundled_text(name)
    except (OSError, ValueError):
        return ""


def _local_dataset_text(ctx: Any, name: str) -> str | None:
    """The local copy fetched by ``v3lum data update`` (stale or not), never a download."""
    data = getattr(ctx, "data", None) if ctx is not None else None
    if data is None:
        return None
    try:
        if not data.info(name).present:
            return None
        return data.fetch_text(name, ttl=_HUGE_TTL)
    except (DatasetError, OSError, ValueError):
        return None


def _list(ctx: Any, kind: str, dataset: str, bundled: str, parser: Any, minimum: int) -> tuple[frozenset[str], str]:
    text = _local_dataset_text(ctx, dataset)
    if text:
        values = _parsed(kind, text, parser)
        if len(values) >= minimum:
            return values, "dataset"
    return _parsed(kind, _bundled_text(ctx, bundled), parser), "bundled"


def _supplement(ctx: Any) -> dict[str, frozenset[str]]:
    out = {"disposable": frozenset(), "free": frozenset(), "relay": frozenset()}
    try:
        doc = json.loads(_bundled_text(ctx, BUNDLED_SUPPLEMENT) or "{}")
    except ValueError:
        return out
    if not isinstance(doc, dict) or doc.get("schema") != SUPPLEMENT_SCHEMA:
        return out

    def domains(*items: Any) -> frozenset[str]:
        found: set[str] = set()
        for item in items:
            for value in item if isinstance(item, list) else []:
                dom = normalise_domain(value)
                if dom:
                    found.add(dom)
        return frozenset(found)

    disp = doc.get("disposable") if isinstance(doc.get("disposable"), dict) else {}
    free = doc.get("free_providers") if isinstance(doc.get("free_providers"), dict) else {}
    relay = doc.get("relay") if isinstance(doc.get("relay"), dict) else {}
    out["disposable"] = domains(disp.get("domains"))
    out["free"] = domains(free.get("brazil"), free.get("legacy_email_basics"))
    out["relay"] = domains(relay.get("domains"))
    return out


def _parse_free(text: Any) -> frozenset[str]:
    return frozenset(d for d in (normalise_domain(x) for x in parse_go_string_set(text)) if d)


def _free_domains(ctx: Any) -> tuple[frozenset[str], str]:
    free, origin = _list(ctx, "free", FREE_DATASET, BUNDLED_FREE, _parse_free, MIN_FREE)
    return free | _supplement(ctx)["free"], origin


def free_domains(ctx: Any = None) -> frozenset[str]:
    """Free-webmail domains: AfterShip list (local dataset copy, else bundled) + the V3LUM supplement."""
    return _free_domains(ctx)[0]


def hygiene_lists(ctx: Any = None) -> HygieneLists:
    """The merged lists for a run (``ctx`` gives the dataset view; None reads bundled data only)."""
    disposable, o_disp = _list(ctx, "disposable", DISPOSABLE_DATASET, BUNDLED_DISPOSABLE, parse_domain_list, MIN_DISPOSABLE)
    free, o_free = _free_domains(ctx)
    roles, o_role = _list(ctx, "role", ROLE_DATASET, BUNDLED_ROLE, parse_go_string_set, MIN_ROLES)
    sup = _supplement(ctx)
    return HygieneLists(
        disposable=disposable | sup["disposable"],
        free=free,
        relay=sup["relay"],
        roles=frozenset(r for r in roles if r and len(r) <= 64),
        origin={"disposable": o_disp, "free": o_free, "roles": o_role},
    )


def candidate_domains(domain: Any) -> list[str]:
    """The domain and its parents down to, and including, its PSL registrable domain (most specific
    first); never a public suffix. [] for an invalid domain or a bare public suffix."""
    dom = normalise_domain(domain)
    if not dom:
        return []
    try:
        reg = psl.registrable_domain(dom)
    except (ValueError, UnicodeError):
        reg = None
    if reg is None:
        return []
    labels = dom.split(".")
    out = []
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        out.append(cand)
        if cand == reg:
            break
    return out


def classify_domain(domain: Any, lists: HygieneLists) -> dict[str, Any]:
    """Offline domain classification (P088 C1-C4, C6). Relay services are never disposable."""
    dom = normalise_domain(domain)
    cands = candidate_domains(dom) if dom else []

    def first(values: frozenset[str]) -> str | None:
        return next((c for c in cands if c in values), None)

    relay, disp, free = first(lists.relay), first(lists.disposable), first(lists.free)
    notes = []
    if relay and disp:
        notes.append("listed as disposable upstream; tagged relay (privacy tool, never scored)")
    return {
        "domain": dom,
        "registrable_domain": cands[-1] if cands else None,
        "valid": bool(cands),
        "disposable": bool(disp) and not relay,
        "free_provider": bool(free),
        "relay": bool(relay),
        "matched": {k: v for k, v in (("disposable", disp), ("free_provider", free), ("relay", relay)) if v},
        "notes": notes,
    }


def _strip_separators(value: str) -> str:
    return re.sub(r"[._-]", "", value)


def classify_address(address: Any, lists: HygieneLists) -> dict[str, Any]:
    """Offline address classification: domain facts plus role_account (A4 + AfterShip, '+tag'
    ignored, '.', '_' and '-' separators tolerated) and the A4 generic-address kind."""
    text = str(address or "").strip()
    if text.count("@") != 1:
        return {"valid": False, "reason": "not a single-@ address"}
    local, domain = text.rsplit("@", 1)
    base = local.split("+", 1)[0].strip().lower()
    out = classify_domain(domain, lists)
    if not out["valid"] or not base or len(base) > 64:
        return {"valid": False, "reason": "invalid address"}
    stripped = _strip_separators(base)
    aftership = base in lists.roles or (len(stripped) >= 2 and stripped in {_strip_separators(r) for r in lists.roles})
    generic = generic_address_kind(text)
    out["generic_address"] = generic
    out["role_account"] = bool(aftership or generic in ("role", "test"))
    out["role_source"] = "a4" if generic in ("role", "test") else ("aftership" if aftership else None)
    out["local_part"] = base
    return out


def is_free_provider(domain: Any, ctx: Any = None) -> bool:
    """The free-webmail flag shared with email_basics (PSL-aware, data files only, no network)."""
    values = free_domains(ctx)
    return any(c in values for c in candidate_domains(domain))


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class EmailHygiene(Module):
    name = "email_hygiene"
    title = "E-mail hygiene (offline lists)"
    description = (
        "Flags disposable, free-webmail, role-account and privacy-relay addresses and domains from bundled CC0/MIT lists "
        "(disposable-email-domains, AfterShip email-verifier) plus a V3LUM supplement; offline, no SMTP."
    )
    category = "email"
    accepts = {T.EMAIL, T.DOMAIN}
    tags = {"offline", "free"}
    reference = "https://github.com/disposable-email-domains/disposable-email-domains"
    notice = "Offline lists only: nothing leaves the machine (TLP:RED-safe) and no SMTP check is ever made. Relay services are privacy tools, never scored."
    terms = "open"  # CC0 + MIT dataset sources
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SRC_DISPOSABLE, SRC_FREE, SRC_ROLE)
    default_enabled = True
    max_pivots = 0

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Only mail domains: a bare public suffix or an invalid domain is not applicable."""
        domain = entity.value.rsplit("@", 1)[-1] if entity.type is T.EMAIL else entity.value
        return bool(candidate_domains(domain))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        lists = hygiene_lists(ctx)
        if entity.type is T.EMAIL:
            facts = classify_address(entity.value, lists)
        else:
            facts = classify_domain(entity.value, lists)
        if not facts.get("valid"):
            return res.mark("error", f"cannot classify {entity.type.value}: {facts.get('reason') or 'invalid domain'}")
        res.raw = {"classification": facts, "lists": dict(lists.origin)}
        domain = facts["domain"]
        res.attr("disposable", facts["disposable"])
        res.attr("free_provider", facts["free_provider"])
        res.attr("relay", facts["relay"])
        if entity.type is T.EMAIL:
            res.attr("role_account", facts["role_account"])
            if facts.get("generic_address"):
                res.attr("generic_address", facts["generic_address"])
        matched = facts["matched"]
        if facts["relay"]:
            res.finding(
                "Privacy relay / alias service",
                "info",
                f"{domain} forwards mail for a hidden mailbox (matched {matched['relay']}). A privacy tool: never treated as disposable or malicious.",
                confidence="probable",
                criterion="domain on the V3LUM relay-service list (P088 C4)",
                data={"matched": matched["relay"]},
                tags=["info", "privacy_relay", "context_only"],
            )
        if facts["disposable"]:
            res.finding(
                "Disposable e-mail domain",
                "low",
                f"{domain} is a disposable/temporary mailbox provider (matched list entry {matched['disposable']}): a weak fraud signal, not proof.",
                confidence="probable",
                criterion="domain or parent (PSL-aware) on the CC0 disposable-email-domains list or the V3LUM supplement",
                data={"matched": matched["disposable"], "list": lists.origin.get("disposable", "")},
                tags=["weak_signal"],
            )
        if entity.type is T.EMAIL and facts["role_account"] and facts.get("role_source") == "aftership":
            # A4 role/test addresses are already flagged by email_basics; this adds the AfterShip roles
            res.finding(
                "Role account (team mailbox)",
                "info",
                f"The local part '{facts['local_part']}' names a team or function, not a person: context only, never scored as exposure.",
                confidence="probable",
                criterion="local part on the AfterShip email-verifier role list (merged with the A4 generic-address list)",
                tags=["info", "context_only"],
            )
        return res
