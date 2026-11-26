"""Benign, ubiquitous infrastructure that is recorded but not pivoted on (AR06, contract v2 s.18).

Pivoting on ``gmail.com`` or ``8.8.8.8`` explodes an investigation without adding intelligence.
Noise lists come from a built-in core (this file, ``_CORE``) plus data fragments
``v3lum/data/noise/<list>.json`` (schema ``v3lum.noise/1``)::

    {"schema": "v3lum.noise/1", "kind": "sinkhole", "name": "example_sinkholes",
     "source": "https://...", "licence": "CC0-1.0", "domains": [...], "ips": [...], "cidrs": [...]}

Kinds: cdn | cloud | resolver | webmail | hosting | saas | sinkhole | parked | benign_scanner |
warninglist (``v3lum/data/noise/core.json`` documents them; ``private`` is computed for private,
loopback, reserved, multicast and link-local addresses). Only permissive data may be bundled: a
fragment whose licence is copyleft or non-commercial is rejected (A6).

Rules:

* Noise applies only to infrastructure: domains, IPs and bare-host URLs. A URL with a path other
  than '/' or with a query is never noise - a Google Forms phishing URL is investigated (the engine
  tags it ``hosted_on_legit_platform``, see :func:`legit_platform`).
* Domain lists match the host and its parent domains down to the PSL registrable domain, never
  above it: ``evil.github.io`` (a registrable domain under the github.io public suffix) is not
  noise even though ``github.io`` is.
* ``warninglist`` lists are not noise: :func:`warninglists` names the matching lists (bundled
  'warninglist' fragments and runtime lists registered with :func:`register_list`); their values are
  listed but not auto-pivoted and their malicious findings become 'POSSIBLE - on warninglist <name>'.
* Runtime lists are backed by a registered dataset and loaded lazily from the local copy (never
  downloaded here); a missing or unusable dataset means the list is not applied and is reported by
  :func:`errors`, never raised.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum import paths
from v3lum.core import psl
from v3lum.core.datasets import DatasetError, DataStore, check_name
from v3lum.core.entities import Entity, url_host

__all__ = [
    "CDN_KINDS",
    "KINDS",
    "NOISE_SCHEMA",
    "PLATFORM_HOSTS",
    "PRECEDENCE",
    "RUNTIME_FORMATS",
    "NoiseList",
    "errors",
    "is_cdn",
    "is_noise",
    "is_parked",
    "is_public_ip",
    "is_sinkhole",
    "legit_platform",
    "lists",
    "noise_kind",
    "noise_kinds",
    "register_list",
    "reload",
    "unregister_list",
    "warninglists",
]

NOISE_SCHEMA = "v3lum.noise/1"
KINDS_SCHEMA = "v3lum.noise_kinds/1"
KINDS: tuple[str, ...] = ("cdn", "cloud", "resolver", "webmail", "hosting", "saas", "sinkhole", "parked", "benign_scanner", "warninglist")
#: Computed kinds (never listed in fragments).
COMPUTED_KINDS: tuple[str, ...] = ("private",)
#: Kinds ``is_cdn`` covers (shared delivery/cloud/hosting/SaaS infrastructure).
CDN_KINDS = frozenset({"cdn", "cloud", "hosting", "saas"})
#: Order used by ``noise_kind`` when an entity is on several lists (most informative first).
PRECEDENCE: tuple[str, ...] = ("sinkhole", "parked", "benign_scanner", "resolver", "webmail", "cdn", "cloud", "hosting", "saas", "private")
RUNTIME_FORMATS: tuple[str, ...] = ("misp_warninglist", "lines", "cidrs")

_FRAGMENT_KEYS = frozenset({"schema", "kind", "name", "source", "licence", "description", "domains", "ips", "cidrs", "version", "checked_at", "notes"})
_LIST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")
#: Bundling copyleft, share-alike, no-derivatives or non-commercial data is forbidden (A6).
_COPYLEFT_RE = re.compile(
    r"(?<![a-z])(a?gpl|lgpl|by[- ]?sa|by[- ]?nc|nc[- ]?sa|nc[- ]?nd|by[- ]?nd|share[- ]?alike|no[- ]?deriv\w*|"
    r"non[- ]?commercial|odbl|eupl|mpl|cddl|epl|sspl|osl|cecill|unknown|all rights reserved)(?![a-z])",
    re.I,
)
#: The licences that may be bundled (A6): MIT, BSD, Apache-2.0, CC0, CC BY 4.0, public-domain or
#: public data, and the team's own lists. Anything else is a runtime dataset, never a fragment.
_PERMISSIVE_LICENCES = frozenset({
    "mit", "mit license", "bsd", "0bsd", "bsd-2-clause", "bsd-3-clause", "apache-2.0", "apache 2.0", "apache license 2.0",
    "apache license, version 2.0", "cc0", "cc0-1.0", "cc0 1.0", "cc-by-4.0", "cc by 4.0", "public domain", "public data",
    "iana public data", "v3lum", "proprietary-internal",
})


def _licence_problem(licence: str) -> str:
    """Why a fragment licence cannot be bundled ('' when it can, A6)."""
    if _COPYLEFT_RE.search(licence):
        return "copyleft, share-alike, no-derivatives, non-commercial or unknown-terms data is runtime-download only, A6"
    core = " ".join(re.sub(r"\s*\(.*\)\s*$", "", licence).lower().replace("_", "-").split())
    if core not in _PERMISSIVE_LICENCES:
        return "only MIT, BSD, Apache-2.0, CC0, CC BY 4.0 or public data may be bundled (A6): ship it as a runtime dataset"
    return ""

# --------------------------------------------------------------------------------------
# built-in core lists (kinds documented in v3lum/data/noise/core.json)
# --------------------------------------------------------------------------------------

_CORE: dict[str, dict[str, frozenset[str]]] = {
    "webmail": {
        "domains": frozenset({
            "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "icloud.com",
            "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "yandex.ru", "mail.ru", "uol.com.br",
            "bol.com.br", "terra.com.br", "ig.com.br",
        }),
    },
    "resolver": {
        "domains": frozenset({"dns.google", "one.one.one.one", "cloudflare-dns.com", "dns.quad9.net"}),
        "ips": frozenset({
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
            "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:fe::9",
        }),
    },
    "saas": {
        "domains": frozenset({
            "google.com", "microsoft.com", "office365.com", "outlook.office365.com", "protection.outlook.com",
            "facebook.com", "apple.com", "mailchimp.com", "sendgrid.net", "amazonses.com", "mimecast.com", "pphosted.com",
            "zoho.com", "forms.gle", "1drv.ms", "dropbox.com", "notion.site",
        }),
    },
    "cloud": {
        "domains": frozenset({"amazonaws.com", "azure.com", "azurewebsites.net", "windows.net", "googleusercontent.com", "googleapis.com"}),
    },
    "cdn": {
        "domains": frozenset({
            "cloudflare.com", "cloudflare.net", "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net",
            "fastly.net", "cloudfront.net", "fbcdn.net", "gstatic.com",
        }),
    },
    "hosting": {
        "domains": frozenset({
            "awsdns-cn-01.com", "googledomains.com", "domaincontrol.com", "registrar-servers.com", "ns.cloudflare.com",
            "nsone.net", "ultradns.net", "dynect.net", "github.io", "githubusercontent.com", "wordpress.com", "wix.com",
            "wixsite.com", "shopify.com", "squarespace.com", "locaweb.com.br", "hostgator.com.br", "kinghost.net",
            "uolhost.com.br", "blogspot.com", "pages.dev", "web.app", "firebaseapp.com",
        }),
    },
    "parked": {
        "domains": frozenset({"dns-parking.com", "sedoparking.com", "parkingcrew.net", "bodis.com"}),
    },
}
# v1 names (flat views of the core)
_CORE_DOMAINS = frozenset(d for spec in _CORE.values() for d in spec.get("domains", ()))
_CORE_IPS = frozenset(ip for spec in _CORE.values() for ip in spec.get("ips", ()))

#: Legitimate hosting/sharing platforms abused for phishing: pattern -> platform id. A pattern is an
#: exact host (also matched with 'www.'), 'host/path-prefix', or '*.suffix' (strict subdomains).
PLATFORM_HOSTS: dict[str, str] = {
    "docs.google.com/forms": "google_forms",
    "forms.gle": "google_forms",
    "sites.google.com": "google_sites",
    "drive.google.com": "google_drive",
    "onedrive.live.com": "onedrive",
    "1drv.ms": "onedrive",
    "*.sharepoint.com": "sharepoint",
    "dropbox.com": "dropbox",
    "*.github.io": "github_pages",
    "*.pages.dev": "cloudflare_pages",
    "*.web.app": "firebase_hosting",
    "*.firebaseapp.com": "firebase_hosting",
    "*.blogspot.com": "blogger",
    "*.wixsite.com": "wix",
    "*.notion.site": "notion",
}


# --------------------------------------------------------------------------------------
# data structures
# --------------------------------------------------------------------------------------


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


class _NetSet:
    """Merged IPv4/IPv6 ranges with O(log n) containment."""

    def __init__(self, nets: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = ()) -> None:
        v4: list[tuple[int, int]] = []
        v6: list[tuple[int, int]] = []
        for net in nets:
            (v4 if net.version == 4 else v6).append((int(net.network_address), int(net.broadcast_address)))
        self._ranges = {4: _merge(v4), 6: _merge(v6)}
        self._starts = {v: [s for s, _ in r] for v, r in self._ranges.items()}

    def __len__(self) -> int:
        return len(self._ranges[4]) + len(self._ranges[6])

    def contains(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        ranges, starts = self._ranges[ip.version], self._starts[ip.version]
        value = int(ip)
        i = bisect.bisect_right(starts, value) - 1
        return i >= 0 and ranges[i][1] >= value


@dataclass(frozen=True, eq=False)
class NoiseList:
    """One loaded noise list (built-in core kind, bundled fragment, or runtime list)."""

    name: str
    kind: str
    origin: str
    source: str = ""
    licence: str = ""
    description: str = ""
    domains: frozenset[str] = frozenset()
    ips: frozenset[str] = frozenset()
    nets: _NetSet = field(default_factory=_NetSet)

    def matches_domain(self, candidates: list[str]) -> bool:
        return any(c in self.domains for c in candidates)

    def matches_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return ip.compressed in self.ips or self.nets.contains(ip)


@dataclass
class _State:
    lists: tuple[NoiseList, ...]
    errors: tuple[str, ...]
    kinds_doc: dict[str, Any]


_STATE: _State | None = None
_STATE_LOCK = threading.RLock()
_EXTRA_DIRS: tuple[Path, ...] = ()


# --------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------


def _norm_domain(raw: Any) -> str | None:
    text = str(raw or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return text if _DOMAIN_RE.match(text or "-") and "." in text else None


def _fragment_sources() -> list[tuple[str, str, str]]:
    """(origin, stem, text) of every fragment: bundled first, then extra directories (sorted)."""
    out: list[tuple[str, str, str]] = []
    try:
        base = resources.files("v3lum.data").joinpath("noise")
        entries = sorted((e for e in base.iterdir() if e.name.endswith(".json")), key=lambda e: e.name) if base.is_dir() else []
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        entries = []
    for entry in entries:
        try:
            out.append((f"v3lum/data/noise/{entry.name}", entry.name[:-5], entry.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as exc:
            out.append((f"v3lum/data/noise/{entry.name}", entry.name[:-5], f"\x00unreadable: {exc}"))
    for directory in _EXTRA_DIRS:
        for path in sorted(Path(directory).glob("*.json")):
            try:
                out.append((str(path), path.stem, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError) as exc:
                out.append((str(path), path.stem, f"\x00unreadable: {exc}"))
    return out


def _parse_kinds(origin: str, data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    kinds = data.get("kinds")
    if not isinstance(kinds, dict):
        return {}, [f"{origin}: 'kinds' must be an object kind -> description"]
    errs = [f"{origin}: undocumented kind {k!r}" for k in (*KINDS, *COMPUTED_KINDS) if k not in kinds]
    errs += [f"{origin}: unknown kind {k!r}" for k in kinds if k not in KINDS and k not in COMPUTED_KINDS]
    return kinds, errs


def _parse_fragment(origin: str, stem: str, data: dict[str, Any]) -> tuple[NoiseList | None, list[str]]:
    errs: list[str] = []
    unknown = sorted(set(data) - _FRAGMENT_KEYS)
    if unknown:
        errs.append(f"{origin}: unknown keys {unknown}")
    kind = data.get("kind")
    if kind not in KINDS:
        return None, errs + [f"{origin}: kind {kind!r} is not one of {', '.join(KINDS)}"]
    if kind == "warninglist" and not data.get("name"):
        return None, errs + [f"{origin}: warninglist fragments must name their list ('name')"]
    name = str(data.get("name") or stem).strip().lower()
    if not _LIST_NAME_RE.match(name):
        return None, errs + [f"{origin}: invalid list name {name!r}"]
    licence = str(data.get("licence") or "").strip()
    if not licence:
        return None, errs + [f"{origin}: 'licence' is required (only permissive data is bundled, A6)"]
    problem = _licence_problem(licence)
    if problem:
        return None, errs + [f"{origin}: licence {licence!r} cannot be bundled ({problem})"]
    source = str(data.get("source") or "").strip()
    if not source:
        return None, errs + [f"{origin}: 'source' is required"]
    domains: set[str] = set()
    ips: set[str] = set()
    nets: list[Any] = []
    for key in ("domains", "ips", "cidrs"):
        values = data.get(key, [])
        if not isinstance(values, list):
            errs.append(f"{origin}: '{key}' must be a list")
            continue
        for raw in values:
            if key == "domains":
                dom = _norm_domain(raw)
                if dom is None:
                    errs.append(f"{origin}: invalid domain {raw!r}")
                else:
                    domains.add(dom)
                continue
            try:
                if key == "ips":
                    ips.add(ipaddress.ip_address(str(raw).strip()).compressed)
                else:
                    nets.append(ipaddress.ip_network(str(raw).strip(), strict=False))
            except ValueError:
                errs.append(f"{origin}: invalid {key[:-1]} {raw!r}")
    if not (domains or ips or nets):
        return None, errs + [f"{origin}: the list has no valid entries"]
    lst = NoiseList(
        name=name, kind=str(kind), origin=origin, source=source, licence=licence, description=str(data.get("description") or ""),
        domains=frozenset(domains), ips=frozenset(ips), nets=_NetSet(nets),
    )
    return lst, errs


def _load() -> _State:
    lists: list[NoiseList] = [
        NoiseList(
            name=f"core_{kind}", kind=kind, origin="v3lum/core/noise.py", source="V3LUM built-in core", licence="V3LUM",
            domains=spec.get("domains", frozenset()), ips=spec.get("ips", frozenset()),
        )
        for kind, spec in _CORE.items()
    ]
    errors: list[str] = []
    kinds_doc: dict[str, Any] = {}
    names = {lst.name for lst in lists}
    for origin, stem, text in _fragment_sources():
        if text.startswith("\x00unreadable"):
            errors.append(f"{origin}: {text[1:]}")
            continue
        try:
            data = json.loads(text)
        except ValueError as exc:
            errors.append(f"{origin}: invalid JSON ({exc})")
            continue
        if not isinstance(data, dict):
            errors.append(f"{origin}: a fragment must be a JSON object")
            continue
        schema = data.get("schema")
        if schema == KINDS_SCHEMA:
            kinds_doc, errs = _parse_kinds(origin, data)
            errors.extend(errs)
            continue
        if schema != NOISE_SCHEMA:
            errors.append(f"{origin}: schema must be {NOISE_SCHEMA!r} (got {schema!r})")
            continue
        lst, errs = _parse_fragment(origin, stem, data)
        errors.extend(errs)
        if lst is None:
            continue
        if lst.name in names:
            errors.append(f"{origin}: duplicate list name {lst.name!r}")
            continue
        names.add(lst.name)
        lists.append(lst)
    return _State(tuple(lists), tuple(errors), kinds_doc)


def _state() -> _State:
    global _STATE
    with _STATE_LOCK:
        if _STATE is None:
            _STATE = _load()
        return _STATE


def reload(extra_dirs: Iterable[str | Path] | None = None) -> None:
    """Drop the loaded lists (and runtime list data); ``extra_dirs`` adds fragment directories
    (tests and plugins; ``()`` removes them)."""
    global _STATE, _EXTRA_DIRS
    with _STATE_LOCK:
        if extra_dirs is not None:
            _EXTRA_DIRS = tuple(Path(d) for d in extra_dirs)
        _STATE = None
        for rl in list(_RUNTIME.values()):
            rl.reset()


def lists() -> list[NoiseList]:
    """Every loaded built-in and bundled list (runtime lists excluded)."""
    return list(_state().lists)


def kinds_doc() -> dict[str, Any]:
    """The kinds documentation of ``v3lum/data/noise/core.json``."""
    return dict(_state().kinds_doc)


# --------------------------------------------------------------------------------------
# runtime lists (dataset-backed)
# --------------------------------------------------------------------------------------


@dataclass
class _Loaded:
    strings: Any = None  # DatasetIndex/frozenset of full values (and hosts)
    hosts: Any = None  # DatasetIndex/frozenset matched against host candidates
    nets: _NetSet | None = None
    substrings: tuple[str, ...] = ()


class _RuntimeList:
    def __init__(self, name: str, kind: str, dataset: str, fmt: str, description: str) -> None:
        self.name = name
        self.kind = kind
        self.dataset = dataset
        self.fmt = fmt
        self.description = description
        self.error = ""
        self._loaded: _Loaded | None = None
        self._mtime: int | None = None
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._loaded, self._mtime, self.error = None, None, ""

    def load(self) -> _Loaded | None:
        path = paths.datasets_dir() / self.dataset
        with self._lock:
            try:
                mtime = path.stat().st_mtime_ns
            except OSError:
                self._loaded, self._mtime = None, None
                self.error = f"noise list {self.name}: dataset {self.dataset} not downloaded (run v3lum data update {self.dataset}); list not applied"
                return None
            if self._mtime == mtime:
                return self._loaded
            self._mtime = mtime
            try:
                self._loaded = self._read()
                self.error = ""
            except (DatasetError, ValueError, OSError, KeyError, TypeError) as exc:
                self._loaded = None
                self.error = f"noise list {self.name}: dataset {self.dataset} unusable ({exc}); list not applied"
            return self._loaded

    def _read(self) -> _Loaded:
        store = DataStore(None)  # local copies only: never a download from here
        if self.fmt == "lines":
            return _Loaded(strings=store.index(self.dataset, fmt="lines"))
        if self.fmt == "cidrs":
            return _Loaded(nets=_nets(store.fetch_lines(self.dataset)))
        doc = store.fetch_json(self.dataset)
        if not isinstance(doc, dict) or not isinstance(doc.get("list"), list):
            raise ValueError("not a MISP warninglist (no 'list' array)")
        wtype = str(doc.get("type") or "string").lower()
        if wtype == "cidr":
            return _Loaded(nets=_nets(doc["list"]))
        if wtype == "hostname":
            return _Loaded(hosts=store.index(self.dataset, column="list", fmt="json"))
        if wtype == "string":
            return _Loaded(strings=store.index(self.dataset, column="list", fmt="json"))
        if wtype == "substring":
            return _Loaded(substrings=tuple(str(v).strip().lower() for v in doc["list"][:10000] if str(v).strip()))
        raise ValueError(f"unsupported MISP warninglist type {wtype!r}")

    def matches(self, value: str, target: tuple[str, Any] | None) -> bool:
        loaded = self.load()
        if loaded is None:
            return False
        if loaded.strings is not None and (value in loaded.strings or (target is not None and target[0] == "domain" and any(c in loaded.strings for c in _candidates(target[1])))):
            return True
        if loaded.hosts is not None and target is not None and target[0] == "domain" and any(c in loaded.hosts for c in _candidates(target[1])):
            return True
        if loaded.nets is not None and target is not None and target[0] == "ip" and loaded.nets.contains(target[1]):
            return True
        return bool(loaded.substrings) and any(s in value for s in loaded.substrings)


def _nets(values: Iterable[Any]) -> _NetSet:
    nets = []
    for raw in values:
        try:
            nets.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            continue
    return _NetSet(nets)


_RUNTIME: dict[str, _RuntimeList] = {}
_RUNTIME_LOCK = threading.Lock()


def register_list(name: str, *, kind: str = "warninglist", dataset: str, fmt: str = "misp_warninglist", description: str = "") -> str:
    """Register a runtime noise/warning list backed by a registered dataset (call at import time
    in the module file that registers the dataset). Returns ``name``.

    ``fmt``: 'misp_warninglist' (MISP JSON: types cidr, hostname, string, substring), 'lines' (one
    value per line) or 'cidrs' (one network per line). The list is loaded lazily from the local
    copy; while the dataset is missing it is not applied and ``errors()`` says so.
    """
    if not isinstance(name, str) or not _LIST_NAME_RE.match(name):
        raise ValueError(f"invalid noise list name {name!r} (lower case letters, digits, '.', '_', '-')")
    if kind not in KINDS:
        raise ValueError(f"noise list {name}: kind must be one of {', '.join(KINDS)}")
    if fmt not in RUNTIME_FORMATS:
        raise ValueError(f"noise list {name}: fmt must be one of {', '.join(RUNTIME_FORMATS)}")
    check_name(dataset)
    with _RUNTIME_LOCK:
        old = _RUNTIME.get(name)
        if old is not None:
            if (old.kind, old.dataset, old.fmt) != (kind, dataset, fmt):
                raise ValueError(f"noise list {name!r} is already registered for dataset {old.dataset!r}")
            return name
        _RUNTIME[name] = _RuntimeList(name, kind, dataset, fmt, description)
    return name


def unregister_list(name: str) -> bool:
    """Remove a runtime list (tests and plugins)."""
    with _RUNTIME_LOCK:
        return _RUNTIME.pop(name, None) is not None


def errors() -> list[str]:
    """Malformed fragments and runtime lists that cannot be applied (missing/unusable datasets)."""
    state = _state()
    out = list(state.errors)
    bundled = {lst.name for lst in state.lists}
    for rl in list(_RUNTIME.values()):
        if rl.name in bundled:
            out.append(f"noise list {rl.name!r}: runtime list name clashes with a bundled list")
        rl.load()
        if rl.error:
            out.append(rl.error)
    return out


# --------------------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------------------


def _etype(entity: Any) -> str:
    etype = getattr(entity, "type", "")
    return str(getattr(etype, "value", etype))


def _is_bare_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.path in ("", "/") and not parts.query


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None


def _target(entity: Any) -> tuple[str, Any] | None:
    """('domain', host) or ('ip', address) for the infrastructure entities noise applies to."""
    etype, value = _etype(entity), str(getattr(entity, "value", "") or "")
    if etype == "domain":
        return ("domain", value.lower().rstrip("."))
    if etype in ("ipv4", "ipv6"):
        ip = _ip(value)
        return ("ip", ip) if ip is not None else None
    if etype == "url":
        if not _is_bare_url(value):
            return None  # a URL with a path or query is investigated, never noise
        host = url_host(value)
        ip = _ip(host)
        if ip is not None:
            return ("ip", ip)
        return ("domain", host) if host else None
    return None


def _candidates(host: str) -> list[str]:
    """The host and its parents down to the PSL registrable domain (never above it)."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return []
    reg = psl.registrable_domain(host)
    if not reg:
        return [host]
    labels = host.split(".")
    keep = reg.count(".") + 1
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - keep + 1))]


def _private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local


def noise_kinds(entity: Entity) -> frozenset[str]:
    """Every noise kind the entity matches (empty when it is not noise)."""
    target = _target(entity)
    if target is None:
        return frozenset()
    found: set[str] = set()
    state = _state()
    if target[0] == "domain":
        candidates = _candidates(target[1])
        for lst in state.lists:
            if lst.kind != "warninglist" and lst.matches_domain(candidates):
                found.add(lst.kind)
    else:
        ip = target[1]
        if _private(ip):
            found.add("private")
        for lst in state.lists:
            if lst.kind != "warninglist" and lst.matches_ip(ip):
                found.add(lst.kind)
    value = str(getattr(entity, "value", "")).strip().lower()
    for rl in list(_RUNTIME.values()):
        if rl.kind != "warninglist" and rl.kind not in found and rl.matches(value, target):
            found.add(rl.kind)
    return frozenset(found)


def is_noise(entity: Entity) -> bool:
    """True for benign ubiquitous infrastructure (domains, IPs and bare-host URLs only)."""
    return bool(noise_kinds(entity))


def noise_kind(entity: Entity) -> str | None:
    """The most informative noise kind of the entity (see ``PRECEDENCE``), or None."""
    found = noise_kinds(entity)
    return next((k for k in PRECEDENCE if k in found), None)


def is_sinkhole(entity: Entity) -> bool:
    return "sinkhole" in noise_kinds(entity)


def is_parked(entity: Entity) -> bool:
    return "parked" in noise_kinds(entity)


def is_cdn(entity: Entity) -> bool:
    """CDN, cloud, hosting or SaaS infrastructure (``CDN_KINDS``)."""
    return bool(noise_kinds(entity) & CDN_KINDS)


def warninglists(entity: Entity) -> list[str]:
    """Names of the warninglists the entity is on (bundled 'warninglist' fragments and runtime
    lists of kind 'warninglist'). Host matching follows the noise rules (bare-host URLs only);
    string lists also match the full value (a URL with a path, an e-mail, a hash...)."""
    target = _target(entity)
    value = str(getattr(entity, "value", "")).strip().lower()
    names: list[str] = []
    for lst in _state().lists:
        if lst.kind != "warninglist" or target is None:
            continue
        hit = lst.matches_domain(_candidates(target[1])) if target[0] == "domain" else lst.matches_ip(target[1])
        if hit:
            names.append(lst.name)
    for rl in list(_RUNTIME.values()):
        if rl.kind == "warninglist" and rl.name not in names and rl.matches(value, target):
            names.append(rl.name)
    return names


def legit_platform(url: Any) -> str | None:
    """Platform id when ``url`` (a URL/domain string or Entity) is on a legitimate hosting or
    sharing platform from ``PLATFORM_HOSTS`` (e.g. 'google_forms'), else None."""
    if isinstance(url, Entity) or hasattr(url, "type"):
        etype, value = _etype(url), str(getattr(url, "value", ""))
        if etype == "domain":
            value = f"https://{value}/"
        elif etype != "url":
            return None
    else:
        value = str(url or "").strip()
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    path = parts.path or "/"
    if not host:
        return None
    for pattern, platform in PLATFORM_HOSTS.items():
        phost, _, ppath = pattern.partition("/")
        if phost.startswith("*."):
            if not (host.endswith(phost[1:]) and host != phost[2:]):
                continue
        elif host not in (phost, "www." + phost):
            continue
        if ppath:
            prefix = "/" + ppath.strip("/")
            if not (path == prefix or path.startswith(prefix + "/")):
                continue
        return platform
    return None


def is_public_ip(value: str) -> bool:
    """True for globally routable addresses."""
    ip = _ip(value)
    return bool(ip is not None and ip.is_global)
