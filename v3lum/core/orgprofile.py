"""Organisation profile: own domains, brands, CNPJ roots, card BINs, ASNs/CIDRs, app ids, favicon
hashes, suppliers and opt-in executives (P378 conditions 1-4 and 6, A11).

The profile is local configuration: a TOML file (``tomllib``) or JSON at setting
``org_profile_path`` (default ``~/.v3lum/org_profile.toml``, then ``org_profile.json``; a
team-maintained read-only path is allowed). It is sensitive (asset inventory, executive names):
keep it 0600, it is never exported or sent anywhere - reports and exports carry only
own_asset/third_party tags and the profile SHA-256. Problems are collected in ``errors`` and never
raised at scan time; invalid entries are dropped or downgraded (fail closed: an entry whose
verification cannot be trusted is never "verified"). The file mode is checked: group/world access
to the personal copy, or world access to a team path, is reported; a world-writable profile also
downgrades its txt_verified/attested entries to confirmed (anyone could have written them).

Schema (TOML; the JSON form has the same keys)::

    [org]
    name = "ACME S.A."                 # a top-level name = "..." (handy in JSON) is accepted too

    # plain lists may also live under [org]; at top level they must come before the first table
    cnpj_roots = ["12345678"]          # 8-character CNPJ roots (punctuation ignored)
    card_bins = ["412345", "51234567"] # the organisation's own BIN prefixes (6-8 digits, never a PAN)
    favicon_hashes = ["-1234567890"]   # mmh3 favicon hashes

    [[domains]]
    name = "acme.com.br"                  # IDN allowed (stored as punycode); never a public suffix
    verification = "txt_verified"         # seeded | confirmed | txt_verified | attested
    attested_by = ""                      # attested: analyst name (or attested = {by = "...", date = ...})
    attested_date = ""                    # attested: YYYY-MM-DD
    criticality = "high"                  # critical | high | medium | low (default medium)
    third_party_hosted = false            # CDN/cloud/SaaS front door: never an ACTIVE target by default
    note = ""

    [[brands]]
    keyword = "acme"
    variants = ["acmé", "acrne"]          # accent-folded / IDN / homoglyph variants to watch
    criticality = "high"

    [[asns]]                              # or asns = ["AS64500"]
    value = "AS64500"
    criticality = "medium"
    third_party_hosted = false

    [[cidrs]]                             # or cidrs = ["203.0.113.0/24"]
    value = "203.0.113.0/24"
    criticality = "high"
    third_party_hosted = false

    [[app_ids]]
    kind = "m365_tenant"
    value = "00000000-0000-0000-0000-000000000000"

    [[suppliers]]
    name = "Supplier Ltd"
    domains = ["supplier.example"]
    brands = ["supplierbrand"]

    [[executives]]                        # explicit opt-in only, informed under the VIP programme
    name = "..."
    opt_in = true
    programme = "VIP protection"
    informed_at = "2026-11-01"

Membership (``OrgProfile.owns``) uses the PSL registrable domain plus a label-wise subdomain match
(``evilacme.com`` is never ``acme.com``; IDN compared as punycode) and ``ipaddress`` containment;
ASNs, favicon hashes compare equal, CNPJs by their 8-character root and card BINs by prefix. Only
``txt_verified`` and ``attested`` domain entries are verified: ``seeded`` and ``confirmed`` entries
never unlock own-asset-only or per-person breach modules (A4/A11).

v2 (WP18, P378 cond 1/5/8/11): :func:`validate` / :func:`validate_text` are the strict schema check
behind ``v3lum org check`` (every problem with its field path and file line; the lenient loader above
stays as it is for scans); :func:`save` writes the profile 0600 (TOML or JSON, validated first, never
an invalid document); :func:`txt_token` / :func:`txt_record` / :func:`verify_txt` implement the DNS
proof of control (``TXT "v3lum-verify=<hmac12('domain', domain)>"`` at the domain, read through the
core resolver: True / False / None = could not verify, never "absent"); :meth:`OrgProfile.mark_attested`
and :meth:`OrgProfile.mark_txt_verified` record the two verified states and ``add_domain`` /
``add_network`` / ``add_cnpj_root`` / ``add_app_id`` add analyst-confirmed entries (``v3lum org seed``).
Nothing here sends the profile anywhere; the ``v3lum org`` commands write every change to the audit
trail.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core import psl
from v3lum.core.entities import Entity, normalize_domain, url_host

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10: JSON profiles only
    _toml = None

__all__ = [
    "CRITICALITIES",
    "NOT_OWNED",
    "TXT_PREFIX",
    "VERIFICATIONS",
    "VERIFIED",
    "AppId",
    "BrandEntry",
    "DomainEntry",
    "ExecutiveEntry",
    "NetEntry",
    "OrgProfile",
    "Ownership",
    "ProfileProblem",
    "SupplierEntry",
    "default_path",
    "fold",
    "load_default",
    "mark_attested",
    "save",
    "txt_record",
    "txt_token",
    "validate",
    "validate_text",
    "verify_txt",
]

VERIFICATIONS: tuple[str, ...] = ("seeded", "confirmed", "txt_verified", "attested")
#: Verification states that count as verified own assets (A4/A11).
VERIFIED = frozenset({"txt_verified", "attested"})
CRITICALITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
DEFAULT_CRITICALITY = "medium"

_LIST_KEYS = ("domains", "brands", "cnpj_roots", "card_bins", "asns", "cidrs", "app_ids", "favicon_hashes", "suppliers", "executives")
_TOP_KEYS = frozenset({"org", "schema", "version", "name", *_LIST_KEYS})  # top-level 'name' = [org] name
_ORG_KEYS = frozenset({"name", "note", *_LIST_KEYS})
_DOMAIN_KEYS = frozenset({"name", "domain", "verification", "attested_by", "attested_date", "attested", "criticality", "third_party_hosted", "note"})
_BRAND_KEYS = frozenset({"keyword", "name", "variants", "criticality"})
_NET_KEYS = frozenset({"value", "criticality", "third_party_hosted", "note"})
_APP_KEYS = frozenset({"kind", "value", "note"})
_SUPPLIER_KEYS = frozenset({"name", "domains", "brands", "note"})
_EXEC_KEYS = frozenset({"name", "opt_in", "programme", "informed_at"})
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# --------------------------------------------------------------------------------------
# entries
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DomainEntry:
    name: str
    verification: str = "seeded"
    attested_by: str = ""
    attested_date: str = ""
    criticality: str = DEFAULT_CRITICALITY
    third_party_hosted: bool = False
    note: str = ""

    @property
    def verified(self) -> bool:
        """txt_verified or attested (seeded/confirmed are not verified)."""
        return self.verification in VERIFIED


@dataclass(frozen=True)
class BrandEntry:
    keyword: str
    variants: tuple[str, ...] = ()
    criticality: str = DEFAULT_CRITICALITY


@dataclass(frozen=True)
class NetEntry:
    """An own ASN ('AS64500') or network ('203.0.113.0/24')."""

    value: str
    criticality: str = DEFAULT_CRITICALITY
    third_party_hosted: bool = False
    note: str = ""


@dataclass(frozen=True)
class AppId:
    kind: str
    value: str
    note: str = ""


@dataclass(frozen=True)
class SupplierEntry:
    name: str
    domains: tuple[str, ...] = ()
    brands: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class ExecutiveEntry:
    name: str
    opt_in: bool = False
    programme: str = ""
    informed_at: str = ""


@dataclass(frozen=True)
class Ownership:
    """Result of ``OrgProfile.owns``.

    ``kind``: 'domain' | 'cidr' | 'asn' | 'cnpj_root' | 'favicon_hash' | 'card_bin' for own assets,
    'supplier' for supplier domains (own=False), '' when unrelated. ``verified`` is True only for
    txt_verified/attested domain entries (network, ASN, CNPJ and other matches are own but unverified).
    """

    own: bool = False
    verified: bool = False
    kind: str = ""
    entry: Any = None
    criticality: str = ""
    third_party_hosted: bool = False

    @property
    def tag(self) -> str:
        return "own_asset" if self.own else "third_party"


NOT_OWNED = Ownership()


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def fold(text: Any) -> str:
    """Accent-folded, lower-case, whitespace-collapsed form ('Açúcar  União' -> 'acucar uniao')."""
    decomposed = unicodedata.normalize("NFKD", str(text or ""))
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return " ".join(stripped.lower().split())


def _host(value: str) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return text


def _bool(value: Any, where: str, errors: list[str]) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    errors.append(f"{where}: expected true/false")
    return False


def _criticality(value: Any, where: str, errors: list[str]) -> str:
    if value in (None, ""):
        return DEFAULT_CRITICALITY
    text = str(value).strip().lower()
    if text not in CRITICALITIES:
        errors.append(f"{where}: criticality must be one of {', '.join(CRITICALITIES)} (using medium)")
        return DEFAULT_CRITICALITY
    return text


def _date(value: Any) -> str:
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.strftime("%Y-%m-%d")
    text = str(value or "").strip()
    if not _DATE_RE.match(text):
        return ""
    try:
        _dt.date.fromisoformat(text)
    except ValueError:
        return ""
    return text


def _access_problem(path: Path) -> tuple[str, bool]:
    """(problem, world_writable) for the profile file mode (P378 cond 1: 0600, sensitive inventory).

    World-writable files are always a problem (and fail closed); other group/world access is
    reported for the analyst's own copy in the V3LUM home and, for a team-maintained path elsewhere,
    when the file is world-readable.
    """
    if os.name != "posix":  # pragma: no cover - POSIX modes only
        return "", False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return "", False
    world_writable = bool(mode & 0o002)
    try:
        in_home = path.resolve().is_relative_to(paths.home().resolve())
    except (OSError, ValueError):
        in_home = False
    if world_writable:
        return f"the org profile is writable by other users (mode {mode:04o}): chmod 600 (A11)", True
    if (in_home and mode & 0o077) or mode & 0o004:
        return f"the org profile is accessible to other users (mode {mode:04o}): it is a sensitive asset inventory, chmod 600 (A11)", False
    return "", False


def _unknown(item: dict[str, Any], allowed: frozenset[str], where: str, errors: list[str]) -> None:
    extra = sorted(set(item) - allowed)
    if extra:
        errors.append(f"{where}: unknown keys {extra}")


def _domain(value: Any) -> str | None:
    """Normalised (punycode) domain, None when invalid or a public suffix."""
    try:
        dom = normalize_domain(str(value or ""))
    except ValueError:
        return None
    return dom if psl.registrable_domain(dom) else None


def _asn(value: Any) -> str | None:
    m = re.match(r"^(?:as|asn)?\s*(\d{1,10})$", str(value).strip(), flags=re.I)
    if not m or int(m.group(1)) > 4294967295:
        return None
    return f"AS{int(m.group(1))}"


_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
#: Own networks broader than these prefixes are refused by the strict check and by
#: ``OrgProfile.add_network`` (a typo such as 0.0.0.0/0 would make every address an own asset).
_MIN_OWN_PREFIX = {4: 8, 6: 19}


def _require_domain(value: Any) -> str:
    """The normalised (punycode) registrable domain or subdomain; ValueError otherwise."""
    name = _domain(value)
    if name is None:
        raise ValueError(f"{str(value)[:80]!r} is not a valid registrable domain (public suffixes are refused)")
    return name


def _cidr_problem(value: Any) -> str:
    """'' when ``value`` is a valid own network, else why not (malformed, host bits set, too broad)."""
    text = str(value if value is not None else "").strip()
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError:
        try:
            loose = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return f"{text[:60]!r} is not a valid network (CIDR)"
        return f"{text[:60]!r} has host bits set: did you mean {loose}?"
    if net.prefixlen < _MIN_OWN_PREFIX[net.version]:
        return f"{net} is too broad for an own network (at most /{_MIN_OWN_PREFIX[net.version]} for IPv{net.version})"
    return ""


def _entity(entity: Any) -> Entity | None:
    if isinstance(entity, Entity):
        return entity
    if isinstance(entity, str) and ":" in entity:
        etype, _, value = entity.partition(":")
        return Entity.try_make(etype, value)
    if hasattr(entity, "type") and hasattr(entity, "value"):
        return entity  # duck-typed entity (e.g. a graph node key object)
    return None


def _items(data: dict[str, Any], org: dict[str, Any], key: str, errors: list[str]) -> list[Any]:
    out: list[Any] = []
    for origin, container in (("", data), ("org.", org)):
        value = container.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            errors.append(f"{origin}{key}: must be a list")
            continue
        out.extend(value)
    return out


# --------------------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------------------


@dataclass
class OrgProfile:
    """The loaded organisation profile (see the module docstring for the file schema)."""

    path: str = ""
    sha256: str = ""
    name: str = ""
    domains: list[DomainEntry] = field(default_factory=list)
    brands: list[BrandEntry] = field(default_factory=list)
    cnpj_roots: list[str] = field(default_factory=list)
    card_bins: list[str] = field(default_factory=list)
    asns: list[NetEntry] = field(default_factory=list)
    cidrs: list[NetEntry] = field(default_factory=list)
    app_ids: list[AppId] = field(default_factory=list)
    favicon_hashes: list[str] = field(default_factory=list)
    suppliers: list[SupplierEntry] = field(default_factory=list)
    executives: list[ExecutiveEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: ``[org] note`` (free text kept when v3lum rewrites the file)
    note: str = ""
    #: top-level ``schema`` / ``version`` values of the file (kept when v3lum rewrites it)
    meta: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:  # never dump the inventory (or executive names) into logs
        counts = ", ".join(f"{k}={v}" for k, v in self.counts().items() if v)
        return f"OrgProfile(path={self.path!r}, sha256={self.sha256[:12]!r}, {counts or 'empty'}, errors={len(self.errors)})"

    # ---- construction ------------------------------------------------------------------------
    @classmethod
    def empty(cls, path: str = "") -> OrgProfile:
        """A profile without entries (no profile configured)."""
        return cls(path=str(path))

    @classmethod
    def load(cls, path: str | Path) -> OrgProfile:
        """Load a TOML (default) or JSON (``.json``) profile; a missing file gives ``empty()``.

        Read and parse problems end up in ``errors`` (never raised).
        """
        p = Path(path).expanduser()
        if not p.is_file():
            return cls.empty(str(p))
        try:
            raw = p.read_bytes()
        except OSError as exc:
            prof = cls.empty(str(p))
            prof.errors.append(f"cannot read the org profile: {exc}")
            return prof
        access, world_writable = _access_problem(p)
        sha = hashlib.sha256(raw).hexdigest()
        suffix = p.suffix.lower()
        data: Any = None
        problem = ""
        try:
            text = raw.decode("utf-8-sig")
            if suffix == ".json":
                data = json.loads(text)
            elif suffix in (".yaml", ".yml"):
                try:
                    import yaml  # optional extra, safe_load only
                except ImportError:
                    problem = "YAML profiles need the optional extra (pip install 'v3lum[yaml]'): use TOML or JSON"
                else:
                    data = yaml.safe_load(text)
            elif _toml is None:  # pragma: no cover - Python 3.10
                problem = "TOML profiles need Python 3.11+ (tomllib): use an org_profile.json"
            else:
                data = _toml.loads(text)
        except UnicodeDecodeError as exc:
            problem = f"the org profile is not UTF-8 text ({exc.reason})"
        except ValueError as exc:  # json.JSONDecodeError and tomllib.TOMLDecodeError are ValueErrors
            problem = f"invalid {'JSON' if suffix == '.json' else 'TOML'} in the org profile: {exc}"
        except Exception as exc:  # noqa: BLE001 - yaml errors and friends: never raised at scan time
            problem = f"cannot parse the org profile: {exc}"
        if problem:
            prof = cls(path=str(p), sha256=sha)
            prof.errors.extend([problem] + ([access] if access else []))
            return prof
        prof = cls.from_dict(data, path=str(p), sha256=sha)
        if access:
            prof.errors.append(access)
        if world_writable and any(d.verified for d in prof.domains):
            # anyone on this machine could have marked a domain verified: fail closed (A4/A11)
            prof.domains = [replace(d, verification="confirmed", attested_by="", attested_date="") if d.verified else d for d in prof.domains]
            prof.errors.append("txt_verified/attested entries are treated as confirmed while the profile is writable by other users")
        return prof

    @classmethod
    def from_dict(cls, data: Any, *, path: str = "", sha256: str = "") -> OrgProfile:
        """Validate a parsed profile; invalid entries are dropped or downgraded with an error."""
        errors: list[str] = []
        if data is None:
            data = {}
        if not isinstance(data, dict):
            prof = cls(path=path, sha256=sha256)
            prof.errors.append("the org profile must be a table/object")
            return prof
        if not sha256:
            sha256 = hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        _unknown(data, _TOP_KEYS, "org profile", errors)
        org = data.get("org") or {}
        if not isinstance(org, dict):
            errors.append("org: must be a table")
            org = {}
        _unknown(org, _ORG_KEYS, "org", errors)
        prof = cls(path=path, sha256=sha256, name=str(org.get("name") or data.get("name") or "").strip())
        prof.note = str(org.get("note") or "").strip() if isinstance(org.get("note"), str) else ""
        prof.meta = {k: data[k] for k in ("schema", "version") if isinstance(data.get(k), (str, int)) and not isinstance(data.get(k), bool)}
        prof._parse_domains(_items(data, org, "domains", errors), errors)
        prof._parse_brands(_items(data, org, "brands", errors), errors)
        prof._parse_simple(data, org, errors)
        prof._parse_nets(_items(data, org, "asns", errors), "asns", errors)
        prof._parse_nets(_items(data, org, "cidrs", errors), "cidrs", errors)
        prof._parse_apps(_items(data, org, "app_ids", errors), errors)
        prof._parse_suppliers(_items(data, org, "suppliers", errors), errors)
        prof._parse_executives(_items(data, org, "executives", errors), errors)
        prof.errors = errors
        return prof

    def _parse_domains(self, items: list[Any], errors: list[str]) -> None:
        seen: set[str] = set()
        for i, item in enumerate(items):
            where = f"domains[{i}]"
            if isinstance(item, str):
                item = {"name": item}
            if not isinstance(item, dict):
                errors.append(f"{where}: must be a domain name or a table")
                continue
            _unknown(item, _DOMAIN_KEYS, where, errors)
            raw = item.get("name") or item.get("domain")
            name = _domain(raw)
            if name is None:
                errors.append(f"{where}: {str(raw)[:80]!r} is not a valid registrable domain (public suffixes are refused)")
                continue
            if name in seen:
                errors.append(f"{where}: duplicate domain {name} (first entry kept)")
                continue
            seen.add(name)
            verification = str(item.get("verification") or "seeded").strip().lower()
            if verification not in VERIFICATIONS:
                errors.append(f"{where}: verification must be one of {', '.join(VERIFICATIONS)} (treated as seeded)")
                verification = "seeded"
            attested = item.get("attested") if isinstance(item.get("attested"), dict) else {}
            by = str(item.get("attested_by") or attested.get("by") or "").strip()
            date = _date(item.get("attested_date") or attested.get("date"))
            if verification == "attested" and not (by and date):
                errors.append(f"{where}: attested entries need attested_by and attested_date (YYYY-MM-DD); treated as confirmed")
                verification = "confirmed"
            self.domains.append(
                DomainEntry(
                    name=name,
                    verification=verification,
                    attested_by=by if verification == "attested" else "",
                    attested_date=date if verification == "attested" else "",
                    criticality=_criticality(item.get("criticality"), where, errors),
                    third_party_hosted=_bool(item.get("third_party_hosted"), f"{where}.third_party_hosted", errors),
                    note=str(item.get("note") or ""),
                )
            )

    def _parse_brands(self, items: list[Any], errors: list[str]) -> None:
        for i, item in enumerate(items):
            where = f"brands[{i}]"
            if isinstance(item, str):
                item = {"keyword": item}
            if not isinstance(item, dict):
                errors.append(f"{where}: must be a keyword or a table")
                continue
            _unknown(item, _BRAND_KEYS, where, errors)
            keyword = str(item.get("keyword") or item.get("name") or "").strip()
            if not keyword:
                errors.append(f"{where}: keyword is required")
                continue
            variants = item.get("variants") or []
            if not isinstance(variants, list):
                errors.append(f"{where}.variants: must be a list")
                variants = []
            self.brands.append(
                BrandEntry(keyword, tuple(str(v).strip() for v in variants if str(v).strip()), _criticality(item.get("criticality"), where, errors))
            )

    def _parse_simple(self, data: dict[str, Any], org: dict[str, Any], errors: list[str]) -> None:
        for i, raw in enumerate(_items(data, org, "cnpj_roots", errors)):
            root = re.sub(r"[^0-9A-Za-z]", "", str(raw)).upper()
            if len(root) == 14:
                errors.append(f"cnpj_roots[{i}]: a full CNPJ was given; only its 8-character root is kept")
                root = root[:8]
            if len(root) != 8:
                errors.append(f"cnpj_roots[{i}]: a CNPJ root has 8 characters")
                continue
            if root not in self.cnpj_roots:
                self.cnpj_roots.append(root)
        for i, raw in enumerate(_items(data, org, "card_bins", errors)):
            digits = re.sub(r"[\s-]", "", str(raw))
            if not digits.isdigit() or not 6 <= len(digits) <= 8:
                # never echo the value: it may be a full card number
                errors.append(f"card_bins[{i}]: a BIN prefix has 6-8 digits (entry dropped; never store full card numbers)")
                continue
            if digits not in self.card_bins:
                self.card_bins.append(digits)
        for i, raw in enumerate(_items(data, org, "favicon_hashes", errors)):
            text = str(raw).strip()
            if not re.match(r"^-?\d{1,11}$", text):
                errors.append(f"favicon_hashes[{i}]: an mmh3 favicon hash is an integer")
                continue
            value = str(int(text))
            if value not in self.favicon_hashes:
                self.favicon_hashes.append(value)

    def _parse_nets(self, items: list[Any], key: str, errors: list[str]) -> None:
        target = self.asns if key == "asns" else self.cidrs
        for i, item in enumerate(items):
            where = f"{key}[{i}]"
            if not isinstance(item, dict):
                item = {"value": item}
            _unknown(item, _NET_KEYS, where, errors)
            raw = item.get("value")
            if key == "asns":
                value = _asn(raw) if raw is not None else None
            else:
                try:
                    value = str(ipaddress.ip_network(str(raw).strip(), strict=False))
                except ValueError:
                    value = None
            if value is None:
                errors.append(f"{where}: {str(raw)[:60]!r} is not a valid {'ASN' if key == 'asns' else 'network'}")
                continue
            if any(e.value == value for e in target):
                continue
            target.append(
                NetEntry(
                    value,
                    _criticality(item.get("criticality"), where, errors),
                    _bool(item.get("third_party_hosted"), f"{where}.third_party_hosted", errors),
                    str(item.get("note") or "") if isinstance(item.get("note"), str) else "",
                )
            )

    def _parse_apps(self, items: list[Any], errors: list[str]) -> None:
        for i, item in enumerate(items):
            where = f"app_ids[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{where}: must be a table with kind and value")
                continue
            _unknown(item, _APP_KEYS, where, errors)
            kind, value = str(item.get("kind") or "").strip(), str(item.get("value") or "").strip()
            if not kind or not value:
                errors.append(f"{where}: kind and value are required")
                continue
            self.app_ids.append(AppId(kind, value, str(item.get("note") or "") if isinstance(item.get("note"), str) else ""))

    def _parse_suppliers(self, items: list[Any], errors: list[str]) -> None:
        for i, item in enumerate(items):
            where = f"suppliers[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{where}: must be a table")
                continue
            _unknown(item, _SUPPLIER_KEYS, where, errors)
            name = str(item.get("name") or "").strip()
            if not name:
                errors.append(f"{where}: name is required")
                continue
            domains = []
            for j, raw in enumerate(item.get("domains") or []):
                dom = _domain(raw)
                if dom is None:
                    errors.append(f"{where}.domains[{j}]: not a valid registrable domain")
                elif dom not in domains:
                    domains.append(dom)
            brands = tuple(str(b).strip() for b in (item.get("brands") or []) if str(b).strip())
            note = str(item.get("note") or "") if isinstance(item.get("note"), str) else ""
            self.suppliers.append(SupplierEntry(name, tuple(domains), brands, note))

    def _parse_executives(self, items: list[Any], errors: list[str]) -> None:
        for i, item in enumerate(items):
            where = f"executives[{i}]"  # never echo the person's name in messages
            if not isinstance(item, dict):
                errors.append(f"{where}: must be a table")
                continue
            _unknown(item, _EXEC_KEYS, where, errors)
            name = str(item.get("name") or "").strip()
            informed = _date(item.get("informed_at"))
            if not name:
                errors.append(f"{where}: name is required (entry dropped)")
                continue
            if item.get("opt_in") is not True:
                errors.append(f"{where}: dropped - executives are listed only with explicit opt_in = true")
                continue
            if not informed:
                errors.append(f"{where}: dropped - informed_at (YYYY-MM-DD, VIP-protection notice) is required")
                continue
            self.executives.append(ExecutiveEntry(name, True, str(item.get("programme") or "").strip(), informed))

    # ---- views -------------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """The profile in its file schema (JSON-serialisable; ``from_dict`` round-trips it)."""

        def dom(e: DomainEntry) -> dict[str, Any]:
            out: dict[str, Any] = {"name": e.name, "verification": e.verification, "criticality": e.criticality, "third_party_hosted": e.third_party_hosted}
            if e.verification == "attested":
                out.update({"attested_by": e.attested_by, "attested_date": e.attested_date})
            if e.note:
                out["note"] = e.note
            return out

        def net(n: NetEntry) -> dict[str, Any]:
            out: dict[str, Any] = {"value": n.value, "criticality": n.criticality, "third_party_hosted": n.third_party_hosted}
            if n.note:
                out["note"] = n.note
            return out

        def with_note(item: dict[str, Any], note: str) -> dict[str, Any]:
            if note:
                item["note"] = note
            return item

        org: dict[str, Any] = {"name": self.name}
        if self.note:
            org["note"] = self.note
        out: dict[str, Any] = dict(self.meta)
        out.update({
            "org": org,
            "domains": [dom(e) for e in self.domains],
            "brands": [{"keyword": b.keyword, "variants": list(b.variants), "criticality": b.criticality} for b in self.brands],
            "cnpj_roots": list(self.cnpj_roots),
            "card_bins": list(self.card_bins),
            "asns": [net(n) for n in self.asns],
            "cidrs": [net(n) for n in self.cidrs],
            "app_ids": [with_note({"kind": a.kind, "value": a.value}, a.note) for a in self.app_ids],
            "favicon_hashes": list(self.favicon_hashes),
            "suppliers": [with_note({"name": s.name, "domains": list(s.domains), "brands": list(s.brands)}, s.note) for s in self.suppliers],
            "executives": [{"name": x.name, "opt_in": x.opt_in, "programme": x.programme, "informed_at": x.informed_at} for x in self.executives],
        })
        return out

    def counts(self) -> dict[str, int]:
        return {key: len(getattr(self, key)) for key in _LIST_KEYS}

    @property
    def is_empty(self) -> bool:
        return not any(self.counts().values())

    # ---- membership -----------------------------------------------------------------------------
    def domain_entry(self, domain: str) -> DomainEntry | None:
        """The most specific own domain entry covering ``domain`` (PSL + label match), or None."""
        host = _host(domain)
        if not host:
            return None
        reg = psl.registrable_domain(host)
        if reg is None:
            return None
        labels = host.split(".")
        best: DomainEntry | None = None
        for entry in self.domains:
            e_labels = entry.name.split(".")
            if len(e_labels) > len(labels) or labels[-len(e_labels) :] != e_labels:
                continue  # label-wise match only: never a string-suffix match
            if psl.registrable_domain(entry.name) != reg:
                continue
            if best is None or len(e_labels) > best.name.count(".") + 1:
                best = entry
        return best

    def _own_domain(self, domain: str) -> Ownership:
        entry = self.domain_entry(domain)
        if entry is not None:
            return Ownership(True, entry.verified, "domain", entry, entry.criticality, entry.third_party_hosted)
        host = _host(domain)
        labels = host.split(".") if host else []
        for supplier in self.suppliers:
            for sdom in supplier.domains:
                s_labels = sdom.split(".")
                if labels and len(s_labels) <= len(labels) and labels[-len(s_labels) :] == s_labels:
                    return Ownership(False, False, "supplier", supplier, "", False)
        return NOT_OWNED

    def _own_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Ownership:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # ::ffff:203.0.113.5 is 203.0.113.5
        best: tuple[int, NetEntry] | None = None
        for entry in self.cidrs:
            net = ipaddress.ip_network(entry.value)
            if net.version == ip.version and ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, entry)
        if best is None:
            return NOT_OWNED
        entry = best[1]
        return Ownership(True, False, "cidr", entry, entry.criticality, entry.third_party_hosted)

    def owns(self, entity: Any) -> Ownership:
        """Whether an entity (Entity or 'type:value') belongs to the organisation.

        domain/url/email: PSL registrable domain + subdomain match against ``domains`` (IDN as
        punycode, never string-suffix matching); ipv4/ipv6/cidr: ``ipaddress`` containment in
        ``cidrs``; asn: equality; cnpj: 8-character root; favicon_hash: equality; card_bin (and
        the BIN of a masked payment_card): prefix. Everything else is not owned.
        """
        ent = _entity(entity)
        if ent is None:
            return NOT_OWNED
        etype = str(getattr(ent.type, "value", ent.type))
        value = str(ent.value)
        if etype == "domain":
            return self._own_domain(value)
        if etype == "email":
            return self._own_domain(value.rsplit("@", 1)[-1])
        if etype == "url":
            host = url_host(value)
            try:
                return self._own_ip(ipaddress.ip_address(host))
            except ValueError:
                return self._own_domain(host) if host else NOT_OWNED
        if etype in ("ipv4", "ipv6"):
            try:
                return self._own_ip(ipaddress.ip_address(value))
            except ValueError:
                return NOT_OWNED
        if etype == "cidr":
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return NOT_OWNED
            for entry in self.cidrs:
                own = ipaddress.ip_network(entry.value)
                if own.version == net.version and net.subnet_of(own):  # type: ignore[arg-type]
                    return Ownership(True, False, "cidr", entry, entry.criticality, entry.third_party_hosted)
            return NOT_OWNED
        if etype == "asn":
            asn = _asn(value)
            entry = next((e for e in self.asns if e.value == asn), None)
            return Ownership(True, False, "asn", entry, entry.criticality, entry.third_party_hosted) if entry else NOT_OWNED
        if etype == "cnpj":
            root = re.sub(r"[^0-9A-Za-z]", "", value).upper()[:8]
            return Ownership(True, False, "cnpj_root", root, DEFAULT_CRITICALITY, False) if root in self.cnpj_roots else NOT_OWNED
        if etype == "favicon_hash":
            try:
                fav = str(int(value))
            except ValueError:
                return NOT_OWNED
            return Ownership(True, False, "favicon_hash", fav, DEFAULT_CRITICALITY, False) if fav in self.favicon_hashes else NOT_OWNED
        if etype in ("card_bin", "payment_card"):
            digits = re.match(r"^\d+", re.sub(r"[\s-]", "", value))
            prefix = digits.group(0) if digits else ""
            for own_bin in self.card_bins:
                if prefix and prefix.startswith(own_bin):
                    return Ownership(True, False, "card_bin", own_bin, DEFAULT_CRITICALITY, False)
            return NOT_OWNED
        return NOT_OWNED

    def is_verified_domain(self, domain: str) -> bool:
        """True when ``domain`` is covered by a txt_verified or attested entry."""
        entry = self.domain_entry(domain)
        return bool(entry is not None and entry.verified)

    def brand_terms(self) -> list[str]:
        """Brand keywords and variants, accent-folded and lower-case (deduplicated, in order)."""
        out: list[str] = []
        for brand in self.brands:
            for term in (brand.keyword, *brand.variants):
                folded = fold(term)
                if folded and folded not in out:
                    out.append(folded)
        return out

    def supplier_domains(self) -> list[str]:
        """Every supplier domain (punycode, deduplicated, sorted)."""
        return sorted({d for s in self.suppliers for d in s.domains})

    # ---- editing (v2, WP18: `v3lum org verify|seed`; the commands audit every change) ----------
    def _exact_domain(self, name: str) -> int:
        return next((i for i, entry in enumerate(self.domains) if entry.name == name), -1)

    def _set_domain(self, entry: DomainEntry) -> DomainEntry:
        index = self._exact_domain(entry.name)
        if index >= 0:
            self.domains[index] = entry
        else:
            self.domains.append(entry)
        return entry

    def mark_txt_verified(self, domain: str, *, note: str = "") -> DomainEntry:
        """Record a successful DNS TXT proof of control (:func:`verify_txt`): the entry of exactly
        ``domain`` becomes ``txt_verified`` (added, criticality medium, when the profile has none for
        that name; its criticality, hosting flag and note are kept otherwise). ValueError for an
        invalid domain or a public suffix."""
        name = _require_domain(domain)
        index = self._exact_domain(name)
        current = self.domains[index] if index >= 0 else DomainEntry(name)
        updated = replace(current, verification="txt_verified", attested_by="", attested_date="", note=note or current.note)
        return self._set_domain(updated)

    def mark_attested(self, domain: str, by: str, date: Any = None) -> DomainEntry:
        """Record an analyst attestation ``{by, date}`` (P378 cond 2/5): the entry of exactly ``domain``
        becomes ``attested`` (added when missing). ``date`` is 'YYYY-MM-DD' or a date (default: today,
        UTC) and may not lie in the future. ValueError without a name, with a bad date or domain."""
        name = _require_domain(domain)
        who = " ".join(str(by or "").split())
        if not who or _CTRL_RE.search(who):
            raise ValueError("an attestation needs the analyst's name (--by NAME)")
        day = _date(date) if date not in (None, "") else _dt.datetime.now(_dt.timezone.utc).date().isoformat()
        if not day:
            raise ValueError("the attestation date must be YYYY-MM-DD")
        if day > _dt.datetime.now(_dt.timezone.utc).date().isoformat():
            raise ValueError(f"the attestation date {day} lies in the future")
        index = self._exact_domain(name)
        current = self.domains[index] if index >= 0 else DomainEntry(name)
        return self._set_domain(replace(current, verification="attested", attested_by=who, attested_date=day))

    def add_domain(
        self, domain: str, *, verification: str = "seeded", criticality: str = DEFAULT_CRITICALITY, third_party_hosted: bool = False, note: str = ""
    ) -> DomainEntry:
        """Add an analyst-confirmed domain entry (never ``txt_verified``/``attested``: those come only
        from :meth:`mark_txt_verified` / :meth:`mark_attested`). ValueError for an invalid or
        duplicate domain, an unknown criticality or a verified state."""
        name = _require_domain(domain)
        if verification not in ("seeded", "confirmed"):
            raise ValueError("new entries are 'seeded' or 'confirmed'; verified states need `v3lum org verify`")
        if criticality not in CRITICALITIES:
            raise ValueError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        if self._exact_domain(name) >= 0:
            raise ValueError(f"{name} is already in the profile")
        return self._set_domain(DomainEntry(name, verification, "", "", criticality, bool(third_party_hosted), str(note or "")))

    def add_network(
        self, kind: str, value: Any, *, criticality: str = DEFAULT_CRITICALITY, third_party_hosted: bool = False, note: str = ""
    ) -> NetEntry:
        """Add an own ASN (``kind`` 'asns') or network (``kind`` 'cidrs'). ValueError for an invalid,
        too broad or duplicate value."""
        if kind not in ("asns", "cidrs"):
            raise ValueError("kind must be 'asns' or 'cidrs'")
        if criticality not in CRITICALITIES:
            raise ValueError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        if kind == "asns":
            normalised = _asn(value)
            if normalised is None:
                raise ValueError(f"{str(value)[:40]!r} is not a valid ASN")
            target = self.asns
        else:
            problem = _cidr_problem(value)
            if problem:
                raise ValueError(problem)
            normalised = str(ipaddress.ip_network(str(value).strip(), strict=True))
            target = self.cidrs
        if any(entry.value == normalised for entry in target):
            raise ValueError(f"{normalised} is already in the profile")
        entry = NetEntry(normalised, criticality, bool(third_party_hosted), str(note or ""))
        target.append(entry)
        return entry

    def add_cnpj_root(self, value: Any) -> str:
        """Add the 8-character root of a CNPJ (a full CNPJ is reduced to its root). ValueError when
        no 8-character root can be read or it is already listed."""
        root = re.sub(r"[^0-9A-Za-z]", "", str(value or "")).upper()
        if len(root) == 14:
            root = root[:8]
        if len(root) != 8:
            raise ValueError("a CNPJ root has 8 characters")
        if root in self.cnpj_roots:
            raise ValueError(f"CNPJ root {root} is already in the profile")
        self.cnpj_roots.append(root)
        return root

    def add_app_id(self, kind: str, value: str, *, note: str = "") -> AppId:
        """Add an application/tenant id (e.g. kind 'm365_tenant'). ValueError when empty or listed."""
        kind, value = str(kind or "").strip(), str(value or "").strip()
        if not kind or not value or _CTRL_RE.search(kind + value):
            raise ValueError("an app id needs a kind and a value")
        if any(a.kind == kind and a.value == value for a in self.app_ids):
            raise ValueError(f"{kind} {value} is already in the profile")
        entry = AppId(kind, value, str(note or ""))
        self.app_ids.append(entry)
        return entry

    def save(self, path: str | Path | None = None) -> Path:
        """:func:`save` this profile (0600, validated first); returns the written path."""
        return save(self, path)


def load_default(config: Any = None) -> OrgProfile:
    """The profile at setting ``org_profile_path``; '' -> ~/.v3lum/org_profile.toml, then .json.

    A missing file gives an empty profile (``is_empty`` True).
    """
    configured = ""
    getter = getattr(config, "get", None)
    if callable(getter):
        configured = str(getter("org_profile_path", "") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        prof = OrgProfile.load(path)
        if not path.is_file():  # a configured (e.g. team-shared) path that is not there: say so
            prof.errors.append(f"org_profile_path {str(path)[:200]!r} is not a readable file: no own assets are known")
        return prof
    home = paths.home()
    for name in ("org_profile.toml", "org_profile.json"):
        candidate = home / name
        if candidate.is_file():
            return OrgProfile.load(candidate)
    return OrgProfile.empty(str(home / "org_profile.toml"))


# ======================================================================================
# v2 (WP18): strict validation, save, DNS TXT proof of control, attestation
# ======================================================================================

#: Prefix of the DNS TXT record that proves control of a domain (``v3lum org verify``): the record
#: published at the domain itself is ``v3lum-verify=<txt_token(domain)>``.
TXT_PREFIX = "v3lum-verify="
#: Largest profile file :func:`validate` reads.
_MAX_FILE_BYTES = 4 * 1024 * 1024
_ATTESTED_KEYS = frozenset({"by", "date"})
_TOP_ALLOWED = ", ".join(sorted(_TOP_KEYS))


def default_path(config: Any = None) -> Path:
    """Where the profile lives or would be created: setting ``org_profile_path`` when set, else an
    existing ``~/.v3lum/org_profile.toml`` / ``.json``, else ``org_profile.toml`` (``.json`` on
    Python 3.10, which cannot read TOML back)."""
    getter = getattr(config, "get", None)
    configured = str(getter("org_profile_path", "") or "").strip() if callable(getter) else ""
    if configured:
        return Path(configured).expanduser()
    home = paths.home()
    for name in ("org_profile.toml", "org_profile.json"):
        if (home / name).is_file():
            return home / name
    return home / ("org_profile.toml" if _toml is not None else "org_profile.json")


@dataclass(frozen=True)
class ProfileProblem:
    """One strict-validation problem of an org profile.

    ``field`` is the path in the document ('domains[2].verification', 'org.cnpj_roots[0]'; '' for
    the whole file), ``line`` the 1-based line of the file (0 when unknown: a parsed mapping, or a
    problem of the file itself such as its mode), ``message`` says what is wrong without echoing an
    executive's name or a card number.
    """

    field: str
    message: str
    line: int = 0

    def __str__(self) -> str:
        where = f"line {self.line}: " if self.line else ""
        return f"{where}{self.field + ': ' if self.field else ''}{self.message}"


# ---- strict checks -----------------------------------------------------------------------------


class _Checker:
    """Strict schema checks over a parsed document: (field path, message) pairs."""

    def __init__(self) -> None:
        self.problems: list[tuple[str, str]] = []
        self.seen: dict[str, dict[str, str]] = {}

    def add(self, where: str, message: str) -> None:
        self.problems.append((where, message))

    def unique(self, kind: str, key: str, where: str, label: str) -> None:
        first = self.seen.setdefault(kind, {}).get(key)
        if first is not None:
            self.add(where, f"duplicate {label} (first listed at {first})")
        else:
            self.seen[kind][key] = where

    def unknown(self, item: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
        for key in sorted(set(item) - allowed, key=str):
            self.add(f"{where}.{key}" if where else str(key), f"unknown key (allowed: {', '.join(sorted(allowed))})")

    def text(self, item: Mapping[str, Any], key: str, where: str, *, required: bool = False, label: str = "") -> str:
        value = item.get(key)
        here = f"{where}.{key}" if where else key
        if value is None or value == "":
            if required:
                self.add(here, f"{label or key} is required")
            return ""
        if not isinstance(value, str):
            self.add(here, "must be a string")
            return ""
        if _CTRL_RE.search(value):
            self.add(here, "contains a control character")
        return value.strip()

    def boolean(self, item: Mapping[str, Any], key: str, where: str) -> None:
        if key in item and not isinstance(item[key], bool):
            self.add(f"{where}.{key}", "must be true or false")

    def criticality(self, item: Mapping[str, Any], where: str) -> None:
        if "criticality" in item and (not isinstance(item["criticality"], str) or item["criticality"].strip().lower() not in CRITICALITIES):
            self.add(f"{where}.criticality", f"must be one of {', '.join(CRITICALITIES)}")

    def date(self, value: Any, where: str, *, required: bool, label: str) -> str:
        if value in (None, ""):
            if required:
                self.add(where, f"{label} is required (YYYY-MM-DD)")
            return ""
        day = _date(value) if isinstance(value, (str, _dt.date)) else ""
        if not day:
            self.add(where, f"{label} must be a date (YYYY-MM-DD)")
            return ""
        if day > _dt.datetime.now(_dt.timezone.utc).date().isoformat():
            self.add(where, f"{label} {day} lies in the future")
        return day

    def string_list(self, value: Any, where: str) -> list[str]:
        if not isinstance(value, list):
            self.add(where, "must be a list of strings")
            return []
        out = []
        for i, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                self.add(f"{where}[{i}]", "must be a non-empty string")
            else:
                out.append(item.strip())
        return out

    # ---- entries -------------------------------------------------------------------------
    def domain(self, item: Any, where: str) -> None:
        if isinstance(item, str):
            item = {"name": item}
        if not isinstance(item, Mapping):
            self.add(where, "must be a domain name or a table")
            return
        self.unknown(item, _DOMAIN_KEYS, where)
        if "name" in item and "domain" in item:
            self.add(f"{where}.domain", "give the domain once (name)")
        key = "name" if "name" in item else "domain"
        raw = item.get(key)
        if not isinstance(raw, str) or not raw.strip():
            self.add(f"{where}.{key}" if key in item else where, "a domain name is required")
        else:
            name = _domain(raw)
            if name is None:
                self.add(f"{where}.{key}", f"{raw.strip()[:80]!r} is not a valid registrable domain (public suffixes are refused)")
            else:
                self.unique("domains", name, f"{where}.{key}" if key in item and len(item) > 1 else where, f"domain {name}")
        verification = item.get("verification", "seeded")
        state = verification.strip().lower() if isinstance(verification, str) else ""
        if state not in VERIFICATIONS:
            self.add(f"{where}.verification", f"must be one of {', '.join(VERIFICATIONS)} (txt_verified comes from `v3lum org verify`)")
        attested = item.get("attested")
        if attested is not None and not isinstance(attested, Mapping):
            self.add(f"{where}.attested", "must be a table {by, date}")
            attested = {}
        attested = attested or {}
        if attested:
            self.unknown(attested, _ATTESTED_KEYS, f"{where}.attested")
        flat = "attested" not in item  # attested_by / attested_date (else the {by, date} table)
        by_where = f"{where}.attested_by" if flat or "attested_by" in item else f"{where}.attested.by"
        date_where = f"{where}.attested_date" if flat or "attested_date" in item else f"{where}.attested.date"
        by = item.get("attested_by", attested.get("by"))
        date = item.get("attested_date", attested.get("date"))
        if state == "attested":
            if not isinstance(by, str) or not by.strip():
                self.add(by_where, "attested entries need the analyst's name (attested_by or attested.by)")
            self.date(date, date_where, required=True, label="the attestation date")
        elif any(k in item for k in ("attested_by", "attested_date", "attested")):
            self.add(f"{where}.verification", f"attestation fields only apply to verification = 'attested' (this entry is {state or '?'})")
        self.criticality(item, where)
        self.boolean(item, "third_party_hosted", where)
        self.text(item, "note", where)

    def brand(self, item: Any, where: str) -> None:
        if isinstance(item, str):
            item = {"keyword": item}
        if not isinstance(item, Mapping):
            self.add(where, "must be a keyword or a table")
            return
        self.unknown(item, _BRAND_KEYS, where)
        key = "keyword" if "keyword" in item else "name"
        keyword = self.text(item, key, where, required=True, label="keyword")
        if keyword:
            self.unique("brands", fold(keyword), f"{where}.{key}", f"brand keyword {fold(keyword)!r}")
        if "variants" in item:
            self.string_list(item["variants"], f"{where}.variants")
        self.criticality(item, where)

    def cnpj_root(self, item: Any, where: str) -> None:
        if not isinstance(item, str):
            self.add(where, "write CNPJ roots as strings (an integer loses leading zeros)")
            return
        root = re.sub(r"[^0-9A-Za-z]", "", item).upper()
        if len(root) != 8:
            hint = " (a full CNPJ: keep only its first 8 characters)" if len(root) == 14 else ""
            self.add(where, f"a CNPJ root has 8 characters, this one has {len(root)}{hint}")
            return
        self.unique("cnpj_roots", root, where, f"CNPJ root {root}")

    def card_bin(self, item: Any, where: str) -> None:
        digits = re.sub(r"[\s-]", "", str(item)) if isinstance(item, (str, int)) and not isinstance(item, bool) else ""
        if not digits.isdigit() or not 6 <= len(digits) <= 8:
            self.add(where, "a BIN prefix has 6-8 digits (never store full card numbers)")  # the value is never echoed
            return
        self.unique("card_bins", digits, where, "BIN prefix")

    def favicon(self, item: Any, where: str) -> None:
        text = str(item).strip() if isinstance(item, (str, int)) and not isinstance(item, bool) else ""
        if not re.match(r"^-?\d{1,11}$", text) or not -(2**31) <= int(text) < 2**31:
            self.add(where, "an mmh3 favicon hash is a signed 32-bit integer")
            return
        self.unique("favicon_hashes", str(int(text)), where, f"favicon hash {int(text)}")

    def network(self, item: Any, where: str, kind: str) -> None:
        if isinstance(item, Mapping):
            self.unknown(item, _NET_KEYS, where)
            value, vwhere = item.get("value"), f"{where}.value"
            self.criticality(item, where)
            self.boolean(item, "third_party_hosted", where)
            self.text(item, "note", where)
        else:
            value, vwhere = item, where
        if value is None or isinstance(value, bool) or not isinstance(value, (str, int)):
            self.add(vwhere, f"{'an ASN' if kind == 'asns' else 'a network'} is required")
            return
        if kind == "asns":
            asn = _asn(value)
            if asn is None or asn == "AS0":
                self.add(vwhere, f"{str(value)[:40]!r} is not a valid ASN (AS1-AS4294967295)")
            else:
                self.unique("asns", asn, vwhere, asn)
            return
        problem = _cidr_problem(value)
        if problem:
            self.add(vwhere, problem)
        else:
            self.unique("cidrs", str(ipaddress.ip_network(str(value).strip())), vwhere, f"network {ipaddress.ip_network(str(value).strip())}")

    def app_id(self, item: Any, where: str) -> None:
        if not isinstance(item, Mapping):
            self.add(where, "must be a table with kind and value")
            return
        self.unknown(item, _APP_KEYS, where)
        kind = self.text(item, "kind", where, required=True)
        value = self.text(item, "value", where, required=True)
        self.text(item, "note", where)
        if kind and value:
            self.unique("app_ids", f"{kind}\x00{value}", where, f"app id {kind} {value}")

    def supplier(self, item: Any, where: str) -> None:
        if not isinstance(item, Mapping):
            self.add(where, "must be a table")
            return
        self.unknown(item, _SUPPLIER_KEYS, where)
        self.text(item, "name", where, required=True)
        self.text(item, "note", where)
        if "domains" in item:
            for j, raw in enumerate(self.string_list(item["domains"], f"{where}.domains")):
                if _domain(raw) is None:
                    self.add(f"{where}.domains[{j}]", f"{raw[:80]!r} is not a valid registrable domain")
        if "brands" in item:
            self.string_list(item["brands"], f"{where}.brands")

    def executive(self, item: Any, where: str) -> None:
        # never echo the person's name in a message
        if not isinstance(item, Mapping):
            self.add(where, "must be a table")
            return
        self.unknown(item, _EXEC_KEYS, where)
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            self.add(f"{where}.name", "name is required")
        if item.get("opt_in") is not True:
            self.add(f"{where}.opt_in", "executives are listed only with explicit opt_in = true (informed under the VIP-protection programme)")
        self.date(item.get("informed_at"), f"{where}.informed_at", required=True, label="informed_at (date of the VIP-protection notice)")
        self.text(item, "programme", where)


_CHECKS = {
    "domains": _Checker.domain,
    "brands": _Checker.brand,
    "cnpj_roots": _Checker.cnpj_root,
    "card_bins": _Checker.card_bin,
    "favicon_hashes": _Checker.favicon,
    "app_ids": _Checker.app_id,
    "suppliers": _Checker.supplier,
    "executives": _Checker.executive,
}


def _strict(data: Any) -> list[tuple[str, str]]:
    """Strict schema problems of a parsed profile document as (field path, message)."""
    check = _Checker()
    if data is None:
        return []
    if not isinstance(data, Mapping):
        check.add("", "the org profile must be a table/object")
        return check.problems
    for key in sorted(set(data) - _TOP_KEYS, key=str):
        check.add(str(key), f"unknown top-level key (allowed: {_TOP_ALLOWED})")
    org = data.get("org", {})
    if not isinstance(org, Mapping):
        check.add("org", "must be a table")
        org = {}
    check.unknown(org, _ORG_KEYS, "org")
    if "name" in org:
        check.text(org, "name", "org")
    if "name" in data:
        check.text(data, "name", "")
    if "note" in org:
        check.text(org, "note", "org")
    for key in ("schema", "version"):
        if key in data and (isinstance(data[key], bool) or not isinstance(data[key], (str, int))):
            check.add(key, "must be a string or an integer")
    for key in _LIST_KEYS:
        for prefix, container in (("", data), ("org.", org)):
            if key not in container:
                continue
            items = container[key]
            if not isinstance(items, list):
                check.add(f"{prefix}{key}", "must be a list")
                continue
            for i, item in enumerate(items):
                where = f"{prefix}{key}[{i}]"
                if key in ("asns", "cidrs"):
                    check.network(item, where, key)
                else:
                    _CHECKS[key](check, item, where)
    return check.problems


# ---- line numbers ------------------------------------------------------------------------------


class _Scanner:
    """Best-effort map of field paths to 1-based lines for a TOML or JSON document that parsed."""

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        self.i = 0
        self.line = 1
        self.index: dict[str, int] = {}

    def mark(self, path: str, line: int) -> None:
        self.index.setdefault(path, line)

    def skip(self, newlines: bool, comments: bool = True) -> None:
        s, n = self.s, self.n
        while self.i < n:
            ch = s[self.i]
            if ch in " \t\r":
                self.i += 1
            elif ch == "\n":
                if not newlines:
                    return
                self.line += 1
                self.i += 1
            elif ch == "#" and comments:
                while self.i < n and s[self.i] != "\n":
                    self.i += 1
            else:
                return

    def string(self) -> str:
        """Consume a TOML/JSON string at the cursor and return its (approximate) text."""
        s, n = self.s, self.n
        for delim in ('"""', "'''"):
            if s.startswith(delim, self.i):
                end = s.find(delim, self.i + 3)
                end = n if end < 0 else end
                chunk = s[self.i + 3 : end]
                self.line += chunk.count("\n")
                self.i = min(n, end + 3)
                while self.i < n and s[self.i] == delim[0]:  # up to two extra quotes belong to the string
                    self.i += 1
                return chunk
        quote = s[self.i]
        self.i += 1
        out = []
        while self.i < n and s[self.i] != quote and s[self.i] != "\n":
            if quote == '"' and s[self.i] == "\\" and self.i + 1 < n:
                out.append(s[self.i : self.i + 2])
                self.i += 2
                continue
            out.append(s[self.i])
            self.i += 1
        self.i += 1
        raw = "".join(out)
        if quote == '"' and "\\" in raw:
            try:
                return json.loads(f'"{raw}"')
            except ValueError:
                return raw
        return raw

    def scalar(self, stops: str) -> None:
        while self.i < self.n and self.s[self.i] not in stops:
            self.i += 1


class _TomlScanner(_Scanner):
    def key(self) -> str:
        parts = []
        while self.i < self.n:
            self.skip(False)
            if self.i < self.n and self.s[self.i] in "\"'":
                parts.append(self.string())
            else:
                start = self.i
                while self.i < self.n and (self.s[self.i].isalnum() or self.s[self.i] in "-_"):
                    self.i += 1
                parts.append(self.s[start : self.i])
            self.skip(False)
            if self.i < self.n and self.s[self.i] == ".":
                self.i += 1
                continue
            break
        return ".".join(parts)

    def value(self, path: str) -> None:
        self.skip(False)
        if self.i >= self.n:
            return
        ch = self.s[self.i]
        if ch in "\"'":
            self.string()
        elif ch == "[":
            self.i += 1
            k = 0
            while self.i < self.n:
                self.skip(True)
                if self.i >= self.n or self.s[self.i] == "]":
                    self.i += 1
                    return
                self.mark(f"{path}[{k}]", self.line)
                start = self.i
                self.value(f"{path}[{k}]")
                k += 1
                self.skip(True)
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
                elif self.i < self.n and self.s[self.i] == "]":
                    self.i += 1
                    return
                elif self.i == start:
                    return  # malformed: stop rather than loop
        elif ch == "{":
            self.i += 1
            while self.i < self.n:
                self.skip(False)
                if self.i >= self.n or self.s[self.i] in "}\n":
                    self.i += 1
                    return
                line = self.line
                start = self.i
                key = self.key()
                self.skip(False)
                if self.i < self.n and self.s[self.i] == "=":
                    self.i += 1
                self.mark(f"{path}.{key}", line)
                self.value(f"{path}.{key}")
                self.skip(False)
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
                elif self.i < self.n and self.s[self.i] == "}":
                    self.i += 1
                    return
                elif self.i == start:
                    return
        else:
            self.scalar(",]}\n#")

    def run(self) -> dict[str, int]:
        prefix = ""
        counts: dict[str, int] = {}
        while self.i < self.n:
            self.skip(True)
            if self.i >= self.n:
                break
            start = self.i
            if self.s[self.i] == "[":
                aot = self.s.startswith("[[", self.i)
                self.i += 2 if aot else 1
                name = self.key()
                self.skip(False)
                self.i += 2 if aot else 1
                if aot:
                    counts[name] = counts.get(name, -1) + 1
                    prefix = f"{name}[{counts[name]}]"
                else:  # a sub-table of the last element of an array of tables keeps its index
                    parent = max((a for a in counts if name.startswith(a + ".")), key=len, default="")
                    prefix = f"{parent}[{counts[parent]}]{name[len(parent):]}" if parent else name
                self.mark(prefix, self.line)
            else:
                line = self.line
                key = self.key()
                self.skip(False)
                if self.i < self.n and self.s[self.i] == "=":
                    self.i += 1
                    path = f"{prefix}.{key}" if prefix else key
                    self.mark(path, line)
                    self.value(path)
            while self.i < self.n and self.s[self.i] != "\n":  # the rest of the line (a comment)
                self.i += 1
            if self.i == start:
                self.i += 1
        return self.index


class _JsonScanner(_Scanner):
    def value(self, path: str) -> None:
        self.skip(True, comments=False)
        if self.i >= self.n:
            return
        ch = self.s[self.i]
        if ch == "{":
            self.i += 1
            while self.i < self.n:
                self.skip(True, comments=False)
                if self.i >= self.n or self.s[self.i] == "}":
                    self.i += 1
                    return
                if self.s[self.i] != '"':
                    return
                line = self.line
                key = self.string()
                self.skip(True, comments=False)
                if self.i < self.n and self.s[self.i] == ":":
                    self.i += 1
                child = f"{path}.{key}" if path else key
                self.mark(child, line)
                self.value(child)
                self.skip(True, comments=False)
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
                else:
                    self.i += 1
                    return
        elif ch == "[":
            self.i += 1
            k = 0
            while self.i < self.n:
                self.skip(True, comments=False)
                if self.i >= self.n or self.s[self.i] == "]":
                    self.i += 1
                    return
                self.mark(f"{path}[{k}]", self.line)
                self.value(f"{path}[{k}]")
                k += 1
                self.skip(True, comments=False)
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
                else:
                    self.i += 1
                    return
        elif ch == '"':
            self.string()
        else:
            self.scalar(",]}\n \t\r")

    def run(self) -> dict[str, int]:
        self.value("")
        return self.index


def _line_index(text: str, fmt: str) -> dict[str, int]:
    try:
        return (_JsonScanner(text) if fmt == "json" else _TomlScanner(text)).run()
    except (IndexError, RecursionError):  # pragma: no cover - best effort only
        return {}


def _line_for(index: Mapping[str, int], field_path: str) -> int:
    """Line of ``field_path`` or of its closest listed parent (0 when unknown)."""
    path = field_path
    while path:
        if path in index:
            return index[path]
        cut = max(path.rfind("."), path.rfind("["))
        path = path[:cut] if cut > 0 else ""
    return 0


# ---- validate ----------------------------------------------------------------------------------


def _fmt_of(path: Path | None, fmt: str | None, text: str = "") -> str:
    if fmt:
        return "json" if fmt.lower() == "json" else "toml"
    if path is not None:
        return "json" if path.suffix.lower() == ".json" else "toml"
    return "json" if text.lstrip().startswith(("{", "[")) else "toml"


def validate_text(text: str | bytes, *, fmt: str | None = None) -> list[ProfileProblem]:
    """Strict validation of profile text (``fmt`` 'toml' | 'json'; default: JSON when it starts with
    '{' or '[', else TOML). Parse errors come back as one problem with the parser's line."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            return [ProfileProblem("", f"the org profile is not UTF-8 text ({exc.reason})")]
    kind = _fmt_of(None, fmt, text)
    try:
        if kind == "json":
            data = json.loads(text)
        elif _toml is None:  # pragma: no cover - Python 3.10
            return [ProfileProblem("", "TOML profiles need Python 3.11+ (tomllib): use an org_profile.json")]
        else:
            data = _toml.loads(text)
    except ValueError as exc:  # JSONDecodeError / TOMLDecodeError
        line = getattr(exc, "lineno", 0) or 0
        if not line:
            found = re.search(r"line (\d+)", str(exc))
            line = int(found.group(1)) if found else 0
        return [ProfileProblem("", f"invalid {'JSON' if kind == 'json' else 'TOML'}: {exc}", int(line))]
    index = _line_index(text, kind)
    return [ProfileProblem(where, message, _line_for(index, where)) for where, message in _strict(data)]


def validate(source: str | os.PathLike[str] | Mapping[str, Any]) -> list[ProfileProblem]:
    """Strict schema validation (``v3lum org check``; P378 cond 1, A11). [] = valid.

    ``source`` is a profile file (TOML, or JSON for '.json') or an already parsed mapping (no line
    numbers). Everything the lenient loader (:meth:`OrgProfile.load`) drops, downgrades or merely
    tolerates is a problem here: unknown keys; invalid verification states (an unknown state,
    attested without the analyst's name and a past date, attestation fields on another state);
    invalid or public-suffix domains, malformed ASNs, malformed/host-bit/too-broad networks; CNPJ
    roots that are not 8 characters; duplicate domains, brands, roots, BINs, favicon hashes, ASNs,
    networks and app ids; executives without ``opt_in = true`` or ``informed_at``; wrong value
    types. For a file also: parse errors (with the parser's line) and a mode that lets other users
    read or write it (A11: 0600). Each problem carries its field path and file line. Executive
    names and card numbers are never echoed.
    """
    if isinstance(source, Mapping):
        return [ProfileProblem(where, message) for where, message in _strict(source)]
    path = Path(source).expanduser()
    if not path.is_file():
        return [ProfileProblem("", f"{path} is not a readable file")]
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return [ProfileProblem("", f"the org profile is larger than {_MAX_FILE_BYTES // (1024 * 1024)} MB")]
        raw = path.read_bytes()
    except OSError as exc:
        return [ProfileProblem("", f"cannot read the org profile: {exc.strerror or exc}")]
    if path.suffix.lower() in (".yaml", ".yml"):
        return [ProfileProblem("", "YAML profiles are an optional extra and are not validated strictly: convert the profile to TOML or JSON")]
    problems = validate_text(raw, fmt=_fmt_of(path, None))
    access, _writable = _access_problem(path)
    if access:
        problems.append(ProfileProblem("", access))
    return problems


# ---- save --------------------------------------------------------------------------------------


def _toml_str(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _toml_str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def _toml_key(key: str) -> str:
    return key if re.match(r"^[A-Za-z0-9_-]+$", key) else _toml_str(key)


def _dump_toml(data: Mapping[str, Any], stamp: str) -> str:
    lines = [
        "# V3LUM organisation profile (P378, A11): a sensitive asset inventory. Keep it 0600, never share",
        "# or export it. Reports and exports carry only own_asset/third_party tags and its SHA-256.",
        f"# Written by v3lum on {stamp}; `v3lum org check` validates it. Edits keep their meaning,",
        "# but v3lum rewrites the file in this canonical form (comments are not kept).",
    ]
    for key in ("schema", "version"):
        if key in data:
            lines.append(f"{key} = {_toml_value(data[key])}")
    lines += ["", "[org]"]
    for key, value in data.get("org", {}).items():
        lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    for key in ("cnpj_roots", "card_bins", "favicon_hashes"):
        lines.append(f"{key} = {_toml_value(list(data.get(key) or []))}")
    for key in ("domains", "brands", "asns", "cidrs", "app_ids", "suppliers", "executives"):
        for item in data.get(key) or []:
            lines += ["", f"[[{key}]]"]
            lines += [f"{_toml_key(k)} = {_toml_value(v)}" for k, v in item.items()]
    return "\n".join(lines) + "\n"


def save(profile: OrgProfile, path: str | os.PathLike[str] | None = None) -> Path:
    """Write ``profile`` and return the path (P378 cond 1: 0600 via ``paths.secure_write_text``,
    atomic replace).

    ``path`` defaults to ``profile.path``, else :func:`default_path`. The format follows the suffix:
    '.json' writes JSON, anything else TOML (YAML is never written). The document is validated
    strictly before it is written (ValueError listing the problems: v3lum never writes an invalid
    profile) and a TOML document is parsed back and compared. A file outside the V3LUM home keeps
    its group permission bits (a team-maintained profile) but never any for other users.
    ``profile.path`` and ``profile.sha256`` are updated.
    """
    target = Path(path or profile.path or default_path()).expanduser()
    suffix = target.suffix.lower()
    if suffix in (".yaml", ".yml"):
        raise ValueError("v3lum writes TOML or JSON org profiles only: save it as org_profile.toml or org_profile.json")
    kind = "json" if suffix == ".json" else "toml"
    data = profile.to_dict()
    problems = _strict(data)
    if problems:
        shown = "; ".join(f"{w}: {m}" if w else m for w, m in problems[:5])
        raise ValueError(f"refusing to write an invalid org profile ({len(problems)} problem(s)): {shown}")
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kind == "json":
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    else:
        text = _dump_toml(data, stamp)
        if _toml is not None and OrgProfile.from_dict(_toml.loads(text)).to_dict() != data:  # pragma: no cover - serialiser bug guard
            raise RuntimeError("org profile TOML serialisation mismatch: nothing written")
    mode = paths.FILE_MODE
    if target.exists() and not paths.inside_home(target):
        try:
            mode = (stat.S_IMODE(target.stat().st_mode) & 0o660) | 0o600
        except OSError:
            mode = paths.FILE_MODE
    paths.secure_write_text(target, text, mode=mode)
    profile.path = str(target)
    profile.sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return target


def mark_attested(profile: OrgProfile, domain: str, by: str, date: Any = None) -> DomainEntry:
    """Module-level form of :meth:`OrgProfile.mark_attested` (the profile is changed in memory;
    :func:`save` writes it)."""
    return profile.mark_attested(domain, by, date)


# ---- DNS TXT proof of control ------------------------------------------------------------------


def txt_token(domain: str) -> str:
    """The verification token of ``domain``: ``hmacid.hmac12('domain', <normalised domain>)``.

    It is keyed with this installation's secret (``~/.v3lum/secret.key``), so nobody can compute
    it elsewhere; IDN domains are normalised to punycode first. ValueError for an invalid domain
    or a public suffix."""
    from v3lum.core import hmacid

    return hmacid.hmac12("domain", _require_domain(domain))


def txt_record(domain: str) -> str:
    """The TXT record value to publish at ``domain``: ``'v3lum-verify=<txt_token(domain)>'``."""
    return TXT_PREFIX + txt_token(domain)


def _txt_text(record: Any) -> str:
    text = str(record or "").strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    return text.lower()


def verify_txt(resolver: Any, domain: str) -> bool | None:
    """Is ``txt_record(domain)`` published at the domain? Read through ``resolver`` (the core
    DoH resolver, ``Resolver.query(name, 'TXT')``).

    True: one TXT string equals the record (quotes and case ignored). False: the name answered
    (NOERROR or NXDOMAIN) without it. None: could not verify (SERVFAIL, timeout, transport or policy
    failure, offline) - never read as 'absent' (team rule 5). ValueError for an invalid domain.
    """
    name = _require_domain(domain)
    expected = txt_record(name).lower()
    try:
        answer = resolver.query(name, "TXT")
    except Exception:  # noqa: BLE001 - a resolver failure is "could not verify", never "absent"
        return None
    if answer is None or getattr(answer, "could_not_verify", True):
        return None
    return any(_txt_text(rec) == expected for rec in getattr(answer, "records", None) or ())
