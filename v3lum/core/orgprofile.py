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
    "VERIFICATIONS",
    "VERIFIED",
    "AppId",
    "BrandEntry",
    "DomainEntry",
    "ExecutiveEntry",
    "NetEntry",
    "OrgProfile",
    "Ownership",
    "SupplierEntry",
    "fold",
    "load_default",
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


@dataclass(frozen=True)
class AppId:
    kind: str
    value: str


@dataclass(frozen=True)
class SupplierEntry:
    name: str
    domains: tuple[str, ...] = ()
    brands: tuple[str, ...] = ()


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
            target.append(NetEntry(value, _criticality(item.get("criticality"), where, errors), _bool(item.get("third_party_hosted"), f"{where}.third_party_hosted", errors)))

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
            self.app_ids.append(AppId(kind, value))

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
            self.suppliers.append(SupplierEntry(name, tuple(domains), brands))

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

        return {
            "org": {"name": self.name},
            "domains": [dom(e) for e in self.domains],
            "brands": [{"keyword": b.keyword, "variants": list(b.variants), "criticality": b.criticality} for b in self.brands],
            "cnpj_roots": list(self.cnpj_roots),
            "card_bins": list(self.card_bins),
            "asns": [{"value": n.value, "criticality": n.criticality, "third_party_hosted": n.third_party_hosted} for n in self.asns],
            "cidrs": [{"value": n.value, "criticality": n.criticality, "third_party_hosted": n.third_party_hosted} for n in self.cidrs],
            "app_ids": [{"kind": a.kind, "value": a.value} for a in self.app_ids],
            "favicon_hashes": list(self.favicon_hashes),
            "suppliers": [{"name": s.name, "domains": list(s.domains), "brands": list(s.brands)} for s in self.suppliers],
            "executives": [{"name": x.name, "opt_in": x.opt_in, "programme": x.programme, "informed_at": x.informed_at} for x in self.executives],
        }

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
