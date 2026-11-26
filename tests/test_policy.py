"""Policy as code (P327): one table over every gate of ``v3lum.core.policy.decide``.

Each row builds a synthetic provider + module (``clean_registry``), a PolicyContext and a RunInfo,
and asserts ``(allowed, status, reason_code, rule_id)`` - plus, where it matters, the manual-link
flag, the allowed sources of aggregators and the licence basis. The per-rule tests named in
``policy.RULES`` re-run their rows with extra checks; acceptance tests cover the shipped corporate
profile, App.run_single-style refusals and the 'no gate outside policy.py' grep.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import pytest

import v3lum
from tests.fakes import define_module, make_runtime, provider_fragment
from v3lum import paths
from v3lum.config import Config
from v3lum.core import datasets, policy
from v3lum.core import module as module_mod
from v3lum.core import providers as providers_mod
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType, url_host
from v3lum.core.health import HealthState
from v3lum.core.licence import LicenceState
from v3lum.core.models import REASON_CODES, Opsec, Status, valid_reason
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.policy import Decision, PolicyContext, decide

NOW = _dt.datetime(2026, 11, 26, 12, 0, tzinfo=_dt.timezone.utc)
ALL_TYPES = ("domain", "ipv4", "ipv6", "url", "email", "cnpj", "keyword", "company_name", "sha256", "cidr", "username")
MISSING_PACKAGES = frozenset({"websocket"})

ORG: dict[str, Any] = {
    "org": {"name": "ACME"},
    "domains": [
        {"name": "acme-corp.com", "verification": "txt_verified", "criticality": "high"},
        {"name": "acme-attested.com", "verification": "attested", "attested_by": "Ana Analyst", "attested_date": "2026-11-01"},
        {"name": "acme-confirmed.com", "verification": "confirmed"},
        {"name": "acme-seeded.com", "verification": "seeded"},
        {"name": "acme-cdn.com", "verification": "txt_verified", "third_party_hosted": True},
    ],
    "brands": [{"keyword": "acme"}],
}

ALLOW_KINDS = {
    "active": ("2026-11-01", "2027-05-01"),
    "expired": ("2025-10-01", "2026-10-01"),
    "beyond_cap": ("2026-11-01", "2027-12-01"),  # 13 months: never active (fail closed)
    "future": ("2026-12-01", "2027-06-01"),
}


class Row(NamedTuple):
    id: str
    module: dict[str, Any]
    ctx: dict[str, Any]
    entity: str
    run: dict[str, Any]
    expect: tuple[bool, str, str, str]
    extra: dict[str, Any]


def R(id: str, module: dict[str, Any] | None = None, ctx: dict[str, Any] | None = None, entity: str = "domain:example.com", run: dict[str, Any] | None = None, expect: tuple[Any, ...] = (True, "ok", "", ""), **extra: Any) -> Row:  # noqa: A002, N802
    return Row(id, module or {}, ctx or {}, entity, run or {}, tuple(expect), extra)  # type: ignore[arg-type]


OK = (True, "ok", "", "")
TEXT = [("text_blob:" + "a" * 16, "extracted_from", "ioc_extract")]
URL_TOKEN = "url:https://evil.example/t/9f8e7d6c5b4a39281706f5e4d3c2b1a0"
JWT = "jwt:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
LIGHT = {"opsec": "light"}
ACTIVE = {"opsec": "active"}
PROXY = {"proxy_light": "socks5h://127.0.0.1:9050"}

ROWS: list[Row] = [
    # ---- POL-01 selection ---------------------------------------------------------------
    R("pol01-default-allowed", expect=OK),
    R("pol01-optin-quick", {"default_enabled": False}, expect=(False, "skipped", "not_default", "POL-01")),
    R("pol01-optin-explicit", {"default_enabled": False}, {"explicit": True}, expect=OK),
    R("pol01-optin-deep", {"default_enabled": False}, {"preset": "deep"}, expect=OK),
    R("pol01-optin-all-modules", {"default_enabled": False}, {"include_disabled": True}, expect=OK),
    R("pol01-demoted", ctx={"demoted": True}, expect=(False, "skipped", "demoted", "POL-01")),
    R("pol01-demoted-explicit", ctx={"demoted": True, "explicit": True}, expect=OK),
    R("pol01-demoted-deep", ctx={"demoted": True, "preset": "deep"}, expect=(False, "skipped", "demoted", "POL-01")),
    R("pol01-watch-only-scan", {"tags": {"watch_only"}}, expect=(False, "skipped", "not_applicable", "POL-01"), reason="runs only inside v3lum watch"),
    R("pol01-watch-only-watch", {"tags": {"watch_only"}}, {"path": "watch"}, expect=OK),
    R("pol01-watch-only-explicit", {"tags": {"watch_only"}}, {"explicit": True}, expect=(False, "skipped", "not_applicable", "POL-01")),
    R("pol01-type-not-accepted", {"accepts": ("ipv4",)}, expect=(False, "skipped", "not_applicable", "POL-01")),
    # ---- POL-02 metadata validity -------------------------------------------------------
    R("pol02-unregistered", {"unregistered": True}, expect=(False, "skipped", "policy", "POL-02")),
    R("pol02-registered-offline-module", {"disclosure": "none"}, expect=OK),
    # ---- POL-03 offline -----------------------------------------------------------------
    R("pol03-offline-third-party", ctx={"offline": True}, expect=(False, "unavailable", "offline", "POL-03")),
    R("pol03-offline-internal", {"disclosure": "internal"}, {"offline": True, "settings": {"misp_url": "https://misp.corp.example.test"}}, expect=(False, "unavailable", "offline", "POL-03")),
    R("pol03-offline-none", {"disclosure": "none"}, {"offline": True}, expect=OK),
    R("pol03-offline-target", LIGHT, {"offline": True, "mode": "light", "preset": "deep"}, expect=(False, "unavailable", "offline", "POL-03")),
    # ---- POL-04 licence -----------------------------------------------------------------
    R("pol04-open", expect=OK, basis={"open"}),
    R("pol04-key-terms-no-plan", {"terms": "key-terms", "key": True}, {"keys": True}, expect=(False, "skipped", "licence", "POL-04"), link=True),
    R("pol04-key-terms-free-business", {"terms": "key-terms", "free_business": True}, expect=OK, basis={"open"}),
    R("pol04-key-terms-business-plan", {"terms": "key-terms", "key": True}, {"keys": True, "plan": "business"}, expect=OK, basis={"business_plan:{key}"}),
    R("pol04-key-terms-free-plan", {"terms": "key-terms", "key": True}, {"keys": True, "plan": "free"}, expect=(False, "skipped", "licence", "POL-04")),
    # an optional key that is not set means keyless requests: its recorded business plan does not count
    R("pol04-key-terms-optional-unset-business", {"terms": "key-terms", "optional_key": True}, {"plan": "business"}, expect=(False, "skipped", "licence", "POL-04"), link=True),
    R("pol04-key-terms-optional-set-business", {"terms": "key-terms", "optional_key": True}, {"keys": True, "plan": "business"}, expect=OK, basis={"business_plan:{key}"}),
    R("pol04-key-terms-required-unset-business", {"terms": "key-terms", "key": True}, {"plan": "business"}, expect=(False, "needs_key", "needs_key", "POL-12")),
    R("pol04-license-blocked", {"terms": "license"}, expect=(False, "skipped", "licence", "POL-04"), link=True, reason="skipped: license terms (licence profile corporate)"),
    R("pol04-license-allowed", {"terms": "license"}, {"allow": "active"}, expect=OK, basis={"allow:LEGAL-1"}),
    R("pol04-license-expired", {"terms": "license"}, {"allow": "expired"}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-license-beyond-cap", {"terms": "license"}, {"allow": "beyond_cap"}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-license-not-yet-decided", {"terms": "license"}, {"allow": "future"}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-nc-blocked", {"terms": "noncommercial"}, expect=(False, "skipped", "licence", "POL-04"), reason="skipped: noncommercial terms (licence profile corporate)"),
    R("pol04-nc-allowed", {"terms": "noncommercial"}, {"allow": "active"}, expect=OK, basis={"allow:LEGAL-1"}),
    R("pol04-unknown", {"terms": "unknown"}, {"preset": "deep"}, expect=(False, "skipped", "licence", "POL-04"), reason="skipped: unknown terms"),
    R("pol04-unknown-with-allow-entry", {"terms": "unknown"}, {"preset": "deep", "allow": "active"}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-research-covered", {"terms": "noncommercial"}, {"profile": "research", "research": "provider"}, expect=OK, basis={"research:LEGAL-R"}),
    R("pol04-research-not-covered", {"terms": "noncommercial"}, {"profile": "research", "research": "other"}, expect=(False, "skipped", "licence", "POL-04"), reason="outside the research basis scope"),
    R("pol04-research-unknown", {"terms": "unknown"}, {"profile": "research", "research": "*", "preset": "deep"}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-research-key-terms", {"terms": "key-terms", "key": True}, {"profile": "research", "research": "*", "keys": True}, expect=(False, "skipped", "licence", "POL-04")),
    R("pol04-research-license-star", {"terms": "license"}, {"profile": "research", "research": "*"}, expect=OK, basis={"research:LEGAL-R"}),
    R("pol04-aggregator-partial", {"sources": [("open", "open"), ("nc", "noncommercial")]}, expect=OK, sources={"open"}, blocked={"nc"}),
    R("pol04-aggregator-none", {"sources": [("lic", "license"), ("nc", "noncommercial")]}, expect=(False, "skipped", "licence", "POL-04"), sources=set(), link=True, reason="skipped: noncommercial terms"),
    R("pol04-aggregator-unknown-feed", {"sources": [("open", "open"), ("unk", "unknown")]}, {"preset": "deep"}, expect=OK, sources={"open"}, blocked={"unk"}),
    R("pol04-aggregator-allowed-feed", {"sources": [("open", "open"), ("nc", "noncommercial")]}, {"allow": "active"}, expect=OK, sources={"open", "nc"}, basis={"open", "allow:LEGAL-1"}),
    # ---- POL-05 TLP ---------------------------------------------------------------------
    R("pol05-clear-trusted", ctx={"tlp": "clear"}, expect=OK),
    R("pol05-green-community", {"tier": "community"}, {"tlp": "green"}, expect=OK),
    R("pol05-amber-community", {"tier": "community"}, {"tlp": "amber"}, expect=OK),
    R("pol05-amber-trusted", ctx={"tlp": "amber"}, expect=OK),
    R("pol05-amber-reuses", {"reuses": True}, {"tlp": "amber"}, expect=(False, "skipped", "tlp", "POL-05"), reason="may reuse submitted values"),
    R("pol05-green-reuses", {"reuses": True}, {"tlp": "green"}, expect=OK),
    R("pol05-amber-unknown-tier", {"tier": "unknown"}, {"tlp": "amber", "allow_unknown": True, "preset": "deep"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-strict-trusted", ctx={"tlp": "amber+strict"}, expect=OK),
    R("pol05-strict-community", {"tier": "community"}, {"tlp": "amber+strict"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-red-third-party", ctx={"tlp": "red"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-red-none", {"disclosure": "none"}, {"tlp": "red"}, expect=OK),
    R("pol05-red-internal", {"disclosure": "internal"}, {"tlp": "red", "settings": {"misp_url": "https://misp.corp.example.test"}}, expect=OK),
    R("pol05-publishes-clear", {"publishes": True}, {"tlp": "clear"}, expect=(False, "skipped", "policy", "POL-05"), reason="rule 7"),
    R("pol05-publishes-explicit-green", {"publishes": True}, {"tlp": "green", "explicit": True}, expect=(False, "skipped", "policy", "POL-05")),
    R("pol05-red-light-own-proxy", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep", "settings": PROXY}, "domain:acme-corp.com", expect=OK),
    R("pol05-red-light-own-no-egress", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep"}, "domain:acme-corp.com", expect=(False, "skipped", "tlp", "POL-05"), reason="non-corporate egress"),
    R("pol05-red-light-own-override", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep", "egress_override": "IR-77 isolated lab"}, "domain:acme-corp.com", expect=OK),
    R("pol05-red-light-not-own", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep", "settings": PROXY}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-red-light-third-party-hosted", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep", "settings": PROXY}, "domain:acme-cdn.com", expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-red-active-own-wrong-profile", ACTIVE, {"tlp": "red", "mode": "active", "preset": "deep", "settings": PROXY, "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:acme-corp.com", expect=(False, "skipped", "tlp", "POL-05"), reason="proxy_active"),
    R("pol05-strict-light-not-own", LIGHT, {"tlp": "amber+strict", "mode": "light", "preset": "deep"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-amber-light-not-own", LIGHT, {"tlp": "amber", "mode": "light", "preset": "deep"}, expect=OK),
    R("pol05-run-tlp-red", run={"tlp": "red"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-run-tlp-green-over-amber", {"reuses": True}, {"tlp": "amber"}, run={"tlp": "green"}, expect=OK),
    R("pol05-seed-tlp-red", ctx={"seed_tlp": "red"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-unreadable-tlp", ctx={"tlp": "purple"}, expect=(False, "skipped", "tlp", "POL-05")),
    # A2: LIGHT/ACTIVE cases are at least AMBER, whatever --tlp says
    R("pol05-light-case-clear-unknown", {"tier": "unknown"}, {"tlp": "clear", "mode": "light", "preset": "deep", "allow_unknown": True}, expect=(False, "skipped", "tlp", "POL-05"), reason="TLP:AMBER"),
    R("pol05-light-case-clear-reuses", {"reuses": True}, {"tlp": "clear", "mode": "light"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("pol05-passive-case-clear-unknown", {"tier": "unknown"}, {"tlp": "clear", "preset": "deep", "allow_unknown": True}, expect=OK),
    # an egress profile that cannot carry contact does not lift the TLP:RED target rule
    R("pol05-red-active-own-tor", ACTIVE, {"tlp": "red", "mode": "active", "preset": "deep", "settings": {"proxy_active": "socks5h://127.0.0.1:9050"}, "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:acme-corp.com", expect=(False, "skipped", "tlp", "POL-05"), reason="Tor"),
    R("pol05-red-active-own-research-proxy", ACTIVE, {"tlp": "red", "mode": "active", "preset": "deep", "settings": {"proxy_active": "http://research-proxy.example:3128"}, "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:acme-corp.com", expect=OK),
    R("pol05-red-light-own-bad-proxy", LIGHT, {"tlp": "red", "mode": "light", "preset": "deep", "settings": {"proxy_light": "ftp://proxy.example:21"}}, "domain:acme-corp.com", expect=(False, "skipped", "tlp", "POL-05"), reason="unsupported proxy scheme"),
    # a target-contact module that also queries a provider API is bound by that provider's TLP ceiling
    R("pol05-target-with-community-api-strict", {**LIGHT, "target_api": True, "tier": "community"}, {"tlp": "amber+strict", "mode": "light", "preset": "deep"}, "domain:acme-corp.com", expect=(False, "skipped", "tlp", "POL-05"), reason="also queried"),
    R("pol05-target-with-trusted-api-strict", {**LIGHT, "target_api": True}, {"tlp": "amber+strict", "mode": "light", "preset": "deep"}, "domain:acme-corp.com", expect=OK),
    # ---- POL-06 tier --------------------------------------------------------------------
    R("pol06-green-unknown-no-flag", {"tier": "unknown"}, {"tlp": "green", "preset": "deep"}, expect=(False, "skipped", "tier", "POL-06"), reason="--allow-unknown"),
    R("pol06-green-unknown-domain", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, expect=OK),
    R("pol06-clear-unknown-email", {"tier": "unknown"}, {"tlp": "clear", "preset": "deep", "allow_unknown": True, "purpose": "IR-1"}, "email:ana@example.com", expect=(False, "skipped", "tier", "POL-06")),
    R("pol06-green-unknown-cnpj", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, "cnpj:00000000000191", expect=(False, "skipped", "tier", "POL-06")),
    R("pol06-green-unknown-keyword", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, "keyword:acme", expect=(False, "skipped", "tier", "POL-06")),
    R("pol06-green-unknown-company", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, "company_name:Acme Corp", expect=(False, "skipped", "tier", "POL-06")),
    R("pol06-green-unknown-ipv4", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, "ipv4:8.8.8.8", expect=OK),
    R("pol06-green-community-keyword", {"tier": "community"}, {"tlp": "green"}, "keyword:acme", expect=OK),
    # a target module that queries an unknown-tier API: POL-06 in a passive case (light_for_own_assets),
    # POL-05 in a LIGHT case (never below TLP:AMBER, A2)
    R("pol06-target-with-unknown-api", {**LIGHT, "target_api": True, "tier": "unknown"}, {"tlp": "green", "preset": "deep", "settings": {"light_for_own_assets": True}}, "domain:acme-corp.com", expect=(False, "skipped", "tier", "POL-06")),
    R("pol06-target-with-unknown-api-light-case", {**LIGHT, "target_api": True, "tier": "unknown"}, {"tlp": "green", "mode": "light", "preset": "deep", "allow_unknown": True}, expect=(False, "skipped", "tlp", "POL-05")),
    # ---- POL-07 privacy -----------------------------------------------------------------
    R("pol07-secret-third-party", {"accepts": ("jwt",)}, {"tlp": "clear", "explicit": True}, JWT, expect=(False, "skipped", "policy", "POL-07"), reason="secret value (jwt)"),
    R("pol07-secret-internal", {"accepts": ("jwt",), "disclosure": "internal"}, {"settings": {"misp_url": "https://misp.corp.example.test"}}, JWT, expect=(False, "skipped", "policy", "POL-07")),
    R("pol07-secret-target", {**LIGHT, "accepts": ("jwt",)}, {"mode": "light", "preset": "deep"}, JWT, expect=(False, "skipped", "policy", "POL-07")),
    R("pol07-secret-offline", {"accepts": ("jwt",), "disclosure": "none"}, entity=JWT, expect=OK),
    R("pol07-seeds-typed", {"run_on": "seeds"}, expect=OK),
    R("pol07-seeds-pivot", {"run_on": "seeds"}, run={"seed": False}, expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-seeds-unconfirmed", {"run_on": "seeds"}, {"unconfirmed": True}, expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-seeds-text", {"run_on": "seeds"}, run={"provenance": TEXT}, expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-email-no-purpose", entity="email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07"), reason="--purpose"),
    R("pol07-email-reviewed", {"review": True}, {"purpose": "IR-1"}, "email:ana@example.com", expect=OK),
    R("pol07-email-unreviewed", ctx={"purpose": "IR-1"}, entity="email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07"), reason="personal-data review"),
    R("pol07-email-unreviewed-explicit", ctx={"purpose": "IR-1", "explicit": True}, entity="email:ana@example.com", expect=OK),
    R("pol07-username-unreviewed", ctx={"purpose": "IR-1"}, entity="username:octocat", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-verified", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1"}, "email:ana@acme-corp.com", expect=OK),
    R("pol07-breach-attested", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1"}, "email:ana@acme-attested.com", expect=OK),
    R("pol07-breach-confirmed", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1"}, "email:ana@acme-confirmed.com", expect=(False, "skipped", "privacy", "POL-07"), reason="breach check skipped: not an org domain"),
    R("pol07-breach-seeded", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1"}, "email:ana@acme-seeded.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-all-seed", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1", "breach_scope": "all"}, "email:ana@example.com", expect=OK),
    R("pol07-breach-all-pivot", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1", "breach_scope": "all"}, "email:ana@example.com", run={"seed": False}, expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-own-scope", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1", "breach_scope": "own"}, "email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-all-text", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1", "breach_scope": "all"}, "email:ana@example.com", run={"provenance": TEXT}, expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-all-unconfirmed", {"run_on": "own_assets", "review": True}, {"purpose": "IR-1", "breach_scope": "all", "unconfirmed": True}, "email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-breach-all-no-purpose", {"run_on": "own_assets", "review": True}, {"breach_scope": "all"}, "email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-none-personal-no-purpose", {"disclosure": "none"}, entity="email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-none-personal-purpose", {"disclosure": "none"}, {"purpose": "IR-1"}, "email:ana@example.com", expect=OK),
    R("pol07-dns-only-email", {"doh": True}, {"purpose": "IR-1"}, "email:ana@example.com", expect=OK),
    R("pol07-doctor-benign-email", ctx={"path": "doctor"}, entity="email:someone@example.com", expect=OK),
    R("pol07-doctor-other-email", ctx={"path": "doctor"}, entity="email:ana@example.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("pol07-cnpj-needs-no-purpose", entity="cnpj:00000000000191", expect=OK),
    R("pol07-fetches-recipient-token", {"fetches": True}, {"preset": "deep"}, URL_TOKEN, expect=(False, "skipped", "policy", "GUARD-02"), reason="--confirm-url"),
    R("pol07-fetches-token-confirmed", {"fetches": True}, {"preset": "deep", "confirmed": [URL_TOKEN[4:]]}, URL_TOKEN, expect=OK),
    R("pol07-fetches-cached-only", {"fetches": True, "tags": {"cached_only"}}, entity=URL_TOKEN, expect=OK),
    R("pol07-fetches-plain-url", {"fetches": True}, {"preset": "deep"}, "url:https://example.com/", expect=OK),
    # ---- POL-08 own assets --------------------------------------------------------------
    R("pol08-no-profile", {"run_on": "own_assets_only"}, {"org": False}, "domain:acme-corp.com", expect=(False, "skipped", "own_asset", "POL-08"), reason="no org profile (v3lum org)"),
    R("pol08-txt-verified", {"run_on": "own_assets_only"}, entity="domain:acme-corp.com", expect=OK),
    R("pol08-attested", {"run_on": "own_assets_only"}, entity="domain:acme-attested.com", expect=OK),
    R("pol08-confirmed", {"run_on": "own_assets_only"}, entity="domain:acme-confirmed.com", expect=(False, "skipped", "own_asset", "POL-08")),
    R("pol08-seeded", {"run_on": "own_assets_only"}, entity="domain:acme-seeded.com", expect=(False, "skipped", "own_asset", "POL-08")),
    R("pol08-subdomain", {"run_on": "own_assets_only"}, entity="domain:mail.acme-corp.com", expect=OK),
    R("pol08-unrelated", {"run_on": "own_assets_only"}, expect=(False, "skipped", "own_asset", "POL-08")),
    R("pol08-suffix-lookalike", {"run_on": "own_assets_only"}, entity="domain:evilacme-corp.com", expect=(False, "skipped", "own_asset", "POL-08")),
    # ---- POL-09 opsec -------------------------------------------------------------------
    R("pol09-light-passive", LIGHT, {"preset": "deep"}, expect=(False, "skipped", "opsec", "POL-09"), reason="needs --mode light: contacts the target"),
    R("pol09-active-light", ACTIVE, {"preset": "deep", "mode": "light"}, expect=(False, "skipped", "opsec", "POL-09")),
    R("pol09-active-passive", ACTIVE, {"preset": "deep"}, expect=(False, "skipped", "opsec", "POL-09")),
    R("pol09-light-mode-active", LIGHT, {"preset": "deep", "mode": "active"}, expect=OK),
    R("pol09-light-own-assets-verified", LIGHT, {"preset": "deep", "settings": {"light_for_own_assets": True}}, "domain:acme-corp.com", expect=OK),
    R("pol09-light-own-assets-other", LIGHT, {"preset": "deep", "settings": {"light_for_own_assets": True}}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol09-light-own-assets-pivot", LIGHT, {"preset": "deep", "settings": {"light_for_own_assets": True}}, "domain:acme-corp.com", run={"seed": False}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol09-active-own-assets-setting", ACTIVE, {"preset": "deep", "settings": {"light_for_own_assets": True}}, "domain:acme-corp.com", expect=(False, "skipped", "opsec", "POL-09")),
    # ---- POL-10 rules of engagement -----------------------------------------------------
    R("pol10-active-no-ref", ACTIVE, {"preset": "deep", "mode": "active"}, expect=(False, "skipped", "authorization", "POL-10")),
    R("pol10-active-placeholder", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "confirmed"}, expect=(False, "skipped", "authorization", "POL-10")),
    R("pol10-active-test", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "TEST"}, expect=(False, "skipped", "authorization", "POL-10")),
    R("pol10-active-malformed", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "-bad ref"}, expect=(False, "skipped", "authorization", "POL-10")),
    R("pol10-active-no-scope", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001"}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol10-active-scope-mismatch", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"ref": "CHG-OTHER", "hosts": ("example.com",)}}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol10-active-window-closed", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("example.com",), "window_ok": False}}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol10-active-outside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, expect=(False, "skipped", "scope", "POL-10"), reason="outside the scope"),
    R("pol10-active-inside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:acme-corp.com", expect=OK),
    R("pol10-active-pivot-inside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:www.acme-corp.com", run={"seed": False}, expect=OK),
    R("pol10-active-pivot-outside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "domain:cdn.example.net", run={"seed": False}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol10-active-ip-inside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"ips": ("203.0.113.0/24",)}}, "ipv4:203.0.113.10", expect=OK),
    R("pol10-active-url-inside", ACTIVE, {"preset": "deep", "mode": "active", "authorization_ref": "CHG-2026-001", "scope": {"hosts": ("acme-corp.com",)}}, "url:https://acme-corp.com/login", expect=OK),
    R("pol10-light-pivot", LIGHT, {"preset": "deep", "mode": "light"}, run={"seed": False}, expect=(False, "skipped", "scope", "POL-10"), reason="pivots never inherit scope"),
    R("pol10-light-typed", LIGHT, {"preset": "deep", "mode": "light"}, expect=OK),
    R("pol10-light-text", LIGHT, {"preset": "deep", "mode": "light"}, run={"provenance": TEXT}, expect=(False, "skipped", "scope", "POL-10")),
    R("pol10-light-unconfirmed", LIGHT, {"preset": "deep", "mode": "light", "unconfirmed": True}, expect=(False, "skipped", "scope", "POL-10")),
    # ---- POL-11 egress country ----------------------------------------------------------
    R("pol11-needs-br-unset", {"requires_egress": {"BR"}}, expect=(False, "skipped", "egress_country", "POL-11"), link=True, reason="needs BR egress"),
    R("pol11-br-set", {"requires_egress": {"BR"}}, {"settings": {"egress_country": "BR"}}, expect=OK),
    R("pol11-us-set", {"requires_egress": {"BR"}}, {"settings": {"egress_country": "US"}}, expect=(False, "skipped", "egress_country", "POL-11")),
    # ---- POL-12 keys and configuration --------------------------------------------------
    R("pol12-missing-key", {"key": True}, expect=(False, "needs_key", "needs_key", "POL-12"), link=True),
    R("pol12-key-configured", {"key": True}, {"keys": True}, expect=OK),
    R("pol12-internal-unconfigured", {"disclosure": "internal"}, expect=(False, "skipped", "config", "POL-12"), reason="misp_url"),
    R("pol12-contact-ua-missing", {"contact_ua": True}, expect=(False, "skipped", "config", "POL-12"), reason="contact_email"),
    R("pol12-contact-ua-set", {"contact_ua": True}, {"settings": {"contact_email": "soc@acme-corp.com"}}, expect=OK),
    # ---- POL-13 packages ----------------------------------------------------------------
    R("pol13-missing-package", {"requires_packages": ("websocket",)}, expect=(False, "unavailable", "package", "POL-13"), reason="websocket"),
    R("pol13-present-package", {"requires_packages": ("dns",)}, expect=OK),
    # ---- POL-14 datasets ----------------------------------------------------------------
    R("pol14-large-missing-scan", {"disclosure": "none", "dataset": "large"}, expect=(False, "unavailable", "dataset", "POL-14"), reason="v3lum data update"),
    R("pol14-large-missing-run", {"disclosure": "none", "dataset": "large"}, {"path": "run"}, expect=OK),
    R("pol14-small-missing-scan", {"disclosure": "none", "dataset": "small"}, expect=OK),
    R("pol14-missing-offline", {"disclosure": "none", "dataset": "small"}, {"offline": True}, expect=(False, "unavailable", "dataset", "POL-14")),
    R("pol14-large-present", {"disclosure": "none", "dataset": "large", "dataset_present": True}, expect=OK),
    # ---- POL-15 quota -------------------------------------------------------------------
    R("pol15-provider-exhausted", {"quota": True}, {"quota_exhausted": True}, expect=(False, "quota", "quota", "POL-15"), link=True),
    R("pol15-provider-ok", {"quota": True}, expect=OK),
    R("pol15-legacy-daily", {"daily_quota": 50}, {"legacy_exhausted": True}, expect=(False, "quota", "quota", "POL-15"), link=True),
    R("pol15-legacy-not-used", {"daily_quota": 50}, expect=OK),
    # ---- POL-16 circuit -----------------------------------------------------------------
    R("pol16-host-in-circuit", ctx={"circuit": "module"}, expect=(False, "blocked", "circuit", "POL-16"), link=True),
    R("pol16-other-host", ctx={"circuit": "other"}, expect=OK),
    R("pol16-wildcard-host", {"wildcard": True}, {"circuit": "module"}, expect=(False, "blocked", "circuit", "POL-16")),
    R("pol16-target-host", LIGHT, {"preset": "deep", "mode": "light", "circuit": "entity"}, expect=(False, "blocked", "circuit", "POL-16")),
    # ---- first failure wins -------------------------------------------------------------
    R("order-notdefault-before-offline", {"default_enabled": False}, {"offline": True}, expect=(False, "skipped", "not_default", "POL-01")),
    R("order-offline-before-licence", {"terms": "noncommercial"}, {"offline": True}, expect=(False, "unavailable", "offline", "POL-03")),
    R("order-licence-before-tlp", {"terms": "noncommercial"}, {"tlp": "red"}, expect=(False, "skipped", "licence", "POL-04")),
    R("order-tlp-before-tier", {"tier": "unknown"}, {"tlp": "amber", "preset": "deep"}, expect=(False, "skipped", "tlp", "POL-05")),
    R("order-tier-before-privacy", {"tier": "unknown"}, {"tlp": "green", "preset": "deep", "allow_unknown": True}, "email:ana@example.com", expect=(False, "skipped", "tier", "POL-06")),
    R("order-privacy-before-own-asset", {"run_on": "own_assets_only"}, entity="email:ana@acme-corp.com", expect=(False, "skipped", "privacy", "POL-07")),
    R("order-opsec-before-keys", {**LIGHT, "known_key": "shodan"}, {"preset": "deep"}, expect=(False, "skipped", "opsec", "POL-09")),
    R("order-egress-before-keys", {"requires_egress": {"BR"}, "key": True}, expect=(False, "skipped", "egress_country", "POL-11")),
    R("order-keys-before-packages", {"key": True, "requires_packages": ("websocket",)}, expect=(False, "needs_key", "needs_key", "POL-12")),
    R("order-quota-before-circuit", {"quota": True}, {"quota_exhausted": True, "circuit": "module"}, expect=(False, "quota", "quota", "POL-15")),
]


# --------------------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------------------


class FakeScope:
    """Duck-typed scope file (the WP11 Scope API): validate/matches_host/matches_ip/matches_url."""

    def __init__(self, ref: str = "CHG-2026-001", hosts: tuple[str, ...] = (), ips: tuple[str, ...] = (), window_ok: bool = True) -> None:
        self.authorization_ref = ref
        self.hosts = tuple(hosts)
        self.nets = [ipaddress.ip_network(n) for n in ips]
        self.window_ok = window_ok
        self.sha256 = "0" * 64

    def validate(self, ref: str, now: Any) -> list[str]:
        problems = []
        if ref != self.authorization_ref:
            problems.append("authorization_ref mismatch")
        if not self.window_ok:
            problems.append("outside the scope window")
        return problems

    def matches_host(self, host: str) -> bool:
        return any(host == h or host.endswith("." + h) for h in self.hosts)

    def matches_ip(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.nets)

    def matches_url(self, url: str) -> bool:
        return self.matches_host(url_host(url))


class FakeQuota:
    def __init__(self, providers: set[str] = frozenset(), modules: set[str] = frozenset()) -> None:  # type: ignore[assignment]
        self.providers = set(providers)
        self.modules = set(modules)
        self.calls: list[tuple[str, str]] = []

    def exhausted_provider(self, provider: str, *, priority: str = "seed", scope_key: str = "egress") -> bool:
        self.calls.append((provider, priority))
        return provider in self.providers

    def exhausted(self, module: str, limit: int | None, day: str | None = None) -> bool:
        return module in self.modules


def _slug(row_id: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", row_id.lower()).strip("_")[:56]


def _run(self: Any, entity: Entity, ctx: Any) -> Any:
    return self.result(entity)


def build_module(name: str, spec: dict[str, Any]) -> Any:
    """Register the row's provider (when the module needs one) and module; return the class."""
    spec = dict(spec)
    opsec = Opsec.parse(spec.get("opsec", "passive"))
    disclosure = spec.get("disclosure", "target" if opsec >= Opsec.LIGHT else "third_party")
    accepts = tuple(spec.get("accepts", ALL_TYPES))
    if spec.get("unregistered"):
        body = {
            "name": name, "title": name, "description": "unregistered", "category": "utility", "accepts": {EntityType.parse(t) for t in accepts},
            "terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": (), "run": _run,
        }
        return type(name, (module_mod.Module,), body)
    pid = "pp_" + name[3:]
    base = name.replace("_", "-") + ".example.test"
    attrs: dict[str, Any] = {"opsec": opsec, "disclosure": disclosure, "run_on": spec.get("run_on", "any"), "tags": set(spec.get("tags", ()))}
    classes = ["open"]
    tier = spec.get("tier", "trusted")
    if spec.get("doh"):
        attrs.update(provider="core_doh", sources=("core_doh.resolvers",), hosts=(), access_model="free_noauth_unlimited", terms="open", max_requests=0, expected_latency=1.0)
    elif disclosure in ("third_party", "internal") or spec.get("target_api"):
        sources = spec.get("sources") or [("main", spec.get("terms", "open"))]
        classes = [c for _sid, c in sources]
        src_block = {
            sid: {"terms": {"class": cls_, "evidence_url": "https://terms.example.test/", "quote": "synthetic terms", "checked_at": "2026-11-26", "reviewer": "tests", "free_plan_business_use": True if spec.get("free_business") else None}}
            for sid, cls_ in sources
        }
        host = f"*.{base}" if spec.get("wildcard") else f"api.{base}"
        key = f"k_{name}"
        fragment = provider_fragment(
            pid, hosts=(host,), tier=tier, sources=src_block, keys={key: "row key"} if spec.get("key") or spec.get("optional_key") else None,
            publishes_queries=bool(spec.get("publishes")), reuses_queries=bool(spec.get("reuses")), fetches_target=bool(spec.get("fetches")),
        )
        if disclosure == "internal":
            fragment.update(internal=True, hosts=[], hosts_from_settings=["misp_url"])
        if spec.get("review"):
            fragment["personal_data_review"] = {"basis": "DPIA-2026-01", "reviewer": "dpo", "date": "2026-11-20"}
        if spec.get("quota"):
            fragment["quota"] = {"scope": "egress_ip", "day": 100, "published": True, "evidence_url": "https://quota.example.test/limits", "safety_margin": 0.8}
        if spec.get("contact_ua"):
            fragment["http_profile"] = {"user_agent": "contact"}
        providers_mod.register(fragment, origin="tests")
        attrs.update(provider=pid, sources=tuple(f"{pid}.{sid}" for sid, _c in sources), hosts=() if disclosure == "internal" else (host,), max_requests=1, expected_latency=1.0)
        attrs["terms"] = providers_mod.most_restrictive(classes)
        if disclosure == "third_party":
            attrs["access_model"] = "free_noauth_unlimited"
        if spec.get("key"):
            attrs["requires_keys"] = (key,)
        if spec.get("optional_key"):
            attrs["optional_keys"] = (key,)
    elif disclosure == "none" and spec.get("dataset"):
        ds_name = f"ds_{name}.json"
        fragment = provider_fragment(pid, hosts=(f"data.{base}",), sources={"ds": {"dataset": ds_name}})
        providers_mod.register(fragment, origin="tests")
        large = spec["dataset"] == "large"
        datasets.register_dataset(ds_name, f"https://data.{base}/ds.json", licence="CC0-1.0", terms_class="open", provider=pid, source=f"{pid}.ds", large=large)
        attrs.update(sources=(f"{pid}.ds",), terms="open")
        if spec.get("dataset_present"):
            (paths.datasets_dir() / ds_name).write_text("{}", encoding="utf-8")
    else:
        attrs["terms"] = "open"
    for name_ in ("requires_egress", "requires_packages", "daily_quota"):
        if name_ in spec:
            attrs[name_] = frozenset(spec[name_]) if name_ == "requires_egress" else spec[name_]
    if spec.get("known_key"):
        attrs["requires_keys"] = tuple(attrs.get("requires_keys", ())) + (spec["known_key"],)
    worst = providers_mod.most_restrictive(classes)
    never_default = opsec >= Opsec.LIGHT or worst == "unknown" or (tier == "unknown" and disclosure == "third_party") or (spec.get("fetches") and "cached_only" not in attrs["tags"])
    attrs["default_enabled"] = spec.get("default_enabled", not never_default)
    return define_module(name, accepts, _run, **attrs)


def _entity(text: str) -> Entity:
    etype, _, value = text.partition(":")
    return Entity.make(EntityType.parse(etype), value)


def _allow_entry(sid: str, kind: str) -> dict[str, Any]:
    decided, review = ALLOW_KINDS[kind]
    return {
        "source_id": sid, "basis": "provider_grant", "scope": "own-network defence only, no resale", "legal_ref": "LEGAL-1", "approver": "legal (DPO office)",
        "decided_at": decided, "review_by": review, "evidence_url": "https://terms.example.test/", "quote": "written permission",
    }


def build_context(spec: dict[str, Any], cls: Any, entity: Entity, tmp_path: Path) -> PolicyContext:
    c = dict(spec)
    name = cls.name
    opts = ScanOptions(
        tlp=c.get("tlp", "amber"),
        mode=Opsec.parse(c.get("mode", "passive")),
        preset=c.get("preset", "quick"),
        include_disabled=bool(c.get("include_disabled")),
        offline=bool(c.get("offline")),
        purpose=c.get("purpose", ""),
        breach_scope=c.get("breach_scope", "own"),
        allow_unknown=bool(c.get("allow_unknown")),
        authorization_ref=c.get("authorization_ref", ""),
        egress_override=c.get("egress_override", ""),
        licence_profile=c.get("profile", ""),
    )
    if c.get("seed_tlp"):
        opts.seed_tlp = {entity.key: c["seed_tlp"]}
    if c.get("unconfirmed"):
        opts.unconfirmed_seeds = {entity.key}
    opts.confirmed_urls = set(c.get("confirmed", ()))
    if "scope" in c:
        scope_spec = dict(c["scope"])
        opts.scope = FakeScope(scope_spec.get("ref", "CHG-2026-001"), tuple(scope_spec.get("hosts", ())), tuple(scope_spec.get("ips", ())), scope_spec.get("window_ok", True))
    cfg = Config()
    settings = dict(c.get("settings", {}))
    module_keys = tuple(getattr(cls, "requires_keys", ()) or ()) + tuple(getattr(cls, "optional_keys", ()) or ())
    if c.get("plan"):
        settings["key_plans"] = {k: c["plan"] for k in module_keys}
    cfg.settings.update(settings)
    keys = frozenset(module_keys) if c.get("keys") else frozenset()
    entries = [_allow_entry(sid, c["allow"]) for sid in getattr(cls, "sources", ())] if c.get("allow") else []
    data: dict[str, Any] = {"schema": "v3lum.licence_allow/1", "entries": entries}
    if c.get("research"):
        target = {"provider": str(getattr(cls, "provider", "")), "other": "otherprovider", "*": "*"}[c["research"]]
        data["research_basis"] = {"legal_ref": "LEGAL-R", "approver": "legal", "date": "2026-11-01", "scope": target}
    licence = LicenceState.from_dict(data)
    org = OrgProfile.from_dict(ORG) if c.get("org", True) else OrgProfile.empty()
    health = HealthState(tmp_path / f"health-{name}.json", autosave=False)
    if c.get("demoted"):
        for _ in range(5):
            health.record_run(name, 1.0, "blocked")
    quota = FakeQuota(providers={str(getattr(cls, "provider", ""))} if c.get("quota_exhausted") else set(), modules={name} if c.get("legacy_exhausted") else set())
    circuit: set[str] = set()
    if c.get("circuit") == "module":
        host = (getattr(cls, "hosts", ()) or ("none.example.test",))[0]
        circuit = {"x." + host[2:] if host.startswith("*.") else host}
    elif c.get("circuit") == "other":
        circuit = {"other.example.test"}
    elif c.get("circuit") == "entity":
        circuit = {policy._host_of(entity)}
    return PolicyContext(
        options=opts,
        config=cfg,
        providers=providers_mod.registry(),
        org=org,
        licence=licence,
        keys=keys,
        now=NOW,
        quota=quota,
        health=health,
        offline=bool(c.get("offline")),
        explicit=frozenset({name}) if c.get("explicit") else frozenset(),
        circuit=frozenset(circuit),
        path=c.get("path", "scan"),
        licence_profile=c.get("profile", "corporate"),
    )


def build_run(spec: dict[str, Any], entity: Entity) -> RunInfo:
    seed = spec.get("seed", True)
    return RunInfo(entity=entity, is_seed=seed, depth=0 if seed else 1, provenance=tuple(tuple(p) for p in spec.get("provenance", ())), tlp=spec.get("tlp", ""), case_id="case-1")


def evaluate(row: Row, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Decision, Any]:
    monkeypatch.setattr(module_mod, "package_available", lambda name: name not in MISSING_PACKAGES)
    name = "pm_" + _slug(row.id)
    cls = build_module(name, row.module)
    entity = _entity(row.entity)
    pctx = build_context(row.ctx, cls, entity, tmp_path)
    return decide(cls, entity, pctx, run=build_run(row.run, entity)), cls


def check(row: Row, decision: Decision, cls: Any) -> None:
    allowed, status, code, rule_id = row.expect
    got = (decision.allowed, decision.status.value, decision.reason_code, decision.rule_id)
    assert got == (allowed, status, code, rule_id), f"{row.id}: expected {row.expect}, got {got} ({decision.reason})"
    assert valid_reason(decision.status, decision.reason_code), f"{row.id}: non-canonical code {decision.reason_code!r}"
    if not decision.allowed:
        assert decision.reason_code in REASON_CODES
        assert f"[{decision.rule_id}]" in decision.reason, f"{row.id}: the rule id is not quoted in {decision.reason!r}"
    pid = str(getattr(cls, "provider", ""))
    if "link" in row.extra:
        assert decision.emit_manual_link is row.extra["link"], f"{row.id}: emit_manual_link {decision.emit_manual_link}"
    if "reason" in row.extra:
        assert row.extra["reason"] in decision.reason, f"{row.id}: {row.extra['reason']!r} not in {decision.reason!r}"
    if "sources" in row.extra:
        assert decision.allowed_sources == frozenset(f"{pid}.{s}" for s in row.extra["sources"]), f"{row.id}: {decision.allowed_sources}"
    if "blocked" in row.extra:
        assert set(decision.blocked_sources) == {f"{pid}.{s}" for s in row.extra["blocked"]}
        assert all(r.startswith("skipped: ") for r in decision.blocked_sources.values())
    if "basis" in row.extra:
        key = f"k_{cls.name}"
        assert set(decision.licence_basis.values()) == {b.replace("{key}", key) for b in row.extra["basis"]}, f"{row.id}: {decision.licence_basis}"


def run_rows(prefix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[tuple[Row, Decision, Any]]:
    out = []
    for row in ROWS:
        if row.id.startswith(prefix):
            decision, cls = evaluate(row, tmp_path, monkeypatch)
            check(row, decision, cls)
            out.append((row, decision, cls))
    assert out, f"no rows for {prefix}"
    return out


# --------------------------------------------------------------------------------------
# the table
# --------------------------------------------------------------------------------------


def test_table_size_and_unique_ids():
    ids = [r.id for r in ROWS]
    assert len(ids) >= 120
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("row", ROWS, ids=[r.id for r in ROWS])
def test_policy_table(row: Row, clean_registry, tmp_path, monkeypatch):
    decision, cls = evaluate(row, tmp_path, monkeypatch)
    check(row, decision, cls)


def test_all_decisions_use_canonical_reason_codes(clean_registry, tmp_path, monkeypatch):
    """Acceptance: every decision of the table uses a canonical A3 code with its Status mapping."""
    seen: set[str] = set()
    for row in ROWS:
        decision, _cls = evaluate(row, tmp_path, monkeypatch)
        assert valid_reason(decision.status, decision.reason_code)
        if not decision.allowed:
            assert REASON_CODES[decision.reason_code] is decision.status
            seen.add(decision.reason_code)
    expected = {"not_default", "demoted", "not_applicable", "policy", "offline", "licence", "tlp", "tier", "privacy", "own_asset", "opsec",
                "authorization", "scope", "egress_country", "needs_key", "config", "package", "dataset", "quota", "circuit"}
    assert expected <= seen


# --------------------------------------------------------------------------------------
# one test per rule (the enforcing tests named in policy.RULES)
# --------------------------------------------------------------------------------------


def test_pol01_selection(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol01", tmp_path, monkeypatch)}
    assert "--preset deep or -M" in results["pol01-optin-quick"].reason
    assert "run it with -M" in results["pol01-demoted"].reason and "BLOCKED on 5 consecutive runs" in results["pol01-demoted"].reason


def test_pol02_metadata_validity(clean_registry, tmp_path, monkeypatch):
    run_rows("pol02", tmp_path, monkeypatch)
    # a registered module whose file has a load error is refused as well
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_load_error_case", {"disclosure": "none"})
    module_mod._LOAD_ERRORS[cls.__module__] = "ImportError: broken"
    entity = _entity("domain:example.com")
    decision = decide(cls, entity, build_context({}, cls, entity, tmp_path), run=build_run({}, entity))
    assert (decision.allowed, decision.reason_code, decision.rule_id) == (False, "policy", "POL-02")


def test_pol03_offline(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol03", tmp_path, monkeypatch)}
    assert "offline" in results["pol03-offline-third-party"].reason


def test_pol04_licence(clean_registry, tmp_path, monkeypatch):
    results = {row.id: (d, cls) for row, d, cls in run_rows("pol04", tmp_path, monkeypatch)}
    nc, _ = results["pol04-nc-blocked"]
    assert nc.reason == "skipped: noncommercial terms (licence profile corporate) [POL-04]"
    assert nc.allowed_sources == frozenset() and nc.emit_manual_link
    partial, cls = results["pol04-aggregator-partial"]
    assert partial.allowed and partial.licence_basis == {f"{cls.provider}.open": "open"}
    assert "skipped by licence profile corporate" in partial.reason


def test_pol05_tlp(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol05", tmp_path, monkeypatch)}
    assert "TLP:RED" in results["pol05-red-third-party"].reason
    assert "AMBER+STRICT" in results["pol05-strict-community"].reason


def test_pol06_tier(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol06", tmp_path, monkeypatch)}
    for rid in ("pol06-green-unknown-keyword", "pol06-green-unknown-company", "pol06-green-unknown-cnpj"):
        assert "IOC types only" in results[rid].reason


def test_pol07_privacy(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol07", tmp_path, monkeypatch)}
    assert results["pol07-breach-own-scope"].reason == "breach check skipped: not an org domain [POL-07]"


def test_pol08_own_asset(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol08", tmp_path, monkeypatch)}
    assert results["pol08-no-profile"].reason == "no org profile (v3lum org) [POL-08]"
    assert "txt_verified or attested" in results["pol08-confirmed"].reason


def test_pol09_opsec(clean_registry, tmp_path, monkeypatch):
    run_rows("pol09", tmp_path, monkeypatch)


def test_pol10_rules_of_engagement(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol10", tmp_path, monkeypatch)}
    assert "placeholder" in results["pol10-active-placeholder"].reason
    assert "--scope FILE" in results["pol10-active-no-scope"].reason
    assert "mismatch" in results["pol10-active-scope-mismatch"].reason


def test_pol11_egress_country(clean_registry, tmp_path, monkeypatch):
    run_rows("pol11", tmp_path, monkeypatch)


def test_pol12_keys(clean_registry, tmp_path, monkeypatch):
    results = {row.id: (d, cls) for row, d, cls in run_rows("pol12", tmp_path, monkeypatch)}
    missing, cls = results["pol12-missing-key"]
    assert f"v3lum keys set k_{cls.name}" in missing.reason


def test_pol13_packages(clean_registry, tmp_path, monkeypatch):
    results = {row.id: d for row, d, _ in run_rows("pol13", tmp_path, monkeypatch)}
    assert "pip install" in results["pol13-missing-package"].reason


def test_pol14_datasets(clean_registry, tmp_path, monkeypatch):
    run_rows("pol14", tmp_path, monkeypatch)


def test_pol15_quota(clean_registry, tmp_path, monkeypatch):
    run_rows("pol15", tmp_path, monkeypatch)
    # the run priority reaches the quota book (seeds may use the seed reserve, P334)
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_quota_priority", {"quota": True})
    entity = _entity("domain:example.com")
    pctx = build_context({}, cls, entity, tmp_path)
    decide(cls, entity, pctx, run=RunInfo(entity=entity, is_seed=False, depth=2, priority="pivot2"))
    assert pctx.quota.calls[-1] == (cls.provider, "pivot2")


def test_pol16_circuit(clean_registry, tmp_path, monkeypatch):
    run_rows("pol16", tmp_path, monkeypatch)


def test_first_failure_wins(clean_registry, tmp_path, monkeypatch):
    run_rows("order", tmp_path, monkeypatch)


# --------------------------------------------------------------------------------------
# acceptance and API
# --------------------------------------------------------------------------------------


def test_shodan_internetdb_skipped_by_licence_under_shipped_corporate_profile():
    """Acceptance: the reference module is SKIPPED 'licence' and its manual link is requested."""
    module_mod.load_modules()
    cls = module_mod.REGISTRY["shodan_internetdb"]
    rt = make_runtime()
    pctx = policy.make_context(rt, ScanOptions(), path="scan")
    assert pctx.licence_profile == "corporate"
    ip = Entity.make(EntityType.IPV4, "8.8.8.8")
    decision = decide(cls, ip, pctx, run=RunInfo(entity=ip, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code, decision.rule_id) == (False, Status.SKIPPED, "licence", "POL-04")
    assert decision.emit_manual_link is True
    assert decision.reason.startswith("skipped: noncommercial terms (licence profile corporate)")
    assert decision.blocked_sources == {"shodan.internetdb": "skipped: noncommercial terms (licence profile corporate)"}
    assert cls.manual_link  # the engine renders it (P311)
    # an active licence_allow entry clears it (explicit legal decision)
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [_allow_entry("shodan.internetdb", "active")]}), encoding="utf-8")
    allow.chmod(0o600)
    cleared = decide(cls, ip, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ip, is_seed=True))
    assert cleared.allowed and cleared.licence_basis == {"shodan.internetdb": "allow:LEGAL-1"}


@pytest.mark.parametrize("cause", ["tlp_red_third_party", "exhausted_quota", "active_without_authorization"])
def test_run_single_refusals(cause, clean_registry, tmp_path, monkeypatch):
    """App.run_single-style refusals (path 'run', module selected explicitly): TLP:RED with a
    third-party module, an exhausted quota and ACTIVE without authorization (AR15)."""
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    spec, ctx, expected = {
        "tlp_red_third_party": ({}, {"tlp": "red"}, ("tlp", "POL-05")),
        "exhausted_quota": ({"quota": True}, {"quota_exhausted": True}, ("quota", "POL-15")),
        "active_without_authorization": (ACTIVE, {"mode": "active"}, ("authorization", "POL-10")),
    }[cause]
    cls = build_module(f"pm_run_{cause}"[:60], spec)
    entity = _entity("domain:example.com")
    pctx = build_context({**ctx, "path": "run", "explicit": True}, cls, entity, tmp_path)
    decision = decide(cls, entity, pctx, run=build_run({}, entity))
    assert (decision.allowed, decision.reason_code, decision.rule_id) == (False, *expected)


#: gating on shares_input (the v1 TLP:RED gate) - only policy.py may decide on it (acceptance 1).
_GATING = re.compile(
    r"_shares_input\s*\(|getattr\([^)\n]*[\"']shares_input[\"']|\b(?:if|elif|and|or|not|while)\b[^#\n]*\.shares_input\b"
)


def test_no_shares_input_gating_outside_policy():
    """Acceptance: decide() is the only gate - no other code path gates on shares_input."""
    root = Path(v3lum.__file__).resolve().parent
    offenders = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in ("core/policy.py", "core/module.py"):  # module.py derives the alias, policy.py is the gate
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _GATING.search(line):
                offenders.append(f"v3lum/{rel}:{lineno}: {line.strip()}")
    assert not offenders, "shares_input gating outside core/policy.py:\n" + "\n".join(offenders)


def test_rules_table_ids_tests_and_markdown():
    ids = [r.id for r in policy.RULES]
    assert ids == [f"POL-{i:02d}" for i in range(1, 17)] + ["GUARD-01", "GUARD-02"]
    assert policy.POLICY_VERSION == "council-1/2026-11-26"
    root = Path(__file__).resolve().parent.parent
    for r in policy.RULES:
        assert r.text and r.decisions and all(isinstance(d, str) and d for d in r.decisions)
        file_part, _, func = r.test.partition("::")
        source = (root / file_part).read_text(encoding="utf-8")
        assert re.search(rf"^def {re.escape(func)}\(", source, re.M), f"{r.id}: enforcing test {r.test} does not exist"
        assert policy.rule(r.id) is r
    md = policy.rules_markdown()
    assert all(f"| {r.id} |" in md for r in policy.RULES) and policy.POLICY_VERSION in md


def test_decision_validation_and_to_dict():
    with pytest.raises(ValueError):
        Decision(False, Status.SKIPPED, "tlp_red")  # not canonical
    with pytest.raises(ValueError):
        Decision(False, Status.SKIPPED, "quota")  # canonical, but QUOTA's code
    with pytest.raises(ValueError):
        Decision(True, Status.SKIPPED, "")
    d = Decision(False, Status.QUOTA, "quota", "x [POL-15]", "POL-15", allowed_sources={"a.b"}, emit_manual_link=True)
    assert isinstance(d.allowed_sources, frozenset) and hash(d)
    data = d.to_dict()
    assert json.loads(json.dumps(data)) == data and data["status"] == "quota" and data["allowed_sources"] == ["a.b"]


def test_authorization_reference_validation():
    for good in ("CHG-2026-001", "INC#42", "pentest/acme:2026", "abc"):
        assert policy.valid_authorization_ref(good), good
    for bad in ("", "  ", "confirmed", "YES", "ok", "none", "n/a", "test", "-x1", "ab", "has space", "x" * 65):
        assert not policy.valid_authorization_ref(bad), bad
        assert policy.authorization_problem(bad)


def test_entity_tlp_precedence_and_fail_closed(tmp_path):
    entity = _entity("domain:example.com")
    opts = ScanOptions(tlp="green")
    pctx = PolicyContext(options=opts, now=NOW)
    assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity)).value_str == "green"
    opts.seed_tlp = {entity.key: "amber"}
    assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity)).value_str == "amber"
    assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity, tlp="red")).value_str == "red"
    opts.seed_tlp = {entity.key: "ultraviolet"}
    assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity)).value_str == "red"


def test_entity_tlp_light_and_active_cases_are_at_least_amber():
    """A2: LIGHT/ACTIVE cases are never below TLP:AMBER, whoever built the RunInfo."""
    entity = _entity("domain:example.com")
    for mode in (Opsec.LIGHT, Opsec.ACTIVE):
        pctx = PolicyContext(options=ScanOptions(tlp="clear", mode=mode), now=NOW)
        assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity)).value_str == "amber"
        assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity, tlp="green")).value_str == "amber"
        assert policy.entity_tlp(entity, pctx, RunInfo(entity=entity, tlp="red")).value_str == "red"  # only raised
    passive = PolicyContext(options=ScanOptions(tlp="clear"), now=NOW)
    assert policy.entity_tlp(entity, passive, RunInfo(entity=entity)).value_str == "clear"


def test_live_registry_flags_win_over_stale_derived_attributes(clean_registry, tmp_path, monkeypatch):
    """A provider flag or tier recorded in the registry is enforced even when the module class
    carries an older (looser) derived value: the stricter of the two wins."""
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    entity = _entity("domain:example.com")
    publishing = build_module("pm_stale_publishes", {"publishes": True})
    monkeypatch.setattr(publishing, "publishes_queries", False)  # stale derived value
    d = decide(publishing, entity, build_context({"tlp": "clear"}, publishing, entity, tmp_path), run=build_run({}, entity))
    assert (d.allowed, d.reason_code, d.rule_id) == (False, "policy", "POL-05") and "rule 7" in d.reason
    reusing = build_module("pm_stale_reuses", {"reuses": True})
    monkeypatch.setattr(reusing, "reuses_queries", False)
    d = decide(reusing, entity, build_context({"tlp": "amber"}, reusing, entity, tmp_path), run=build_run({}, entity))
    assert (d.allowed, d.reason_code) == (False, "tlp")
    unknown = build_module("pm_stale_tier", {"tier": "unknown"})
    monkeypatch.setattr(unknown, "trust_tier", "trusted")
    d = decide(unknown, entity, build_context({"tlp": "green", "preset": "deep"}, unknown, entity, tmp_path), run=build_run({}, entity))
    assert (d.allowed, d.reason_code, d.rule_id) == (False, "tier", "POL-06")


def test_secret_values_never_reach_a_network_module(clean_registry, tmp_path, monkeypatch):
    """A8/A7: secret types (JWT, bot tokens, keys, card numbers) stay on the machine - also for an
    explicitly selected module at TLP:CLEAR; describe_policy says so."""
    results = {row.id: d for row, d, _ in run_rows("pol07-secret", tmp_path, monkeypatch)}
    assert "found credentials and keys are never used" in results["pol07-secret-third-party"].reason
    cls = build_module("pm_secret_describe", {"accepts": ("jwt", "domain")})
    text = "\n".join(policy.describe_policy(cls, build_context({}, cls, _entity("domain:example.com"), tmp_path)))
    assert "POL-07 privacy: secret values (jwt) are never sent to it" in text


def test_decide_fails_closed_outside_strict_mode(clean_registry, tmp_path, monkeypatch):
    from v3lum.core import vocab

    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_fail_closed", {})
    entity = _entity("domain:example.com")
    pctx = build_context({}, cls, entity, tmp_path)

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(policy, "_pol05_tlp", boom)
    with pytest.raises(RuntimeError):
        decide(cls, entity, pctx, run=build_run({}, entity))  # strict mode (tests): bugs surface
    monkeypatch.setattr(vocab, "strict_enabled", lambda: False)
    decision = decide(cls, entity, pctx, run=build_run({}, entity))
    assert (decision.allowed, decision.reason_code, decision.rule_id) == (False, "policy", "POL-02")


def test_policy_context_validates_path_and_defaults():
    with pytest.raises(ValueError):
        PolicyContext(path="somewhere")
    pctx = PolicyContext()
    assert isinstance(pctx.options, ScanOptions) and pctx.path == "scan" and pctx.licence_profile == "corporate"
    assert pctx.time().tzinfo is not None


class FakeRuntime:
    """The attributes make_context reads from a Runtime (config, now, org, providers, http circuit,
    meta, offline, quota, health)."""

    def __init__(self, *, keys: dict[str, str] | None = None, settings: dict[str, Any] | None = None, offline: bool = False) -> None:
        self.config = Config()
        self.config.file_keys.update(keys or {})
        self.config.settings.update(settings or {})
        self.meta: dict[str, Any] = {}
        self.offline = offline
        self.org = OrgProfile.from_dict(ORG)
        self._providers = None
        self.hosts: set[str] = set()
        self.http = type("Http", (), {"circuit_hosts": lambda _self: frozenset(self.hosts)})()
        self.quota = FakeQuota()

    def now(self) -> _dt.datetime:
        return NOW


def test_make_context_paths_explicit_and_runtime_facts():
    rt = FakeRuntime(settings={"egress_country": "BR"})
    opts = ScanOptions(include={"from_include"})
    with pytest.raises(ValueError):
        policy.make_context(rt, opts, path="nope")
    for path in policy.PATHS:
        pctx = policy.make_context(rt, opts, explicit=["picked"], path=path)
        assert pctx.path == path
        assert pctx.explicit == frozenset({"picked", "from_include"})
    pctx = policy.make_context(rt, opts)
    assert pctx.setting("egress_country") == "BR" and pctx.offline is False
    assert pctx.org is rt.org and pctx.config is rt.config and pctx.quota is rt.quota
    assert pctx.now == NOW and pctx.time() == NOW and pctx.health is policy.shared_health()
    assert pctx.providers is None and pctx.registry is providers_mod.registry()  # the live registry
    assert policy.make_context(FakeRuntime(offline=True), ScanOptions()).offline is True
    assert policy.make_context(rt, ScanOptions(offline=True)).offline is True


def test_make_context_keys_sightings_and_live_circuit():
    rt = FakeRuntime(keys={"shodan": "k" * 32, "abusech": ""})
    rt.meta["sightings_lookup"] = lambda entity: None
    pctx = policy.make_context(rt, ScanOptions())
    assert pctx.keys == frozenset({"shodan"})  # empty values are not configured keys
    assert callable(pctx.sightings)
    assert "api.example.test" not in pctx.circuit
    rt.hosts.add("api.example.test")  # tripped during the run: the policy context sees it live
    assert "api.example.test" in pctx.circuit and list(pctx.circuit) == ["api.example.test"] and len(pctx.circuit) == 1


def test_make_context_research_profile_needs_a_basis():
    rt = FakeRuntime()
    pctx = policy.make_context(rt, ScanOptions(licence_profile="research"))
    assert pctx.licence_profile == "corporate"  # fail closed
    assert any("licence_profile=research needs a recorded legal basis (docs/LEGAL.md)" in n for n in pctx.notes)
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"research_basis": {"legal_ref": "LEGAL-R", "approver": "legal", "date": "2026-11-01", "scope": "*"}}), encoding="utf-8")
    allow.chmod(0o600)
    research = policy.make_context(rt, ScanOptions(licence_profile="research"))
    assert research.licence_profile == "research" and research.licence.research_allowed(NOW)
    rt.config.settings["licence_profile"] = "research"  # the setting works like the flag
    assert policy.make_context(rt, ScanOptions()).licence_profile == "research"


def test_make_context_uses_the_runtime_health_state(tmp_path):
    rt = FakeRuntime()
    injected = HealthState(tmp_path / "h.json", autosave=False)
    rt.health = injected
    assert policy.make_context(rt, ScanOptions()).health is injected


def test_shared_health_reloads_after_another_writer():
    """One shared instance per file: another writer's records are adopted in place, so threads that
    hold the instance (engine workers, the PolicyContext) never write a stale copy back."""
    first = policy.shared_health()
    assert policy.shared_health() is first
    first.record_run("pm_mine", 1.0, "ok")
    other = HealthState.load(first.path)
    for _ in range(5):
        other.record_run("pm_other_writer", 1.0, "blocked")
    again = policy.shared_health()
    assert again is first and again.is_demoted("pm_other_writer")
    first.record_run("pm_mine", 1.0, "ok")  # a later record keeps the other writer's records
    on_disk = HealthState.load(first.path)
    assert on_disk.is_demoted("pm_other_writer") and on_disk.stats("pm_mine")["runs"] == 2


def test_shared_health_keeps_every_concurrent_record():
    """Engine worker threads record through the shared state at the same time: nothing is lost."""
    import threading

    barrier = threading.Barrier(6)

    def worker() -> None:
        barrier.wait()
        for _ in range(30):
            policy.shared_health().record_run("pm_busy", 0.1, "ok")

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert policy.shared_health().stats("pm_busy")["runs"] == 180
    assert HealthState.load(policy.shared_health().path).stats("pm_busy")["runs"] == 180


def test_licence_basis_values(clean_registry, tmp_path, monkeypatch):
    """Decision.licence_basis: 'open' | 'business_plan:<key>' | 'allow:<legal_ref>' | 'research:<legal_ref>'."""
    seen = set()
    for rid in ("pol04-open", "pol04-key-terms-business-plan", "pol04-license-allowed", "pol04-research-covered"):
        row = next(r for r in ROWS if r.id == rid)
        decision, cls = evaluate(row, tmp_path, monkeypatch)
        check(row, decision, cls)
        seen |= {v.split(":", 1)[0] for v in decision.licence_basis.values()}
    assert seen == {"open", "business_plan", "allow", "research"}


def test_watch_only_modules_refused_outside_watch(clean_registry, tmp_path, monkeypatch):
    run_rows("pol01-watch-only", tmp_path, monkeypatch)


def test_unknown_tier_refused_for_keyword_and_company_name(clean_registry, tmp_path, monkeypatch):
    for rid in ("pol06-green-unknown-keyword", "pol06-green-unknown-company"):
        row = next(r for r in ROWS if r.id == rid)
        decision, cls = evaluate(row, tmp_path, monkeypatch)
        check(row, decision, cls)


def test_effective_default_set(clean_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    open_cls = build_module("pm_eds_open", {"accepts": ("sha512",)})
    nc_cls = build_module("pm_eds_nc", {"accepts": ("sha512",), "terms": "noncommercial"})
    optin_cls = build_module("pm_eds_optin", {"accepts": ("sha512",), "default_enabled": False})
    email_cls = build_module("pm_eds_email", {"accepts": ("email",), "review": True})
    entity = _entity("domain:example.com")
    pctx = build_context({"explicit": True, "preset": "deep"}, optin_cls, entity, tmp_path)
    in_set = [cls for cls, _d in policy.effective_default_set("sha512", pctx)]
    assert open_cls in in_set and nc_cls not in in_set and optin_cls not in in_set  # preset/-M never leak in
    rows = {cls.name: d for cls, d in policy.effective_default_set(EntityType.SHA512, pctx, include_blocked=True)}
    assert rows["pm_eds_nc"].reason_code == "licence" and rows["pm_eds_optin"].reason_code == "not_default"
    assert rows["pm_eds_open"].allowed
    # personal types assume a recorded purpose (a plain scan of a personal seed always has one)
    assert email_cls in [c for c, _ in policy.effective_default_set("email", pctx)]
    assert not pctx.option("purpose")  # the caller's options are not changed


def test_describe_policy_explains_rules(clean_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_describe", {"sources": [("open", "open"), ("nc", "noncommercial")], "key": True, "requires_egress": {"BR"}, "run_on": "seeds"})
    entity = _entity("domain:example.com")
    pctx = build_context({"allow": "active"}, cls, entity, tmp_path)
    text = "\n".join(policy.describe_policy(cls, pctx))
    assert f"POL-04 licence (corporate): {cls.provider}.nc allowed (allow:LEGAL-1)" in text
    assert f"POL-04 licence_allow: {cls.provider}.nc by LEGAL-1" in text and "review by 2027-05-01" in text
    assert "POL-05 TLP: third-party provider (trusted-tier provider) - receives at most TLP:AMBER+STRICT" in text
    assert "POL-07 privacy: run_on seeds" in text
    assert "POL-11 egress: needs BR egress" in text
    assert f"POL-12 keys: requires k_{cls.name} (missing)" in text
    assert policy.POLICY_VERSION in text
    blocked = build_module("pm_describe_nc", {"terms": "noncommercial"})
    text = "\n".join(policy.describe_policy(blocked, build_context({}, blocked, entity, tmp_path)))
    assert "skipped: noncommercial terms (licence profile corporate); to clear it:" in text
    assert "not run by default" in text and "licence" in text


def test_reference_modules_under_the_shipped_defaults():
    """The four reference modules: shodan_internetdb licence-blocked; the DoH and offline ones run."""
    module_mod.load_modules()
    rt = FakeRuntime()
    pctx = policy.make_context(rt, ScanOptions(purpose="IR-2026-01"))
    cases = {
        "shodan_internetdb": ("ipv4:8.8.8.8", (False, "licence")),
        "dns_records": ("domain:example.com", (True, "")),
        "email_basics": ("email:ana@example.com", (True, "")),
        "ioc_extract": ("text_blob:indicators 203.0.113.1", (True, "")),
    }
    for name, (value, expected) in cases.items():
        cls = module_mod.REGISTRY[name]
        etype, _, raw = value.partition(":")
        entity = Entity.make(EntityType.parse(etype), raw)
        d = decide(cls, entity, pctx, run=RunInfo(entity=entity, is_seed=True))
        assert (d.allowed, d.reason_code) == expected, (name, d.reason)


def test_decision_carries_allowed_sources_on_later_refusals(clean_registry, tmp_path, monkeypatch):
    """A refusal after the licence step keeps the licence evaluation (coverage rows per feed)."""
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_carry", {"sources": [("open", "open"), ("nc", "noncommercial")]})
    entity = _entity("domain:example.com")
    decision = decide(cls, entity, build_context({"tlp": "red"}, cls, entity, tmp_path), run=build_run({}, entity))
    assert decision.reason_code == "tlp"
    assert decision.allowed_sources == frozenset({f"{cls.provider}.open"})
    assert set(decision.blocked_sources) == {f"{cls.provider}.nc"}


def test_decision_is_frozen_and_dataclass_replace_revalidates():
    d = Decision(True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.allowed = False  # type: ignore[misc]
    with pytest.raises(ValueError):
        dataclasses.replace(d, allowed=False)  # a refusal needs a canonical code


def test_contract_additions_names_resolve():
    """Every backticked v3lum.* name of docs/contract_additions/WP07.md is importable."""
    import importlib

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP07.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?![/\w])", doc)))  # schema ids (v3lum.x/1) excluded
    assert len(names) >= 25
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            try:
                for attr in parts[cut:]:
                    obj = getattr(obj, attr)
            except AttributeError:
                missing.append(dotted)
            break
        else:
            missing.append(dotted)
    assert not missing, missing


def test_pol02_refuses_classes_placed_in_the_registry_without_register(clean_registry, tmp_path, monkeypatch):
    """A class inserted into REGISTRY by hand has no derived provider flags (it could hide a
    publishes_queries provider): the gate refuses it (fail closed)."""
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    body = {
        "name": "pm_bypass_net", "title": "x", "description": "x", "category": "utility", "accepts": {EntityType.DOMAIN},
        "terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "third_party", "hosts": ("api.bypass.example.test",), "run": _run,
    }
    stub = type("pm_bypass_net", (module_mod.Module,), body)
    monkeypatch.setitem(module_mod.REGISTRY, stub.name, stub)
    entity = _entity("domain:example.com")
    decision = decide(stub, entity, build_context({"tlp": "clear"}, stub, entity, tmp_path), run=build_run({}, entity))
    assert (decision.allowed, decision.reason_code, decision.rule_id) == (False, "policy", "POL-02")
    assert "bypassed @register" in decision.reason
    # an offline (disclosure 'none') double gets no network at all: it is evaluated normally
    offline = build_module("pm_bypass_none", {"unregistered": True})
    monkeypatch.setitem(module_mod.REGISTRY, offline.name, offline)
    assert decide(offline, entity, build_context({}, offline, entity, tmp_path), run=build_run({}, entity)).allowed


def test_pol10_with_the_wp11_scope_file(clean_registry, tmp_path, monkeypatch):
    """POL-10 against the real Scope (v3lum.core.scope): bound REF, window, targets, exclusions,
    whole-CIDR containment and an ROE identity that names the organisation."""
    scope_mod = pytest.importorskip("v3lum.core.scope")
    monkeypatch.setattr(module_mod, "package_available", lambda name: True)
    cls = build_module("pm_real_scope", {**ACTIVE, "accepts": ("domain", "ipv4", "cidr", "url")})

    def scope(**over: Any) -> Any:
        data = {
            "authorization_ref": "CHG-2026-001", "owner": "CISO office", "contacts": ["soc@acme-corp.com"], "ticket": "CHG-2026-001",
            "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
            "targets": {"domains": ["acme-corp.com", "*.acme-corp.com"], "cidrs": ["203.0.113.0/25"]},
            "exclusions": {"domains": ["vpn.acme-corp.com"], "cidrs": ["203.0.113.64/28"]},
        }
        data.update(over)
        return scope_mod.Scope.from_dict(data)

    def verdict(entity_text: str, sc: Any, ref: str = "CHG-2026-001", seed: bool = True) -> tuple[bool, str]:
        entity = _entity(entity_text)
        pctx = build_context({"preset": "deep", "mode": "active", "authorization_ref": ref}, cls, entity, tmp_path)
        pctx.options.scope = sc
        d = decide(cls, entity, pctx, run=build_run({"seed": seed}, entity))
        return d.allowed, d.reason_code

    assert verdict("domain:acme-corp.com", scope()) == (True, "")
    assert verdict("domain:www.acme-corp.com", scope(), seed=False) == (True, "")  # a pivot inside the scope
    assert verdict("domain:vpn.acme-corp.com", scope()) == (False, "scope")  # excluded
    assert verdict("domain:example.com", scope()) == (False, "scope")
    assert verdict("ipv4:203.0.113.10", scope()) == (True, "")
    assert verdict("ipv4:203.0.113.70", scope()) == (False, "scope")  # excluded network
    assert verdict("cidr:203.0.113.0/27", scope()) == (True, "")
    assert verdict("cidr:203.0.113.0/24", scope()) == (False, "scope")  # wider than the target
    assert verdict("cidr:203.0.113.64/27", scope()) == (False, "scope")  # overlaps the exclusion
    assert verdict("url:https://www.acme-corp.com/login", scope()) == (True, "")
    assert verdict("domain:acme-corp.com", scope(), ref="CHG-2026-002") == (False, "scope")  # REF mismatch
    assert verdict("domain:acme-corp.com", scope(window_end="2026-11-26T06:00:00Z")) == (False, "scope")  # closed
    named = scope(roe={"user_agent": "ACME red team scanner"})
    assert verdict("domain:acme-corp.com", named) == (False, "scope")  # the ROE identity names the organisation
