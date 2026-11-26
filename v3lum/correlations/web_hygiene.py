"""Correlation pack: web hygiene (P084: CR17-CR24).

The rules turn facts that LIGHT/ACTIVE web modules already recorded under the policy gate into
consistent, ownership-scoped findings. They never trigger contact, probing or fetching (P084 cond 2),
never validate, use or pivot a secret (cond 7) and never crack anything (cond 8).

* **CR17** ``weak_or_expired_tls`` - certificate expired/expiring, hostname mismatch, self-signed,
  weak key or signature (``tls_certificate``, LIGHT tls_inspect) and legacy protocols or weak ciphers
  accepted (``tls_protocols``/``tls_weak_ciphers``, ACTIVE tls_protocol_scan).
* **CR18** ``login_page_without_hsts`` - a page with a login form (``login_form``) served without HSTS
  (``hsts``, ``security_headers_missing``) or over plain HTTP.
* **CR19** ``insecure_session_cookie`` - session-like cookies without Secure/HttpOnly/SameSite
  (``cookie_flags``: names and flags only).
* **CR20** ``cors_credentialed_reflection`` - only from the ACTIVE ``cors_probe`` on in-scope authorized
  targets (cond 6): an arbitrary or null Origin reflected with credentials is HIGH; LIGHT data
  (``cors_acao``) never produces CR20.
* **CR21** ``secret_in_public_asset`` - a secret matched in a public web asset (the secret_scanner data
  shape): type, asset URL and line, SHA-256 and the masked preview (first 4/last 4) only; entropy-gated;
  keys public by design (Google Maps/Firebase web keys, Stripe ``pk_``, Sentry DSN, Mapbox ``pk.``) are
  capped at LOW (cond 7).
* **CR22** ``jwt_weak_configuration`` - static analysis of decoded headers/claims only: alg none, HS* on
  a token exposed in a public asset, missing or very long exp, kid/jku/x5u/jwk anomalies (cond 8).
* **CR23** ``sensitive_file_exposed`` - an exposure confirmed by a content signature kept in evidence,
  never the HTTP status alone (cond 9): path, signature, size and SHA-256 only.
* **CR24** ``public_cloud_bucket`` - attributed buckets only: a public listing HIGH, 403 LOW 'bucket
  exists, private; ownership not verified'; permutation-only hits INFO 'unattributed' (cond 10).

Scoping (:func:`asset_scoping`, cond 3-4, 11): hostile hosts (malicious/phishing/c2...) give INFO
context for every rule; verified own assets (txt_verified/attested org-profile entries), in-scope
targets and explicit web assessments (an analyst-typed seed scanned with --mode light|active) keep the
severity; unverified profile entries and other third-party hosts give INFO context for
CR17-CR20/CR22 and at most MEDIUM for CR21/CR23/CR24. Everything outside the org
profile is tagged ``third_party`` and its recommendation stops at 'notify the owner through a manual,
approved disclosure process'. CR17-CR19 are INFO 'inconclusive' when TLS interception was detected
for the run (``rctx.meta['tls_interception']``) or on the host (``intercepted_by``, cond 5).
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from v3lum.core import entities as _entities
from v3lum.core import psl
from v3lum.core import sanitize as _sanitize
from v3lum.core.correlate import rule
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Confidence, Correlation, Finding, ModuleResult, Opsec, Severity

__all__ = [
    "RULE_BUCKET",
    "RULE_COOKIE",
    "RULE_CORS",
    "RULE_FILE",
    "RULE_HSTS",
    "RULE_JWT",
    "RULE_SECRET",
    "RULE_TLS",
    "Scoping",
    "asset_scoping",
    "interception",
    "public_by_design",
]

# ----------------------------------------------------------------------------------------
# Rule ids and named constants (one place, P084 cond 1-12)
# ----------------------------------------------------------------------------------------

RULE_TLS = "weak_or_expired_tls"  # CR17
RULE_HSTS = "login_page_without_hsts"  # CR18
RULE_COOKIE = "insecure_session_cookie"  # CR19
RULE_CORS = "cors_credentialed_reflection"  # CR20
RULE_SECRET = "secret_in_public_asset"  # CR21
RULE_JWT = "jwt_weak_configuration"  # CR22
RULE_FILE = "sensitive_file_exposed"  # CR23
RULE_BUCKET = "public_cloud_bucket"  # CR24

#: CR17: a certificate expiring within this many days is MEDIUM, within the next threshold LOW.
CERT_EXPIRY_MEDIUM_DAYS = 14
CERT_EXPIRY_LOW_DAYS = 30
#: CR17: minimum key sizes (RSA / EC) and weak signature hashes.
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
WEAK_SIGNATURE_HASHES = frozenset({"md5", "sha1"})
#: CR17: legacy protocols accepted (tri-state 'accepted' only; 'could_not_test' is never 'disabled').
LEGACY_PROTOCOLS_HIGH = frozenset({"sslv2", "sslv3"})
LEGACY_PROTOCOLS_MEDIUM = frozenset({"tlsv1", "tlsv1.0", "tlsv1.1"})
#: CR18: an HSTS max-age below this (180 days) is weak.
HSTS_MIN_MAX_AGE = 15552000
#: CR19: cookie names that look like session/authentication cookies (P063 heuristics).
SESSION_COOKIE_RE = re.compile(r"sess|sid|auth|token|jwt|remember", re.I)
#: CR20: the only module whose results may produce the rule (ACTIVE, in-scope authorized targets).
CORS_PROBE_MODULE = "cors_probe"
#: CR20: forged Origin kinds that make a reflection with credentials HIGH.
CORS_FORGED_ORIGINS = frozenset({"arbitrary", "null", "prefix", "suffix"})
#: CR21: secret findings below this Shannon entropy (bits/char, when the producer records it) are not reported.
MIN_SECRET_ENTROPY = 3.0
#: CR22: a token lifetime above this many days is 'very long'.
JWT_MAX_LIFETIME_DAYS = 30
#: CR22: kid values that look like path traversal, SQL/command injection or URLs.
KID_ANOMALY_RE = re.compile(r"\.\./|^/|\\|['\";|`$]|--|\bunion\b|\bselect\b|^[a-z][a-z0-9+.-]*://", re.I)
#: CR23: path patterns of the most damaging exposures (HIGH); LOW for source maps; MEDIUM otherwise.
SENSITIVE_HIGH_RE = re.compile(
    r"(?:^|/)(?:\.git/(?:head|config)|\.env(?:\.[\w-]+)?|\.htpasswd|wp-config\.php[^/]*|id_[rd]sa|\.npmrc|\.aws/credentials|"
    r"[^/]*\.(?:sql|sql\.gz|bak|zip|tar|tar\.gz|tgz|7z|rar|dump)|config\.php~)$",
    re.I,
)
SENSITIVE_LOW_RE = re.compile(r"\.map$", re.I)
#: CR24: bucket states that mean the bucket exists.
BUCKET_EXISTS = frozenset({"public_listing", "exists_private", "redirect"})
#: Entity/finding tags of hostile hosts (cond 4).
HOSTILE_TAGS = frozenset({"malicious", "phishing", "c2", "malware", "botnet"})
#: Analyst override verdicts that take a finding out of the evidence.
FALSE_POSITIVE_VERDICTS = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
#: Recommendation for every asset outside the org profile (cond 11).
DISCLOSURE = "Notify the owner through a manual, approved disclosure process."
NO_CONTACT = "This pack never contacts the host: re-checks run only through the LIGHT/ACTIVE modules under the policy gate."

_REFERENCES = ("https://owasp.org/www-project-secure-headers/", "https://cheatsheetseries.owasp.org/")
_UTC = _dt.timezone.utc
_STRICT_RULES = frozenset({RULE_TLS, RULE_HSTS, RULE_COOKIE, RULE_CORS, RULE_JWT})


# ----------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------


def _date(value: Any) -> _dt.datetime | None:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_UTC)
    text = str(value or "").strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if not m:
        return None
    if len(text) > 10:
        try:
            parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=_UTC)
        except ValueError:
            pass
    try:
        return _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=_UTC)
    except ValueError:
        return None


def _now(rctx: Any) -> _dt.datetime:
    now = getattr(rctx, "now", None)
    if isinstance(now, _dt.datetime):
        return now if now.tzinfo else now.replace(tzinfo=_UTC)
    return _dt.datetime.now(_UTC)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _scrub(text: str) -> str:
    """Output strings pass the P145 text scrubber: a secret that slipped into a source's data is masked."""
    try:
        return _sanitize.scrub_text(text)
    except Exception:  # noqa: BLE001 - fail closed
        return "[removed by the sanitizer]"


def _dicts(node: Node, name: str) -> list[tuple[Mapping[str, Any], str]]:
    """(value, source module) for dict values of an attribute, list values flattened."""
    out: list[tuple[Mapping[str, Any], str]] = []
    for value, src in node.attributes.get(name, []):
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, Mapping):
                out.append((item, src))
    return out


def _overridden_fp(f: Finding) -> bool:
    override = f.override if isinstance(f.override, dict) else None
    return bool(override and str(override.get("verdict") or "").strip().lower() in FALSE_POSITIVE_VERDICTS)


def _host_of(entity: Entity) -> str:
    if entity.type is EntityType.URL:
        return _entities.url_host(entity.value)
    if entity.type in (EntityType.DOMAIN, EntityType.IPV4, EntityType.IPV6):
        return entity.value
    return ""


def _host_entity(host: str) -> Entity | None:
    if not host:
        return None
    for etype in (EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN):
        ent = Entity.try_make(etype, host)
        if ent is not None:
            return ent
    return None


# ----------------------------------------------------------------------------------------
# Scoping (P084 cond 3, 4, 11)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scoping:
    """How a hygiene fact may be reported. ``kind`` 'hostile' | 'own_asset' (a VERIFIED org-profile
    asset) | 'in_scope' | 'assessment' | 'own_unverified' (a seeded/confirmed profile entry, not yet
    txt_verified or attested) | 'third_party'; ``own`` = inside the org profile (label own_asset vs
    third_party)."""

    kind: str
    reason: str
    own: bool = False

    @property
    def keeps_severity(self) -> bool:
        """Own assets, in-scope targets and explicit web assessments keep the rule severity."""
        return self.kind in ("own_asset", "in_scope", "assessment")


def _scope_object(rctx: Any) -> Any:
    opts = getattr(rctx, "options", None)
    scope = getattr(opts, "scope", None)
    if scope is None or hasattr(scope, "matches_host"):
        return scope
    if isinstance(scope, Mapping):
        try:
            from v3lum.core.scope import Scope  # lazy: the scope module imports the HTTP stack

            return Scope.from_dict(scope)
        except Exception:  # noqa: BLE001 - an unreadable scope matches nothing (fail closed)
            return None
    return None


def _in_scope(rctx: Any, entity: Entity, host: str) -> bool:
    scope = _scope_object(rctx)
    if scope is None or getattr(scope, "problems", ()):
        return False
    try:
        if entity.type is EntityType.URL:
            return bool(scope.matches_url(entity.value))
        return bool(host) and bool(scope.matches_host(host))
    except Exception:  # noqa: BLE001
        return False


def _mode(rctx: Any) -> Opsec:
    opts = getattr(rctx, "options", None)
    try:
        return Opsec.parse(getattr(opts, "mode", Opsec.PASSIVE))
    except (KeyError, ValueError, TypeError):
        return Opsec.PASSIVE


def _related(graph: Graph, node: Node, host: str) -> list[Node]:
    nodes = [node]
    names = [host]
    reg = psl.registrable_domain(host) if host and not host.replace(".", "").isdigit() and ":" not in host else None
    if reg and reg != host:
        names.append(reg)
    for name in names:
        ent = _host_entity(name)
        other = graph.get(ent) if ent is not None else None
        if other is not None and other is not node:
            nodes.append(other)
    return nodes


def _hostile(nodes: Iterable[Node]) -> str:
    for n in nodes:
        tags = n.tags & HOSTILE_TAGS
        if tags:
            return f"{n.entity.display} tagged {sorted(tags)[0]}"
        for f in n.findings:
            hit = set(f.tags) & HOSTILE_TAGS
            if hit and not _overridden_fp(f):
                return f"{n.entity.display} tagged {sorted(hit)[0]} by {f.module or 'a source'}"
    return ""


def asset_scoping(graph: Graph, node: Node, rctx: Any, *, host: str = "") -> Scoping:
    """Classify the asset a hygiene fact describes: hostile host (INFO for every rule), own asset (org
    profile), in-scope target (``options.scope``), explicit web assessment (an analyst-typed seed scanned
    with --mode light|active) or third party."""
    entity = node.entity
    host = host or _host_of(entity)
    nodes = _related(graph, node, host)
    hostile = _hostile(nodes)
    own, verified = _ownership(rctx, entity, host, node)
    if hostile:
        return Scoping("hostile", f"hostile host ({hostile}): INFO context only", own)
    if own and verified:
        return Scoping("own_asset", "verified organisation asset (org profile)", True)
    scope_owner = own  # in-scope / assessed own entries keep their own_asset label
    if _in_scope(rctx, entity, host):
        return Scoping("in_scope", "in-scope target of the authorized engagement (scope file)", scope_owner)
    unconfirmed = set(getattr(getattr(rctx, "options", None), "unconfirmed_seeds", ()) or ())
    if _mode(rctx) >= Opsec.LIGHT and any(n.seed and n.key not in unconfirmed for n in nodes):  # analyst-typed seeds only
        return Scoping("assessment", f"explicit web assessment of an analyst-typed seed (--mode {_mode(rctx).label})", scope_owner)
    if own:
        return Scoping("own_unverified", "organisation asset not verified yet (seeded/confirmed profile entry, not "
                       "txt_verified or attested)", True)
    return Scoping("third_party", "third-party host outside the org profile")


#: Ownership kinds of profile entries without a verification state (analyst-maintained ranges).
_UNSTATED_VERIFICATION = frozenset({"cidr", "asn"})


def _ownership(rctx: Any, entity: Entity, host: str, node: Node) -> tuple[bool, bool]:
    """``(own, verified)``: inside the org profile, and covered by a txt_verified/attested entry (P084
    cond 3 keeps the CR17-CR20/CR22 severity only for VERIFIED own assets). An engine ``own_asset`` tag
    the profile does not contradict counts as verified; CIDR/ASN entries carry no verification state."""
    org = getattr(rctx, "org", None)
    if org is not None:
        for candidate in (entity, _host_entity(host)):
            if candidate is None:
                continue
            try:
                owned = org.owns(candidate)
            except Exception:  # noqa: BLE001 - a profile problem never makes an asset own
                continue
            if getattr(owned, "own", False):
                return True, bool(getattr(owned, "verified", False)) or getattr(owned, "kind", "") in _UNSTATED_VERIFICATION
    if node.ownership == "own_asset" or "own_asset" in node.tags:
        return True, True
    return False, False


def interception(rctx: Any, node: Node | None = None) -> str:
    """The TLS-interception issuer detected for the run (``rctx.meta['tls_interception']``, P329) or on
    the host (``intercepted_by``); '' when none."""
    meta = getattr(rctx, "meta", None) or {}
    value = meta.get("tls_interception") if isinstance(meta, Mapping) else None
    if value:
        if isinstance(value, Mapping):
            return str(value.get("issuer") or value.get("product") or "detected")
        return str(value) if not isinstance(value, bool) else "detected"
    if node is not None:
        for v in node.attr_values("intercepted_by"):
            if v:
                return str(v.get("issuer") if isinstance(v, Mapping) else v)
    return ""


def _severity(rule_id: str, severity: Severity, scoping: Scoping) -> Severity:
    if scoping.kind == "hostile":
        return Severity.INFO
    if scoping.keeps_severity:
        return severity
    return Severity.INFO if rule_id in _STRICT_RULES else min(severity, Severity.MEDIUM)


def _build(
    rule_id: str,
    node: Node,
    scoping: Scoping,
    *,
    title: str,
    severity: Severity,
    summary: str,
    criterion: str,
    evidence: Iterable[str],
    fix: str,
    tags: Iterable[str],
    confidence: Confidence = Confidence.PROBABLE,
    key: str = "",
    inconclusive: str = "",
) -> Correlation:
    tag_list = list(tags)
    if inconclusive:
        final = Severity.INFO
        confidence = Confidence.POSSIBLE
        title = f"{title} - inconclusive (TLS interception)"
        criterion = (f"inconclusive - TLS interception by {inconclusive} detected on this network: certificate, HSTS and cookie "
                     f"facts may be the proxy's (P329) | {criterion}")
        tag_list.append("inconclusive")
    else:
        final = _severity(rule_id, severity, scoping)
    if final < severity and not inconclusive:
        criterion = f"{criterion}; {scoping.reason}: {severity.label.upper()} lowered to {final.label.upper()} (P084 cond 3-4)"
    if final is Severity.INFO and severity > Severity.INFO:
        tag_list.append("context_only")
    tag_list.append("own_asset" if scoping.own else "third_party")
    recommendation = fix if scoping.own and scoping.kind != "hostile" else (
        "Hostile host: hygiene facts are context for the investigation only." if scoping.kind == "hostile" else DISCLOSURE
    )
    if scoping.kind == "in_scope" and not scoping.own:  # the authorized engagement's client receives the fix
        recommendation = f"{fix} {DISCLOSURE}"
    # an explicit assessment of a third-party seed stops at the disclosure process (cond 11)
    corr = Correlation(
        rule=rule_id,
        title=_scrub(title),
        severity=final,
        description=_scrub(f"{summary} Scope: {scoping.reason}. {NO_CONTACT}"),
        entities=[node.entity],
        confidence=confidence,
        evidence=[_scrub(e) for e in evidence if e],
        recommendation=_scrub(recommendation),
        tags=list(dict.fromkeys(tag_list)),
        criterion=_scrub(criterion),
        why=_scrub(summary),
        key=key,
    )
    return corr


def _worst(issues: list[tuple[Severity, str]]) -> Severity:
    return max((s for s, _ in issues), default=Severity.INFO)


def _web_nodes(graph: Graph) -> list[Node]:
    return [n for n in graph.nodes.values() if n.entity.type in (EntityType.URL, EntityType.DOMAIN, EntityType.IPV4, EntityType.IPV6)]


# ----------------------------------------------------------------------------------------
# CR17 weak_or_expired_tls
# ----------------------------------------------------------------------------------------


def _tls_issues(node: Node, now: _dt.datetime) -> list[tuple[Severity, str]]:
    issues: list[tuple[Severity, str]] = []
    for cert, _src in _dicts(node, "tls_certificate"):
        not_after = _date(cert.get("not_after"))
        if not_after is not None:
            left = (not_after - now).days
            if not_after < now:
                issues.append((Severity.HIGH, f"certificate expired on {not_after.date().isoformat()}"))
            elif left <= CERT_EXPIRY_MEDIUM_DAYS:
                issues.append((Severity.MEDIUM, f"certificate expires in {left} day(s) ({not_after.date().isoformat()})"))
            elif left <= CERT_EXPIRY_LOW_DAYS:
                issues.append((Severity.LOW, f"certificate expires in {left} day(s) ({not_after.date().isoformat()})"))
        if cert.get("hostname_match") is False:
            issues.append((Severity.HIGH, "certificate does not match the host name"))
        if cert.get("self_signed") is True:
            issues.append((Severity.MEDIUM, "self-signed certificate"))
        elif cert.get("chain_verified") is False:
            issues.append((Severity.MEDIUM, "certificate chain does not verify"))
        key_type = str(cert.get("key_type") or "").lower()
        bits = _int(cert.get("key_bits"))
        if bits is not None and ((key_type in ("rsa", "dsa") and bits < MIN_RSA_BITS) or (key_type in ("ec", "ecdsa") and bits < MIN_EC_BITS)):
            issues.append((Severity.MEDIUM, f"weak {key_type.upper()} key ({bits} bits)"))
        sig = str(cert.get("signature_hash") or "").lower().replace("-", "")
        if sig in WEAK_SIGNATURE_HASHES:
            issues.append((Severity.MEDIUM, f"{sig.upper()} signature"))
    for protocols, _src in _dicts(node, "tls_protocols"):
        for proto, state in protocols.items():
            name = str(proto).strip().lower().replace(" ", "")
            if str(state).strip().lower() != "accepted":
                continue  # 'refused' is fine; 'could_not_test' is never 'disabled' (rule 5)
            if name in LEGACY_PROTOCOLS_HIGH:
                issues.append((Severity.HIGH, f"{proto} accepted"))
            elif name in LEGACY_PROTOCOLS_MEDIUM:
                issues.append((Severity.MEDIUM, f"{proto} accepted"))
    ciphers = sorted({str(c) for c in node.attr_values("tls_weak_ciphers") if c})
    if ciphers:
        issues.append((Severity.MEDIUM, f"weak cipher suites accepted ({', '.join(ciphers[:4])})"))
    return issues


@rule(
    RULE_TLS,
    "Weak or expired TLS",
    "TLS facts of a live handshake (LIGHT tls_inspect) or protocol scan (ACTIVE tls_protocol_scan): expired or expiring "
    "certificate, host-name mismatch, self-signed or unverifiable chain, weak key or signature, legacy protocols or weak "
    "ciphers accepted. Severity kept for own assets, in-scope targets and explicit web assessments; INFO context for "
    "other third parties and hostile hosts; INFO 'inconclusive' under TLS interception (P084 cond 3-5).",
    version="1",
    code="CR17",
    severity="high",
    criterion="expired cert / hostname mismatch / SSLv3 (HIGH); expiring <= 14 d, self-signed, weak key or SHA-1, TLS 1.0/1.1, "
    "weak ciphers (MEDIUM); expiring <= 30 d (LOW)",
    references=(*_REFERENCES, "https://ssl-config.mozilla.org/"),
    attack=("T1557",),
    false_positives="A certificate rotated after the handshake was recorded; an internal-only name answered by a default "
    "virtual host; protocol support of a legacy-client endpoint kept on purpose.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_TLS}/positive_expired_own_certificate_high.json",
        f"tests/fixtures/rules/{RULE_TLS}/positive_interception_inconclusive_info.json",
        f"tests/fixtures/rules/{RULE_TLS}/negative_healthy_certificate.json",
    ),
)
def weak_or_expired_tls(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    now = _now(rctx)
    for node in _web_nodes(graph):
        issues = _tls_issues(node, now)
        if not issues:
            continue
        scoping = asset_scoping(graph, node, rctx)
        worst = _worst(issues)
        text = "; ".join(i for _, i in sorted(issues, key=lambda x: -int(x[0])))
        yield _build(
            RULE_TLS, node, scoping,
            title=f"Weak or expired TLS on {node.entity.display}",
            severity=worst,
            summary=f"TLS problems on {_entities.defang(node.entity.value)}: {text}.",
            criterion=f"CR17: {text}",
            evidence=[text],
            fix="Renew or replace the certificate, disable SSLv3/TLS 1.0/1.1 and weak cipher suites (Mozilla 'intermediate').",
            tags=["misconfiguration"],
            inconclusive=interception(rctx, node),
        )


# ----------------------------------------------------------------------------------------
# CR18 login_page_without_hsts
# ----------------------------------------------------------------------------------------


def _hsts_state(node: Node) -> tuple[str, int | None]:
    """('absent' | 'weak' | 'ok' | 'unknown', max_age) from ``hsts`` and ``security_headers_missing``."""
    states: list[tuple[str, int | None]] = []
    for hsts, _src in _dicts(node, "hsts"):
        present = hsts.get("present")
        max_age = _int(hsts.get("max_age"))
        if present is False or max_age == 0:
            states.append(("absent", max_age))
        elif present is True or max_age is not None:
            states.append(("weak" if max_age is not None and max_age < HSTS_MIN_MAX_AGE else "ok", max_age))
    missing = {str(h).strip().lower() for h in node.attr_values("security_headers_missing")}
    if "strict-transport-security" in missing:
        states.append(("absent", None))
    if not states:
        return "unknown", None
    for wanted in ("ok", "weak", "absent"):
        for state, age in states:
            if state == wanted:
                return state, age
    return "unknown", None


@rule(
    RULE_HSTS,
    "Login page without HSTS",
    "A page with a login form (LIGHT fetch) served without Strict-Transport-Security, with a weak max-age, or over plain "
    "HTTP: a network attacker can strip TLS and capture credentials. Severity kept for own assets, in-scope targets and "
    "explicit web assessments; INFO context elsewhere; INFO 'inconclusive' under TLS interception (P084 cond 3-5).",
    version="1",
    code="CR18",
    severity="medium",
    criterion="login_form and (no HSTS or max-age 0 or plain HTTP) MEDIUM; HSTS max-age < 180 days LOW",
    references=(*_REFERENCES, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    attack=("T1557",),
    false_positives="HSTS set on the registrable domain with includeSubDomains (or preloaded) while the login host does "
    "not repeat it; a login form that only posts to an HTTPS host with HSTS.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_HSTS}/positive_own_login_without_hsts_medium.json",
        f"tests/fixtures/rules/{RULE_HSTS}/positive_third_party_login_info.json",
        f"tests/fixtures/rules/{RULE_HSTS}/negative_hsts_present_or_unknown.json",
    ),
)
def login_page_without_hsts(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in _web_nodes(graph):
        if not any(v is True for v in node.attr_values("login_form")):
            continue
        plain = node.entity.type is EntityType.URL and node.entity.value.lower().startswith("http://")
        state, max_age = _hsts_state(node)
        if plain:
            severity, text = Severity.MEDIUM, "password form served over plain HTTP"
        elif state == "absent":
            severity, text = Severity.MEDIUM, "no Strict-Transport-Security header on the login page"
        elif state == "weak":
            severity, text = Severity.LOW, f"weak HSTS max-age {max_age} s (< {HSTS_MIN_MAX_AGE})"
        else:
            continue  # HSTS present, or no header facts: never conclude 'missing' without them (rule 5)
        scoping = asset_scoping(graph, node, rctx)
        yield _build(
            RULE_HSTS, node, scoping,
            title=f"Login page without HSTS: {node.entity.display}",
            severity=severity,
            summary=f"{_entities.defang(node.entity.value)} shows a login form: {text}.",
            criterion=f"CR18: login_form and {text}",
            evidence=[text],
            fix="Serve the login only over HTTPS with 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "and redirect HTTP to HTTPS.",
            tags=["misconfiguration"],
            inconclusive=interception(rctx, node),
        )


# ----------------------------------------------------------------------------------------
# CR19 insecure_session_cookie
# ----------------------------------------------------------------------------------------


@rule(
    RULE_COOKIE,
    "Insecure session cookie",
    "Session-like cookies (sess, sid, auth, token, jwt, remember) set without Secure or HttpOnly (MEDIUM) or without "
    "SameSite (LOW), from the Set-Cookie headers a LIGHT fetch recorded (names and flags only, never values). Severity "
    "kept for own assets, in-scope targets and explicit web assessments; INFO context elsewhere; INFO 'inconclusive' "
    "under TLS interception (P084 cond 3-5).",
    version="1",
    code="CR19",
    severity="medium",
    criterion="session-like cookie without Secure or HttpOnly (MEDIUM) or without SameSite (LOW)",
    references=(*_REFERENCES, "https://owasp.org/www-community/controls/SecureCookieAttribute"),
    attack=("T1539",),
    false_positives="A cookie whose name looks like a session but holds a non-sensitive preference; a cookie the "
    "application never uses for authentication.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_COOKIE}/positive_own_session_cookie_medium.json",
        f"tests/fixtures/rules/{RULE_COOKIE}/negative_flags_set_or_not_session.json",
    ),
)
def insecure_session_cookie(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in _web_nodes(graph):
        issues: list[tuple[Severity, str]] = []
        for cookie, _src in _dicts(node, "cookie_flags"):
            name = str(cookie.get("name") or "").strip()
            session_like = cookie.get("session_like") is True or bool(name and SESSION_COOKIE_RE.search(name))
            if not session_like:
                continue
            missing = [flag for flag, key in (("Secure", "secure"), ("HttpOnly", "httponly")) if cookie.get(key) is False]
            samesite = str(cookie.get("samesite") or "").strip().lower()
            if missing:
                issues.append((Severity.MEDIUM, f"cookie '{name or '?'}' without {' and '.join(missing)}"))
            elif "samesite" in cookie and samesite in ("", "none"):  # a key the producer did not record is unknown
                issues.append((Severity.LOW, f"cookie '{name or '?'}' " + ("with SameSite=None" if samesite == "none" else "without SameSite")))
        if not issues:
            continue
        scoping = asset_scoping(graph, node, rctx)
        text = "; ".join(i for _, i in issues[:6])
        yield _build(
            RULE_COOKIE, node, scoping,
            title=f"Insecure session cookie on {node.entity.display}",
            severity=_worst(issues),
            summary=f"Session cookies of {_entities.defang(node.entity.value)}: {text}.",
            criterion=f"CR19: {text}",
            evidence=[text],
            fix="Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies, preferably with the __Host- prefix.",
            tags=["misconfiguration"],
            inconclusive=interception(rctx, node),
        )


# ----------------------------------------------------------------------------------------
# CR20 cors_credentialed_reflection
# ----------------------------------------------------------------------------------------


def _cors_probe_is_active() -> bool:
    try:
        from v3lum.core.module import REGISTRY  # lazy

        cls = REGISTRY.get(CORS_PROBE_MODULE)
    except Exception:  # noqa: BLE001
        cls = None
    return cls is None or getattr(cls, "opsec", Opsec.ACTIVE) == Opsec.ACTIVE


def _authorized_active(rctx: Any) -> bool:
    opts = getattr(rctx, "options", None)
    authorized = bool(getattr(opts, "authorized", False) or str(getattr(opts, "authorization_ref", "") or "").strip())
    return _mode(rctx) == Opsec.ACTIVE and authorized


@rule(
    RULE_CORS,
    "CORS reflects a forged Origin with credentials",
    "Results of the ACTIVE cors_probe on in-scope authorized targets only (a crafted Origin is not visitor traffic): an "
    "arbitrary or null Origin reflected with Access-Control-Allow-Credentials: true is HIGH; a reflection without "
    "credentials MEDIUM when the endpoint returns user data, else LOW; ACAO '*' INFO. LIGHT observations of ACAO never "
    "produce this rule (P084 cond 6, P283 cond 5).",
    version="1",
    code="CR20",
    severity="high",
    criterion="cors_probe result on an in-scope authorized target: forged Origin reflected + ACAC true (HIGH)",
    references=(*_REFERENCES, "https://portswigger.net/web-security/cors"),
    attack=("T1185", "T1189"),
    false_positives="An endpoint that reflects Origins but returns only public data and ignores cookies; a reflection "
    "limited by a server-side allow-list the probe's forged names happened to pass.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_CORS}/positive_in_scope_reflection_with_credentials_high.json",
        f"tests/fixtures/rules/{RULE_CORS}/negative_light_acao_only.json",
        f"tests/fixtures/rules/{RULE_CORS}/negative_out_of_scope_probe_result.json",
    ),
)
def cors_credentialed_reflection(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    if not _authorized_active(rctx) or not _cors_probe_is_active():
        return
    for node in _web_nodes(graph):
        rows = [row for row, src in _dicts(node, "cors_results") if src == CORS_PROBE_MODULE]
        if not rows:
            continue
        host = _host_of(node.entity)
        if not _in_scope(rctx, node.entity, host):
            continue  # cond 6: in-scope authorized targets only
        issues: list[tuple[Severity, str]] = []
        for row in rows:
            kind = str(row.get("origin_kind") or "").strip().lower()
            endpoint = str(row.get("endpoint") or node.entity.value)
            reflected = row.get("acao_reflected") is True
            if kind == "wildcard" or str(row.get("acao") or "") == "*":
                issues.append((Severity.INFO, f"{endpoint}: ACAO '*' (no credentials possible)"))
            elif reflected and kind in CORS_FORGED_ORIGINS and row.get("acac") is True:
                issues.append((Severity.HIGH, f"{endpoint}: {kind} Origin reflected with credentials"))
            elif reflected:
                sev = Severity.MEDIUM if row.get("user_data") is True else Severity.LOW
                issues.append((sev, f"{endpoint}: {kind or 'forged'} Origin reflected without credentials"
                                    + (" (user data)" if row.get("user_data") is True else "")))
        if not issues:
            continue
        scoping = asset_scoping(graph, node, rctx)
        text = "; ".join(i for _, i in sorted(issues, key=lambda x: -int(x[0]))[:5])
        yield _build(
            RULE_CORS, node, scoping,
            title=f"CORS reflects forged Origins on {node.entity.display}",
            severity=_worst(issues),
            summary=f"The authorized ACTIVE CORS probe of {_entities.defang(node.entity.value)} found: {text}.",
            criterion=f"CR20 (cors_probe, ACTIVE, in scope): {text}",
            evidence=[text, f"{len(rows)} probe result(s)"],
            fix="Allow-list exact trusted Origins server-side; never reflect arbitrary or null Origins together with "
            "Access-Control-Allow-Credentials.",
            tags=["misconfiguration", "exposure"],
        )


# ----------------------------------------------------------------------------------------
# CR21 secret_in_public_asset
# ----------------------------------------------------------------------------------------


def public_by_design(rule_id: str, kind: str = "", preview: str = "") -> str:
    """Why a key type is public by design ('' when it is not): Google Maps/Firebase web keys (AIza...),
    Stripe publishable keys (pk_), Sentry DSNs and Mapbox public tokens (pk.) - capped at LOW (P084 cond 7)."""
    rid = f"{rule_id} {kind}".lower()
    pre = str(preview or "")
    if "gcp-api-key" in rid or "firebase" in rid or "google-maps" in rid or pre.startswith("AIza"):
        return "Google Maps/Firebase web key (public by design, restrict it by referrer)"
    if "publishable" in rid or pre.startswith(("pk_live", "pk_test")):
        return "Stripe publishable key (public by design)"
    if "sentry-dsn" in rid or "sentry_dsn" in rid or ("sentry" in rid and "dsn" in rid):
        return "Sentry DSN (public by design)"
    if "mapbox" in rid and pre.startswith("pk."):
        return "Mapbox public token (public by design)"
    return ""


#: CR21: a masked preview is at most 8 characters, a mask mark and at most 8 characters ('AKIA…Q2XZ'), or
#: a bracketed redaction ('[redacted]', '[password redacted]'); anything else is never printed.
_MASKED_PREVIEW_RE = re.compile(r"^(?:.{0,8}(?:…|\.\.\.|\*{3,}).{0,8}|\[[a-z ]{1,30}\])$", re.S)


def _masked_preview(value: Any) -> str:
    """The producer's masked preview - core ``sanitize.mask_secret`` ``preview`` or the secret_scanner
    ``display`` - when it really is masked; '****' when it is not (a raw value is never printed)."""
    text = str(value or "").strip()
    if not text:
        return ""
    return text if _MASKED_PREVIEW_RE.match(text) else "****"


def _public_locations(f: Finding) -> list[dict[str, Any]]:
    out = []
    for loc in f.data.get("locations") or () if isinstance(f.data, Mapping) else ():
        if isinstance(loc, Mapping):
            path = str(loc.get("path") or loc.get("url") or "")
            out.append({"path": path, "line": loc.get("line")})
    return out


@rule(
    RULE_SECRET,
    "Secret exposed in a public web asset",
    "A secret matched (pattern + entropy gate) in a public web asset - live or archived JavaScript, a page, a public file - "
    "reported only as type, asset URL and line, SHA-256 and a masked preview (first 4/last 4). Never validated, tested, "
    "used or pivoted. Keys public by design are capped at LOW; hostile hosts (phishing kits) give INFO context (P084 "
    "cond 7, 4, 11).",
    version="1",
    code="CR21",
    severity="high",
    criterion="provider-specific secret pattern above the entropy gate in a public asset; own/in-scope HIGH, third-party "
    "<= MEDIUM, public-by-design keys LOW, hostile hosts INFO",
    references=(*_REFERENCES, "https://github.com/gitleaks/gitleaks"),
    attack=("T1552.001",),
    false_positives="Documentation/example credentials not on the allow-list; a revoked key still present in an old "
    "archived file; a test key of a sandbox environment.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_SECRET}/positive_own_js_aws_key_high.json",
        f"tests/fixtures/rules/{RULE_SECRET}/positive_phishing_kit_info_only.json",
        f"tests/fixtures/rules/{RULE_SECRET}/positive_public_by_design_key_low.json",
        f"tests/fixtures/rules/{RULE_SECRET}/negative_generic_or_local_text.json",
    ),
)
def secret_in_public_asset(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in graph.nodes.values():
        for f in node.findings:
            if "credential_exposure" not in f.tags or "weak_signal" in f.tags or _overridden_fp(f) or not isinstance(f.data, Mapping):
                continue
            data = f.data
            if data.get("generic") is True or str(data.get("rule") or "") == "generic-api-key":
                continue  # entropy-only matches are a count, never a finding (P068 cond 9)
            entropy = _float(data.get("entropy"))
            if entropy is not None and entropy < MIN_SECRET_ENTROPY:
                continue
            masked = data.get("masked") if isinstance(data.get("masked"), Mapping) else {}
            sha = str(masked.get("sha256") or "")
            # core mask_secret writes 'preview', the secret_scanner/archive_mining shape writes 'display'
            preview = _masked_preview(masked.get("preview") or masked.get("display"))
            password = "password" in (str(data.get("kind") or "").lower(), str(masked.get("kind") or "").lower())
            if not sha and not password:
                continue  # without the fingerprint there is nothing safe to report (passwords keep no digest by design)
            locations = _public_locations(f)
            public_urls = [loc for loc in locations if loc["path"].lower().startswith(("http://", "https://"))]
            if node.entity.type in (EntityType.URL, EntityType.DOMAIN):
                asset = node.entity.value
            elif public_urls:
                asset = public_urls[0]["path"]
            else:
                continue  # analyst-supplied text or a local file: secret_scanner reports it, not a public asset
            host = _entities.url_host(asset) if "://" in asset else asset
            scoping = asset_scoping(graph, node, rctx, host=host)
            rule_name = str(data.get("rule") or f.title)
            kind = str(masked.get("type") or data.get("kind") or "secret")
            design = public_by_design(rule_name, kind, preview)
            severity = Severity.LOW if design else (Severity.HIGH if scoping.keeps_severity else Severity.MEDIUM)
            where = ", ".join(f"{loc['path'] or asset}:{loc['line']}" for loc in (public_urls or locations)[:3]) or asset
            facts = f"{kind} ({rule_name}) {preview or '****'}" + (f" sha256:{sha[:16]}" if sha else "") + f" at {where}"
            criterion = f"CR21: {rule_name} pattern above the entropy gate in a public asset" + (f"; {design}: capped at LOW" if design else "")
            if "phishing_kit_exfil" in f.tags:
                facts += " (phishing-kit exfiltration channel)"
            yield _build(
                RULE_SECRET, node, scoping,
                title=f"Secret exposed in a public asset: {kind} {preview or sha[:8] or '[redacted]'}",
                severity=severity,
                summary=f"A {kind} secret appears in a public asset: {facts}. It was never validated, tested or used.",
                criterion=criterion,
                evidence=[facts, *([f.id] if f.id else [])],
                fix="Revoke and rotate the credential, remove it from the asset and its history, and move it to server-side "
                "configuration.",
                tags=["credential_exposure", "exposure"],
                key=sha[:16] or f"{rule_name}@{where}",
            )


# ----------------------------------------------------------------------------------------
# CR22 jwt_weak_configuration
# ----------------------------------------------------------------------------------------


def _jwt_assets(graph: Graph, node: Node) -> list[Node]:
    """Public web assets the token was found in (url/domain/ip nodes with an edge to it)."""
    out = []
    for edge in graph.edges:
        if edge.dst == node.key:
            src = graph.get(edge.src)
            if src is not None and src.entity.type in (EntityType.URL, EntityType.DOMAIN, EntityType.IPV4, EntityType.IPV6):
                out.append(src)
    return out


def _jwt_issues(header: Mapping[str, Any], claims: Mapping[str, Any], public: bool) -> list[tuple[Severity, str]]:
    issues: list[tuple[Severity, str]] = []
    alg = str(header.get("alg") or "").strip()
    if alg.lower() == "none":
        issues.append((Severity.HIGH, "unsigned token (alg 'none')"))
    elif alg.upper().startswith("HS") and public:
        issues.append((Severity.MEDIUM, f"{alg.upper()} (shared-secret HMAC) token exposed in a public asset"))
    exp, iat = _int(claims.get("exp")), _int(claims.get("iat"))
    if iat is None:
        iat = _int(claims.get("nbf"))  # an explicit 0 is a timestamp, not 'missing'
    if "exp" not in claims or exp is None:
        issues.append((Severity.LOW, "no expiry (exp missing)"))
    elif iat is not None and exp - iat > JWT_MAX_LIFETIME_DAYS * 86400:
        issues.append((Severity.LOW, f"very long lifetime ({(exp - iat) // 86400} days > {JWT_MAX_LIFETIME_DAYS})"))
    iss = str(claims.get("iss") or "")
    iss_host = _entities.url_host(iss) if "://" in iss else iss.split("/")[0]
    iss_reg = psl.registrable_domain(iss_host) if iss_host and "." in iss_host else None
    for field_name in ("jku", "x5u"):
        url = str(header.get(field_name) or "").strip()
        if not url:
            continue
        host = _entities.url_host(url)
        reg = psl.registrable_domain(host) if host and "." in host else None
        if url.lower().startswith("http://") or not iss_reg or reg != iss_reg:
            issues.append((Severity.MEDIUM, f"{field_name} points to a key URL outside the issuer ({_entities.defang(url)})"))
    if header.get("jwk"):
        issues.append((Severity.MEDIUM, "embedded jwk header (key injection risk)"))
    kid = str(header.get("kid") or "")
    if kid and KID_ANOMALY_RE.search(kid):
        issues.append((Severity.MEDIUM, "kid with path, URL or injection characters"))
    return issues


@rule(
    RULE_JWT,
    "Weak JWT configuration",
    "Static analysis of a decoded JWT header and claims (never verified, cracked, replayed or sent anywhere): alg none, "
    "HS* tokens exposed in public assets, missing or very long expiry, kid/jku/x5u/jwk anomalies. Severity kept when the "
    "token belongs to an own asset, an in-scope target or an explicit web assessment; INFO context elsewhere (P084 cond "
    "8, 3).",
    version="1",
    code="CR22",
    severity="high",
    criterion="alg none (HIGH); HS* in a public asset, jku/x5u outside the issuer, jwk, odd kid (MEDIUM); no or very long "
    "exp (LOW)",
    references=("https://datatracker.ietf.org/doc/html/rfc8725", "https://cheatsheetseries.owasp.org/"),
    attack=("T1606", "T1528"),
    false_positives="A test token from documentation; a token whose verifier pins the algorithm and ignores jku/x5u; a "
    "refresh token whose long lifetime is bounded server-side.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_JWT}/positive_own_alg_none_high.json",
        f"tests/fixtures/rules/{RULE_JWT}/negative_rs256_short_lived.json",
    ),
)
def jwt_weak_configuration(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in graph.of_type(EntityType.JWT):
        headers = [h for h, _ in _dicts(node, "jwt_header")]
        claims_list = [c for c, _ in _dicts(node, "jwt_claims")]
        if not headers and not claims_list:
            continue
        header = headers[0] if headers else {}
        claims = claims_list[0] if claims_list else {}
        assets = _jwt_assets(graph, node)
        issues = _jwt_issues(header, claims, public=bool(assets))
        if not issues:
            continue
        scopings = [asset_scoping(graph, a, rctx) for a in assets]
        if not scopings:
            iss = str(claims.get("iss") or "")
            host = _entities.url_host(iss) if "://" in iss else iss.split("/")[0]
            scopings = [asset_scoping(graph, node, rctx, host=host)]
        hostile = next((s for s in scopings if s.kind == "hostile"), None)
        scoping = hostile or next((s for s in scopings if s.keeps_severity), scopings[0])
        text = "; ".join(i for _, i in sorted(issues, key=lambda x: -int(x[0])))
        where = ", ".join(_entities.defang(a.entity.value) for a in assets[:3]) or "analyst input"
        yield _build(
            RULE_JWT, node, scoping,
            title=f"Weak JWT configuration: {node.entity.display}",
            severity=_worst(issues),
            summary=f"Token {node.entity.display} (alg {header.get('alg') or '?'}, found in {where}): {text}. Static analysis only; "
            "the token was never verified, cracked or replayed.",
            criterion=f"CR22 (static analysis): {text}",
            evidence=[text, f"found in {where}"],
            fix="Pin the verification algorithm (asymmetric keys for public clients), reject alg none and header-supplied "
            "keys (jku/x5u/jwk), keep tokens short-lived and out of public assets.",
            tags=["misconfiguration", "credential_exposure"],
        )


# ----------------------------------------------------------------------------------------
# CR23 sensitive_file_exposed
# ----------------------------------------------------------------------------------------


@rule(
    RULE_FILE,
    "Sensitive file exposed",
    "An exposure (.git, .env, backups, dumps, .DS_Store, server-status, phpinfo, source maps) confirmed by a content "
    "signature kept in evidence - never by the HTTP status alone - reported as path, signature, size and SHA-256 only, "
    "never the body. Hostile hosts give INFO context; third-party hosts at most MEDIUM (P084 cond 9, 4, 11).",
    version="1",
    code="CR23",
    severity="high",
    criterion="content-signature match of a sensitive path: VCS metadata, .env, credentials, backups/dumps (HIGH); "
    "listings and debug pages (MEDIUM); source maps (LOW)",
    references=(*_REFERENCES, "https://owasp.org/www-project-web-security-testing-guide/"),
    attack=("T1213", "T1552.001"),
    false_positives="A decoy/honeypot file; a soft-404 page that happens to match a signature; an intentionally public "
    "source map.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_FILE}/positive_own_git_head_high.json",
        f"tests/fixtures/rules/{RULE_FILE}/negative_status_only_no_signature.json",
    ),
)
def sensitive_file_exposed(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in _web_nodes(graph):
        for row, src in _dicts(node, "sensitive_files"):
            signature = str(row.get("signature") or "").strip()
            path = str(row.get("path") or "").strip()
            if not signature or not path:
                continue  # cond 9: never the HTTP status alone
            if SENSITIVE_HIGH_RE.search(path):
                severity = Severity.HIGH
            elif SENSITIVE_LOW_RE.search(path):
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM
            scoping = asset_scoping(graph, node, rctx)
            sha = str(row.get("sha256") or "")
            size = _int(row.get("size"))
            facts = (f"{path} (signature '{signature}'" + (f", {size} bytes" if size is not None else "")
                     + (f", sha256:{sha[:16]}" if sha else "") + ")")
            yield _build(
                RULE_FILE, node, scoping,
                title=f"Sensitive file exposed on {node.entity.display}: {path}",
                severity=severity,
                summary=f"{_entities.defang(node.entity.value)} serves {facts}; confirmed by its content signature, not the status.",
                criterion=f"CR23: content signature '{signature}' matched for {path} ({src or 'sensitive_files'})",
                evidence=[facts],
                fix="Remove the file from the web root, block the path, and rotate any credential it held.",
                tags=["exposure"],
                key=path,
            )


# ----------------------------------------------------------------------------------------
# CR24 public_cloud_bucket
# ----------------------------------------------------------------------------------------


@rule(
    RULE_BUCKET,
    "Cloud storage bucket of the target",
    "A cloud bucket attributed to the target by evidence (referenced by its pages, JS, archives, DNS/CNAME or the scope "
    "file): a public listing is HIGH; 403 is LOW 'bucket exists, private; ownership not verified'. Permutation-only hits "
    "are INFO 'unattributed' (existence only, no listing). Nothing is ever written to or downloaded from a bucket (P084 "
    "cond 10).",
    version="1",
    code="CR24",
    severity="high",
    criterion="attributed bucket: public listing (HIGH), exists private / other region (LOW); unattributed existence "
    "(INFO)",
    references=(*_REFERENCES, "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"),
    attack=("T1530", "T1619"),
    false_positives="A bucket that is public on purpose (static site, open data); a same-named bucket of an unrelated "
    "owner referenced by a third-party script.",
    fixtures=(
        f"tests/fixtures/rules/{RULE_BUCKET}/positive_attributed_public_listing_high.json",
        f"tests/fixtures/rules/{RULE_BUCKET}/positive_attributed_private_low.json",
        f"tests/fixtures/rules/{RULE_BUCKET}/positive_permutation_only_info.json",
        f"tests/fixtures/rules/{RULE_BUCKET}/negative_absent_or_unverified.json",
    ),
)
def public_cloud_bucket(graph: Graph, results: list[ModuleResult], rctx: Any) -> Iterator[Correlation]:
    for node in graph.nodes.values():
        for row, _src in _dicts(node, "cloud_buckets"):
            state = str(row.get("state") or "").strip().lower()
            bucket = str(row.get("bucket") or "").strip()
            if state not in BUCKET_EXISTS or not bucket:
                continue  # absent / could_not_verify: nothing to report (rule 5)
            provider = str(row.get("provider") or "cloud")
            attribution = str(row.get("attribution") or "").strip().lower()
            attributed = (bool(attribution) and attribution != "permutation") or row.get("attributed") is True
            if not attributed:
                severity = Severity.INFO
                text = f"{provider} bucket '{bucket}' exists (permutation only): unattributed, existence only, no listing"
            elif state == "public_listing":
                severity = Severity.HIGH
                text = f"{provider} bucket '{bucket}' attributed to the target ({attribution}) allows a public listing"
            elif state == "exists_private":
                severity = Severity.LOW
                text = f"{provider} bucket '{bucket}' ({attribution}): bucket exists, private; ownership not verified"
            else:
                severity = Severity.LOW
                text = f"{provider} bucket '{bucket}' ({attribution}) exists in another region; ownership not verified"
            scoping = asset_scoping(graph, node, rctx)
            yield _build(
                RULE_BUCKET, node, scoping,
                title=f"Cloud bucket of {node.entity.display}: {bucket}",
                severity=severity,
                summary=f"{text}. Nothing was written to or downloaded from the bucket.",
                criterion=f"CR24: {text}" + ("" if attributed else " (P084 cond 10: unattributed hits are INFO)"),
                evidence=[text, *([str(row.get('evidence'))] if row.get("evidence") else [])],
                fix="Review the bucket's access policy (block public access unless intended) with its owner.",
                tags=["exposure"],
                confidence=Confidence.PROBABLE if attributed else Confidence.POSSIBLE,
                key=bucket,
            )
