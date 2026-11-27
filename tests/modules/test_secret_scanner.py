"""secret_scanner (P312, batch p1-G03-1): the shared offline engine and the text/file/JWT module.

No token-shaped value is committed: every positive vector is generated at test time (seeded) from
the rule's own pattern, and the fixture templates in tests/fixtures/secret_scanner/ carry
<<NAME>> placeholders that are filled with generated fake values. The negative fixture holds only
documented examples and placeholders. gitleaks_minimised.toml / gitleaks_truncated.toml are
minimised copies of the MIT-licensed gitleaks config (attribution in the files).
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import string
import time
import types
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.store import Store
from v3lum.modules.utility import secret_scanner as S
from v3lum.modules.utility.secret_scanner import SecretScanner
from v3lum.report import FORMATS, write_reports

try:  # Python 3.11+
    import re._constants as sre_c
    import re._parser as sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants as sre_c  # type: ignore[no-redef]
    import sre_parse  # type: ignore[no-redef]

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "secret_scanner"
DATA = Path(S.__file__).resolve().parents[2] / "data"
needs_toml = pytest.mark.skipif(S._toml is None, reason="no TOML parser (Python 3.11+ tomllib or tomli)")
BUNDLED_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"


# =============================================================================================
# test-time generation of fake values (nothing token-shaped is committed)
# =============================================================================================
ALNUM = string.ascii_letters + string.digits
_CATS = {
    sre_c.CATEGORY_DIGIT: string.digits, sre_c.CATEGORY_NOT_DIGIT: string.ascii_letters, sre_c.CATEGORY_WORD: ALNUM + "_",
    sre_c.CATEGORY_NOT_WORD: "-.+/", sre_c.CATEGORY_SPACE: " ", sre_c.CATEGORY_NOT_SPACE: ALNUM,
}
_PRINTABLE = [chr(c) for c in range(33, 127)] + [" "]
_REPEATS = tuple(op for op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, getattr(sre_c, "POSSESSIVE_REPEAT", None)) if op is not None)


def _class_chars(items) -> list[str]:
    chars: set[str] = set()
    negate = False
    for op, av in items:
        if op is sre_c.NEGATE:
            negate = True
        elif op is sre_c.LITERAL:
            chars.add(chr(av))
        elif op is sre_c.RANGE:
            lo, hi = av
            chars.update(chr(c) for c in range(lo, min(hi, 126) + 1) if c >= 32)
        elif op is sre_c.CATEGORY:
            chars.update(_CATS.get(av, ""))
    if negate:
        chars = {c for c in _PRINTABLE if c not in chars}
    return sorted(chars)


def _gen(tree, rng: random.Random, groups: dict[int, str], budget: int) -> str:
    """One random string the parsed pattern can match (anchors and lookarounds are left to the check)."""
    out: list[str] = []
    for op, av in tree:
        if op is sre_c.LITERAL:
            out.append(chr(av))
        elif op is sre_c.NOT_LITERAL:
            out.append(rng.choice([c for c in ALNUM if ord(c) != av]))
        elif op is sre_c.ANY:
            out.append(rng.choice(ALNUM))
        elif op is sre_c.IN:
            chars = _class_chars(av)
            out.append(rng.choice([c for c in chars if c in ALNUM] or chars))
        elif op in _REPEATS:
            lo, hi, sub = av
            hi = lo + budget if hi is sre_c.MAXREPEAT else hi
            n = rng.randint(lo, max(lo, min(hi, lo + budget)))
            if n == 0 and hi > 0 and rng.random() < 0.5:
                n = 1
            out.extend(_gen(sub, rng, groups, max(4, budget // 2)) for _ in range(n))
        elif op is sre_c.SUBPATTERN:
            gid, _add, _del, sub = av
            text = _gen(sub, rng, groups, budget)
            if gid:
                groups[gid] = text
            out.append(text)
        elif op is sre_c.BRANCH:
            out.append(_gen(rng.choice(av[1]), rng, groups, budget))
        elif op is sre_c.GROUPREF:
            out.append(groups.get(av, ""))
        elif op is sre_c.CATEGORY:
            out.append(rng.choice(_CATS.get(av, ALNUM)))
        elif op is sre_c.GROUPREF_EXISTS:
            gid, yes, no = av
            out.append(_gen(yes if gid in groups else (no or []), rng, groups, budget))
        elif op in (sre_c.AT, sre_c.ASSERT, sre_c.ASSERT_NOT):
            continue
        else:  # pragma: no cover - a construct the sampler does not know
            raise NotImplementedError(op)
    return "".join(out)


def _secret_span(rule: dict, match: re.Match) -> tuple[int, int]:
    """The span of the value the engine treats as the secret (secretGroup, else the first non-empty group)."""
    sg = rule.get("secret_group")
    groups = match.groups()
    if sg and len(groups) >= sg:
        return match.span(sg)
    idx = next((i for i, g in enumerate(groups, 1) if g), 0)
    return match.span(idx)


def _fires(rule: dict, engine: dict, text: str) -> bool:
    out = S.scan_text(text, engine)
    return any(rule["id"] in f["rule_ids"] for f in out["findings"])


def positive_vector(rule: dict, engine: dict, tries: int = 200) -> str | None:
    """A synthetic line the rule reports (keyword prefilter, regex, entropy and allowlists all pass)."""
    tree = sre_parse.parse(rule["regex"], re.ASCII)
    single = {**engine, "rules": [rule]}
    for i in range(tries):
        rng = random.Random(f"{rule['id']}:{i}")
        candidate = _gen(tree, rng, {}, rng.choice([8, 16, 24, 40]))
        if not rule["rx"].search(candidate):
            continue
        keywords = rule.get("keywords") or []
        line = candidate if not keywords or any(k in candidate.lower() for k in keywords) else f"{keywords[0]} {candidate}"
        text = f"config start\n{line}\nconfig end\n"
        if _fires(rule, single, text):
            return text
    return None


def negative_vector(rule: dict, positive: str) -> str:
    """The positive with its secret replaced by a placeholder of the same length."""
    a, b = _secret_span(rule, rule["rx"].search(positive))
    return positive[:a] + "x" * (b - a) + positive[b:]


def _pick(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def fake_values(seed: str = "p312") -> dict[str, str]:
    """Generated fake credentials for the fixture templates (deterministic per seed)."""
    rng = random.Random(seed)
    b64url = ALNUM + "-_"

    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")

    jwt = ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64({"iss": "https://auth.example.com", "jti": _pick(rng, ALNUM, 24),
                                                               "iat": 1764158400}), _pick(rng, b64url, 43)])
    pem_body = "\n".join(_pick(rng, ALNUM + "+/", 64) for _ in range(5))
    generic = _pick(rng, string.ascii_lowercase, 6) + _pick(rng, string.digits, 4) + _pick(rng, ALNUM, 22)
    return {
        "AWS": "AKIA" + _pick(rng, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
        "GHP": "ghp_" + _pick(rng, ALNUM, 36),
        "SLACK": "xoxb-" + _pick(rng, string.digits, 12) + "-" + _pick(rng, string.digits, 13) + "-" + _pick(rng, ALNUM, 24),
        "TG": rng.choice("123456789") + _pick(rng, string.digits, 9) + ":AA" + _pick(rng, b64url, 33),
        "TG_URL": rng.choice("123456789") + _pick(rng, string.digits, 9) + ":A" + _pick(rng, b64url, 34),
        "DISCORD": "https://discord.com/api/webhooks/" + rng.choice("123456789") + _pick(rng, string.digits, 17) + "/" + _pick(rng, b64url, 68),
        "JWT": jwt,
        "PEM": f"-----BEGIN RSA PRIVATE KEY-----\n{pem_body}\n-----END RSA PRIVATE KEY-----",
        "GENERIC": generic,
        "SMTP_PW": "Kx" + _pick(rng, ALNUM, 10) + "-" + _pick(rng, string.digits, 3),
    }


def secrets_of(values: dict[str, str]) -> list[str]:
    """The parts of the fake values that must never be persisted (the Discord token, a PEM body line...)."""
    out = [v for k, v in values.items() if k not in ("DISCORD", "PEM", "TG_URL")]
    out.append(values["DISCORD"].rsplit("/", 1)[1])
    out.append(values["PEM"].splitlines()[1])
    out.append(values["TG_URL"].split(":", 1)[1])
    return out


def fill(template: str, values: dict[str, str]) -> str:
    return re.sub(r"<<([A-Z_]+)>>", lambda m: values.get(m.group(1), m.group(0)), template)


# Documented placeholder values that look like real secrets to push-protection scanners are kept out of
# the fixture files and substituted here.
PLACEHOLDERS = {"@@SLACK_DOC_WEBHOOK@@": "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24}


def template(name: str) -> str:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    for marker, value in PLACEHOLDERS.items():
        text = text.replace(marker, value)
    return text


def scan_module(text: str, **kw):
    return run_module(SecretScanner, Entity.make(T.TEXT, text), FakeHttp(), **kw)


def by_rule(res) -> dict[str, object]:
    return {f.data["rule"]: f for f in res.findings if f.title.startswith("Secret exposed: ")}


def stored_view(res) -> list[object]:
    """What the module itself writes (findings without the seed entity, attributes, raw)."""
    findings = []
    for f in res.findings:
        d = f.to_dict()
        d.pop("entity", None)
        findings.append(d)
    return [findings, res.attributes, res.raw, res.error]


# =============================================================================================
# metadata and the bundled ruleset (c1, c2)
# =============================================================================================
def test_metadata():
    cls = SecretScanner
    assert (cls.disclosure, cls.hosts, cls.terms, cls.trust_tier) == ("none", (), "open", "n/a")
    assert cls.accepts == {T.TEXT, T.FILE, T.JWT} and cls.produces == set() and cls.default_enabled is True
    assert T.URL not in cls.accepts  # c1: it never fetches URLs
    source = Path(S.__file__).read_text(encoding="utf-8")
    assert "ctx.http" not in source and "requests" not in source and "urllib.request" not in source


@needs_toml
def test_bundled_gitleaks_ruleset_compiles():
    engine = S.default_engine()
    assert engine["error"] is None and engine["sha256"] == BUNDLED_SHA256
    stats = engine["stats"]
    assert (stats["rules"], stats["regex_rules"], stats["path_only"], stats["compile_errors"]) == (222, 221, 1, 0)
    assert stats["converted"] == 26 and stats["optimised"] == 5
    assert engine["skipped"] == ["pkcs12-file"]  # the single path-only rule
    assert len(engine["rules"]) == 221 + len(S.V3LUM_EXTRA_RULES)
    raw = (DATA / S.RULESET).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BUNDLED_SHA256
    notice = json.loads((DATA / "notices" / "gitleaks.json").read_text(encoding="utf-8"))
    assert "MIT" in json.dumps(notice) and "Zachary Rice" in json.dumps(notice)


def test_re2_to_python_conversion():
    assert S.convert_re2_to_python(r"[[:alnum:]]+") == "[0-9A-Za-z]+"
    assert S.convert_re2_to_python(r"abc(?i)def") == "abc(?i:def)"
    assert S.convert_re2_to_python(r"abc\z") == r"abc\Z"
    mid = re.compile(S.convert_re2_to_python(r"key(?i)Token=[a-z]{4}"), re.ASCII)
    assert mid.fullmatch("keyTOKEN=ABCD") and not mid.fullmatch("KEYtoken=abcd")
    posix = re.compile(S.convert_re2_to_python(r"^[[:alpha:]_][[:digit:]]+$"), re.ASCII)
    assert posix.match("a123") and posix.match("_9") and not posix.match("1a")
    doubled = S._DOUBLE_PREFIX + "(?:secret)" + ")"
    assert S.optimise_backtracking(doubled) != doubled
    assert re.compile(S.optimise_backtracking(doubled)).search("my.secret")


# =============================================================================================
# c3: one positive and one negative synthetic vector per rule
# =============================================================================================
@needs_toml
def test_every_rule_has_a_positive_and_a_negative_vector():
    engine = S.default_engine()
    no_positive, negative_fires, full_misses = [], [], []
    for rule in engine["rules"]:
        text = positive_vector(rule, engine)
        if text is None:
            no_positive.append(rule["id"])
            continue
        if not _fires(rule, engine, text):  # the full engine (all rules, keyword windows) reports it too
            full_misses.append(rule["id"])
        if _fires(rule, {**engine, "rules": [rule]}, negative_vector(rule, text)):
            negative_fires.append(rule["id"])
    assert not no_positive, f"rules without a generated positive vector: {no_positive}"
    assert not full_misses, f"positives the full engine misses: {full_misses}"
    assert not negative_fires, f"rules that report a placeholder: {negative_fires}"


@needs_toml
def test_documented_examples_and_placeholders_are_not_reported():
    out = S.scan_text(template("negative_synthetic.txt"))
    assert out["findings"] == [] and out["allowlisted"] >= 5
    for value, reason in (("AKIAIOSFODNN7EXAMPLE", "documented example"), ("sk_test_51ExampleTestKey0000", "test-mode key prefix"),
                          ("xxxxxxxx", "placeholder"), ("changeme", "placeholder"), ("${API_KEY}", "placeholder"),
                          ("<your-api-key>", "placeholder"), ("{{ vault_secret }}", "placeholder")):
        assert S.v3lum_allowlisted(value) == reason, value
    assert S.v3lum_allowlisted(fake_values()["GHP"]) is None


@needs_toml
def test_path_allowlist_and_keyword_prefilter():
    values = fake_values()
    text = f'GITHUB_TOKEN="{values["GHP"]}"\n'
    assert S.scan_text(text, path="web/node_modules/pkg/index.js")["path_allowlisted"] is True
    assert S.scan_text(text, path="web/app.js")["findings"]
    custom = S.compile_rules(None, extra=[{"id": "t-rule", "regex": r"(tk-[0-9]{6})", "keywords": ["zzq"], "entropy": None,
                                          "secret_group": 1, "kind": "token", "tags": []}])
    assert S.scan_text("value tk-123456", custom)["findings"] == []  # no keyword: the rule never runs
    assert S.scan_text("zzq tk-123456", custom)["findings"][0]["rule_id"] == "t-rule"


# =============================================================================================
# c2: ReDoS harness, input caps
# =============================================================================================
@needs_toml
def test_redos_harness_every_pattern_within_budget():
    budget = 1.0  # seconds per adversarial input (the slowest pattern takes < 0.1 s here)
    slow = []
    for rule in S.default_engine()["rules"]:
        for probe in S.redos_probe_inputs(rule):
            start = time.perf_counter()
            for _ in rule["rx"].finditer(probe):
                pass
            elapsed = time.perf_counter() - start
            if elapsed > budget:
                slow.append((rule["id"], round(elapsed, 2), probe[:30]))
    assert not slow, f"patterns over the ReDoS budget: {slow}"


@needs_toml
def test_input_caps_truncate_and_say_so():
    ghp = fake_values()["GHP"]
    long_line = "x" * (S.MAX_LINE + 10) + f' GITHUB_TOKEN="{ghp}"'
    out = S.scan_text(long_line)
    assert out["truncated"] is True and out["findings"] == []  # beyond 10k characters: not scanned
    capped = S.scan_text("a" * 100 + f'\nGITHUB_TOKEN="{ghp}"\n', max_bytes=50)
    assert capped["truncated"] is True and capped["findings"] == []
    res = scan_module(long_line)
    assert res.status is Status.OK
    assert any(f.title == "Input truncated for secret scanning" for f in res.findings)


# =============================================================================================
# c4-c8: masking, one finding per secret, severity from context, kit rules, nothing leaves
# =============================================================================================
def test_masking_rules():
    token = "ABCD" + "x" * 16 + "WXYZ"
    m = S.mask_secret(token, "aws-access-token")
    assert m == {"rule": "aws-access-token", "kind": "token", "display": "ABCD…WXYZ", "sha256": hashlib.sha256(token.encode()).hexdigest(),
                 "length": 24}
    short = S.mask_secret("k3y-abc-1234", "some-rule")
    assert short["display"] == "[redacted]" and short["sha256"] == hashlib.sha256(b"k3y-abc-1234").hexdigest()
    pw = S.mask_secret("Correct-Horse-Battery-9", "v3lum-smtp-password-assignment", "password")
    assert pw == {"rule": "v3lum-smtp-password-assignment", "kind": "password", "display": "[password redacted]", "sha256": None, "length": None}
    assert S.secret_kind("v3lum-phpmailer-password") == "password" and S.secret_kind("generic-api-key", 'db_password = "x"') == "password"
    assert S.secret_kind("aws-access-token") == "token"


@needs_toml
def test_template_findings_masked_deduplicated_and_never_pivoted():
    values = fake_values()
    res = scan_module(fill(template("positive_template.txt"), values))
    assert res.status is Status.OK and res.pivots == []  # c6: never pivoted
    found = by_rule(res)
    aws = found["aws-access-token"]
    assert aws.data["masked"]["display"] == values["AWS"][:4] + "…" + values["AWS"][-4:]
    assert aws.data["masked"]["sha256"] == hashlib.sha256(values["AWS"].encode()).hexdigest()
    assert aws.data["locations"] == [{"path": None, "line": 2}]
    ghp = found["github-pat"]
    text = fill(template("positive_template.txt"), values)
    expected = [n for n, line in enumerate(text.split("\n"), 1) if values["GHP"] in line]
    assert ghp.data["count"] == 2 and [loc["line"] for loc in ghp.data["locations"]] == expected  # one finding, N locations
    assert {"private-key", "jwt", "v3lum-discord-webhook-url", "v3lum-telegram-bot-token-url"} <= set(found)
    smtp = [f for f in found.values() if f.data["kind"] == "password"]
    assert smtp and all(f.data["masked"]["sha256"] is None and f.data["masked"]["display"] == "[password redacted]" for f in smtp)
    assert all("@" in f.key or ":" in f.key for f in smtp)  # keyed by location, no digest of a password
    generic = [f for f in res.findings if f.title == "Generic high-entropy secrets (count only)"]
    assert generic and generic[0].severity.label == "info"
    assert res.attributes["secret_counts"]["github-pat"] == 1
    for secret in secrets_of(values):
        assert_no_secret(secret, *stored_view(res))


@needs_toml
def test_kit_exfiltration_rules_and_abuse_recommendation():
    values = fake_values("kit")
    res = scan_module(fill(template("kit_template.php"), values))
    found = by_rule(res)
    assert {"v3lum-telegram-bot-token-bare", "v3lum-discord-webhook-url", "v3lum-phpmailer-password"} <= set(found)
    for rule in ("v3lum-telegram-bot-token-bare", "v3lum-discord-webhook-url"):
        f = found[rule]
        assert "phishing_kit_exfil" in f.tags and f.data["owner"] == "attacker_infra" and f.severity.label == "medium"
        assert "abuse" in f.data["recommendation"]
    assert found["v3lum-phpmailer-password"].data["masked"]["display"] == "[password redacted]"
    for secret in secrets_of(values):
        assert_no_secret(secret, *stored_view(res))


@needs_toml
def test_severity_from_ownership_context():
    org = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    own, third, unknown = (fake_values(s)["AWS"] for s in ("own", "third", "unknown"))
    text = (f"aws_access_key_id = {own}  # deploy user for app.example.com\n"
            f"aws_access_key_id = {third}  # partner bucket at files.example.net\n"
            f"aws_access_key_id = {unknown}\n")
    res = scan_module(text, org_profile=org)
    sev = {f.data["masked"]["sha256"]: (f.data["owner"], f.severity.label) for f in res.findings if f.data.get("rule") == "aws-access-token"}
    digest = {v: hashlib.sha256(v.encode()).hexdigest() for v in (own, third, unknown)}
    assert sev[digest[own]] == ("own", "critical")
    assert sev[digest[third]] == ("third_party", "medium")
    assert sev[digest[unknown]] == ("unknown", "high")
    assert S.secret_severity("aws-access-token", "own")["recommendation"].startswith("notify the owning team")
    assert S.secret_severity("mailgun-private-api-token", "own")["severity"] == "high"
    assert S.secret_severity("mailgun-private-api-token")["severity"] == "medium"
    assert S.secret_severity("generic-api-key", "own") == {"severity": "info", "count_only": True, "recommendation": ""}
    no_org = scan_module(f"aws_access_key_id = {unknown}\n")
    assert by_rule(no_org)["aws-access-token"].severity.label == "high"


@needs_toml
def test_file_input_keeps_the_location_and_skips_binary(tmp_path):
    values = fake_values("file")
    path = tmp_path / "settings.env"
    path.write_text(f"# app settings\nGITHUB_TOKEN={values['GHP']}\n", encoding="utf-8")
    res = run_module(SecretScanner, Entity.make(T.FILE, str(path)), FakeHttp())
    assert by_rule(res)["github-pat"].data["locations"] == [{"path": str(path), "line": 2}]
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02" * 4000 + values["GHP"].encode())
    assert SecretScanner().applies(Entity.make(T.FILE, str(binary)), None) is False
    huge = tmp_path / "huge.log"
    with open(huge, "wb") as fh:
        fh.truncate(S.MAX_FILE_BYTES + 1)  # sparse: nothing is written
    assert SecretScanner().applies(Entity.make(T.FILE, str(huge)), None) is False
    empty = tmp_path / "clean.txt"
    empty.write_text("nothing to see here\n", encoding="utf-8")
    assert run_module(SecretScanner, Entity.make(T.FILE, str(empty)), FakeHttp()).status is Status.EMPTY


def _jwt(header: dict, payload: dict, sig: str = "") -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{enc(header)}.{enc(payload)}.{sig}"


def test_jwt_decoded_offline_with_personal_claims_as_flags_only():
    token = _jwt({"alg": "none", "typ": "JWT"}, {"iss": "https://auth.example.com", "sub": "user-4711", "email": "person@example.org",
                                                 "name": "Example Person", "exp": 1764158400})
    res = run_module(SecretScanner, Entity.make(T.JWT, token), FakeHttp())
    titles = {f.title: f for f in res.findings}
    assert titles["Unsigned JWT (alg 'none')"].severity.label == "low"
    claims = res.attributes["jwt_claims"]
    assert claims["iss"] == "https://auth.example.com" and claims["exp"] == "2025-11-26T12:00:00Z"
    assert (claims["has_sub"], claims["has_email"], claims["has_name"]) == (True, True, True)
    dump = json.dumps(stored_view(res), default=str)
    assert "user-4711" not in dump and "person@example.org" not in dump and "Example Person" not in dump
    signed = _jwt({"alg": "HS256", "typ": "JWT"}, {"iss": "https://auth.example.com"}, "c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVlLTEyMzQ")
    res2 = run_module(SecretScanner, Entity.make(T.JWT, signed), FakeHttp())
    assert res2.attributes["jwt_header"] == {"alg": "HS256", "typ": "JWT"} and not any("Unsigned" in f.title for f in res2.findings)
    broken = run_module(SecretScanner, Entity.make(T.JWT, "bm90LWpzb24.bm90LWpzb24.c2ln"), FakeHttp())
    assert broken.status is Status.ERROR and "could not be decoded" in broken.error


# =============================================================================================
# ruleset loading: fixtures, missing TOML parser, optional google-re2
# =============================================================================================
@needs_toml
def test_minimised_and_broken_rulesets():
    parsed = S.parse_gitleaks_toml((FIXTURES / "gitleaks_minimised.toml").read_bytes())
    assert parsed["ok"] and parsed["stats"]["rules"] == 15 and parsed["stats"]["compile_errors"] == 0
    engine = S.compile_rules(parsed, extra=())
    ghp = fake_values("mini")["GHP"]
    assert S.scan_text(f'token = "{ghp}"', engine)["findings"][0]["rule_id"] == "github-pat"
    broken = S.parse_gitleaks_toml((FIXTURES / "gitleaks_truncated.toml").read_text(encoding="utf-8"))
    assert broken["ok"] is False and broken["error"].startswith("malformed toml")
    html = S.parse_gitleaks_toml("<!DOCTYPE html><html><body>rate limited</body></html>")
    assert html["ok"] is False and html["error"] == "html instead of toml"


def test_missing_toml_parser_is_unavailable(monkeypatch):
    monkeypatch.setattr(S, "_toml", None)
    assert S.parse_gitleaks_toml('title = "x"')["error"].startswith("no TOML parser")
    monkeypatch.setattr(S, "default_engine", lambda: {"rules": [], "allowlists": [], "error": "no TOML parser", "sha256": ""})
    res = scan_module("GITHUB_TOKEN=whatever")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


@needs_toml
def test_google_re2_used_when_installed(monkeypatch):
    parsed = S.parse_gitleaks_toml((FIXTURES / "gitleaks_minimised.toml").read_bytes())
    monkeypatch.setattr(S, "_re2", types.SimpleNamespace(compile=lambda p: re.compile(S.convert_re2_to_python(p), re.ASCII)))
    engines = {r["id"]: r["engine"] for r in S.compile_rules(parsed)["rules"]}
    assert engines["github-pat"] == "re2" and engines["v3lum-discord-webhook-url"] == "re"  # V3LUM rules are Python syntax

    def broken(_pattern):
        raise ValueError("unsupported")

    monkeypatch.setattr(S, "_re2", types.SimpleNamespace(compile=broken))
    assert {r["engine"] for r in S.compile_rules(parsed)["rules"]} == {"re"}
    assert json.loads((DATA / "extras" / "re2.json").read_text(encoding="utf-8"))


def test_entropy():
    assert S.shannon_entropy("aaaa") == 0.0 and S.shannon_entropy("ab") == 1.0 and S.shannon_entropy("") == 0.0


# =============================================================================================
# c5: end to end - no fake secret on disk (case DB, evidence, cache, reports) or in events
# =============================================================================================
@needs_toml
def test_end_to_end_no_secret_on_disk_or_in_events(tmp_path):
    values = fake_values("e2e")
    jwt_seed = fake_values("e2e-seed")["JWT"]
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    kit = inputs / "kit.php"
    kit.write_text(fill(template("kit_template.php"), values), encoding="utf-8")
    conf = inputs / "config.txt"
    conf.write_text(fill(template("positive_template.txt"), values), encoding="utf-8")
    events: list[tuple[str, str]] = []
    rt = make_runtime(FakeHttp())
    rt.events.subscribe(lambda kind, payload: events.append((kind, repr(payload))))
    seeds = [Entity.make(T.FILE, str(kit)), Entity.make(T.FILE, str(conf)), Entity.make(T.JWT, jwt_seed)]
    case = Engine(rt, ScanOptions(include={"secret_scanner"}, depth=1)).investigate(seeds)
    results = [r for r in case.results if r.module == "secret_scanner"]
    assert len(results) == 3 and sum(len(r.findings) for r in results) >= 8
    data = case.to_dict()
    out_dir = tmp_path / "reports"
    write_reports(data, FORMATS, out_dir)
    store = Store()
    store.save_case(data)
    store.close()
    assert any(paths.home().rglob("*"))
    for secret in secrets_of(values):  # secrets found in the files: nowhere, events included
        assert_no_secret(secret, paths.home(), out_dir, json.dumps(data, default=str), repr(events))
    # the JWT seed is a SECRET_TYPES input: written redacted to the case, evidence and reports (the
    # in-memory event objects carry the analyst's own seed Entity; listeners render entity.display)
    assert_no_secret(jwt_seed, paths.home(), out_dir, json.dumps(data, default=str))
