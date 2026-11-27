"""Offline tests of hunter_sender_check (P090 cond 4): own-domain pattern and BEC lookalike verdicts.
The module is offline (disclosure none): inline data, no network; uses the tests.fakes kit."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.email.hunter_io import HunterSenderCheck, domain_lookalike, hunter_pattern_regex, sender_plausible

OWN = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"},
                                        {"name": "exemplo.com.br", "verification": "confirmed"}]})
PATTERNS = {"example.com": "{first}.{last}"}
OPTS = ScanOptions(purpose="phishing triage, ticket EX-3")


def run(address: str, **kw):
    kw.setdefault("org_profile", OWN)
    kw.setdefault("settings", {"hunter_sender_check_patterns": PATTERNS})
    kw.setdefault("options", OPTS)
    http = FakeHttp()
    res = run_module(HunterSenderCheck, f"email:{address}", http, **kw)
    assert http.calls == []  # offline
    return res


@pytest.mark.parametrize("candidate, reason", [
    ("example.net", "tld_swap"),
    ("examp1e.com", "homoglyph"),
    ("exarnple.com", "homoglyph"),
    ("example-1.com", "hyphen_or_digit_variant"),
    ("exampel.com", "edit_distance=1"),
    ("example-billing.com", "own_label_inside"),
    ("exemplo.com", "tld_swap"),
])
def test_lookalikes(candidate, reason):
    found = domain_lookalike(candidate, ["example.com", "exemplo.com.br"])
    assert found is not None and found[0] == reason


def test_own_and_unrelated_domains_are_not_lookalikes():
    assert domain_lookalike("mail.example.com", ["example.com"]) is None
    assert domain_lookalike("example.com", ["example.com"]) is None
    assert domain_lookalike("unrelated.org", ["example.com"]) is None


def test_pattern_regex():
    rx = hunter_pattern_regex("{first}.{last}")
    assert rx.match("maria.souza") and rx.match("maria.souza2") and not rx.match("msouza")
    assert hunter_pattern_regex("{f}{last}").match("msouza")
    assert hunter_pattern_regex("no tokens") is None and hunter_pattern_regex("{first}<script>") is None


def test_verdicts():
    assert sender_plausible("maria.souza@example.com", ["example.com"], PATTERNS)["verdict"] == "plausible"
    assert sender_plausible("ceo.office.urgent@example.com", ["example.com"], PATTERNS)["verdict"] == "pattern_mismatch"
    assert sender_plausible("ceo@examp1e.com", ["example.com"], PATTERNS)["verdict"] == "lookalike_domain"
    assert sender_plausible("someone@unrelated.org", ["example.com"], PATTERNS)["verdict"] == "other_domain"
    assert sender_plausible("not-an-address", ["example.com"], PATTERNS)["verdict"] == "invalid"


def test_lookalike_sender_is_a_medium_finding():
    res = run("ceo@examp1e.com")
    assert res.status is Status.OK
    finding = res.findings[0]
    assert finding.severity.name == "MEDIUM" and "typosquat" in finding.tags and finding.criterion
    assert res.attributes["sender_check"]["own_domain"] == "example.com"


def test_pattern_mismatch_and_plausible():
    res = run("ceo.office.urgent@example.com")
    assert res.findings[0].title == "Own-domain sender does not fit the address pattern"
    res = run("maria.souza@example.com")
    assert res.status is Status.OK and res.findings[0].severity.name == "INFO"


def test_unrelated_is_empty_and_no_own_domains_is_skipped_config():
    assert run("someone@unrelated.org").status is Status.EMPTY
    res = run("someone@unrelated.org", org_profile=OrgProfile.empty(), settings={})
    assert res.status is Status.SKIPPED and res.reason_code == "config"
