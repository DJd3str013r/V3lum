"""email_hygiene (P088): offline disposable / free-provider / role-account / relay classification.

Lists: the CC0 disposable-email-domains blocklist and the MIT AfterShip free/role lists, bundled in
v3lum/data/email_hygiene/ and registered as refreshable datasets with the bundled copy as fallback;
the V3LUM supplement adds temp-mail and Brazilian webmail domains and the relay services. Trimmed
real list excerpts for the dataset path are in tests/fixtures/email_hygiene/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import DeadHttp, FakeHttp, make_ctx, make_runtime, run_module
from v3lum.core import datasets
from v3lum.core.datasets import DatasetError
from v3lum.core.models import Status
from v3lum.modules.email import email_hygiene as eh
from v3lum.modules.email.email_hygiene import (
    DISPOSABLE_DATASET,
    FREE_DATASET,
    ROLE_DATASET,
    EmailHygiene,
    candidate_domains,
    classify_address,
    classify_domain,
    hygiene_lists,
    is_free_provider,
    parse_domain_list,
    parse_go_string_set,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "email_hygiene"
DISPOSABLE_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
FREE_URL = "https://raw.githubusercontent.com/AfterShip/email-verifier/master/metadata_free.go"
ROLE_URL = "https://raw.githubusercontent.com/AfterShip/email-verifier/master/metadata_role.go"


def titles(res):
    return {f.title for f in res.findings}


# ------------------------------------------------------------------ list parsing (bundled data)
def test_bundled_lists_parse_and_merge():
    lists = hygiene_lists()
    assert len(lists.disposable) >= eh.MIN_DISPOSABLE and len(lists.free) >= eh.MIN_FREE and len(lists.roles) >= eh.MIN_ROLES
    assert lists.origin == {"disposable": "bundled", "free": "bundled", "roles": "bundled"}
    assert "yopmail.com" in lists.disposable and "gmail.com" in lists.free and "simplelogin.io" in lists.relay


def test_trimmed_real_excerpts_parse():
    blocklist = parse_domain_list((FIXTURES / "disposable_blocklist.conf").read_text(encoding="utf-8"))
    assert {"0-mailer.dynv6.net", "agent.qq.com", "yopmail.com", "21cn.com"} <= blocklist
    free = parse_go_string_set((FIXTURES / "aftership_free.go").read_text(encoding="utf-8"))
    assert {"gmail.com", "uol.com.br", "duck.com"} <= free
    roles = parse_go_string_set((FIXTURES / "aftership_role.go").read_text(encoding="utf-8"))
    assert roles and all(r == r.lower() for r in roles)
    assert parse_domain_list("<html>not a list</html>\n") == frozenset()
    assert parse_go_string_set(None) == frozenset()


def test_local_supplement_c3():
    """P088 C3: the missing temp-mail domains are disposable and the Brazilian webmail domains free."""
    lists = hygiene_lists()
    for domain in ("pee.place", "tempmail.net", "omail.io"):
        assert classify_domain(domain, lists)["disposable"] is True, domain
    for domain in ("uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "globo.com", "globomail.com", "zipmail.com.br", "r7.com", "yahoo.com.br", "hotmail.com.br", "outlook.com.br"):
        facts = classify_domain(domain, lists)
        assert facts["free_provider"] is True and facts["disposable"] is False, domain


def test_former_email_basics_free_providers_are_kept():
    """P088 C1: the hard-coded v1 FREE_PROVIDERS moved into the data files (none lost)."""
    for domain in ("live.com.br", "tuta.io", "tutanota.com", "gmail.com", "proton.me", "inbox.com"):
        assert is_free_provider(domain), domain


# ------------------------------------------------------------------ PSL-aware matching (C2)
def test_psl_aware_matching():
    lists = hygiene_lists()
    assert candidate_domains("a.b.yopmail.com") == ["a.b.yopmail.com", "b.yopmail.com", "yopmail.com"]
    assert candidate_domains("co.uk") == []  # a public suffix is never a candidate
    # an entry below its registrable domain (agent.qq.com) and one under a PSL private suffix (dynv6.net)
    assert classify_domain("x.agent.qq.com", lists)["disposable"] is True
    assert classify_domain("qq.com", lists)["disposable"] is False
    assert classify_domain("mail.0-mailer.dynv6.net", lists)["disposable"] is True
    assert classify_domain("someone-else.dynv6.net", lists)["disposable"] is False  # never the public suffix
    assert classify_domain("mail.uol.com.br", lists)["free_provider"] is True


def test_idn_domains_are_matched_as_punycode():
    lists = eh.HygieneLists(disposable=frozenset({"xn--bcher-kva.example"}), free=frozenset(), relay=frozenset(), roles=frozenset())
    assert classify_domain("bücher.example", lists)["disposable"] is True


# ------------------------------------------------------------------ relay services (C4)
def test_relay_is_never_disposable_even_when_an_upstream_list_says_so():
    lists = hygiene_lists()
    tainted = eh.HygieneLists(lists.disposable | {"simplelogin.io", "addy.io"}, lists.free, lists.relay, lists.roles)
    for domain in ("simplelogin.io", "addy.io", "anonaddy.com", "burnermail.io", "duck.com", "mozmail.com"):
        facts = classify_domain(domain, tainted)
        assert facts["relay"] is True and facts["disposable"] is False, domain
    assert classify_domain("simplelogin.io", tainted)["notes"]


def test_relay_module_finding_is_context_only():
    res = run_module(EmailHygiene, "email:alias@simplelogin.io", FakeHttp())
    assert res.status is Status.OK
    assert res.attributes["relay"] is True and res.attributes["disposable"] is False
    relay = next(f for f in res.findings if f.title == "Privacy relay / alias service")
    assert relay.severity.label == "info" and {"privacy_relay", "context_only"} <= set(relay.tags)
    assert "Disposable e-mail domain" not in titles(res)


# ------------------------------------------------------------------ the module (offline, C1/C6)
def test_disposable_address():
    http = FakeHttp()
    res = run_module(EmailHygiene, "email:throwaway@yopmail.com", http)
    assert res.status is Status.OK
    assert res.attributes["disposable"] is True and res.attributes["free_provider"] is False
    assert res.attributes["relay"] is False and res.attributes["role_account"] is False
    finding = next(f for f in res.findings if f.title == "Disposable e-mail domain")
    assert finding.severity.label == "low" and finding.criterion and "weak_signal" in finding.tags
    assert http.calls == []  # offline: no SMTP, no HTTP, no DNS (C6)


def test_free_webmail_and_brazilian_provider():
    res = run_module(EmailHygiene, "email:fulano.silva@uol.com.br", FakeHttp())
    assert res.attributes["free_provider"] is True and res.attributes["disposable"] is False
    assert not res.findings  # free webmail is a fact, not a finding (email_basics reports it)


def test_role_accounts_share_the_a4_list():
    """P088 C2: one role list - the A4 generic-address file plus the AfterShip roles."""
    a4 = run_module(EmailHygiene, "email:contato@acme.com.br", FakeHttp())
    assert a4.attributes["role_account"] is True and a4.attributes["generic_address"] == "role"
    assert "Role account (team mailbox)" not in titles(a4)  # A4 roles: email_basics flags them already
    lists = hygiene_lists()
    aftership_only = next(r for r in sorted(lists.roles) if r.isalpha() and r not in {"info", "sales", "admin", "support", "contact", "billing"} and classify_address(f"{r}@acme.com.br", lists)["role_source"] == "aftership")
    res = run_module(EmailHygiene, f"email:{aftership_only}@acme.com.br", FakeHttp())
    assert res.attributes["role_account"] is True
    role = next(f for f in res.findings if f.title == "Role account (team mailbox)")
    assert {"info", "context_only"} <= set(role.tags)


def test_ordinary_address_and_plus_tag():
    lists = hygiene_lists()
    facts = classify_address("john.doe+news@acme.com.br", lists)
    assert facts["valid"] and facts["role_account"] is False and facts["local_part"] == "john.doe"
    assert classify_address("info+x@acme.com", lists)["role_account"] is True  # '+tag' ignored


def test_domain_input():
    res = run_module(EmailHygiene, "domain:mailinator.com", FakeHttp())
    assert res.status is Status.OK and res.attributes["disposable"] is True
    assert "role_account" not in res.attributes


def test_public_suffix_is_not_applicable():
    res = run_module(EmailHygiene, "domain:com.br", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_tlp_red_runs_offline():
    """C1: the offline classification works under TLP:RED (disclosure 'none', no network at all)."""
    res = run_module(EmailHygiene, "email:throwaway@yopmail.com", DeadHttp(), tlp="red")
    assert res.status is Status.OK and res.attributes["disposable"] is True
    assert res.hosts == {}


# ------------------------------------------------------------------ refreshable datasets (C2)
def _install(monkeypatch, http):
    monkeypatch.setattr(eh, "MIN_DISPOSABLE", 5)
    monkeypatch.setattr(eh, "MIN_FREE", 5)
    monkeypatch.setattr(eh, "MIN_ROLES", 3)
    rt = make_runtime(http)
    for name in (DISPOSABLE_DATASET, FREE_DATASET, ROLE_DATASET):
        monkeypatch.setitem(datasets.DATASETS[name], "min_bytes", 1)  # trimmed excerpts are tiny
        result = rt.data.update(name)
        assert result.ok, result.reason
    return rt


def test_local_dataset_copy_is_preferred(monkeypatch):
    blocklist = (FIXTURES / "disposable_blocklist.conf").read_text(encoding="utf-8") + "fresh-temp-mail.example\n"
    http = (
        FakeHttp()
        .add("GET", DISPOSABLE_URL, text=blocklist, headers={"content-type": "text/plain"})
        .add("GET", FREE_URL, text=(FIXTURES / "aftership_free.go").read_text(encoding="utf-8"), headers={"content-type": "text/plain"})
        .add("GET", ROLE_URL, text=(FIXTURES / "aftership_role.go").read_text(encoding="utf-8"), headers={"content-type": "text/plain"})
    )
    rt = _install(monkeypatch, http)
    ctx = make_ctx(EmailHygiene, runtime=rt, entity="domain:fresh-temp-mail.example")
    lists = hygiene_lists(ctx)
    assert lists.origin == {"disposable": "dataset", "free": "dataset", "roles": "dataset"}
    assert classify_domain("fresh-temp-mail.example", lists)["disposable"] is True
    calls = len(http.calls)
    res = run_module(EmailHygiene, "domain:fresh-temp-mail.example", runtime=rt)
    assert res.attributes["disposable"] is True and len(http.calls) == calls  # never downloads in a run
    assert {d["name"] for d in res.datasets} >= {DISPOSABLE_DATASET}


def test_bad_refresh_keeps_the_bundled_fallback(monkeypatch):
    http = FakeHttp().add("GET", DISPOSABLE_URL, text="<html><title>Just a moment...</title></html>", headers={"content-type": "text/html"})
    rt = make_runtime(http)
    result = rt.data.update(DISPOSABLE_DATASET)
    assert not result.ok
    ctx = make_ctx(EmailHygiene, runtime=rt, entity="domain:yopmail.com")
    lists = hygiene_lists(ctx)
    assert lists.origin["disposable"] == "bundled" and "yopmail.com" in lists.disposable


def test_dataset_validators_reject_bad_bodies(tmp_path):
    page = tmp_path / "page.conf"
    page.write_text("<!doctype html><html>blocked</html>", encoding="utf-8")
    with pytest.raises(DatasetError):
        eh._validate_domain_list(page)
    short = tmp_path / "short.conf"
    short.write_text("yopmail.com\n", encoding="utf-8")
    with pytest.raises(DatasetError):
        eh._validate_domain_list(short)
    go = tmp_path / "free.go"
    go.write_text('var freeDomains = map[string]bool {\n\t"gmail.com": true,\n}', encoding="utf-8")
    with pytest.raises(DatasetError):
        eh._validate_free(go)
    assert eh._validate_go_set(go, 1) is True


def test_golden_path_acceptance_routes_are_offline():
    from tests.fakes import fixture

    for entity, path in (("email:someone@example.com", "acceptance/email/email_hygiene.json"), ("domain:example.com", "acceptance/domain/email_hygiene.json")):
        assert fixture(path)["routes"] == []
        res = run_module(EmailHygiene, entity, FakeHttp())
        assert res.status in (Status.OK, Status.EMPTY)
