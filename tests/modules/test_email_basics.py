"""email_basics (reference DoH-only module): pivots, generic addresses and rule 5 (P328 cond 8).

A DoH failure must never become mx_valid=False or 'domain does not accept mail'. Fixtures in
tests/fixtures/email_basics/ are trimmed real DoH MX answers (github.com, example.com null MX).
"""

from __future__ import annotations

from tests.fakes import DeadHttp, FakeHttp, add_dns, add_dns_failure, doh_url, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.email.email_basics import EmailBasics


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def run(http, address):
    return EmailBasics().run(Entity.make("email", address), make_ctx(EmailBasics, http))


def titles(res):
    return {f.title for f in res.findings}


ABSENCE_TITLES = {"Email domain does not accept mail", "Email domain does not exist (NXDOMAIN)"}


# ------------------------------------------------------------------ moved cases
def test_email_basics_corporate():
    http = FakeHttp()
    add_dns(http, "acme.com", "MX", ["10 mx.acme.com."])
    res = run(http, "john.doe+news@acme.com")
    assert res.attributes["free_provider"] is False and res.attributes["mx_valid"] is True
    assert "acme.com" in pivots(res, T.DOMAIN)
    assert "john.doe@acme.com" in pivots(res, T.EMAIL)
    assert "Plus-addressing used" in titles(res)
    assert not res.source_statuses  # the DoH source answered
    http.assert_hosts_within(EmailBasics)


def test_derived_personal_identifiers_wait_for_the_analyst():
    """Only the typed address goes to other sources: the base mailbox and the local-part handle are
    pivots for analyst selection (AR07, A8)."""
    http = FakeHttp()
    add_dns(http, "acme.com", "MX", ["10 mx.acme.com."])
    res = run(http, "john.doe+news@acme.com")
    base = next(p for p in res.pivots if p.entity.type is T.EMAIL)
    assert base.entity.value == "john.doe@acme.com" and base.expand is False and base.note
    handle = next(p for p in res.pivots if p.entity.type is T.USERNAME)
    assert handle.expand is False


def test_email_basics_free_and_dead_domain():
    http = FakeHttp()
    add_dns(http, "gmail.com", "MX", ["5 gmail-smtp-in.l.google.com."])
    res = run(http, "someone@gmail.com")
    assert res.attributes["free_provider"] is True
    dom = next(p for p in res.pivots if p.entity.type is T.DOMAIN)
    assert dom.expand is False
    http2 = FakeHttp()
    add_dns(http2, "no-such-domain.example", "MX", [], status=3, provider="all")  # confirmed by a 2nd resolver
    res2 = run(http2, "x@no-such-domain.example")
    finding = next(f for f in res2.findings if "does not exist" in f.title)
    assert finding.severity.label == "low" and "second resolver" in finding.criterion
    assert res2.attributes["mx_valid"] is False


# ------------------------------------------------------------------ real fixtures
def test_real_github_mx():
    http = FakeHttp().add("GET", doh_url("github.com", "MX"), json=module_fixture(EmailBasics, "github.com_MX.json"))
    res = run(http, "octocat@github.com")
    assert res.attributes["mx"] == ["github-com.mail.protection.outlook.com"]
    assert res.attributes["mx_valid"] is True
    assert not (titles(res) & ABSENCE_TITLES)
    username = next(p for p in res.pivots if p.entity.type is T.USERNAME)
    assert username.entity.value == "octocat" and username.expand is False


def test_null_mx_and_generic_address():
    http = FakeHttp().add("GET", doh_url("example.com", "MX"), json=module_fixture(EmailBasics, "example.com_MX.json"))
    res = run(http, "someone@example.com")
    assert res.attributes["mx_valid"] is False
    refuses = next(f for f in res.findings if f.title == "Email domain does not accept mail")
    assert refuses.criterion and "null MX" in refuses.description
    assert res.attributes["generic_address"] == "example_domain"
    generic = next(f for f in res.findings if f.title == "Generic, role or test address")
    assert {"info", "context_only"} <= set(generic.tags)  # context only, never scored
    assert not any(p.entity.type is T.USERNAME for p in res.pivots)  # no handle pivot for generic mailboxes


def test_role_address_flagged():
    http = FakeHttp()
    add_dns(http, "acme.com", "MX", ["10 mx.acme.com."])
    res = run(http, "noreply@acme.com")
    assert res.attributes["generic_address"] == "role"


def test_v1_role_accounts_stay_flagged():
    """The role mailboxes of the v1 module list (administrator, helpdesk, hr, it, ti) live in the
    central data/generic_addresses.json now: they are still flagged, never handle pivots."""
    for local in ("administrator", "helpdesk", "hr", "it", "ti"):
        http = FakeHttp()
        add_dns(http, "acme.com", "MX", ["10 mx.acme.com."])
        res = run(http, f"{local}@acme.com")
        assert res.attributes["generic_address"] == "role", local
        assert not any(p.entity.type is T.USERNAME for p in res.pivots), local


def test_implicit_mx_and_no_mail_on_noerror():
    http = FakeHttp()
    add_dns(http, "web-only.example", "MX", [])
    add_dns(http, "web-only.example", "A", ["203.0.113.80"])
    add_dns(http, "web-only.example", "AAAA", [])
    res = run(http, "ops@web-only.example")
    assert res.attributes["mx_valid"] is True  # RFC 5321 implicit MX
    http2 = FakeHttp()
    for rtype in ("MX", "A", "AAAA"):
        add_dns(http2, "nomail.example", rtype, [])
    res2 = run(http2, "ops@nomail.example")
    assert res2.attributes["mx_valid"] is False
    assert "Email domain does not accept mail" in titles(res2)


# ------------------------------------------------------------------ rule 5: could not verify
def test_dead_doh_never_claims_absence():
    res = run(DeadHttp(), "john@acme.com")
    assert res.status is Status.OK  # the address itself still yields its pivots
    assert "mx_valid" not in res.attributes
    assert not (titles(res) & ABSENCE_TITLES)
    assert "could not be verified" in res.error
    assert "acme.com" in pivots(res, T.DOMAIN)
    outcome = res.source_statuses["core_doh.resolvers"]  # coverage sees 'could not verify', not 'answered'
    assert outcome["status"] == "error" and outcome["reason_code"] in ("error", "timeout")


def test_dead_doh_through_the_engine():
    res = run_module(EmailBasics, "email:john@acme.com", DeadHttp())
    assert res.status is Status.OK
    assert "mx_valid" not in res.attributes and not (titles(res) & ABSENCE_TITLES)


def test_servfail_refused_429_and_challenge_are_unknown():
    for kind in ("servfail", "refused", "http429", "challenge", "timeout"):
        http = FakeHttp()
        add_dns_failure(http, "acme.com", "MX", kind=kind, provider="all")
        res = run(http, "john@acme.com")
        assert "mx_valid" not in res.attributes, kind
        assert not (titles(res) & ABSENCE_TITLES), kind


def test_unconfirmed_nxdomain_is_unknown():
    http = FakeHttp()
    add_dns(http, "maybe.example", "MX", [], status=3)  # Google NXDOMAIN
    add_dns_failure(http, "maybe.example", "MX", kind="servfail", provider="cloudflare")
    res = run(http, "x@maybe.example")
    assert "mx_valid" not in res.attributes
    assert not (titles(res) & ABSENCE_TITLES)


def test_implicit_mx_failure_is_unknown():
    http = FakeHttp()
    add_dns(http, "half.example", "MX", [])
    add_dns_failure(http, "half.example", "A", kind="servfail", provider="all")
    add_dns(http, "half.example", "AAAA", [])
    res = run(http, "x@half.example")
    assert "mx_valid" not in res.attributes
    assert not (titles(res) & ABSENCE_TITLES)


# ------------------------------------------------------------------ P088 C1: free providers from the data files
def test_free_providers_come_from_the_shared_data_files():
    """The v1 hard-coded FREE_PROVIDERS moved into v3lum/data/email_hygiene (one set of data files,
    PSL-aware): the AfterShip list plus the V3LUM supplement (Brazilian webmail, former v1 entries)."""
    import v3lum.modules.email.email_basics as eb

    assert not hasattr(eb, "FREE_PROVIDERS")
    assert "github.email_hygiene_aftership_free" in EmailBasics.sources
    for address in ("fulano@bol.com.br", "x@tuta.io", "x@live.com.br", "x@mail.uol.com.br"):
        domain = address.split("@", 1)[1]
        http = FakeHttp()
        add_dns(http, domain, "MX", ["10 mx." + domain + "."])
        res = run(http, address)
        assert res.attributes["free_provider"] is True, address
        dom = next(p for p in res.pivots if p.entity.type is T.DOMAIN)
        assert dom.expand is False, address
    http = FakeHttp()
    add_dns(http, "acme-industria.com.br", "MX", ["10 mx.acme-industria.com.br."])
    assert run(http, "joao@acme-industria.com.br").attributes["free_provider"] is False


def test_golden_path_acceptance_route_replays():
    """tests/fixtures/acceptance/email/email_basics.json replays the real null-MX answer of example.com."""
    from tests.fakes import fixture

    routes = fixture("acceptance/email/email_basics.json")
    http = FakeHttp()
    for route in routes["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route["headers"])
    res = run_module(EmailBasics, "email:someone@example.com", http)
    assert res.status is Status.OK and res.attributes["mx_valid"] is False
    assert len(http.calls) == len(routes["routes"])
