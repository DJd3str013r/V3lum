"""lint.forbidden_probe: the shared LINT-03/04/05 tables (team rules 2, 4 and 7; A5 rule 2, A7)."""

from __future__ import annotations

import pytest

from v3lum.core import lint
from v3lum.core.lint import (
    CPF_LOOKUP_HOSTS,
    FORBIDDEN_PROBE_PATTERNS,
    PEOPLE_SEARCH_DENYLIST,
    SUBMISSION_PATTERNS,
    forbidden_probe,
    probe_violations,
)


@pytest.mark.parametrize(
    "url,method",
    [
        # sign-up / registration
        ("https://github.com/signup_check/username?value={}", "GET"),
        ("https://www.example.com/sign-up", "GET"),
        ("https://discord.com/api/v9/auth/register", "POST"),
        ("https://example.com/users/registration?email={}", "GET"),
        # availability / existence checks
        ("https://api.twitter.com/i/users/username_available.json?username={}", "GET"),
        ("https://www.reddit.com/api/username_available.json?user={}", "GET"),
        ("https://forum.example.com/u/check_username.json?username={}", "GET"),
        ("https://www.example.com/api/v1/checkUsername?u={}", "GET"),
        ("https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/", "GET"),
        ("https://example.com/api/availability?name={}", "GET"),
        ("https://login.yahoo.com/account/module/create?validateField=yid", "GET"),
        # e-mail (SMTP) verification
        ("https://api.hunter.io/v2/email-verifier?email={}", "GET"),
        ("https://example.com/verify-email?address={}", "GET"),
        # password reset / recovery
        ("https://accounts.spotify.com/en/password-reset", "GET"),
        ("https://example.com/reset-password?email={}", "POST"),
        ("https://example.com/forgot", "GET"),
        ("https://example.com/forgotPassword", "GET"),
        ("https://example.com/account/recovery", "GET"),
        # login
        ("https://www.linkedin.com/login", "GET"),
        ("https://accounts.google.com/signin/v2/identifier", "GET"),
        ("https://example.com/users/sign_in", "GET"),
        ("/api/login", "POST"),
        # the account as a query parameter of an existence/availability/verification oracle
        ("https://signup.example.com/api/check?username={account}", "GET"),
        ("https://example.com/ajax/check.php?email={account}", "GET"),
        ("https://example.com/api/available?username={account}", "GET"),
        ("https://example.com/api/v1/users/exists?username={account}", "GET"),
        ("https://example.com/api/isAvailable?handle={account}", "GET"),
        ("https://accounts.example.com/get_username_suggestions?requested_username={account}", "GET"),
        ("https://api.example.com/v2/usernames/{account}/available", "GET"),
        ("https://www.example.com/user/exists/{account}", "GET"),
        # SMTP / mailbox verification services
        ("https://api.kickbox.com/v2/verify?email={account}", "GET"),
        ("https://api.neverbounce.com/v4/single/check?email={account}", "GET"),
        ("https://hunter.io/verify/{account}", "GET"),
        # more sign-up and reset shapes
        ("https://example.com/accounts/emailsignup/", "GET"),
        ("https://www.instagram.com/accounts/web_create_ajax/attempt/", "POST"),
        ("https://example.com/create-account?email={account}", "GET"),
        ("https://example.com/lost-password?user={account}", "GET"),
        ("https://example.com/users/password/new", "GET"),
        ("https://example.com/recover?email={account}", "GET"),
        ("https://example.com/api/v1/sessions", "POST"),
    ],
)
def test_enumeration_and_login_endpoints_are_lint03(url, method):
    assert forbidden_probe(url, method=method) == "LINT-03"


@pytest.mark.parametrize(
    "url,method",
    [
        ("https://urlscan.io/api/v1/scan/", "POST"),
        ("https://urlscan.io/api/v1/scan", "GET"),
        ("https://www.virustotal.com/api/v3/files", "POST"),
        ("https://www.virustotal.com/api/v3/urls", "POST"),
        ("https://www.virustotal.com/api/v3/files/upload_url", "GET"),
        ("https://www.virustotal.com/api/v3/urls/abc/analyse", "POST"),
        ("https://www.virustotal.com/vtapi/v2/url/scan", "POST"),
        ("https://www.virustotal.com/gui/home/upload", "GET"),
        ("https://web.archive.org/save/https://example.com/", "GET"),
        ("https://web.archive.org/save", "POST"),
        ("https://archive.ph/submit/?url=https://example.com", "GET"),
        ("https://archive.today/?run=1&url=https://example.com/", "GET"),
        ("https://www.ssllabs.com/ssltest/analyze.html?d=example.com", "GET"),
        ("https://securityheaders.com/?q=example.com&followRedirects=on", "GET"),
        ("https://tools.example/recent-searches", "GET"),
        ("https://tools.example/api/recent_lookups", "GET"),
        ("https://www.hybrid-analysis.com/api/v2/submit/url", "POST"),
        ("https://tools.example/submit?url={}", "GET"),
        ("https://tools.example/api?scan_trigger=1", "GET"),
        ("https://api.shodan.io/shodan/scan", "POST"),
        ("https://search.example/api/v2/hosts/1.2.3.4/rescan", "POST"),
    ],
)
def test_submission_endpoints_are_lint05(url, method):
    assert forbidden_probe(url, method=method) == "LINT-05"


@pytest.mark.parametrize(
    "url",
    [
        "https://tudosobretodos.info/busca?nome={}",
        "https://www.buscaprime.com.br/",
        "https://cadastropre.com.br/#/consulta",
        "https://valoresareceber.bcb.gov.br/publico/rest/valoresAReceber/{cpf}/{data}",
        "https://dehashed.com/search?query={}",
        "https://api.snusbase.com/data/search",
        "https://pimeyes.com/en",
        "https://consulta-painel.xyz/cpf",
        "https://servicos.receita.fazenda.gov.br/Servicos/CPF/ConsultaSituacao/ConsultaPublica.asp",
        "https://api.example.com/v1/pessoa?cpf={}",
        "https://api.example.com/v1/consultaCpf/{}",
    ],
)
def test_cpf_lookup_and_people_search_are_lint04(url):
    assert forbidden_probe(url) == "LINT-04"


@pytest.mark.parametrize(
    "url,method",
    [
        ("https://www.instagram.com/{}/", "GET"),
        ("https://api.github.com/users/{}", "GET"),
        ("https://www.reddit.com/user/{}/about.json", "GET"),
        ("https://urlscan.io/api/v1/search/?q=domain:example.com", "GET"),
        ("https://urlscan.io/result/0e9a8d3c-0000-0000-0000-000000000000/", "GET"),
        ("https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "GET"),
        ("https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8", "GET"),
        ("https://web.archive.org/web/*/example.com", "GET"),
        ("https://archive.org/wayback/available?url=example.com", "GET"),
        ("https://www.ssllabs.com/ssltest/analyze.html?d=example.com&hideResults=on", "GET"),
        ("https://securityheaders.com/?q=example.com&hide=on", "GET"),
        ("https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration", "GET"),
        ("https://rdap.registro.br/domain/example.com.br", "GET"),
        ("https://haveibeenpwned.com/api/v3/breachedaccount/someone@example.com", "GET"),
        ("https://www.shodan.io/host/8.8.8.8", "GET"),
        ("https://api.shodan.io/shodan/host/8.8.8.8", "GET"),
        ("https://example.com/invalidate-cache", "GET"),
        ("https://example.com/registered-agents", "GET"),
        ("https://example.com/blogin", "GET"),
        ("https://painel.saude.gov.br/", "GET"),  # official data dashboards are not 'painéis'
        ("https://brasilapi.com.br/api/cnpj/v1/00000000000191", "GET"),
        ("https://example.com/upload-guide", "GET"),  # an upload page viewed with GET submits nothing
        ("https://www.abuseipdb.com/check/8.8.8.8", "GET"),  # a reputation page, not an account check
        ("https://www.abuseipdb.com/check/{value}", "GET"),
        ("https://check-host.net/check-http?host=example.com", "GET"),
        ("https://example.com/verify?token=abc", "GET"),
        ("https://www.duolingo.com/2017-06-30/users?username={account}", "GET"),  # a public profile lookup
        ("https://example.com/u/{account}/checks", "GET"),
        ("https://example.com/checkout", "GET"),
        ("https://archive.ph/newest/https://example.com/", "GET"),
        ("https://api.example.com/v1/sessions", "GET"),
    ],
)
def test_allowed_urls(url, method):
    assert forbidden_probe(url, method=method) is None
    assert probe_violations(url, method=method) == []


def test_method_matters_for_generic_submissions():
    assert forbidden_probe("https://api.example.com/v1/scan", method="GET") is None
    assert forbidden_probe("https://api.example.com/v1/scan", method="post") == "LINT-05"
    assert forbidden_probe("https://api.example.com/v1/files/upload", method="PUT") == "LINT-05"
    # a site-list entry with "method": null is a GET, never a crash
    assert forbidden_probe("https://api.example.com/v1/scan", method=None) is None
    assert forbidden_probe("https://example.com/login", method=None) == "LINT-03"
    assert forbidden_probe(None) is None


def test_host_names_are_not_endpoint_keywords():
    assert forbidden_probe("https://login.example.com/") is None
    assert forbidden_probe("https://register.example.com/api/v1/items") is None
    assert forbidden_probe("https://login.example.com/login") == "LINT-03"


def test_several_violations_are_all_reported_lowest_first():
    url = "https://tudosobretodos.info/login?next=/submit"
    assert probe_violations(url) == ["LINT-03", "LINT-04", "LINT-05"]
    assert forbidden_probe(url) == "LINT-03"


def test_runtime_site_list_filtering():
    sites = [
        {"name": "ok", "uri_check": "https://www.example.com/{account}"},
        {"name": "signup", "uri_check": "https://www.example.com/signup?user={account}"},
        {"name": "reset", "uri_check": "https://www.example.com/password_reset", "method": "POST"},
        {"name": "panel", "uri_check": "https://buscaprime.com.br/{account}"},
    ]
    kept = [s["name"] for s in sites if forbidden_probe(s["uri_check"], method=s.get("method", "GET")) is None]
    assert kept == ["ok"]


def test_split_probe_url():
    assert lint.split_probe_url("https://User:pw@WWW.Example.com:8443/a?b#c") == ("www.example.com", "/a?b#c")
    assert lint.split_probe_url("www.example.com/login") == ("www.example.com", "/login")
    assert lint.split_probe_url("http://[2001:db8::1]:80/x") == ("2001:db8::1", "/x")
    assert lint.split_probe_url("/just/a/path") == ("", "/just/a/path")


def test_tables_are_exported_with_rule_ids():
    assert {p.rule_id for p in FORBIDDEN_PROBE_PATTERNS} == {"LINT-03"}
    assert {p.rule_id for p in SUBMISSION_PATTERNS} == {"LINT-05"}
    assert {"cadastropre.com.br", "valoresareceber.bcb.gov.br"} <= CPF_LOOKUP_HOSTS
    assert {"tudosobretodos.info", "buscaprime.com.br", "dehashed.com"} <= PEOPLE_SEARCH_DENYLIST
    assert set(lint.PROBE_RULES) == {"LINT-03", "LINT-04", "LINT-05"}
    assert lint.people_search_host("api.tudosobretodos.info") and not lint.people_search_host("example.com")


def test_patterns_are_linear_on_pathological_input():
    import time

    start = time.perf_counter()
    for blob in ("/" + "-" * 100_000, "/" + "a_" * 50_000, "?" + "=&" * 50_000, "/" + "signupsignup" * 5_000,
                 "/check?" + "a&" * 20_000, "/" + "verify/{" * 5_000, "/users/" + "x/" * 20_000):
        probe_violations("https://example.com" + blob, method="POST")
    probe_violations("https://archive.ph/?" + "a" * 40_000)
    assert time.perf_counter() - start < 2.0
