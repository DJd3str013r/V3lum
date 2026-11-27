"""P323 pattern DB (v3lum.core.patterns): vectors per pattern, the confidence/emission rules,
masking, a ReDoS check of every regex and the end-to-end rule that a mixed incident text never
sends a card number or a secret off the machine."""

from __future__ import annotations

import re
import time

import pytest

from tests.fakes import FakeHttp, define_module, make_runtime, source_ids, test_provider
from v3lum.core import patterns as P
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T

ENABLED = [p for p in P.PATTERNS if p.enabled]


@pytest.mark.parametrize("pat", ENABLED, ids=lambda p: p.name)
def test_positive_vectors_match_in_full(pat):
    for vector in pat.vectors_ok:
        hits = P.match_patterns(vector, names=(pat.name,))
        assert hits, f"{pat.name}: {vector!r} should match"
        assert hits[0].value in vector and pat.check(hits[0].value)


@pytest.mark.parametrize("pat", ENABLED, ids=lambda p: p.name)
def test_negative_vectors_do_not_match(pat):
    for vector in pat.vectors_bad:
        assert P.match_patterns(vector, names=(pat.name,)) == [], f"{pat.name}: {vector!r} must not match"


def test_db_rules():
    names = [p.name for p in P.PATTERNS]
    assert len(names) == len(set(names))
    for p in P.PATTERNS:
        assert p.kind in P.KINDS
        if p.validator is None:
            assert p.confidence <= P.NO_VALIDATOR_MAX_CONFIDENCE, p.name
        if p.enabled:
            assert p.vectors_ok and p.vectors_bad, p.name
        if p.emitted:
            assert p.consumer or p.mask, p.name
        if p.kind in ("secret", "financial"):
            assert p.mask, f"{p.name}: secrets and financial data are always masked"
    generic = {"phone_generic", "date_of_birth", "uuid", "ulid", "unix_timestamp", "ssn_us", "solana"}
    assert all(not P.pattern(n).enabled for n in generic)  # generic patterns are disabled (P323 cond 3)
    with pytest.raises(ValueError):
        P.Pattern("x", "secret", re.compile("x"), None, 0.9, vectors_ok=("x",), vectors_bad=("y",))
    with pytest.raises(ValueError):
        P.Pattern("x", "nope", re.compile("x"), None, 0.1)


def test_unconsumed_patterns_are_not_emitted_by_default():
    assert P.match_patterns("_ldap._tcp.dc._msdcs.example.com") == []
    assert [h.name for h in P.match_patterns("_ldap._tcp.dc._msdcs.example.com", include_unconsumed=True)] == ["srv_name"]
    assert P.odd_headers("Server: nginx\nX-Backend-Server: app-07.internal\nX-Frame-Options: DENY") == ["X-Backend-Server: app-07.internal"]
    assert P.match_patterns("2024-01-15 call +1 415 555 2671") == []  # generic phone/date never emitted


def test_masking_of_sensitive_hits():
    card = P.match_patterns("pay with 4111 1111 1111 1111 now")[0]
    assert card.masked == "411111…1111" and card.entity_type == "payment_card"
    assert P.mask_pan("4111 1111 1111 1111") == "4111 11** **** 1111"
    iban = P.match_patterns("IBAN DE89 3704 0044 0532 0130 00")[0]
    assert iban.masked == "DE89 **** **** **** **30 00" and iban.entity_type == ""
    cpf = P.match_patterns("CPF 111.444.777-35")[0]
    assert cpf.masked == "***.444.777-**"
    gh = "ghp" + "_" + "V3lumSyntheticTokenForTests0123456789"[:36]
    secret = P.match_patterns(f"token {gh}")[0]
    assert secret.masked.startswith("github_token:ghp_…") and gh not in secret.masked
    assert P.card_brand("6362970000457013") == "elo" and P.card_brand("4111111111111112") is None
    assert P.iban_valid("GB82WEST12345698765432") and not P.iban_valid("GB82WEST12345698765433")


def test_hits_inside_longer_tokens_are_ignored():
    assert P.match_patterns("9977cd94a6566863255315d07871bfb6", names=("payment_card",)) == []  # digits inside an MD5
    assert P.match_patterns("a11222333000181b", names=("cnpj_bare",)) == []
    assert P.match_patterns("x1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", names=("btc_base58",)) == []


PATHOLOGICAL = {
    "dots": "." * 1_000_000,
    "hyphens": "-" * 1_000_000,
    "digits": "1" * 1_000_000,
    "digits_spaced": "1 " * 500_000,
    "alnum": "aA1" * 333_334,
    "hexrun": "ab" * 500_000,
    "base58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" * 17_000,
    "dashes_digits": "1-" * 500_000,
    "eyj": "eyJ." * 250_000,
    "underscores": "_x." * 333_334,
    "spaces": " " * 1_000_000,
}


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_every_regex_is_linear_on_pathological_input(name):
    """ReDoS review: each regex of the DB runs over 1 MB of a pathological input in well under a second.
    Measured in CPU time of this process (matching is single-threaded), so a loaded CI machine does
    not turn scheduling delays into a failure; catastrophic backtracking still costs CPU."""
    text = PATHOLOGICAL[name]
    total = 0.0
    for p in P.PATTERNS:
        start = time.process_time()
        for _ in p.regex.finditer(text):
            pass
        took = time.process_time() - start
        total += took
        assert took < 1.0, f"{p.name} took {took:.2f}s on {name}"
    assert total < 5.0


def test_mixed_incident_text_sends_no_card_number_or_secret(clean_registry):
    """P323 cond 9: a mixed incident text goes through ioc_extract and a third-party lookup module
    (FakeHttp records every request): no card number and no secret leaves the machine."""
    gh = "ghp" + "_" + "V3lumSyntheticTokenForTests0123456789"[:36]
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    bot = "123456789" + ":AA" + "V3lumSyntheticBotTokenForTests0000"[:33]
    pan = "4111 1111 1111 1111"
    text = (f"Incidente 2026-11-26: C2 45.33.32.156 e hxxps://evil-panel[.]example.net/gate\n"
            f"vazou o token {gh} e o JWT {jwt}; bot {bot}\n"
            f"cartao {pan} / 5555555555554444, CPF 111.444.777-35, IBAN DE89 3704 0044 0532 0130 00\n"
            "hash 44d88612fea8a8f36de82e1278abb02f")

    def lookup(self, entity, ctx):
        ctx.http.get("https://api.example.test/lookup", params={"q": entity.value}, source=self.sources[0])
        return self.result(entity)

    with test_provider() as prov:
        define_module("t_p323_lookup", [t for t in T if t not in (T.TEXT, T.FILE)], lookup, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
                      hosts=prov.hosts, access_model="free_noauth_unlimited", max_requests=5, category="threat_intel_ioc")
        http = FakeHttp().add("GET", re.compile(r"https://api\.example\.test/lookup.*"), json={"ok": True}, times=None)
        case = Engine(make_runtime(http), ScanOptions(include={"ioc_extract", "t_p323_lookup"}, depth=2)).investigate(
            [Entity.make("text_blob", text)])
    sent = " ".join(http.urls())
    assert "45.33.32.156" in sent or "evil-panel.example.net" in sent  # IOCs do reach the lookup
    for raw in (gh, jwt, bot, pan, pan.replace(" ", ""), "5555555555554444", "411111", "555555"):
        assert raw not in sent, raw
    for raw in ("111.444.777-35", "11144477735", "DE89370400440532013000"):
        assert raw not in sent
    assert not any(n.entity.type in (T.SECRET, T.PAYMENT_CARD, T.TELEGRAM_BOT_TOKEN, T.CPF) and n.investigated
                   for n in case.graph.of_type(T.SECRET, T.PAYMENT_CARD, T.TELEGRAM_BOT_TOKEN, T.CPF))
