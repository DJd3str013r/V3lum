"""Watch mode (WP26, P030, A14): rules from the org profile only, local matching (IDNA, accents,
homoglyphs, permutations), the bounded CertStream consumer replayed from recorded messages through an
injectable transport with a fake clock, polling sources through the policy gate (path 'watch') with
first_seen diffing, alerts (JSONL 0600, alerts table, the day's watch case, 200/hour summary), mutes,
capped passive enrichment (never LIGHT/ACTIVE), retention prune, health and the ``v3lum watch`` command.
Offline and deterministic: no network, no real sleeping."""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import random
import stat
import sys
import threading
import types
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, define_module, make_runtime, source_ids, test_provider
from v3lum.cli import main
from v3lum.core import policy
from v3lum.core import watch as W
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.store import Store

FIXTURES = Path(__file__).parent / "fixtures" / "watch"

PROFILE = {
    "org": {"name": "ACME Bank"},
    "domains": [{"name": "acmebank.com.br", "verification": "txt_verified", "criticality": "high"}],
    "brands": [{"keyword": "AcmeBank", "variants": ["acme-bank"], "criticality": "high"}],
    "suppliers": [{"name": "Supplier Ltd", "domains": ["supplier.example"], "brands": ["supplybrand"]}],
    "cnpj_roots": ["12345678"],
    "card_bins": ["412345"],
    "executives": [{"name": "Joana Exemplo", "opt_in": True, "programme": "VIP protection", "informed_at": "2026-11-01"}],
}


@pytest.fixture()
def registry(clean_registry):
    return clean_registry


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def org():
    return OrgProfile.from_dict(PROFILE)


@pytest.fixture()
def rt(clock, org):
    return make_runtime(FakeHttp(clock=clock), clock=clock, org_profile=org, settings={"watch_enrich_per_hour": 30})


@pytest.fixture()
def store(rt, clock):
    s = Store(settings=rt.config, clock=clock, health=False)
    yield s
    s.close()


def watcher(rt, store, org, **kw):
    lines = kw.pop("lines", None)
    out = (lambda text, style: lines.append(text)) if lines is not None else None
    kw.setdefault("enricher", lambda domain, alert: "")
    kw.setdefault("certstream", False)
    return W.Watcher(rt, store, org, clock=rt.clock, out=out, **kw)


def replay_messages() -> list[str]:
    return [json.loads(line)["raw"] for line in (FIXTURES / "certstream_messages.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


class ReplayConn:
    def __init__(self, messages, transport):
        self.messages = list(messages)
        self.transport = transport

    def recv(self, timeout):
        if self.messages:
            return self.messages.pop(0)
        self.transport.exhausted.set()
        raise EOFError("replay finished")

    def send(self, data):  # never called: the consumer sends nothing
        self.transport.sent.append(data)

    def close(self):
        self.transport.closed += 1


class ReplayTransport:
    """Injectable CertStream transport: each connect() replays one recorded session (or fails)."""

    def __init__(self, sessions=(), *, fail=0):
        self.sessions = [list(s) for s in sessions]
        self.fail = fail
        self.urls: list[str] = []
        self.sent: list[object] = []
        self.closed = 0
        self.exhausted = threading.Event()

    def connect(self, url, *, timeout):
        self.urls.append(url)
        if self.fail > 0:
            self.fail -= 1
            raise ConnectionRefusedError("connection refused (replay)")
        if not self.sessions:
            self.exhausted.set()
            raise ConnectionRefusedError("no more recorded sessions")
        return ReplayConn(self.sessions.pop(0), self)


def hits_source(name, hits, *, accepts=(T.DOMAIN, T.KEYWORD), calls=None, **attrs):
    """A synthetic watch_source module returning ``hits`` (a list or fn(entity) -> list) as watch_hits."""

    def run(self, entity, ctx):
        if calls is not None:
            calls.append(entity.key)
        res = self.result(entity)
        found = hits(entity) if callable(hits) else hits
        if found:
            res.attr("watch_hits", list(found))
        return res

    tags = set(attrs.pop("tags", ())) | {"watch_source"}
    return define_module(name, list(accepts), run, tags=tags, **attrs)


def hit(name, *, serial=None, source="synthetic_ct", **extra):
    return {"name": name, "registrable_domain": W._registrable(name) or None, "serial": serial, "cert_sha256": None,
            "issuer": "/C=US/O=Let's Encrypt/CN=R13", "not_before": "2026-11-26T00:00:00Z", "source": source, **extra}


def alert_lines(lines):
    return [line for line in lines if line.startswith("[!] 2026")]


# ======================================================================================
# permutations, rules, matching
# ======================================================================================


def test_permutations_cover_every_technique_and_stay_local():
    perms = W.permutations("acmebank.com.br")
    techniques = set(perms.values())
    assert techniques == set(W.TECHNIQUES)
    assert perms["acmbank.com.br"] == "omission"
    assert perms["acmebbank.com.br"] == "repetition"
    assert perms["acmebnak.com.br"] == "transposition"
    assert perms["acrnebank.com.br"] == "homoglyph"
    assert perms["acme-bank.com.br"] == "hyphenation"
    assert perms["acmebank.net"] == "tld_swap"
    assert any(k.startswith("xn--") and v == "homoglyph" for k, v in perms.items())  # Cyrillic look-alikes as punycode
    assert "acmebank.com.br" not in perms and all(k.isascii() for k in perms)
    labels = W.permutations("Acme Bank")  # a bare keyword: labels only, no TLD swap
    assert "acmebnak" in labels and all("." not in k for k in labels) and "tld_swap" not in labels.values()
    assert len(W.permutations("acmebank.com.br", limit=10)) == 10
    assert W.permutations("") == {} and W.permutations("com.br") == {}  # a public suffix has no registrable label


def test_rules_come_only_from_the_profile_and_never_target_a_natural_person(org):
    problems: list[str] = []
    data = dict(PROFILE, brands=[{"keyword": "AcmeBank", "variants": ["acme-bank", "joana exemplo", "ceo@acmebank.com.br", "+55 11 98765-4321", "@joana"],
                                  "criticality": "high"}])
    rules = W.rules_from_profile(OrgProfile.from_dict(data), problems=problems)
    ids = [r.id for r in rules]
    assert ids == ["domain:acmebank.com.br", "brand:acmebank", "supplier:supplier-ltd", "own_addresses:acmebank.com.br",
                   "cnpj_root:12345678", "card_bin:412345"]
    terms = {t for r in rules for t in r.terms}
    assert not any("joana" in t or "@" in t or "98765" in t for t in terms)  # people never become terms
    assert sum("natural persons are not watched" in p for p in problems) == 4
    brand = next(r for r in rules if r.kind == "brand")
    assert brand.terms == ("acmebank", "acme-bank") and brand.keyword == "AcmeBank" and brand.criticality == "high"
    assert [e.key for e in brand.entities] == ["keyword:AcmeBank"]
    domain = rules[0]
    assert [e.key for e in domain.entities] == ["domain:acmebank.com.br"] and domain.ioc_types == ("domain", "url")
    assert next(r for r in rules if r.kind == "own_addresses").ioc_types == ("email",)  # domain-wide, verified domains only
    seeded = W.rules_from_profile({"domains": [{"name": "acmebank.com.br", "verification": "seeded"}]})
    assert [r.kind for r in seeded] == ["domain"]  # no address rule without a verified domain
    assert W.rules_from_profile({"executives": PROFILE["executives"]}) == []
    assert W.rules_from_profile(None) == []


def test_matcher_folds_idna_accents_and_homoglyphs_and_never_alerts_own_domains(org):
    m = W.Matcher(W.rules_from_profile(org))
    cases = {
        "login-acmebank.com": ("keyword", "domain:acmebank.com.br"),
        "acrnebank.com.br": ("permutation", "domain:acmebank.com.br"),
        "ac-mebank-seguro.net": ("keyword", "domain:acmebank.com.br"),
        "xn--acmbank-dya.com": ("permutation", "domain:acmebank.com.br"),  # acmébank.com (IDN)
        "xn--cmebank-1fg.com": ("permutation", "domain:acmebank.com.br"),  # Cyrillic 'а'
        "acme8ank-login.org": ("homoglyph", "domain:acmebank.com.br"),
        "supp1ybrand.io": ("homoglyph", "supplier:supplier-ltd"),
    }
    for name, (kind, rule) in cases.items():
        assert m.prefilter(name), name
        nm = m.match(name)
        assert nm is not None and nm.matches and nm.matches[0].kind == kind and nm.matches[0].rule.id == rule, (name, nm)
    assert m.match("*.login-acmebank.com").registrable_domain == "login-acmebank.com"
    own = m.match("www.acmebank.com.br")
    assert own.protected_by == "domain:acmebank.com.br" and own.matches == ()
    assert m.match("portal.supplier.example").protected_by == "supplier:supplier-ltd"
    assert not m.prefilter("example.org") and m.match("example.org").matches == ()
    assert m.match("not a domain") is None and m.match("https://x.example/") is None


# ======================================================================================
# CertStream: parsing, prefilter, bounded queue, backoff, reconnect rate
# ======================================================================================


def test_parse_certstream_keeps_certificate_metadata_only():
    kinds = [W.parse_certstream(raw)[0] for raw in replay_messages()]
    assert kinds == ["heartbeat", "certificate", "certificate", "certificate", "certificate", "certificate", "malformed",
                     "certificate", "certificate", "certificate", "other"]
    kind, ev = W.parse_certstream(replay_messages()[2])
    assert ev.names == ("login-acmebank.com", "www.login-acmebank.com") and ev.serial == "0A1B2C3D4E5F"
    assert ev.cert_sha256 == "ab" * 32 and ev.issuer == "/C=US/CN=R13/O=Let's Encrypt" and ev.not_before == "2025-11-26T12:00:00Z"
    assert ev.source == "Google 'Argon2026h1' log"
    der = {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": ["a.example"], "as_der": "AAEC"}}}
    import hashlib

    assert W.parse_certstream(json.dumps(der))[1].cert_sha256 == hashlib.sha256(b"\x00\x01\x02").hexdigest()
    assert W.parse_certstream(b"\xff\xfe")[0] == "malformed"
    assert W.parse_certstream("[1, 2]")[0] == "malformed"


def test_replay_prefilters_before_queueing_and_counts_everything(org, clock):
    transport = ReplayTransport([replay_messages()])
    consumer = W.CertStreamConsumer("wss://certstream.example.test/", W.Matcher(W.rules_from_profile(org)), transport=transport,
                                    clock=clock, rng=random.Random(1))
    consumer.run(max_connections=1)
    st = consumer.stats
    assert (st.received, st.heartbeats, st.malformed, st.other) == (11, 1, 1, 1)
    assert st.prefiltered == 1  # the unrelated certificate never reaches the queue
    assert st.queued == consumer.queued == 7 and st.dropped_queue == 0
    assert transport.urls == ["wss://certstream.example.test/"] and transport.sent == []  # nothing is ever sent
    events = consumer.drain()
    assert consumer.queued == 0 and consumer._bytes == 0
    assert events[-1].names == ("acmebank-pagamentos.com.br",)  # example.org was filtered out of the domains-only message


def test_bounded_queue_drops_and_counts_and_caps_memory(org, clock):
    matcher = W.Matcher(W.rules_from_profile(org))
    consumer = W.CertStreamConsumer("wss://x.test/", matcher, transport=ReplayTransport(), clock=clock, max_items=2)
    raw = replay_messages()[2]
    assert [consumer.handle_message(raw) for _ in range(4)] == [True, True, False, False]
    assert (consumer.stats.queued, consumer.stats.dropped_queue, consumer.queued) == (2, 2, 2)
    small = W.CertStreamConsumer("wss://x.test/", matcher, transport=ReplayTransport(), clock=clock, max_bytes=1024)
    big = json.dumps({"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": [f"login-acmebank-{i}.com" for i in range(60)]}}})
    assert small.handle_message(big) is False and small.stats.dropped_queue == 1  # byte cap
    huge = json.dumps({"message_type": "certificate_update", "pad": "x" * (W.MESSAGE_MAX_BYTES + 1)})
    assert consumer.handle_message(huge) is False and consumer.stats.oversize == 1
    many = json.dumps({"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": [f"login-acmebank-{i}.com" for i in range(500)]}}})
    roomy = W.CertStreamConsumer("wss://x.test/", matcher, transport=ReplayTransport(), clock=clock)
    roomy.handle_message(many)
    assert len(roomy.drain()[0].names) == W.NAMES_PER_CERT  # names per certificate are capped


def test_reconnect_backoff_has_jitter_and_grows_to_a_cap(org, clock):
    consumer = W.CertStreamConsumer("wss://x.test/", W.Matcher(W.rules_from_profile(org)), transport=ReplayTransport(fail=6),
                                    clock=clock, rng=random.Random(7))
    consumer.run(max_connections=6)
    delays = consumer.stats.backoffs
    assert consumer.stats.connect_errors == 6 and len(delays) == 6
    for attempt, delay in enumerate(delays):
        nominal = min(W.BACKOFF_CAP, W.BACKOFF_BASE * 2**attempt)
        assert nominal / 2 <= delay <= nominal  # half fixed, half jitter
    assert delays[-1] > delays[0]
    assert len({round(d / min(W.BACKOFF_CAP, 2**i), 6) for i, d in enumerate(delays)}) > 1  # jitter, not a fixed ladder
    rng_a, rng_b = random.Random(1), random.Random(2)
    a = W.CertStreamConsumer("wss://x.test/", W.Matcher(()), transport=ReplayTransport(), rng=rng_a)
    b = W.CertStreamConsumer("wss://x.test/", W.Matcher(()), transport=ReplayTransport(), rng=rng_b)
    assert a.backoff(30) <= W.BACKOFF_CAP and a.backoff(3) != b.backoff(3)
    assert sum(clock.sleeps) >= sum(delays) - 1e-6  # waits use the injected clock (no real sleeping)


def test_reconnect_rate_is_capped(org, clock):
    sessions = [["{\"message_type\": \"heartbeat\"}"] for _ in range(10)]
    consumer = W.CertStreamConsumer("wss://x.test/", W.Matcher(W.rules_from_profile(org)), transport=ReplayTransport(sessions),
                                    clock=clock, rng=random.Random(3), max_reconnects=3)
    start = clock.monotonic()
    consumer.run(max_connections=5)
    assert consumer.stats.connects == 5 and consumer.stats.rate_capped >= 1
    # never more than 3 connections inside any one-hour window
    times = list(consumer._connects)
    assert len(times) <= 3 and clock.monotonic() - start >= W.RECONNECT_WINDOW


def test_a_healthy_connection_resets_the_backoff(org):
    clock = FakeClock()

    class SlowConn:
        def __init__(self):
            self.n = 0

        def recv(self, timeout):
            self.n += 1
            clock.advance(30)
            if self.n > 3:
                raise EOFError("closed")
            return '{"message_type": "heartbeat"}'

        def close(self):
            pass

    class Transport:
        def connect(self, url, *, timeout):
            return SlowConn()

    consumer = W.CertStreamConsumer("wss://x.test/", W.Matcher(()), transport=Transport(), clock=clock, rng=random.Random(5))
    consumer._attempt = 6
    consumer.run(max_connections=1)
    assert consumer.stats.heartbeats == 3 and consumer.stats.backoffs[-1] <= W.BACKOFF_BASE  # reset after >= 60 s up


# ======================================================================================
# alerts: replay through the watcher, LRU dedupe, first_seen across runs, JSONL, case
# ======================================================================================


def _replay_into(w, clock):
    transport = ReplayTransport([replay_messages()])
    w.consumer = W.CertStreamConsumer("wss://certstream.example.test/", w.matcher, transport=transport, clock=clock)
    w.consumer.run(max_connections=1)
    w.drain_stream()
    w._flush_case()
    return transport


def test_replay_alerts_new_registrable_domains_with_lru_dedupe(rt, store, org, clock, isolated_home):
    lines: list[str] = []
    w = watcher(rt, store, org, lines=lines)
    _replay_into(w, clock)
    alerts = W.recent_alerts(store)
    assert sorted(a.registrable_domain for a in alerts) == ["ac-mebank-seguro.net", "acmebank-pagamentos.com.br", "acrnebank.com.br", "login-acmebank.com"]
    rep = w.report
    assert rep.alerts == 4 and rep.own == 2 and rep.duplicates == 2 and rep.known == 1
    first = next(a for a in alerts if a.registrable_domain == "login-acmebank.com")
    assert first.serial == "0A1B2C3D4E5F" and first.cert_sha256 == "ab" * 32 and first.rule_id == "domain:acmebank.com.br"
    assert first.reason == "contains the keyword 'acmebank'" and first.tlp == "amber" and first.source.startswith("certstream:")
    assert len(alert_lines(lines)) == 4 and all("[.]" in line for line in alert_lines(lines))  # defanged on the terminal
    # JSONL: certificate metadata only, 0600 in a 0700 directory
    day = clock.now().strftime("%Y-%m-%d")
    path = isolated_home / "watch" / f"alerts-{day}.jsonl"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    records = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 4
    for key in ("timestamp", "rule_id", "matched_name", "registrable_domain", "reason", "cert_sha256", "issuer", "not_before"):
        assert key in records[0]
    assert "leaf_cert" not in path.read_text(encoding="utf-8") and "all_domains" not in path.read_text(encoding="utf-8")
    # the day's watch case: one correlation per alert, linked rows
    case = store.get_case(W.watch_case_id(clock.now()))
    assert case["kind"] == "watch" and case["tlp"] == "amber" and len(case["correlations"]) == 4
    assert {c["id"] for c in case["correlations"]} == {a.id for a in alerts}
    with store.connection() as conn:
        linked = conn.execute("SELECT COUNT(*) FROM alerts WHERE case_id = ?", (case["case_id"],)).fetchone()[0]
        seen = conn.execute("SELECT COUNT(*) FROM watch_first_seen").fetchone()[0]
    assert linked == 4 and seen == 5  # four new domains + the new serial of an already alerted one


def test_first_seen_diffing_across_runs(rt, store, org, clock):
    w1 = watcher(rt, store, org)
    _replay_into(w1, clock)
    assert w1.report.alerts == 4
    clock.advance(3600)
    w2 = watcher(rt, store, org)
    _replay_into(w2, clock)
    assert w2.report.alerts == 0 and w2.report.known >= 4  # nothing new: no alert
    extra = json.dumps({"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": ["acmebank-boleto.com"], "serial_number": "1234"}}})
    w2.consumer.handle_message(extra)
    w2.drain_stream()
    assert w2.report.alerts == 1 and W.recent_alerts(store, limit=1)[0].registrable_domain == "acmebank-boleto.com"


def test_above_200_alerts_per_hour_one_summary_line_replaces_the_rest(registry, rt, store, org):
    hits_source("t_flood", [hit(f"login{i}-acmebank.com") for i in range(250)], accepts=(T.DOMAIN,))
    lines: list[str] = []
    rep = watcher(rt, store, org, lines=lines, sources=["t_flood"]).run(once=True)
    assert rep.alerts == 250 and rep.summarized == 50
    assert len(alert_lines(lines)) == 200
    summary = [line for line in lines if "more alert(s) in hour" in line]
    assert len(summary) == 1 and summary[0].startswith("[!] 50 more alert(s)")
    assert len(W.recent_alerts(store, limit=1000)) == 250  # every alert is still recorded


def test_mutes_per_rule_and_per_domain(registry, rt, store, org):
    hits_source("t_mutes", [hit("login-acmebank.com"), hit("supp1ybrand.io"), hit("acmebank-promo.net")], accepts=(T.DOMAIN,))
    rules = W.rules_from_profile(org)
    assert W.mute(store, "supplier:supplier-ltd", rules=rules) == ("supplier:supplier-ltd", "")
    assert W.mute(store, "WWW.Login-AcmeBank.com", rules=rules) == ("", "login-acmebank.com")
    with pytest.raises(ValueError):
        W.mute(store, "no such thing", rules=rules)
    rep = watcher(rt, store, org, sources=["t_mutes"]).run(once=True)
    assert rep.alerts == 1 and rep.muted == 2
    assert [a.registrable_domain for a in W.recent_alerts(store)] == ["acmebank-promo.net"]
    assert W.unmute(store, "login-acmebank.com", rules=rules) is True and W.unmute(store, "login-acmebank.com", rules=rules) is False
    assert W.mutes(store) == [{"rule_id": "supplier:supplier-ltd", "domain": "", "created": W.mutes(store)[0]["created"]}]
    rep2 = watcher(rt, store, org, sources=["t_mutes"]).run(once=True)
    assert rep2.alerts == 0  # muted hits were recorded as seen: unmuting never floods old matches


def test_max_alerts_stops_the_watch(registry, rt, store, org):
    hits_source("t_many", [hit(f"acmebank-{i}.net") for i in range(10)], accepts=(T.DOMAIN,))
    rep = watcher(rt, store, org, sources=["t_many"]).run(max_alerts=3, max_runtime=7200)
    assert rep.alerts == 3 and rep.stop_reason == "max_alerts" and rep.cycles == 1


# ======================================================================================
# polling: watch sources, policy path 'watch', keywords, --once, interval
# ======================================================================================


def test_watch_source_hits_produce_first_seen_diffs(registry, rt, store, org, clock):
    calls: list[str] = []
    batches = {1: [hit("acmebank-pix.com", serial="AA")], 2: [hit("acmebank-pix.com", serial="BB"), hit("acmebank-cartao.com")]}
    run_no = {"n": 1}
    hits_source("t_ct_deltas", lambda e: batches[run_no["n"]] if e.type is T.DOMAIN else [], calls=calls)
    rep1 = watcher(rt, store, org, sources=["t_ct_deltas"]).run(once=True)
    assert rep1.alerts == 1 and rep1.sources["t_ct_deltas"]["status"] == "ok"
    assert calls == ["domain:acmebank.com.br", "keyword:AcmeBank"]  # org domains and brand keywords (disclosure none: local)
    run_no["n"] = 2
    clock.advance(3600)
    rep2 = watcher(rt, store, org, sources=["t_ct_deltas"]).run(once=True)
    assert rep2.alerts == 1 and rep2.known == 1  # the new serial of a known domain is state, not an alert
    assert [a.registrable_domain for a in W.recent_alerts(store)] == ["acmebank-cartao.com", "acmebank-pix.com"]
    with store.connection() as conn:
        serials = sorted(r[0] for r in conn.execute("SELECT cert_serial FROM watch_first_seen WHERE registrable_domain = 'acmebank-pix.com'"))
    assert serials == ["AA", "BB"]


def test_hits_a_source_matched_itself_are_keyed_by_name_not_collapsed(registry, rt, store, org):
    post = [{"name": f"https://t.me/s/somechannel/{i}", "registrable_domain": None, "serial": None, "cert_sha256": None, "issuer": None,
             "not_before": "2026-11-26T00:00:00Z", "source": "telegram.tme", "rule_id": "brand:1a2b3c4d"} for i in (1, 2)]
    hits_source("t_posts", post, accepts=(T.DOMAIN,))
    rep = watcher(rt, store, org, sources=["t_posts"]).run(once=True)
    assert rep.alerts == 2 and {a.registrable_domain for a in W.recent_alerts(store)} == {"https://t.me/s/somechannel/1", "https://t.me/s/somechannel/2"}
    assert all(a.reason.startswith("reported by") and a.rule_id == "domain:acmebank.com.br" for a in W.recent_alerts(store))
    assert rep.enriched == []  # URLs are never enriched automatically


def test_watch_only_module_is_never_selected_by_scan(registry, rt, store, org):
    calls: list[str] = []
    cls = hits_source("t_watch_only", [], calls=calls, accepts=(T.DOMAIN,), tags={"watch_only"})
    seed = Entity.make(T.DOMAIN, "acmebank.com.br")
    case = Engine(rt, ScanOptions(include={"t_watch_only"})).investigate([seed])
    assert calls == [] and case.coverage["t_watch_only"]["status"] == "skipped"
    eng = Engine(rt, ScanOptions(include={"t_watch_only"}))
    decision = policy.decide(cls, seed, eng.policy_context(path="scan"), run=RunInfo(entity=seed))
    assert not decision.allowed and decision.reason_code == "not_applicable" and "v3lum watch" in decision.reason
    watcher(rt, store, org, sources=["t_watch_only"]).run(once=True)
    assert calls == ["domain:acmebank.com.br"]  # selected only inside v3lum watch


def test_keywords_never_appear_in_any_outbound_request(registry, clock):
    """Acceptance: brand keywords and their permutations stay on the machine (third-party sources get org
    domains only; the CertStream consumer sends nothing)."""
    org = OrgProfile.from_dict({"domains": [{"name": "zentrix.com.br", "verification": "txt_verified"}],
                                "brands": [{"keyword": "AcmeBank", "variants": ["acme-bank"]}]})
    http = FakeHttp(clock=clock)
    http.add("GET", "https://ct.example.test/search*", json={"ok": True})
    rt = make_runtime(http, clock=clock, org_profile=org)
    store = Store(settings=rt.config, clock=clock, health=False)
    local: list[str] = []

    def third(self, entity, ctx):
        ctx.http.get(f"https://ct.example.test/search?q={entity.value}")
        res = self.result(entity)
        res.attr("watch_hits", [hit("acmebank-seguro.com")])
        return res

    with test_provider("watchtp", hosts=("ct.example.test",)) as prov:
        define_module("t_ct_third", [T.DOMAIN, T.KEYWORD], third, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
                      hosts=prov.hosts, access_model="free_noauth_unlimited", tags={"watch_source"})
        hits_source("t_local_kw", [], calls=local, accepts=(T.KEYWORD,))
        w = W.Watcher(rt, store, org, clock=clock, sources=["t_ct_third", "t_local_kw"], enricher=lambda d, a: "", certstream=False)
        rep = w.run(once=True)
        polled = rep.alerts
        transport = _replay_into(w, clock)
    urls = [c["url"] for c in http.calls]
    assert urls == ["https://ct.example.test/search?q=zentrix.com.br"]
    secrets = {s for s in {"acmebank", "acme-bank", *W.permutations("acmebank"), *W.permutations("zentrix.com.br")} if s not in "zentrix.com.br"}
    blob = json.dumps(http.calls, default=str).lower()
    assert not any(s in blob for s in secrets)
    assert rep.keywords_kept_local == 1 and local == ["keyword:AcmeBank"]  # a disclosure-'none' source gets it locally
    assert transport.sent == [] and transport.urls == ["wss://certstream.example.test/"]
    assert polled == 1 and rep.alerts == 6  # the replay matched locally (acmebank.com.br is not an own domain here)
    store.close()


def test_once_runs_exactly_one_bounded_cycle(registry, rt, store, org, clock):
    calls: list[str] = []
    hits_source("t_once", [], calls=calls, accepts=(T.DOMAIN,))
    start = clock.monotonic()
    rep = watcher(rt, store, org, sources=["t_once"]).run(once=True)
    assert rep.cycles == 1 and rep.stop_reason == "once" and calls == ["domain:acmebank.com.br"]
    assert clock.monotonic() - start < 1.0  # no waiting for the next interval


def test_max_runtime_runs_cycles_on_the_interval(registry, rt, store, org, clock):
    calls: list[str] = []
    hits_source("t_interval", [], calls=calls, accepts=(T.DOMAIN,))
    rep = watcher(rt, store, org, sources=["t_interval"]).run(max_runtime=7200, interval=3600)
    assert rep.cycles == 2 and rep.stop_reason == "max_runtime" and len(calls) == 2
    short = watcher(rt, store, org, sources=["t_interval"]).run(max_runtime=1200, interval=1)  # interval floor
    assert short.cycles == 1 + 1200 // W.MIN_INTERVAL - (1 if 1200 % W.MIN_INTERVAL == 0 else 0)


def test_no_rules_without_a_profile(rt, store):
    rep = W.Watcher(rt, store, OrgProfile.empty(), clock=rt.clock).run(once=True)
    assert rep.stop_reason == "no_rules" and rep.cycles == 0


# ======================================================================================
# enrichment: capped, passive, never LIGHT/ACTIVE
# ======================================================================================


def test_enrichment_is_capped_at_30_per_hour_and_the_rest_is_listed(registry, rt, store, org, clock):
    batch = {"n": 0}
    hits_source("t_enrich", lambda e: [hit(f"acmebank-{batch['n']}-{i}.net") for i in range((40, 10, 5)[batch["n"]])], accepts=(T.DOMAIN,))
    enriched: list[str] = []

    def run(n):
        batch["n"] = n
        return watcher(rt, store, org, sources=["t_enrich"], enricher=lambda d, a: enriched.append(d) or f"case-{d}").run(once=True)

    rep = run(0)
    assert len(rep.enriched) == 30 and len(rep.enrich_listed) == 10 and len(enriched) == 30
    clock.advance(600)
    rep2 = run(1)  # a later --once run in the same hour: the cap holds across runs
    assert rep2.enriched == [] and len(rep2.enrich_listed) == 10
    clock.advance(3600)
    rep3 = run(2)
    assert len(rep3.enriched) == 5 and rep3.enrich_listed == []


def test_default_enrichment_is_a_passive_scan_and_never_light_or_active(registry, rt, store, org):
    passive: list[str] = []
    contact: list[str] = []
    define_module("t_enrich_passive", [T.DOMAIN], lambda self, e, c: passive.append(e.key) or self.result(e))
    define_module("t_enrich_light", [T.DOMAIN], lambda self, e, c: contact.append(e.key) or self.result(e), opsec=Opsec.LIGHT)
    define_module("t_enrich_active", [T.DOMAIN], lambda self, e, c: contact.append(e.key) or self.result(e), opsec=Opsec.ACTIVE)
    light_src: list[str] = []
    hits_source("t_light_source", [hit("acmebank-x.net")], calls=light_src, accepts=(T.DOMAIN,), opsec=Opsec.LIGHT)
    hits_source("t_src", [hit("acmebank-promo.net")], accepts=(T.DOMAIN,))
    w = W.Watcher(rt, store, org, clock=rt.clock, sources=["t_src", "t_light_source"], certstream=False,
                  enrich_modules=["t_enrich_passive", "t_enrich_light", "t_enrich_active"])
    rep = w.run(once=True)
    assert light_src == [] and rep.sources["t_light_source"]["reason_code"] == "opsec"  # a LIGHT watch source never runs
    assert passive == ["domain:acmebank-promo.net"] and contact == []  # never automatic LIGHT/ACTIVE contact
    assert len(rep.enriched) == 1 and rep.enriched[0]["case_id"]
    case = store.get_case(rep.enriched[0]["case_id"])
    assert case["options"]["mode"] == "passive" and case["tlp"] == "amber"
    assert any("passive enrichment of watch alert" in n for n in case["notes"])


# ======================================================================================
# retention, endpoint, transport, health, votes
# ======================================================================================


def test_prune_drops_expired_alerts_and_state_but_keeps_held_cases(rt, store, org, clock, isolated_home):
    old = clock.now() - _dt.timedelta(days=200)
    old_iso = old.isoformat(timespec="seconds").replace("+00:00", "Z")
    held, expired = "watch-20260510", "watch-20260511"
    for cid in (held, expired):
        store.save_case({"case_id": cid, "created": old_iso, "kind": "watch", "tlp": "amber", "seeds": [], "options": {"tlp": "amber"}})
    assert store.hold(held, "litigation", "legal team")
    with store.connection() as conn:
        for i, cid in enumerate((held, expired, None)):
            conn.execute("INSERT INTO alerts (id, rule_id, ts, payload, case_id) VALUES (?, 'brand:x', ?, '{}', ?)", (f"old{i}", old_iso, cid))
            conn.execute("INSERT INTO watch_first_seen (rule_id, registrable_domain, cert_serial, first_seen, case_id) VALUES ('brand:x', ?, '', ?, ?)",
                         (f"d{i}.example", old_iso, cid))
        conn.execute("INSERT INTO alerts (id, rule_id, ts, payload, case_id) VALUES ('new', 'brand:x', ?, '{}', NULL)", (clock.now().isoformat(),))
    wdir = isolated_home / "watch"
    wdir.mkdir(exist_ok=True)
    for name in ("alerts-2026-05-10.jsonl", "alerts-2026-05-11.jsonl", f"alerts-{clock.now():%Y-%m-%d}.jsonl", "notes.txt"):
        (wdir / name).write_text("{}\n", encoding="utf-8")
    counts = watcher(rt, store, org).prune()
    assert counts == {"files": 1, "alerts": 2, "first_seen": 2, "cases": 1}
    with store.connection() as conn:
        assert sorted(r[0] for r in conn.execute("SELECT id FROM alerts")) == ["new", "old0"]
        assert [r[0] for r in conn.execute("SELECT case_id FROM watch_first_seen")] == [held]
    assert store.get_case(expired) is None and store.tombstone(expired) is not None and store.get_case(held) is not None
    assert sorted(p.name for p in wdir.iterdir()) == ["alerts-2026-05-10.jsonl", f"alerts-{clock.now():%Y-%m-%d}.jsonl", "notes.txt"]


def test_certstream_endpoint_self_hosted_first_and_tlp_gated(org):
    from v3lum.config import Config

    def cfg(url):
        c = Config()
        c.settings["certstream_url"] = url
        return c

    public = W.certstream_endpoint(cfg(""), org)
    assert (public["url"], public["kind"], public["disclosure"], public["tier"], public["max_tlp"]) == (
        W.PUBLIC_CERTSTREAM_URL, "public", "third_party", "community", "amber")
    internal = W.certstream_endpoint(cfg("ws://10.0.0.5:8080/full-stream"), org)
    assert (internal["disclosure"], internal["max_tlp"], internal["problem"]) == ("internal", "red", "")
    own = W.certstream_endpoint(cfg("wss://ct.acmebank.com.br/"), org)
    assert own["disclosure"] == "internal"  # an own domain of the org profile
    other = W.certstream_endpoint(cfg("wss://certstream.example.net/"), org)
    assert (other["disclosure"], other["tier"], other["max_tlp"]) == ("third_party", "unknown", "green")
    assert "wss://" in W.certstream_endpoint(cfg("ws://certstream.example.net/"), org)["problem"]
    assert W.certstream_endpoint(cfg("https://certstream.example.net/"), org)["problem"]
    rt_strict = make_runtime(FakeHttp(), org_profile=org, settings={"certstream_url": ""})
    with Store(settings=rt_strict.config, health=False) as st:
        w = W.Watcher(rt_strict, st, org, transport=ReplayTransport(), tlp="amber+strict")
        status = w.certstream_status()
        assert status["state"] == "unavailable" and "TLP:AMBER+STRICT" in status["detail"]
        assert W.Watcher(rt_strict, st, org, transport=ReplayTransport()).certstream_status()["state"] == "running"


def test_without_the_extra_the_consumer_is_unavailable_not_an_error(rt, store, org, monkeypatch):
    monkeypatch.setattr(W, "certstream_available", lambda: False)
    w = W.Watcher(rt, store, org, clock=rt.clock)
    for once in (True, False):
        status = w.certstream_status(once=once)
        assert status["state"] == "unavailable" and "v3lum[watch]" in status["detail"]
    rep = w.run(once=True)
    assert rep.stop_reason == "once" and rep.certstream["state"] == "unavailable" and rep.stream == {}


def test_websocket_transport_verifies_tls_and_sends_nothing(monkeypatch):
    from v3lum.config import Config

    created: list[tuple[str, dict]] = []

    class Closed(Exception):
        pass

    class TimedOut(Exception):
        pass

    class FakeWS:
        def __init__(self):
            self.sent: list[object] = []
            self.queue = ['{"message_type": "heartbeat"}', TimedOut(), Closed()]
            self.closed = False

        def settimeout(self, t):
            self.timeout = t

        def recv(self):
            item = self.queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        def send(self, data):
            self.sent.append(data)

        def close(self):
            self.closed = True

    ws = FakeWS()
    mod = types.ModuleType("websocket")
    mod.create_connection = lambda url, **kw: created.append((url, kw)) or ws
    mod.WebSocketTimeoutException = TimedOut
    mod.WebSocketConnectionClosedException = Closed
    monkeypatch.setitem(sys.modules, "websocket", mod)
    cfg = Config()
    cfg.settings["proxy"] = "http://proxy.corp.example:3128"
    conn = W.WebSocketTransport(cfg).connect("wss://certstream.calidog.io/", timeout=5)
    url, kw = created[0]
    import ssl

    assert url == "wss://certstream.calidog.io/" and kw["sslopt"]["cert_reqs"] == ssl.CERT_REQUIRED and kw["sslopt"]["check_hostname"] is True
    assert kw["http_proxy_host"] == "proxy.corp.example" and kw["http_proxy_port"] == 3128 and kw["proxy_type"] == "http"
    assert kw["header"] == [f"User-Agent: V3LUM/{__import__('v3lum').__version__}"]
    assert conn.recv(1.0) == '{"message_type": "heartbeat"}' and conn.recv(1.0) is None
    with pytest.raises(EOFError):
        conn.recv(1.0)
    conn.close()
    assert ws.closed and ws.sent == []


def test_health_reports_unavailable_extra_probe_and_polling_sources(registry, rt, org, monkeypatch):
    monkeypatch.setattr(W, "certstream_available", lambda: False)
    hits_source("t_health_src", [], accepts=(T.DOMAIN,))
    data = W.health(rt.config, org=org)
    cs = data["certstream"]
    assert cs["available"] is False and cs["reachable"] is None and "v3lum[watch]" in cs["detail"]
    assert any(s["module"] == "t_health_src" and s["ready"] for s in data["polling_sources"]) and data["rules"] == 6
    monkeypatch.setattr(W, "certstream_available", lambda: True)
    transport = ReplayTransport([[]])
    ok = W.health(rt.config, org=org, transport=transport, probe=True)["certstream"]
    assert ok["reachable"] is True and transport.sent == [] and transport.closed == 1
    bad = W.health(rt.config, org=org, transport=ReplayTransport(fail=1), probe=True)["certstream"]
    assert bad["reachable"] is False and "could not connect" in bad["detail"]


def test_votes_give_per_rule_precision_and_the_watch_case_renders(rt, store, org, clock):
    w = watcher(rt, store, org)
    _replay_into(w, clock)
    alerts = W.recent_alerts(store)
    W.vote_alert(store, alerts[0].id, "right", analyst="ana")
    W.vote_alert(store, alerts[1].id, "wrong", analyst="ana", reason="benign_infra")
    prec = store.rule_precision()
    assert prec[alerts[0].rule_id][1] >= 1 and alerts[0].rule_id.startswith("domain:")
    with pytest.raises(ValueError):
        W.vote_alert(store, "nope", "right", analyst="ana")
    from rich.console import Console

    from v3lum.ui.render import render_case
    from v3lum.ui.theme import THEME

    buf = io.StringIO()
    render_case(Console(file=buf, width=200, no_color=True, theme=THEME), store.get_case(W.watch_case_id(clock.now())))
    assert "watch alert" in buf.getvalue()


# ======================================================================================
# the stream inside the loop (a reader thread; the fake clock is gated on the replay)
# ======================================================================================


class GatedClock(FakeClock):
    """The main thread's first sleep waits (real time, bounded) until the replay was fully read."""

    def __init__(self, gate):
        super().__init__()
        self.gate = gate
        self.main = threading.get_ident()

    def sleep(self, seconds):
        if threading.get_ident() == self.main:
            self.gate.wait(2.0)
        super().sleep(seconds)


def test_run_consumes_the_stream_in_a_bounded_reader_thread(registry, org):
    transport = ReplayTransport([replay_messages()])
    clock = GatedClock(transport.exhausted)
    rt = make_runtime(FakeHttp(clock=clock), clock=clock, org_profile=org)
    hits_source("t_quiet", [], accepts=(T.DOMAIN,))
    with Store(settings=rt.config, clock=clock, health=False) as st:
        w = W.Watcher(rt, st, org, clock=clock, transport=transport, sources=["t_quiet"], enricher=lambda d, a: "", rng=random.Random(2))
        rep = w.run(max_runtime=10, interval=3600)
        assert rep.certstream["state"] == "running" and rep.stop_reason == "max_runtime"
        assert rep.alerts == 4 and rep.stream["connects"] >= 1 and rep.stream["queued"] == 7
        assert transport.sent == [] and not w.consumer._thread.is_alive()


# ======================================================================================
# the command (acceptance: `v3lum watch --once`)
# ======================================================================================


@pytest.fixture()
def cli(registry, monkeypatch, isolated_home, clock):
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp(clock=clock)

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    monkeypatch.setattr(W, "certstream_available", lambda: False)
    monkeypatch.setenv("COLUMNS", "250")
    path = isolated_home / "org_profile.json"
    path.write_text(json.dumps(PROFILE), encoding="utf-8")
    path.chmod(0o600)
    hits_source("t_cli_src", [hit("login-acmebank.com", serial="0A")], accepts=(T.DOMAIN,))
    return isolated_home


def test_cli_watch_once_runs_one_cycle_and_reports_certstream_unavailable(cli, capsys):
    assert main(["watch", "--once", "--sources", "t_cli_src"]) == 0
    out = capsys.readouterr().out
    assert "TLP:AMBER" in out and "certstream: unavailable" in out and "v3lum[watch]" in out
    assert "login-acmebank[.]com" in out and "one cycle done (--once)" in out and "1 cycle(s), 1 new alert(s)" in out
    assert "Joana" not in out  # executives never appear (never rules)
    assert main(["watch", "--once", "--sources", "t_cli_src", "--tlp", "red"]) == 0
    assert "TLP:RED" in capsys.readouterr().out


def test_cli_watch_rules_mute_unmute_alerts_vote_and_status(cli, capsys):
    assert main(["watch", "rules"]) == 0
    out = capsys.readouterr().out
    assert "brand:acmebank" in out and "domain:acmebank.com.br" in out and "Joana" not in out
    assert main(["watch", "mute", "brand:acmebank"]) == 0 and "muted rule brand:acmebank" in capsys.readouterr().out
    assert main(["watch", "mute", "evil.example"]) == 0 and "muted domain evil.example" in capsys.readouterr().out
    assert main(["watch", "mute", "!!"]) == 1
    capsys.readouterr()
    assert main(["watch", "rules"]) == 0 and "muted" in capsys.readouterr().out
    assert main(["watch", "unmute", "brand:acmebank"]) == 0 and "unmuted" in capsys.readouterr().out
    assert main(["watch", "--once", "--sources", "t_cli_src"]) == 0
    capsys.readouterr()
    assert main(["watch", "alerts"]) == 0
    out = capsys.readouterr().out
    alert_id = out.split()[0]
    assert "login-acmebank[.]com" in out and len(alert_id) == 16
    assert main(["watch", "vote", alert_id, "right"]) == 0 and "recorded" in capsys.readouterr().out
    assert main(["watch", "status"]) == 0
    out = capsys.readouterr().out
    assert "certstream: unavailable" in out and "source t_cli_src" in out
    assert main(["watch", "--once", "--sources", "nope_module"]) == 1


def test_cli_watch_without_a_profile_is_a_clear_error(registry, isolated_home, capsys, monkeypatch):
    monkeypatch.setattr(W, "certstream_available", lambda: False)
    assert main(["watch", "--once"]) == 1
    assert "no org profile" in capsys.readouterr().err


def test_own_domain_addresses_are_the_only_address_rule_and_are_masked_on_screen(registry, rt, store, org):
    hits_source("t_stealer", [hit("someone@acmebank.com.br"), hit("other@unrelated.example")], accepts=(T.DOMAIN,))
    lines: list[str] = []
    rep = watcher(rt, store, org, lines=lines, sources=["t_stealer"]).run(once=True)
    alerts = W.recent_alerts(store)
    own = [a for a in alerts if a.rule_id == "own_addresses:acmebank.com.br"]
    assert len(own) == 1 and own[0].reason.startswith("address at the verified own domain")
    assert any("s***[@]acmebank[.]com[.]br" in line for line in alert_lines(lines))  # local part masked (and defanged) on the terminal
    assert not any("someone@" in line for line in lines)
    assert all(not e["domain"].count("@") for e in rep.enriched)  # addresses are never enriched
    # a third-party address belongs to a natural person: never an alert, never stored (A14)
    assert len(alerts) == 1 and rep.alerts == 1 and rep.rejected == 1
    with store.connection() as conn:
        stored = " ".join(str(r[0]) for r in conn.execute("SELECT payload FROM alerts")) + " ".join(
            str(r[0]) for r in conn.execute("SELECT registrable_domain FROM watch_first_seen"))
    assert "other@" not in stored and "unrelated.example" not in stored


# ======================================================================================
# review additions: natural persons, hit validation, mutes, statuses, bounds, TLP audit
# ======================================================================================


def test_hits_that_are_no_host_url_or_own_address_are_dropped_and_never_stored(registry, rt, store, org, isolated_home):
    """Third-party e-mails, phone numbers, CPF-like digits, bare IPs and free text are never watched:
    no alert, no first_seen row, no JSONL line (A14 / LGPD)."""
    people = ["other@unrelated.example", "+55 11 98765-4321", "123.456.789-09", "203.0.113.5", "Joana Exemplo", "ftp://acmebank-x.com/"]
    hits_source("t_people", [hit(v) for v in people] + [hit("acmebank-pagar.com")], accepts=(T.DOMAIN,))
    rep = watcher(rt, store, org, sources=["t_people"]).run(once=True)
    assert rep.rejected == len(people) and rep.alerts == 1
    assert [a.registrable_domain for a in W.recent_alerts(store)] == ["acmebank-pagar.com"]
    with store.connection() as conn:
        keys = [r[0] for r in conn.execute("SELECT registrable_domain FROM watch_first_seen")]
    assert keys == ["acmebank-pagar.com"]
    blob = "".join(p.read_text(encoding="utf-8") for p in (isolated_home / "watch").glob("alerts-*.jsonl"))
    assert not any(v in blob for v in ("98765", "789-09", "203.0.113", "Joana", "other@"))
    assert W._hit_kind("123.456.789-09") == ("", "", "") and W._hit_kind("*.login-acmebank.com")[0] == "domain"
    assert W.Matcher(W.rules_from_profile(org)).match("123.456.789-09") is None  # a numeric 'TLD' is no host name


def test_url_hits_lose_credentials_and_follow_domain_mutes(registry, rt, store, org):
    rules = W.rules_from_profile(org)
    W.mute(store, "evil.example", rules=rules)
    hits_source("t_urls", [hit("https://login.evil.example/acmebank"), hit("https://user:s3cret@phish.example/x?a=1")], accepts=(T.DOMAIN,))
    rep = watcher(rt, store, org, sources=["t_urls"]).run(once=True)
    assert rep.muted == 1 and rep.alerts == 1  # the domain mute covers URLs on that domain
    alert = W.recent_alerts(store)[0]
    assert alert.registrable_domain == "https://phish.example/x?a=1" and "s3cret" not in json.dumps(alert.to_record())
    assert "user" not in alert.name


def test_a_domain_label_that_is_an_executives_name_never_becomes_a_keyword():
    prof = dict(PROFILE, domains=[{"name": "acmebank.com.br", "verification": "txt_verified"},
                                  {"name": "joanaexemplo.com.br", "verification": "seeded"}],
                suppliers=[{"name": "S", "domains": ["joana-exemplo.net", "supplier.example"]}])
    problems: list[str] = []
    rules = {r.id: r for r in W.rules_from_profile(OrgProfile.from_dict(prof), problems=problems)}
    own = rules["domain:joanaexemplo.com.br"]
    assert own.terms == () and own.permutations == {} and own.domains == ("joanaexemplo.com.br",)  # still protected
    assert "joanaexemplo" not in rules["supplier:s"].terms and "supplier" in rules["supplier:s"].terms
    assert not any(k.startswith(("joana", "j0ana")) for k in rules["supplier:s"].permutations)
    assert sum("name of a person" in p for p in problems) == 2
    m = W.Matcher(list(rules.values()))
    assert m.match("www.joanaexemplo.com.br").protected_by and m.match("joanaexemplo-login.com").matches == ()
    # a short given name never drops an unrelated brand ('Ana Li' vs 'Banalia')
    short = {"brands": [{"keyword": "Banalia"}], "executives": [{"name": "Ana Li", "opt_in": True, "programme": "x", "informed_at": "2026-11-01"}]}
    assert [r.terms for r in W.rules_from_profile(short)] == [("banalia",)]


def test_a_source_failing_on_one_entity_is_never_reported_ok(registry, rt, store, org):
    from v3lum.core.models import Status

    def flaky(self, entity, ctx):
        res = self.result(entity)
        if entity.type is T.KEYWORD:
            return res.mark(Status.RATE_LIMITED, "429 from the source", reason_code="rate_limited")
        return res

    define_module("t_flaky", [T.DOMAIN, T.KEYWORD], flaky, tags={"watch_source"})
    rep = watcher(rt, store, org, sources=["t_flaky"]).run(once=True)
    state = rep.sources["t_flaky"]
    assert state["status"] == "rate_limited" and "1 of 2 entity runs could not verify" in state["reason"]
    assert any("no polling source answered" in n for n in rep.notes)
    assert W._merge_states([{"status": "ok", "reason_code": "", "reason": ""}, {"status": "empty", "reason_code": "", "reason": ""}])["status"] == "ok"


def test_the_200_lines_per_hour_budget_holds_across_once_runs(registry, rt, store, org, clock):
    batch = {"n": 0}
    hits_source("t_hourly", lambda e: [hit(f"acmebank-{batch['n']}-{i}.net") for i in range(150)], accepts=(T.DOMAIN,))
    lines: list[str] = []
    rep1 = watcher(rt, store, org, lines=lines, sources=["t_hourly"]).run(once=True)
    clock.advance(300)  # the next timer run, same clock hour
    batch["n"] = 1
    rep2 = watcher(rt, store, org, lines=lines, sources=["t_hourly"]).run(once=True)
    assert rep1.alerts == rep2.alerts == 150 and rep1.summarized == 0 and rep2.summarized == 100
    assert len(alert_lines(lines)) == 200 and sum("more alert(s) in hour" in line for line in lines) == 1


def test_refused_handshakes_back_off_long_and_never_leak_the_endpoint_secret(org, clock):
    class Refused(Exception):
        status_code = 429

    class Transport:
        def connect(self, url, *, timeout):
            raise Refused(f"Handshake status 429 Too Many Requests for {url}")

    url = "wss://watcher:t0ps3cret@ct.example.test/full-stream?token=abc123"
    consumer = W.CertStreamConsumer(url, W.Matcher(W.rules_from_profile(org)), transport=Transport(), clock=clock, rng=random.Random(4))
    consumer.run(max_connections=1)
    st = consumer.stats
    assert st.refused == 1 and st.backoffs[0] >= W.BACKOFF_BASE * 2**W.REFUSED_BACKOFF_ATTEMPT / 2  # >= 32 s, not 0.5-1 s
    assert "t0ps3cret" not in st.last_error and "abc123" not in st.last_error and "429" in st.last_error
    assert W._display_url(url) == "wss://ct.example.test/full-stream?..."
    # an empty frame (websocket-client returns '' for a close frame) is not 'malformed'
    sessions = [["", '{"message_type": "heartbeat"}']]
    quiet = W.CertStreamConsumer("wss://x.test/", W.Matcher(()), transport=ReplayTransport(sessions), clock=clock)
    quiet.run(max_connections=1)
    assert quiet.stats.malformed == 0 and quiet.stats.received == 1 and quiet.stats.heartbeats == 1


def test_health_never_shows_endpoint_credentials(rt, org, monkeypatch):
    monkeypatch.setattr(W, "certstream_available", lambda: True)
    rt.config.settings["certstream_url"] = "wss://watcher:t0ps3cret@10.0.0.7:8443/full-stream?token=abc123"
    bad = W.health(rt.config, org=org, transport=ReplayTransport(fail=1), probe=True)["certstream"]
    shown = json.dumps(bad)
    assert bad["disclosure"] == "internal" and bad["url"] == "wss://10.0.0.7:8443/full-stream?..."
    assert "t0ps3cret" not in shown and "abc123" not in shown and bad["reachable"] is False
    # the run's status/report shows the display form; only the consumer gets the full URL
    monkeypatch.setattr(W.CertStreamConsumer, "start", lambda self: None)
    with Store(settings=rt.config, health=False) as st:
        w = W.Watcher(rt, st, org, transport=ReplayTransport())
        status = w.certstream_status()
        assert status["state"] == "running" and status["url"] == "wss://10.0.0.7:8443/full-stream?..."
        w._start_stream(status)
        assert w.consumer.url == rt.config.settings["certstream_url"]


def test_ransomware_victim_feeds_watch_only_with_the_pro_key(registry, rt, store, org, monkeypatch):
    with test_provider("t_victims", hosts=("victims.example.test",), keys=("t_victims_pro",)) as prov:
        monkeypatch.setitem(W.VICTIM_FEED_KEYS, prov.id, "t_victims_pro")
        common = {"disclosure": "third_party", "provider": prov.id, "sources": source_ids(prov), "hosts": prov.hosts,
                  "access_model": "free_noauth_unlimited", "tags": {"watch_source"}}
        calls: list[str] = []
        define_module("t_victims_keyless", [T.DOMAIN], lambda self, e, c: calls.append(e.key) or self.result(e), **common)
        define_module("t_victims_pro", [T.DOMAIN], lambda self, e, c: calls.append(e.key) or self.result(e),
                      requires_keys=("t_victims_pro",), **{**common, "access_model": "free_auth_limited"})
        w = watcher(rt, store, org, sources=["t_victims_keyless", "t_victims_pro"])
        assert [c.name for c in w.watch_sources()] == ["t_victims_pro"]
        rep = w.run(once=True)
    assert rep.sources["t_victims_keyless"]["reason_code"] == "policy" and "PRO key" in rep.sources["t_victims_keyless"]["reason"]
    assert rep.sources["t_victims_pro"]["status"] == "needs_key" and calls == []  # no key configured: never run


def test_a_lowered_watch_tlp_is_recorded_in_the_watch_case_audit(registry, rt, store, org, clock):
    hits_source("t_lowered", [hit("acmebank-baixo.com")], accepts=(T.DOMAIN,))
    change = {"os_user": "ana", "analyst": "ana", "at": "2026-11-26T12:00:00+00:00", "from": "amber", "to": "clear"}
    rep = watcher(rt, store, org, sources=["t_lowered"], tlp="clear", tlp_change=change).run(once=True)
    assert rep.alerts == 1 and rep.tlp == "clear"
    rows = [r for r in store.audit_rows(W.watch_case_id(clock.now())) if r["kind"] == "tlp_change"]
    assert len(rows) == 1 and rows[0]["payload"]["to"] == "clear" and rows[0]["payload"]["path"] == "watch"


def test_cli_watch_announces_a_lowered_tlp_and_defangs_listed_domains(cli, capsys):
    assert main(["watch", "--once", "--sources", "t_cli_src", "--tlp", "clear"]) == 0
    out = capsys.readouterr().out
    assert "TLP lowered from TLP:AMBER to TLP:CLEAR" in out and "login-acmebank[.]com" in out
    from rich.console import Console

    from v3lum.commands.watch import _summary

    buf = io.StringIO()
    rep = W.WatchReport(enrich_listed=[f"acmebank-{i}.net" for i in range(25)], enrich_listed_more=5, rejected=2, stop_reason="once")
    _summary(Console(file=buf, width=400, no_color=True), rep)
    text = buf.getvalue()
    assert "acmebank-0[.]net" in text and "acmebank-0.net" not in text and "(30 in all)" in text and "2 hit(s) dropped" in text


def test_contract_additions_names_resolve():
    """Every backticked v3lum.* name of docs/contract_additions/WP26.md exists."""
    import importlib
    import re

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP26.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`", doc)))
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        obj, rest = None, []
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for attr in rest:
            if not hasattr(obj, attr):
                missing.append(dotted)
                break
            obj = getattr(obj, attr)
    assert len(names) > 25 and not missing, missing
    public = {"Watcher", "WatchRule", "Alert", "rules_from_profile", "permutations", "health"}
    assert public <= set(W.__all__)
