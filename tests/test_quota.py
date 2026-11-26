"""Provider quotas (P334, WP10): UTC windows on a fake clock, atomic reservations under 12 threads
(one book and one book per 'process'), the seed reserve, provider signals (persisted quota marker,
in-memory rate-limit backoff), key-scoped monthly windows, the token bucket, deferred lookups,
report lines, DoH never charged and the v1 per-module counters."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from tests.fakes import FakeClock, FakeHttp
from v3lum import paths
from v3lum.core import providers as providers_mod
from v3lum.core.http import HttpClient, QuotaExceeded, RateLimited
from v3lum.core.migrations import user_version
from v3lum.core.quota import (
    DOH_PROVIDERS,
    MAX_SIGNAL_DAYS,
    RATE_WAIT_MAX,
    QuotaBook,
    default_path,
    deferral_key,
    window_end,
    window_start,
)

START = datetime(2026, 11, 26, 12, 30, 0, tzinfo=timezone.utc)


def prov(pid: str = "qprov", *, name: str = "QProv", hour=None, day=None, month=None, scope="egress_ip", rate=None, burst=1, keys=(), hosts=("api.qprov.test",), markers=()):
    quota = None
    if any(v is not None for v in (hour, day, month, rate)):
        quota = providers_mod.QuotaSpec(scope=scope, hour=hour, day=day, month=month, rate_per_second=rate, burst=burst, evidence_url="https://qprov.test/limits")
    terms = providers_mod.Terms(class_="open")
    return providers_mod.Provider(
        id=pid,
        name=name,
        operator=name,
        hosts=tuple(hosts),
        tier="trusted",
        quota=quota,
        keys={k: providers_mod.KeySpec(name=k, provider=pid) for k in keys},
        error_markers=tuple(providers_mod.parse_marker(m) for m in markers),
        sources={"default": providers_mod.Source(id=f"{pid}.default", provider=pid, title="default", terms=terms, upstream_family=pid)},
    )


def registry(*items):
    return providers_mod.ProviderRegistry(list(items))


@pytest.fixture()
def clock():
    return FakeClock(START)


def book_for(tmp_path, clock, *items, name="quota.db"):
    return QuotaBook(tmp_path / name, clock=clock, providers=registry(*items))


# --------------------------------------------------------------------------------------
# windows on a fake clock
# --------------------------------------------------------------------------------------


def test_window_keys_and_resets():
    now = datetime(2026, 12, 31, 23, 59, 30, tzinfo=timezone.utc)
    assert window_start("hour", now) == "2026-12-31T23"
    assert window_start("day", now) == "2026-12-31"
    assert window_start("month", now) == "2026-12"
    assert window_end("hour", now) == datetime(2027, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert window_end("day", now) == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert window_end("month", now) == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert window_end("month", datetime(2026, 2, 10, tzinfo=timezone.utc)) == datetime(2026, 3, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        window_start("week", now)


def test_hour_day_month_windows_follow_the_fake_clock(tmp_path, clock):
    # published 10/h, 25/day, 50/month -> budgets 8, 20, 40 (80%, P334 cond 3)
    p = prov(hour=10, day=25, month=50)
    book = book_for(tmp_path, clock, p)
    for _ in range(8):
        book.reserve("qprov", "api.qprov.test")
    with pytest.raises(QuotaExceeded) as err:
        book.reserve("qprov", "api.qprov.test")
    assert "8/8 this hour" in str(err.value) and "could not verify" in str(err.value)
    assert book.remaining("qprov") == 0 and book.exhausted_provider("qprov")
    clock.advance(3600)  # next hour: the hour window resets, the day keeps counting
    for _ in range(8):
        book.reserve("qprov", "api.qprov.test")
    clock.advance(3600)
    for _ in range(4):
        book.reserve("qprov", "api.qprov.test")
    with pytest.raises(QuotaExceeded) as err:
        book.reserve("qprov", "api.qprov.test")
    assert "20/20 today" in str(err.value)
    usage = book.usage("qprov")
    assert usage["day"] == {"used": 20, "budget": 20} and usage["month"] == {"used": 20, "budget": 40}
    clock.advance(86400)  # next day: hour and day reset, the month remembers
    assert book.remaining("qprov") == 8
    for burst in (8, 8, 4):
        for _ in range(burst):
            book.reserve("qprov", "api.qprov.test")
        clock.advance(3600)
    assert book.usage("qprov")["month"] == {"used": 40, "budget": 40}
    clock.advance(86400)  # a new day, but the month budget is used up
    with pytest.raises(QuotaExceeded) as err:
        book.reserve("qprov", "api.qprov.test")
    assert "40/40 this month" in str(err.value) and "2026-12-01 00:00 UTC" in str(err.value)
    clock.advance(4 * 86400)  # December
    assert book.remaining("qprov") == 8


def test_providers_without_a_quota_block_are_never_charged(tmp_path, clock):
    book = book_for(tmp_path, clock, prov("free", name="Free"))
    for _ in range(100):
        assert book.reserve("free", "api.qprov.test") == 0.0
    assert book.remaining("free") is None and not book.exhausted_provider("free")
    assert book.reserve("unregistered", "x.test") == 0.0
    con = sqlite3.connect(book.path)
    assert con.execute("SELECT COUNT(*) FROM windows").fetchone()[0] == 0


def test_doh_is_never_charged(tmp_path, clock):
    # even a (hypothetical) quota block on a resolver provider never charges DoH (P334 cond 1)
    items = [prov(pid, name=pid, day=1, hosts=(f"{pid}.test",)) for pid in sorted(DOH_PROVIDERS)]
    book = book_for(tmp_path, clock, *items)
    for pid in sorted(DOH_PROVIDERS):
        for _ in range(5):
            assert book.reserve(pid, "dns.google") == 0.0
        assert book.remaining(pid) is None
    book2 = book_for(tmp_path, clock, prov("lookalike", day=1, hosts=("dns.google",)), name="q2.db")
    for _ in range(3):  # charged by host: public DoH endpoints are free whoever owns them
        assert book2.reserve("lookalike", "dns.google") == 0.0
    con = sqlite3.connect(book.path)
    assert con.execute("SELECT COUNT(*) FROM windows").fetchone()[0] == 0


# --------------------------------------------------------------------------------------
# atomic reservations (12 threads, 50/day -> never more than 40)
# --------------------------------------------------------------------------------------


def _hammer(reserve, attempts: int, ok: list[int], refused: list[int], lock: threading.Lock) -> None:
    for _ in range(attempts):
        try:
            reserve()
        except QuotaExceeded:
            with lock:
                refused.append(1)
        else:
            with lock:
                ok.append(1)


def test_twelve_threads_never_overshoot_a_shared_book(tmp_path, clock):
    book = book_for(tmp_path, clock, prov("hackertarget", name="HackerTarget", day=50))
    ok: list[int] = []
    refused: list[int] = []
    lock = threading.Lock()
    threads = [threading.Thread(target=_hammer, args=(lambda: book.reserve("hackertarget", "api.qprov.test"), 10, ok, refused, lock)) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(ok) == 40 and len(refused) == 80
    assert book.usage("hackertarget")["day"] == {"used": 40, "budget": 40}


def test_twelve_processes_worth_of_books_never_overshoot(tmp_path, clock):
    """One QuotaBook (own SQLite connection) per thread on the same file: the BEGIN IMMEDIATE
    reservation is what keeps separate processes from overshooting."""
    p = prov("hackertarget", name="HackerTarget", day=50)
    QuotaBook(tmp_path / "shared.db", clock=clock, providers=registry(p)).close()
    ok: list[int] = []
    refused: list[int] = []
    lock = threading.Lock()
    books = [QuotaBook(tmp_path / "shared.db", clock=clock, providers=registry(p)) for _ in range(12)]
    threads = [threading.Thread(target=_hammer, args=(lambda b=b: b.reserve("hackertarget", "api.qprov.test"), 10, ok, refused, lock)) for b in books]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert len(ok) == 40 and len(refused) == 80
    con = sqlite3.connect(tmp_path / "shared.db")
    assert con.execute("SELECT SUM(used) FROM windows WHERE window = 'day'").fetchone()[0] == 40
    for b in books:
        b.close()


# --------------------------------------------------------------------------------------
# seed reserve (P334 cond 6)
# --------------------------------------------------------------------------------------


def test_seed_reserve_pivot2_never_consumes_the_last_twenty_percent(tmp_path, clock):
    book = book_for(tmp_path, clock, prov(day=50))  # budget 40, seed reserve 8
    taken = 0
    with pytest.raises(QuotaExceeded) as err:
        while True:
            book.reserve("qprov", "api.qprov.test", priority="pivot2")
            taken += 1
    assert taken == 32 and "kept for analyst-typed seeds" in str(err.value)
    assert book.exhausted_provider("qprov", priority="pivot2") and not book.exhausted_provider("qprov")
    assert book.remaining("qprov") == 8 and book.remaining("qprov", priority="pivot2") == 0
    for _ in range(4):
        book.reserve("qprov", "api.qprov.test", priority="pivot")  # depth-1 pivots may use the reserve
    for _ in range(4):
        book.reserve("qprov", "api.qprov.test", priority="seed")
    with pytest.raises(QuotaExceeded):
        book.reserve("qprov", "api.qprov.test", priority="seed")
    with pytest.raises(QuotaExceeded):  # an unknown priority is treated like pivot2 (fail safe)
        book.reserve("qprov", "api.qprov.test", priority="whatever")


# --------------------------------------------------------------------------------------
# provider signals (P334 cond 8) and the HTTP client's quota protocol
# --------------------------------------------------------------------------------------


def test_provider_quota_signal_wins_until_the_window_resets(tmp_path, clock):
    book = book_for(tmp_path, clock, prov(hour=100, day=1000))
    book.reserve("qprov", "api.qprov.test")
    book.signal("qprov", kind="quota")  # counters say 1/80 but the provider says exhausted
    assert book.exhausted_provider("qprov") and book.remaining("qprov") == 0
    with pytest.raises(QuotaExceeded) as err:
        book.reserve("qprov", "api.qprov.test")
    assert "provider reported its quota exhausted" in str(err.value) and "13:00" in str(err.value)
    other = book_for(tmp_path, clock, prov(hour=100, day=1000))  # recorded: another run/process sees it
    assert other.exhausted_provider("qprov", priority="pivot") and other.exhausted_provider("qprov", priority="pivot2")
    with pytest.raises(QuotaExceeded):
        other.reserve("qprov", "api.qprov.test", priority="pivot")  # pivots never spend the request
    assert not other.exhausted_provider("qprov")  # an analyst-typed seed keeps one honest attempt
    other.reserve("qprov", "api.qprov.test", priority="seed")
    other.signal("qprov", kind="quota")  # ... and the provider, still exhausted, says so again
    with pytest.raises(QuotaExceeded):
        other.reserve("qprov", "api.qprov.test", priority="seed")
    clock.advance(30 * 60)  # 13:00 UTC: the shortest window (hour) reset
    assert not book.exhausted_provider("qprov") and not other.exhausted_provider("qprov", priority="pivot")
    book.reserve("qprov", "api.qprov.test")
    end = book.mark_exhausted("qprov", datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc))
    assert end == datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc)
    assert book.mark_exhausted("qprov", "2026-11-26T15:00:00+00:00") == end  # an earlier end never shortens it
    assert any("quota exhausted (provider signal) until 2026-11-26 18:00 UTC" in line for line in book.quota_lines())


def test_signal_without_a_quota_block_lasts_until_the_utc_day_ends(tmp_path, clock):
    book = book_for(tmp_path, clock, prov("nb", name="NoBlock"))
    book.signal("nb", kind="quota")
    with pytest.raises(QuotaExceeded):
        book.reserve("nb", "api.qprov.test")
    clock.advance(11 * 3600 + 31 * 60)  # past midnight UTC
    assert book.reserve("nb", "api.qprov.test") == 0.0


def test_rate_limited_signal_is_an_in_memory_backoff(tmp_path, clock):
    book = book_for(tmp_path, clock, prov(day=100))
    book.signal("qprov", kind="rate_limited")
    with pytest.raises(RateLimited) as err:
        book.reserve("qprov", "api.qprov.test")
    assert "rest of this run" in str(err.value) and book.backing_off("qprov")
    assert not book.exhausted_provider("qprov")  # a rate limit is not a quota
    fresh = book_for(tmp_path, clock, prov(day=100))  # never persisted: a new run starts clean
    fresh.reserve("qprov", "api.qprov.test")
    book.reset_run()
    book.reserve("qprov", "api.qprov.test")
    until = datetime(2026, 11, 26, 12, 31, tzinfo=timezone.utc)
    book.signal("qprov", kind="rate_limited", until=until)
    with pytest.raises(RateLimited):
        book.reserve("qprov", "api.qprov.test")
    clock.advance(61)
    book.reserve("qprov", "api.qprov.test")
    book.signal("qprov", kind="something_else")  # ignored
    book.reserve("qprov", "api.qprov.test")


def test_http_client_quota_marker_in_a_200_body_marks_the_provider_exhausted(tmp_path, clock):
    """P321 + P334 cond 8: an error inside an HTTP-200 body classified 'quota' reaches signal(); the
    next request to the provider is refused before it is sent, until the window resets."""
    marker = {"id": "qprov_quota", "statuses": [200], "json_path": "error", "equals": "daily limit reached", "maps_to": "quota", "reason": "QProv: daily quota exhausted"}
    p = prov(day=100, markers=(marker,))
    reg = registry(p)
    book = QuotaBook(tmp_path / "quota.db", clock=clock, providers=reg)
    http = FakeHttp(clock=clock)
    http.add("GET", "https://api.qprov.test/a", json={"ok": True}, times=1)
    http.add("GET", "https://api.qprov.test/b", json={"error": "daily limit reached"}, times=1)
    http.add("GET", "https://api.qprov.test/c", json={"ok": True})
    client = HttpClient(transport=http, providers=reg, quota=book, clock=clock, retries=0)
    assert client.request("GET", "https://api.qprov.test/a").status == 200
    marked = client.request("GET", "https://api.qprov.test/b")  # ctx.http.check() would raise QuotaExceeded here
    assert marked.classification is not None and marked.classification.status == "quota"
    assert book.exhausted_provider("qprov")
    sent = len(http.calls)
    with pytest.raises(QuotaExceeded) as err:
        client.request("GET", "https://api.qprov.test/c")
    assert len(http.calls) == sent  # refused before sending
    assert "could not verify" in str(err.value)
    assert book.usage("qprov")["day"]["used"] == 2  # a + b were charged, c was not
    clock.advance(12 * 3600)  # next UTC day: the signal expired with the window
    assert client.request("GET", "https://api.qprov.test/c").status == 200


# --------------------------------------------------------------------------------------
# key-scoped monthly windows (keyed plans counted per key name, never multiplied)
# --------------------------------------------------------------------------------------


def test_keyed_plan_counts_per_key_name_in_a_monthly_window(tmp_path, clock):
    p = prov("keyed", name="Keyed", month=125, scope="key", keys=("keyed_api",))
    book = book_for(tmp_path, clock, p)
    for _ in range(100):  # budget 100 of the published 125/month
        book.reserve("keyed", "api.qprov.test")
    with pytest.raises(QuotaExceeded) as err:
        book.reserve("keyed", "api.qprov.test")
    assert "100/100 this month" in str(err.value) and "2026-12-01" in str(err.value)
    con = sqlite3.connect(book.path)
    rows = con.execute("SELECT scope_key, window, window_start, used FROM windows").fetchall()
    assert rows == [("key:keyed_api", "month", "2026-11", 100)]
    clock.advance(3 * 86400)  # 29 November: the month keeps counting
    assert book.exhausted_provider("keyed")
    clock.advance(3 * 86400)  # December
    assert book.remaining("keyed") == 100
    lines = book.quota_lines()
    assert not any(line.startswith("Keyed") for line in lines)


def test_egress_budgets_ignore_keys_and_proxies(tmp_path, clock):
    """A13: an egress-IP budget is one counter per installation whatever keys exist."""
    p = prov("egr", name="Egr", day=10, keys=("egr_key",))
    book = book_for(tmp_path, clock, p)
    for _ in range(8):
        book.reserve("egr", "api.qprov.test")
    con = sqlite3.connect(book.path)
    assert con.execute("SELECT DISTINCT scope_key FROM windows").fetchall() == [("egress",)]
    with pytest.raises(QuotaExceeded):
        book.reserve("egr", "api.qprov.test")


# --------------------------------------------------------------------------------------
# token bucket (rate_per_second / burst)
# --------------------------------------------------------------------------------------


def test_token_bucket_returns_the_wait_and_never_sleeps(tmp_path, clock):
    """The book takes the provider's next slot and returns the wait; the HTTP client waits on its
    own clock and deadline (a book bound to the system clock must never block a test). The rate is
    budgeted like the windows: 2/s published at the default 80% margin = 1.6/s (0.625 s apart)."""
    book = book_for(tmp_path, clock, prov(day=1000, rate=2.0, burst=2))
    assert book.reserve("qprov", "api.qprov.test") == 0.0
    assert book.reserve("qprov", "api.qprov.test") == 0.0  # burst of 2
    assert book.reserve("qprov", "api.qprov.test") == pytest.approx(0.625)  # then 1.6/s
    assert book.reserve("qprov", "api.qprov.test") == pytest.approx(1.25)
    assert clock.sleeps == []  # nothing slept
    clock.advance(1.0)
    assert book.reserve("qprov", "api.qprov.test") == pytest.approx(0.875)
    assert book.rate_interval("qprov") == pytest.approx(0.625) and book.rate_interval("unknown") == 0.0
    assert RATE_WAIT_MAX == 15.0


def test_token_bucket_applies_the_safety_margin_of_the_block(tmp_path, clock):
    """P334 cond 3: budgets default to at most 80% of the published limit - the rate included
    (VirusTotal publishes 4/min: requests go 18.75 s apart, never exactly at the limit)."""
    vt = prov("vt", name="VT", day=500, rate=4 / 60, hosts=("vt.test",))
    exact = providers_mod.Provider(
        id="exact", name="Exact", operator="Exact", hosts=("exact.test",), tier="trusted",
        quota=providers_mod.QuotaSpec(scope="egress_ip", rate_per_second=1.0, safety_margin=1.0),
        sources={"default": providers_mod.Source(id="exact.default", provider="exact", title="d", terms=providers_mod.Terms(class_="open"), upstream_family="exact")},
    )
    book = book_for(tmp_path, clock, vt, exact)
    assert book.rate_interval("vt") == pytest.approx(18.75)
    assert book.reserve("vt", "vt.test") == 0.0 and book.reserve("vt", "vt.test") == pytest.approx(18.75)
    assert book.rate_interval("exact") == pytest.approx(1.0)  # a block may state its own margin


def test_token_bucket_slots_are_per_provider_and_scope(tmp_path, clock):
    book = book_for(tmp_path, clock, prov(day=1000, rate=0.05), prov("other", day=1000, rate=0.05, hosts=("o.test",)))
    assert book.reserve("qprov", "api.qprov.test") == 0.0
    assert book.reserve("qprov", "api.qprov.test") == pytest.approx(25.0)  # 0.05/s at 80%: one request every 25 s
    assert book.reserve("other", "o.test") == 0.0
    book.reset_run()
    assert book.reserve("qprov", "api.qprov.test") == 0.0


# --------------------------------------------------------------------------------------
# deferred lookups and report lines (P334 cond 6-7)
# --------------------------------------------------------------------------------------


def test_deferral_list_is_pseudonymised_and_resolvable(tmp_path, clock):
    book = book_for(tmp_path, clock, prov("hackertarget", name="HackerTarget", day=50))
    book.defer("CASE1", "t_ht", "domain:evil.example", "quota: HackerTarget", provider="hackertarget")
    book.defer("CASE1", "t_ht", "email:alice@corp.example", "quota", provider="hackertarget")
    book.defer("CASE1", "t_ht", "email:alice@corp.example", "quota again", provider="hackertarget")  # idempotent per pair
    book.defer("CASE2", "t_ht", "domain:other.example", "quota", provider="hackertarget")
    rows = book.deferred("CASE1")
    assert len(rows) == 2 and all(r["entity_key"].split(":", 1)[1].startswith("#") for r in rows)
    assert {r["entity_key"] for r in rows} == {deferral_key("domain:evil.example"), deferral_key("email:alice@corp.example")}
    case = {"seeds": ["domain:evil.example"], "entities": [{"key": "email:alice@corp.example"}]}
    resolved = book.deferred("CASE1", case=case)
    assert {r["entity_key"] for r in resolved} == {"domain:evil.example", "email:alice@corp.example"}
    assert {r["reason"] for r in resolved} == {"quota: HackerTarget", "quota again"}
    raw = (tmp_path / "quota.db").read_bytes()
    assert b"evil.example" not in raw and b"alice@corp.example" not in raw  # never a value in the quota DB
    for _ in range(40):
        book.reserve("hackertarget", "api.qprov.test")
    assert book.quota_lines("CASE1") == ["HackerTarget: 40/40 today, 2 lookups deferred"]
    assert book.quota_lines() == ["HackerTarget: 40/40 today, 4 lookups deferred"]  # this run's defer() calls
    assert book.forget_case("CASE1", dry_run=True) == 2
    assert book.forget_case("CASE1") == 2 and book.deferred("CASE1") == []
    assert book.deferred("CASE2")


def test_quota_lines_list_only_exhausted_or_deferred_providers(tmp_path, clock):
    book = book_for(tmp_path, clock, prov("a", name="Alpha", day=100), prov("b", name="Beta", hour=5, hosts=("b.test",)))
    book.reserve("a", "api.qprov.test")
    assert book.quota_lines() == []
    for _ in range(4):
        book.reserve("b", "b.test")
    assert book.quota_lines() == ["Beta: 4/4 this hour"]
    book.defer("C", "mod_a", "domain:x.example", "quota", provider="a")
    assert book.quota_lines() == ["Alpha: 1/80 today, 1 lookup deferred", "Beta: 4/4 this hour"]
    summary = book.provider_summary()
    assert summary["b"]["hour"] == {"used": 4, "budget": 4} and summary["a"]["signal_until"] == ""


def test_quota_lines_survive_a_block_with_a_rate_only(tmp_path, clock):
    """A quota block may declare only rate_per_second (urlscan, NVD, HIBP...): its deferral line must
    not crash the report (the engine would lose every quota line of the case)."""
    book = book_for(tmp_path, clock, prov("ro", name="RateOnly", rate=0.5), prov("a", name="Alpha", day=100, hosts=("a.test",)))
    book.defer("C", "mod_ro", "domain:x.example", "rate limited", provider="ro")
    book.defer("C", "mod_a", "domain:y.example", "quota", provider="a")
    assert book.quota_lines("C") == ["Alpha: 0/80 today, 1 lookup deferred", "RateOnly, 1 lookup deferred"]
    assert book.quota_lines() == ["Alpha: 0/80 today, 1 lookup deferred", "RateOnly, 1 lookup deferred"]
    assert book.provider_summary()["ro"] == {"signal_until": ""}


def test_deferral_reasons_never_keep_the_investigated_value(tmp_path, clock):
    """The quota DB may be team-shared (quota_db_path): a reason quoting the entity keeps only its
    pseudonym, and deleted deferrals are overwritten (secure_delete)."""
    book = book_for(tmp_path, clock, prov(day=10))
    book.defer("C", "t_mod", "email:alice.q@corp.example", "QProv: quota used up for Alice.Q@corp.example (retry tomorrow)", provider="qprov")
    book.defer("C", "t_mod", "domain:evil.example", "x" * 500, provider="qprov")
    rows = {r["entity_key"]: r["reason"] for r in book.deferred("C")}
    pseudo = deferral_key("email:alice.q@corp.example")
    assert rows[pseudo] == f"QProv: quota used up for {pseudo} (retry tomorrow)"
    assert len(rows[deferral_key("domain:evil.example")]) == 200
    assert book.forget_case("C") == 2
    assert book._conn.execute("PRAGMA secure_delete").fetchone()[0] == 1  # the book's own connection overwrites deleted rows
    book.close()
    assert b"alice.q@corp.example" not in (tmp_path / "quota.db").read_bytes().lower()


def test_provider_signals_are_bounded_whatever_the_provider_says(tmp_path, clock):
    """A hostile or broken Retry-After (years) never blocks a provider beyond MAX_SIGNAL_DAYS."""
    book = book_for(tmp_path, clock, prov(day=100))
    far = datetime(2099, 1, 1, tzinfo=timezone.utc)
    end = book.mark_exhausted("qprov", far)
    assert end == START + timedelta(days=MAX_SIGNAL_DAYS)
    other = book_for(tmp_path, clock, prov(day=100))  # the persisted signal is bounded too
    assert other.exhausted_provider("qprov", priority="pivot")
    clock.advance(MAX_SIGNAL_DAYS * 86400 + 1)
    assert not other.exhausted_provider("qprov", priority="pivot") and not book.exhausted_provider("qprov")
    book.signal("qprov", kind="rate_limited", until="2099-01-01T00:00:00+00:00")
    with pytest.raises(RateLimited):
        book.reserve("qprov", "api.qprov.test")
    clock.advance(MAX_SIGNAL_DAYS * 86400 + 1)
    assert book.reserve("qprov", "api.qprov.test") == 0.0  # the in-memory backoff ended too


def test_signal_ends_are_stored_in_utc(tmp_path, clock):
    """Stored ends are compared as text (MAX, pruning): an ISO end with another offset is normalised."""
    book = book_for(tmp_path, clock, prov(day=100))
    end = book.mark_exhausted("qprov", "2026-11-26T15:00:00-03:00")
    assert end == datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc)
    book.mark_exhausted("qprov", "2026-11-26T19:00:00+05:00")  # 14:00 UTC: earlier, never shortens
    con = sqlite3.connect(book.path)
    assert con.execute("SELECT exhausted_until FROM signals").fetchall() == [("2026-11-26T18:00:00+00:00",)]


# --------------------------------------------------------------------------------------
# v1 API, paths and migrations
# --------------------------------------------------------------------------------------


def test_v1_module_counters_are_kept(tmp_path, clock):
    book = book_for(tmp_path, clock, prov(day=100))
    assert book.used("t_mod") == 0 and not book.exhausted("t_mod", 3)
    book.add("t_mod", 2)
    book.add("t_mod", 0)
    book.add("t_mod", 1)
    assert book.used("t_mod") == 3 and book.exhausted("t_mod", 3) and not book.exhausted("t_mod", None)
    assert book.summary() == {"t_mod": 3}
    book.add("t_mod", 5, day="2026-01-01")
    assert book.used("t_mod", "2026-01-01") == 5
    for _ in range(7):
        book.reserve("qprov", "api.qprov.test")
    assert book.used("qprov") == 7  # a provider id reads its day window (ctx.quota_remaining)
    book.reset("t_mod")
    assert book.used("t_mod") == 0 and book.used("qprov") == 7
    book.signal("qprov", kind="quota")
    book.reset()
    assert book.used("qprov") == 0 and not book.exhausted_provider("qprov")
    assert QuotaBook.today(datetime(2026, 5, 4, tzinfo=timezone.utc)) == "2026-05-04"


def test_default_path_honours_quota_db_path(tmp_path):
    assert default_path() == paths.home() / "quota.db"
    assert default_path({"quota_db_path": ""}) == paths.home() / "quota.db"
    shared = tmp_path / "team" / "quota.db"
    assert default_path({"quota_db_path": str(shared)}) == shared
    shared.parent.mkdir()
    book = QuotaBook(settings={"quota_db_path": str(shared)})
    assert book.path == str(shared) and shared.exists()
    book.close()


def test_old_quota_db_upgrades_in_place(tmp_path, clock):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS quota (module TEXT, day TEXT, used INTEGER, PRIMARY KEY (module, day))")
    con.execute("INSERT INTO quota VALUES ('t_old', '2026-11-26', 4)")
    con.commit()
    con.close()
    book = QuotaBook(db, clock=clock, providers=registry())
    assert book.version == 2 and book.used("t_old") == 4
    con = sqlite3.connect(db)
    assert user_version(con) == 2
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"quota", "windows", "signals", "deferred"} <= tables


# --------------------------------------------------------------------------------------
# shared per-host limiter and the LIGHT/ACTIVE hard ceilings (P334 cond 4-5, A7)
# --------------------------------------------------------------------------------------


def test_limiter_ceiling_constants():
    from v3lum.core import limiter

    assert limiter.LIGHT_MAX_RPS == 1.0 and limiter.LIGHT_MAX_PER_HOST_PER_SCAN == 25
    assert limiter.ACTIVE_MAX_RPS == 10.0 and limiter.ACTIVE_MAX_CONCURRENT == 2
    assert limiter.opsec_floor("light") == 1.0 and limiter.opsec_floor("active") == pytest.approx(0.1)
    assert limiter.opsec_floor("passive") == 0.0 and limiter.opsec_floor(None) == 0.0


def test_limiter_always_reserves_and_uses_the_largest_declared_interval():
    from v3lum.core.limiter import HostLimiter
    from v3lum.core.models import Opsec

    clock = FakeClock(START)
    lim = HostLimiter(clock=clock)
    assert lim.reserve("api.example.test", 0) == 0.0
    assert lim.reserve("api.example.test", 0) == 0.0  # interval 0: the slot is still reserved
    assert lim.reserve("api.example.test", 2.0) == 0.0  # first request at the new interval
    assert lim.reserve("api.example.test", 0) == pytest.approx(2.0)  # another module's 0 s waits for the 2 s
    assert lim.interval_for("API.example.test.") == 2.0
    assert lim.reserve("target.example.test", 0, opsec=Opsec.LIGHT) == 0.0
    assert lim.reserve("target.example.test", 0, opsec="light") == pytest.approx(1.0)  # LIGHT floor: 1 req/s
    assert lim.reserve("probe.example.test", 0.0, opsec=Opsec.ACTIVE) == 0.0
    assert lim.reserve("probe.example.test", 0.0, opsec=Opsec.ACTIVE) == pytest.approx(0.1)  # ACTIVE: 10 req/s
    lim.wait_turn("target.example.test", 0)
    assert clock.sleeps and clock.sleeps[-1] == pytest.approx(2.0)


def test_active_contact_gets_at_most_two_connections_per_host():
    from v3lum.core.limiter import HostLimiter

    lim = HostLimiter(max_per_host=8)
    with lim.acquire("probe.example.test", 10, opsec="active"), lim.acquire("probe.example.test", 10, opsec="active"):
        with pytest.raises(TimeoutError), lim.acquire("probe.example.test", 10, timeout=0.01, opsec="active"):
            pass
        with lim.acquire("probe.example.test", 8, timeout=0.01):  # passive traffic has its own pool
            pass
    # a lower max_concurrent lowers the pool
    with lim.acquire("other.example.test", 1, opsec="active"), pytest.raises(TimeoutError), lim.acquire("other.example.test", 1, timeout=0.01, opsec="active"):
        pass


def test_a_scope_limit_lowers_an_existing_active_pool():
    """The host's ACTIVE pool was created at the ceiling (2) by an earlier caller: a scope file's
    max_concurrency of 1 still holds for its callers, and nobody exceeds the ceiling."""
    from v3lum.core.limiter import HostLimiter

    lim = HostLimiter()
    with lim.acquire("probe2.example.test", 2, opsec="active"):
        pass
    with lim.acquire("probe2.example.test", 1, opsec="active"):
        with pytest.raises(TimeoutError), lim.acquire("probe2.example.test", 1, timeout=0.01, opsec="active"):
            pass
        # the ceiling pool still has room for one more, then 2 connections are held: the ceiling
        with lim.acquire("probe2.example.test", 2, timeout=0.01, opsec="active"), pytest.raises(TimeoutError), lim.acquire(
            "probe2.example.test", 2, timeout=0.01, opsec="active"
        ):
            pass
    with lim.acquire("probe2.example.test", 1, timeout=0.01, opsec="active"):  # everything was released
        pass


def test_light_requests_per_host_per_scan_are_capped_at_25():
    from v3lum.core.limiter import LIGHT_MAX_PER_HOST_PER_SCAN, HostLimiter

    lim = HostLimiter()
    assert all(lim.charge_scan("target.example.test", opsec="light") for _ in range(LIGHT_MAX_PER_HOST_PER_SCAN))
    assert not lim.charge_scan("target.example.test", opsec="light")
    assert lim.scan_count("target.example.test", opsec="light") == 25
    assert lim.charge_scan("other.example.test", opsec="light")  # per host
    assert not lim.charge_scan("x.example.test", opsec="light", limit=0)
    assert lim.charge_scan("y.example.test", opsec="light", limit=500) and lim.scan_count("y.example.test", opsec="light") == 1
    assert all(lim.charge_scan("z.example.test", opsec="active") for _ in range(100))  # ACTIVE: per-case budget elsewhere
    lim.reset_scan()
    assert lim.charge_scan("target.example.test", opsec="light") and lim.scan_count("target.example.test", opsec="light") == 1


def test_refused_requests_never_take_token_bucket_slots(tmp_path, clock):
    """A pivot loop refused by the seed reserve must not push later seeds into a rate-limit wait."""
    book = book_for(tmp_path, clock, prov(day=10, rate=1.0))  # budget 8, pivot2 limit 6, 0.8 req/s
    for _ in range(6):
        book.reserve("qprov", "api.qprov.test", priority="pivot2")
        clock.advance(2)
    for _ in range(50):
        with pytest.raises(QuotaExceeded):
            book.reserve("qprov", "api.qprov.test", priority="pivot2")
    assert book.reserve("qprov", "api.qprov.test", priority="seed") == 0.0  # no wait inherited from refusals
