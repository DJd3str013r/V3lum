"""pwned_passwords_internal (P141): the HIBP Pwned Passwords k-anonymity helper (not a registered module).

Fixtures in tests/fixtures/pwned_passwords_internal/ are recorded answers for HIBP's documented example
prefix 5BAA6 (SHA-1 of 'password'): ``range_padded_ok.txt`` (live 2026-11-26 with Add-Padding, CRLF,
10 of 2,098 rows: first rows, the example row and its neighbours, the last real row and 3 padding rows),
``range_plain_ok.txt`` (research sample 2026-11-25, LF), ``malformed_truncated.txt`` (a transfer cut
mid-row), the live HTTP 400 answers for 'ZZZZZ' and '5BAA', and the response headers of both live
calls. Public data only (hash suffixes and counts).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from tests.fakes import module_fixture
from v3lum.core import module as module_api
from v3lum.modules.breach_leak import pwned_passwords_internal as pw
from v3lum.modules.breach_leak.pwned_passwords_internal import (
    ATTRIBUTION,
    HEADERS,
    PwnedResult,
    annotate,
    check_enabled,
    count_in_range,
    http_fetch,
    lookup,
    note_for,
    range_problem,
    range_url,
    sha1_prefix_suffix,
)

FIXDIR = Path(__file__).resolve().parents[1] / "fixtures" / "pwned_passwords_internal"
NAME = "pwned_passwords_internal"
SECRET = "password"  # HIBP's documented example: SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
FULL_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
SUFFIX = FULL_HASH[5:]
#: a distinctive fixture-only value for the leak checks ('password' also spells the provider's host name)
OTHER = "Fixture-only value 7f3c!"
OTHER_HASH = hashlib.sha1(OTHER.encode()).hexdigest().upper()  # noqa: S324 - the API is defined over SHA-1


def raw(name: str) -> bytes:
    return (FIXDIR / name).read_bytes()  # byte-exact: CRLF kept


def env(name: str):
    return module_fixture(NAME, name)


class Recorder:
    """fetch_range double: answers one canned (status, headers, body) and records what was sent."""

    def __init__(self, status=200, headers=None, body=b"", error: Exception | None = None):
        self.answer = (status, headers or {"content-type": "text/plain"}, body)
        self.error = error
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if self.error is not None:
            raise self.error
        return self.answer


def assert_no_secret(*items):
    text = json.dumps([repr(i) for i in items])
    for needle in (OTHER, OTHER_HASH, OTHER_HASH.lower(), OTHER_HASH[5:], OTHER_HASH[5:].lower(), FULL_HASH, SUFFIX):
        assert needle not in text


def with_other(body: bytes, count: int = 7) -> bytes:
    """The recorded range body plus a row for OTHER's suffix (its prefix differs: synthetic)."""
    return body + f"\r\n{OTHER_HASH[5:]}:{count}".encode()


# ---------------------------------------------------------------------- cond 2: prefix only


def test_sha1_prefix_and_suffix_in_memory():
    assert sha1_prefix_suffix(SECRET) == ("5BAA6", SUFFIX)
    assert sha1_prefix_suffix(SECRET.encode()) == ("5BAA6", SUFFIX)
    for bad in ("", b"", None, 5):
        with pytest.raises(ValueError):
            sha1_prefix_suffix(bad)


def test_only_a_five_hex_prefix_can_reach_a_url():
    assert range_url("5baa6") == "https://api.pwnedpasswords.com/range/5BAA6"
    for bad in (SECRET, FULL_HASH, SUFFIX, "5BAA", "5BAA61", "ZZZZZ", "5BAA6/../x", None):
        with pytest.raises(ValueError):
            range_url(bad)


def test_lookup_sends_only_the_prefix_with_padding_and_matches_in_memory():
    fetch = Recorder(body=raw("range_padded_ok.txt"))
    res = lookup(SECRET, fetch, finding_kind="password", enabled=True)
    assert res == PwnedResult(52373976, "appears 52373976 times in public breach corpora", None, ATTRIBUTION)
    assert fetch.calls == [("https://api.pwnedpasswords.com/range/5BAA6", HEADERS)]
    assert HEADERS == {"Add-Padding": "true"}
    fetch = Recorder(body=with_other(raw("range_padded_ok.txt")))
    res = lookup(OTHER, fetch, finding_kind="password", enabled=True)
    assert res.count == 7 and fetch.calls[0][0] == f"https://api.pwnedpasswords.com/range/{OTHER_HASH[:5]}"
    assert_no_secret(fetch.calls, res)


def test_plain_body_padding_rows_and_absent_suffixes():
    assert count_in_range(raw("range_plain_ok.txt"), SUFFIX) == 52373976  # LF body
    padded = raw("range_padded_ok.txt")
    assert count_in_range(padded, "39A850EAE7C3A36A485BAC684289911BFE9") == 0  # padding row: never a match
    assert count_in_range(padded, "0" * 35) == 0
    assert count_in_range(padded, "not-a-suffix") is None
    assert note_for(0) == "appears 0 times in public breach corpora" and note_for(1) == "appears 1 time in public breach corpora"


# ---------------------------------------------------------------------- cond 1: never reachable by input


def test_disabled_by_default_and_credential_kinds_only():
    fetch = Recorder(body=raw("range_padded_ok.txt"))
    res = lookup(SECRET, fetch, finding_kind="password")
    assert res.count is None and "disabled" in res.reason and fetch.calls == []
    for kind in ("aws_access_key", "github_token", "jwt", "private_key", "text_blob", ""):
        with pytest.raises(ValueError):
            lookup(SECRET, fetch, finding_kind=kind, enabled=True)
    assert fetch.calls == []

    class Ctx:
        def __init__(self, value):
            self.value = value

        def setting(self, name, default=None):
            return self.value if name == pw.SETTING else default

    assert check_enabled(Ctx(None)) is False and check_enabled(Ctx("true")) is False and check_enabled(Ctx(True)) is True
    assert check_enabled(object()) is False


def test_not_a_registered_module_and_no_input_path_reaches_it():
    module_api.load_modules()
    assert NAME not in module_api.REGISTRY
    assert not [v for v in vars(pw).values() if isinstance(v, type) and issubclass(v, module_api.Module)]
    root = Path(__file__).resolve().parents[2] / "v3lum"
    importers = []
    for path in root.rglob("*.py"):
        if path.name == "pwned_passwords_internal.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "pwned_passwords_internal" in text or "pwnedpasswords.com/range" in text:
            importers.append(str(path.relative_to(root)))
    # only the secret scanner (P312) or the core helper it calls may use the helper; nothing else
    assert all(p.endswith(("modules/utility/secret_scanner.py", "core/pwned.py")) for p in importers), importers


# ---------------------------------------------------------------------- cond 3: nothing leaks


def test_nothing_about_the_secret_is_logged_or_returned(caplog):
    caplog.set_level(logging.DEBUG)
    for fetch in (Recorder(body=with_other(raw("range_padded_ok.txt"))), Recorder(error=ConnectionError("reset by peer")),
                  Recorder(status=400, body=env("error_400_not_hex.json")["body"]), Recorder(body=raw("malformed_truncated.txt"))):
        res = lookup(OTHER, fetch, finding_kind="db_password", enabled=True)
        assert set(vars(res)) == {"count", "note", "reason", "attribution"}
        assert_no_secret(res, fetch.calls, annotate({"preview": "Fixt…7f3c"}, res))
    assert_no_secret(caplog.text)


def test_http_fetch_adapter_asks_for_no_store_and_no_redirects():
    seen = {}

    class Resp:
        status, headers, content = 200, {"cache-control": "no-store"}, raw("range_padded_ok.txt")

    class Http:
        def get(self, url, **kw):
            seen.update(url=url, **kw)
            return Resp()

    res = lookup(SECRET, http_fetch(Http()), finding_kind="password", enabled=True)
    assert res.count == 52373976
    assert seen["ttl"] == 0 and seen["allow_redirects"] is False and seen["source"] == "pwnedpasswords.range"
    assert seen["url"].endswith("/range/5BAA6") and seen["headers"] == HEADERS


# ---------------------------------------------------------------------- rule 5: could not verify, never 0


def test_failures_are_could_not_verify_never_zero():
    cases = [
        Recorder(status=400, body=env("error_400_not_hex.json")["body"].encode()),
        Recorder(status=400, body=env("error_400_bad_format.json")["body"].encode()),
        Recorder(status=429, body=b"slow down"),
        Recorder(status=503, body=b"unavailable"),
        Recorder(status=403, body=b"<html><title>Just a moment...</title>cf-chl</html>"),
        Recorder(status=200, body=b"<html>maintenance</html>"),
        Recorder(status=200, body=raw("malformed_truncated.txt")),
        Recorder(status=200, body=b""),
        Recorder(error=TimeoutError("timed out")),
    ]
    for fetch in cases:
        res = lookup(SECRET, fetch, finding_kind="password", enabled=True)
        assert res.count is None and res.note is None and "could not verify" in res.reason
        assert annotate({}, res) == {"pwned_check": res.reason}
    assert range_problem(200, raw("range_padded_ok.txt"), {}) is None


# ---------------------------------------------------------------------- cond 4-5: the note on the masked finding


def test_annotation_on_the_already_masked_finding():
    res = lookup(SECRET, Recorder(body=raw("range_plain_ok.txt")), finding_kind="password", enabled=True)
    data = annotate({"type": "password", "preview": "pa…rd", "sha256": "ab" * 32}, res)
    assert data["pwned_count"] == 52373976 and data["pwned_note"] == "appears 52373976 times in public breach corpora"
    assert "CC BY 4.0" in data["pwned_attribution"] and "haveibeenpwned.com" in data["pwned_attribution"]
    assert "never validates the credential" in data["pwned_note_scope"]
    headers = env("range_padded_headers.json")["headers"]
    assert headers["cache-control"] == "no-store"  # the provider marks padded answers no-store
