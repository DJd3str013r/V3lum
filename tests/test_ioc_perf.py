"""P172 cond 5: extraction performance (marked slow). 1 MB of dots/hyphens < 2 s; 1 MB of mixed
text < 2 s; 10 MB < 10 s. The first call loads the bundled lists (noise, aliases) once. Budgets are
measured in CPU time of this process (extraction is single-threaded), so a loaded CI machine running
other suites in parallel does not turn a scheduling delay into a failure."""

from __future__ import annotations

import random
import time

import pytest

from v3lum.core import ioc

pytestmark = pytest.mark.slow

_WORDS = ["the", "quick", "analyst", "observed", "beacon", "traffic", "from", "the", "loader", "to", "its", "panel", "and", "a", "second", "stage", "over", "https", "while", "persistence", "used", "a", "scheduled", "task", "named", "updater", "and", "lateral", "movement", "used", "remote", "services"]


def mixed_text(size: int) -> str:
    rnd = random.Random(1729)
    lines = []
    for i in range(4000):
        extra = rnd.choice([
            f" contacted 45.{i % 200}.{i % 250}.{(i * 7) % 250} on port 443.",
            f" domain evil-{i % 300}[.]example.net was registered.",
            f" hxxps://cdn{i % 120}.bad-host.example.org/gate.php?id={i % 400}",
            f" sha256 {i * 7919 + 1234567:064x}",
            f" see CVE-2023-{1000 + i % 900} and T1059.001.",
            " nothing else here.", " nothing else here.", " nothing else here.",
        ])
        lines.append(" ".join(rnd.choice(_WORDS) for _ in range(14)) + "." + extra)
    base = "\n".join(lines)
    return (base * (size // len(base) + 1))[:size]


@pytest.fixture(scope="module", autouse=True)
def warm_up():
    ioc.extract("warm up 8.8.8.8 example.com https://example.com/x Emotet malware CVE-2021-44228")


def timed(text: str) -> tuple[float, ioc.ExtractionResult]:
    start = time.process_time()
    result = ioc.extract(text)
    return time.process_time() - start, result


@pytest.mark.parametrize("text", ["." * 1_000_000, "-" * 1_000_000, ".-" * 500_000, "a." * 500_000, "1." * 500_000,
                                  ":" * 1_000_000, "a@" * 500_000, "[.]" * 333_334, "QUJD" * 250_000],
                         ids=["dots", "hyphens", "dot-hyphen", "label-dots", "digit-dots", "colons", "at-signs", "defang", "base64ish"])
def test_one_megabyte_of_pathological_input_under_two_seconds(text):
    took, result = timed(text)
    assert took < 2.0, f"{took:.2f}s"
    assert result.entities == []


@pytest.mark.parametrize("text", [("+1234567890123456789012345678901 " * 32_000)[:1_000_000], ("+1 2 3 4 5 6 7 8 9 0 1 2 " * 40_000)[:1_000_000],
                                  ("+1(2)(3)(4)(5)(6)(7)(8)(9) " * 37_000)[:1_000_000], ("1234-5678 " * 100_000)[:1_000_000]],
                         ids=["plus-digit-runs", "plus-spaced-digits", "plus-parens", "digit-groups"])
def test_one_megabyte_of_phone_shaped_input_under_two_seconds(text):
    """The phone stage (one flat character class per '+', separators checked in code) stays linear:
    the earlier nested-group regex took ~10 s of CPU on 1 MB of '+' and long digit runs."""
    took, _result = timed(text)
    assert took < 2.0, f"{took:.2f}s"


def test_one_megabyte_of_url_dense_text_under_two_seconds():
    """Percent- and base64-encoded URL components are checked for hidden secrets/cards/CPFs; the
    cheap pre-filter keeps a URL-only megabyte within budget."""
    urls = (f"https://host{i % 500}.example.net/p/AbCdEfGhIjKlMnOpQrStUv{i}/x%2Fy%20z?q=hello%20world%20{i}"
            f"&r=https%3A%2F%2Finner{i % 50}.example.org%2Fa&t=QmFzZTY0VGV4dEZvclRlc3Q{i}" for i in range(9000))
    took, result = timed(" ".join(urls)[:1_000_000])
    assert took < 2.0, f"{took:.2f}s"
    assert len(result.entities) > 1000


def test_one_megabyte_of_mixed_text_under_two_seconds():
    took, result = timed(mixed_text(1_000_000))
    assert took < 2.0, f"{took:.2f}s"
    assert len(result.entities) > 1000


def test_ten_megabytes_under_ten_seconds():
    took, result = timed(mixed_text(10_000_000))
    assert took < 10.0, f"{took:.2f}s"
    assert len(result.entities) > 1000
