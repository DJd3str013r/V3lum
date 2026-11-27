"""Benchmark the teler list after stripping redundant leading star classes (python3 -I).

usage: python3 -I bench_teler.py <bad-crawlers.txt>
"""
import re
import sys
import time

LEAD = re.compile(r"^\[(?:[^\]\\]|\\.)+\]\*(?=.)")


def norm(p):
    # for re.search, an unanchored leading '[...]*' can match empty -> boolean result unchanged
    return LEAD.sub("", p, count=1)


def main():
    text = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
    pats = [ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")]
    changed = [(p, norm(p)) for p in pats if norm(p) != p]
    print("normalised", len(changed), changed)
    dups = len(pats) - len(set(pats))
    print("duplicates", dups)
    combo = re.compile("|".join("(?:%s)" % norm(p) for p in pats), re.I)
    raw = re.compile("|".join("(?:%s)" % p for p in pats), re.I)
    adversarial = ["a" * 1024, "A/" * 512, ("Mozilla/5.0 " * 90)[:1024], "-" * 1024, "1" * 1024]
    typical = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
        "sqlmap/1.8.11#stable (https://sqlmap.org)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
        "curl/8.5.0",
    ]
    for label, rx in (("normalised", combo), ("raw", raw)):
        for s in adversarial:
            t0 = time.perf_counter()
            rx.search(s)
            print("%-10s adversarial %-14r %.2f ms" % (label, s[:12], (time.perf_counter() - t0) * 1000))
        t0 = time.perf_counter()
        for _ in range(200):
            for s in typical:
                rx.search(s)
        print("%-10s typical avg %.3f ms/UA" % (label, (time.perf_counter() - t0) * 1000 / (200 * len(typical))))
    # equivalence check on a corpus of UAs: boolean result must be identical
    corpus = typical + adversarial + ["Feedreader 3.1", "HeadlessChrome/120", "MyCrawler", "x-bot-y", ""]
    print("equivalent", all(bool(combo.search(s)) == bool(raw.search(s)) for s in corpus))


if __name__ == "__main__":
    main()
