"""Read-only inspector for downloaded pages (run with python3 -I).

Usage: python3 -I inspect_page.py <body_file> [grep_regex ...]

Prints: size, a JSON hint, <title>, og:/twitter: meta tags, robots meta, a few marker hits
(captcha/challenge/cloudflare words) and, for each extra regex, up to 5 short context snippets.
Control characters are stripped; nothing in the file is executed.
"""
import html
import json
import re
import sys

CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
MARKERS = [r"just a moment", r"challenge-platform", r"cf-chl", r"captcha", r"turnstile", r"access denied",
           r"attention required", r"cf-mitigated", r"blocked", r"rate limit", r"too many requests",
           r"enable javascript", r"<noscript", r"anomaly", r"verify you are human", r"ddos-guard"]


def clean(s, n=200):
    s = CTRL.sub("?", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[:n] + "..."


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = fh.read()
    text = data.decode("utf-8", "replace")
    print("bytes:", len(data))
    try:
        obj = json.loads(text)
        print("JSON top-level:", type(obj).__name__, (list(obj.keys())[:30] if isinstance(obj, dict) else len(obj)))
    except ValueError:
        print("not JSON")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    print("title:", clean(html.unescape(m.group(1))) if m else None)
    for mm in re.finditer(r"<meta\s+[^>]*?(?:property|name)=[\"']((?:og|twitter|description|robots)[^\"']*)[\"'][^>]*>", text, re.I):
        tag = mm.group(0)
        c = re.search(r"content=[\"']([^\"']*)[\"']", tag, re.I)
        print("meta", mm.group(1), "=", clean(html.unescape(c.group(1)) if c else "", 160))
    low = text.lower()
    for mk in MARKERS:
        n = len(re.findall(mk, low))
        if n:
            print("marker %r x%d" % (mk, n))
    for rx in sys.argv[2:]:
        hits = list(re.finditer(rx, text, re.I))
        print("regex %r: %d hits" % (rx, len(hits)))
        for h in hits[:5]:
            a, b = max(0, h.start() - 80), min(len(text), h.end() + 80)
            print("   ..", clean(text[a:b], 240))


if __name__ == "__main__":
    main()
