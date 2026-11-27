"""Read untrusted live bodies safely (prep tooling). Run with python3 -I.

python3 -I code/peek.py <body_file> [token ...] [--ctx N] [--grep REGEX] [--forms] [--links N]

Prints the size, the <title>, challenge hints, whether each token occurs (case-insensitive) with a short
context, optional regex hits, form actions and the first N hrefs. Control characters are replaced, so
nothing in the body can drive the terminal. Never executes or renders anything.
"""
import re
import sys

CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(s, n=300):
    s = CTRL.sub("?", s)
    s = re.sub(r"\s+", " ", s)
    return s[:n]


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    path, rest = argv[0], argv[1:]
    ctx, grep, forms, links = 120, None, False, 0
    tokens = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--ctx", "--grep", "--links"):
            val = rest[i + 1]
            if a == "--ctx":
                ctx = int(val)
            elif a == "--grep":
                grep = val
            else:
                links = int(val)
            i += 2
            continue
        if a == "--forms":
            forms = True
            i += 1
            continue
        tokens.append(a)
        i += 1
    raw = open(path, "rb").read()
    text = raw.decode("utf-8", "replace")
    print("bytes:", len(raw))
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    print("title:", clean(m.group(1)) if m else None)
    for hint in ("just a moment", "cf-chl", "challenge-platform", "captcha", "turnstile", "hcaptcha", "recaptcha",
                 "access denied", "attention required", "ddos-guard", "_incapsula", "akamai", "datadome",
                 "please enable javascript", "enable javascript", "sign in", "login", "entrar", "not found",
                 "404", "nao encontrad", "não encontrad", "no results", "nenhum resultado"):
        if hint in text.lower():
            print("hint:", hint)
    low = text.lower()
    for t in tokens:
        j = low.find(t.lower())
        print("token", repr(t), "found" if j >= 0 else "absent", ("@" + str(j)) if j >= 0 else "")
        if j >= 0:
            print("   ...", clean(text[max(0, j - ctx): j + len(t) + ctx], 2 * ctx + len(t) + 10))
    if grep:
        for k, mm in enumerate(re.finditer(grep, text)):
            if k >= 15:
                break
            print("grep:", clean(text[max(0, mm.start() - ctx): mm.end() + ctx], 2 * ctx + 200))
    if forms:
        for mm in re.finditer(r"(?is)<form\b[^>]*>", text):
            print("form:", clean(mm.group(0), 400))
        for mm in re.finditer(r"(?is)<input\b[^>]*>", text):
            print("input:", clean(mm.group(0), 300))
    if links:
        hrefs = re.findall(r'(?i)href="([^"]+)"', text)
        for h in hrefs[:links]:
            print("href:", clean(h, 200))


if __name__ == "__main__":
    main(sys.argv[1:])
