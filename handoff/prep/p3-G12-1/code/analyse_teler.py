"""Analyse the teler bad-crawlers list (untrusted data; run with python3 -I).

usage: python3 -I analyse_teler.py <bad-crawlers.txt>
Prints line counts, patterns that do not compile in Python re, static ReDoS flags,
names of scanner tools present, and timing of a combined case-insensitive alternation
against adversarial 1 KB strings (each pattern is also timed individually).
"""
import re
import sys
import time

TOOLS = ["sqlmap", "nuclei", "masscan", "nikto", "nmap", "zgrab", "wpscan", "dirbuster", "gobuster",
         "ffuf", "hydra", "acunetix", "nessus", "openvas", "burp", "zaproxy", "zap", "w3af", "wfuzz",
         "commix", "xsstrike", "jaeles", "httpx", "katana", "feroxbuster", "dirb", "arachni", "netsparker",
         "qualys", "censys", "shodan", "expanse", "palo alto", "leakix", "l9", "netcraft", "internetmeasurement",
         "shadowserver", "project sonar", "rapid7", "binaryedge", "onyphe", "zmeu", "jndi", "python-requests",
         "curl", "wget", "go-http-client", "okhttp", "axios", "java", "libwww", "anthropic", "gptbot",
         "claudebot", "googlebot", "bingbot", "ahrefs", "semrush"]


def main():
    text = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
    lines = text.split("\n")
    pats = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    print("lines", len(lines), "patterns", len(pats),
          "leading_space", sum(1 for p in pats if p != p.lstrip()),
          "trailing_space", sum(1 for p in pats if p != p.rstrip()))
    bad = []
    for p in pats:
        try:
            re.compile(p, re.I)
        except re.error as exc:
            bad.append((p, str(exc)))
    print("python_re_compile_errors", len(bad))
    for p, e in bad[:20]:
        print("  BAD", repr(p), e)
    nested = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
    flagged = [p for p in pats if nested.search(p)]
    print("static_nested_quantifier_flags", len(flagged), flagged[:10])
    for t in TOOLS:
        hits = [p for p in pats if t in p.lower()]
        if hits:
            print("tool", t, "->", hits[:6])
    combined = re.compile("|".join("(?:%s)" % p for p in pats if (p, None) not in bad), re.I)
    adversarial = ["a" * 1024, "A/" * 512, ("Mozilla/5.0 " * 90)[:1024], "-" * 1024, "1" * 1024,
                   ("x" * 50 + " ") * 20]
    for s in adversarial:
        t0 = time.perf_counter()
        combined.search(s)
        dt = (time.perf_counter() - t0) * 1000
        print("combined %-24r %.2f ms" % (s[:20], dt))
    worst = []
    for p in pats:
        try:
            rx = re.compile(p, re.I)
        except re.error:
            continue
        t0 = time.perf_counter()
        for s in adversarial:
            rx.search(s)
        worst.append(((time.perf_counter() - t0) * 1000, p))
    worst.sort(reverse=True)
    print("slowest individual patterns (ms over all adversarial strings):")
    for dt, p in worst[:8]:
        print("  %.3f %r" % (dt, p))


if __name__ == "__main__":
    main()
