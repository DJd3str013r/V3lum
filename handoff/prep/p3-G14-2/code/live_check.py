"""Polite keyless live checker for batch p3-G14-2 (prep tooling only; not part of parsers.py).

Run: python3 -I code/live_check.py <out_dir> <plan.json>

plan.json: [{"label": str, "url": "https://...", "accept": "text/html" (optional), "max_bytes": int (optional)}]

Rules enforced here (task live-verification rules):
- https only, GET only, curl --max-time 20, curl's own User-Agent (no header spoofing), no cookie jar,
  TLS verification on (the preconfigured CA bundle through CURL_CA_BUNDLE), redirects NOT followed:
  a redirect target is requested only by a later plan entry, after review.
- >= 1.2 s between any two requests (one request at a time); at most 5 requests per host, counted across
  every run recorded in out_dir/_log.jsonl, so re-runs cannot exceed the cap.
- Set-Cookie headers are never stored; session ids and CSRF/viewstate values in bodies are masked.
- Bodies are untrusted data: stored as <label>.body, never executed, read only with python3 -I scripts.
Every request is appended to out_dir/_log.jsonl (status, timing, a header subset, curl errors).
"""
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

MIN_INTERVAL_S = 1.2
MAX_PER_HOST = 5
DEFAULT_MAX_BYTES = 3_000_000
KEEP_HEADERS = (
    "content-type", "content-length", "location", "server", "cache-control", "retry-after",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
    "ratelimit-reset", "ratelimit-policy", "x-rate-limit-limit", "x-rate-limit-remaining", "cf-cache-status",
    "cf-mitigated", "cf-ray-present", "x-vercel-cache", "x-vercel-mitigated", "set-cookie-present",
    "x-frame-options", "x-cache", "via", "age", "x-robots-tag", "content-security-policy-present",
    "x-amzn-waf-action", "x-datadome", "x-sucuri-id", "x-iinfo", "x-cdn", "strict-transport-security-present",
    "x-powered-by", "referrer-policy",
)
_SESSION_PATTERNS = (
    (re.compile(rb"(?i)(jsessionid|phpsessid|sessionid|session_id|sid)=[A-Za-z0-9._%-]{8,}"), rb"\1=REDACTED"),
    (re.compile(rb'(?i)(name="(?:csrf[A-Za-z0-9_-]*|_csrf[A-Za-z0-9_-]*|csrfmiddlewaretoken|authenticity_token|_token|'
                rb'__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION|__RequestVerificationToken)"[^>]*?value=")[^"]*'),
     rb"\1REDACTED"),
    (re.compile(rb'(?i)(<meta\s+name="csrf-token"\s+content=")[^"]*'), rb"\1REDACTED"),
    (re.compile(rb'(?i)("(?:csrfToken|csrf_token|xsrfToken)"\s*:\s*")[^"]*'), rb"\1REDACTED"),
)


def _parse_headers(path):
    try:
        raw = open(path, "rb").read().decode("iso-8859-1")
    except OSError:
        return [], {}
    blocks = [b for b in raw.replace("\r\n", "\n").split("\n\n") if b.strip()]
    statuses, last = [], {}
    for block in blocks:
        lines = block.split("\n")
        if not lines or not lines[0].startswith("HTTP/"):
            continue
        statuses.append(lines[0].strip())
        hdrs = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip().lower()
            if k == "set-cookie":
                hdrs["set-cookie-present"] = "yes"
                continue
            if k in ("content-security-policy", "strict-transport-security", "cf-ray"):
                hdrs[k + "-present"] = "yes"
                continue
            hdrs[k] = v.strip()[:300]
        last = hdrs
    return statuses, last


def _scrub(hdr_path, body_path):
    try:
        with open(hdr_path, "rb") as fh:
            lines = fh.read().split(b"\n")
        with open(hdr_path, "wb") as fh:
            fh.write(b"\n".join(ln for ln in lines if not ln.lower().startswith(b"set-cookie:")))
    except OSError:
        pass
    try:
        with open(body_path, "rb") as fh:
            body = fh.read()
        for pat, repl in _SESSION_PATTERNS:
            body = pat.sub(repl, body)
        with open(body_path, "wb") as fh:
            fh.write(body)
    except OSError:
        pass


def _host_counts(log_path):
    counts = {}
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                host = urlsplit(rec.get("url", "")).hostname or ""
                counts[host] = counts.get(host, 0) + 1
    except OSError:
        pass
    return counts


def run(out_dir, plan):
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "_log.jsonl")
    per_host = _host_counts(log_path)
    last_t = 0.0
    for item in plan:
        url, label = item["url"], item["label"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", label):
            raise SystemExit("bad label " + label)
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise SystemExit("https only: " + url)
        host = parts.hostname or ""
        if per_host.get(host, 0) >= MAX_PER_HOST:
            print("SKIP (per-host cap)", label)
            continue
        wait = MIN_INTERVAL_S - (time.monotonic() - last_t)
        if wait > 0:
            time.sleep(wait)
        body_path = os.path.join(out_dir, label + ".body")
        hdr_path = os.path.join(out_dir, label + ".headers")
        max_bytes = int(item.get("max_bytes", DEFAULT_MAX_BYTES))
        cmd = ["curl", "-sS", "--max-time", "20", "--proto", "=https", "--compressed", "--max-filesize",
               str(max_bytes), "-o", body_path, "-D", hdr_path,
               "-w", "%{http_code}\t%{time_total}\t%{size_download}\t%{url_effective}\t%{redirect_url}\t"
                     "%{time_starttransfer}"]
        if item.get("accept"):
            cmd += ["-H", "Accept: " + item["accept"]]
        cmd.append(url)
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        last_t = time.monotonic()
        per_host[host] = per_host.get(host, 0) + 1
        fields = (proc.stdout or "").split("\t")
        statuses, hdrs = _parse_headers(hdr_path)
        _scrub(hdr_path, body_path)
        size = os.path.getsize(body_path) if os.path.exists(body_path) else 0
        rec = {
            "label": label, "url": url, "method": "GET", "accept": item.get("accept"),
            "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
            "http_code": fields[0] if fields else "", "time_total_s": fields[1] if len(fields) > 1 else "",
            "ttfb_s": fields[5] if len(fields) > 5 else "", "size_download": fields[2] if len(fields) > 2 else "",
            "redirect_url": fields[4] if len(fields) > 4 else "", "status_lines": statuses,
            "headers": {k: v for k, v in hdrs.items() if k in KEEP_HEADERS}, "body_bytes_on_disk": size,
            "curl_exit": proc.returncode, "curl_stderr": (proc.stderr or "").strip()[-600:],
        }
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(label, rec["http_code"], rec["time_total_s"] + "s", size, "B", rec["redirect_url"],
              ("ERR " + rec["curl_stderr"]) if proc.returncode else "", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    with open(sys.argv[2], encoding="utf-8") as fh:
        run(sys.argv[1], json.load(fh))
