"""Polite live checker for batch p3-G14-1 (run with python3 -I).

Usage: python3 -I live_check.py <plan.json> <out_dir>

plan.json: [{"id": "...", "url": "https://...", "accept": "text/html"}]

Rules enforced here:
- curl with --max-time 20, curl's own User-Agent, no cookie jar, redirects NOT followed;
- at most 5 requests per host over every run (counted from <out_dir>/_log.jsonl);
- at least 1.5 s between requests;
- Set-Cookie and other session-like header values are dropped before the headers are written.
Bodies are written as untrusted bytes and never interpreted here.
"""
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

PER_HOST_CAP = 5
GAP_S = 1.5
DROP_HEADERS = re.compile(r"^(set-cookie|cookie|x-csrf[-\w]*|x-request-id|cf-ray|x-amz-cf-id|x-amzn-trace-id|report-to|nel)\s*:", re.I)
KEEP_HEADERS = ("content-type", "content-length", "server", "location", "cache-control", "retry-after",
                "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-policy",
                "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "cf-mitigated", "cf-cache-status",
                "x-cache", "x-frame-options", "content-security-policy", "age", "vary", "x-powered-by",
                "access-control-allow-origin", "x-robots-tag", "link")


def host_counts(log_path):
    counts = {}
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                h = rec.get("host")
                counts[h] = counts.get(h, 0) + 1
    return counts


def scrub_headers(raw):
    out = []
    for line in raw.splitlines():
        if DROP_HEADERS.match(line):
            name = line.split(":", 1)[0]
            out.append(name + ": <dropped>")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def selected(raw):
    sel = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k in KEEP_HEADERS:
            sel[k] = v.strip()[:300]
    return sel


def main():
    plan_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "_log.jsonl")
    with open(plan_path, encoding="utf-8") as fh:
        plan = json.load(fh)
    counts = host_counts(log_path)
    first = True
    for item in plan:
        url = item["url"]
        parts = urlsplit(url)
        if parts.scheme != "https":
            print("skip (not https):", item["id"])
            continue
        host = parts.hostname
        if counts.get(host, 0) >= PER_HOST_CAP:
            print("skip (host cap reached):", item["id"], host)
            continue
        if not first:
            time.sleep(GAP_S)
        first = False
        body_path = os.path.join(out_dir, item["id"] + ".body")
        hdr_path = os.path.join(out_dir, item["id"] + ".headers.tmp")
        cmd = ["curl", "-sS", "--max-time", "20", "-o", body_path, "-D", hdr_path,
               "-w", "%{http_code}\t%{time_total}\t%{size_download}\t%{redirect_url}",
               "--proto", "=https", "--compressed"]
        if item.get("accept"):
            cmd += ["-H", "Accept: " + item["accept"]]
        cmd.append(url)
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - t0
        counts[host] = counts.get(host, 0) + 1
        raw_hdr = ""
        if os.path.exists(hdr_path):
            with open(hdr_path, encoding="latin-1") as fh:
                raw_hdr = fh.read()
            os.remove(hdr_path)
            with open(os.path.join(out_dir, item["id"] + ".headers"), "w", encoding="utf-8") as fh:
                fh.write(scrub_headers(raw_hdr))
        fields = (proc.stdout or "").split("\t")
        rec = {
            "id": item["id"],
            "url": url,
            "host": host,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": fields[0] if fields else None,
            "time_total": fields[1] if len(fields) > 1 else None,
            "bytes": fields[2] if len(fields) > 2 else None,
            "redirect_url": fields[3] if len(fields) > 3 else None,
            "wall_s": round(elapsed, 2),
            "curl_rc": proc.returncode,
            "curl_err": (proc.stderr or "").strip()[:300],
            "headers": selected(raw_hdr),
        }
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(json.dumps({k: rec[k] for k in ("id", "status", "time_total", "bytes", "redirect_url", "curl_rc")}))


if __name__ == "__main__":
    main()
