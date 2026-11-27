#!/usr/bin/env python3
"""Live-check runner for batch p3-G12-1 prep (run with python3 -I).

Usage: python3 -I live_check.py <plan.json> <out_dir> [id1,id2,...]

The plan is a JSON list of {id, url, method?: GET|HEAD, headers?: {}, max_bytes?, gap?}.
Each entry is fetched with curl (proxy and CA come from the environment; TLS verification is
never disabled; redirects are NOT followed), --max-time 20. Requests to the same host are
spaced by at least max(MIN_GAP, entry 'gap') seconds. Every request carries a generic client
User-Agent (no project, organisation, person or mailbox in it). Bodies go to <out>/<id>.body,
metadata to <out>/<id>.meta.json; Set-Cookie/Cookie/Authorization and key-like headers are
dropped before anything is written. No keys are used, no cookies kept, only GET/HEAD.
A per-host counter refuses more than MAX_PER_HOST requests per run (prep rule: ~5 per source).
"""
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

MIN_GAP = 2.0
MAX_PER_HOST = 5
UA = "fixture-capture/0.1 (low-volume research check)"
DROP_HEADERS = {"set-cookie", "cookie", "authorization", "x-api-key", "api-key",
                "x-access-token", "token"}


def parse_headers(raw):
    blocks, cur = [], []
    for line in raw.splitlines():
        line = line.rstrip("\r")
        if not line:
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)
    out = []
    for blk in blocks:
        hdrs = {}
        for h in blk[1:]:
            if ":" not in h:
                continue
            k, v = h.split(":", 1)
            k = k.strip().lower()
            if k in DROP_HEADERS:
                hdrs[k] = "<dropped>"
                continue
            hdrs[k] = v.strip()
        out.append({"status_line": blk[0], "headers": hdrs})
    return out


def load_counts(out):
    p = out / "_host_counts.json"
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def main():
    plan = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    only = set(sys.argv[3].split(",")) if len(sys.argv) > 3 else None
    counts = load_counts(out)
    last_by_host = {}
    failed = 0
    for req in plan:
        if only and req["id"] not in only:
            continue
        url = req["url"]
        host = urlsplit(url).hostname
        if counts.get(host, 0) >= MAX_PER_HOST:
            print(f"{req['id']:<32} REFUSED: {host} already has {counts[host]} requests")
            continue
        need = max(MIN_GAP, float(req.get("gap", 0)))
        gap = time.monotonic() - last_by_host.get(host, -1e9)
        if gap < need:
            time.sleep(need - gap)
        body = out / (req["id"] + ".body")
        hdr = out / (req["id"] + ".hdr.tmp")
        method = req.get("method", "GET")
        argv = ["curl", "-sS", "--max-time", "20",
                "--max-filesize", str(req.get("max_bytes", 5_000_000)),
                "-o", str(body), "-D", str(hdr), "-w", "%{json}", "-A", UA]
        if method == "HEAD":
            argv.append("--head")
        elif method != "GET":
            raise SystemExit("only GET/HEAD allowed in this prep")
        for k, v in (req.get("headers") or {}).items():
            if k.lower() in DROP_HEADERS or k.lower() == "user-agent":
                raise SystemExit("credential/UA headers are not allowed in this prep")
            argv += ["-H", f"{k}: {v}"]
        argv.append(url)
        started = time.time()
        proc = subprocess.run(argv, capture_output=True, text=True)
        last_by_host[host] = time.monotonic()
        counts[host] = counts.get(host, 0) + 1
        (out / "_host_counts.json").write_text(json.dumps(counts, indent=1, sort_keys=True))
        try:
            wo = json.loads(proc.stdout or "{}")
        except ValueError:
            wo = {}
        raw_h = hdr.read_text(errors="replace") if hdr.exists() else ""
        if hdr.exists():
            hdr.unlink()
        meta = {
            "id": req["id"],
            "url": url,
            "method": method,
            "user_agent": UA,
            "request_headers": req.get("headers") or {},
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "curl_exit": proc.returncode,
            "curl_stderr": proc.stderr.strip()[-600:],
            "http_code": wo.get("http_code"),
            "time_total_s": wo.get("time_total"),
            "time_starttransfer_s": wo.get("time_starttransfer"),
            "size_download": wo.get("size_download"),
            "content_type": wo.get("content_type"),
            "redirect_url": wo.get("redirect_url"),
            "responses": parse_headers(raw_h),
        }
        (out / (req["id"] + ".meta.json")).write_text(json.dumps(meta, indent=1, ensure_ascii=False))
        print(f"{req['id']:<32} exit={proc.returncode:<3} http={meta['http_code']} "
              f"t={meta['time_total_s']} bytes={meta['size_download']} "
              f"ct={meta['content_type']} {meta['curl_stderr'][:200]}")
        if proc.returncode != 0:
            failed += 1
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
