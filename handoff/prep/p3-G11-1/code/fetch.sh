#!/usr/bin/env bash
# Live-check helper: fetch.sh NAME URL [extra curl args...]
# Saves the body to raw/NAME.body and response headers to raw/NAME.headers, and appends one line
# (UTC time, name, http code, seconds, bytes, content-type, rc, url) to raw/live_log.tsv.
# TLS verification stays on (CA bundle from the environment); proxies are never changed.
# Cookies are never stored (Set-Cookie lines are removed from the saved headers).
set -u
NAME="$1"; URL="$2"; shift 2
RAW="$(cd "$(dirname "$0")/.." && pwd)/raw"
mkdir -p "$RAW"
OUT=$(curl -sS --max-time 20 -o "$RAW/$NAME.body" -D "$RAW/$NAME.headers" \
  -w '%{http_code}\t%{time_total}\t%{size_download}\t%{content_type}' "$@" "$URL" 2>"$RAW/$NAME.stderr")
RC=$?
printf '%s\t%s\t%s\trc=%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NAME" "$OUT" "$RC" "$URL" | tee -a "$RAW/live_log.tsv"
if [ -s "$RAW/$NAME.stderr" ]; then echo "stderr:"; head -c 600 "$RAW/$NAME.stderr"; echo; fi
if [ -f "$RAW/$NAME.headers" ]; then sed -i '/^[Ss]et-[Cc]ookie:/d' "$RAW/$NAME.headers"; fi
