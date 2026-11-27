"""Print each recorded request of a research sample file (label, url, status, headers, body excerpt). Run with python3 -I."""
import json
import sys


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 1500
    with open(path, "rb") as fh:
        obj = json.loads(fh.read().decode("utf-8", "replace"))
    print("NOTES:", obj.get("notes"))
    for r in obj.get("requests", []):
        print("=" * 80)
        for k in ("label", "url", "http_status", "status_chain", "headers", "elapsed_s", "curl_error", "note", "body_kind", "bytes_read"):
            print(f"{k}: {r.get(k)!r}")
        body = r.get("body")
        if not isinstance(body, str):
            body = json.dumps(body, ensure_ascii=False)
        print("body:", body[:limit])


if __name__ == "__main__":
    main()
