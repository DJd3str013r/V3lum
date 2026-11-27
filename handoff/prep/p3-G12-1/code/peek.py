"""Safe viewer for untrusted downloaded data (run with python3 -I).

Prints a file with control characters escaped, optionally pretty-printing JSON
and truncating long output. Never executes or imports the data.
usage: python3 -I peek.py <path> [max_chars] [--json]
"""
import json
import sys


def esc(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\n\t":
            out.append(ch)
        elif o < 32 or 127 <= o < 160:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4000
    as_json = "--json" in sys.argv
    with open(path, "rb") as fh:
        data = fh.read()
    print("# bytes=%d" % len(data))
    text = data.decode("utf-8", "replace")
    if as_json:
        try:
            text = json.dumps(json.loads(text), indent=1, ensure_ascii=False)
        except ValueError as exc:
            print("# not json: %s" % exc)
    print(esc(text[:limit]))
    if len(text) > limit:
        print("# ... truncated (%d chars total)" % len(text))


if __name__ == "__main__":
    main()
