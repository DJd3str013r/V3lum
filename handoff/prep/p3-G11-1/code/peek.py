"""Safe viewer for untrusted downloaded samples (run with: python3 -I peek.py FILE [MAXCHARS] [OFFSET]).

Prints JSON pretty-printed (or text) with every non-printable / control character escaped,
so terminal escape sequences inside downloaded data never reach the terminal. Never executes
or imports anything from the data directory.
"""
import json
import sys


def _safe(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\n\t":
            out.append(ch)
        elif o < 0x20 or 0x7F <= o < 0xA0 or o in (0x2028, 0x2029, 0x200E, 0x200F, 0x202A,
                                                    0x202B, 0x202C, 0x202D, 0x202E):
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def main(argv):
    path = argv[1]
    limit = int(argv[2]) if len(argv) > 2 else 6000
    offset = int(argv[3]) if len(argv) > 3 else 0
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8", errors="replace")
    try:
        obj = json.loads(text)
        shown = json.dumps(obj, indent=1, ensure_ascii=False)
        kind = "json"
    except ValueError as exc:
        shown = text
        kind = "text (not JSON: %s)" % str(exc)[:80]
    print("## %s  bytes=%d  kind=%s" % (path.rsplit("/", 1)[-1], len(raw), kind))
    print(_safe(shown[offset:offset + limit]))
    if len(shown) > offset + limit:
        print("... [truncated, %d more chars]" % (len(shown) - offset - limit))


if __name__ == "__main__":
    main(sys.argv)
