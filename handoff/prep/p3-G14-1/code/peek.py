"""Read-only viewer for untrusted downloaded files (run with python3 -I).

Usage: python3 -I peek.py <path> [max_chars]

JSON files: prints the structure (keys, types, short values).
Other files: prints a control-character-stripped head.
Never executes or imports anything from the inspected file.
"""
import json
import re
import sys

CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\x1b]")


def safe(s, n=120):
    s = CTRL.sub("?", str(s))
    return s if len(s) <= n else s[:n] + "...(%d chars)" % len(s)


def walk(obj, path="$", depth=0, max_depth=6, max_items=4):
    pad = "  " * depth
    if depth > max_depth:
        print(pad + path + ": ...")
        return
    if isinstance(obj, dict):
        print("%s%s: dict(%d keys)" % (pad, path, len(obj)))
        for i, (k, v) in enumerate(obj.items()):
            if i >= 60:
                print(pad + "  ... more keys")
                break
            walk(v, "%s.%s" % (path, safe(k, 60)), depth + 1, max_depth, max_items)
    elif isinstance(obj, list):
        print("%s%s: list(%d)" % (pad, path, len(obj)))
        for i, v in enumerate(obj[:max_items]):
            walk(v, "%s[%d]" % (path, i), depth + 1, max_depth, max_items)
    else:
        print("%s%s = %s (%s)" % (pad, path, safe(repr(obj)), type(obj).__name__))


def main():
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    with open(path, "rb") as fh:
        data = fh.read()
    print("bytes:", len(data))
    text = data.decode("utf-8", "replace")
    try:
        obj = json.loads(text)
    except ValueError:
        print("not JSON; head:")
        print(safe(text, n))
        return
    walk(obj)


if __name__ == "__main__":
    main()
