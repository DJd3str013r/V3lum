"""Inspect an untrusted JSON sample: print structure (keys, types, short values). Run with python3 -I."""
import json
import sys


def show(obj, depth=0, maxdepth=4, maxlist=3, key=""):
    pad = "  " * depth
    if isinstance(obj, dict):
        print(f"{pad}{key}{{dict {len(obj)} keys}}")
        if depth < maxdepth:
            for k, v in list(obj.items())[:60]:
                show(v, depth + 1, maxdepth, maxlist, key=f"{k!r}: ")
    elif isinstance(obj, list):
        print(f"{pad}{key}[list len={len(obj)}]")
        if depth < maxdepth:
            for v in obj[:maxlist]:
                show(v, depth + 1, maxdepth, maxlist)
    else:
        s = repr(obj)
        if len(s) > 160:
            s = s[:160] + "..."
        print(f"{pad}{key}{s}")


def main():
    path = sys.argv[1]
    maxdepth = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        obj = json.loads(data.decode("utf-8", "replace"))
    except ValueError as exc:
        print("not json:", exc)
        print(data[:2000].decode("utf-8", "replace"))
        return
    show(obj, maxdepth=maxdepth)


if __name__ == "__main__":
    main()
