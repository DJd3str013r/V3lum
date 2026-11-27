"""Print selected text fields of FBI wanted items whose path matches a substring. Run with python3 -I."""
import json
import sys

FIELDS = ("uid", "title", "aliases", "description", "caution", "remarks", "details", "additional_information",
          "reward_text", "warning_message", "field_offices", "subjects", "status", "publication", "modified",
          "url", "path", "files", "nationality", "possible_countries", "legat_names", "suspects")


def main():
    with open(sys.argv[1], "rb") as fh:
        obj = json.loads(fh.read().decode("utf-8", "replace"))
    needle = sys.argv[2] if len(sys.argv) > 2 else "/wanted/cyber/"
    maxlen = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    for it in obj.get("items") or []:
        if needle not in str(it.get("path")):
            continue
        print("=" * 70)
        for f in FIELDS:
            v = it.get(f)
            s = json.dumps(v, ensure_ascii=False)
            print(f"{f}: {s[:maxlen]}")
        print("images:", len(it.get("images") or []), "keys:", sorted((it or {}).keys())[:5], "...")


if __name__ == "__main__":
    main()
