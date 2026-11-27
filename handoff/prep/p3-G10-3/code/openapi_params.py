"""List paths and query parameters of an untrusted OpenAPI JSON document. Run with python3 -I."""
import json
import sys


def main():
    with open(sys.argv[1], "rb") as fh:
        spec = json.loads(fh.read().decode("utf-8", "replace"))
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            print(method.upper(), path, "-", str(op.get("summary"))[:80])
            for p in op.get("parameters") or []:
                sch = p.get("schema") or {}
                desc = str(p.get("description") or "")[:100]
                print(f"   {p.get('in')}:{p.get('name')} type={sch.get('type') or sch.get('anyOf')} default={sch.get('default')} max={sch.get('maximum')} {desc}")


if __name__ == "__main__":
    main()
