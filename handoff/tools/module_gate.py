"""Merge gate for finished module batches (MODULE_GUIDE section 0 + team rules).

Usage: python3 -I module_gate.py <scratchpad> <repo> <batch> [<batch> ...]

For each batch, reads impl/modules/<batch>.json (the manifest) and checks:
  files      every listed file exists, lies in a path module batches may create, and no seeded/core
             provider fragment is edited (only <id>__<batch>.json extensions); tracked files the
             batch modified are listed for review
  tests      the batch's offline tests pass
  contract   tests/test_registry_contract.py::test_module_contract[<module>] for every module, plus
             the global contract tests (a global failure counts only when it names the batch)
  lint       P327 lint (v3lum.core.lint) on the batch's code and data files: no blocking issue
  ruff       ruff check on the batch's Python files
  secrets    no distinctive secret (sanitize.find_secrets) in any batch file
  review     non-reserved e-mail addresses, checksum-valid CPFs and phone-like numbers in fixtures
             (reported for a human/agent look, not failing)
Writes impl/modules/gates/<batch>.json and prints one verdict line per batch.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys

S, REPO, BATCHES = sys.argv[1], sys.argv[2], sys.argv[3:]
PY = os.path.join(REPO, ".venv", "bin", "python")
RUFF = os.path.join(REPO, ".venv", "bin", "ruff")
MAN = os.path.join(S, "impl", "modules")
OUT = os.path.join(MAN, "gates")
os.makedirs(OUT, exist_ok=True)
owners = json.load(open(os.path.join(S, "impl", "providers_seed", "owners.json")))
OWNED_PROVIDER_IDS = set(owners.get("providers", {}))

ALLOWED = [
    "v3lum/modules/*", "tests/modules/*", "tests/fixtures/*", "tests/live/*", "v3lum/data/*",
    "v3lum/correlations/*", "docs/backlog/*",
]
CORE_DATA = {  # data files that belong to the core, never to a batch
    "v3lum/data/providers/README.md", "v3lum/data/vocab/README.md", "v3lum/data/README.md",
}
RESERVED_MAIL = re.compile(
    r"@(?:[a-z0-9-]+\.)*(?:example(?:\.com|\.org|\.net)?|test|invalid|localhost|local|example\.com\.br)$", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
CPF = re.compile(r"(?<!\d)(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?!\d)")
PHONE = re.compile(r"(?:\+55[\s.-]?\(?[1-9]{2}\)?[\s.-]?9?\d{4}[\s.-]?\d{4})|(?:\([1-9]{2}\)\s?9?\d{4}-\d{4})")
FAKE_SECRET_HINTS = ("EXAMPLE", "example", "xxxx", "XXXX", "dummy", "DUMMY", "fake", "FAKE", "test", "TEST", "0000000000")


def cpf_valid(raw: str) -> bool:
    d = [int(c) for c in raw if c.isdigit()]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        s = sum(d[i] * (n + 1 - i) for i in range(n))
        r = (s * 10) % 11 % 10
        if r != d[n]:
            return False
    return True


def run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, (p.stdout + p.stderr)


def tail(text: str, n: int = 25) -> str:
    return "\n".join(text.strip().splitlines()[-n:])


def git_status(paths: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    if not paths:
        return out
    code, text = run(["git", "status", "--porcelain", "--untracked-files=all", "--", *paths])
    for line in text.splitlines():
        if len(line) > 3:
            out[line[3:].strip()] = line[:2]
    return out


LINT_SNIPPET = r"""
import json, sys
from v3lum.core import lint
issues = []
for path in sys.argv[1:]:
    try:
        if path.endswith('.py'):
            prof = 'code' if path.startswith('v3lum/correlations/') else 'module'
            got = lint.lint_module_source(path, profile=prof)
        elif path.endswith('.json') and path.startswith('v3lum/data/'):
            got = lint.lint_data_file(path)
        else:
            continue
    except Exception as exc:  # a crash in the lint is a gate failure too
        issues.append({'path': path, 'line': 0, 'rule_id': 'CRASH', 'message': repr(exc), 'allowed': False})
        continue
    for i in lint.blocking(got):
        issues.append(i.to_dict() if hasattr(i, 'to_dict') else {'path': path, 'message': str(i)})
print(json.dumps(issues))
"""

SECRET_SNIPPET = r"""
import json, sys
from v3lum.core.sanitize import find_secrets
out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        continue
    for h in find_secrets(text, distinctive_only=True):
        v = h.value
        out.append({'path': path, 'kind': h.kind, 'preview': (v[:4] + '...' + v[-4:]) if len(v) > 8 else '***', 'raw_len': len(v), 'sample_hint': v})
print(json.dumps(out))
"""


def gate(batch: str) -> dict:
    mpath = os.path.join(MAN, f"{batch}.json")
    res: dict = {"batch": batch, "verdict": "fail", "problems": [], "review": []}
    if not os.path.exists(mpath):
        res["problems"].append("manifest missing")
        return res
    man = json.load(open(mpath))
    files = [f.strip().lstrip("./") for f in man.get("files", []) if f and f.strip()]
    files = [os.path.relpath(f, REPO) if os.path.isabs(f) else f for f in files]
    modules = [m.get("name") for m in man.get("modules", []) if m.get("name")]
    res["modules"] = modules
    res["files"] = files
    # -- files
    missing = [f for f in files if not os.path.exists(os.path.join(REPO, f))]
    outside = [f for f in files if not any(fnmatch.fnmatch(f, pat) for pat in ALLOWED) or f in CORE_DATA]
    prov_bad = []
    for f in files:
        if f.startswith("v3lum/data/providers/") and f.endswith(".json"):
            stem = os.path.basename(f)[:-5]
            if "__" not in stem and stem in OWNED_PROVIDER_IDS:
                prov_bad.append(f)
    status = git_status(files)
    modified_tracked = sorted(f for f, st in status.items() if st.strip() and st != "??" and "M" in st)
    not_changed = sorted(f for f in files if f not in status and not os.path.isdir(os.path.join(REPO, f)))
    res.update(missing=missing, outside_allowed=outside, provider_violations=prov_bad,
               modified_tracked=modified_tracked, listed_but_unchanged=not_changed)
    if missing:
        res["problems"].append(f"{len(missing)} listed files missing")
    if outside:
        res["problems"].append(f"files outside batch paths: {outside}")
    if prov_bad:
        res["problems"].append(f"edits shared/core provider fragments: {prov_bad}")
    if modified_tracked:
        res["review"].append(f"modifies tracked files (must be upgrades listed in the spec): {modified_tracked}")
    # untracked files carrying the batch's module names but missing from the list
    code, text = run(["git", "status", "--porcelain", "--untracked-files=all"])
    unlisted = []
    for line in text.splitlines():
        p = line[3:].strip()
        if p in files:
            continue
        base = os.path.basename(p)
        for m in modules:
            if m and (f"/{m}/" in f"/{p}" or base.startswith(f"{m}.") or base == f"test_{m}.py"
                      or base.startswith(f"{m}__") or f"__{batch}." in base):
                unlisted.append(p)
                break
    res["unlisted_candidates"] = sorted(set(unlisted))
    if unlisted:
        res["review"].append(f"files that look like the batch's but are not in the manifest: {sorted(set(unlisted))[:20]}")
    # -- tests
    tests = [f for f in files if f.startswith("tests/") and f.endswith(".py") and "/live/" not in f
             and os.path.basename(f).startswith("test_") and os.path.exists(os.path.join(REPO, f))]
    if tests:
        code, text = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests])
        res["tests"] = {"exit": code, "tail": tail(text, 15)}
        if code != 0:
            res["problems"].append("batch tests fail")
    else:
        res["tests"] = {"exit": None, "tail": "no test files listed"}
        res["problems"].append("no offline test files listed")
    # -- contract (per module)
    if modules:
        ids = [f"tests/test_registry_contract.py::test_module_contract[{m}]" for m in modules]
        code, text = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", *ids])
        res["contract"] = {"exit": code, "tail": tail(text, 20)}
        if code != 0:
            res["problems"].append("module contract fails")
    code, text = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_registry_contract.py",
                      "-k", "not test_module_contract and not test_checker"])
    mine = [ln for ln in text.splitlines() if any(m and m in ln for m in modules) or f"__{batch}" in ln
            or any(os.path.basename(f) in ln for f in files if f.startswith("v3lum/data/"))]
    res["global_contract"] = {"exit": code, "mentions_batch": mine[:15]}
    if code != 0 and mine:
        res["problems"].append("global contract tests fail on this batch")
    # -- lint
    lint_files = [f for f in files if os.path.exists(os.path.join(REPO, f)) and (
        (f.endswith(".py") and (f.startswith("v3lum/modules/") or f.startswith("v3lum/correlations/")))
        or (f.endswith(".json") and f.startswith("v3lum/data/")))]
    if lint_files:
        code, text = run([PY, "-c", LINT_SNIPPET, *lint_files])
        try:
            issues = json.loads(text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            issues = [{"message": "lint did not run: " + tail(text, 5)}]
        res["lint"] = issues
        if issues:
            res["problems"].append(f"{len(issues)} blocking lint issues")
    # -- ruff
    pyfiles = [f for f in files if f.endswith(".py") and os.path.exists(os.path.join(REPO, f))]
    if pyfiles:
        code, text = run([RUFF, "check", *pyfiles])
        res["ruff"] = {"exit": code, "tail": tail(text, 15)}
        if code != 0:
            res["problems"].append("ruff errors")
    # -- secrets
    scan = []
    for f in files:
        full = os.path.join(REPO, f)
        if os.path.isdir(full):
            for root, _dirs, names in os.walk(full):
                scan += [os.path.relpath(os.path.join(root, n), REPO) for n in names]
        elif os.path.exists(full):
            scan.append(f)
    scan = sorted(set(scan))
    if scan:
        code, text = run([PY, "-c", SECRET_SNIPPET, *scan])
        try:
            hits = json.loads(text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            hits = [{"path": "?", "kind": "scan-crash", "preview": tail(text, 3), "sample_hint": ""}]
        real = [h for h in hits if not any(x in h.get("sample_hint", "") for x in FAKE_SECRET_HINTS)]
        for h in hits:
            h.pop("sample_hint", None)
        res["secrets"] = hits
        if real:
            res["problems"].append(f"{len(real)} distinctive secret(s) in batch files")
    # -- review: personal data in fixtures / data
    mails, cpfs, phones = set(), set(), set()
    for f in scan:
        if not (f.startswith("tests/fixtures/") or f.startswith("v3lum/data/")):
            continue
        try:
            text = open(os.path.join(REPO, f), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in EMAIL.findall(text):
            if not RESERVED_MAIL.search(m):
                mails.add(m.lower())
        for c in CPF.findall(text):
            if cpf_valid(c):
                cpfs.add(c)
        for p in PHONE.findall(text):
            digits = re.sub(r"\D", "", p)
            if "555501" not in digits and len(digits) >= 10:
                phones.add(p.strip())
    if mails:
        res["review"].append(f"{len(mails)} non-reserved e-mail(s) in fixtures/data: {sorted(mails)[:12]}")
    if cpfs:
        res["review"].append(f"{len(cpfs)} checksum-valid CPF(s) in fixtures/data: {sorted(cpfs)[:6]}")
    if phones:
        res["review"].append(f"{len(phones)} phone-like number(s) in fixtures/data: {sorted(phones)[:6]}")
    res["verdict"] = "pass" if not res["problems"] else "fail"
    return res


for b in BATCHES:
    r = gate(b)
    json.dump(r, open(os.path.join(OUT, f"{b}.json"), "w"), indent=1)
    print(f"{b}: {r['verdict'].upper()} modules={len(r.get('modules', []))} files={len(r.get('files', []))} "
          f"problems={r['problems']} review={len(r['review'])}")
