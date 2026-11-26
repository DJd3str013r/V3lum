"""docs/MODULE_GUIDE.md is the frozen module contract v2 (A16): keep it executable.

* every backticked dotted name starting with ``v3lum.`` (or ``tests.fakes.``) resolves - import the
  longest module prefix, then getattr the rest - except the names of the 'Arriving later' table;
* the ```python guide-example module runs in an isolated registry with ``test_provider()`` (the
  ```json guide-provider fragment) and its ```python guide-example-test functions pass;
* every ClassVar of the class-variable table exists on Module with the documented default, and the
  derived-attribute table lists exactly ``module.DERIVED``.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.fakes import test_provider
from v3lum.core import module as modreg
from v3lum.core.models import Opsec

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "MODULE_GUIDE.md"
TEXT = GUIDE.read_text(encoding="utf-8")
DOTTED = re.compile(r"`((?:v3lum|tests\.fakes)(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?:\(\))?`")
TABLE_ROW = re.compile(r"^\|\s*`([A-Za-z_][A-Za-z0-9_]*)`\s*\|\s*`([^`]*)`\s*\|", re.M)


def section(heading_prefix: str) -> str:
    """Text of the section whose heading starts with ``heading_prefix`` (up to the next heading of
    the same or a higher level)."""
    lines = TEXT.splitlines()
    level = len(heading_prefix) - len(heading_prefix.lstrip("#"))
    start = next((i for i, line in enumerate(lines) if line.startswith(heading_prefix)), None)
    assert start is not None, f"section {heading_prefix!r} missing from the guide"
    out: list[str] = []
    fenced = False
    for line in lines[start + 1 :]:
        if line.startswith("```"):
            fenced = not fenced
        marker = line.split(" ", 1)[0]
        if not fenced and marker and set(marker) == {"#"} and len(marker) <= level:
            break
        out.append(line)
    return "\n".join(out)


def code_block(tag: str) -> str:
    match = re.search(r"^```" + re.escape(tag) + r"\n(.*?)^```", TEXT, re.M | re.S)
    assert match, f"no ```{tag} block in the guide"
    return match.group(1)


def resolve(dotted: str) -> Any:
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            obj = getattr(obj, attr)
        return obj
    raise ImportError(dotted)


def arriving_later() -> set[str]:
    return set(DOTTED.findall(section("## 25. Arriving later")))


def test_guide_is_marked_frozen_v2():
    first = TEXT.splitlines()[0]
    assert re.fullmatch(r"# V3LUM module contract v2 - FROZEN \d{4}-\d{2}-\d{2}", first)
    header = TEXT[:1200]
    assert "A16" in header and "architect-approved migration" in header and "docs/contract_additions/" in header
    for number in range(0, 23):  # every section of the module-author contract
        assert re.search(rf"^## {number}\. ", TEXT, re.M), f"contract section {number} missing"
    assert "## 26. Additions after the freeze" in TEXT and "docs/contract_additions/" in section("## 26. Additions after the freeze")


def test_every_backticked_name_resolves():
    later = arriving_later()
    names = sorted(set(DOTTED.findall(TEXT)) - later)
    assert len(names) > 100  # the guide documents the contract by name
    missing = []
    for name in names:
        try:
            resolve(name)
        except (ImportError, AttributeError) as exc:
            missing.append(f"{name} ({type(exc).__name__}: {exc})")
    assert not missing, "guide names that do not resolve:\n" + "\n".join(missing)


def test_arriving_later_table_is_not_empty():
    later = arriving_later()
    assert {"v3lum.core.policy.decide", "v3lum.core.specs.compile_spec", "v3lum.core.ioc.extract"} <= later


def test_classvar_table_matches_module():
    rows = TABLE_ROW.findall(section("### 1.3 Class variables and defaults"))
    assert len(rows) >= 30
    namespace = {"__builtins__": {}, "Opsec": Opsec, "frozenset": frozenset, "set": set, "None": None, "True": True, "False": False}
    wrong = []
    for name, default in rows:
        if not hasattr(modreg.Module, name):
            wrong.append(f"{name}: not a Module attribute")
            continue
        expected = eval(default, namespace)  # noqa: S307 - literals of our own guide, no builtins
        actual = getattr(modreg.Module, name)
        both_sets = isinstance(actual, (set, frozenset)) and isinstance(expected, (set, frozenset))
        if actual != expected or (type(actual) is not type(expected) and not both_sets):
            wrong.append(f"{name}: guide says {default}, Module has {actual!r}")
    assert not wrong, "\n".join(wrong)
    listed = {name for name, _ in rows}
    assert set(modreg.MUST_DECLARE) | set(modreg.MUST_DECLARE_NETWORKED) <= listed


def test_derived_table_matches_register():
    names = set(re.findall(r"^\|\s*`([a-z_]+)`\s*\|", section("## 2. Derived attributes"), re.M))
    assert names == set(modreg.DERIVED)


def test_guide_example_runs_with_its_test(clean_registry):
    fragment = json.loads(code_block("json guide-provider"))
    module_code = code_block("python guide-example")
    test_code = "\n".join(line for line in code_block("python guide-example-test").splitlines() if not line.startswith("from v3lum.modules."))
    fields = {k: v for k, v in fragment.items() if k not in ("schema", "id")}
    with test_provider(fragment["id"], **fields):
        namespace: dict[str, Any] = {"__name__": "guide_example"}
        exec(compile(module_code, f"{GUIDE}:guide-example", "exec"), namespace)  # noqa: S102 - our own guide
        classes = [v for v in namespace.values() if isinstance(v, type) and issubclass(v, modreg.Module) and v is not modreg.Module]
        assert len(classes) == 1 and modreg.REGISTRY[classes[0].name] is classes[0]
        exec(compile(test_code, f"{GUIDE}:guide-example-test", "exec"), namespace)  # noqa: S102
        tests = sorted((n, f) for n, f in namespace.items() if n.startswith("test_") and callable(f))
        assert len(tests) >= 3
        for _name, fn in tests:
            fn()
        from tests.test_registry_contract import module_problems

        problems = [p for p in module_problems(classes[0]) if "tests/modules/" not in p and "tests/fixtures/" not in p]
        assert not problems, "\n".join(problems)


@pytest.mark.parametrize("module_name", ["dns_records", "email_basics", "shodan_internetdb", "ioc_extract"])
def test_reference_modules_are_documented(module_name):
    assert f"`{module_name}`" in section("## 24. Worked examples: the four reference modules")
