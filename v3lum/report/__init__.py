"""Report writers. All work from the case dict (``CaseResult.to_dict()`` or a stored case).

Report files hold case data: they are written owner-only (0600) through
:func:`v3lum.paths.secure_write_text` (``os.open(..., 0o600)`` + atomic replace, AR03/A10), whatever
the process umask and wherever ``out_dir`` is. A missing ``out_dir`` is created 0700. File names are
``v3lum-<case_id>.<ext>``: a case id that is not a plain name (path separators, '..') is refused, so
a damaged or crafted case can never write outside ``out_dir``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from v3lum import paths

FORMATS = ("html", "md", "json", "stix")

#: Case ids name files and directories: no separators, no '..' (the rule of paths.case_dir).
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def write_reports(case: dict[str, Any], formats: list[str] | tuple[str, ...], out_dir: str | Path) -> dict[str, str]:
    """Write the requested formats into ``out_dir`` (files 0600). Returns {format: path}."""
    from v3lum.report import html as html_r
    from v3lum.report import markdown as md_r
    from v3lum.report import stix as stix_r

    case_id = str(case.get("case_id") or "")
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(f"invalid case id {case_id[:80]!r}: reports are named after it (letters, digits, '-' and '_' only)")
    out = paths.private_dir(out_dir)
    base = f"v3lum-{case_id}"
    written: dict[str, str] = {}
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "json":
            p = out / f"{base}.json"
            text = json.dumps(case, ensure_ascii=False, indent=2, default=str)
        elif fmt in ("md", "markdown"):
            p = out / f"{base}.md"
            text = md_r.render(case)
        elif fmt == "html":
            p = out / f"{base}.html"
            text = html_r.render(case)
        elif fmt == "stix":
            p = out / f"{base}.stix.json"
            text = json.dumps(stix_r.bundle(case), ensure_ascii=False, indent=2)
        else:
            raise ValueError(f"unknown report format {fmt!r} (choose from {', '.join(FORMATS)})")
        paths.secure_write_text(p, text)
        written[fmt] = str(p)
    return written
