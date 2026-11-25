"""Report writers. All work from the case dict (``CaseResult.to_dict()`` or a stored case)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FORMATS = ("html", "md", "json", "stix")


def write_reports(case: dict[str, Any], formats: list[str] | tuple[str, ...], out_dir: str | Path) -> dict[str, str]:
    """Write the requested formats into ``out_dir``. Returns {format: path}."""
    from v3lum.report import html as html_r
    from v3lum.report import markdown as md_r
    from v3lum.report import stix as stix_r

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = f"v3lum-{case['case_id']}"
    written: dict[str, str] = {}
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "json":
            p = out / f"{base}.json"
            p.write_text(json.dumps(case, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        elif fmt in ("md", "markdown"):
            p = out / f"{base}.md"
            p.write_text(md_r.render(case), encoding="utf-8")
        elif fmt == "html":
            p = out / f"{base}.html"
            p.write_text(html_r.render(case), encoding="utf-8")
        elif fmt == "stix":
            p = out / f"{base}.stix.json"
            p.write_text(json.dumps(stix_r.bundle(case), ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            raise ValueError(f"unknown report format {fmt!r} (choose from {', '.join(FORMATS)})")
        written[fmt] = str(p)
    return written
