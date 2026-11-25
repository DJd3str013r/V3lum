"""Test doubles: an offline HTTP client with canned routes, and runtime/context factories.

Usage in module tests::

    http = FakeHttp()
    http.add("GET", "https://internetdb.shodan.io/1.2.3.4", json={"ports": [22]})
    ctx = make_ctx(SomeModule, http)
    res = SomeModule().run(Entity.make("ipv4", "1.2.3.4"), ctx)

Routes match on method + URL. A route URL ending with ``*`` is a prefix match; a route may be a
regex (``re.compile``). Unmatched requests raise ``AssertionError`` listing the known routes, so
tests never touch the network by accident.
"""

from __future__ import annotations

import json as _json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.http import NetworkError, Response

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Any:
    """Load tests/fixtures/<name> (JSON parsed when the name ends with .json)."""
    path = FIXTURES / name
    text = path.read_text(encoding="utf-8")
    return _json.loads(text) if name.endswith(".json") else text


class FakeHttp:
    def __init__(self) -> None:
        self.routes: list[tuple[str, Any, dict[str, Any]]] = []
        self.calls: list[dict[str, Any]] = []

    def add(
        self,
        method: str,
        url: str | re.Pattern[str],
        *,
        status: int = 200,
        json: Any = None,
        text: str | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        error: Exception | None = None,
        final_url: str | None = None,
    ) -> FakeHttp:
        if json is not None:
            content = _json.dumps(json).encode()
            hdrs = {"content-type": "application/json"}
        elif text is not None:
            content = text.encode()
            hdrs = {"content-type": "text/html; charset=utf-8"}
        else:
            content = body or b""
            hdrs = {}
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        self.routes.append((method.upper(), url, {"status": status, "content": content, "headers": hdrs, "error": error, "final_url": final_url}))
        return self

    def _match(self, method: str, url: str) -> dict[str, Any] | None:
        for m, pattern, spec in self.routes:
            if m != method:
                continue
            if isinstance(pattern, re.Pattern):
                if pattern.search(url):
                    return spec
            elif pattern.endswith("*"):
                if url.startswith(pattern[:-1]):
                    return spec
            elif pattern == url:
                return spec
        return None

    def request(self, method: str, url: str, *, params: dict[str, Any] | None = None, **kw: Any) -> Response:
        method = method.upper()
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            url = url + ("&" if "?" in url else "?") + urlencode(clean, doseq=True)
        self.calls.append({"method": method, "url": url, **kw})
        spec = self._match(method, url)
        if spec is None:
            known = "\n  ".join(f"{m} {p}" for m, p, _ in self.routes) or "(none)"
            raise AssertionError(f"unexpected HTTP request: {method} {url}\nknown routes:\n  {known}")
        if spec["error"] is not None:
            raise spec["error"]
        return Response(status=spec["status"], url=spec["final_url"] or url, headers=dict(spec["headers"]), content=spec["content"])

    def urls(self) -> list[str]:
        return [c["url"] for c in self.calls]


class DeadHttp(FakeHttp):
    """Every request fails like a dead network."""

    def request(self, method: str, url: str, **kw: Any) -> Response:
        raise NetworkError(f"ConnectionError contacting {url}")


def doh(name: str, rtype: str, records: list[str], *, status: int = 0, ad: bool = False) -> dict[str, Any]:
    """Build a Google DoH JSON answer."""
    from v3lum.core.dns import RTYPES

    return {
        "Status": status,
        "AD": ad,
        "Answer": [{"name": name + ".", "type": RTYPES[rtype], "TTL": 300, "data": r} for r in records],
    }


def add_dns(http: FakeHttp, name: str, rtype: str, records: list[str], *, status: int = 0, ad: bool = False) -> None:
    http.add("GET", f"https://dns.google/resolve?name={name}&type={rtype}", json=doh(name, rtype, records, status=status, ad=ad))


def add_nxdomain_everything(http: FakeHttp) -> None:
    """Any DNS query not answered by a more specific route returns NXDOMAIN."""
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?"), json={"Status": 3, "Answer": []})


def make_runtime(http: Any = None, *, keys: dict[str, str] | None = None, settings: dict[str, Any] | None = None) -> Runtime:
    cfg = Config()
    cfg.file_keys.update(keys or {})
    cfg.settings.update(settings or {})
    return Runtime(cfg, http_client=http or FakeHttp())


def make_ctx(module_cls: Any, http: Any = None, *, keys: dict[str, str] | None = None, options: ScanOptions | None = None, settings: dict[str, Any] | None = None) -> Any:
    rt = make_runtime(http, keys=keys, settings=settings)
    return rt.context(module_cls, options or ScanOptions())
