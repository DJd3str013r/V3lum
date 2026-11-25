"""HTTP plumbing: cached, rate-limited, retrying client shared by all modules.

* SQLite cache keyed by method+URL(+body): 2xx/404/410 cached, 401/403/429/5xx never cached.
* Per-host politeness: minimum interval between requests and max concurrent connections.
* Retries on connection errors and 502/503/504; honours short ``Retry-After`` on 429.
* Proxy / Tor support (``socks5h://`` needs PySocks). TLS verification is always on.
* Responses are size-capped (default 15 MB) to protect memory.

Modules never touch this class directly: they get ``ctx.http``, a :class:`ScopedHttp`
that carries the module's cache TTL / politeness settings and counts its requests.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

import requests

CACHEABLE_STATUS = frozenset({200, 201, 202, 203, 204, 206, 300, 301, 302, 303, 307, 308, 404, 410})
RETRY_STATUS = frozenset({502, 503, 504})


class HttpError(Exception):
    """Non-success HTTP status (or unusable body) for a request whose result was required."""

    def __init__(self, message: str, status: int = 0, url: str = "", body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.url = url
        self.body = body[:500]


class RateLimited(HttpError):
    """The provider answered 429 (or an equivalent quota error)."""


class AuthRequired(HttpError):
    """The provider answered 401/403 (missing/invalid key or blocked)."""


class NetworkError(Exception):
    """Connection failure, DNS failure, TLS failure or timeout."""


class OfflineError(NetworkError):
    """Offline mode: the request is not in the cache."""


@dataclass
class Response:
    status: int
    url: str
    headers: dict[str, str]
    content: bytes
    elapsed: float = 0.0
    from_cache: bool = False
    truncated: bool = False
    history: list[str] = field(default_factory=list)  # redirect chain (URLs)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        ctype = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {self.url}: {exc}", self.status, self.url, self.text) from exc

    def raise_for_status(self) -> Response:
        if self.status == 429:
            raise RateLimited(f"rate limited by {urlsplit(self.url).hostname}", 429, self.url, self.text)
        if self.status in (401, 403):
            raise AuthRequired(f"HTTP {self.status} from {urlsplit(self.url).hostname}", self.status, self.url, self.text)
        if not self.ok:
            raise HttpError(f"HTTP {self.status} from {urlsplit(self.url).hostname}", self.status, self.url, self.text)
        return self


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------


class HttpCache:
    """Tiny thread-safe SQLite response cache."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, url TEXT, host TEXT, status INTEGER,"
            " headers TEXT, body BLOB, ts REAL, history TEXT)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS cache_host ON cache(host)")
        self._conn.commit()

    def get(self, key: str, ttl: float) -> Response | None:
        if ttl <= 0:
            return None
        with self._lock:
            row = self._conn.execute("SELECT url, status, headers, body, ts, history FROM cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        url, status, headers, body, ts, history = row
        if time.time() - ts > ttl:
            return None
        return Response(
            status=status,
            url=url,
            headers=json.loads(headers or "{}"),
            content=body or b"",
            from_cache=True,
            history=json.loads(history or "[]"),
        )

    def put(self, key: str, resp: Response) -> None:
        if resp.status not in CACHEABLE_STATUS or resp.truncated:
            return
        host = urlsplit(resp.url).hostname or ""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, url, host, status, headers, body, ts, history) VALUES (?,?,?,?,?,?,?,?)",
                (key, resp.url, host, resp.status, json.dumps(resp.headers), resp.content, time.time(), json.dumps(resp.history)),
            )
            self._conn.commit()

    def clear(self, host: str | None = None, older_than: float | None = None) -> int:
        clauses, params = [], []
        if host:
            clauses.append("(host = ? OR host LIKE ?)")
            params += [host, f"%.{host}"]
        if older_than:
            clauses.append("ts < ?")
            params.append(time.time() - older_than)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            cur = self._conn.execute(f"DELETE FROM cache{where}", params)
            self._conn.commit()
            if not clauses:
                self._conn.execute("VACUUM")
            return cur.rowcount

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total, size = self._conn.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(body)),0) FROM cache").fetchone()
            hosts = self._conn.execute("SELECT host, COUNT(*) c FROM cache GROUP BY host ORDER BY c DESC LIMIT 15").fetchall()
        return {"entries": total, "bytes": size, "top_hosts": hosts, "path": self.path}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# --------------------------------------------------------------------------------------
# Politeness
# --------------------------------------------------------------------------------------


class HostLimiter:
    """Minimum interval between requests + max concurrency, per host."""

    def __init__(self, max_per_host: int = 4) -> None:
        self.max_per_host = max_per_host
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}
        self._sems: dict[str, threading.BoundedSemaphore] = {}

    def _sem(self, host: str) -> threading.BoundedSemaphore:
        with self._lock:
            if host not in self._sems:
                self._sems[host] = threading.BoundedSemaphore(self.max_per_host)
            return self._sems[host]

    def wait_turn(self, host: str, min_interval: float) -> None:
        if min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next.get(host, 0.0))
            self._next[host] = slot + min_interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)

    def slot(self, host: str) -> threading.BoundedSemaphore:
        return self._sem(host)


# --------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------

RequestHook = Callable[[str, str, int, float, bool, str], None]


class HttpClient:
    def __init__(
        self,
        *,
        user_agent: str = "Mozilla/5.0 (V3LUM)",
        timeout: float = 20.0,
        proxy: str = "",
        cache: HttpCache | None = None,
        default_ttl: float = 86400,
        offline: bool = False,
        max_per_host: int = 4,
        retries: int = 2,
        max_bytes: int = 15 * 1024 * 1024,
        on_request: RequestHook | None = None,
        trust_env: bool = True,
    ) -> None:
        self.trust_env = trust_env
        self.user_agent = user_agent
        self.timeout = timeout
        self.proxy = proxy
        self.cache = cache
        self.default_ttl = default_ttl
        self.offline = offline
        self.retries = retries
        self.max_bytes = max_bytes
        self.on_request = on_request
        self.limiter = HostLimiter(max_per_host)
        self._local = threading.local()
        self._inflight: dict[str, threading.Lock] = {}
        self._inflight_lock = threading.Lock()

    # ------------------------------------------------------------------ session
    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.trust_env = self.trust_env
            adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=16, max_retries=0)
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
            if self.proxy:
                sess.proxies = {"http": self.proxy, "https": self.proxy}
            self._local.session = sess
        return sess

    def _url_lock(self, key: str) -> threading.Lock:
        with self._inflight_lock:
            if key not in self._inflight:
                self._inflight[key] = threading.Lock()
            return self._inflight[key]

    @staticmethod
    def cache_key(method: str, url: str, body: bytes | None = None) -> str:
        h = hashlib.sha256()
        h.update(method.upper().encode())
        h.update(b" ")
        h.update(url.encode("utf-8", errors="replace"))
        if body:
            h.update(b"\n")
            h.update(body)
        return h.hexdigest()

    # ------------------------------------------------------------------ request
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json_body: Any = None,
        timeout: float | None = None,
        ttl: float | None = None,
        allow_redirects: bool = True,
        max_bytes: int | None = None,
        min_interval: float = 0.0,
        user_agent: str | None = None,
    ) -> Response:
        method = method.upper()
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            url = url + ("&" if "?" in url else "?") + urlencode(clean, doseq=True)
        body_bytes: bytes | None = None
        if json_body is not None:
            body_bytes = json.dumps(json_body, sort_keys=True).encode()
        elif isinstance(data, (bytes, str)):
            body_bytes = data.encode() if isinstance(data, str) else data
        elif isinstance(data, dict):
            body_bytes = urlencode(data, doseq=True).encode()

        if ttl is None:
            ttl = self.default_ttl if method in ("GET", "HEAD") else 0
        key = self.cache_key(method, url, body_bytes)
        host = urlsplit(url).hostname or ""

        if self.cache is not None and ttl > 0:
            hit = self.cache.get(key, ttl)
            if hit is not None:
                self._emit(method, url, hit.status, 0.0, True, "")
                return hit

        if self.offline:
            raise OfflineError(f"offline mode: {url} not cached")

        # Identical concurrent requests collapse into one network call.
        with self._url_lock(key):
            if self.cache is not None and ttl > 0:
                hit = self.cache.get(key, ttl)
                if hit is not None:
                    self._emit(method, url, hit.status, 0.0, True, "")
                    return hit
            resp = self._send(
                method,
                url,
                host=host,
                headers=headers,
                data=data,
                json_body=json_body,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                max_bytes=max_bytes or self.max_bytes,
                min_interval=min_interval,
                user_agent=user_agent,
            )
            if self.cache is not None and ttl > 0:
                self.cache.put(key, resp)
            return resp

    def _send(
        self,
        method: str,
        url: str,
        *,
        host: str,
        headers: dict[str, str] | None,
        data: Any,
        json_body: Any,
        timeout: float,
        allow_redirects: bool,
        max_bytes: int,
        min_interval: float,
        user_agent: str | None,
    ) -> Response:
        hdrs = {"User-Agent": user_agent or self.user_agent, "Accept-Language": "en-US,en;q=0.8"}
        if headers:
            hdrs.update(headers)
        attempts = self.retries + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            self.limiter.wait_turn(host, min_interval)
            start = time.monotonic()
            try:
                with self.limiter.slot(host):
                    raw = self._session().request(
                        method,
                        url,
                        headers=hdrs,
                        data=data,
                        json=json_body,
                        timeout=timeout,
                        allow_redirects=allow_redirects,
                        stream=True,
                    )
                    try:
                        content, truncated = self._read(raw, max_bytes)
                    finally:
                        raw.close()
            except requests.exceptions.RequestException as exc:
                elapsed = time.monotonic() - start
                last_exc = exc
                self._emit(method, url, 0, elapsed, False, type(exc).__name__)
                if attempt < attempts - 1 and not isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema)):
                    time.sleep(0.8 * (attempt + 1))
                    continue
                raise NetworkError(f"{type(exc).__name__} contacting {host}: {_short(exc)}") from exc
            elapsed = time.monotonic() - start
            resp = Response(
                status=raw.status_code,
                url=raw.url,
                headers={k.lower(): v for k, v in raw.headers.items()},
                content=content,
                elapsed=elapsed,
                truncated=truncated,
                history=[h.url for h in raw.history],
            )
            self._emit(method, url, resp.status, elapsed, False, "")
            if resp.status in RETRY_STATUS and attempt < attempts - 1:
                time.sleep(1.2 * (attempt + 1))
                continue
            if resp.status == 429 and attempt < attempts - 1:
                retry_after = _retry_after(resp.headers.get("retry-after"))
                if retry_after is not None and retry_after <= 15:
                    time.sleep(retry_after + 0.2)
                    continue
            return resp
        raise NetworkError(f"giving up on {host}: {last_exc}")  # pragma: no cover - loop always returns/raises

    @staticmethod
    def _read(raw: requests.Response, max_bytes: int) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        for chunk in raw.iter_content(chunk_size=65536):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                return b"".join(chunks)[:max_bytes], True
        return b"".join(chunks), False

    def _emit(self, method: str, url: str, status: int, elapsed: float, cached: bool, error: str) -> None:
        if self.on_request:
            try:
                self.on_request(method, url, status, elapsed, cached, error)
            except Exception:  # pragma: no cover - UI hooks must never break requests
                pass


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def _short(exc: Exception) -> str:
    text = str(exc)
    return text if len(text) < 160 else text[:157] + "..."


class ScopedHttp:
    """Per-module-run facade over the shared client: defaults + request counters."""

    def __init__(
        self,
        client: HttpClient,
        *,
        ttl: float | None = None,
        min_interval: float = 0.0,
        user_agent: str | None = None,
    ) -> None:
        self._client = client
        self._ttl = ttl
        self._min_interval = min_interval
        self._ua = user_agent
        self._lock = threading.Lock()
        self.requests = 0
        self.cache_hits = 0

    def request(self, method: str, url: str, **kw: Any) -> Response:
        kw.setdefault("ttl", self._ttl if method.upper() in ("GET", "HEAD") else None)
        kw.setdefault("min_interval", self._min_interval)
        if self._ua and "user_agent" not in kw:
            kw["user_agent"] = self._ua
        resp = self._client.request(method, url, **kw)
        with self._lock:
            if resp.from_cache:
                self.cache_hits += 1
            else:
                self.requests += 1
        return resp

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> Response:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self.request("POST", url, **kw)

    def get_json(self, url: str, *, ok404: bool = False, **kw: Any) -> Any:
        """GET and parse JSON. Raises RateLimited/AuthRequired/HttpError on failure.

        With ``ok404=True`` a 404 returns ``None`` (common "not found" signal).
        """
        headers = dict(kw.pop("headers", None) or {})
        headers.setdefault("Accept", "application/json")
        resp = self.get(url, headers=headers, **kw)
        if ok404 and resp.status == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def post_json(self, url: str, *, ok404: bool = False, **kw: Any) -> Any:
        headers = dict(kw.pop("headers", None) or {})
        headers.setdefault("Accept", "application/json")
        resp = self.post(url, headers=headers, **kw)
        if ok404 and resp.status == 404:
            return None
        resp.raise_for_status()
        return resp.json()
