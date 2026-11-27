"""Avatar image hashing for cross-account correlation (P114, batch p2-G05-2).

One GET per avatar URL already found on a profile, on an allow-list of avatar/CDN hosts of the trusted
or community platforms of the username pack; the image is hashed in memory and discarded. The
comparison across accounts happens in the correlation rules of ``v3lum/correlations/p2_g05_2.py``
(``p2g05_avatar_reuse``, ``p2g05_avatar_brand_logo``, ``p2g05_gravatar_email_match``), which read the
facts this module records on the avatar URL entity.

Final conditions served here:

* cond 1 - at most 30 avatar downloads per case (QUOTA ``quota`` beyond) and one download per avatar
  URL per case (the engine runs one (module, entity) pair once); the ">= 2 FOUND profiles with
  avatars" gate is applied by the rules (no pair, no report), see the batch backlog for the exact
  pre-download gate.
* cond 2 - http(s) URLs on :data:`AVATAR_ALLOWLIST` only (exact host + path prefix; no userinfo, port,
  IP literal or SVG path), through the core SSRF/host guard; every redirect hop must be allow-listed
  too (``hop_check``), so self-hosted, personal or target-domain avatars are never fetched.
* cond 3 - Pillow (optional extra ``full``, pinned minimum :data:`MIN_PILLOW`) only: no imagehash,
  numpy or scipy. 512 KB cap; content type, magic bytes and Pillow formats restricted to
  JPEG/PNG/GIF/WEBP (SVG never parsed); 16 M pixels checked from the header before decoding (Pillow's
  own bomb limit is 2x its ``MAX_IMAGE_PIXELS``) and DecompressionBomb errors and warnings caught;
  first frame only.
* cond 4 - whole-image dHash only: no face detection, cropping, facial recognition or reverse image
  search, and no face/biometric library is imported (tested). Only URL, SHA-256 and dHash (plus format
  and size facts) are kept; the HTTP cache never stores the image (ttl 0); nothing is uploaded.
* cond 5 - flat avatars (32x32 grayscale stddev < 6) and the bundled default/placeholder dHashes
  (``v3lum/data/default_avatars/*.json``) are marked ``avatar_ignored`` and never count as identity.
* cond 7 - this module never asks Gravatar about a case e-mail: it only fetches avatar URLs already
  found on profiles; e-mail hashes are compared locally by the rule.
* cond 8 - unavatar.io is not in this build (unknown tier, unreviewed terms): no host, no key use.
* cond 9 - results are text: URL, SHA-256, dHash, distance; no thumbnail is stored or rendered.
"""

from __future__ import annotations

import hashlib
import io
import math
import threading
import warnings
from collections import OrderedDict
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError, PolicyError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

__all__ = [
    "AVATAR_ALLOWLIST",
    "CASE_BUDGET",
    "ImageRejected",
    "AVATAR_FORMATS",
    "DHASH_MATCH_MAX",
    "FLAT_STDDEV_MAX",
    "FORBIDDEN_IMAGING_MODULES",
    "MAX_AVATAR_BYTES",
    "MAX_DOWNLOADS_PER_CASE",
    "MAX_PIXELS",
    "MIN_PILLOW",
    "AvatarCorrelation",
    "avatar_url_decision",
    "check_avatar_payload",
    "dhash_from_gray9x8",
    "hamming",
    "image_facts",
    "is_flat",
    "load_placeholders",
    "pillow_version_ok",
    "placeholder_match",
    "sniff_image_format",
    "upload_date_hint",
]

MAX_AVATAR_BYTES = 512 * 1024  # cond 3
MAX_PIXELS = 16_000_000  # cond 3
AVATAR_FORMATS = ("JPEG", "PNG", "GIF", "WEBP")  # cond 3: SVG never parsed
MAX_DOWNLOADS_PER_CASE = 30  # cond 1
DHASH_MATCH_MAX = 8  # cond 5: Hamming distance <= 8 = 'same avatar image'
FLAT_STDDEV_MAX = 6.0  # cond 5: grayscale stddev < 6 = flat/default avatar
#: cond 3 pin: the Pillow release this module was tested with (re-check the advisory database at merge).
MIN_PILLOW = (13, 0, 0)
#: cond 3/4: face/biometric and heavy imaging libraries this module must never import (tested).
FORBIDDEN_IMAGING_MODULES = ("face_recognition", "dlib", "mediapipe", "insightface", "deepface", "facenet_pytorch", "cv2",
                             "retinaface", "mtcnn", "imagehash", "numpy", "scipy", "torch", "tensorflow")

_GITHUB = "github.avatar_correlation_avatars"
_GRAVATAR = "gravatar.avatar_correlation_avatars"
#: cond 2: (host, path prefix) -> registry source. Exact hosts only; the path prefix pins avatar paths.
AVATAR_ALLOWLIST: dict[str, tuple[str, str]] = {
    "avatars.githubusercontent.com": ("/", _GITHUB),
    "secure.gravatar.com": ("/avatar/", _GRAVATAR),
    "gravatar.com": ("/avatar/", _GRAVATAR),
    "www.gravatar.com": ("/avatar/", _GRAVATAR),
    "0.gravatar.com": ("/avatar/", _GRAVATAR),
    "1.gravatar.com": ("/avatar/", _GRAVATAR),
    "2.gravatar.com": ("/avatar/", _GRAVATAR),
    "cdn.bsky.app": ("/img/avatar/", "bsky_app.avatars"),
    "gitlab.com": ("/uploads/-/system/user/avatar/", "gitlab.avatar_correlation_avatars"),
    "codeberg.org": ("/avatars/", "codeberg.avatar_correlation_avatars"),
    "cdn-avatars.huggingface.co": ("/", "huggingface.avatar_correlation_avatars"),
}
_SOURCES = tuple(sorted({src for _p, src in AVATAR_ALLOWLIST.values()}))


# ---------------------------------------------------------------------------------------------
# URL and payload checks (cond 2/3)
# ---------------------------------------------------------------------------------------------


def avatar_url_decision(url: Any) -> tuple[bool, str]:
    """cond 2: (allowed, reason). http(s), no userinfo/port/IP literal, exact host + path prefix, no SVG."""
    if not isinstance(url, str) or not url.strip():
        return False, "empty"
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return False, "bad_url"
    if parts.scheme not in ("http", "https"):
        return False, "scheme"
    if parts.username or parts.password:
        return False, "userinfo"
    if port not in (None, 80, 443):
        return False, "port"
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or ":" in host or host.replace(".", "").isdigit():
        return False, "host"
    if (parts.path or "").lower().endswith(".svg"):
        return False, "svg"
    entry = AVATAR_ALLOWLIST.get(host)
    if entry is None:
        return False, "host"
    return ((True, "allowlisted") if (parts.path or "/").startswith(entry[0]) else (False, "path"))


def _source_for(url: str) -> str:
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    entry = AVATAR_ALLOWLIST.get(host)
    return entry[1] if entry else ""


def _hop_guard(url: str) -> None:
    """cond 2: a redirect is followed only to another allow-listed avatar URL."""
    ok, reason = avatar_url_decision(url)
    if not ok:
        raise PolicyError("policy", f"avatar redirect to a URL outside the avatar host allow-list refused ({reason}; P114 cond 2)")


def sniff_image_format(data: Any) -> str | None:
    """Magic bytes: 'jpeg' | 'png' | 'gif' | 'webp' | 'svg' | None."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    head = bytes(data[:512])
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    probe = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if probe.startswith(b"<?xml") or b"<svg" in probe:
        return "svg"
    return None


def check_avatar_payload(data: Any, content_type: str | None = None, max_bytes: int = MAX_AVATAR_BYTES) -> tuple[bool, str]:
    """cond 3: (ok, format-or-reason) before Pillow sees the bytes: size, content type, magic bytes, no SVG."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return False, "empty"
    if len(data) > max_bytes:
        return False, "too_large"
    ctype = (content_type or "").split(";")[0].strip().lower()
    if "svg" in ctype:
        return False, "svg"
    if ctype and not ctype.startswith("image/"):
        return False, "content_type"
    fmt = sniff_image_format(data)
    if fmt == "svg":
        return False, "svg"
    if fmt is None:
        return False, "unknown_format"
    return True, fmt


# ---------------------------------------------------------------------------------------------
# dHash and flat check (cond 3/5)
# ---------------------------------------------------------------------------------------------


def dhash_from_gray9x8(pixels: Any) -> str:
    """64-bit dHash (16 hex) of a 9x8 grayscale matrix (72 values, row-major): bit = left > right, MSB first."""
    values = list(pixels)
    if len(values) != 72:
        raise ValueError("need 72 grayscale values (9x8)")
    bits = 0
    for y in range(8):
        for x in range(8):
            bits = (bits << 1) | (1 if values[y * 9 + x] > values[y * 9 + x + 1] else 0)
    return f"{bits:016x}"


def hamming(a: Any, b: Any) -> int:
    """Hamming distance of two dHashes (hex); 64 when either is missing or invalid."""
    try:
        return bin(int(str(a), 16) ^ int(str(b), 16)).count("1")
    except (TypeError, ValueError):
        return 64


def _stddev(values: list[int]) -> float:
    if not values:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    return math.sqrt(max(sum(v * v for v in values) / n - mean * mean, 0.0))


def is_flat(stddev32: Any) -> bool:
    """cond 5: a flat/default avatar has a 32x32 grayscale stddev below 6 (unreadable counts as flat)."""
    try:
        return float(stddev32) < FLAT_STDDEV_MAX
    except (TypeError, ValueError):
        return True


class ImageRejected(ValueError):
    """The bytes are not an image this module may decode. ``kind`` is 'limit' (a deliberate refusal:
    pixel limit, decompression bomb) or 'unreadable' (a corrupt or unexpected body: could not verify)."""

    def __init__(self, message: str, kind: str = "limit") -> None:
        super().__init__(message)
        self.kind = kind


def _pillow() -> Any:
    from PIL import Image  # optional extra 'full' (requires_packages): imported only when a run needs it

    return Image


def pillow_version_ok(version: str | None = None) -> bool:
    """cond 3: the installed Pillow is at least :data:`MIN_PILLOW`."""
    if version is None:
        try:
            import PIL

            version = str(getattr(PIL, "__version__", ""))
        except ImportError:
            return False
    parts: list[int] = []
    for piece in str(version).split(".")[:3]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) >= MIN_PILLOW


def _pixels(img: Any) -> list[int]:
    getter = getattr(img, "get_flattened_data", None)  # Pillow >= 12.1; getdata() goes away in Pillow 14
    data = getter() if callable(getter) else img.getdata()
    return [int(v) for v in data]


def image_facts(data: bytes) -> dict[str, Any]:
    """cond 3/4: decode the first frame in memory and return {format, width, height, dhash, stddev32}.

    Raises :class:`ImageRejected` for a format outside JPEG/PNG/GIF/WEBP, more than 16 M pixels, a
    decompression bomb or an unreadable image. Only the 9x8 and 32x32 grayscale reductions are computed:
    no region of the image is ever cropped or analysed.
    """
    image_mod = _pillow()
    with warnings.catch_warnings():
        warnings.simplefilter("error", image_mod.DecompressionBombWarning)
        try:
            with image_mod.open(io.BytesIO(bytes(data)), formats=list(AVATAR_FORMATS)) as img:
                width, height = (int(v) for v in img.size)
                if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                    raise ImageRejected(f"image of {width}x{height} pixels is above the {MAX_PIXELS:,}-pixel limit")
                fmt = str(img.format or "")
                img.seek(0)  # first frame only (animated GIF/WEBP)
                gray = img.convert("L")
                dhash = dhash_from_gray9x8(_pixels(gray.resize((9, 8))))
                stddev32 = round(_stddev(_pixels(gray.resize((32, 32)))), 3)
        except ImageRejected:
            raise
        except (image_mod.DecompressionBombError, image_mod.DecompressionBombWarning) as exc:
            raise ImageRejected(f"decompression bomb refused ({type(exc).__name__})") from None
        except (OSError, ValueError, EOFError, SyntaxError, TypeError, IndexError, MemoryError) as exc:
            raise ImageRejected(f"unreadable image ({type(exc).__name__})", "unreadable") from None
    return {"format": fmt, "width": width, "height": height, "dhash": dhash, "stddev32": stddev32}


def load_placeholders(data_view: Any) -> list[dict[str, str]]:
    """cond 5: the bundled per-platform default/placeholder dHashes (``v3lum/data/default_avatars``)."""
    out: list[dict[str, str]] = []
    try:
        directory = data_view.bundled_path("default_avatars")
        files = sorted(p for p in directory.glob("*.json")) if directory.is_dir() else []
    except (AttributeError, OSError, ValueError):
        return out
    for path in files:
        try:
            doc = data_view.bundled_json(f"default_avatars/{path.name}")
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("dhash"), str) and isinstance(doc.get("platform"), str):
            out.append({"platform": doc["platform"], "dhash": doc["dhash"].lower(), "sha256": str(doc.get("sha256") or "").lower()})
    return out


def placeholder_match(dhash: str, sha256: str, placeholders: list[dict[str, str]]) -> dict[str, str] | None:
    """cond 5: the default/placeholder entry this image matches (same bytes, or dHash distance <= 8)."""
    for entry in placeholders:
        if sha256 and entry.get("sha256") == sha256:
            return entry
        if hamming(dhash, entry.get("dhash")) <= DHASH_MATCH_MAX:
            return entry
    return None


def upload_date_hint(headers: Any) -> str | None:
    """Optional Last-Modified hint (C0230); sentinel dates before 2004 (Gravatar defaults: 1984) are dropped."""
    value = (headers or {}).get("last-modified") if hasattr(headers, "get") else None
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(str(value))
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.year < 2004:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class _CaseBudget:
    """cond 1: at most MAX_DOWNLOADS_PER_CASE downloads per case (in memory, per process)."""

    def __init__(self, limit: int = MAX_DOWNLOADS_PER_CASE, cases: int = 64) -> None:
        self.limit = limit
        self._cases = cases
        self._used: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, case_id: str) -> bool:
        if not case_id:
            return True  # a single run (no case): one entity, one download
        with self._lock:
            used = self._used.pop(case_id, 0)
            if used >= self.limit:
                self._used[case_id] = used
                return False
            self._used[case_id] = used + 1
            while len(self._used) > self._cases:
                self._used.popitem(last=False)
            return True

    def reset(self) -> None:
        with self._lock:
            self._used.clear()


CASE_BUDGET = _CaseBudget()


@register
class AvatarCorrelation(Module):
    name = "avatar_correlation"
    title = "Avatar image hash (dHash) for correlation"
    description = (
        "Downloads an avatar already found on a profile (allow-listed avatar CDNs only), hashes the whole image in memory "
        "(SHA-256 + 64-bit dHash, Pillow) and discards it; correlation rules compare accounts and Gravatar e-mail hashes."
    )
    category = "username_social"
    accepts = {T.URL}
    produces = frozenset()
    tags = {"free"}
    reference = "https://www.hackerfactor.com/blog/index.php?/archives/529-Kind-of-Like-That.html"
    notice = (
        "Whole-image hashing only: no face detection, facial recognition or reverse image search (biometric data, LGPD art. 11). "
        "The image is processed in memory and discarded; only its URL, SHA-256 and dHash are kept. A matching avatar is an "
        "identity signal, never proof of the same person."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the avatar CDN receives a request for an avatar URL it already published
    provider = "github"
    sources = _SOURCES
    hosts = tuple(sorted(AVATAR_ALLOWLIST))
    access_model = "free_noauth_unlimited"
    requires_packages = ("PIL",)
    max_requests = 1
    expected_latency = 0.5
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 0  # cond 4: the image is never cached
    default_enabled = True
    settings = {"avatar_correlation_brand_logos": {}}

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return avatar_url_decision(entity.value)[0]

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        url = entity.value
        ok, why = avatar_url_decision(url)
        if not ok:
            return res.mark("skipped", f"not an allow-listed avatar URL ({why}; P114 cond 2)", reason_code="not_applicable")
        source = _source_for(url)
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and source not in allowed:
            return res.mark("skipped", f"source {source} not allowed in this run", reason_code="licence")
        if not pillow_version_ok():
            return res.mark("unavailable", f"Pillow >= {'.'.join(map(str, MIN_PILLOW))} required (P114 cond 3: patched minimum)",
                            reason_code="package")
        if not CASE_BUDGET.take(str(getattr(ctx, "case_id", "") or "")):
            return res.mark("quota", f"avatar_correlation: {MAX_DOWNLOADS_PER_CASE} avatar downloads per case reached (P114 cond 1)")
        resp = ctx.http.get(url, source=source, ttl=0, max_bytes=MAX_AVATAR_BYTES, hop_check=_hop_guard,
                            headers={"Accept": "image/jpeg,image/png,image/gif,image/webp"})
        try:
            ctx.http.check(resp)
        except HttpError:
            if resp.status in (404, 410) and getattr(resp, "classification", None) is None:
                res.error = f"the avatar URL answered HTTP {resp.status}: the image is gone, nothing to hash"
                return res.mark("empty")
            raise
        if resp.status != 200:
            return res.mark("error", f"unexpected HTTP {resp.status} for the avatar: could not verify")
        if getattr(resp, "truncated", False):
            return res.mark("skipped", f"avatar larger than {MAX_AVATAR_BYTES // 1024} KB: not downloaded further (P114 cond 3)",
                            reason_code="not_applicable")
        body = bytes(resp.content or b"")
        ok, fmt = check_avatar_payload(body, resp.headers.get("content-type"))
        if not ok:
            if fmt == "svg":
                return res.mark("skipped", "SVG avatar: never parsed (P114 cond 3)", reason_code="not_applicable")
            return res.mark("error", f"the avatar URL did not answer a JPEG/PNG/GIF/WEBP image ({fmt}): could not verify")
        try:
            facts = image_facts(body)
        except ImageRejected as exc:
            if exc.kind == "unreadable":
                return res.mark("error", f"avatar not hashed: {exc}: could not verify")
            return res.mark("skipped", f"avatar not hashed: {exc} (P114 cond 3)", reason_code="not_applicable")
        sha256 = hashlib.sha256(body).hexdigest()
        del body  # cond 4: the image is discarded; only URL, SHA-256 and dHash remain
        placeholder = placeholder_match(facts["dhash"], sha256, load_placeholders(ctx.data))
        flat = is_flat(facts["stddev32"])
        ignored = f"placeholder:{placeholder['platform']}" if placeholder else ("flat" if flat else None)
        hint = upload_date_hint(resp.headers)
        res.attr("avatar_dhash", facts["dhash"])
        res.attr("avatar_sha256", sha256)
        res.attr("avatar_facts", {"format": facts["format"], "width": facts["width"], "height": facts["height"],
                                  "bytes": len(resp.content or b""), "stddev32": facts["stddev32"], "frames_used": 1,
                                  "upload_date_hint": hint})
        if ignored:
            res.attr("avatar_ignored", ignored)
        res.raw = {"url": url, "sha256": sha256, "dhash": facts["dhash"], "format": facts["format"],
                   "size": [facts["width"], facts["height"]], "stddev32": facts["stddev32"], "ignored": ignored,
                   "upload_date_hint": hint, "source": source}
        return res

