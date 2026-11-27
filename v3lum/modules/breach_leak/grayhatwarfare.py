"""GrayhatWarfare open-bucket index: bucket and file NAMES only (P138), keyed.

``GET https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=<term>&start=0&limit=100`` and
``.../api/v2/files?keywords=...`` with ``Authorization: Bearer <key>``.

* **Key** (cond 1): key ``grayhat`` (provider fragment, alias ``V3LUM_GRAYHAT_KEY``), Bearer header only
  (never ``?access_token=``: URLs reach the cache and logs); a missing key or a 401 is NEEDS_KEY.
  Key-terms: a company/team account on a plan recorded by legal before it runs under corporate.
* **Names only** (cond 2): only GrayhatWarfare's own index is queried - for org-profile brands/domains and
  analyst-typed seeds (SKIPPED ``privacy`` otherwise). :func:`grayhat_url` builds the two search endpoints
  on buckets.grayhatwarfare.com and nothing else: there is no code path that lists or downloads objects
  from any cloud provider (rule 3, LGPD), and file URLs/paths are never kept (the provider's P145 schema
  drops them before the module sees the answer).
* **Masking** (cond 3): file names with CPF patterns, e-mails, phone numbers, person-name runs or
  personal-document stems (cv, holerite, rg, cnh...) are masked before storage (:func:`mask_file_name`);
  reports show counts and extensions (attribute ``grayhat_files_summary``); masked names stay in the
  sanitized evidence only.
* **Candidates** (cond 4): brand-named buckets are LOW 'exists, ownership unverified' until linked to the
  organisation; only buckets named after a verified org-profile domain count as confirmed own buckets and
  only those pivot (``expand=False``) towards the ACTIVE bucket check of an authorized scope. Rows also feed
  ``cloud_buckets`` (attribution 'permutation': unattributed, CR24 INFO).
* **Cap** (cond 5): 100 results per endpoint (``limit=100``; ``capped`` flagged). The success fixtures are
  documentation-shaped until a trimmed real capture made with the team key replaces them.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.psl import registrable_domain

SOURCE = "grayhatwarfare.api"
HOST = "buckets.grayhatwarfare.com"
KEY_NAME = "grayhat"
ENDPOINTS = {"buckets": "/api/v2/buckets", "files": "/api/v2/files"}
RESULT_CAP = 100  # cond 5
MAX_CANDIDATES = 25
UNVERIFIED = "exists, ownership unverified"

_CPF = re.compile(r"(?<!\d)\d{3}[.\s_-]?\d{3}[.\s_-]?\d{3}[\s_.-]?\d{2}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_PHONE = re.compile(r"(?<!\d)(?:\+?55[\s_.-]?)?\(?\d{2}\)?[\s_.-]?9?\d{4}[\s_.-]?\d{4}(?!\d)")
_NAME = re.compile(r"(?<![A-Za-zÀ-ÖØ-öø-ÿ])[A-ZÀ-ÖØ-Þ][a-zß-öø-ÿ]{1,}(?:[ _.-](?:d[aeo]s?[ _.-])?[A-ZÀ-ÖØ-Þ][a-zß-öø-ÿ]{1,})+")
_PERSONAL_DOC = re.compile(r"(?i)(?<![a-z])(cv|curr[ií]culo|curriculum|resume|holerite|contracheque|payslip|rg|cnh|"
                           r"passaporte|passport|comprovante|extrato|cpf|ctps|certid[aã]o)(?![a-z])")
_EXT = re.compile(r"^[A-Za-z0-9]{1,8}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,252}(?:/[A-Za-z0-9._-]{1,63})?$")


def grayhat_url(endpoint: str, keywords: Any, *, start: int = 0, limit: int = RESULT_CAP) -> str:
    """One of the two GrayhatWarfare index searches (cond 2/5); ValueError for any other endpoint, a URL
    or an empty/oversized term. No builder exists for cloud-provider hosts or object downloads."""
    if endpoint not in ENDPOINTS:
        raise ValueError(f"grayhat: endpoint not allow-listed: {endpoint!r}")
    if not isinstance(keywords, str) or not keywords.strip() or len(keywords) > 100 or "://" in keywords or "/" in keywords:
        raise ValueError("grayhat: keywords must be a brand, company or domain term")
    lim = max(1, min(int(limit or RESULT_CAP), RESULT_CAP))
    query = urlencode({"keywords": " ".join(keywords.split()), "start": max(0, int(start or 0)), "limit": lim})
    return f"https://{HOST}{ENDPOINTS[endpoint]}?{query}"


def grayhat_headers(key: Any) -> dict[str, str]:
    """Bearer header (cond 1); ValueError without a key."""
    if not isinstance(key, str) or not key.strip():
        raise ValueError("grayhat key not configured")
    return {"Authorization": "Bearer " + key.strip(), "Accept": "application/json"}


def mask_file_name(name: Any) -> tuple[str, list[str]]:
    """Mask personal data in a file name before storage (cond 3): CPF patterns -> [cpf], e-mails ->
    [email], phones -> [phone], person-name-like Title-Case runs -> [name]; a personal-document stem is
    masked whole -> [personal-doc]. Directories are dropped, the extension is kept. -> (masked, kinds)."""
    text = "".join(ch for ch in (name if isinstance(name, str) else "") if ord(ch) >= 32)[:512]
    base = text.replace("\\", "/").rsplit("/", 1)[-1]
    stem, dot, ext = base.rpartition(".")
    if not dot or not stem or not _EXT.match(ext or ""):
        stem, ext = base, ""
    kinds: set[str] = set()
    if _PERSONAL_DOC.search(stem):
        kinds.add("personal-doc")
        stem = "[personal-doc]"
    else:
        for kind, rx in (("email", _EMAIL), ("cpf", _CPF), ("phone", _PHONE), ("name", _NAME)):
            if rx.search(stem):
                kinds.add(kind)
                stem = rx.sub(f"[{kind}]", stem)
    return stem + ("." + ext.lower() if ext else ""), sorted(kinds)


def file_extension(name: Any) -> str:
    base = (name if isinstance(name, str) else "").replace("\\", "/").rsplit("/", 1)[-1]
    stem, dot, ext = base.rpartition(".")
    return ext.lower() if dot and stem and _EXT.match(ext) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _stamp(value: Any) -> str | None:
    epoch = _int(value)
    if epoch is not None and 0 < epoch < 253402300799:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
        return value[:19] + "Z"
    return None


def parse_buckets(body: Any) -> dict[str, Any] | None:
    """Bucket search -> names only (cond 2/5): {total, returned, capped, buckets [{bucket, provider,
    file_count}]}. None when the body is not a bucket result."""
    if not isinstance(body, dict) or not isinstance(body.get("buckets"), list):
        return None
    rows = []
    for item in body["buckets"][:RESULT_CAP]:
        if not isinstance(item, dict):
            continue
        name = item.get("bucket") if isinstance(item.get("bucket"), str) else None
        name = name.strip().lower() if name else None
        if not name or not _BUCKET.match(name):
            continue
        count = _int(item.get("fileCount"))
        provider = item.get("type") if isinstance(item.get("type"), str) else None
        rows.append({"bucket": name, "provider": provider.strip().lower()[:20] if provider else None,
                     "file_count": count if count is not None and count >= 0 else None})
    meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
    total = _int(meta.get("results"))
    total = total if total is not None else len(body["buckets"])
    return {"total": total, "returned": len(rows), "capped": total > RESULT_CAP or len(body["buckets"]) > RESULT_CAP, "buckets": rows}


def parse_files(body: Any) -> dict[str, Any] | None:
    """File search -> masked names, counts and extensions (cond 2/3/5). Raw names and object URLs are
    never returned. None when the body is not a file result."""
    if not isinstance(body, dict) or not isinstance(body.get("files"), list):
        return None
    files, exts, buckets, scrubbed = [], {}, {}, 0
    for item in body["files"][:RESULT_CAP]:
        if not isinstance(item, dict):
            continue
        raw_name = item.get("filename") if isinstance(item.get("filename"), str) else ""
        if not raw_name:
            continue
        masked, kinds = mask_file_name(raw_name)
        scrubbed += 1 if kinds else 0
        ext = file_extension(raw_name) or "(none)"
        exts[ext] = exts.get(ext, 0) + 1
        bucket = item.get("bucket").strip().lower() if isinstance(item.get("bucket"), str) else None
        if bucket and not _BUCKET.match(bucket):
            bucket = None
        if bucket:
            buckets[bucket] = buckets.get(bucket, 0) + 1
        size = _int(item.get("size"))
        provider = item.get("type") if isinstance(item.get("type"), str) else None
        files.append({"bucket": bucket, "filename": masked, "scrub_kinds": kinds, "size": size if size is not None and size >= 0 else None,
                      "type": provider.strip().lower()[:20] if provider else None, "lastModified": _stamp(item.get("lastModified"))})
    meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
    total = _int(meta.get("results"))
    total = total if total is not None else len(body["files"])
    return {"total": total, "returned": len(files), "capped": total > RESULT_CAP or len(body["files"]) > RESULT_CAP,
            "files": files, "extension_counts": exts, "bucket_counts": buckets, "scrubbed_count": scrubbed}


def _fold(text: Any) -> str:
    norm = unicodedata.normalize("NFKD", str(text or ""))
    return "".join(ch for ch in norm if not unicodedata.combining(ch)).lower()


def brand_hits(bucket: str, terms: list[str]) -> list[str]:
    folded = _fold(bucket)
    flat = folded.replace("-", "").replace("_", "").replace(".", "")
    return [t for t in terms if len(t) >= 3 and (t in folded or t.replace(" ", "") in flat)]


@register
class GrayhatWarfare(Module):
    name = "grayhatwarfare"
    title = "GrayhatWarfare open buckets (names only)"
    description = (
        "Open cloud buckets and exposed file NAMES that GrayhatWarfare indexes for an org brand, domain or analyst-typed "
        "term: counts, extensions and brand-named bucket candidates; never lists or downloads objects."
    )
    category = "breach_leak"
    accepts = {T.KEYWORD, T.ORG, T.DOMAIN}
    produces = {T.URL}
    run_on = "any"  # cond 2: org-profile brands/domains or analyst-typed seeds, enforced in run()
    reference = "https://buckets.grayhatwarfare.com/docs/api/v2"
    notice = (
        "Names only: bucket and file names from GrayhatWarfare's index, never object listings or downloads (third-party "
        "files may hold personal data, LGPD). Personal data in file names is masked before storage. Brand-named buckets "
        "are unverified candidates. Key-terms: a company/team account recorded by legal."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "grayhatwarfare"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 2
    expected_latency = 1.5
    timeout = 45.0
    min_interval = 2.0
    cache_ttl = 0  # the provider is sensitive and ttl 0: never cached
    max_pivots = MAX_CANDIDATES
    manual_link = "pentest:grayhat_files"
    default_enabled = False
    error_markers = (
        {"id": "grayhat_error_body", "statuses": [200], "json_path": "error", "regex": "\\S", "maps_to": "error", "reason_code": "error",
         "reason": "GrayhatWarfare: error object inside an HTTP 200 answer"},
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        try:
            grayhat_url("files", self._term(entity))
        except ValueError:
            return False
        return True

    @staticmethod
    def _term(entity: Entity) -> str:
        if entity.type is T.DOMAIN:
            reg = registrable_domain(entity.value) or entity.value
            label = reg.split(".", 1)[0]
            return label if len(label) >= 4 else reg
        return " ".join(str(entity.value).split())

    @staticmethod
    def _org_match(entity: Entity, ctx: Any) -> bool:
        org = getattr(ctx, "org", None)
        if org is None:
            return False
        try:
            if entity.type is T.DOMAIN:
                return bool(org.owns(entity).own)
            folded = _fold(entity.value).strip()
            return any(folded == t or (len(t) >= 4 and t in folded) for t in org.brand_terms())
        except Exception:  # noqa: BLE001 - a broken profile never widens a gate
            return False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        typed = bool(getattr(ctx, "is_seed", False)) and int(getattr(ctx, "depth", 0) or 0) == 0
        if not typed and not self._org_match(entity, ctx):
            return res.mark(Status.SKIPPED, "GrayhatWarfare is queried only for org-profile brands/domains and analyst-typed seeds",
                            reason_code="privacy")
        try:
            headers = grayhat_headers(ctx.key(KEY_NAME))
        except ValueError:
            return res.mark(Status.NEEDS_KEY, "GrayhatWarfare needs the key 'grayhat' (V3LUM_GRAYHAT_KEY)", reason_code="needs_key")
        term = self._term(entity)
        bucket_body = ctx.http.get_json(grayhat_url("buckets", term), headers=headers, source=SOURCE, ttl=0)
        buckets = parse_buckets(bucket_body)
        if buckets is None:
            return res.mark(Status.ERROR, "unexpected GrayhatWarfare bucket answer: could not verify")
        file_body = ctx.http.get_json(grayhat_url("files", term), headers=headers, source=SOURCE, ttl=0)
        files = parse_files(file_body)
        if files is None:
            return res.mark(Status.ERROR, "unexpected GrayhatWarfare file answer: could not verify")
        # evidence in the provider schema's shape (sanitized again by the engine): masked names only
        res.raw = {
            "meta": {"results": buckets["total"] + files["total"]},
            "buckets": [{"bucket": b["bucket"], "fileCount": b["file_count"], "type": b["provider"]} for b in buckets["buckets"]],
            "files": [{"bucket": f["bucket"], "filename": f["filename"], "size": f["size"], "type": f["type"], "lastModified": f["lastModified"]}
                      for f in files["files"]],
        }
        if not buckets["returned"] and not files["returned"]:
            res.error = f"GrayhatWarfare indexes no bucket or file name matching '{term}' (index coverage only)"
            return res.mark(Status.EMPTY)
        self._candidates(res, ctx, entity, term, buckets)
        self._files(res, term, files)
        return res

    def _candidates(self, res: ModuleResult, ctx: Any, entity: Entity, term: str, buckets: dict[str, Any]) -> None:
        org = getattr(ctx, "org", None)
        terms = [t for t in dict.fromkeys([_fold(term).strip(), *(org.brand_terms() if org is not None else [])]) if t]
        rows, cloud_rows = [], []
        for item in buckets["buckets"]:
            hits = brand_hits(item["bucket"], terms)
            if not hits:
                continue
            host = item["bucket"].split("/", 1)[0]
            confirmed = False
            if org is not None:
                try:
                    confirmed = bool(org.is_verified_domain(host))
                except Exception:  # noqa: BLE001
                    confirmed = False
            rows.append({"bucket": item["bucket"], "provider": item["provider"], "file_count": item["file_count"], "brand_hits": hits,
                         "ownership": "own (confirmed)" if confirmed else UNVERIFIED})
            cloud_rows.append({"bucket": item["bucket"], "provider": item["provider"] or "cloud", "state": "public_listing",
                               "attribution": "permutation", "evidence": "listed in the GrayhatWarfare open-bucket index (crawl time)"})
            if confirmed:
                res.pivot(T.URL, f"https://{item['bucket']}/", "candidate_bucket", confidence="probable", expand=False,
                          note="own bucket (verified org-profile domain) listed as open by GrayhatWarfare: ACTIVE check only within an authorized scope")
            if len(rows) >= MAX_CANDIDATES:
                break
        summary = {"total": buckets["total"], "returned": buckets["returned"], "capped": buckets["capped"]}
        res.attr("grayhat_buckets", rows)
        res.attr("cloud_buckets", cloud_rows)
        if not rows:
            return
        confirmed = [r for r in rows if r["ownership"] != UNVERIFIED]
        res.finding(
            "Brand-named open buckets in the GrayhatWarfare index",
            "medium" if confirmed else "low",
            f"{len(rows)} open bucket(s) named after '{term}' or an org brand"
            + (f", {len(confirmed)} on a verified own domain" if confirmed else "")
            + f" ({UNVERIFIED} for the others: link them through the org profile, a CNAME or a website reference before acting). "
            "Names only: no object was listed or downloaded." + (" Results capped at 100." if buckets["capped"] else ""),
            confidence="probable" if confirmed else "possible",
            criterion="bucket name contains the searched brand/domain term in GrayhatWarfare's open-bucket index",
            data={"buckets": [{k: r[k] for k in ("bucket", "provider", "file_count", "ownership")} for r in rows], **summary},
            tags=["exposure", "ownership_unverified"] if not confirmed else ["exposure", "own_asset"],
            source=SOURCE,
        )

    @staticmethod
    def _files(res: ModuleResult, term: str, files: dict[str, Any]) -> None:
        summary = {k: files[k] for k in ("total", "returned", "capped", "extension_counts", "bucket_counts", "scrubbed_count")}
        res.attr("grayhat_files_summary", summary)
        if not files["returned"]:
            return
        top = sorted(files["extension_counts"].items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        res.finding(
            "Exposed file names matching the term (GrayhatWarfare)",
            "low",
            f"{files['total']} file name(s) in open buckets match '{term}' ({files['returned']} read"
            + (", capped at 100" if files["capped"] else "") + "); extensions: "
            + ", ".join(f"{ext} x{n}" for ext, n in top)
            + f". {files['scrubbed_count']} name(s) carried personal data and were masked. Names only: never downloaded.",
            confidence="possible",
            criterion="GrayhatWarfare file-name search matched the term in its open-bucket index",
            data={"total": files["total"], "returned": files["returned"], "extension_counts": files["extension_counts"],
                  "buckets": len(files["bucket_counts"]), "scrubbed_count": files["scrubbed_count"]},
            tags=["exposure", "privacy"],
            source=SOURCE,
        )
