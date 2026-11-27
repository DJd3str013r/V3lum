"""QR code and barcode decoding from local images: quishing, PIX QR and boleto barcodes (P261, batch p2-G12-1).

Offline module (disclosure 'none': no network at all, ctx.http refuses every request; terms 'open'; provider tier
n/a; allowed at TLP:RED; default-on). Final conditions:

* c1 FILE input only. An analyst-typed image URL is downloaded only by the shared LIGHT file fetcher (P269;
  LIGHT/ACTIVE phase, docs/backlog/p2-G12-1.md), which hands the module a file.
* c2 decoder: zxing-cpp, the optional extra ``v3lum[qr]`` (Apache-2.0; it also reads the ITF barcodes printed
  on boletos). OpenCV and pyzbar are not used. A missing extra gives UNAVAILABLE 'package'
  ('pip install v3lum[qr]', ``requires_packages``).
* c3 decoding runs only inside the shared file-analysis sandbox ``core/sandbox.py`` (:func:`zxing_child` through
  ``image_metadata.sandbox_run``: python -I child, wall timeout, rlimits, 100 MB input, 1 MB JSON output) with
  Pillow's pixel cap (warning promoted to an error) and every payload capped at :data:`QR_PAYLOAD_CAP` bytes.
  zxing-cpp and Pillow's decoders are native code: they are never run in process. This build has no core
  sandbox yet, so the module reports UNAVAILABLE 'package' with that reason (could not verify, never 'no code').
* c4 every code in the image is decoded and reported. URLs become url pivots (relation ``qr_payload``) that are
  never fetched or opened by V3LUM; they expand only in a passive scan (passive URL reputation), never in a
  LIGHT/ACTIVE scan or when they carry a per-recipient token (a tokenised QR URL would confirm the scan to the
  phisher). PIX payloads and boleto barcodes go to the P233 parser functions called directly
  (``br_parsers.parse_brcode`` / ``parse_boleto``, CRC16 and check digits); other text goes to the shared P172
  IOC extractor (``v3lum.core.ioc.extract``). Wi-Fi passwords and OTP secrets are never kept.
* c5 display: payload type and defanged value ('QR -> URL hxxps://example[.]com/...'). No code decoded reads
  'no QR/barcode found' (EMPTY), never 'clean'.
* c6 fixtures: small QR and ITF PNGs generated once with a dev-only encoder (benign URL, PIX BR Code with a valid
  CRC, boleto barcode), a multi-code image and an oversized image (tests/fixtures/qr_decode/).
"""

from __future__ import annotations

import re
import warnings
from typing import Any

from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.geo_image_meta.image_metadata import (
    IMAGE_MAX_PIXELS,
    InputRefused,
    SandboxUnavailable,
    as_str,
    defang_url,
    image_error_reason,
    read_head,
    read_regular_file,
    sandbox_failure,
    sandbox_run,
    sniff_image,
)

try:  # P233 parser functions (batch p1-G10-1), called directly (c4)
    from v3lum.modules.brazil_public_data import br_parsers as _p233
except ImportError:  # pragma: no cover - the P233 module ships with the Brazil batch
    _p233 = None

QR_PAYLOAD_CAP = 4096  # c3
MAX_CODES = 64
NO_CODE_TEXT = "no QR/barcode found"  # c5 (never 'clean')
_FORMAT_LABEL = {"QRCode": "QR", "MicroQRCode": "Micro QR", "RMQRCode": "rMQR", "ITF": "ITF", "DataMatrix": "DataMatrix",
                 "PDF417": "PDF417", "Aztec": "Aztec", "Code128": "Code 128", "EAN13": "EAN-13"}
_PRIVATE_KINDS = ("email", "phone", "sms", "vcard", "contact", "coordinates")
DECODER_LIMITS = {"wall_timeout": 20.0, "cpu_seconds": 15}


def zxing_format_name(value: Any) -> str:
    """'QR Code' / 'BarcodeFormat.QRCode' / 'QRCode' -> 'QRCode'; 'Micro QR Code' -> 'MicroQRCode'."""
    v = re.sub(r"[^A-Za-z0-9]", "", (as_str(value, 64) or "").split(".")[-1])
    return {"rMQRCode": "RMQRCode"}.get(v, v)


def parse_wifi_qr(text: str) -> dict[str, Any]:
    """WIFI:T:WPA;S:<ssid>;P:<password>;H:true;; -> ssid/auth/hidden; the password is never kept (a flag only)."""
    body = text[5:] if text.upper().startswith("WIFI:") else text
    fields: dict[str, str] = {}
    cur, key, esc = "", None, False
    for ch in body[:QR_PAYLOAD_CAP]:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":" and key is None:
            key, cur = cur.upper(), ""
        elif ch == ";":
            if key:
                fields[key] = cur
            key, cur = None, ""
        else:
            cur += ch
    return {"kind": "wifi", "ssid": (fields.get("S") or "")[:64] or None, "auth": (fields.get("T") or "nopass")[:16],
            "hidden": (fields.get("H") or "").lower() == "true", "password_present": bool(fields.get("P"))}


def classify_qr_payload(text: Any, fmt: str = "QRCode", content_type: str = "Text") -> dict[str, Any]:
    """Route one decoded payload (c4): url -> passive URL reputation (never fetched or opened); PIX and boleto ->
    the P233 parsers; Wi-Fi/OTP secrets summarised without the secret; everything else -> the P172 extractor."""
    t = as_str(text, QR_PAYLOAD_CAP) or ""
    fmtn = zxing_format_name(fmt)
    if (content_type or "").lower() == "binary":
        return {"kind": "binary", "route": None, "value": None}
    low = t.lower()
    digits = re.sub(r"[\s.\-]", "", t)
    if t.strip().startswith("000201") and "br.gov.bcb.pix" in low:
        parsed = _p233.parse_brcode(t.strip(), origin="qr") if _p233 else {"ok": False, "error": "P233 parser unavailable"}
        return {"kind": "pix", "route": "P233.parse_brcode", "value": t.strip(), "pix": parsed}
    if re.fullmatch(r"\d{44}", digits) or re.fullmatch(r"\d{47,48}", digits):
        parsed = _p233.parse_boleto(digits) if _p233 else {"ok": False, "error": "P233 parser unavailable"}
        return {"kind": "boleto", "route": "P233.parse_boleto", "value": digits, "boleto": parsed,
                "barcode": fmtn in ("ITF", "ITF14")}
    if re.match(r"(?i)^https?://\S+$", t):
        return {"kind": "url", "route": "passive_url_reputation", "value": t}
    if re.match(r"(?i)^www\.[^\s/]+\.[a-z]{2,}(/\S*)?$", t):
        return {"kind": "url", "route": "passive_url_reputation", "value": "http://" + t, "note": "scheme-less URL"}
    if low.startswith("wifi:"):
        return {"kind": "wifi", "route": None, "value": None, "wifi": parse_wifi_qr(t)}
    if low.startswith("otpauth://"):
        return {"kind": "otp_secret", "route": None, "value": None, "note": "one-time-password enrolment secret: never stored or exported"}
    for prefix, kind in (("mailto:", "email"), ("tel:", "phone"), ("smsto:", "sms"), ("sms:", "sms"), ("geo:", "coordinates"),
                         ("begin:vcard", "vcard"), ("mecard:", "contact"), ("bitcoin:", "crypto_uri"), ("ethereum:", "crypto_uri"),
                         ("intent://", "app_link"), ("tg://", "app_link"), ("whatsapp://", "app_link")):
        if low.startswith(prefix):
            return {"kind": kind, "route": "P172.extract", "value": t, "privacy": kind in _PRIVATE_KINDS}
    return {"kind": "text", "route": "P172.extract", "value": t}


def qr_display_line(item: dict[str, Any], fmt: str = "QRCode") -> str:
    """c5: payload type and defanged value, e.g. 'QR -> URL hxxps://example[.]com/...'."""
    fmtn = zxing_format_name(fmt)
    label = _FORMAT_LABEL.get(fmtn, fmtn or "code")
    kind = item.get("kind")
    if kind == "url":
        return f"{label} -> URL {defang_url(item['value'])}"
    if kind == "pix":
        p = item.get("pix") or {}
        if not p.get("ok"):
            return f"{label} -> PIX payload not readable ({p.get('error')})"
        crc = "CRC ok" if p.get("crc_ok") else "CRC INVALID (edited or damaged payload)"
        kind_txt = "dynamic" if p.get("dynamic") else "static"
        where = f", location host {p.get('location_host_defanged')} (never fetched)" if p.get("location_host_defanged") else ""
        return f"{label} -> PIX {kind_txt} key {p.get('key_display') or '-'} ({p.get('key_type') or 'no key'}), {crc}{where}"
    if kind == "boleto":
        line = _p233.boleto_verdict_line(item.get("boleto"), origin="qr") if _p233 else "boleto (P233 parser unavailable)"
        return f"{label} -> {line}"
    if kind == "wifi":
        w = item["wifi"]
        pw = "present, not kept" if w.get("password_present") else "none"
        return f'{label} -> Wi-Fi network "{w.get("ssid") or "?"}" ({w.get("auth")}, password {pw})'
    if kind == "otp_secret":
        return f"{label} -> one-time-password secret (hidden, not kept)"
    if kind == "binary":
        return f"{label} -> binary payload"
    text = re.sub(r"(?i)\bhttps?://\S+", lambda m: defang_url(m.group()), item.get("value") or "")
    text = text if len(text) <= 120 else text[:117] + "..."
    return f'{label} -> {str(kind).replace("_", " ")} "{text}"'


def normalize_zxing_results(dump: Any) -> dict[str, Any]:
    """zxing_child output -> {status, reason_code, reason, codes, summary} (c3-c5). Every code is reported;
    nothing decoded -> status 'empty' with 'no QR/barcode found' (never 'clean')."""
    if not isinstance(dump, dict):
        return {"status": "error", "reason_code": "error", "reason": "decoder output is not an object", "codes": []}
    if dump.get("error"):
        if dump.get("error") == "UnidentifiedImageError":
            return {"status": "error", "reason_code": "error", "reason": "not a supported image format", "codes": []}
        err = image_error_reason({"error": dump.get("error"), "message": dump.get("message")}) or {}
        return {"status": "error", "reason_code": err.get("reason_code", "error"), "reason": err.get("reason", "image could not be decoded"), "codes": []}
    codes: list[dict[str, Any]] = []
    results = dump.get("results")
    for r in (results if isinstance(results, list) else [])[:MAX_CODES]:
        if not isinstance(r, dict):
            continue
        fmt = zxing_format_name(r.get("format"))
        text = r.get("text") if isinstance(r.get("text"), str) else ""
        truncated = bool(r.get("truncated")) or len(text) > QR_PAYLOAD_CAP
        item = classify_qr_payload(text[:QR_PAYLOAD_CAP], fmt, as_str(r.get("content_type")) or "Text")
        display = qr_display_line(item, fmt) + (" [payload capped at 4 KB]" if truncated else "")
        codes.append({"format": fmt, "valid": bool(r.get("valid", True)), "error": as_str(r.get("error"), 200),
                      "truncated": truncated, "kind": item["kind"], "route": item.get("route"), "display": display, "item": item})
    if not codes:
        return {"status": "empty", "reason_code": None, "reason": NO_CODE_TEXT, "codes": [], "summary": NO_CODE_TEXT}
    kinds = ", ".join(sorted({c["kind"] for c in codes}))
    return {"status": "ok", "reason_code": None, "reason": None, "codes": codes, "summary": f"{len(codes)} code(s) decoded: {kinds}"}


def zxing_child(data: bytes, max_pixels: int = IMAGE_MAX_PIXELS, payload_cap: int = QR_PAYLOAD_CAP) -> dict[str, Any]:
    """c2-c4 sandbox child (runs ONLY inside core/sandbox.py): decode EVERY code in the image."""
    import io

    import zxingcpp
    from PIL import Image, UnidentifiedImageError

    Image.MAX_IMAGE_PIXELS = max_pixels
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data)) as im:
                size = im.size
                gray = im.convert("L")
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            return {"error": "DecompressionBombError", "message": str(exc)[:300]}
        except UnidentifiedImageError:
            return {"error": "UnidentifiedImageError", "message": "not a recognised image format"}
        except (OSError, SyntaxError, ValueError) as exc:
            return {"error": type(exc).__name__, "message": str(exc)[:300]}
    results = []
    for r in zxingcpp.read_barcodes(gray, try_rotate=True, try_downscale=True, try_invert=True)[:MAX_CODES]:
        raw = bytes(r.bytes or b"")
        text = r.text or ""
        results.append({
            "format": str(r.format).split(".")[-1], "content_type": str(r.content_type).split(".")[-1],
            "text": text[:payload_cap], "text_len": len(text), "bytes_len": len(raw),
            "truncated": len(raw) > payload_cap or len(text) > payload_cap, "valid": bool(r.valid),
            "error": str(r.error) if r.error else None, "symbology_identifier": r.symbology_identifier,
            "ec_level": r.ec_level, "orientation": r.orientation,
        })
    return {"width": size[0], "height": size[1], "results": results}


def _passive_scan(ctx: Any) -> bool:
    mode = getattr(ctx, "mode", Opsec.PASSIVE)
    try:
        return Opsec.parse(mode) == Opsec.PASSIVE if not isinstance(mode, Opsec) else mode == Opsec.PASSIVE
    except (KeyError, ValueError):
        return False


def _token(url: str, ctx: Any) -> bool:
    try:
        from v3lum.core.policy import recipient_token
    except ImportError:  # pragma: no cover
        return False
    try:
        return bool(recipient_token(url, getattr(ctx, "org", None)))
    except Exception:  # noqa: BLE001 - fail closed: treat as a token (no expansion)
        return True


@register
class QrDecode(Module):
    name = "qr_decode"
    title = "QR code and barcode decoding (quishing, PIX, boleto)"
    description = (
        "Decodes every QR code and barcode in a local image offline (zxing-cpp in the file-analysis sandbox): URLs for "
        "passive reputation (never fetched), PIX BR Codes and boleto barcodes through the P233 parsers, other text "
        "through the IOC extractor."
    )
    category = "geo_image_meta"
    accepts = {T.FILE}
    produces = {T.URL, T.DOMAIN, T.EMAIL, T.PHONE, T.CNPJ, T.BOLETO, T.ORG}
    reference = "https://github.com/zxing-cpp/zxing-cpp"
    tags = {"offline", "brazil"}
    notice = "Decoded URLs are never fetched or opened (a tokenised QR URL would confirm the scan to the phisher); Wi-Fi passwords and OTP secrets are never kept."
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # no network at all
    hosts = ()
    access_model = "offline"
    requires_packages = ("zxingcpp", "PIL")
    max_requests = 0
    expected_latency = 0.1
    timeout = 60.0
    max_pivots = 100
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return sniff_image(read_head(entity.value, 64)) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            read_regular_file(entity.value)  # c3: regular files of at most 100 MB only
            out = sandbox_run(f"{__name__}:zxing_child", entity.value,
                              args={"max_pixels": IMAGE_MAX_PIXELS, "payload_cap": QR_PAYLOAD_CAP}, **DECODER_LIMITS)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        except SandboxUnavailable as exc:
            return res.mark("unavailable", f"QR decoding runs zxing-cpp only inside the file-analysis sandbox: {exc}", reason_code="package")
        if not out.get("ok"):
            code, reason = sandbox_failure(out)
            return res.mark("error", reason, reason_code=code)
        norm = normalize_zxing_results(out.get("result"))
        if norm["status"] == "error":
            return res.mark("error", str(norm["reason"]), reason_code=str(norm.get("reason_code") or "error"))
        if norm["status"] == "empty":
            res.raw = {"summary": NO_CODE_TEXT, "codes": []}
            return res.mark("empty", NO_CODE_TEXT)
        self.emit(res, norm, ctx)
        return res

    def emit(self, res: ModuleResult, norm: dict[str, Any], ctx: Any) -> None:
        """Attributes, findings and pivots of a normalised decoder result (c4, c5)."""
        codes = norm["codes"]
        res.attr("qr_summary", norm["summary"])
        res.attr("qr_codes", [{k: c[k] for k in ("format", "kind", "display", "valid", "truncated", "route")} for c in codes])
        res.finding("QR codes and barcodes decoded", "info", norm["summary"] + ": " + "; ".join(c["display"] for c in codes),
                    tags=["info", "qr_code"], data={"count": len(codes)})
        passive = _passive_scan(ctx)
        pix_done = False
        for idx, code in enumerate(codes):
            item, kind = code["item"], code["kind"]
            if kind == "url":
                url = item["value"]
                token = _token(url, ctx)
                expand = passive and not token
                note = ("decoded from a QR code: passive URL reputation only, never fetched or opened by V3LUM"
                        + ("; carries a per-recipient token: analyst selection required" if token else "")
                        + ("" if passive else "; not expanded in a LIGHT/ACTIVE scan"))
                if res.pivot(T.URL, url, "qr_payload", confidence="confirmed", expand=expand, note=note) is not None:
                    res.finding("URL in a QR code (quishing check)", "info",
                                f"{code['display']}. The URL is checked by passive reputation sources only and is never fetched or opened.",
                                tags=["info", "qr_code"], key=str(idx))
            elif kind == "pix":
                parsed = item.get("pix") or {}
                if not pix_done and parsed.get("ok"):
                    pix_done = True
                    for k, v in (_p233.brcode_entities(parsed).get("attributes") or {}).items() if _p233 else ():
                        res.attr(k, v)
                for p in (_p233.brcode_entities(parsed).get("pivots") or []) if _p233 else ():
                    res.pivot(T(p["type"]), p["value"], p["relation"], confidence="probable", expand=bool(p.get("expand")), note=str(p.get("note") or ""))
                if parsed.get("ok") and parsed.get("crc_ok") is False:
                    res.finding("PIX QR payload altered or damaged (CRC mismatch)", "medium",
                                f"{code['display']}. The QR symbol itself decoded cleanly, so the BR Code text was most likely edited "
                                "after it was generated (a tampered PIX QR redirects the payment).",
                                confidence="probable", criterion="PIX BR Code CRC16/CCITT-FALSE (field 63) does not match the payload (P233 parser)",
                                tags=["fraud", "tampering_suspected", "qr_code"], key=str(idx))
            elif kind == "boleto":
                parsed = item.get("boleto") or {}
                if parsed.get("ok"):
                    res.pivot(T.BOLETO, item["value"], "qr_payload", confidence="confirmed", expand=True,
                              note="boleto barcode decoded from the image (P233 checks)")
                    if not parsed.get("check_digits_ok"):
                        res.finding("Boleto barcode check digits do not match", "low",
                                    f"{code['display']}. An altered boleto barcode can redirect the payment.", confidence="possible",
                                    criterion="boleto check digit (mod 10/11, P233 parser) does not match the decoded barcode",
                                    tags=["fraud", "qr_code"], key=str(idx))
            elif item.get("route") == "P172.extract" and item.get("value"):
                self._extract(res, item["value"], bool(item.get("privacy")))
        res.raw = {"summary": norm["summary"], "codes": [_raw_code(c) for c in codes]}

    def _extract(self, res: ModuleResult, text: str, private: bool) -> None:
        """c4: other text goes to the shared P172 extractor; personal identifiers pivot with expand=False."""
        from v3lum.core.ioc import extract

        for ioc in extract(text, limit=50, source_type="qr").entities:
            ent = ioc.entity
            personal = ent.type in PERSONAL_TYPES or private
            expand = bool(ioc.expand) and ent.type in IOC_TYPES and not personal
            note = ("personal identifier from a QR payload: analyst selection required" if personal
                    else "found in a QR payload text (P172 extractor)")
            res.pivot(ent.type, ent.value, "qr_payload", confidence="probable" if ioc.confidence >= 0.75 else "possible",
                      expand=expand, note=note)


def _raw_code(code: dict[str, Any]) -> dict[str, Any]:
    """Evidence of one code: secrets are never kept (Wi-Fi password, OTP secret); CPF PIX keys masked."""
    item = code["item"]
    out = {k: code[k] for k in ("format", "kind", "display", "valid", "truncated", "route")}
    if code["kind"] in ("url", "text", "crypto_uri", "app_link"):
        out["payload"] = item.get("value")
    elif code["kind"] == "pix" and _p233 is not None and isinstance(item.get("pix"), dict):
        out["payload"] = _p233.masked_brcode(item["value"], item["pix"])
    elif code["kind"] == "boleto":
        out["payload"] = item.get("value")
    return out
