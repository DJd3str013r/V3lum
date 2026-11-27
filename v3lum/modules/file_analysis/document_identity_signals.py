"""Identity signals of a typed person inside the case's own documents: name windows + the nearest CPF
(P273, batch p3-G12-1; port of the Ceos ``documentos.py`` heuristics, team-owned).

Final conditions, as implemented here:

1. Offline module: disclosure ``none`` (no network at all), terms ``open``, provider tier n/a, allowed at TLP:RED.
   Opt-in (``default_enabled=False``).
2. Legal floor: the module runs on a **person seed the analyst typed** (``run_on='seeds'``; the policy gate also
   requires a recorded purpose for this personal type) and reads only the **documents attached to the current
   case** - the analyst-typed ``text_blob`` and ``file`` seeds of the running investigation's graph (outside a scan
   there is no case: SKIPPED ``not_applicable``). A typed ``cpf`` seed is only searched inside those documents and
   never triggers any lookup (rule 4); typed ``keyword`` seeds ``cidade:``/``city:`` and ``uf:`` give the
   subject's city/UF hints.
3. Text: text_blob seeds as typed (already scrubbed by the input path, P145/P172) and regular text files
   (<= 20 MB, like ioc_extract); PDF/image text produced by P269/P363 is not published to the case yet (core
   request), so those files are reported in coverage, never parsed here (no own PDF parsing). CPF check digits
   use the core P232 validator ``v3lum.core.validators.cpf_valid``. Name windows are bounded (<= 200 characters);
   only the CPF nearest to the subject's name **in the same record** counts (:func:`document_layout`: one
   record per line in tables, ';' / '|' / bullets / blank lines end records in prose), so a neighbour's CPF
   cannot attach to the subject; a city near the name is a strong signal (+2), a UF only a weak one (+1).
4. Never creates CPF entities: the nearest CPF is stored only masked (``***.XXX.XXX-**``) in attributes and
   evidence, never pivoted, never sent; masked CPFs are never compared with the typed CPF's digits (no
   CPF-fragment joins, P236 floor) - the analyst reads the pair. The typed CPF is compared exactly, in memory.
5. No cross-case name<->CPF index: results carry the tags ``privacy`` and ``no_cross_case_index``; the module never
   writes ``ctx.state`` and produces no pivots, so nothing reaches the P375 sightings index; the attributes
   ``identity_signals``/``identity_windows`` must be left out of STIX/MISP exports (core request: exporters drop
   them, as they hold name-CPF pairs) and follow A10 retention with the case.
6. Tests use synthetic text fixtures (gazette paragraph and table, masked list, contract form, a name without a
   CPF) and assert masked output in the terminal, HTML, Markdown and JSON renderers.
"""

from __future__ import annotations

import bisect
import hashlib
import os
import re
import stat as _stat
import unicodedata
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.validators import cpf_valid

MAX_WINDOW = 200
MAX_READ = 20 * 1024 * 1024
MAX_DOCUMENTS = 50
MAX_WINDOWS_KEPT = 20
TEXT_EXT = {".txt", ".csv", ".tsv", ".md", ".log", ".json", ".xml", ".html", ".htm", ".eml", ""}
UF_CODES = frozenset(["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"])
_CPF_RE = re.compile(r"(?<![\d*])(\d{3})\.?(\d{3})\.?(\d{3})\s?-?\s?(\d{2})(?!\d)")
_MASKED_CPF_RE = re.compile(r"(?<![\w*])(?:\*{3}|[xX]{3})\.?(\d{3})\.?(\d{3})-?(?:\*{2}|[xX]{2})(?![\w*])")
_STRONG_SEP_RE = re.compile(r";|\||•|\n[ \t\r\f\v]*\n")
_CPF_LABEL_RE = re.compile(r"\bcpf\b")
_LABEL_WORDS = frozenset(("cpf", "n", "no", "nr", "num", "numero", "mf", "rg"))
_HINT_RE = re.compile(r"^\s*(cidade|city|municipio|município|uf|estado)\s*:\s*(.{1,80})$", re.I)
PRIVACY_TAGS = ["info", "privacy", "no_cross_case_index"]


# ======================================================================================================
# pure helpers (ported from the batch prep parsers)
# ======================================================================================================

def fold(text: Any) -> str:
    """Accent-fold and casefold keeping one output character per input character (offsets stay valid)."""
    if not isinstance(text, str):
        return ""
    out = []
    for ch in text:
        if ch.isascii():
            out.append(ch.lower())
            continue
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)).casefold()
        out.append(base[:1] if base else " ")
    return "".join(out)


def _digits(value: Any) -> str:
    return "".join(ch for ch in value if "0" <= ch <= "9") if isinstance(value, str) else ""


def mask_cpf(cpf: Any) -> str | None:
    """Government masking pattern '***.456.789-**' (AR24)."""
    d = _digits(cpf)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else None


def mask_cpfs_in_text(text: Any) -> str:
    """Mask every CPF-shaped number (valid or not) in ``text``."""
    if not isinstance(text, str):
        return ""
    return _CPF_RE.sub(lambda m: f"***.{m.group(2)}.{m.group(3)}-**", text)


def find_cpfs(text: str) -> list[dict[str, Any]]:
    """CPF occurrences [{start, end, kind full|masked, valid, masked, _digits}]; the digits never leave memory."""
    out: list[dict[str, Any]] = []
    for m in _CPF_RE.finditer(text):
        d = "".join(m.groups())
        out.append({"start": m.start(), "end": m.end(), "kind": "full", "valid": cpf_valid(d), "masked": mask_cpf(d),
                    "_digits": d})
    for m in _MASKED_CPF_RE.finditer(text):
        out.append({"start": m.start(), "end": m.end(), "kind": "masked", "valid": None,
                    "masked": f"***.{m.group(1)}.{m.group(2)}-**", "_digits": None})
    out.sort(key=lambda c: c["start"])
    return out


def name_regex(name: Any) -> re.Pattern[str] | None:
    """Accent/case-insensitive regex of a full name (any punctuation, <= 10 chars, between the parts)."""
    parts = [p for p in re.split(r"[^0-9a-z]+", fold(name)) if p] if isinstance(name, str) else []
    if len(parts) < 2 or sum(len(p) for p in parts) < 5:
        return None
    sep = r"[^0-9a-z]{1,10}"
    return re.compile(r"(?<![0-9a-z])" + sep.join(re.escape(p) for p in parts) + r"(?![0-9a-z])")


def document_layout(text: str, cands: list[dict[str, Any]] | None = None) -> str:
    """'lines' when the document lists one record per line (tables, CSV), else 'prose'."""
    if cands is None:
        cands = find_cpfs(text)
    if len(cands) < 3:
        return "prose"
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    per_line: dict[int, list[dict[str, Any]]] = {}
    record_lines = 0
    for c in cands:
        per_line.setdefault(bisect.bisect_right(starts, c["start"]) - 1, []).append(c)
    for ln, cs in per_line.items():
        if len(cs) != 1:
            continue
        ls = starts[ln]
        le = starts[ln + 1] - 1 if ln + 1 < len(starts) else len(text)
        rest = text[ls:cs[0]["start"]] + " " + text[cs[0]["end"]:le]
        words = [w for w in re.findall(r"[a-z]{2,}", fold(rest)) if w not in _LABEL_WORDS]
        if len(words) >= 2:
            record_lines += 1
    return "lines" if record_lines >= 3 and record_lines >= 0.6 * len(per_line) else "prose"


def _choose_cpf(text: str, folded: str, s: int, e: int, cands: list[dict[str, Any]], layout: str) -> tuple[dict[str, Any] | None, bool]:
    """The CPF of the name at [s, e): same record only; then a 'CPF' label after the name, then no line break,
    then the smallest distance, then 'after'."""
    scored = []
    for c in cands:
        if c["start"] >= e:
            side, gap_s, gap_e = "after", e, c["start"]
        elif c["end"] <= s:
            side, gap_s, gap_e = "before", c["end"], s
        else:
            continue
        gap = text[gap_s:gap_e]
        if layout == "lines":
            if "\n" in gap:
                continue
        elif _STRONG_SEP_RE.search(gap):
            continue
        labelled = bool(_CPF_LABEL_RE.search(folded[gap_s:gap_e])) and side == "after"
        key = (0 if labelled else 1, 1 if "\n" in gap else 0, len(gap), 0 if side == "after" else 1)
        scored.append((key, side, len(gap), c))
    if not scored:
        return None, False
    scored.sort(key=lambda t: t[0])
    best = scored[0]
    ambiguous = (len(scored) > 1 and scored[1][0][:2] == best[0][:2] and abs(scored[1][2] - best[2]) <= 3
                 and scored[1][3]["masked"] != best[3]["masked"])
    return {"cpf": best[3], "side": best[1], "distance": best[2]}, ambiguous


def identity_signals(text: str, person_name: str, cpf: str | None = None, city: str | None = None,
                     uf: str | None = None, max_window: int = MAX_WINDOW) -> dict[str, Any]:
    """Identity signals of one typed person inside one case document (masked CPFs only in the output)."""
    res: dict[str, Any] = {"name_found": False, "occurrences": 0, "windows": [], "nearest_cpf_masked": None,
                           "typed_cpf": None, "signals": [], "confidence": "none", "criterion": None, "alert": None,
                           "layout": None, "errors": []}
    rx = name_regex(person_name)
    if rx is None:
        res["errors"].append("name needs at least two parts")
        res["criterion"] = "name too short to search"
        return res
    if not isinstance(text, str) or not text:
        res["criterion"] = "empty document"
        return res
    folded = fold(text)
    cands = find_cpfs(text)
    layout = document_layout(text, cands)
    res["layout"] = layout
    typed = _digits(cpf) if cpf is not None else None
    if typed is not None and not cpf_valid(typed):
        res["errors"].append("typed CPF is not valid (check digits)")
        typed = None
    city_rx = None
    if isinstance(city, str) and city.strip():
        cparts = [p for p in re.split(r"[^0-9a-z]+", fold(city)) if p]
        if cparts:
            city_rx = re.compile(r"(?<![0-9a-z])" + r"[^0-9a-z]{1,3}".join(map(re.escape, cparts)) + r"(?![0-9a-z])")
    uf_code = uf.strip().upper() if isinstance(uf, str) and uf.strip().upper() in UF_CODES else None
    uf_rx = re.compile(rf"(?<![0-9A-Za-z]){uf_code}(?![0-9A-Za-z])") if uf_code else None
    best_overall = None
    choices: list[dict[str, Any] | None] = []
    for m in rx.finditer(folded):
        s, e = m.start(), m.end()
        radius = max(0, (max_window - (e - s)) // 2)
        ws, we = max(0, s - radius), min(len(text), e + radius)
        in_window = [c for c in cands if c["start"] >= ws and c["end"] <= we]
        choice, ambiguous = _choose_cpf(text, folded, s, e, in_window, layout)
        choices.append(choice)
        res["windows"].append({
            "start": ws, "end": we, "excerpt": mask_cpfs_in_text(text[ws:we]),
            "nearest_cpf_masked": choice["cpf"]["masked"] if choice else None,
            "cpf_kind": choice["cpf"]["kind"] if choice else None,
            "cpf_side": choice["side"] if choice else None,
            "cpf_distance": choice["distance"] if choice else None,
            "ambiguous": ambiguous,
            "city_near": bool(city_rx.search(folded[ws:we])) if city_rx else False,
            "uf_near": bool(uf_rx.search(text[ws:we])) if uf_rx else False,
        })
        if choice and (best_overall is None or choice["distance"] < best_overall["distance"]):
            best_overall = choice
    res["occurrences"] = len(res["windows"])
    res["name_found"] = res["occurrences"] > 0
    if not res["name_found"]:
        res["criterion"] = "name not found in this document"
        if typed is not None:
            res["typed_cpf"] = {"masked": mask_cpf(typed), "found_in_document": any(c["_digits"] == typed for c in cands),
                                "next_to_name": False}
        return res
    signals: list[str] = []
    score = 0
    if best_overall:
        res["nearest_cpf_masked"] = best_overall["cpf"]["masked"]
    if any(w["city_near"] for w in res["windows"]):
        signals.append("city_near_name")
        score += 2
    elif any(w["uf_near"] for w in res["windows"]):
        signals.append("uf_near_name")
        score += 1
    elif uf_rx is not None and uf_rx.search(text):
        signals.append("uf_in_document")
    attached = [c["cpf"] for c in choices if c]
    if typed is not None:
        next_to = any(c["_digits"] == typed for c in attached)
        res["typed_cpf"] = {"masked": mask_cpf(typed), "found_in_document": any(c["_digits"] == typed for c in cands),
                            "next_to_name": next_to}
        if next_to:
            signals.append("typed_cpf_next_to_name")
            score += 4
        elif any(c["kind"] == "full" for c in attached):
            signals.append("different_cpf_next_to_name")
            res["alert"] = "a different CPF is next to this name (possible homonym)"
        elif any(c["kind"] == "masked" for c in attached):
            signals.append("masked_cpf_next_to_name")  # never compared with the typed digits (no fragment join)
            score += 1
    elif attached:
        signals.append("cpf_next_to_name")
        score += 1
    if any(w["ambiguous"] for w in res["windows"]):
        signals.append("ambiguous_cpf")
    res["signals"] = signals
    if res["alert"]:
        res["confidence"] = "weak"
    elif score >= 4:
        res["confidence"] = "strong"
    elif score >= 2:
        res["confidence"] = "medium"
    else:
        res["confidence"] = "weak"
    if "typed_cpf_next_to_name" in signals:
        res["criterion"] = "typed CPF next to the name"
    elif res["alert"]:
        res["criterion"] = "name found; another CPF is next to it"
    elif "masked_cpf_next_to_name" in signals:
        res["criterion"] = "name found next to a masked CPF - the analyst compares (no fragment join)"
    elif "cpf_next_to_name" in signals:
        res["criterion"] = "name found next to a CPF"
    else:
        res["criterion"] = "name found without a CPF nearby (homonyms possible)"
    return res


# ======================================================================================================
# case documents
# ======================================================================================================

def _case_graph(ctx: Any) -> Any:
    runtime = getattr(ctx, "runtime", None)
    pctx = getattr(runtime, "policy_context", None)
    return getattr(pctx, "graph", None)


def _snapshot(items: Any) -> list[Any]:
    for _ in range(3):  # the engine thread may grow the live graph while this worker reads it
        try:
            return list(items or ())
        except RuntimeError:
            continue
    return []


def _read_text_file(path: str) -> str | None:
    """Text of a regular text file of at most 20 MB (FIFOs/devices refused), else None."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not _stat.S_ISREG(st.st_mode) or st.st_size > MAX_READ or os.path.splitext(path)[1].lower() not in TEXT_EXT:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_READ)
    except OSError:
        return None


def case_documents(ctx: Any) -> tuple[list[tuple[str, str]], list[str], dict[str, Any]]:
    """(documents [(label, text)], skipped labels, hints {'cpfs': [...], 'city', 'uf'}) from the typed seeds of the
    running investigation. Labels never carry document text: 'text_blob #n (sha256:12)' or the file name."""
    graph = _case_graph(ctx)
    docs: list[tuple[str, str]] = []
    skipped: list[str] = []
    hints: dict[str, Any] = {"cpfs": [], "city": None, "uf": None}
    if graph is None:
        return docs, skipped, hints
    seeds = [n for n in _snapshot(getattr(graph, "nodes", {}).values()) if getattr(n, "seed", False)]
    n_text = 0
    for node in seeds:
        ent = node.entity
        if ent.type is T.TEXT and len(docs) < MAX_DOCUMENTS:
            n_text += 1
            digest = hashlib.sha256(ent.value.encode("utf-8", "replace")).hexdigest()[:12]
            docs.append((f"text_blob #{n_text} (sha256 {digest})", ent.value))
        elif ent.type is T.FILE and len(docs) < MAX_DOCUMENTS:
            label = os.path.basename(ent.value) or "file"
            text = _read_text_file(ent.value)
            if text is None:
                skipped.append(label)
            else:
                docs.append((label, text))
        elif ent.type is T.CPF:
            hints["cpfs"].append(ent.value)
        elif ent.type is T.KEYWORD:
            m = _HINT_RE.match(ent.value)
            if m:
                key, val = m.group(1).lower(), m.group(2).strip()
                if key in ("uf", "estado") and val.upper() in UF_CODES:
                    hints["uf"] = val.upper()
                elif key not in ("uf", "estado"):
                    hints["city"] = val
    return docs, skipped, hints


@register
class DocumentIdentitySignals(Module):
    name = "document_identity_signals"
    title = "Identity signals in case documents (name + nearest CPF)"
    description = ("Finds a typed person's name in the case's own text documents and reports the nearest CPF of the "
                   "same record (masked), city/UF signals and a confidence - offline, never a CPF lookup.")
    category = "file_analysis"
    accepts = {T.PERSON}
    produces = frozenset()
    tags = {"offline", "brazil"}
    reference = "https://www.gov.br/anpd/pt-br"
    notice = ("Personal data (LGPD): runs only on a typed person seed with a recorded purpose and only over the case's "
              "own documents; CPFs are shown masked, never looked up, never indexed across cases or exported.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    run_on = "seeds"
    max_pivots = 0
    timeout = 60.0
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not bool(getattr(ctx, "is_seed", True)):
            return res.mark(Status.SKIPPED, "runs only for person seeds the analyst typed", reason_code="privacy")
        if name_regex(entity.value) is None:
            return res.mark(Status.SKIPPED, "the name needs at least two parts to be searched", reason_code="not_applicable")
        docs, skipped, hints = case_documents(ctx)
        if not docs:
            why = "no text document attached to this case (add the documents as text_blob/file seeds of the same scan)"
            if skipped:
                why += f"; {len(skipped)} attached file(s) have no extracted text yet (PDF/image text from P269/P363)"
            return res.mark(Status.SKIPPED, why, reason_code="not_applicable")
        typed_cpfs = [c for c in hints["cpfs"] if cpf_valid(_digits(c))]
        per_doc: list[dict[str, Any]] = []
        windows: list[dict[str, Any]] = []
        for label, text in docs:
            results = [identity_signals(text, entity.value, cpf=c, city=hints["city"], uf=hints["uf"])
                       for c in (typed_cpfs or [None])]
            best = max(results, key=lambda r: ({"strong": 3, "medium": 2, "weak": 1, "none": 0}[r["confidence"]],
                                               "typed_cpf_next_to_name" in r["signals"]))
            summary = {k: best[k] for k in ("name_found", "occurrences", "confidence", "criterion", "signals", "alert",
                                            "layout", "nearest_cpf_masked", "typed_cpf")}
            summary["document"] = label
            per_doc.append(summary)
            for w in best["windows"]:
                if len(windows) < MAX_WINDOWS_KEPT:
                    windows.append({"document": label, **{k: w[k] for k in ("excerpt", "nearest_cpf_masked", "cpf_kind",
                                                                         "cpf_side", "cpf_distance", "ambiguous",
                                                                         "city_near", "uf_near")}})
        found = [d for d in per_doc if d["name_found"]]
        rank = {"strong": 3, "medium": 2, "weak": 1, "none": 0}
        overall = max((d["confidence"] for d in found), key=lambda c: rank[c], default="none")
        res.raw = {"documents": per_doc, "windows": windows, "skipped_files": skipped,
                   "typed_cpfs_masked": [mask_cpf(c) for c in typed_cpfs], "privacy": True,
                   "cross_case_index": False, "export": False}
        res.attr("identity_signals", {"documents_searched": len(docs), "documents_with_name": len(found),
                                      "confidence": overall, "per_document": per_doc,
                                      "files_without_text": skipped or None})
        res.attr("identity_windows", windows)
        if not found:
            return res.mark(Status.EMPTY, f"name not found in the {len(docs)} case document(s) searched")
        for d in found:
            sev_conf = {"strong": "probable", "medium": "possible", "weak": "possible"}[d["confidence"]]
            desc = (f"{d['document']}: {d['occurrences']} occurrence(s); {d['criterion']}"
                    + (f"; nearest CPF in the same record {d['nearest_cpf_masked']}" if d["nearest_cpf_masked"] else "")
                    + (f". ALERT: {d['alert']}" if d["alert"] else "")
                    + ". The analyst reads the name-CPF pair; it is never indexed across cases or exported.")
            res.finding("Typed name found in a case document", "info", desc, confidence=sev_conf,
                        criterion=f"name window <= {MAX_WINDOW} chars; nearest CPF of the same record; {d['confidence']} signals",
                        data={"document": d["document"], "confidence": d["confidence"], "signals": d["signals"]},
                        tags=PRIVACY_TAGS, key=d["document"])
        return res
