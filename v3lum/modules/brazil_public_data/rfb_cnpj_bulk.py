"""P238 ``rfb_cnpj_bulk`` - offline lookups on the local RFB CNPJ open-data index.

The index is built only by the shared importer (``rfb_import.py``: ``v3lum data import-rfb``, outside any
scan). This module reads it offline (disclosure 'none'). Council P238 final conditions, as implemented here:

6. CNPJ root -> branches (head office taken from the index, never assumed /0001), company facts and PJ
   partners: company-centric, always available. Person-centric reverse lookups (partner name, e-mail, phone,
   address/CEP -> CNPJs) run only as explicit analyst queries: an analyst-typed seed, the module explicitly
   selected (``-M rfb_cnpj_bulk``), inside a case with a recorded purpose, within a per-case limit (setting
   ``rfb_cnpj_bulk_case_limit``, default 20, counted in ``ctx.state`` per case id); every lookup is recorded
   in the result (``rfb_reverse_lookup``, evidence) and logged; capped at the top 50 plus a total count.
7. Results are company-centric hypotheses: CNPJ pivots with expand=False; partner-name matches are POSSIBLE
   (name only, homonyms possible; the masked CPF is never used to split or join); no person dossiers, no
   person-centric attributes and no free-text person search.
8. Contacts shared by >= 20 companies (distinct CNPJ roots) are tagged ``shared_contact`` ('possible
   accountant/virtual office') and excluded from same-owner rules (P258: tag and attribute
   ``rfb_shared_contacts``). Every finding cites 'RFB snapshot YYYY-MM'.
9. Opt-in (default_enabled False); offline once imported. Without the index: UNAVAILABLE reason_code 'dataset'
   ('run v3lum data import-rfb'), with the last import problem (e.g. a rotated share token) and its hint, never
   'no companies'.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data import rfb_import as imp

SOURCE = imp.SOURCE
REVERSE_CAP = 50
CASE_LIMIT = 20
PERSON_KINDS = {T.PERSON: "partner_name", T.EMAIL: "email", T.PHONE: "phone", T.CEP: "address"}
UNAVAILABLE_TEXT = "RFB CNPJ index not imported: " + imp.IMPORT_HINT


def cnpj_format(c: str) -> str:
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if len(c) == 14 else c


class RfbIndex:
    """Read-only view of the installed ``rfb_cnpj.sqlite``."""

    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.meta = dict(self.conn.execute("SELECT k, v FROM meta").fetchall())
        self.tables = set((self.meta.get("tables") or "").split(","))

    def close(self) -> None:
        self.conn.close()

    @property
    def snapshot(self) -> str:
        return self.meta.get("snapshot") or "unknown"

    def lookup(self, table: str, code: Any) -> str | None:
        row = self.conn.execute("SELECT descricao FROM lookups WHERE tbl = ? AND codigo = ?", (table, str(code or ""))).fetchone()
        return row[0] if row else None

    def company(self, root: str) -> dict[str, Any] | None:
        if "empresas" not in self.tables:
            return None
        row = self.conn.execute("SELECT razao_social, natureza, porte, capital FROM empresas WHERE cnpj_basico = ? LIMIT 1", (root,)).fetchone()
        if row is None:
            return None
        return {"razao_social": row[0], "natureza": row[1], "porte": row[2], "capital": row[3]}

    def establishment(self, cnpj: str) -> dict[str, Any] | None:
        cur = self.conn.execute("SELECT * FROM estabelecimentos WHERE cnpj = ? LIMIT 1", (cnpj,))
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip([d[0] for d in cur.description], row, strict=True))

    def branches(self, root: str, limit: int = REVERSE_CAP) -> tuple[list[dict[str, Any]], int]:
        total = self.conn.execute("SELECT COUNT(*) FROM estabelecimentos WHERE cnpj_basico = ?", (root,)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT cnpj, matriz, situacao, uf, municipio FROM estabelecimentos WHERE cnpj_basico = ? "
            "ORDER BY matriz DESC, situacao != 'ATIVA', cnpj LIMIT ?", (root, limit),
        ).fetchall()
        return [{"cnpj": r[0], "matriz": bool(r[1]), "situacao": r[2], "uf": r[3], "municipio": r[4]} for r in rows], int(total)

    def hq(self, root: str) -> str | None:
        row = self.conn.execute("SELECT cnpj FROM estabelecimentos WHERE cnpj_basico = ? AND matriz = 1 LIMIT 1", (root,)).fetchone()
        return row[0] if row else None

    def simples(self, root: str) -> dict[str, Any] | None:
        if "simples" not in self.tables:
            return None
        row = self.conn.execute("SELECT simples, simples_desde, simples_excluido, mei, mei_desde, mei_excluido FROM simples "
                                "WHERE cnpj_basico = ? LIMIT 1", (root,)).fetchone()
        if row is None:
            return None
        return {"simples": {"optante": None if row[0] is None else bool(row[0]), "since": row[1], "excluded": row[2]},
                "mei": {"optante": None if row[3] is None else bool(row[3]), "since": row[4], "excluded": row[5]}}

    def pj_partners(self, root: str) -> list[dict[str, Any]]:
        if "socios" not in self.tables:
            return []
        rows = self.conn.execute("SELECT socio_cnpj, qualificacao, data_entrada FROM socios WHERE cnpj_basico = ? AND tipo = 'pj' "
                                 "AND socio_cnpj IS NOT NULL LIMIT 50", (root,)).fetchall()
        return [{"cnpj": r[0], "qualificacao": r[1], "since": r[2]} for r in rows]

    def contacts_of(self, cnpj: str) -> list[tuple[str, str]]:
        return [(r[0], r[1]) for r in self.conn.execute("SELECT kind, key FROM contact_keys WHERE cnpj = ? AND kind != 'cep'", (cnpj,))]

    def shared_roots(self, kind: str, key: str) -> int | None:
        row = self.conn.execute("SELECT roots FROM shared_contacts WHERE kind = ? AND key = ?", (kind, key)).fetchone()
        return int(row[0]) if row else None

    def by_contact(self, kind: str, key: str, limit: int = REVERSE_CAP) -> tuple[list[dict[str, Any]], int]:
        total = self.conn.execute("SELECT COUNT(DISTINCT cnpj) FROM contact_keys WHERE kind = ? AND key = ?", (kind, key)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT e.cnpj, e.matriz, e.situacao FROM contact_keys c JOIN estabelecimentos e ON e.cnpj = c.cnpj "
            "WHERE c.kind = ? AND c.key = ? GROUP BY e.cnpj ORDER BY e.situacao != 'ATIVA', e.matriz DESC, e.cnpj LIMIT ?",
            (kind, key, limit),
        ).fetchall()
        return [{"cnpj": r[0], "matriz": bool(r[1]), "situacao": r[2]} for r in rows], int(total)

    def by_partner_name(self, name_key: str, limit: int = REVERSE_CAP) -> tuple[list[dict[str, Any]], int]:
        """Companies whose QSA lists a natural-person or foreign partner with this normalised name (never the CPF)."""
        total = self.conn.execute("SELECT COUNT(DISTINCT cnpj_basico) FROM socios WHERE name_key = ? AND tipo IN ('pf', 'estrangeiro')",
                                  (name_key,)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT cnpj_basico, MIN(qualificacao), MIN(data_entrada) FROM socios WHERE name_key = ? AND tipo IN ('pf', 'estrangeiro') "
            "GROUP BY cnpj_basico ORDER BY cnpj_basico LIMIT ?", (name_key, limit),
        ).fetchall()
        return [{"cnpj_basico": r[0], "qualificacao": r[1], "since": r[2]} for r in rows], int(total)

    def by_company_name(self, name: str, limit: int = REVERSE_CAP) -> list[dict[str, Any]]:
        key = imp.match_key(name)
        rows = self.conn.execute("SELECT cnpj_basico, razao_social, natureza FROM empresas WHERE razao_social = ? LIMIT ?",
                                 (name.strip().upper(), limit * 4)).fetchall()
        out = []
        for root, razao, natureza in rows:
            if imp.match_key(razao) == key and (natureza or "") not in imp.EI_NATUREZAS:
                out.append({"cnpj_basico": root, "razao_social": razao})
        return out[:limit]


def index_path(home: Path | None = None) -> Path:
    base = Path(home) if home is not None else paths.datasets_dir()
    return base / imp.INDEX_DIR / imp.INDEX_FILE


def open_index(home: Path | None = None) -> tuple[RfbIndex | None, str]:
    """The installed index (never downloads) or (None, why)."""
    path = index_path(home)
    if not path.is_file():
        return None, "missing"
    try:
        idx = RfbIndex(path)
    except sqlite3.Error:
        return None, "unreadable"
    if idx.meta.get("schema") != imp.INDEX_SCHEMA:
        idx.close()
        return None, "format"
    return idx, ""


def company_name_for(cnpj: str) -> tuple[str | None, str | None]:
    """(razao social, natureza) of a CNPJ from the local index, or (None, None) - used by dou_search."""
    idx, _ = open_index()
    if idx is None:
        return None, None
    try:
        rec = idx.company(imp.cnpj_clean(cnpj)[:8])
    finally:
        idx.close()
    return (rec["razao_social"], rec["natureza"]) if rec else (None, None)


def _contact_key(etype: Any, value: str) -> tuple[str, str] | None:
    """(kind, key) of a person-centric seed in the index's normalised form."""
    if etype is T.EMAIL:
        return ("email", value.strip().lower())
    if etype is T.PHONE:
        digits = imp.only_digits(value)
        if digits.startswith("55") and len(digits) in (12, 13):
            digits = digits[2:]
        return ("phone", digits.lstrip("0")) if 10 <= len(digits) <= 11 else None
    if etype is T.CEP:
        digits = imp.only_digits(value)
        return ("cep", digits) if len(digits) == 8 else None
    return None


@register
class RfbCnpjBulk(Module):
    name = "rfb_cnpj_bulk"
    title = "RFB CNPJ open data (local index: branches, shared contacts, purpose-bound reverse lookups)"
    description = (
        "Offline lookups on the RFB CNPJ open-data dump imported by `v3lum data import-rfb`: CNPJ root -> branches and "
        "head office, contacts shared by many companies (possible accountant/virtual office), and - only as explicit "
        "purpose-bound analyst queries - partner name, e-mail, phone or CEP -> CNPJs (top 50 plus a count)."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.PERSON, T.EMAIL, T.PHONE, T.CEP}
    produces = {T.CNPJ}
    tags = {"brazil", "offline", "bulk_download"}
    reference = "https://dados.gov.br/dados/conjuntos-dados/cadastro-nacional-da-pessoa-juridica---cnpj"
    notice = (
        "Local index of the RFB CNPJ open-data dump (imported outside scans; nothing is sent during a scan). Person-centric "
        "reverse lookups only on analyst-typed seeds with -M rfb_cnpj_bulk, in a case with a recorded purpose, capped and "
        "limited per case; partner-name matches are name-only hypotheses (homonyms), never person dossiers. Masked CPFs are "
        "never shown, joined or completed. Findings cite 'RFB snapshot YYYY-MM'."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 0.3
    timeout = 30.0
    max_pivots = 60
    default_enabled = False  # A3/P238 cond 9: opt-in (bulk download, person-centric lookups)
    settings = {
        "rfb_cnpj_bulk_share_link": "",
        "rfb_cnpj_bulk_share_source": "",
        "rfb_cnpj_bulk_share_checked_at": "",
        "rfb_cnpj_bulk_case_limit": CASE_LIMIT,
        "rfb_cnpj_bulk_chunk_mb": 16,
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind = PERSON_KINDS.get(entity.type)
        if kind is not None:
            refusal = self._person_refusal(ctx, kind)
            if refusal:
                return res.mark(Status.SKIPPED, refusal, reason_code="privacy")
        idx, problem = open_index()
        if idx is None:
            last = (imp.read_state().get("last_import") or {})
            extra = ""
            if last.get("status") and last.get("status") != "imported":
                extra = f" (last import {last.get('at', '?')}: {last.get('reason', '')[:160]}" + (f"; {last['hint']}" if last.get("hint") else "") + ")"
            why = "local index has an unknown schema: re-import" if problem == "format" else UNAVAILABLE_TEXT
            return res.mark(Status.UNAVAILABLE, why + extra + "; never read as 'no companies'", reason_code="dataset")
        try:
            label = imp.snapshot_label(idx.snapshot) if imp.MONTH_RE.match(idx.snapshot) else f"RFB snapshot {idx.snapshot}"
            res.attr("rfb_snapshot", idx.snapshot)
            self._cite(ctx, idx)
            if entity.type is T.CNPJ:
                return self._cnpj(res, idx, str(entity.value), label)
            if entity.type is T.ORG:
                return self._company_name(res, ctx, idx, str(entity.value), label)
            return self._reverse(res, ctx, idx, entity, kind or "", label)
        except sqlite3.Error as exc:
            return res.mark(Status.ERROR, f"local RFB index unreadable ({type(exc).__name__}): could not verify", reason_code="error")
        finally:
            idx.close()

    # ------------------------------------------------------------------ gates (cond 6)
    def _person_refusal(self, ctx: Any, kind: str) -> str:
        if not getattr(ctx, "is_seed", False):
            return f"{kind} -> CNPJs runs only on analyst-typed seeds (never on pivots)"
        if self.name not in set(getattr(getattr(ctx, "options", None), "include", ()) or ()):
            return f"{kind} -> CNPJs is an explicit analyst query: select the module (-M {self.name})"
        if not str(getattr(ctx, "case_id", "") or "").strip():
            return f"{kind} -> CNPJs runs only inside a case"
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return f"{kind} -> CNPJs needs a recorded purpose (--purpose)"
        limit = int(ctx.setting("rfb_cnpj_bulk_case_limit", CASE_LIMIT) or CASE_LIMIT)
        used = int(ctx.state.get(self._case_key(ctx), 0) or 0)
        if used >= limit:
            return f"per-case limit of {limit} person-centric RFB lookups reached (setting rfb_cnpj_bulk_case_limit)"
        return ""

    @staticmethod
    def _case_key(ctx: Any) -> str:
        return f"case_lookups:{str(getattr(ctx, 'case_id', '') or '')[:64]}"

    def _count_lookup(self, ctx: Any) -> int:
        key = self._case_key(ctx)
        used = int(ctx.state.get(key, 0) or 0) + 1
        ctx.state.set(key, used)
        return used

    @staticmethod
    def _cite(ctx: Any, idx: RfbIndex) -> None:
        used = getattr(getattr(ctx, "data", None), "used", None)
        if isinstance(used, list) and not any(isinstance(c, dict) and c.get("name") == "rfb_cnpj_bulk.index" for c in used):
            used.append({"name": "rfb_cnpj_bulk.index", "sha256": "", "fetched_at": idx.meta.get("imported_at", ""),
                         "licence": "Dados abertos RFB (open government data)", "snapshot": idx.snapshot})

    # ------------------------------------------------------------------ company-centric (always available)
    def _cnpj(self, res: ModuleResult, idx: RfbIndex, value: str, label: str) -> ModuleResult:
        cnpj = imp.cnpj_clean(value)
        root = cnpj[:8]
        est = idx.establishment(cnpj)
        comp = idx.company(root)
        branches, total = idx.branches(root)
        if est is None and comp is None and not branches:
            return res.mark(Status.EMPTY, f"CNPJ not in the local index ({label}; companies opened after the snapshot are missing)")
        if comp:
            res.attr("legal_name", comp["razao_social"])
            nat = comp.get("natureza")
            if nat:
                res.attr("legal_nature", {"code": nat, "label": idx.lookup("naturezas", nat)})
            res.attr("company_size", comp.get("porte"))
            res.attr("capital", comp.get("capital"))
        if est:
            res.attr("branch_type", "MATRIZ" if est.get("matriz") else "FILIAL")
            res.attr("trade_name", est.get("nome_fantasia"))
            res.attr("status", est.get("situacao"))
            res.attr("status_date", est.get("data_situacao"))
            res.attr("opened", est.get("data_inicio"))
            res.attr("cnae", est.get("cnae"))
        sim = idx.simples(root)
        if sim:
            res.attr("simples_nacional", sim["simples"])
            res.attr("mei", sim["mei"])
        hq = idx.hq(root)
        res.attr("rfb_hq_cnpj", hq)
        res.attr("rfb_branches", {"total": total, "shown": branches, "snapshot": idx.snapshot})
        for b in branches:
            if b["cnpj"] != cnpj:
                res.pivot(T.CNPJ, b["cnpj"], "same_cnpj_root", confidence="confirmed", expand=False,
                          note=f"same CNPJ root ({'head office' if b['matriz'] else 'branch'}), {label}")
        for p in idx.pj_partners(root):
            res.pivot(T.CNPJ, p["cnpj"], "partner_of", confidence="confirmed", expand=False, note=f"PJ partner in the QSA, {label}")
        shared = []
        if est:
            for kind, key in idx.contacts_of(cnpj):
                roots = idx.shared_roots(kind, key)
                if roots:
                    shared.append({"kind": kind, "companies": roots, "label": imp.SHARED_CONTACT_LABEL})
        if shared:
            res.attr("rfb_shared_contacts", shared)
            res.finding(
                "Registered contact shared by many companies", "info",
                "; ".join(f"{s['kind']} shared by {s['companies']} companies" for s in shared) + f" ({label})",
                confidence="probable", source=SOURCE, tags=["shared_contact", "context_only"],
                criterion=f"the same RFB {', '.join(sorted({s['kind'] for s in shared}))} is registered for >= "
                f"{imp.SHARED_CONTACT_THRESHOLD} distinct companies: {imp.SHARED_CONTACT_LABEL}; never same-owner evidence",
                data={"shared": shared, "snapshot": idx.snapshot},
            )
        if total > len(branches):
            res.finding("Many establishments under this CNPJ root", "info", f"{total} establishments, first {len(branches)} listed ({label})",
                        source=SOURCE, data={"total": total, "snapshot": idx.snapshot}, tags=["info"])
        return res

    def _company_name(self, res: ModuleResult, ctx: Any, idx: RfbIndex, name: str, label: str) -> ModuleResult:
        if not getattr(ctx, "is_seed", False):
            return res.mark(Status.SKIPPED, "company names are resolved only when analyst-typed", reason_code="not_applicable")
        if "empresas" not in idx.tables:
            return res.mark(Status.UNAVAILABLE, "the local RFB index has no Empresas table: re-import", reason_code="dataset")
        found = idx.by_company_name(name)
        if not found:
            return res.mark(Status.EMPTY, f"no company with this exact razao social in the local index ({label})")
        for f in found:
            hq = idx.hq(f["cnpj_basico"])
            if hq:
                res.pivot(T.CNPJ, hq, "legal_name", confidence="probable" if len(found) == 1 else "possible", expand=False,
                          note=f"exact razao social match, {label}: confirm before following")
        res.finding("Exact razao social match in the RFB index", "info", f"{len(found)} company(ies) ({label})", source=SOURCE,
                    confidence="probable" if len(found) == 1 else "possible", data={"matches": len(found), "snapshot": idx.snapshot})
        return res

    # ------------------------------------------------------------------ person-centric (cond 6-8)
    def _reverse(self, res: ModuleResult, ctx: Any, idx: RfbIndex, entity: Entity, kind: str, label: str) -> ModuleResult:
        needed = "socios" if kind == "partner_name" else "estabelecimentos"
        if needed not in idx.tables:
            return res.mark(Status.UNAVAILABLE, f"the local RFB index has no {needed} table: re-import with --tables qsa",
                            reason_code="dataset")
        used = self._count_lookup(ctx)
        shared_roots = None
        if kind == "partner_name":
            name_key = imp.match_key(entity.value)
            rows, total = idx.by_partner_name(name_key)
            results = [{"cnpj": idx.hq(r["cnpj_basico"]), "root": r["cnpj_basico"], "qualificacao": idx.lookup("qualificacoes", r["qualificacao"])
                        or r["qualificacao"], "since": r["since"]} for r in rows]
        else:
            ck = _contact_key(entity.type, str(entity.value))
            if ck is None:
                return res.mark(Status.SKIPPED, f"not a lookup key for {kind}", reason_code="not_applicable")
            rows, total = idx.by_contact(*ck)
            results = [{"cnpj": r["cnpj"], "matriz": r["matriz"], "situacao": r["situacao"]} for r in rows]
            if ck[0] != "cep":
                shared_roots = idx.shared_roots(*ck)
        audit = {"kind": kind, "total": total, "shown": len(results), "truncated": total > len(results), "snapshot": idx.snapshot,
                 "purpose_recorded": True, "case_lookups": used}
        res.attr("rfb_reverse_lookup", audit)
        ctx.log(f"rfb_cnpj_bulk: purpose-bound {kind} reverse lookup #{used} in case {getattr(ctx, 'case_id', '')} "
                f"({total} companies, {label})", "info")
        res.raw = {"lookup": audit, "companies": [{k: v for k, v in r.items() if k != "qualificacao"} for r in results]}
        if not results:
            return res.mark(Status.EMPTY, f"no company with this {kind.replace('_', ' ')} in the local index ({label})")
        relation = "partner_name_match" if kind == "partner_name" else "rfb_contact_of"
        confidence = "possible" if kind == "partner_name" else "probable"
        for r in results:
            if r.get("cnpj"):
                res.pivot(T.CNPJ, r["cnpj"], relation, confidence=confidence, expand=False,
                          note=("name-only partner match (homonyms possible)" if kind == "partner_name" else f"registered {kind}") + f", {label}")
        tags = ["name_only_match"] if kind == "partner_name" else []
        if shared_roots:
            tags.append("shared_contact")
            res.attr("rfb_shared_contacts", [{"kind": kind, "companies": shared_roots, "label": imp.SHARED_CONTACT_LABEL}])
        if kind == "partner_name":
            title, crit = ("Partner-name matches in the RFB QSA (name only)",
                           f"same normalised partner name in the QSA of {total} company(ies): name-only, homonyms possible, never confirmed "
                           f"by CPF fragments ({label})")
        else:
            title, crit = (f"Companies registered with this {kind}",
                           f"{total} establishment(s) registered with this {kind} in the RFB open data ({label})"
                           + (f"; shared by {shared_roots} companies: {imp.SHARED_CONTACT_LABEL}, never same-owner evidence" if shared_roots else ""))
        res.finding(title, "info", f"{total} found, top {len(results)} listed ({label})", confidence=confidence, source=SOURCE,
                    criterion=crit, tags=tags, data={"total": total, "shown": len(results), "snapshot": idx.snapshot,
                                                    "cnpjs": [r.get("cnpj") for r in results if r.get("cnpj")]})
        return res


__all__ = ["RfbCnpjBulk", "RfbIndex", "company_name_for", "index_path", "open_index"]
