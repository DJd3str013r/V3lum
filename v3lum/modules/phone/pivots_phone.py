"""Phone pivot links (P128): manual links for an analyst-typed phone seed. V3LUM never fetches them.

Disclosure ``none``: the module only builds URLs; ``ctx.http`` refuses every request.

* ``phone:spamcalls_num`` from the data pack ``v3lum/data/pivot_links/phone.json`` (caller reports,
  labelled 'user reports, unverified'; spamcalls.net is a community-tier host);
* ABR Telecom's Consulta Número page for +55 numbers (the current operator after portability). Its form
  is a POST behind reCAPTCHA, so the link is static: it carries no value and the analyst types the
  number on the page (manual only, A9);
* the messaging links ``https://wa.me/{digits}`` and ``https://t.me/+{digits}``, OFF by default (setting
  ``phone_messaging_links``, P128 cond 2). They open the app with the analyst's own account and are
  never fetched or used as presence checks (P131 stays rejected).

Privacy (P128 cond 4, P311 cond 6): phone links are privacy links. They are emitted only for
analyst-typed seeds of a case that opted in (``--show-personal`` with a recorded ``--purpose``, the
engine's opt-in rule for privacy links) and never for auto-discovered numbers; otherwise the run is
SKIPPED 'privacy'. Every link is rendered through ``v3lum.core.links`` (whitelist placeholders, the
P311 lint and the provider-registry tiers: spamcalls.net community, wa.me/t.me/ABR Telecom trusted).
TLP (A2): at AMBER and above each label carries 'opening sends <number> to <host>' (the renderers show
links as non-clickable text there); at RED the module emits no link.
"""

from __future__ import annotations

from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import links as _links
from v3lum.core import tlp as _tlp
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SETTING = "phone_messaging_links"
SPAMCALLS_REF = "phone:spamcalls_num"
SPAMCALLS_BADGE = "user reports, unverified"
MESSAGING_NOTICE = "manual: opens the app with YOUR account; nothing is sent unless you type; use a team research device"
ABR_URL = "https://consultanumero.abrtelecom.com.br/consultanumero/consulta/consultaSituacaoAtualCtg"
ABR_HOST = "consultanumero.abrtelecom.com.br"
CHECKED_AT = "2026-11-26"
STATIC_NOTE = "manual: CAPTCHA, type the number on the page"

#: ABR Telecom: a static page (POST form + reCAPTCHA, no URL parameter): an inline-pack link without a
#: placeholder, rendered and linted by core/links.py with the registry tier of its host.
ABR_LINK = _links.PivotLink(
    pack=_links.INLINE_PACK,
    id="abrtelecom_consulta_numero",
    label="ABR Telecom Consulta Número: current operator after portability",
    template=ABR_URL,
    entity_types=(T.PHONE,),
    category="other",
    host=ABR_HOST,
    verified=True,
    checked_at=CHECKED_AT,
    privacy=True,
    antibot=True,
    notes="Static landing page: opening it sends nothing; typing the number there sends it to ABR Telecom.",
)
#: Messaging deep links (off by default): generic pages for any number, never fetched.
MESSAGING_LINKS: tuple[_links.PivotLink, ...] = (
    _links.PivotLink(
        pack="pivots_phone",
        id="whatsapp_chat",
        label="WhatsApp chat (wa.me)",
        template="https://wa.me/{wa}",
        entity_types=(T.PHONE,),
        category="social",
        host="wa.me",
        verified=True,
        checked_at=CHECKED_AT,
        privacy=True,
        notes="wa.me/{digits} redirects to api.whatsapp.com/send (Meta); generic for any number: never a presence check.",
    ),
    _links.PivotLink(
        pack="pivots_phone",
        id="telegram_chat",
        label="Telegram chat (t.me)",
        template="https://t.me/+{e164}",
        entity_types=(T.PHONE,),
        category="social",
        host="t.me",
        verified=True,
        checked_at=CHECKED_AT,
        privacy=True,
        notes="t.me/+{digits} answers a generic 'Chat with <number>' page: never a presence check.",
    ),
)


def opted_in(ctx: Any) -> bool:
    """Privacy links render only for analyst-typed seeds of a case that opted in (P311 cond 6): the same
    rule the engine applies to privacy manual links (``show_personal`` with a recorded ``purpose``)."""
    opts = getattr(ctx, "options", None)
    purpose = str(getattr(opts, "purpose", "") or "").strip()
    return bool(getattr(ctx, "is_seed", False) and getattr(opts, "show_personal", False) and purpose)


def tlp_level(ctx: Any) -> _tlp.TLP:
    """The run's TLP; an unreadable value fails closed to RED."""
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


def phone_links(entity: Entity, *, messaging: bool) -> tuple[list[tuple[_links.RenderedLink, str]], list[dict[str, str]]]:
    """The links that apply to ``entity`` -> ([(rendered link, kind)], hidden [{id, reason}]). Every link
    goes through ``links.render`` (lint + registry tier); a link that does not render is listed as hidden."""
    shown: list[tuple[_links.RenderedLink, str]] = []
    hidden: list[dict[str, str]] = []
    candidates: list[tuple[str, Any, str]] = [("spamcalls_num", SPAMCALLS_REF, "reputation")]
    if entity.value.startswith("+55"):
        candidates.append(("abrtelecom_consulta_numero", ABR_LINK, "static"))
    else:
        hidden.append({"id": "abrtelecom_consulta_numero", "reason": "Brazilian (+55) numbers only"})
    for link in MESSAGING_LINKS:
        if messaging:
            candidates.append((link.id, link, "messaging"))
        else:
            hidden.append({"id": link.id, "reason": f"off by default (setting {SETTING}=false)"})
    for ident, link, kind in candidates:
        rendered = _links.render(link, entity)
        if rendered is None:
            hidden.append({"id": ident, "reason": "did not render (lint, host tier or value)"})
        else:
            shown.append((rendered, kind))
    return shown, hidden


def link_label(entity: Entity, rendered: _links.RenderedLink, kind: str, level: _tlp.TLP) -> str:
    """The label shown with a link: the badge of user-report links, the notice of messaging links (P128
    cond 2) and, at TLP:AMBER and above, the A2 disclosure warning (a static page sends nothing until the
    analyst types the number)."""
    label = rendered.label
    if kind == "reputation" and SPAMCALLS_BADGE not in label:
        label = f"{label} ({SPAMCALLS_BADGE})"
    if kind == "messaging":
        label = f"{label} - {MESSAGING_NOTICE}"
    if kind == "static":
        label = f"{label} ({STATIC_NOTE})"
    if level >= _tlp.TLP.AMBER:
        if kind == "static":
            label += f" - opening sends nothing; typing {entity.display} on that page sends it to {rendered.host}"
        else:
            label += " - " + _links.disclosure_note(entity, rendered)
    return label


@register
class PivotsPhone(Module):
    name = "pivots_phone"
    title = "Phone pivot links (manual)"
    description = (
        "Manual pivot links for an analyst-typed phone seed: spamcalls.net caller reports (user reports, "
        "unverified), ABR Telecom's current-operator page for +55 numbers and, when enabled, WhatsApp/Telegram "
        "chat links. V3LUM never fetches them."
    )
    category = "phone"
    accepts = {T.PHONE}
    produces = frozenset()
    run_on = "seeds"  # privacy links: analyst-typed seeds only (P128 cond 4)
    reference = "https://spamcalls.net/en/page/contact"
    tags = {"offline", "brazil"}
    notice = (
        "Manual links only (never fetched). spamcalls.net shows user reports (unverified) and public per-number "
        "request counters; opening a link sends the number to its host. Messaging links are off by default "
        f"(setting {SETTING}): {MESSAGING_NOTICE}; never a presence check. ABR Telecom's page has a CAPTCHA: "
        "type the number yourself."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.01
    timeout = 10.0
    default_enabled = True
    settings = {
        SETTING: SettingSpec(
            False,
            "pivots_phone: also emit WhatsApp/Telegram chat links (wa.me/t.me) for opted-in phone seeds; they open "
            "the app with YOUR account (use a team research device) and are never presence checks",
        ),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bool(getattr(ctx, "is_seed", False))  # never auto-discovered numbers (P311 cond 6)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not opted_in(ctx):
            return res.mark(
                Status.SKIPPED,
                "phone pivot links are privacy links: shown only for analyst-typed seeds of a case that opted in (--show-personal with a --purpose)",
                reason_code="privacy",
            )
        level = tlp_level(ctx)
        if level is _tlp.TLP.RED:
            return res.mark(Status.SKIPPED, "TLP:RED: third-party pivot links are hidden from reports (v3lum links shows them with the warning)", reason_code="tlp")
        messaging = bool(ctx.setting(SETTING, False))
        shown, hidden = phone_links(entity, messaging=messaging)
        emitted = []
        for rendered, kind in shown:
            label = link_label(entity, rendered, kind, level)
            res.link(label, rendered.url)
            emitted.append({
                "id": rendered.ref.split(":", 1)[1], "kind": kind, "url": rendered.url, "host": rendered.host,
                "tier": rendered.tier, "clickable": level < _tlp.TLP.AMBER, "label": label,
                "notice": MESSAGING_NOTICE if kind == "messaging" else "",
            })
        res.raw = {"tlp": level.value_str, "messaging_links": messaging, "links": emitted, "hidden": hidden}
        return res
