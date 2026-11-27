"""Site contacts (P077, batch p9-G03-2): one extractor, two modules.

* ``site_contacts`` (LIGHT, opt-in): live contact/about/footer pages of an analyst-typed seed through
  the shared safe-fetch helper (``light_fetch.fetch_homepage`` / ``safe_get`` over ``ctx.http``: LIGHT
  egress profile, ``ua_light``, seeds only, redirects followed by hand with every hop checked - seed
  binding, same registrable domain, ports, per-recipient token URLs - and re-checked by the core after
  resolution, 25 requests per target host per scan); robots.txt honoured (urllib.robotparser).
* ``site_contacts_archive`` (PASSIVE, opt-in): the same extractor over archived snapshots (Wayback
  ``id_`` bodies, at most 5 pages, the P059 client helpers); no target contact.

Final conditions (P077) and where they live:

1. two modules over one extractor (:func:`extract_contacts` + :func:`contacts_policy`); both
   default_enabled False. The homepage 'already fetched by web_fingerprint' is reused through the shared
   safe fetch (``fetch_homepage``: same URL, no Accept header, same 1 MB cap and TTL, one cache row per
   hop) in the LIGHT module; the PASSIVE module has no access to it (core request: a read-only view of
   the case's fetched pages).
2. LIGHT: run_on 'seeds' (the core refuses pivots, binds requests to the seed host and its
   subdomains, applies the P376 guard and the P334/A7 LIGHT budget).
3. crawl bounds (:func:`plan_crawl`): at most 10 pages of the seed host (and its subdomains) inside
   the same registrable domain (core PSL), home + contact/about/footer links, GET only, form actions
   never collected, no login/admin/search/cart pages, no query strings, no token-like or e-mail-bearing
   URLs (WP28 known gap; their paths are never recorded either), redirects that leave the seed host or
   the registrable domain are not followed, robots.txt honoured (RFC 9309: 4xx allow, 5xx/unreachable
   disallow), 1 MB per page, stdlib html.parser.
4. extraction: role/corporate e-mails, official social profiles (Instagram, Facebook, TikTok, Telegram,
   YouTube, LinkedIn company, X), wa.me/api.whatsapp.com and tel: phones (E.164), BR phone formats, PIX
   keys (CPF keys validated offline and masked, CNPJ keys check-digit validated), PIX BR Code payloads
   (CRC16), CNPJ text (check digits), schema.org JSON-LD contact points and Cloudflare-encoded e-mails.
5. organisational/role contacts and official profiles become attributes and expand=False pivots;
   personal e-mails/phones of natural persons on legitimate third-party sites are counted only
   (``third_party_counts``), never stored or pivoted.
6. org-profile own sites: personal contacts are kept only as privacy-tagged ``privacy_mentions``;
   hostile sites (an own phishing-kit/fake-store rule hit on a crawled page - the entity tags of the
   case are not visible to modules, see core_requests) with a recorded purpose: privacy-noted
   expand=False pivots; CPF is never pivoted and always masked.
7. no mailbox verification and no automatic Proton/Gravatar/breach sweep: every pivot is expand=False
   (nothing runs on them unless the analyst selects them).
8. theHarvester (GPL-2.0) is idea-only: nothing copied. Tests use synthetic HTML fixtures (role vs
   personal, wa.me and PIX, robots refusal, page cap) and one trimmed real role-contact page.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.robotparser
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.entities import Entity, display_value
from v3lum.core.entities import EntityType as T
from v3lum.core.http import DeadlineExceeded, NetworkError, OfflineError, RequestCapReached
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.core.validators import cnpj_valid, cpf_valid, crc16_ccitt
from v3lum.modules.url_web.light_fetch import fetch_homepage, safe_get
from v3lum.modules.url_web.web_fingerprint import (
    BUNDLED_RULES,
    FETCH_MAX_BYTES,
    SRC_WAYBACK,
    WAYBACK_AVAILABLE,
    classify_response,
    clean,
    extract_page_facts,
    fetch_block,
    fetch_refusal,
    header_first,
    load_json,
    match_own_rules,
    target_url,
)

PAGE_MAX_BYTES = 1_048_576  # FC3: 1 MB per page
MAX_PAGES = 10  # FC3 (LIGHT)
MAX_ARCHIVE_PAGES = 5  # FC1 (archive)
ROBOTS_MAX_BYTES = 500 * 1024

# ============================================================================================ robots (FC3)
def robots_decision(robots_txt: Any, url: str, user_agent: str = "*", http_status: Any = 200) -> dict[str, Any]:
    """urllib.robotparser decision for one URL (RFC 9309: 4xx -> allow all; 5xx/unreachable -> disallow
    all; an HTML page served as robots.txt -> no rules)."""
    try:
        code = int(http_status) if http_status is not None else 0
    except (TypeError, ValueError):
        code = 0
    if 400 <= code < 500:
        return {"allowed": True, "reason": f"robots.txt HTTP {code}: no restrictions"}
    if code == 0 or code >= 500:
        return {"allowed": False, "reason": f"robots.txt unreachable (HTTP {code or 'error'}): full disallow assumed"}
    if isinstance(robots_txt, (bytes, bytearray)):
        text = bytes(robots_txt)[:ROBOTS_MAX_BYTES].decode("utf-8", "replace")
    else:
        text = str(robots_txt or "")[:ROBOTS_MAX_BYTES]
    head = text[:512].lstrip().lower()
    if head.startswith(("<!doctype", "<html")) or "<head" in head or "<body" in head:
        return {"allowed": True, "reason": "robots.txt is an HTML page: treated as no rules"}
    rp = urllib.robotparser.RobotFileParser()
    try:
        rp.parse(text.splitlines())
        ok = rp.can_fetch(user_agent or "*", url)
    except Exception:  # noqa: BLE001 - unparseable robots: no rules
        return {"allowed": True, "reason": "robots.txt unparseable: treated as no rules"}
    return {"allowed": bool(ok), "reason": "allowed by robots.txt" if ok else "disallowed by robots.txt"}


# ============================================================================================ crawl plan (FC3)
CONTACT_HINTS = ("contato", "contact", "fale-conosco", "faleconosco", "fale_conosco", "atendimento", "sac", "sobre", "about", "quem-somos",
                 "quemsomos", "institucional", "empresa", "ouvidoria", "privacidade", "privacy", "lgpd", "imprensa", "nossa-historia", "canais")
EXCLUDED_PATH_RX = re.compile(
    r"(?:^|/)(?:login|logon|signin|sign-in|entrar|acesso|account|conta|minha-conta|my-account|admin|administrator|wp-admin|wp-login\.php|"
    r"painel|dashboard|search|busca|pesquisa|cart|carrinho|checkout|logout|sair|register|cadastro|signup|password|senha|recuperar|reset|api|"
    r"cgi-bin|xmlrpc\.php|feed)(?:/|$|\.)", re.I)
SKIP_EXT_RX = re.compile(r"\.(?:pdf|jpe?g|png|gif|svg|webp|ico|zip|rar|7z|gz|exe|apk|msi|dmg|mp4|mp3|docx?|xlsx?|pptx?|css|js|xml|json)$", re.I)
_TOKENISH = re.compile(r"(?=[A-Za-z0-9_-]{16,})(?=[^/]*\d)(?=[^/]*[A-Za-z])[A-Za-z0-9_-]{16,}")


def registrable(host: str) -> str:
    h = str(host or "").strip(".").lower()
    return psl.registrable_domain(h) or h


def _host_allowed(host: str, seed_host: str) -> bool:
    return host == seed_host or host.endswith("." + seed_host)


def plan_crawl(home_url: str, home_facts: Mapping[str, Any], robots: Callable[[str], Mapping[str, Any]] | None = None, *,
               max_pages: int = MAX_PAGES, seed_host: str | None = None) -> dict[str, Any]:
    """<= max_pages pages: the home first, then contact/about links, then footer links (FC3).

    Refused (listed with the reason): query strings, login/admin/search/cart-type paths, other registrable
    domains, hosts outside the seed host (LIGHT seed binding), token-like or e-mail-bearing paths, and
    robots-disallowed URLs. Non-HTML files are ignored; form actions are never collected."""
    try:
        base = urllib.parse.urlsplit(home_url)
    except ValueError:
        return {"pages": [], "refused": [{"url": str(home_url)[:200], "reason": "bad url"}], "capped": 0}
    site = registrable(base.hostname or "")
    bind = (seed_host or base.hostname or "").lower()
    refused: list[dict[str, str]] = []
    seen: set[str] = set()

    def norm(u: str) -> str:
        p = urllib.parse.urlsplit(u)
        return urllib.parse.urlunsplit((p.scheme.lower(), (p.netloc or "").lower(), p.path or "/", "", ""))

    def consider(u: str) -> str | None:
        try:
            absu = urllib.parse.urljoin(home_url, u)
            p = urllib.parse.urlsplit(absu)
            host = (p.hostname or "").lower()
        except ValueError:
            return None
        if p.scheme not in ("http", "https") or not host:
            return None
        if registrable(host) != site:
            return None
        path = urllib.parse.unquote(p.path or "/")
        personal_path = "@" in path or bool(_TOKENISH.search(path))
        # an e-mail address or a per-recipient token in a link is never written to the crawl summary (P077 c5)
        shown = urllib.parse.urlunsplit((p.scheme, host, "/[path withheld]" if personal_path else (p.path or "/"), "", ""))[:200]
        if not _host_allowed(host, bind):
            refused.append({"url": shown, "reason": "outside the seed host (LIGHT runs only on the analyst-typed host)"})
            return None
        if p.query:
            refused.append({"url": shown, "reason": "query string (no query-string crawling)"})
            return None
        if p.username or p.password:
            refused.append({"url": shown, "reason": "credentials in the URL"})
            return None
        if EXCLUDED_PATH_RX.search(path):
            refused.append({"url": shown, "reason": "login/admin/search-type page"})
            return None
        if personal_path:
            refused.append({"url": shown, "reason": "token-like or e-mail-bearing path (possible per-recipient URL)"})
            return None
        if SKIP_EXT_RX.search(p.path or "") or (p.path or "").lower().startswith("/cdn-cgi/"):
            return None  # files and CDN-internal endpoints (Cloudflare e-mail protection) are never pages
        n = norm(absu)
        if n in seen:
            return None
        seen.add(n)
        if robots is not None:
            dec = robots(n)
            if not dec.get("allowed"):
                refused.append({"url": n[:200], "reason": str(dec.get("reason") or "robots.txt")})
                return None
        return n

    cands: list[tuple[int, int, str]] = []
    first = consider(home_url)
    if first:
        cands.append((0, -1, first))
    for idx, a in enumerate((home_facts or {}).get("anchors") or []):
        href = str(a.get("href") or "") if isinstance(a, Mapping) else ""
        if not href or href.startswith("#"):
            continue
        low = (href + " " + str(a.get("text") or "")).lower()
        prio = 1 if any(k in low for k in CONTACT_HINTS) else (2 if a.get("footer") else None)
        if prio is None:
            continue
        c = consider(href)
        if c:
            cands.append((prio, idx, c))
    cands.sort(key=lambda c: (c[0], c[1]))
    pages = [c[2] for c in cands]
    return {"pages": pages[:max_pages], "refused": refused[:50], "capped": max(0, len(pages) - max_pages)}


# ============================================================================================ extraction (FC4)
ROLE_LOCALPARTS = {
    "contato", "contact", "contatos", "sac", "atendimento", "faleconosco", "fale-conosco", "fale.conosco", "suporte", "support", "help",
    "ajuda", "security", "seguranca", "abuse", "dpo", "privacidade", "privacy", "lgpd", "encarregado", "ouvidoria", "comercial", "vendas",
    "sales", "financeiro", "cobranca", "rh", "recrutamento", "imprensa", "press", "info", "informacoes", "noreply", "no-reply",
    "naoresponda", "webmaster", "postmaster", "hostmaster", "juridico", "legal", "compliance", "marketing", "parcerias", "licitacoes",
    "relacionamento", "ri", "investidores", "secretaria", "administrativo", "admin", "cert", "csirt", "soc", "noc", "ti", "helpdesk",
    "servicedesk", "pedidos", "loja", "trocas", "cadastro", "reclamacoes", "denuncia", "etica", "hello", "office", "contas", "pagamentos",
    "billing", "diretoria", "protocolo", "gabinete", "sic",
}
FREEMAIL = {"gmail.com", "hotmail.com", "outlook.com", "live.com", "yahoo.com", "yahoo.com.br", "bol.com.br", "uol.com.br", "terra.com.br",
            "ig.com.br", "icloud.com", "protonmail.com", "proton.me", "msn.com", "hotmail.com.br", "globo.com", "globomail.com", "r7.com",
            "zipmail.com.br"}
EMAIL_RX = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24})(?![\w-])")
OBFUSCATED_EMAIL_RX = re.compile(
    r"([A-Za-z0-9._%+-]{1,64})\s{0,3}(?:\[at\]|\(at\)|\{at\}|\s+arroba\s+)\s{0,3}([A-Za-z0-9-]{1,63}(?:\s{0,3}(?:\[dot\]|\(dot\)|\.|\s+ponto\s+)\s{0,3}[A-Za-z0-9-]{1,63}){1,6})",
    re.I)


def classify_email(address: Any, site_domain: str | None = None) -> dict[str, Any] | None:
    """{address, class role|personal, relation same_site|third_party, freemail} (FC4/FC5): a role local
    part (contato, sac, atendimento, security, abuse, dpo, ouvidoria..., optionally with a region or a
    number: 'sac.sp', 'contato2') is 'role'; anything else is treated as a natural person's address."""
    a = str(address or "").strip().strip(".").lower()
    if "@" not in a:
        return None
    local, dom = a.rsplit("@", 1)
    base = re.split(r"[._+-]", local)[0] if local else ""
    is_role = local in ROLE_LOCALPARTS or base in ROLE_LOCALPARTS or re.sub(r"\d+$", "", local) in ROLE_LOCALPARTS
    rel = "same_site" if site_domain and registrable(dom) == registrable(site_domain) else "third_party"
    return {"address": a, "class": "role" if is_role else "personal", "relation": rel, "freemail": dom in FREEMAIL}


def decode_cfemail(hexstr: Any) -> str | None:
    """Cloudflare e-mail obfuscation (data-cfemail / /cdn-cgi/l/email-protection#hex)."""
    try:
        b = bytes.fromhex(str(hexstr).strip()[:256])
    except ValueError:
        return None
    if len(b) < 2:
        return None
    s = "".join(chr(x ^ b[0]) for x in b[1:])
    return s if EMAIL_RX.fullmatch(s) else None


BR_DDD = {11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48, 49, 51, 53,
          54, 55, 61, 62, 63, 64, 65, 66, 67, 68, 69, 71, 73, 74, 75, 77, 79, 81, 82, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96,
          97, 98, 99}


def normalise_br_phone(raw: Any) -> dict[str, Any] | None:
    """BR phone text / tel: / wa.me digits -> {e164, kind, national} (FC4). Kinds: mobile, landline,
    tollfree (0800), shared_cost (0300/0303), premium, capital_number (4004/3003...), foreign."""
    s = str(raw or "")[:64]
    plus = s.strip().startswith("+") or s.strip().startswith("00")
    d = re.sub(r"\D", "", s)
    if s.strip().startswith("00"):
        d = d[2:]
    if not d:
        return None
    if re.fullmatch(r"0(800|300|303|500|900)\d{6,7}", d):
        kind = {"800": "tollfree", "300": "shared_cost", "303": "shared_cost"}.get(d[1:4], "premium")
        return {"e164": None, "kind": kind, "national": f"{d[:4]} {d[4:7]} {d[7:]}"}
    if re.fullmatch(r"(400[0-9]|402[0-9]|300[0-9])\d{4}", d):
        return {"e164": "+55" + d, "kind": "capital_number", "national": f"{d[:4]}-{d[4:]}"}
    if plus and not d.startswith("55"):
        return {"e164": "+" + d, "kind": "foreign", "national": None} if 8 <= len(d) <= 15 else None
    if d.startswith("55") and len(d) in (12, 13):
        d = d[2:]
    elif d.startswith("0") and len(d) in (11, 12):
        d = d[1:]
    if len(d) not in (10, 11) or int(d[:2]) not in BR_DDD:
        return None
    sub = d[2:]
    if len(sub) == 9 and sub[0] == "9":
        return {"e164": "+55" + d, "kind": "mobile", "national": f"({d[:2]}) {sub[:5]}-{sub[5:]}"}
    if len(sub) == 8 and sub[0] in "2345":
        return {"e164": "+55" + d, "kind": "landline", "national": f"({d[:2]}) {sub[:4]}-{sub[4:]}"}
    return None


BR_PHONE_TEXT_RX = re.compile(
    r"(?<!\d)(?:\+?55[\s.-]?)?\(?0?(\d{2})\)?[\s.-]?(9?\d{4})[\s.-]?(\d{4})(?!\d)|(?<!\d)(0800|0300|0303)[\s.-]?(\d{3})[\s.-]?(\d{4})(?!\d)"
    r"|(?<!\d)(400\d|402\d|300\d)[\s.-]?(\d{4})(?!\d)")


def parse_whatsapp_url(url: Any) -> dict[str, Any] | None:
    """wa.me / api.whatsapp.com / web.whatsapp.com send links -> {kind whatsapp, e164, phone_kind};
    chat.whatsapp.com -> group invite."""
    try:
        p = urllib.parse.urlsplit(str(url).strip()[:2048])
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    q = urllib.parse.parse_qs(p.query)
    num = None
    if host in ("wa.me", "www.wa.me"):
        num = p.path.strip("/").split("/")[0]
    elif host in ("api.whatsapp.com", "web.whatsapp.com", "whatsapp.com", "www.whatsapp.com") and p.path.rstrip("/") in ("/send", ""):
        num = (q.get("phone") or [""])[0]
    elif host == "chat.whatsapp.com":
        code = p.path.strip("/").split("/")[0]
        return {"kind": "group_invite", "url": "https://chat.whatsapp.com/" + code} if re.fullmatch(r"[A-Za-z0-9]{6,64}", code or "") else None
    if num is None:
        return None
    digits = re.sub(r"\D", "", num)
    ph = normalise_br_phone("+" + digits) if digits else None
    if not ph or not ph.get("e164"):
        return None
    return {"kind": "whatsapp", "e164": ph["e164"], "phone_kind": ph["kind"]}


SOCIAL_HOSTS = {"instagram.com": "instagram", "facebook.com": "facebook", "fb.com": "facebook", "tiktok.com": "tiktok", "t.me": "telegram",
                "telegram.me": "telegram", "youtube.com": "youtube", "linkedin.com": "linkedin", "x.com": "x", "twitter.com": "x",
                "threads.net": "threads"}
_SOCIAL_RESERVED = {
    "instagram": {"p", "reel", "reels", "explore", "stories", "accounts", "tv", "about", "developer", "legal"},
    "facebook": {"sharer", "sharer.php", "share", "dialog", "plugins", "tr", "login", "events", "groups", "watch", "photo", "photo.php",
                 "story.php", "permalink.php", "help", "policies", "privacy", "hashtag", "l.php", "profile.php"},
    "tiktok": {"tag", "music", "discover", "embed", "legal", "about"},
    "telegram": {"share", "joinchat", "s", "addstickers", "proxy", "iv"},
    "youtube": {"watch", "embed", "shorts", "results", "playlist", "feed", "redirect", "share", "about", "t", "live"},
    "linkedin": {"sharearticle", "sharing", "feed", "jobs", "login", "posts", "pulse"},
    "x": {"intent", "share", "home", "search", "hashtag", "i", "login"},
    "threads": {"intent"},
}


def parse_social_url(url: Any) -> dict[str, Any] | None:
    """Official social PROFILE link -> {platform, kind profile|invite, handle, url}; share/intent/post
    links and LinkedIn /in/ person profiles -> None (FC4)."""
    try:
        p = urllib.parse.urlsplit(str(url).strip()[:2048])
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    for pre in ("www.", "m.", "pt-br.", "br.", "mobile."):
        if host.startswith(pre):
            host = host[len(pre):]
            break
    plat = SOCIAL_HOSTS.get(host)
    segs = [s for s in p.path.split("/") if s]
    if not plat or not segs:
        return None
    first = segs[0]
    if plat == "telegram" and (first.startswith("+") or (first == "joinchat" and len(segs) > 1)):
        code = first[1:] if first.startswith("+") else segs[1]
        return {"platform": "telegram", "kind": "invite", "handle": None, "url": "https://t.me/+" + code} if re.fullmatch(r"[\w-]{6,64}", code) else None
    if first.lower() in _SOCIAL_RESERVED.get(plat, set()):
        return None
    handle = None
    if plat == "youtube":
        if first.startswith("@"):
            handle = first
        elif first in ("channel", "c", "user") and len(segs) > 1:
            handle = f"{first}/{segs[1]}"
    elif plat == "linkedin":
        if first in ("company", "school", "showcase") and len(segs) > 1:
            handle = f"{first}/{segs[1]}"
        else:
            return None  # /in/<person>: a natural person, not an official organisation profile
    elif plat == "tiktok":
        handle = first if first.startswith("@") else None
    elif plat == "facebook":
        handle = segs[1] if first == "pages" and len(segs) > 1 else first
    else:
        handle = first
    if not handle or not re.fullmatch(r"[@\w.\-/]{1,100}", handle):
        return None
    canon_host = {"telegram": "t.me", "x": "x.com", "threads": "threads.net"}.get(plat, plat + ".com")
    return {"platform": plat, "kind": "profile", "handle": handle if plat == "youtube" else handle.lstrip("@"), "url": f"https://{canon_host}/{handle}"}


def mask_cpf(digits: Any) -> str | None:
    d = re.sub(r"\D", "", str(digits or ""))
    return display_value(T.CPF, d) if len(d) == 11 else None


def fmt_cnpj(d: str) -> str:
    d = re.sub(r"\D", "", d)
    return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"


CNPJ_RX = re.compile(r"(?<![\d/.-])(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})(?![\d/.-])")
CPF_RX = re.compile(r"(?<![\d/.-])(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?![\d/.-])")
EVP_RX = re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b", re.I)


def find_cnpjs(text: Any) -> list[str]:
    """Valid CNPJs (check digits, offline) in text."""
    out: list[str] = []
    for m in CNPJ_RX.finditer(str(text or "")[:PAGE_MAX_BYTES]):
        d = re.sub(r"\D", "", m.group(1))
        if len(set(d)) > 1 and cnpj_valid(d):
            f = fmt_cnpj(d)
            if f not in out and len(out) < 20:
                out.append(f)
    return out


def pix_key_type(key: Any) -> str | None:
    k = str(key or "").strip()
    d = re.sub(r"\D", "", k)
    if EVP_RX.fullmatch(k):
        return "evp"
    if "@" in k and EMAIL_RX.fullmatch(k):
        return "email"
    if k.startswith("+"):
        return "phone"
    if re.fullmatch(r"[\d./-]+", k) and len(d) == 14 and cnpj_valid(d):
        return "cnpj"
    if re.fullmatch(r"[\d.-]+", k) and len(d) == 11 and cpf_valid(d):
        return "cpf"
    return None


def _tlv(x: str) -> dict[str, str]:
    i, out = 0, {}
    while i + 4 <= len(x):
        tag, ln = x[i:i + 2], x[i + 2:i + 4]
        if not ln.isdigit():
            break
        n = int(ln)
        out[tag] = x[i + 4:i + 4 + n]
        i += 4 + n
    return out


def parse_brcode(payload: Any) -> dict[str, Any] | None:
    """PIX 'copia e cola' payload -> {key, key_type, crc_ok, merchant_name_present} (the merchant name may
    be a natural person's: only its presence is returned)."""
    s = str(payload or "").strip()[:512]
    if not s.startswith("000201") or "br.gov.bcb.pix" not in s.lower():
        return None
    top = _tlv(s)
    key = _tlv(top.get("26", "")).get("01")
    crc_ok = False
    pos = s.rfind("6304")
    if pos >= 0:
        crc_ok = f"{crc16_ccitt(s[:pos + 4].encode('utf-8')):04X}" == s[pos + 4:pos + 8].upper()
    return {"key": key, "key_type": pix_key_type(key) if key else None, "crc_ok": crc_ok, "merchant_name_present": bool(top.get("59"))}


def _brcode_at(text: str, start: int, max_len: int = 512) -> str | None:
    i, end = start, min(len(text), start + max_len)
    while i + 4 <= end:
        tag, ln = text[i:i + 2], text[i + 2:i + 4]
        if not (tag.isdigit() and ln.isdigit()):
            return None
        n = int(ln)
        if tag == "63":
            return text[start:i + 4 + n] if n == 4 and i + 8 <= len(text) else None
        i += 4 + n
    return None


def find_pix_keys(text: Any, window: int = 120) -> list[dict[str, Any]]:
    """PIX keys announced near the word 'pix' and BR Code payloads; CPF keys only masked (FC4/FC6)."""
    t = str(text or "")[:PAGE_MAX_BYTES]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None, valid: bool = True) -> None:
        if value and (kind, value) not in seen and len(out) < 30:
            seen.add((kind, value))
            out.append({"type": kind, "value": value, "valid": valid})

    for m in list(re.finditer(r"000201", t))[:20]:
        payload = _brcode_at(t, m.start())
        br = parse_brcode(payload) if payload else None
        if br and br["key"]:
            add("brcode:" + (br["key_type"] or "unknown"), mask_cpf(br["key"]) if br["key_type"] == "cpf" else br["key"], br["crc_ok"])
    for m in list(re.finditer(r"\bpix\b", t, re.I))[:50]:
        seg = t[m.end():m.end() + window]
        for c in CNPJ_RX.finditer(seg):
            d = re.sub(r"\D", "", c.group(1))
            if cnpj_valid(d):
                add("cnpj", fmt_cnpj(d))
        for c in CPF_RX.finditer(seg):
            d = re.sub(r"\D", "", c.group(1))
            if len(d) == 11:
                add("cpf", mask_cpf(d), cpf_valid(d))
        for c in EVP_RX.finditer(seg):
            add("evp", c.group(1).lower())
        for c in EMAIL_RX.finditer(seg):
            add("email", c.group(1).lower())
        for c in re.finditer(r"\+55[\s\d().-]{10,16}", seg):
            ph = normalise_br_phone(c.group(0))
            if ph and ph.get("e164"):
                add("phone", ph["e164"])
    return out


def _jsonld_nodes(obj: Any, depth: int = 0) -> Iterable[dict[str, Any]]:
    if depth > 6:
        return
    if isinstance(obj, list):
        for x in obj[:50]:
            yield from _jsonld_nodes(x, depth + 1)
    elif isinstance(obj, dict):
        yield obj
        for k in ("@graph", "contactPoint", "publisher", "author", "organization", "brand", "parentOrganization"):
            if k in obj:
                yield from _jsonld_nodes(obj[k], depth + 1)


def _as_list(v: Any) -> list[str]:
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if isinstance(x, (str, int))][:20]
    return [str(v)] if isinstance(v, (str, int)) else []


def extract_contacts(body: Any = None, page_url: str = "", content_type: Any = None, facts: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One page -> raw contacts (FC3/FC4), no policy yet: e-mails (mailto, text, obfuscated,
    Cloudflare-encoded, JSON-LD), phones (tel:, text, JSON-LD), WhatsApp links, social profiles, PIX
    keys and CNPJs. The page is parsed up to 1 MB with the stdlib html.parser."""
    f = facts if facts is not None else extract_page_facts(body, page_url, content_type, max_bytes=PAGE_MAX_BYTES)
    text = str(f.get("text") or "")
    emails: dict[str, str] = {}
    phones: dict[str, dict[str, Any]] = {}
    wa: list[dict[str, Any]] = []
    social: list[dict[str, Any]] = []
    ld_cnpjs: list[str] = []

    def add_email(a: str, src: str) -> None:
        a = a.strip().strip(".").lower()
        if len(emails) < 100 and EMAIL_RX.fullmatch(a) and not re.search(r"\.(png|jpe?g|gif|svg|webp|css|js)$", a) and a not in emails:
            emails[a] = src

    def add_phone(raw: str, src: str, ctx_text: str = "") -> None:
        ph = normalise_br_phone(raw)
        if ph and len(phones) < 100:
            key = ph["e164"] or ph["national"]
            if key not in phones:
                phones[key] = dict(ph, source=src, context=clean(ctx_text, 80))

    for a in f.get("anchors") or []:
        if not isinstance(a, Mapping):
            continue
        href = str(a.get("href") or "").strip()
        low = href.lower()
        atext = clean(str(a.get("text") or ""), 120)
        if low.startswith("mailto:"):
            for x in urllib.parse.unquote(href[7:].split("?", 1)[0]).split(",")[:5]:
                add_email(x, "mailto")
        elif low.startswith("tel:"):
            add_phone(urllib.parse.unquote(href[4:]), "tel", atext)
        elif "/cdn-cgi/l/email-protection#" in low:
            e = decode_cfemail(href.split("#", 1)[1])
            if e:
                add_email(e, "cfemail")
        else:
            w = parse_whatsapp_url(href)
            if w:
                w["context"] = atext[:80]
                if w not in wa and len(wa) < 30:
                    wa.append(w)
                continue
            s = parse_social_url(href)
            if s and s not in social and len(social) < 30:
                social.append(s)
    for h in f.get("cfemails") or []:
        e = decode_cfemail(h)
        if e:
            add_email(e, "cfemail")
    for block in f.get("jsonld") or []:
        obj, _err = load_json(block)
        for node in _jsonld_nodes(obj):
            ctx_text = " ".join(str(node.get(k) or "") for k in ("contactType", "name", "@type"))[:80]
            for e in _as_list(node.get("email")):
                add_email(e[7:] if e.lower().startswith("mailto:") else e, "jsonld")
            for t in _as_list(node.get("telephone")):
                add_phone(t, "jsonld", ctx_text)
            for u in _as_list(node.get("sameAs")):
                sp = parse_social_url(u)
                if sp and sp not in social and len(social) < 30:
                    social.append(sp)
            for k in ("taxID", "vatID", "identifier"):
                for v in _as_list(node.get(k)):
                    ld_cnpjs.extend(x for x in find_cnpjs(v) if x not in ld_cnpjs)
    for m in EMAIL_RX.finditer(text):
        add_email(m.group(1), "text")
    for m in OBFUSCATED_EMAIL_RX.finditer(text):
        dom = re.sub(r"\s*(?:\[dot\]|\(dot\)|\.|\s+ponto\s+)\s*", ".", m.group(2), flags=re.I)
        add_email(f"{m.group(1)}@{dom}", "obfuscated")
    for m in BR_PHONE_TEXT_RX.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1  # context = the same text node only
        add_phone(m.group(0), "text", text[max(line_start, m.start() - 60):m.start()])
    return {"emails": [{"address": k, "source": v} for k, v in emails.items()], "phones": list(phones.values()), "whatsapp": wa,
            "social": social, "pix": find_pix_keys(text), "cnpjs": list(dict.fromkeys(find_cnpjs(text) + ld_cnpjs))[:20],
            "truncated": bool(f.get("truncated"))}


def merge_contacts(items: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"emails": [], "phones": [], "whatsapp": [], "social": [], "pix": [], "cnpjs": []}
    for c in items:
        for k in out:
            for v in c.get(k) or []:
                if v not in out[k]:
                    out[k].append(v)
    return out


# ============================================================================================ policy (FC5-FC7)
ROLE_CONTEXT_RX = re.compile(r"atendimento|\bsac\b|vendas|suporte|support|fale conosco|comercial|central|ouvidoria|oficial|whatsapp business|"
                             r"pedidos|loja|customer|service|sales|contactpoint", re.I)


def contacts_policy(contacts: Mapping[str, Any], site_class: str = "third_party", purpose_recorded: bool = False,
                    site_domain: str | None = None) -> dict[str, Any]:
    """FC5-FC7. site_class 'third_party' (legitimate site), 'own_asset' (org profile) or 'hostile'
    (phishing/fraud/fake store). Returns {attributes, pivots, mentions, counts}: every pivot has
    expand=False; personal items are privacy-tagged; CPF only ever masked, never a pivot; nothing is
    queued for mailbox verification or Proton/Gravatar/breach sweeps."""
    attrs: list[dict[str, Any]] = []
    pivots: list[dict[str, Any]] = []
    mentions: list[dict[str, Any]] = []
    counts = {"personal_emails": 0, "personal_phones": 0, "cpf_keys": 0}

    def personal(kind: str, value: str, extra: Mapping[str, Any] | None = None) -> None:
        item = dict({"type": kind, "value": value, "privacy": True}, **(extra or {}))
        if site_class == "own_asset":
            mentions.append(item)
        elif site_class == "hostile" and purpose_recorded:
            pivots.append(dict(item, expand=False))
        else:
            counts[f"personal_{kind}s"] = counts.get(f"personal_{kind}s", 0) + 1

    for e in contacts.get("emails") or []:
        cl = classify_email(e.get("address"), site_domain)
        if not cl:
            continue
        if cl["class"] == "role" and not cl["freemail"]:
            attrs.append({"type": "email", "value": cl["address"], "relation": cl["relation"]})
            pivots.append({"type": "email", "value": cl["address"], "expand": False, "privacy": False})
        else:
            personal("email", cl["address"])
    for p in contacts.get("phones") or []:
        org = p.get("kind") in ("tollfree", "shared_cost", "capital_number", "landline") or bool(ROLE_CONTEXT_RX.search(p.get("context") or ""))
        val = p.get("e164") or p.get("national")
        if not val:
            continue
        if org:
            attrs.append({"type": "phone", "value": val, "kind": p.get("kind")})
            if p.get("e164"):
                pivots.append({"type": "phone", "value": p["e164"], "expand": False, "privacy": False})
        else:
            personal("phone", val, {"kind": p.get("kind")})
    for w in contacts.get("whatsapp") or []:
        if w.get("kind") == "group_invite":
            attrs.append({"type": "invite", "value": w["url"], "kind": "whatsapp_group"})
            continue
        if ROLE_CONTEXT_RX.search(w.get("context") or "") or w.get("phone_kind") != "mobile":
            attrs.append({"type": "whatsapp", "value": w["e164"], "kind": w.get("phone_kind")})
            pivots.append({"type": "phone", "value": w["e164"], "expand": False, "privacy": False})
        else:
            personal("phone", w["e164"], {"kind": "whatsapp"})
    for s in contacts.get("social") or []:
        if s.get("kind") == "invite":
            attrs.append({"type": "invite", "value": s["url"], "kind": f"{s['platform']}_invite"})
            pivots.append({"type": "telegram_invite", "value": s["url"], "expand": False, "privacy": False})
            continue
        attrs.append({"type": "social", "platform": s["platform"], "handle": s["handle"], "value": s["url"]})
        pivots.append({"type": "url", "value": s["url"], "expand": False, "privacy": False})
        pivots.append({"type": "social_account", "value": f"{s['platform']}:{s['handle']}", "platform": s["platform"], "expand": False, "privacy": False})
    for cn in contacts.get("cnpjs") or []:
        attrs.append({"type": "cnpj", "value": cn})
        pivots.append({"type": "cnpj", "value": cn, "expand": False, "privacy": False})
    for k in contacts.get("pix") or []:
        t = str(k.get("type") or "")
        if t.endswith("cpf"):
            counts["cpf_keys"] += 1
            if site_class == "own_asset" or (site_class == "hostile" and purpose_recorded):
                mentions.append({"type": "pix_cpf", "value": k["value"], "privacy": True, "masked": True})
        elif t.endswith("cnpj"):
            attrs.append({"type": "pix_key", "key_type": "cnpj", "value": k["value"]})
            pivots.append({"type": "cnpj", "value": k["value"], "expand": False, "privacy": False, "pix": True})
        elif t.endswith("evp"):
            if site_class == "hostile" and purpose_recorded:
                pivots.append({"type": "pix_key", "value": k["value"], "expand": False, "privacy": True})
            elif site_class == "own_asset":
                mentions.append({"type": "pix_key", "value": k["value"], "privacy": True})
            else:
                attrs.append({"type": "pix_key", "key_type": "evp", "value": k["value"]})
        elif t.endswith("email"):
            cl = classify_email(k["value"], site_domain)
            if cl and cl["class"] == "role" and not cl["freemail"]:
                attrs.append({"type": "pix_key", "key_type": "email", "value": k["value"]})
            else:
                personal("email", k["value"], {"pix": True})
        elif t.endswith("phone"):
            personal("phone", k["value"], {"pix": True})
    uniq: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for p in pivots:
        key = (p["type"], p["value"])
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return {"attributes": attrs, "pivots": uniq, "mentions": mentions, "counts": counts}


# ============================================================================================ output
_PIVOT_TYPES = {"email": (T.EMAIL, "contact_email"), "phone": (T.PHONE, "phone_of"), "url": (T.URL, "site_social_profile"),
                "social_account": (T.SOCIAL_ACCOUNT, "site_social_profile"), "cnpj": (T.CNPJ, "company_of"),
                "telegram_invite": (T.TELEGRAM_INVITE, "site_social_profile"), "pix_key": (T.PIX, "pix_key_of")}


def site_class_of(ctx: Any, entity: Entity, own_hits: Iterable[Mapping[str, Any]]) -> str:
    try:
        if ctx.org.owns(entity).own:
            return "own_asset"
    except Exception:  # noqa: BLE001
        pass
    return "hostile" if any(h.get("kind") == "phishing_kit" for h in own_hits) else "third_party"


def emit_contacts(res: ModuleResult, policy: Mapping[str, Any], *, site_class: str, purpose_recorded: bool) -> bool:
    """attributes + expand=False pivots (FC5-FC7); returns True when something was recorded."""
    groups: dict[str, list[Any]] = {"emails": [], "phones": [], "whatsapp": [], "social": [], "invites": [], "cnpjs": [], "pix_keys": []}
    for a in policy["attributes"]:
        t = a["type"]
        if t == "email":
            groups["emails"].append({"address": a["value"], "relation": a.get("relation")})
        elif t == "phone":
            groups["phones"].append({"number": a["value"], "kind": a.get("kind")})
        elif t == "whatsapp":
            groups["whatsapp"].append({"number": a["value"], "kind": a.get("kind")})
        elif t == "social":
            groups["social"].append({"platform": a["platform"], "handle": a["handle"], "url": a["value"]})
        elif t == "invite":
            groups["invites"].append({"kind": a.get("kind"), "url": a["value"]})
        elif t == "cnpj":
            groups["cnpjs"].append(a["value"])
        elif t == "pix_key":
            groups["pix_keys"].append({"type": a.get("key_type"), "value": a["value"]})
    groups = {k: v for k, v in groups.items() if v}
    res.attr("site_contacts", groups)
    res.attr("privacy_mentions", policy["mentions"])
    counts = {k: v for k, v in policy["counts"].items() if v}
    res.attr("third_party_counts", counts)
    kept = 0
    for p in policy["pivots"]:
        etype, relation = _PIVOT_TYPES.get(p["type"], (None, None))
        if etype is None:
            continue
        if p.get("privacy"):
            note = "personal contact on a hostile site: privacy, analyst selection only (purpose recorded)"
        else:
            note = "organisational contact published on the site (self-declared): analyst selection only"
        if res.pivot(etype, p["value"], relation, confidence="probable", expand=False, note=note) is not None:
            kept += 1
    return bool(groups or policy["mentions"] or counts or kept)


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test (A7): extractor, policy and robots parser on in-memory input; no network."""
    try:
        page = ("<html><body><a href='mailto:contato@example.com'>c</a><a href='mailto:maria.silva@example.com'>m</a>"
                "<a href='https://wa.me/551155550123'>SAC</a><a href='https://www.instagram.com/lojaexemplo/'>ig</a></body></html>")
        pol = contacts_policy(extract_contacts(page, "https://example.com/"), "third_party", site_domain="example.com")
        assert {"type": "email", "value": "contato@example.com", "relation": "same_site"} in pol["attributes"]
        assert pol["counts"]["personal_emails"] == 1
        assert robots_decision("User-agent: *\nDisallow: /", "https://example.com/x")["allowed"] is False
        return HealthResult("ok", "extractor, policy and robots parser ok")
    except AssertionError:
        return HealthResult("dead", "site_contacts self-test failed")


# ============================================================================================ modules
@register
class SiteContacts(Module):
    name = "site_contacts"
    title = "Site contacts (LIGHT bounded crawl)"
    description = (
        "Role/corporate e-mails, phones, WhatsApp links, official social profiles, PIX keys and CNPJs from at most 10 contact/about/footer "
        "pages of an analyst-typed site (LIGHT, robots.txt honoured); personal contacts of natural persons are counted, not stored."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.EMAIL, T.PHONE, T.URL, T.SOCIAL_ACCOUNT, T.CNPJ, T.TELEGRAM_INVITE, T.PIX}
    run_on = "seeds"
    tags = {"brazil"}
    reference = "https://www.rfc-editor.org/rfc/rfc9309"
    notice = (
        "LIGHT: GETs at most 10 pages of the analyst-typed site (robots.txt honoured, no forms, no login/admin/search pages, no query "
        "strings). LGPD: personal contacts of natural persons are counted only (own sites: privacy-tagged mentions; hostile sites with a "
        "recorded purpose: privacy pivots); CPF is masked and never pivoted; nothing triggers mailbox checks or breach sweeps."
    )
    terms = "open"
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    max_requests = 16  # robots.txt + 10 pages + redirect hops
    expected_latency = 12.0
    timeout = 90.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 7 * 86400
    max_pivots = 60
    default_enabled = False
    settings = {
        "site_contacts_max_pages": SettingSpec(MAX_PAGES, "site_contacts: pages per site (P077 cond 3: at most 10)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return target_url(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        start = target_url(entity)
        if start is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        parts = urllib.parse.urlsplit(start)
        seed_host = (parts.hostname or "").lower()
        try:
            cap = max(1, min(MAX_PAGES, int(ctx.setting("site_contacts_max_pages", MAX_PAGES))))
        except (TypeError, ValueError):
            cap = MAX_PAGES
        robots = self._robots(ctx, entity, f"{parts.scheme}://{parts.netloc}/robots.txt")
        summary: dict[str, Any] = {"pages_planned": 0, "pages_fetched": 0, "pages": [], "refused": [], "capped": 0, "robots": robots["note"]}
        if robots.get("stop"):
            res.attr("crawl_summary", summary)
            st, code, reason = robots["stop"]
            return res.mark(st, f"robots.txt: {reason}", reason_code=code)

        def robots_fn(u: str) -> dict[str, Any]:
            return robots_decision(robots["body"], u, "*", robots["status"])

        first = robots_fn(start)
        if not first["allowed"]:
            summary["refused"].append({"url": start[:200], "reason": first["reason"]})
            res.attr("crawl_summary", summary)
            if robots["status"] == 0 or robots["status"] >= 500:
                return res.mark("error", f"{first['reason']}: no page fetched (could not verify)", reason_code="error")
            return res.mark("skipped", f"robots.txt disallows {start}: no page fetched", reason_code="policy")
        home = self._page(ctx, entity, start, home=True)
        if home["stop"]:
            res.attr("crawl_summary", summary)
            st, code, reason = home["stop"]
            return res.mark(st, reason, reason_code=code)
        plan = plan_crawl(home["url"], home["facts"], robots_fn, max_pages=cap, seed_host=seed_host)
        summary.update({"pages_planned": len(plan["pages"]), "refused": plan["refused"], "capped": plan["capped"]})
        found = [home["contacts"]] if home["contacts"] else []
        own_hits = list(home["own_hits"])
        fetched = [home["url"]] if home["ok"] else []
        for url in plan["pages"]:
            if url in (start, home["url"]) or url in fetched:
                continue
            try:
                page = self._page(ctx, entity, url)
            except RequestCapReached:
                res.stop("request_cap")  # the per-run request cap: the pages already read are kept (partial)
                break
            if page["refused"]:
                summary["refused"].append({"url": url[:200], "reason": page["refused"]})
                continue
            if page["stop"]:
                summary["refused"].append({"url": url[:200], "reason": page["stop"][2]})
                if page["stop"][0] in ("rate_limited", "quota"):
                    res.stop(page["stop"][0])  # partial: the pages read so far are kept
                break  # a challenge or block on one page: stop the crawl, never retried
            if page["ok"] and page["url"] not in fetched:
                fetched.append(page["url"])
                own_hits.extend(page["own_hits"])
                if page["contacts"]:
                    found.append(page["contacts"])
        summary["pages_fetched"] = len(fetched)
        summary["pages"] = [u[:200] for u in fetched]
        site_class = site_class_of(ctx, entity, own_hits)
        summary["site_class"] = site_class
        res.attr("crawl_summary", summary)
        purpose = bool(str(getattr(ctx, "purpose", "") or "").strip())
        policy = contacts_policy(merge_contacts(found), site_class, purpose, site_domain=seed_host)
        res.raw = {"crawl": summary, "kept": policy["attributes"], "counts": policy["counts"], "site_class": site_class, "purpose_recorded": purpose}
        recorded = emit_contacts(res, policy, site_class=site_class, purpose_recorded=purpose)
        if not fetched:
            return res.mark("error", home["reason"] or "no page could be read (could not verify)", reason_code="error")
        if not recorded:
            return res.mark("empty", f"no organisational contact on {len(fetched)} page(s)")
        return res

    def _robots(self, ctx: Any, entity: Entity, url: str) -> dict[str, Any]:
        """robots.txt through the shared safe fetch (RFC 9309: redirects followed up to 5 hops on the seed;
        4xx = no restrictions, 5xx/unreachable/not fetched = full disallow). A rate limit, a quota or a
        challenge/error page stops the run (never retried)."""
        try:
            got = safe_get(ctx, url, accept=None, max_bytes=ROBOTS_MAX_BYTES, entity=entity)
        except NetworkError as exc:
            if isinstance(exc, (DeadlineExceeded, OfflineError)):
                raise
            return {"status": 0, "body": "", "note": f"unreachable ({clean(str(exc), 80)})"}
        if got.refused:
            return {"status": 0, "body": "", "note": f"not fetched ({fetch_refusal(got)[2][:120]})"}
        status = int(got.status or 0)
        blocked = fetch_block(got)
        if blocked is not None and (blocked[0] in ("rate_limited", "quota") or status not in (401, 403, 404, 410)):
            return {"status": status, "body": "", "note": f"HTTP {status} ({blocked[2][:120]})", "stop": blocked}
        body = got.body if 200 <= status < 300 else b""
        return {"status": status, "body": body, "note": f"HTTP {status}"}

    def _page(self, ctx: Any, entity: Entity, url: str, *, home: bool = False) -> dict[str, Any]:
        """One page through the shared safe fetch (the homepage with ``fetch_homepage``, the cache row
        web_fingerprint and the other LIGHT modules share). ``stop`` = (status, code, reason) for a refused
        homepage or a block/rate-limit answer; ``refused`` = why a crawled page was not requested."""
        out: dict[str, Any] = {"url": url, "ok": False, "stop": None, "refused": None, "facts": {}, "contacts": None, "own_hits": [],
                               "reason": None}
        got = fetch_homepage(ctx, entity) if home else safe_get(ctx, url, accept=None, max_bytes=PAGE_MAX_BYTES, entity=entity)
        if got.refused:
            refusal = fetch_refusal(got)
            if home:
                out["stop"] = refusal
            else:
                out["refused"] = refusal[2][:200]
            return out
        out["url"] = str(got.url or url)
        verdict = classify_response(got.status, got.headers, got.body)
        if verdict["verdict"] in ("corporate_proxy", "challenge"):
            out["stop"] = ("blocked", "challenge", verdict["reason"])
            return out
        blocked = fetch_block(got)
        if blocked is not None:
            out["stop"] = blocked
            return out
        if not verdict["fingerprint_body"]:
            out["reason"] = verdict["reason"]
            return out
        facts = extract_page_facts(got.body, out["url"], header_first(got.headers, "content-type"), max_bytes=PAGE_MAX_BYTES)
        out.update({"ok": True, "facts": facts, "contacts": extract_contacts(facts=facts, page_url=out["url"]),
                    "own_hits": match_own_rules(ctx.data.bundled_json(BUNDLED_RULES), facts, out["url"])})
        return out


@register
class SiteContactsArchive(Module):
    name = "site_contacts_archive"
    title = "Site contacts from archived pages (Wayback)"
    description = (
        "Role/corporate contacts, official social profiles, PIX keys and CNPJs from at most 5 archived homepage/contact/about pages "
        "(Wayback id_ snapshots): no contact with the target; personal contacts of natural persons are counted, not stored."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.EMAIL, T.PHONE, T.URL, T.SOCIAL_ACCOUNT, T.CNPJ, T.TELEGRAM_INVITE, T.PIX}
    run_on = "seeds"
    tags = {"brazil"}
    reference = "https://archive.org/help/wayback_api.php"
    notice = (
        "Reads historical snapshots served by the Internet Archive (never the live site). LGPD: personal contacts of natural persons are "
        "counted only (own sites: privacy-tagged mentions; hostile sites with a recorded purpose: privacy pivots); CPF is masked and never "
        "pivoted."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "internet_archive"
    sources = (SRC_WAYBACK,)
    hosts = ("archive.org", "web.archive.org")
    access_model = "free_noauth_limited"
    max_requests = 12  # availability + <= 5 id_ snapshots (+ archive-internal redirects)
    expected_latency = 30.0
    timeout = 120.0
    cache_ttl = 30 * 86400
    max_pivots = 60
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return target_url(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        from v3lum.modules.url_web.web_archives import archive_snapshot_url, parse_wayback_available, query_target

        res = self.result(entity)
        q = query_target(entity)
        if q is None:
            return res.mark("skipped", "not an http(s) URL or a domain", reason_code="not_applicable")
        homepage = q["homepage"] if q["kind"] == "domain" else q["query"]
        resp = ctx.http.get(WAYBACK_AVAILABLE, params={"url": homepage}, source=SRC_WAYBACK)
        if resp.classification is not None:
            ctx.http.check(resp)
        if resp.status >= 400:
            return res.mark("error", f"Wayback availability API HTTP {resp.status}: archive unreachable, could not verify", reason_code="error")
        parsed = parse_wayback_available(resp.content)
        if parsed["state"] == "error":
            return res.mark("error", f"Wayback availability: {parsed['error']} (could not verify)", reason_code="error")
        closest = parsed.get("closest")
        if parsed["state"] == "empty" or not closest:
            return res.mark("empty", "no archived capture of the homepage")
        ts = str(closest.get("timestamp") or "")
        raw_home = closest.get("raw_snapshot") or archive_snapshot_url("wayback", ts, homepage)
        if not raw_home:
            # a capture exists but its URL carries credentials/tokens/e-mails (P059 c7): never fetched, not an absence
            return res.mark("skipped", "the closest snapshot URL carries secrets or personal identifiers: not fetched", reason_code="policy")
        res.attr("archive_snapshot", {"url": closest.get("snapshot_url"), "captured_at": closest.get("captured_at"), "status": closest.get("status"),
                                      "source": "wayback"})
        original_home = self._original(raw_home) or homepage
        home = self._page(ctx, raw_home, original_home)
        summary: dict[str, Any] = {"pages_planned": 0, "pages_fetched": 0, "pages": [], "refused": [], "capped": 0, "robots": "not applicable (archive)"}
        if not home["ok"]:
            res.attr("crawl_summary", summary)
            if home.get("could_not_verify"):
                # the archive failed, or the closest capture is an error/block page: nothing was read (rule 5)
                return res.mark("error", f"archived homepage: {home['reason']} (could not verify)", reason_code="error")
            return res.mark("empty", home["reason"] or "the archived homepage is not a readable HTML page")
        site_host = (urllib.parse.urlsplit(original_home).hostname or "").lower()
        plan = plan_crawl(original_home, home["facts"], None, max_pages=MAX_ARCHIVE_PAGES, seed_host=registrable(site_host))
        summary.update({"pages_planned": len(plan["pages"]), "refused": plan["refused"], "capped": plan["capped"]})
        found = [home["contacts"]]
        own_hits = list(home["own_hits"])
        fetched = [original_home]
        for url in plan["pages"]:
            if url == original_home or len(fetched) >= MAX_ARCHIVE_PAGES:
                continue
            raw = archive_snapshot_url("wayback", ts, url)
            if not raw:
                continue
            page = self._page(ctx, raw, url)
            if page["ok"]:
                fetched.append(url)
                found.append(page["contacts"])
                own_hits.extend(page["own_hits"])
        summary["pages_fetched"] = len(fetched)
        summary["pages"] = [u[:200] for u in fetched]
        site_class = site_class_of(ctx, entity, own_hits)
        summary["site_class"] = site_class
        res.attr("crawl_summary", summary)
        purpose = bool(str(getattr(ctx, "purpose", "") or "").strip())
        policy = contacts_policy(merge_contacts(found), site_class, purpose, site_domain=site_host)
        res.raw = {"crawl": summary, "kept": policy["attributes"], "counts": policy["counts"], "site_class": site_class, "purpose_recorded": purpose,
                   "captured_at": closest.get("captured_at")}
        if not emit_contacts(res, policy, site_class=site_class, purpose_recorded=purpose):
            return res.mark("empty", f"no organisational contact on {len(fetched)} archived page(s)")
        return res

    @staticmethod
    def _original(raw_url: str) -> str | None:
        m = re.match(r"^https://web\.archive\.org/web/\d{4,14}id_/(.+)$", raw_url)
        return m.group(1) if m else None

    def _page(self, ctx: Any, raw_url: str, original: str) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": False, "facts": {}, "contacts": None, "own_hits": [], "reason": None}
        resp = ctx.http.get(raw_url, source=SRC_WAYBACK, max_bytes=FETCH_MAX_BYTES, allow_redirects=True)
        if resp.classification is not None:
            ctx.http.check(resp)
        if resp.status == 404:
            out.update(reason="not archived (HTTP 404 from the archive)", could_not_verify=True)
            return out
        if resp.status >= 500:
            out.update(reason=f"archive HTTP {resp.status}: archive unreachable", could_not_verify=True)
            return out
        verdict = classify_response(resp.status, resp.headers, resp.content)
        if not verdict["fingerprint_body"]:
            # an archived error, challenge, proxy or corporate block page is inconclusive; a non-HTML capture is not
            out.update(reason=verdict["reason"], could_not_verify=verdict["verdict"] != "not_html")
            return out
        facts = extract_page_facts(resp.content, original, header_first(resp.headers, "content-type"), max_bytes=PAGE_MAX_BYTES)
        out.update({"ok": True, "facts": facts, "contacts": extract_contacts(facts=facts, page_url=original),
                    "own_hits": match_own_rules(ctx.data.bundled_json(BUNDLED_RULES), facts, original)})
        return out


__all__ = [
    "SiteContacts", "SiteContactsArchive", "classify_email", "contacts_policy", "decode_cfemail", "extract_contacts", "find_cnpjs",
    "find_pix_keys", "normalise_br_phone", "parse_brcode", "parse_social_url", "parse_whatsapp_url", "plan_crawl", "robots_decision",
]
