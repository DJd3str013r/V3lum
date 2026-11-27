"""WalletExplorer: Bitcoin wallet clustering and service labels (P208).

Final conditions (P208):

* cond 1 - GET https://www.walletexplorer.com/api/1/address-lookup?address=<a>&caller=<caller_id> at about
  one request per second (min_interval 1 s, provider profile: one at a time). ``caller`` comes from the
  operator-identifier setting: ``caller_id`` (a shared core setting once the core adds it), else this
  module's ``walletexplorer_caller_id``, else the P326 role mailbox ``contact_email``. It must be a generic
  team identifier - never an analyst's name, a personal e-mail, the case id or the investigated value
  (:func:`validate_caller_id`); unset or refused = SKIPPED reason_code 'config'. The address is validated
  locally first (P217): WalletExplorer answers ``found:false`` both for an unused and an invalid address.
* cond 2 - ``found:false`` -> EMPTY. Labels read 'WalletExplorer label (name database not updated since
  2016, per its info page)' with attribution: a lead for a legal request to that service, not proof of
  ownership.
* cond 3 - service labels (exchange, mixer, other services) become stop-node tags for graph expansion
  (P213: tag ``stop_node`` plus the class tag, attribute ``stop_node_hint`` exchange|mixer) and the finding
  names the exchange a legal request can go to; mixers, dark-web markets, ransomware wallets and fraud
  schemes are not legal-request leads. The label category comes from WalletExplorer's own service index
  (home page, a monthly dataset). ``updated_to_block`` is kept in ``wallet_cluster`` and the rule
  ``p2g09_walletexplorer_lag`` compares it with the chain tip btc_explorers reports to show the data lag.
  Registry provider walletexplorer: tier community, terms open.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, Module, register
from v3lum.core.validators import btc_address_valid
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import safe_plain
from v3lum.modules.darkweb_ransomware.onion_safety import fetch_dataset

try:
    from v3lum.config import SettingSpec
except ImportError:  # pragma: no cover - contract v2 always has it
    SettingSpec = None  # type: ignore[assignment,misc]

SOURCE = "walletexplorer.api"
SOURCE_INDEX = "walletexplorer.walletexplorer_service_index"
LOOKUP_URL = "https://www.walletexplorer.com/api/1/address-lookup"
HOME_URL = "https://www.walletexplorer.com/"
ADDRESS_PAGE = "https://www.walletexplorer.com/address/{address}"
INDEX_DATASET = "walletexplorer_service_index"
LABEL_NOTE = "WalletExplorer label (name database not updated since 2016, per its info page)"
ATTRIBUTION = "WalletExplorer.com (Ales Janda): Bitcoin wallet clustering and service labels"
#: the genesis-block address: the benign health-check value (an unlabelled cluster)
GENESIS_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

_CATEGORY = {"exchanges": "exchange", "pools": "mining_pool", "services/others": "service", "gambling": "gambling", "old/historic": "historic"}
_MIXER_RE = re.compile(r"mix|fog|launder|blender|tumbl|helix|wasabi|samourai|joinmarket", re.I)
_MARKET_RE = re.compile(r"market|silkroad|agora|evolution|nucleus|abraxas|alphabay|hydra|dream|crimenet", re.I)
_RANSOM_RE = re.compile(r"locker|ransom|cryptowall|wannacry|locky|cerber", re.I)
_FRAUD_RE = re.compile(r"ponzi|pirateat40", re.I)
_NOT_LEGAL_LEAD = frozenset({"mixer", "darknet_market", "ransomware", "fraud_scheme"})
_TAG = {"exchange": "exchange", "mixer": "mixer", "darknet_market": "darknet_market", "ransomware": "ransomware", "fraud_scheme": "fraud"}
_ROLE_WORDS = frozenset({
    "cti", "soc", "csirt", "cert", "sirt", "security", "seguranca", "infosec", "threatintel", "intel", "osint", "abuse", "noc", "ir",
    "dfir", "cyber", "team", "secops", "cybersecurity", "blueteam",
})


def _setting(default: Any, description: str) -> Any:
    return SettingSpec(default, description) if SettingSpec is not None else default


# ------------------------------------------------------------------ parsing
def parse_lookup(doc: Any) -> dict[str, Any]:
    """address-lookup answer -> {'status': 'found'|'empty'|'error', 'wallet_id', 'label', 'updated_to_block',
    'reason'} (cond 2). Live 2026-11-26: {'found': true, 'label': 'BTC-e.com', 'wallet_id': '000003a2f31608c0',
    'updated_to_block': 977103}; unlabelled clusters have no 'label'; {'found': false, ...} for an unused or
    invalid address; bad input -> {'error': '<text>'} per the API page."""
    out: dict[str, Any] = {"status": "error", "wallet_id": None, "label": None, "updated_to_block": None, "reason": ""}
    if not isinstance(doc, dict):
        out["reason"] = "WalletExplorer answered an unexpected JSON type: could not verify"
        return out
    if isinstance(doc.get("error"), str):
        out["reason"] = f"WalletExplorer error: {safe_plain(doc['error'], 120)}: could not verify"
        return out
    block = doc.get("updated_to_block")
    out["updated_to_block"] = block if isinstance(block, int) and not isinstance(block, bool) and block >= 0 else None
    found = doc.get("found")
    if found is False:
        out["status"] = "empty"
        return out
    if found is not True:
        out["reason"] = "WalletExplorer answer has no boolean 'found': could not verify"
        return out
    wallet_id = doc.get("wallet_id")
    out["wallet_id"] = wallet_id if isinstance(wallet_id, str) and re.fullmatch(r"[0-9a-f]{8,32}", wallet_id) else None
    label = doc.get("label")
    out["label"] = safe_plain(label, 80) if isinstance(label, str) and label.strip() else None
    out["status"] = "found"
    return out


def parse_service_index(text: str) -> dict[str, dict[str, str]]:
    """Home page 'Top wallets' table (``table.serviceslist``) -> {wallet label: {'category', 'base'}}.
    Headings: Exchanges, Pools, Services/others, Gambling, Old/historic; variant wallets map to their base."""
    body = str(text or "")
    start = body.find("serviceslist")
    if start < 0:
        return {}
    table = body[start:]
    end = table.find("</table>")
    table = table[: end if end > 0 else len(table)]
    labels: dict[str, dict[str, str]] = {}
    for block in re.split(r"<h3>", table)[1:]:
        heading = re.match(r"\s*([^<:]+):?\s*</h3>", block)
        if not heading:
            continue
        category = _CATEGORY.get(heading.group(1).strip().lower(), "service")
        for item in re.findall(r"<li>(.*?)</li>", block, re.S):
            hrefs = re.findall(r'href="/wallet/([^"]+)"', item)
            if not hrefs:
                continue
            base = safe_plain(html.unescape(hrefs[0]), 80)
            for href in hrefs:
                labels[safe_plain(html.unescape(href), 80)] = {"category": category, "base": base}
    return labels


def label_base(label: str) -> str:
    """'Huobi.com-2' / 'BTC-e.com-old' / 'BTCC.com-old2' -> the base service name."""
    return re.sub(r"-(?:\d+|old\d*|output|cold(?:-old)?|original|hot|new)$", "", str(label or ""), flags=re.I)


def classify_label(label: str, labels: dict[str, dict[str, str]] | None = None) -> dict[str, Any] | None:
    """Label -> category, stop-node and legal-request lead (cond 2, 3; P213). Every labelled wallet is a stop
    node. Exchanges, pools, gambling and other services are legal-request leads; mixers, dark-web markets,
    ransomware wallets (CryptoLocker sits under Services/others on the live page) and Ponzi schemes are not."""
    if not label:
        return None
    index = labels or {}
    entry = index.get(label)
    base = entry["base"] if entry else label_base(label)
    category = entry["category"] if entry else (index.get(base) or {}).get("category", "service")
    if category != "exchange":
        if _MIXER_RE.search(base):
            category = "mixer"
        elif _RANSOM_RE.search(base):
            category = "ransomware"
        elif _FRAUD_RE.search(base):
            category = "fraud_scheme"
        elif _MARKET_RE.search(base):
            category = "darknet_market"
    return {"label": label, "base": base, "category": category, "legal_request_lead": category not in _NOT_LEGAL_LEAD,
            "tags": ["stop_node", _TAG.get(category, "crypto_service")]}


def label_wording(classified: dict[str, Any]) -> str:
    """cond 2 wording: attribution and the stale-database caveat."""
    text = f"{LABEL_NOTE}: {classified['label']} ({classified['category'].replace('_', ' ')})"
    if classified["legal_request_lead"]:
        text += f"; a lead for a legal request to {classified['base']}, not proof of ownership"
    else:
        text += "; a lead, not proof of ownership"
    return text + " - source: WalletExplorer.com"


def validate_caller_id(caller: Any, forbidden: tuple[str, ...] = ()) -> str | None:
    """cond 1: a generic team identifier. Returns why it is refused, or None when acceptable: unset; spaces or
    URL characters; the investigated value or the case id inside it; an e-mail whose local part names no role
    (cti, soc, csirt, security, abuse...)."""
    text = str(caller or "").strip()
    if not text:
        return "walletexplorer needs a caller id: set caller_id / walletexplorer_caller_id (a generic team identifier) or the role mailbox contact_email"
    if len(text) > 80 or re.search(r"[\s<>\"'&#?/=%]", text):
        return "the caller id must be a short identifier without spaces or URL characters"
    low = text.lower()
    for value in forbidden:
        value = str(value or "").strip().lower()
        if len(value) >= 4 and value in low:
            return "the caller id must not contain an investigated value or a case id"
    if "@" in text:
        local = low.split("@", 1)[0]
        if not any(t in _ROLE_WORDS for t in re.split(r"[._+-]", local) if t):
            return "the caller id looks like a personal e-mail: use a role mailbox (e.g. cti@...) or a team id"
    return None


def _validate_index(path: Path) -> bool:
    if len(parse_service_index(Path(path).read_text(encoding="utf-8", errors="replace"))) < 20:
        raise ValueError("WalletExplorer home page without its service table")
    return True


register_dataset(
    INDEX_DATASET,
    HOME_URL,
    ttl=30 * 86400,
    description="WalletExplorer service index (home page 'Top wallets' table: exchanges, pools, services, gambling, historic); label categories for P208 cond 3",
    licence="WalletExplorer free public pages (attribution: WalletExplorer.com)",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="walletexplorer",
    source=SOURCE_INDEX,
    validate=_validate_index,
    min_bytes=256,
    expect="bytes",  # an HTML page by design: the validator requires the service table (a challenge page has none)
    max_bytes=1_000_000,
    large=False,
)


@register
class Walletexplorer(Module):
    name = "walletexplorer"
    title = "WalletExplorer (Bitcoin wallet clustering and service labels)"
    description = (
        "The WalletExplorer cluster (wallet id) of a Bitcoin address and its service label (exchange, mixer, service) when "
        "the cluster is a known service: labelled services are graph stop-nodes and leads for a legal request."
    )
    category = "crypto"
    accepts = {T.BTC}
    tags = {"free"}
    reference = "https://www.walletexplorer.com/info"
    notice = (
        "WalletExplorer receives the address and the team's caller id (never an analyst, a case id or the investigated value). "
        "Its name database is not updated since 2016: a label is a lead for a legal request, not proof of ownership."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # WalletExplorer receives the address
    provider = "walletexplorer"
    sources = (SOURCE, SOURCE_INDEX)
    hosts = ("www.walletexplorer.com",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.1
    timeout = 10.0
    min_interval = 1.0
    daily_quota = 500
    cache_ttl = 86400
    manual_link = "https://www.walletexplorer.com/address/{q}"
    default_enabled = True
    settings = {
        "walletexplorer_caller_id": _setting(
            "", "WalletExplorer 'caller' parameter: a generic team identifier (default: setting caller_id, else contact_email); never a person, case id or investigated value"
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(T.BTC, GENESIS_ADDRESS)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return btc_address_valid(str(entity.value).strip())  # P217: found:false is identical for invalid input

    @staticmethod
    def caller(ctx: Any) -> str:
        for name in ("caller_id", "walletexplorer_caller_id", "contact_email"):
            value = ctx.setting(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    @staticmethod
    def _labels(ctx: Any) -> dict[str, dict[str, str]]:
        try:
            return parse_service_index(fetch_dataset(ctx, INDEX_DATASET, "text"))
        except (DatasetError, DatasetUnavailable, OSError):
            return {}  # categories fall back to name heuristics

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        address = str(entity.value).strip()
        if not btc_address_valid(address):
            return res.mark("skipped", "not a valid Bitcoin address (core validators): never sent", reason_code="not_applicable")
        caller = self.caller(ctx)
        problem = validate_caller_id(caller, (address, getattr(ctx, "case_id", "") or ""))
        if problem:
            return res.mark("skipped", problem, reason_code="config")
        doc = ctx.http.get_json(LOOKUP_URL, params={"address": address, "caller": caller}, source=SOURCE, allow_redirects=False)
        parsed = parse_lookup(doc)
        if parsed["status"] == "error":
            return res.mark("error", parsed["reason"])
        res.link("WalletExplorer address page", ADDRESS_PAGE.format(address=quote(address, safe="")))
        res.attr("data_attribution", ATTRIBUTION)
        block = parsed["updated_to_block"]
        if parsed["status"] == "empty":
            res.attr("wallet_cluster", {"updated_to_block": block, "note": f"no cluster for this address (WalletExplorer data as of block {block})"})
            res.raw = {"found": False, "updated_to_block": block}
            return res.mark("empty")
        classified = classify_label(parsed["label"], self._labels(ctx)) if parsed["label"] else None
        cluster: dict[str, Any] = {"wallet_id": parsed["wallet_id"], "updated_to_block": block}
        res.raw = {"found": True, **cluster, "label": parsed["label"]}
        if classified is None:
            cluster["note"] = "unlabelled cluster (no known service)"
            res.attr("wallet_cluster", cluster)
            res.finding(
                "WalletExplorer cluster (unlabelled)",
                "info",
                f"The address belongs to WalletExplorer wallet {parsed['wallet_id'] or '?'} (multi-input clustering heuristic); no "
                f"service label. Data as of block {block}. Source: WalletExplorer.com.",
                confidence="possible",
                data=dict(cluster),
                source=SOURCE,
            )
            return res
        cluster.update(label=classified["label"], category=classified["category"], legal_request_lead=classified["legal_request_lead"], note=LABEL_NOTE)
        res.attr("wallet_cluster", cluster)
        res.attr("wallet_labels", [classified["label"]])
        if classified["category"] in ("exchange", "mixer"):
            res.attr("stop_node_hint", classified["category"])
        severity = {"mixer": "low", "darknet_market": "medium", "ransomware": "medium", "fraud_scheme": "medium"}.get(classified["category"], "info")
        tags = list(classified["tags"])
        recommendation = (
            f" Recommendation: a legal request to {classified['base']} can identify the account holder; do not expand the "
            "graph through this service wallet." if classified["legal_request_lead"] else " Do not expand the graph through this wallet."
        )
        res.finding(
            "WalletExplorer service label",
            severity,
            f"{label_wording(classified)}. Wallet {parsed['wallet_id'] or '?'}; data as of block {block}.{recommendation}",
            confidence="possible",
            criterion=f"WalletExplorer labels the address's cluster '{classified['label']}' ({classified['category'].replace('_', ' ')}); "
            "name database not updated since 2016",
            data=dict(cluster),
            tags=tags,
            source=SOURCE,
            key=classified["label"],
        )
        return res


__all__ = [
    "GENESIS_ADDRESS",
    "LABEL_NOTE",
    "Walletexplorer",
    "classify_label",
    "label_base",
    "label_wording",
    "parse_lookup",
    "parse_service_index",
    "validate_caller_id",
]
