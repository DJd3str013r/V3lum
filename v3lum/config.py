"""Configuration and API-key management.

Precedence (highest first): command-line flags > environment variables > config file > defaults.
API keys: ``V3LUM_KEY_<NAME>`` env vars (e.g. ``V3LUM_KEY_SHODAN``), a few conventional
aliases (``SHODAN_API_KEY``, ``GITHUB_TOKEN``...), or ``v3lum keys set <name> <value>``
which writes ``~/.v3lum/config.json`` with 0600 permissions. Keys are never printed in full.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from typing import Any

from v3lum import paths

DEFAULT_SETTINGS: dict[str, Any] = {
    "mode": "passive",  # passive | light | active
    "depth": 1,  # pivot depth (0 = only the input)
    "threads": 12,
    "timeout": 20.0,  # per HTTP request (seconds)
    "max_entities": 150,  # budget of investigated entities per scan
    "cache_ttl": 86400,  # default HTTP cache TTL (seconds)
    "dns_mode": "doh",  # doh | system
    "doh_provider": "google",  # google | cloudflare
    "proxy": "",  # e.g. socks5h://127.0.0.1:9050 (Tor) or http://proxy:3128
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "default_region": "BR",  # phone parsing region
    "report_dir": "",  # empty = ~/.v3lum/cases/<case>/
    "report_formats": ["html", "md", "json"],
    "feedback": True,  # ask "did this make sense?" after interactive scans
    "fx": True,  # banner/boot animation
    "nsfw_sites": False,  # include adult sites in username checks
}

# Known API keys: name -> (description, where to get it, env aliases)
KNOWN_KEYS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "shodan": ("Shodan API (host details, search)", "https://account.shodan.io", ("SHODAN_API_KEY",)),
    "virustotal": ("VirusTotal v3 (files, URLs, domains, IPs)", "https://www.virustotal.com/gui/my-apikey", ("VT_API_KEY", "VIRUSTOTAL_API_KEY")),
    "abuseipdb": ("AbuseIPDB (IP abuse reports)", "https://www.abuseipdb.com/account/api", ("ABUSEIPDB_API_KEY",)),
    "greynoise": ("GreyNoise (community works without key)", "https://viz.greynoise.io/account/api-key", ("GREYNOISE_API_KEY",)),
    "otx": ("AlienVault OTX", "https://otx.alienvault.com/api", ("OTX_API_KEY",)),
    "abusech": ("abuse.ch Auth-Key (URLhaus, ThreatFox, MalwareBazaar, YARAify)", "https://auth.abuse.ch/", ("ABUSECH_AUTH_KEY",)),
    "urlscan": ("urlscan.io (higher search quota)", "https://urlscan.io/user/profile/", ("URLSCAN_API_KEY",)),
    "github": ("GitHub token (raises API limit 60 -> 5000/h, no scopes needed)", "https://github.com/settings/tokens", ("GITHUB_TOKEN", "GH_TOKEN")),
    "securitytrails": ("SecurityTrails (DNS history, subdomains)", "https://securitytrails.com/app/account/credentials", ("SECURITYTRAILS_API_KEY",)),
    "censys": ("Censys Platform API token", "https://platform.censys.io/account/api", ("CENSYS_API_KEY",)),
    "hibp": ("Have I Been Pwned (paid: email breach search)", "https://haveibeenpwned.com/API/Key", ("HIBP_API_KEY",)),
    "hunter": ("Hunter.io (emails of a domain)", "https://hunter.io/api-keys", ("HUNTER_API_KEY",)),
    "ipinfo": ("ipinfo.io token (more fields/quota)", "https://ipinfo.io/account/token", ("IPINFO_TOKEN",)),
    "etherscan": ("Etherscan API (EVM chains)", "https://etherscan.io/myapikey", ("ETHERSCAN_API_KEY",)),
    "opensanctions": ("OpenSanctions API (sanctions/PEP screening)", "https://www.opensanctions.org/api/", ("OPENSANCTIONS_API_KEY",)),
    "transparencia": ("Portal da Transparencia (CGU) API key", "https://portaldatransparencia.gov.br/api-de-dados/cadastrar-email", ("PORTAL_TRANSPARENCIA_KEY",)),
    "numverify": ("numverify (phone carrier/line type)", "https://numverify.com/product", ("NUMVERIFY_API_KEY",)),
    "pulsedive": ("Pulsedive", "https://pulsedive.com/api/", ("PULSEDIVE_API_KEY",)),
    "hybridanalysis": ("Hybrid Analysis", "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab", ("HYBRID_ANALYSIS_API_KEY",)),
    "leakix": ("LeakIX", "https://leakix.net/settings/api", ("LEAKIX_API_KEY",)),
    "netlas": ("Netlas.io", "https://app.netlas.io/profile/", ("NETLAS_API_KEY",)),
    "criminalip": ("Criminal IP", "https://www.criminalip.io/mypage/information", ("CRIMINALIP_API_KEY",)),
    "fullhunt": ("FullHunt", "https://fullhunt.io/user/settings/", ("FULLHUNT_API_KEY",)),
    "intelx": ("Intelligence X (metadata search only)", "https://intelx.io/account?tab=developer", ("INTELX_API_KEY",)),
    "google_safebrowsing": ("Google Safe Browsing v4", "https://developers.google.com/safe-browsing/v4/get-started", ("GOOGLE_SAFEBROWSING_KEY",)),
    "ipqs": ("IPQualityScore", "https://www.ipqualityscore.com/create-account", ("IPQS_API_KEY",)),
    "chainabuse": ("Chainabuse (crypto scam reports)", "https://www.chainabuse.com/api", ("CHAINABUSE_API_KEY",)),
    "builtwith": ("BuiltWith", "https://api.builtwith.com/", ("BUILTWITH_API_KEY",)),
}


def _env_key(name: str) -> str:
    val = os.environ.get(f"V3LUM_KEY_{name.upper()}")
    if val:
        return val.strip()
    for alias in KNOWN_KEYS.get(name, ("", "", ()))[2]:
        val = os.environ.get(alias)
        if val:
            return val.strip()
    return ""


def mask(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}{'*' * (len(secret) - 6)}{secret[-3:]}"


@dataclass
class Config:
    settings: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_SETTINGS))
    file_keys: dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- persistence
    @classmethod
    def load(cls) -> Config:
        cfg = cls()
        path = paths.config_file()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            cfg.settings.update({k: v for k, v in (data.get("settings") or {}).items() if k in DEFAULT_SETTINGS})
            cfg.file_keys.update({k: str(v) for k, v in (data.get("keys") or {}).items() if v})
        for key, default in DEFAULT_SETTINGS.items():
            env = os.environ.get(f"V3LUM_{key.upper()}")
            if env is not None and env != "":
                cfg.settings[key] = _coerce(env, default)
        return cfg

    def save(self) -> None:
        path = paths.config_file()
        payload = {
            "settings": {k: v for k, v in self.settings.items() if DEFAULT_SETTINGS.get(k) != v},
            "keys": self.file_keys,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover - Windows
            pass
        os.replace(tmp, path)

    # ---------------------------------------------------------------- keys
    def key(self, name: str) -> str:
        return _env_key(name) or self.file_keys.get(name, "")

    def keys(self) -> dict[str, str]:
        names = set(KNOWN_KEYS) | set(self.file_keys)
        return {n: self.key(n) for n in names if self.key(n)}

    def key_source(self, name: str) -> str:
        if _env_key(name):
            return "env"
        if self.file_keys.get(name):
            return "config"
        return ""

    def set_key(self, name: str, value: str) -> None:
        self.file_keys[name.strip().lower()] = value.strip()
        self.save()

    def unset_key(self, name: str) -> bool:
        existed = self.file_keys.pop(name.strip().lower(), None) is not None
        self.save()
        return existed

    # ---------------------------------------------------------------- settings
    def get(self, name: str, default: Any = None) -> Any:
        return self.settings.get(name, DEFAULT_SETTINGS.get(name, default))

    def set(self, name: str, value: Any) -> None:
        if name not in DEFAULT_SETTINGS:
            raise KeyError(f"unknown setting {name!r}")
        self.settings[name] = _coerce(value, DEFAULT_SETTINGS[name]) if isinstance(value, str) else value
        self.save()


def _coerce(value: str, default: Any) -> Any:
    if isinstance(default, bool):
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int) and not isinstance(default, bool):
        return int(value)
    if isinstance(default, float):
        return float(value)
    if isinstance(default, list):
        return [v.strip() for v in str(value).split(",") if v.strip()]
    return value
