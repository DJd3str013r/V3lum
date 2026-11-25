"""Shared pytest setup: every test runs with an isolated V3LUM_HOME and no real API keys."""

from __future__ import annotations

import os

import pytest

# Keys present in the developer's environment must never leak into tests.
_KEY_ENV_PREFIXES = ("V3LUM_KEY_",)
_KEY_ENV_NAMES = {
    "SHODAN_API_KEY", "VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "OTX_API_KEY",
    "ABUSECH_AUTH_KEY", "URLSCAN_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "SECURITYTRAILS_API_KEY", "CENSYS_API_KEY",
    "HIBP_API_KEY", "HUNTER_API_KEY", "IPINFO_TOKEN", "ETHERSCAN_API_KEY", "OPENSANCTIONS_API_KEY",
    "PORTAL_TRANSPARENCIA_KEY", "NUMVERIFY_API_KEY",
}


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "v3lum_home"
    home.mkdir()
    monkeypatch.setenv("V3LUM_HOME", str(home))
    for name in list(os.environ):
        if name.startswith(_KEY_ENV_PREFIXES) or name in _KEY_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("V3LUM_") and name not in ("V3LUM_HOME", "V3LUM_LIVE"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    yield home


def pytest_collection_modifyitems(config, items):
    if os.environ.get("V3LUM_LIVE") == "1":
        return
    skip = pytest.mark.skip(reason="live API test: set V3LUM_LIVE=1 to run")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
