"""Benign, ubiquitous infrastructure that should not be pivoted on (resolvers, big providers, CDNs).

Pivoting on ``gmail.com`` or ``8.8.8.8`` explodes an investigation without adding intelligence.
Lists come from ``v3lum/data/noise.json`` (derived from MISP warninglists) plus a built-in core.
"""

from __future__ import annotations

import functools
import ipaddress

from v3lum.core import psl
from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity, EntityType, url_host

_CORE_DOMAINS = {
    # webmail / big platforms
    "gmail.com", "googlemail.com", "google.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "yandex.ru", "mail.ru", "uol.com.br",
    "bol.com.br", "terra.com.br", "ig.com.br",
    # infrastructure / CDNs / DNS hosting
    "microsoft.com", "office365.com", "outlook.office365.com", "protection.outlook.com", "googleusercontent.com",
    "cloudflare.com", "cloudflare.net", "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net",
    "fastly.net", "amazonaws.com", "awsdns-cn-01.com", "cloudfront.net", "azure.com", "azurewebsites.net",
    "windows.net", "googledomains.com", "domaincontrol.com", "registrar-servers.com", "dns-parking.com",
    "ns.cloudflare.com", "nsone.net", "ultradns.net", "dynect.net", "github.io", "githubusercontent.com",
    "gstatic.com", "googleapis.com", "facebook.com", "fbcdn.net", "apple.com", "wordpress.com", "wix.com",
    "shopify.com", "squarespace.com", "mailchimp.com", "sendgrid.net", "amazonses.com", "mimecast.com",
    "pphosted.com", "zoho.com", "locaweb.com.br", "hostgator.com.br", "kinghost.net", "uolhost.com.br",
}
_CORE_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
}


@functools.lru_cache(maxsize=1)
def _lists() -> tuple[frozenset[str], frozenset[str], tuple[ipaddress._BaseNetwork, ...]]:
    domains, ips, nets = set(_CORE_DOMAINS), set(_CORE_IPS), []
    if DataStore.bundled_exists("noise.json"):
        data = DataStore.bundled_json("noise.json")
        domains.update(d.lower() for d in data.get("domains", []))
        ips.update(data.get("ips", []))
        for cidr in data.get("cidrs", []):
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
    return frozenset(domains), frozenset(ips), tuple(nets)


def is_noise(entity: Entity) -> bool:
    domains, ips, nets = _lists()
    t = entity.type
    if t in (EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL):
        host = entity.value
        if t is EntityType.URL:
            host = url_host(entity.value)
        elif t is EntityType.EMAIL:
            return False  # an email at gmail.com is a person, not noise
        reg = psl.registrable_domain(host) or host
        return host in domains or reg in domains
    if t in (EntityType.IPV4, EntityType.IPV6):
        if entity.value in ips:
            return True
        try:
            ip = ipaddress.ip_address(entity.value)
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local:
            return True
        return any(ip.version == n.version and ip in n for n in nets)
    return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global
