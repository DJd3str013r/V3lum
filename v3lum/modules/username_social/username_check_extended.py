"""P113 username_check_extended: the opt-in username pack on the same engine (A5, FC1).

Runs only when selected (-M username_check_extended or --preset deep): the Maigret curated profile
(no protection, activation or engine entries) plus the WhatsMyName and V3LUM-calibrated sites that
are not in the default pack, at most 600 requests and 600 s per handle. Only sites recorded in the
overlay as trusted or community are ever queried (FC8); sites whose registry terms are not 'open'
run only through per-source filtering (ctx.allowed_sources, A1 BR11) and 'unknown' terms never run:
they appear in the coverage appendix as 'skipped: licence' until legal_dpo records their terms.
See v3lum/modules/username_social/username_check.py for the engine and the final conditions.
"""

from __future__ import annotations

from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec
from v3lum.core.module import register
from v3lum.modules.username_social.username_check import (
    EXTENDED_CAP,
    EXTENDED_DEADLINE,
    EXTENDED_PACK,
    GRACE,
    MIN_INTERVAL,
    SRC_MAIGRET,
    SRC_MAIGRET_META,
    SRC_SHERLOCK,
    SRC_SHERLOCK_EXCLUSIONS,
    SRC_WMN,
    UsernamePackBase,
    pack_hosts,
    pack_sources,
)

#: dataset sources the extended pack reads (Maigret only when its selection holds maigret ids)
EXTENDED_DATASET_SOURCES = (SRC_MAIGRET, SRC_MAIGRET_META, SRC_SHERLOCK, SRC_SHERLOCK_EXCLUSIONS, SRC_WMN)


@register
class UsernameCheckExtended(UsernamePackBase):
    # ---- identity -----------------------------------------------------------------------------
    name = "username_check_extended"
    title = "Username check (extended pack)"
    description = (
        "Opt-in tri-state check of a typed handle on the extended site pack (Maigret curated profile and the other "
        "WhatsMyName/V3LUM sites, tier-gated): FOUND rows, a counts line and has_account pivots; a weak signal."
    )
    category = "username_social"
    accepts = {T.USERNAME}
    produces = {T.URL, T.USERNAME}
    tags = {"pack", "curated_pack", "slow", "people_sweep", "free"}
    reference = "https://github.com/soxoj/maigret"
    notice = (
        "Opt-in username sweep (-M or --preset deep): weak signals only, the same handle does not prove identity. Each "
        "site receives the handle; sites without reviewed terms are skipped (licence) and listed in the coverage appendix."
    )
    run_on = "seeds"
    # ---- MUST be declared ------------------------------------------------------------------
    terms = "unknown"  # = most restrictive site source: About.me/Dribbble/Kaggle terms await legal_dpo (A1)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = pack_hosts(EXTENDED_PACK)  # generated from the selection list (FC3)
    max_requests = EXTENDED_CAP  # FC1: <= 600 requests per username (sites + controls)
    expected_latency = 60.0
    # ---- registry and behaviour -------------------------------------------------------------
    provider = "github"
    sources = EXTENDED_DATASET_SOURCES + pack_sources(EXTENDED_PACK)
    access_model = "free_noauth_limited"
    timeout = EXTENDED_DEADLINE + GRACE
    min_interval = MIN_INTERVAL
    cache_ttl = 86400
    max_pivots = 650
    default_enabled = False  # A5/FC1: only -M or --preset deep
    # ---- engine --------------------------------------------------------------------------------
    pack_id = EXTENDED_PACK
    default_pack = False
