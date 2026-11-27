"""Live checks of batch p3-G12-2 (vin_decoder, elf_triage); run with V3LUM_LIVE=1.

vin_decoder asks NHTSA vPIC about the widely published documentation VIN 1HGCM82633A004352 (the research
sample: a 2003 Honda Accord; it identifies no case vehicle). A 403/429/challenge from this datacenter egress is an
acceptable outcome when it is reported as could not verify for the vPIC source (never 'no vehicle data'): the
check then skips with the reason. elf_triage is offline: its live check parses a real system binary of this host
(no network) to exercise the bounded standard-library reader on a full-size ELF.
"""

from __future__ import annotations

import os
import shutil

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis.elf_triage import ElfTriage
from v3lum.modules.utility import vin_decoder as vd
from v3lum.modules.utility.vin_decoder import VinDecoder

pytestmark = pytest.mark.live
DOC_VIN = "1HGCM82633A004352"


def test_vin_decoder_decodes_the_documentation_vin_with_vpic():
    res = run_module(VinDecoder, Entity.make(T.VIN, DOC_VIN), runtime=Runtime(Config(), no_cache=True))
    assert res.status is Status.OK  # the offline facts always stand
    assert res.attributes["vin_country"] == "United States" and res.attributes["vin_validity"] == "valid"
    st = res.source_statuses.get(vd.SRC_VPIC)
    if st and st["status"] in ("blocked", "rate_limited", "error", "quota"):
        pytest.skip(f"vPIC could not verify from this egress: {st['status']} {st['reason'][:160]}")
    assert res.attributes["vehicle_make"] == "HONDA" and res.attributes["vehicle_model"] == "Accord"
    assert res.attributes["vehicle_model_year"] == "2003"
    assert res.attributes["vpic_result"]["error_codes"] == [0]
    assert DOC_VIN not in str(res.attributes) and res.requests == 1


def test_elf_triage_parses_a_real_system_binary():
    path = os.path.realpath(shutil.which("ls") or "/bin/ls")
    if not os.path.isfile(path):
        pytest.skip("no system binary to parse on this host")
    with open(path, "rb") as fh:
        if fh.read(4) != b"\x7fELF":
            pytest.skip("the system binaries of this host are not ELF")
    res = run_module(ElfTriage, Entity.make(T.FILE, path))
    assert res.status is Status.OK and res.requests == 0
    assert res.attributes["elf_linkage"] in ("dynamic", "static") and res.attributes["elf_arch"]
    assert res.attributes["elf_symbols"]["imports_count"] >= 0 and res.attributes["elf_sections"]
