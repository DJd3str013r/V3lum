"""Live checks of batch p2-G12-3 (windows_artifact_triage, P367); run with V3LUM_LIVE=1.

The module is offline (disclosure 'none'): it never touches the network, and every check asserts that it made no
request. The live part is the input and the optional-parser pins. The test harness (never the module) downloads:

* real Windows shortcuts from LnkParse3's own test suite (MIT, github.com/Matmaus/LnkParse3, base64 files under
  ``tests/samples/``) together with the JSON that LnkParse3 itself expects for them (``tests/json/``). The
  built-in [MS-SHLLINK] reader must agree with LnkParse3 on every fact the module uses; the values are compared
  at run time and never copied into the repository (they include machine names of the people who made them);
* the PyPI metadata of the three optional parsers (LnkParse3, olefile, pymsi): the pinned versions still exist,
  their licences are still permissive and no advisory is listed.

Nothing is executed. A 403/429/timeout from this datacenter egress skips that check with the reason (could not
verify the sample); the module itself cannot be blocked.
"""

from __future__ import annotations

import base64

import pytest
import requests

from tests.fakes import FakeHttp, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import windows_artifact_triage as W
from v3lum.modules.file_analysis.windows_artifact_triage import WindowsArtifactTriage

pytestmark = pytest.mark.live

LNKPARSE3_RAW = "https://raw.githubusercontent.com/Matmaus/LnkParse3/master/tests"
SAMPLES = ("microsoft_example", "network_info", "sample", "unknown_block")
PINS = {"LnkParse3": ("1.6.0", "MIT"), "olefile": ("0.47", "BSD"), "pymsi": ("0.0.0rc1", "MIT")}
MAX_SAMPLE = 2 * 1024 * 1024


def get(url: str, what: str) -> requests.Response:
    """GET one public resource (size-capped); skip the check when this egress cannot get it."""
    try:
        r = requests.get(url, timeout=30)
    except requests.RequestException as exc:
        pytest.skip(f"{what}: {type(exc).__name__} from this egress (could not verify)")
    if r.status_code != 200:
        pytest.skip(f"{what}: HTTP {r.status_code} from this egress (could not verify)")
    if len(r.content) > MAX_SAMPLE:
        pytest.skip(f"{what}: larger than {MAX_SAMPLE} bytes")
    return r


def run_offline(path: str, **kw):
    http = FakeHttp()
    res = run_module(WindowsArtifactTriage, Entity.make(T.FILE, path), http, **kw)
    assert http.calls == [] and res.requests == 0  # offline module: no request whatever the input
    return res


@pytest.mark.parametrize("name", SAMPLES)
def test_real_shortcuts_match_lnkparse3_expectations(tmp_path, name):
    data = base64.b64decode(get(f"{LNKPARSE3_RAW}/samples/{name}", f"sample {name}").content)
    expected = get(f"{LNKPARSE3_RAW}/json/{name}.json", f"expected JSON {name}").json()
    ours = W.lnk_read_builtin(data)
    hdr, theirs_hdr = ours["header"], expected["header"]
    for k in ("link_flags", "file_flags", "creation_time", "accessed_time", "modified_time", "file_size", "icon_index", "windowstyle"):
        assert hdr[k] == theirs_hdr[k], k
    assert ours["data"] == expected.get("data", {})
    li, theirs_li = ours.get("link_info") or {}, expected.get("link_info") or {}
    for k in ("location", "local_base_path", "common_path_suffix"):
        assert li.get(k) == theirs_li.get(k), k
    for k in ("drive_serial_number", "drive_type", "net_name"):
        assert (li.get("location_info") or {}).get(k) == (theirs_li.get("location_info") or {}).get(k), k
    tracker = (expected.get("extra") or {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK")
    if tracker:
        for k in ("machine_identifier", "droid_volume_identifier", "droid_file_identifier", "birth_droid_file_identifier"):
            assert ours["extra"]["DISTRIBUTED_LINK_TRACKER_BLOCK"][k] == tracker[k], k
    assert ours["size"] == expected["size"] == len(data)

    path = tmp_path / f"{name}.lnk"
    path.write_bytes(data)
    res = run_offline(str(path), settings={"windows_artifact_triage_use_extras": False})
    assert res.status in (Status.OK, Status.EMPTY)
    assert res.attributes["windows_artifact_summary"].startswith("LNK ->")
    if tracker and tracker.get("machine_identifier"):
        assert res.attributes["lnk_machine_id"] == tracker["machine_identifier"].lower()
        assert all(p.expand is False for p in res.pivots if p.relation == "lnk_metadata")
    if name == "unknown_block":  # a real cmd.exe dropper shortcut: renames and starts a .vbs
        titles = {f.title for f in res.findings}
        assert "Suspicious LNK: launches a script interpreter or system binary" in titles
    if name == "network_info":  # a share on a private address: hostile pivot, MEDIUM, never contacted
        remote = [f for f in res.findings if f.title.startswith("Suspicious LNK: target on a remote share")]
        assert remote and remote[0].severity.label == "medium"
    default = run_offline(str(path))  # with LnkParse3 when installed, the built-in reader otherwise
    assert default.status is res.status


@pytest.mark.parametrize("package", sorted(PINS))
def test_optional_parser_pins_are_still_published(package):
    version, licence = PINS[package]
    meta = get(f"https://pypi.org/pypi/{package}/{version}/json", f"PyPI {package}").json()
    info = meta.get("info") or {}
    text = " ".join(str(info.get(k) or "") for k in ("license", "license_expression")) + " " + " ".join(info.get("classifiers") or [])
    assert info.get("version") == version and licence in text
    assert "GPL" not in (info.get("license_expression") or "")
    assert meta.get("vulnerabilities") == []
