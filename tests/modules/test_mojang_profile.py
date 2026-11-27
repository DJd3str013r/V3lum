"""Offline tests of mojang_profile (P116) on tests/fixtures/mojang_profile/ (found/absent are real captures of
2026-11-26: Mojang's own MHF_Steve helper account and a random control; 204/400/429 answers are synthetic)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import MojangProfile

FIX = "mojang_profile"
API = "https://api.mojang.com/users/profiles/minecraft/{}"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_profile_uuid_from_a_namemc_url():
    http = FakeHttp().add("GET", API.format("MHF_Steve"), **env("found.http.json"))
    res = run_module(MojangProfile, "url:https://namemc.com/profile/MHF_Steve", http)
    assert res.status is Status.OK
    assert res.attributes["account_id"] == "c06f89064c8a49119c29ea1dbd1aab82"
    assert res.attributes["platform_facts"]["uuid"] == "c06f8906-4c8a-4911-9c29-ea1dbd1aab82"
    assert http.hosts() == {"api.mojang.com"}  # NameMC is never contacted
    http.assert_hosts_within(MojangProfile)


def test_documented_absences():
    http = FakeHttp().add("GET", API.format("vwc6ikwm4hhrsl_z"), **env("absent.http.json"))
    res = run_module(MojangProfile, "url:https://api.mojang.com/users/profiles/minecraft/vwc6ikwm4hhrsl_z", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", API.format("vwc6ikwm4hhrsl_z"), **env("legacy_204_synthetic.http.json"))
    assert run_module(MojangProfile, "url:https://api.mojang.com/users/profiles/minecraft/vwc6ikwm4hhrsl_z", http).status is Status.EMPTY


def test_invalid_name_rate_limit_and_odd_404_are_could_not_verify():
    http = FakeHttp().add("GET", API.format("bad_name"), **env("invalid_name_synthetic.http.json"))
    assert run_module(MojangProfile, "url:https://namemc.com/profile/bad_name", http).status is Status.ERROR
    http = FakeHttp().add("GET", API.format("MHF_Steve"), **env("rate_limited_synthetic.http.json"))
    assert run_module(MojangProfile, "url:https://namemc.com/profile/MHF_Steve", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", API.format("MHF_Steve"), status=404, text="<html>gateway</html>", headers={"content-type": "text/html"})
    assert run_module(MojangProfile, "url:https://namemc.com/profile/MHF_Steve", http).status is Status.ERROR
    http = FakeHttp().add("GET", API.format("MHF_Steve"), json={"id": "not-hex", "name": "MHF_Steve"})
    assert run_module(MojangProfile, "url:https://namemc.com/profile/MHF_Steve", http).status is Status.ERROR
