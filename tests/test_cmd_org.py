"""``v3lum org`` and the org profile v2 API (WP18, P378 cond 1/5/8/11, A11): strict validation with
line/field errors, 0600 saves, DNS TXT proof of control through the core resolver (FakeHttp DoH),
analyst attestation, passive seeding that needs a confirmation per proposal (a non-TTY writes
nothing), and an audit row for every profile change. Offline and deterministic."""

from __future__ import annotations

import datetime as _dt
import importlib.util
import io
import json
import os
import stat

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, add_dns_failure, allow_vocab, define_module
from v3lum.cli import main
from v3lum.core import orgprofile
from v3lum.core.entities import EntityType as T
from v3lum.core.orgprofile import OrgProfile, ProfileProblem

HAS_TOML = importlib.util.find_spec("tomllib") is not None
needs_toml = pytest.mark.skipif(not HAS_TOML, reason="TOML profiles need Python 3.11+ (tomllib)")

BAD_TOML = """\
[org]
name = "ACME"
colour = "blue"

[[domains]]
name = "acme.com.br"
verification = "txt_verified"

[[domains]]
name = "acme.com.br"
verification = "verifed"

[[asns]]
value = "AS-x"

[[cidrs]]
value = "203.0.113.5/24"

[[executives]]
name = "Some Person"
opt_in = false
informed_at = 2026-10-01
"""

BAD_JSON = {
    "org": {"name": "ACME"},
    "cnpj_roots": ["1234567"],
    "domains": [{"name": "acme.example", "verification": "attested", "attested_by": "A"}],
}


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")


@pytest.fixture()
def http(monkeypatch):
    """Runtimes built by the App go over this FakeHttp (DoH answers included)."""
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp()
    clock = FakeClock()
    fake.clock = clock

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    return fake


def _write_profile(home, data, name="org_profile.json", mode=0o600):
    path = home / name
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    path.chmod(mode)
    return path


def _audit(kind="profile_change"):
    from v3lum.core.store import Store

    with Store() as store:
        return [r for r in store.audit_rows("org-profile") if r["kind"] == kind]


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# --------------------------------------------------------------------------------------
# org check / validate
# --------------------------------------------------------------------------------------


@needs_toml
def test_check_lists_every_problem_with_line_and_field(isolated_home, capsys):
    path = _write_profile(isolated_home, BAD_TOML, "org_profile.toml")
    assert main(["org", "check"]) == 1
    out = capsys.readouterr().out
    for line, field, words in (
        (3, "org.colour", "unknown key"),
        (10, "domains[1].name", "duplicate domain acme.com.br"),
        (11, "domains[1].verification", "must be one of"),
        (14, "asns[0].value", "not a valid ASN"),
        (17, "cidrs[0].value", "host bits set"),
        (21, "executives[0].opt_in", "explicit opt_in = true"),
    ):
        assert f"{path}:{line}: {field}: " in out and words in out, (line, field)
    assert "Some Person" not in out  # executive names are never echoed


def test_check_json_profile(isolated_home, capsys):
    path = _write_profile(isolated_home, json.dumps(BAD_JSON, indent=2))
    assert main(["org", "check", str(path)]) == 1
    out = capsys.readouterr().out
    assert f"{path}:6: cnpj_roots[0]: a CNPJ root has 8 characters" in out
    assert f"{path}:9: domains[0].attested_date: the attestation date is required" in out
    assert "domains[0].attested_date: the attestation date is required" in out


def test_check_valid_profile_and_mode(isolated_home, capsys):
    path = _write_profile(isolated_home, {"domains": [{"name": "acme.example", "verification": "txt_verified"}]})
    assert main(["org", "check"]) == 0
    assert "valid" in capsys.readouterr().out
    path.chmod(0o644)
    assert main(["org", "check"]) == 1
    assert "chmod 600" in capsys.readouterr().out


def test_validate_api():
    problems = orgprofile.validate({
        "domains": ["com.br", {"name": "a.example", "verification": "seeded", "attested_by": "X"}],
        "cnpj_roots": ["43.828.151/0001-45", 43828151],
        "cidrs": ["0.0.0.0/0"],
        "card_bins": ["4111111111111111"],
        "executives": [{"name": "Person Name", "opt_in": True}],
        "favicon_hashes": ["99999999999"],
    })
    text = "\n".join(str(p) for p in problems)
    assert all(isinstance(p, ProfileProblem) and p.line == 0 for p in problems)
    for expected in (
        "domains[0].name", "public suffixes are refused", "attestation fields only apply", "full CNPJ",
        "cnpj_roots[1]: write CNPJ roots as strings", "too broad", "card_bins[0]", "executives[0].informed_at", "favicon_hashes[0]",
    ):
        assert expected in text, expected
    assert "4111111111111111" not in text and "Person Name" not in text
    assert orgprofile.validate({}) == [] and orgprofile.validate({"domains": ["acme.example"]}) == []
    assert orgprofile.validate_text("{not json", fmt="json")[0].message.startswith("invalid JSON")


# --------------------------------------------------------------------------------------
# save / token / verify_txt / attestation (API)
# --------------------------------------------------------------------------------------


def test_save_writes_0600_and_round_trips(tmp_path):
    prof = OrgProfile.from_dict({
        "org": {"name": 'ACME "Q"', "note": "n"},
        "domains": [{"name": "acme.com.br", "verification": "txt_verified", "criticality": "high"}],
        "cidrs": [{"value": "203.0.113.0/24", "note": "dc"}],
        "app_ids": [{"kind": "m365_tenant", "value": "abc", "note": "tenant"}],
        "executives": [{"name": "E", "opt_in": True, "informed_at": "2026-10-01"}],
    })
    assert prof.errors == []
    for name in ("p.json",) + (("p.toml",) if HAS_TOML else ()):
        path = orgprofile.save(prof, tmp_path / name)
        assert _mode(path) == 0o600 and orgprofile.validate(path) == []
        again = OrgProfile.load(path)
        assert again.errors == [] and again.to_dict() == prof.to_dict()
        assert prof.path == str(path) and len(prof.sha256) == 64


def test_save_refuses_an_invalid_document(tmp_path):
    prof = OrgProfile(domains=[orgprofile.DomainEntry("acme.example", "attested")])  # attested without by/date
    with pytest.raises(ValueError, match="refusing to write"):
        orgprofile.save(prof, tmp_path / "p.json")
    assert not (tmp_path / "p.json").exists()
    with pytest.raises(ValueError):
        orgprofile.save(OrgProfile(), tmp_path / "p.yaml")


def test_save_keeps_group_bits_of_a_team_profile_outside_the_home(tmp_path):
    team = tmp_path / "team" / "org.json"
    team.parent.mkdir()
    team.write_text("{}", encoding="utf-8")
    team.chmod(0o664)
    orgprofile.save(OrgProfile.from_dict({"domains": ["acme.example"]}), team)
    assert _mode(team) == 0o660  # group kept, never world


def test_txt_token_is_keyed_and_idn_normalised():
    token = orgprofile.txt_token("açúcar.com.br")
    assert len(token) == 12 and token == orgprofile.txt_token("XN--ACAR-0OA8I.com.br")
    assert orgprofile.txt_record("acme.com.br") == "v3lum-verify=" + orgprofile.txt_token("acme.com.br")
    with pytest.raises(ValueError):
        orgprofile.txt_token("com.br")


class _Answer:
    def __init__(self, records=(), status="NOERROR", error=""):
        self.records = list(records)
        self.status = status
        self.error = error

    @property
    def could_not_verify(self) -> bool:
        return self.status not in ("NOERROR", "NXDOMAIN") or bool(self.error)


class _Resolver:
    def __init__(self, answer):
        self.answer = answer
        self.asked: list[tuple[str, str]] = []

    def query(self, name, rtype="A"):
        self.asked.append((name, rtype))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_verify_txt_true_false_none():
    record = orgprofile.txt_record("acme.example")
    resolver = _Resolver(_Answer([f'"{record.upper()}"', "v=spf1 -all"]))
    assert orgprofile.verify_txt(resolver, "ACME.example") is True and resolver.asked == [("acme.example", "TXT")]
    assert orgprofile.verify_txt(_Resolver(_Answer(["v=spf1 -all"])), "acme.example") is False
    assert orgprofile.verify_txt(_Resolver(_Answer([], status="NXDOMAIN")), "acme.example") is False
    assert orgprofile.verify_txt(_Resolver(_Answer([], status="SERVFAIL")), "acme.example") is None
    assert orgprofile.verify_txt(_Resolver(_Answer([], error="timeout")), "acme.example") is None
    assert orgprofile.verify_txt(_Resolver(RuntimeError("boom")), "acme.example") is None
    assert orgprofile.verify_txt(_Resolver(_Answer([record + "x"])), "acme.example") is False  # exact value only


def test_mark_attested_and_entry_editing():
    prof = OrgProfile.from_dict({"domains": [{"name": "acme.example", "criticality": "high", "third_party_hosted": True}]})
    entry = orgprofile.mark_attested(prof, "acme.example", "Jane Analyst", "2026-11-01")
    assert entry.verification == "attested" and entry.attested_by == "Jane Analyst" and entry.criticality == "high" and entry.third_party_hosted
    future = (_dt.date.today() + _dt.timedelta(days=3)).isoformat()
    with pytest.raises(ValueError, match="future"):
        prof.mark_attested("acme.example", "J", future)
    with pytest.raises(ValueError, match="name"):
        prof.mark_attested("acme.example", "  ")
    assert prof.mark_txt_verified("new.example").verification == "txt_verified"
    with pytest.raises(ValueError, match="verified states"):
        prof.add_domain("other.example", verification="txt_verified")
    with pytest.raises(ValueError, match="already"):
        prof.add_domain("new.example")
    with pytest.raises(ValueError, match="too broad"):
        prof.add_network("cidrs", "0.0.0.0/4")
    assert prof.add_network("asns", "64500").value == "AS64500"
    assert prof.add_cnpj_root("11.222.333/0001-81") == "11222333"


# --------------------------------------------------------------------------------------
# org verify (DNS TXT through the core resolver) and --attest
# --------------------------------------------------------------------------------------


def test_verify_by_dns_txt_marks_txt_verified_and_audits(isolated_home, http, capsys):
    path = _write_profile(isolated_home, {"domains": [{"name": "acme.example", "verification": "confirmed", "criticality": "high"}]})
    record = orgprofile.txt_record("acme.example")
    add_dns(http, "acme.example", "TXT", [f'"{record}"', '"v=spf1 -all"'])
    assert main(["org", "verify", "acme.example"]) == 0
    assert "txt_verified" in capsys.readouterr().out
    prof = OrgProfile.load(path)
    entry = prof.domain_entry("acme.example")
    assert entry.verification == "txt_verified" and entry.criticality == "high"
    assert _mode(path) == 0o600
    rows = _audit()
    assert len(rows) == 1 and rows[0]["payload"]["action"] == "verify_txt" and rows[0]["payload"]["domain"] == "acme.example"
    assert rows[0]["payload"]["previous"] == "confirmed" and rows[0]["payload"]["profile_sha256_after"] == prof.sha256
    assert {h for h in http.hosts()} <= {"dns.google", "cloudflare-dns.com"}  # only the core DoH resolver


def test_verify_without_the_record_prints_it_and_changes_nothing(isolated_home, http, capsys):
    path = _write_profile(isolated_home, {"domains": ["acme.example"]})
    before = path.read_bytes()
    add_dns(http, "acme.example", "TXT", ['"v=spf1 -all"'])
    assert main(["org", "verify", "acme.example"]) == 1
    out = capsys.readouterr().out
    assert orgprofile.txt_record("acme.example") in out and "publish at acme.example" in out
    assert path.read_bytes() == before and _audit() == []


def test_verify_when_dns_cannot_answer_is_could_not_verify(isolated_home, http, capsys):
    path = _write_profile(isolated_home, {"domains": ["acme.example"]})
    before = path.read_bytes()
    add_dns_failure(http, "acme.example", "TXT", kind="servfail", provider="all")
    assert main(["org", "verify", "acme.example"]) == 1
    assert "could not verify" in capsys.readouterr().out
    assert path.read_bytes() == before and _audit() == []


def test_verify_creates_the_profile_when_missing(isolated_home, http, capsys):
    record = orgprofile.txt_record("acme.example")
    add_dns(http, "acme.example", "TXT", [record])
    assert main(["org", "verify", "acme.example"]) == 0
    path = orgprofile.default_path()
    assert path.is_file() and _mode(path) == 0o600
    assert OrgProfile.load(path).is_verified_domain("www.acme.example")


def test_attest(isolated_home, http, capsys):
    path = _write_profile(isolated_home, {"domains": ["acme.example"]})
    assert main(["org", "verify", "acme.example", "--attest"]) == 1
    assert "--by NAME" in capsys.readouterr().err
    assert main(["org", "verify", "acme.example", "--attest", "--by", "Jane Analyst", "--date", "2026-11-20"]) == 0
    entry = OrgProfile.load(path).domain_entry("acme.example")
    assert (entry.verification, entry.attested_by, entry.attested_date) == ("attested", "Jane Analyst", "2026-11-20")
    assert http.calls == []  # an attestation sends nothing
    rows = _audit()
    assert rows and rows[-1]["payload"]["action"] == "attest" and rows[-1]["payload"]["attested_by"] == "Jane Analyst"
    assert _mode(path) == 0o600


def test_changes_are_refused_on_an_invalid_or_read_only_profile(isolated_home, http, capsys):
    path = _write_profile(isolated_home, {"domains": ["acme.example"], "typo": 1})
    assert main(["org", "verify", "acme.example", "--attest", "--by", "J"]) == 1
    assert "fix them before" in capsys.readouterr().err
    assert json.loads(path.read_text())["typo"] == 1  # untouched
    if os.geteuid() != 0:  # root ignores the write bit
        path = _write_profile(isolated_home, {"domains": ["acme.example"]}, mode=0o400)
        assert main(["org", "verify", "acme.example", "--attest", "--by", "J"]) == 1
        assert "read-only" in capsys.readouterr().err


def test_show_never_prints_executive_names(isolated_home, capsys):
    _write_profile(isolated_home, {
        "org": {"name": "ACME"},
        "domains": [{"name": "acme.example", "verification": "txt_verified"}, {"name": "cdn.acme.example", "third_party_hosted": True}],
        "executives": [{"name": "Chief Person", "opt_in": True, "informed_at": "2026-10-01"}],
    })
    assert main(["org", "show"]) == 0
    out = capsys.readouterr().out
    assert "acme.example" in out and "txt_verified" in out and "executives 1" in out
    assert "Chief Person" not in out


# --------------------------------------------------------------------------------------
# org seed
# --------------------------------------------------------------------------------------

LIGHT_CALLS: list[str] = []


@pytest.fixture()
def seed_modules(clean_registry):
    """Synthetic passive sources: RDAP-like (domain -> CNPJ, sibling tenant domain), NIC.br-like
    (CNPJ -> ASN), RIPEstat-like (ASN -> prefix), plus a LIGHT module that must never run."""
    LIGHT_CALLS.clear()

    def rdap(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.CNPJ, "11.222.333/0001-81", "registrant")
        res.pivot(T.DOMAIN, "acme-group.example", "same_m365_tenant")
        res.pivot(T.DOMAIN, "unrelated.example", "links_to")
        return res

    def nicbr(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.ASN, "AS64500", "owns_network")
        return res

    def ripestat(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.CIDR, "203.0.113.0/24", "announces")
        return res

    def light(self, entity, ctx):
        LIGHT_CALLS.append(entity.key)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "light-found.example", "same_m365_tenant")
        return res

    with allow_vocab(relations=["owns_network"]):
        define_module("t_seed_rdap", [T.DOMAIN], rdap)
        define_module("t_seed_nicbr", [T.CNPJ], nicbr)
        define_module("t_seed_ripe", [T.ASN], ripestat)
        define_module("t_seed_light", [T.DOMAIN], light, opsec="light")  # selected with -M: still never runs
        yield


SEED_ARGS = ["org", "seed", "domain:acme-seed.example", "-M", "t_seed_rdap,t_seed_nicbr,t_seed_ripe,t_seed_light", "--depth", "3"]


def test_seed_in_a_non_tty_proposes_and_writes_nothing(isolated_home, http, seed_modules, capsys):
    assert main(SEED_ARGS) == 0
    out = capsys.readouterr().out
    table = out[out.index("proposals (nothing is trusted"):]  # after the live feed of the seed scan
    for value in ("acme-group.example", "11222333", "AS64500", "203.0.113.0/24"):
        assert value in table, value
    assert "unrelated.example" not in table  # not an ownership relation
    assert "nothing written" in table
    assert not orgprofile.default_path().exists() and _audit() == []
    assert LIGHT_CALLS == []  # seeding is a PASSIVE scan through the gate: never LIGHT/ACTIVE


def test_seed_needs_a_confirmation_per_proposal(isolated_home, http, seed_modules, monkeypatch, capsys):
    path = _write_profile(isolated_home, {"domains": [{"name": "acme-seed.example", "verification": "txt_verified"}]})
    # proposals in order: domain acme-group.example, network 203.0.113.0/24, ASN AS64500, CNPJ root 11222333
    monkeypatch.setattr("sys.stdin", _Tty("y\nn\ny\ny\n"))
    assert main(SEED_ARGS) == 0
    out = capsys.readouterr().out
    assert "added as 'seeded'" in out
    prof = OrgProfile.load(path)
    assert prof.errors == []
    added = prof.domain_entry("acme-group.example")
    assert added is not None and added.verification == "seeded" and not added.verified  # nothing auto-trusted
    assert [n.value for n in prof.asns] == ["AS64500"] and prof.cnpj_roots == ["11222333"]
    assert prof.cidrs == []  # declined
    assert prof.is_verified_domain("acme-seed.example")
    assert _mode(path) == 0o600
    rows = _audit()
    assert {r["payload"]["value"] for r in rows} == {"acme-group.example", "AS64500", "11222333"}
    assert all(r["payload"]["action"] == "seed" for r in rows)


def test_seed_quit_writes_nothing(isolated_home, http, seed_modules, monkeypatch, capsys):
    path = _write_profile(isolated_home, {"domains": ["acme-seed.example"]})
    before = path.read_bytes()
    monkeypatch.setattr("sys.stdin", _Tty("q\n"))
    assert main(SEED_ARGS) == 0
    assert "nothing added" in capsys.readouterr().out
    assert path.read_bytes() == before and _audit() == []


def test_seed_rejects_inputs_of_other_types(isolated_home, http, capsys):
    assert main(["org", "seed", "44d88612fea8a8f36de82e1278abb02f"]) == 1
    assert "org seed takes" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# scope draft --from-org / scope check (A7, A11 BR7, P378 cond 9)
# --------------------------------------------------------------------------------------

SCOPE_PROFILE = {
    "domains": [
        {"name": "acme.example", "verification": "txt_verified"},
        {"name": "cdn.acme.example", "verification": "attested", "attested_by": "A", "attested_date": "2026-11-01", "third_party_hosted": True},
        {"name": "shop-acme.example", "verification": "attested", "attested_by": "A", "attested_date": "2026-11-01", "third_party_hosted": True},
        {"name": "seeded-acme.example", "verification": "seeded"},
        {"name": "confirmed-acme.example", "verification": "confirmed"},
    ],
    "cidrs": [{"value": "203.0.113.0/24"}, {"value": "198.51.100.0/24", "third_party_hosted": True}],
}


@needs_toml
def test_scope_draft_excludes_third_party_hosted_and_is_never_usable_unbound(isolated_home, tmp_path, capsys):
    import tomllib

    from v3lum.core.scope import Scope

    _write_profile(isolated_home, SCOPE_PROFILE)
    draft = tmp_path / "draft.toml"
    assert main(["scope", "draft", "--from-org", "-o", str(draft)]) == 0
    assert "DRAFT" in capsys.readouterr().out
    assert _mode(draft) == 0o600
    data = tomllib.loads(draft.read_text(encoding="utf-8"))
    assert data["targets"]["domains"] == ["acme.example"]  # verified and not third-party hosted only
    assert data["targets"]["cidrs"] == []  # networks carry no verification: comments only
    assert set(data["exclusions"]["domains"]) == {"cdn.acme.example", "shop-acme.example"}
    assert data["exclusions"]["cidrs"] == ["198.51.100.0/24"]
    targets = json.dumps(data["targets"])
    for hosted in ("cdn.acme.example", "shop-acme.example", "198.51.100.0/24", "seeded-acme.example", "confirmed-acme.example"):
        assert hosted not in targets
    assert data["authorization_ref"] == "REQUIRED"
    scope = Scope.load(draft)
    assert scope.validate("REQUIRED")  # owner, contacts, ticket and window are missing: never usable as drafted
    assert not scope.targets.host_match("cdn.acme.example") and scope.excluded_host("cdn.acme.example")
    assert main(["scope", "check", str(draft), "--authorized", "PT-2026-001"]) == 1
    out = capsys.readouterr().out
    assert "unbound draft" in out and "owner is required" in out
    assert main(["scope", "draft", "--from-org", "-o", str(draft)]) == 1  # never overwritten silently
    assert "--force" in capsys.readouterr().err


def test_scope_draft_to_stdout_and_without_a_profile(isolated_home, capsys):
    assert main(["scope", "draft", "--from-org"]) == 1
    assert "no org profile" in capsys.readouterr().err
    _write_profile(isolated_home, SCOPE_PROFILE)
    assert main(["scope", "draft", "--from-org"]) == 0
    captured = capsys.readouterr()
    assert 'authorization_ref = "REQUIRED"' in captured.out and "THIS FILE IS NOT AN AUTHORIZATION" in captured.out
    assert "DRAFT" in captured.err  # the notice never pollutes a redirected draft


def test_the_active_scope_never_defaults_from_the_profile(isolated_home, tmp_path, capsys):
    """With a profile and a draft at hand, ACTIVE without an explicit --scope is still refused."""
    _write_profile(isolated_home, SCOPE_PROFILE)
    assert main(["scope", "draft", "--from-org", "-o", str(tmp_path / "draft.toml")]) == 0
    capsys.readouterr()
    rc = main(["--offline", "scan", "domain:acme.example", "--mode", "active", "--authorized", "PT-2026-001", "--json", "-f", ""])
    assert rc == 1
    assert "--scope" in capsys.readouterr().err


def test_scope_check_of_a_bound_scope(isolated_home, tmp_path, capsys):
    _write_profile(isolated_home, SCOPE_PROFILE)
    now = _dt.datetime.now(_dt.timezone.utc)
    scope = {
        "authorization_ref": "PT-2026-001", "owner": "ACME security", "contacts": ["soc@acme.example"], "ticket": "SEC-1",
        "window_start": (now - _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end": (now + _dt.timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets": {"domains": ["acme.example", "cdn.acme.example"], "cidrs": [], "url_prefixes": []},
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope), encoding="utf-8")
    assert main(["scope", "check", str(path), "--authorized", "PT-2026-001"]) == 0
    out = capsys.readouterr().out
    assert "usable now" in out and "third_party_hosted" in out and "cdn.acme.example" in out  # pointed out
    assert main(["scope", "check", str(path), "--authorized", "PT-2026-999"]) == 1
    assert "mismatch" in capsys.readouterr().out


# --------------------------------------------------------------------------------------
# docs/contract_additions/WP18.md
# --------------------------------------------------------------------------------------


def test_contract_additions_names_resolve():
    """Every backticked ``v3lum.*`` name of docs/contract_additions/WP18.md is importable, and the
    OrgProfile methods listed there exist; the seed relations named for module authors are the
    ones ``org seed`` follows."""
    import importlib
    import re
    from pathlib import Path

    from v3lum.commands import org as org_cmd

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP18.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`", doc)))
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        obj, rest = None, parts
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for attr in rest:
            if obj is None or not hasattr(obj, attr):
                missing.append(dotted)
                break
            obj = getattr(obj, attr)
    assert len(names) > 20 and not missing, missing
    for method in ("mark_txt_verified", "mark_attested", "add_domain", "add_network", "add_cnpj_root", "add_app_id", "save"):
        assert callable(getattr(OrgProfile, method)), method
    for name in ("save", "validate", "validate_text", "txt_token", "txt_record", "verify_txt", "mark_attested", "default_path", "ProfileProblem"):
        assert name in orgprofile.__all__, name
    assert {"registrant", "announces", "cert_san", "same_m365_tenant", "owns_network"} <= org_cmd.SEED_RELATIONS



def test_seed_follows_entries_the_profile_already_holds(isolated_home, http, seed_modules, capsys):
    """A CNPJ root already in the profile is not proposed again, but it still leads on to its ASN
    and the ASN's announced prefixes (domain -> CNPJ -> ASN -> prefix)."""
    _write_profile(isolated_home, {"domains": [{"name": "acme-seed.example", "verification": "txt_verified"}], "cnpj_roots": ["11222333"]})
    assert main(SEED_ARGS) == 0
    out = capsys.readouterr().out
    table = out[out.index("proposals (nothing is trusted"):]
    assert "AS64500" in table and "203.0.113.0/24" in table and "acme-group.example" in table
    assert "CNPJ root" not in table  # held already: not proposed again (only named as the parent)


def test_seed_proposals_never_walk_through_a_supplier_domain():
    from v3lum.commands.org import seed_proposals
    from v3lum.core.entities import Entity
    from v3lum.core.graph import Graph

    prof = OrgProfile.from_dict({
        "domains": [{"name": "acme.example", "verification": "txt_verified"}],
        "suppliers": [{"name": "Hosting Ltd", "domains": ["supplier.example"]}],
    })
    graph = Graph()
    seed = Entity.make("domain", "acme.example")
    supplier = Entity.make("domain", "supplier.example")
    graph.add_node(seed, 0, seed=True)
    graph.add_node(supplier, 1)
    graph.add_edge(seed, supplier, "same_m365_tenant", "m365")
    for etype, value, relation in (("cnpj", "11.222.333/0001-81", "registrant"), ("domain", "supplier-brand.example", "cert_san")):
        ent = Entity.make(etype, value)
        graph.add_node(ent, 2)
        graph.add_edge(supplier, ent, relation, "rdap")
    sibling = Entity.make("domain", "acme-group.example")
    graph.add_node(sibling, 1)
    graph.add_edge(seed, sibling, "cert_san", "ct_logs")
    values = {(p.kind, p.value) for p in seed_proposals(graph, [seed], prof)}
    assert values == {("domains", "acme-group.example")}  # nothing of (or behind) the supplier

