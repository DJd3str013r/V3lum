"""``v3lum links`` (WP18, P311 cond 5/6/8/10, A2): TLP rendering (clickable at CLEAR/GREEN,
non-clickable text with 'opening sends <value> to <host>' at AMBER and above, the RED warning),
``--open`` confirmation (refused in a non-TTY at AMBER+), grouping by analyst question with verified
links first, flagged entities, touches_target links and privacy links. Never fetches anything."""

from __future__ import annotations

import io
import json
import re

import pytest

from v3lum.cli import main
from v3lum.core import links as linklib

PACK = {
    "schema": "v3lum.pivot_pack/1",
    "pack": "wp18_test",
    "title": "WP18 test pack",
    "links": [
        {
            "id": "live_view", "label": "Live screenshot of the site", "template": "https://screens.example.org/shot?u={q}",
            "entity_types": ["domain"], "category": "history", "host": "screens.example.org", "verified": False,
            "checked_at": "2026-11-26", "privacy": False, "publishes": False, "touches_target": True,
            "login_required": False, "antibot": False, "notes": "test",
        },
        {
            "id": "rep", "label": "Reputation page", "template": "https://rep.example.org/d/{q}", "entity_types": ["domain"],
            "category": "reputation", "host": "rep.example.org", "verified": True, "checked_at": "2026-11-26",
            "privacy": False, "publishes": False, "touches_target": False, "login_required": False, "antibot": False, "notes": "test",
        },
        # core tests never rely on module-batch pivot packs: the username and URL links come from here
        {
            "id": "user_profile", "label": "Profile page", "template": "https://github.com/{user}", "entity_types": ["username"],
            "category": "social", "host": "github.com", "verified": True, "checked_at": "2026-11-26",
            "privacy": True, "publishes": False, "touches_target": False, "login_required": False, "antibot": False, "notes": "test",
        },
        {
            "id": "url_rep", "label": "URL reputation page", "template": "https://rep.example.org/u?q={q}", "entity_types": ["url"],
            "category": "reputation", "host": "rep.example.org", "verified": True, "checked_at": "2026-11-26",
            "privacy": False, "publishes": False, "touches_target": False, "login_required": False, "antibot": False, "notes": "test",
        },
    ],
}
DOMAIN = "domain:acme-portal.example"  # .example is not an IANA TLD: force the type


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def browser(monkeypatch):
    """Record webbrowser.open instead of opening anything; wide console."""
    monkeypatch.setenv("COLUMNS", "250")
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url, *a, **k: opened.append(url) or True)
    return opened


@pytest.fixture()
def test_pack(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "wp18_test.json").write_text(json.dumps(PACK), encoding="utf-8")
    linklib.reload([str(packs)])
    assert not [e for e in linklib.errors() if "wp18_test" in e]
    yield
    linklib.reload()


@pytest.fixture()
def flagged(monkeypatch):
    """The case DB knows the entity with a hostile verdict (WP16 Store.sightings_for)."""
    from v3lum.core.store import SightingsSummary, Store

    def sightings_for(self, entity, *, case_id="", case_tlp=""):
        return SightingsSummary(visible=[{"case_id": "20261101-000000-abcd", "created": "2026-11-01", "verdict": "malicious", "tlp": "amber", "case_verdict": ""}])

    monkeypatch.setattr(Store, "sightings_for", sightings_for)


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["links", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


# --------------------------------------------------------------------------------------
# TLP rendering
# --------------------------------------------------------------------------------------


def test_clear_prints_clickable_urls(capsys):
    rc, out, _ = _run(capsys, "8.8.8.8", "--tlp", "clear")
    assert rc == 0
    assert "TLP:CLEAR" in out and "https://www.shodan.io/host/8.8.8.8" in out
    assert "opening sends" not in out


def test_amber_default_is_non_clickable_with_the_disclosure_note(capsys):
    rc, out, _ = _run(capsys, "8.8.8.8")  # setting tlp: amber (A2)
    assert rc == 0
    assert "TLP:AMBER" in out
    assert "hxxps://www[.]shodan[.]io/host/8.8.8.8" in out and "https://www.shodan.io" not in out
    assert "opening sends 8.8.8.8 to www.shodan.io" in out


def test_red_lists_third_party_links_only_here_with_the_warning(capsys):
    rc, out, _ = _run(capsys, "8.8.8.8", "--tlp", "red")
    assert rc == 0
    assert "TLP:RED" in out and "listed only here" in out and "reports hide them" in out
    assert "opening sends 8.8.8.8 to www.shodan.io" in out


def test_json_carries_the_rendering_decision(capsys):
    rc, out, _ = _run(capsys, "8.8.8.8", "--json")
    assert rc == 0
    rows = json.loads(out)
    shodan = next(r for r in rows if r["host"] == "www.shodan.io")
    assert shodan["entity"] == "ipv4:8.8.8.8" and shodan["url"] == "https://www.shodan.io/host/8.8.8.8"
    assert shodan["clickable"] is False and shodan["tlp"] == "amber"
    assert shodan["disclosure"] == "opening sends 8.8.8.8 to www.shodan.io"
    rc, out, _ = _run(capsys, "8.8.8.8", "--json", "--tlp", "green")
    assert all(r["clickable"] for r in json.loads(out) if not r["touches_target"])


# --------------------------------------------------------------------------------------
# --open
# --------------------------------------------------------------------------------------


def test_open_is_refused_in_a_non_tty_at_amber(capsys, browser):
    rc, _out, err = _run(capsys, "8.8.8.8", "--open", "1")
    assert rc == 1
    assert "interactive confirmation" in err and "TLP:AMBER" in err
    assert browser == []


def test_open_at_amber_asks_naming_the_host(capsys, monkeypatch, browser):
    rows = json.loads((main(["links", "8.8.8.8", "--json"]), capsys.readouterr().out)[1])
    index = next(i for i, r in enumerate(rows, 1) if r["host"] == "www.shodan.io")
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    rc, out, _ = _run(capsys, "8.8.8.8", "--open", str(index))
    assert rc == 0 and browser == [] and "not opened" in out
    assert "open www.shodan.io?" in out and "opening sends 8.8.8.8 to www.shodan.io" in out
    monkeypatch.setattr("sys.stdin", _Tty("y\n"))
    rc, out, _ = _run(capsys, "8.8.8.8", "--open", str(index))
    assert rc == 0 and browser == ["https://www.shodan.io/host/8.8.8.8"]


def test_open_at_clear_opens_without_a_prompt(capsys, browser):
    rows = json.loads((main(["links", "8.8.8.8", "--json", "--tlp", "clear"]), capsys.readouterr().out)[1])
    index = next(i for i, r in enumerate(rows, 1) if r["host"] == "www.shodan.io")
    rc, _out, _err = _run(capsys, "8.8.8.8", "--tlp", "clear", "--open", str(index))
    assert rc == 0 and browser == ["https://www.shodan.io/host/8.8.8.8"]


def test_open_out_of_range(capsys, browser):
    rc, _out, err = _run(capsys, "8.8.8.8", "--tlp", "clear", "--open", "999")
    assert rc == 1 and "--open must be between 1 and" in err and browser == []


# --------------------------------------------------------------------------------------
# grouping, badges, touches_target, flagged entities, privacy
# --------------------------------------------------------------------------------------


def test_grouped_by_analyst_question_verified_first(capsys, test_pack):
    rc, out, _ = _run(capsys, DOMAIN, "--json", "--tlp", "clear")
    assert rc == 0
    rows = json.loads(out)
    order = {c: i for i, c in enumerate(linklib.LINK_CATEGORIES)}
    ranks = [order[r["category"]] for r in rows]
    assert ranks == sorted(ranks)  # grouped by analyst question, in LINK_CATEGORIES order
    for cat in {r["category"] for r in rows}:
        flags = [r["verified"] for r in rows if r["category"] == cat]
        assert flags == sorted(flags, reverse=True)  # verified first inside each group
    rep = next(r for r in rows if r["ref"] == "wp18_test:rep")
    assert rep["badge"] == "unknown operator" and rep["tier"] == "unknown"
    live = next(r for r in rows if r["ref"] == "wp18_test:live_view")
    assert live["touches_target"] and not live["clickable"] and "unverified" in live["badge"]


def test_touches_target_links_are_defanged_and_confirmed_even_at_clear(capsys, test_pack, browser):
    rc, out, _ = _run(capsys, DOMAIN, "--tlp", "clear")
    assert rc == 0
    assert "hxxps://screens[.]example[.]org/shot?u=" in out and "touches target" in out
    assert "it opens the target or makes a third party fetch it live" in out
    rows = json.loads((main(["links", DOMAIN, "--json", "--tlp", "clear"]), capsys.readouterr().out)[1])
    index = next(i for i, r in enumerate(rows, 1) if r["ref"] == "wp18_test:live_view")
    rc, _out, err = _run(capsys, DOMAIN, "--tlp", "clear", "--open", str(index))
    assert rc == 1 and "interactive confirmation" in err and browser == []


def test_flagged_entity_shows_the_contact_warning_first(capsys, test_pack, flagged):
    rc, out, _ = _run(capsys, DOMAIN, "--tlp", "clear")
    assert rc == 0
    warning = out.index("flagged: case-DB sighting with verdict malicious")
    first_link = out.index("  1 ")
    assert warning < first_link
    assert "screens.example.org" not in out and "screens[.]example[.]org" not in out  # touches_target hidden
    assert "hidden for a flagged entity" in out
    rc, out, _ = _run(capsys, DOMAIN, "--tlp", "clear", "--all")
    assert "screens[.]example[.]org" in out  # expanded on request, still non-clickable
    rows = json.loads((main(["links", DOMAIN, "--json"]), capsys.readouterr().out)[1])
    assert rows and all(r["flagged"] for r in rows)


def test_privacy_links_only_with_show_personal(capsys, test_pack):
    rc, out, _ = _run(capsys, "user:octocat", "--tlp", "green")
    assert rc == 0 and "github.com/octocat" not in out
    rc, out, _ = _run(capsys, "user:octocat", "--tlp", "green", "--show-personal")
    assert rc == 0 and "https://github.com/octocat" in out


def test_cpf_never_appears_in_a_link(capsys):
    rc, out, _ = _run(capsys, "cpf:529.982.247-25", "--tlp", "clear", "--show-personal")
    assert rc == 0
    assert "529982247" not in out and "529.982.247-25" not in out
    assert "no pivot links" in out


def test_unreadable_input_is_an_error(capsys):
    rc, _out, err = _run(capsys, "ipv4:not-an-ip")
    assert rc == 1 and err


def test_the_investigated_url_is_never_printed_clickable(capsys):
    """P311 cond 8: the investigated URL itself is defanged in the header and in every disclosure
    note (terminals link raw URLs), at every TLP; the JSON keeps the raw value."""
    target = "https://evil-portal.example/secure/verify"
    for tlp in ("clear", "amber"):
        rc, out, _ = _run(capsys, f"url:{target}", "--tlp", tlp)
        assert rc == 0
        # never standalone (a pivot URL may carry it inside its own path: that link opens the pivot site)
        assert not re.search(r"(?:^|\s)" + re.escape(target), out, re.M), tlp
        assert "hxxps://evil-portal[.]example/secure/verify" in out
    rc, out, _ = _run(capsys, f"url:{target}", "--json")
    assert rc == 0 and all(r["entity"] == f"url:{target}" for r in json.loads(out))


def test_open_prompt_defangs_the_investigated_url_and_escapes_markup(capsys, monkeypatch, browser, test_pack):
    target = "url:https://evil-portal.example/a[bold]b"
    rows = json.loads((main(["links", target, "--json"]), capsys.readouterr().out)[1])
    assert rows
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    rc, out, _ = _run(capsys, target, "--open", "1")
    assert rc == 0 and browser == [] and "not opened" in out
    prompt = next(line for line in out.splitlines() if "? opening sends" in line)
    assert "hxxps://evil-portal[.]example/a[bold]b" in prompt  # defanged, markup shown literally
    assert not re.search(r"(?:^|\s)https://evil-portal\.example", prompt)
