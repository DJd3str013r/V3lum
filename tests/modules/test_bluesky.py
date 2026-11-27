"""Offline tests of the bluesky module (P099) on trimmed real AppView/PLC answers (tests/fixtures/bluesky/)."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, add_dns, add_dns_failure, fixture, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.bluesky import Bluesky, normalise_actor, parse_plc_audit, plc_audit_url

APPVIEW = "https://public.api.bsky.app/xrpc/"
OFFICIAL_DID = "did:plc:z72i7hdynmk6r22z27h6tvur"


def profile_url(actor: str) -> str:
    return f"{APPVIEW}app.bsky.actor.getProfile?actor={actor}"


def resolve_url(handle: str) -> str:
    return f"{APPVIEW}com.atproto.identity.resolveHandle?handle={handle}"


def search_url(term: str) -> str:
    return f"{APPVIEW}app.bsky.actor.searchActors?q={term}&limit=10"


def plc(did: str) -> str:
    return f"https://plc.directory/{did}/log/audit"


def env(name: str) -> dict:
    d = module_fixture("bluesky", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def official(http: FakeHttp) -> FakeHttp:
    http.add("GET", profile_url("bsky.app"), json=module_fixture("bluesky", "getprofile_ok.json"))
    http.add("GET", resolve_url("bsky.app"), json=module_fixture("bluesky", "resolvehandle_ok.json"))
    http.add("GET", plc(OFFICIAL_DID), json=module_fixture("bluesky", "plc_audit_ok.json"))
    add_dns(http, "_atproto.bsky.app", "TXT", [f"did={OFFICIAL_DID}"])
    return http


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def test_custom_domain_handle_confirmed_with_history():
    http = official(FakeHttp())
    res = run_module(Bluesky, "bsky_handle:bsky.app", http)
    assert res.status is Status.OK
    link = res.attributes["bsky_domain_link"]
    assert link["confidence"] == "confirmed"
    assert set(link["basis"]) == {"getProfile handle", "resolveHandle DID", "DNS TXT _atproto"}
    assert link["checked_at"]  # handles can be transferred: the check date is kept (cond 5)
    p = pivots(res)
    dom = p[("domain", "bsky.app")]
    assert dom.relation == "handle_domain" and dom.confidence_label == "confirmed" and dom.expand is True
    prev = p[("username", "bluesky-team")]
    assert prev.relation == "previous_handle" and prev.expand is False and prev.confidence_label == "probable"
    history = res.attributes["handle_history"]
    assert [t["handle"] for t in history["timeline"]] == ["bluesky-team.bsky.social", "bsky.app", "bsky.app"]
    assert history["timeline"][-1]["pds"] == "https://puffball.us-east.host.bsky.network"
    assert "self_hosted_pds" not in res.attributes  # *.bsky.network is Bluesky's own hosting
    assert res.attributes["presence"]["state"] == "found"
    # cond 6: never the subject-controlled .well-known/atproto-did nor a did.json
    assert not [u for u in http.urls() if ".well-known" in u or u.endswith("did.json")]
    http.assert_hosts_within(Bluesky, extra=("dns.google", "cloudflare-dns.com"))


def test_username_is_normalised_and_bio_email_never_harvested():
    http = FakeHttp()
    http.add("GET", profile_url("example-dev.bsky.social"), json=module_fixture("bluesky", "getprofile_bsky_social.json"))
    http.add("GET", plc("did:plc:examplehandleexample2345"), json=module_fixture("bluesky", "plc_audit_legacy_tombstone.json"))
    res = run_module(Bluesky, "username:example-dev", http)
    assert res.status is Status.OK
    p = pivots(res)
    assert p[("bsky_handle", "example-dev.bsky.social")].expand is False
    assert not [k for k in p if k[0] == "email"]  # the bio's e-mail is not harvested
    assert not [k for k in p if k[0] == "domain"]  # a hosted handle is no domain link
    history = res.attributes["handle_history"]
    assert history["nullified_skipped"] == 1 and history["tombstoned_at"] == "2025-01-01T10:00:00Z"
    assert res.attributes["self_hosted_pds"] == ["https://pds.example.com"]
    old = p[("username", "old-example")]
    assert old.relation == "previous_handle" and old.confidence_label == "probable" and old.expand is False
    claimed = p[("username", "example.com")]
    assert claimed.confidence_label == "possible" and claimed.expand is False  # past custom domain: self-asserted
    assert "resolveHandle" not in " ".join(http.urls())  # hosted handles need no domain check


def test_profile_not_found_400_is_absent():
    http = FakeHttp().add("GET", profile_url("qz7k2v9m4p1w8n3x5c6b.bsky.social"), **env("getprofile_not_found.http.json"))
    res = run_module(Bluesky, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent"
    assert "Profile not found" in res.attributes["presence"]["marker"]


def test_other_400_is_not_applicable():
    http = FakeHttp().add("GET", profile_url("weird-handle.example.org"), **env("getprofile_invalid_syntax.http.json"))
    res = run_module(Bluesky, "bsky_handle:weird-handle.example.org", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_bad_syntax_and_did_web_send_nothing():
    http = FakeHttp()
    res = run_module(Bluesky, "username:under_score", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res = run_module(Bluesky, "url:https://bsky.app/profile/did:web:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []
    assert normalise_actor("did:web:example.com")["actor"] is None
    assert plc_audit_url("did:web:example.com") is None and plc_audit_url("did:plc:short") is None


def test_handle_invalid_and_did_mismatch_are_possible():
    http = FakeHttp()
    http.add("GET", profile_url("custom.example.net"), json=module_fixture("bluesky", "getprofile_handle_invalid.json"))
    http.add("GET", resolve_url("custom.example.net"), json=module_fixture("bluesky", "resolvehandle_other_did.json"))
    http.add("GET", plc("did:plc:exampleexampleexample234"), **{**env("plc_audit_not_found.http.json")})
    add_dns_failure(http, "_atproto.custom.example.net", "TXT", kind="servfail")
    add_dns_failure(http, "_atproto.custom.example.net", "TXT", kind="servfail", provider="cloudflare")
    res = run_module(Bluesky, "bsky_handle:custom.example.net", http)
    assert res.status is Status.OK
    link = res.attributes["bsky_domain_link"]
    assert link["confidence"] == "possible"
    assert any("handle.invalid" in p for p in link["problems"]) and any("differs" in p for p in link["problems"])
    dom = pivots(res)[("domain", "custom.example.net")]
    assert dom.confidence_label == "possible" and dom.expand is False
    assert ("bsky_handle", "handle.invalid") not in pivots(res)


def test_domain_seed_official_account_and_candidates():
    http = FakeHttp()
    http.add("GET", resolve_url("bsky.app"), json=module_fixture("bluesky", "resolvehandle_ok.json"))
    http.add("GET", profile_url(OFFICIAL_DID), json=module_fixture("bluesky", "getprofile_ok.json"))
    http.add("GET", plc(OFFICIAL_DID), json=module_fixture("bluesky", "plc_audit_ok.json"))
    http.add("GET", search_url("bsky.app"), json=module_fixture("bluesky", "searchactors_ok.json"))
    add_dns(http, "_atproto.bsky.app", "TXT", [f"did={OFFICIAL_DID}"])
    res = run_module(Bluesky, "domain:bsky.app", http)
    assert res.status is Status.OK
    p = pivots(res)
    acct = p[("bsky_handle", "bsky.app")]
    assert acct.relation == "official_account" and acct.confidence_label == "confirmed" and acct.expand is False
    cand = res.attributes["candidate_accounts"]
    assert cand["label"] == "candidate accounts named like bsky.app" and cand["returned"] == 3
    named = [v for k, v in p.items() if v.relation == "named_like"]
    assert named and all(v.confidence_label == "possible" and v.expand is False for v in named)
    assert any(f.title == "Bluesky account uses this domain as its handle" for f in res.findings)
    assert len(http.calls) <= Bluesky.max_requests + 2  # + DoH (not counted)


def test_domain_nobody_claims_is_empty():
    http = FakeHttp()
    http.add("GET", resolve_url("example.com"), **env("resolvehandle_not_found.http.json"))
    http.add("GET", search_url("example.com"), json=module_fixture("bluesky", "searchactors_empty.json"))
    res = run_module(Bluesky, "domain:example.com", http)
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent"


def test_keyword_search_top_10_candidates_never_identity_links():
    http = FakeHttp().add("GET", search_url("candidate"), json=module_fixture("bluesky", "searchactors_many.json"))
    res = run_module(Bluesky, "keyword:candidate", http)
    assert res.status is Status.OK
    assert res.attributes["candidate_accounts"]["returned"] == 12
    assert len(res.attributes["candidate_accounts"]["candidates"]) == 10
    named = [p for p in res.pivots if p.relation == "named_like"]
    assert len(named) == 10 and all(p.expand is False and p.confidence_label == "possible" for p in named)
    empty = run_module(Bluesky, "keyword:nobody", FakeHttp().add("GET", search_url("nobody"), json={"actors": []}))
    assert empty.status is Status.EMPTY


def test_429_5xx_malformed_and_error_in_200_are_could_not_verify():
    res = run_module(Bluesky, "bsky_handle:bsky.app", FakeHttp().add("GET", profile_url("bsky.app"), **env("rate_limited.http.json")))
    assert res.status is Status.RATE_LIMITED
    html = module_fixture("bluesky", "getprofile_html.html")
    res = run_module(Bluesky, "bsky_handle:bsky.app", FakeHttp().add("GET", profile_url("bsky.app"), status=503, text=html))
    assert res.status is Status.ERROR
    bad = module_fixture("bluesky", "getprofile_malformed.txt")
    res = run_module(Bluesky, "bsky_handle:bsky.app", FakeHttp().add("GET", profile_url("bsky.app"), body=bad.encode(),
                                                                         headers={"content-type": "application/json"}))
    assert res.status is Status.ERROR
    in200 = {"error": "InternalServerError", "message": "Internal Server Error"}
    res = run_module(Bluesky, "bsky_handle:bsky.app", FakeHttp().add("GET", profile_url("bsky.app"), json=in200))
    assert res.status is Status.ERROR


def test_plc_failure_keeps_the_profile_and_is_reported_per_source():
    http = FakeHttp()
    http.add("GET", profile_url("example-dev.bsky.social"), json=module_fixture("bluesky", "getprofile_bsky_social.json"))
    http.add("GET", plc("did:plc:examplehandleexample2345"), status=502, text="bad gateway", times=5)
    res = run_module(Bluesky, "username:example-dev", http)
    assert res.status is Status.OK
    assert res.source_statuses["bluesky.plc_audit"]["status"] in ("error", Status.ERROR)


def test_plc_log_is_capped_at_200_entries():
    entry = json.loads(json.dumps(module_fixture("bluesky", "plc_audit_ok.json")[0]))
    entries = []
    for i in range(250):
        e = json.loads(json.dumps(entry))
        e["operation"]["alsoKnownAs"] = [f"at://h{i}.bsky.social"]
        e["createdAt"] = f"2024-01-01T00:{i // 60:02d}:{i % 60:02d}.000Z"
        entries.append(e)
    audit = parse_plc_audit(entries)
    assert audit["truncated"] is True and audit["dropped"] == 50 and len(audit["timeline"]) == 200
    assert audit["timeline"][0]["handle"] == "h0.bsky.social" and audit["timeline"][-1]["handle"] == "h249.bsky.social"


def test_runs_on_analyst_typed_seeds_only():
    # cond 3/8: the policy gate (POL-07) refuses pivots for run_on='seeds' modules
    assert Bluesky.run_on == "seeds"
    assert Bluesky.default_enabled is True and Bluesky.terms == "open" and Bluesky.trust_tier == "trusted"
    assert set(Bluesky.hosts) == {"public.api.bsky.app", "plc.directory"}


def test_golden_domain_acceptance_routes_replay():
    routes = fixture("acceptance/domain/bluesky.json")
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "bluesky"
    http = FakeHttp()
    for r in routes["routes"]:
        body = {"json": r["json"]} if "json" in r else {"text": r["text"]}
        http.add(r["method"], r["url"], status=r["status"], headers=r.get("headers"), **body)
    res = run_module(Bluesky, "domain:example.com", http)
    assert res.status is Status.OK  # no account claims example.com; name-search candidates only
    assert res.attributes["presence"]["state"] == "absent"
    assert all(p.relation == "named_like" and p.expand is False for p in res.pivots)
    assert len(http.calls) == len(routes["routes"])
