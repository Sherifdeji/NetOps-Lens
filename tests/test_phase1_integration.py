"""Phase 1 live-Batfish integration tests.

Skips with an explicit reason when Batfish is down (via the project's
``batfish_session`` fixture). Scenario paths resolve ONLY through
``lab/scenarios/manifest.yaml`` — never hard-coded pairs. Assertions only;
no print demonstrations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pybatfish.datamodel import HeaderConstraints, PathConstraints

from netops_lens.acl_parser import load_node_acl, parse_acl_rule_line
from netops_lens.batfish_client import BatfishClient
from netops_lens.config import load_settings

REPO_ROOT = Path(__file__).resolve().parent.parent
START = "@enter(r1[GigabitEthernet0/1])"


def _icmp() -> HeaderConstraints:
    return HeaderConstraints(srcIps="192.0.2.10", dstIps="198.51.100.1", ipProtocols=["ICMP"])


def _tcp(port: int) -> HeaderConstraints:
    return HeaderConstraints(
        srcIps="192.0.2.10",
        dstIps="198.51.100.1",
        ipProtocols=["TCP"],
        dstPorts=[port],
    )


def _disposition(records) -> str:
    """Final disposition of the first trace of the first flow row."""
    return records[0]["Traces"][0]["disposition"]


@pytest.fixture(scope="module")
def manifest() -> dict:
    with open(REPO_ROOT / "lab/scenarios/manifest.yaml") as fh:
        data = yaml.safe_load(fh)
    assert set(data["scenarios"]) == {"healthy", "removed_route", "acl_blocks_db"}
    for name, entry in data["scenarios"].items():
        for key in (
            "baseline_path",
            "proposed_path",
            "intent_path",
            "expected_verdict",
        ):
            assert key in entry, f"{name} manifest entry missing {key}"
        assert (REPO_ROOT / entry["baseline_path"]).is_dir()
        assert (REPO_ROOT / entry["proposed_path"]).is_dir()
        assert (REPO_ROOT / entry["intent_path"]).is_file()
    return data


@pytest.fixture(scope="module")
def live(manifest, batfish_session) -> dict:
    """Connected client with every manifest snapshot initialized.

    Takes ``batfish_session`` purely as the skip-with-reason health gate.
    Uses a unique run-scoped Batfish network; deleted at module teardown.
    """
    import uuid

    del batfish_session
    settings = load_settings()
    network = f"netops-lens-phase1-it-{uuid.uuid4().hex[:8]}"
    client = BatfishClient(settings.batfish_host, network)
    client.connect()
    names: dict[str, str] = {}
    for entry in manifest["scenarios"].values():
        for role in ("baseline_path", "proposed_path"):
            path = entry[role]
            if path not in names:
                snap_name = path.strip("/").replace("/", "-")
                names[path] = client.init_snapshot(REPO_ROOT / path, snap_name)
    yield {"client": client, "snapshots": names}
    try:
        client.delete_network()
    except Exception:
        pass


def _snap(live, scenario: str, role: str, manifest) -> str:
    return live["snapshots"][manifest["scenarios"][scenario][role]]


def test_manifest_and_intents_are_well_formed(manifest):
    assert set(manifest["scenarios"]) == {"healthy", "removed_route", "acl_blocks_db"}
    for name, entry in manifest["scenarios"].items():
        assert entry["expected_verdict"] in (
            "REGRESSION_DETECTED",
            "NO_REGRESSION_DETECTED",
            "INCONCLUSIVE",
        ), name
        with open(REPO_ROOT / entry["intent_path"]) as fh:
            intent = yaml.safe_load(fh)
        assert intent["version"] == 1
        flows = intent.get("must_reach", []) + intent.get("must_not_reach", [])
        ids = [f["id"] for f in flows]
        assert len(set(ids)) == len(ids), f"{name} intent has duplicate flow ids"
        for flow in flows:
            assert flow["protocol"] in ("ICMP", "TCP", "UDP")
            if flow["protocol"] in ("TCP", "UDP"):
                assert 1 <= flow["dst_port"] <= 65535
            else:
                assert "dst_port" not in flow


def test_preserved_baseline_health_ok(live, manifest):
    health = live["client"].health_records(_snap(live, "removed_route", "baseline_path", manifest))
    assert health.parse_status, "fileParseStatus returned no rows"
    assert all(r["Status"] == "PASSED" for r in health.parse_status)
    assert list(health.init_issues) == []
    assert {r["Node"] for r in health.nodes} == {"r1", "r2"}


def test_healthy_proposed_reachable(live, manifest):
    client = live["client"]
    snap = _snap(live, "healthy", "proposed_path", manifest)
    records = client.ask("traceroute", snap, startLocation=START, headers=_icmp())
    assert _disposition(records) == "ACCEPTED"


def test_removed_route_proposed_no_route(live, manifest):
    client = live["client"]
    base = _snap(live, "removed_route", "baseline_path", manifest)
    prop = _snap(live, "removed_route", "proposed_path", manifest)
    assert (
        _disposition(client.ask("traceroute", base, startLocation=START, headers=_icmp()))
        == "ACCEPTED"
    )
    assert (
        _disposition(client.ask("traceroute", prop, startLocation=START, headers=_icmp()))
        == "NO_ROUTE"
    )


def test_acl_baseline_permits_authorized_blocks_unauthorized(live, manifest):
    client = live["client"]
    snap = _snap(live, "acl_blocks_db", "baseline_path", manifest)
    assert (
        _disposition(client.ask("traceroute", snap, startLocation=START, headers=_tcp(1433)))
        == "ACCEPTED"
    )
    blocked = _disposition(client.ask("traceroute", snap, startLocation=START, headers=_tcp(22)))
    assert blocked.startswith("DENIED"), blocked


def test_acl_proposed_blocks_authorized_stays_blocked(live, manifest):
    client = live["client"]
    snap = _snap(live, "acl_blocks_db", "proposed_path", manifest)
    for port in (1433, 22):
        denied = _disposition(
            client.ask("traceroute", snap, startLocation=START, headers=_tcp(port))
        )
        assert denied.startswith("DENIED"), (port, denied)


def test_acl_parser_matches_both_fixtures(manifest):
    base_dir = REPO_ROOT / manifest["scenarios"]["acl_blocks_db"]["baseline_path"]
    prop_dir = REPO_ROOT / manifest["scenarios"]["acl_blocks_db"]["proposed_path"]
    base_rules = load_node_acl(base_dir, "r1", "DB-FILTER")
    prop_rules = load_node_acl(prop_dir, "r1", "DB-FILTER")
    assert [(r.sequence_number, r.rule.action.value) for r in base_rules] == [
        (10, "permit"),
        (20, "deny"),
    ]
    assert [(r.sequence_number, r.rule.action.value) for r in prop_rules] == [
        (10, "deny"),
        (20, "deny"),
    ]
    assert base_rules[0].rule.dst_port == 1433
    assert base_rules[1].rule.dst_port == 22
    assert prop_rules[0].rule.dst_port == 1433
    assert "10 permit tcp" in base_rules[0].raw_line
    assert "10 deny tcp" in prop_rules[0].raw_line


def test_testfilters_identifies_denying_rule(live, manifest):
    client = live["client"]
    snap = _snap(live, "acl_blocks_db", "proposed_path", manifest)
    rows = client.ask("testFilters", snap, headers=_tcp(1433), filters="DB-FILTER")
    assert rows, "testFilters returned no rows for the denied TCP/1433 flow"
    assert rows[0]["Action"] == "DENY"
    line_content = rows[0]["Line_Content"]
    assert line_content.startswith("10 "), line_content
    assert "deny" in line_content and "1433" in line_content
    # Reconcile against the parser: sequence from config, never from Batfish.
    prop_dir = REPO_ROOT / manifest["scenarios"]["acl_blocks_db"]["proposed_path"]
    parsed = {r.sequence_number: r for r in load_node_acl(prop_dir, "r1", "DB-FILTER")}
    matched = parse_acl_rule_line(line_content)
    assert matched.sequence_number == 10
    assert matched.rule == parsed[10].rule


def test_trace_steps_name_denying_filter(live, manifest):
    client = live["client"]
    snap = _snap(live, "acl_blocks_db", "proposed_path", manifest)
    records = client.ask("traceroute", snap, startLocation=START, headers=_tcp(1433))
    denied_steps = [
        step
        for hop in records[0]["Traces"][0]["hops"]
        for step in hop["steps"]
        if step["action"] == "DENIED"
    ]
    assert denied_steps, "no DENIED step in the trace"
    assert denied_steps[0]["detail"]["filter"] == "DB-FILTER"


def test_differential_reports_change_and_absence(live, manifest):
    client = live["client"]
    path = PathConstraints(startLocation=START)
    removed_base = _snap(live, "removed_route", "baseline_path", manifest)
    removed_prop = _snap(live, "removed_route", "proposed_path", manifest)
    rows = client.ask(
        "differentialReachability",
        removed_prop,
        reference_snapshot=removed_base,
        pathConstraints=path,
        headers=_icmp(),
        maxTraces=5,
    )
    assert len(rows) == 1
    assert rows[0]["Snapshot_Traces"][0]["disposition"] == "NO_ROUTE"
    assert rows[0]["Reference_Traces"][0]["disposition"] == "ACCEPTED"

    acl_base = _snap(live, "acl_blocks_db", "baseline_path", manifest)
    acl_prop = _snap(live, "acl_blocks_db", "proposed_path", manifest)
    acl_rows = client.ask(
        "differentialReachability",
        acl_prop,
        reference_snapshot=acl_base,
        pathConstraints=path,
        headers=_tcp(1433),
        maxTraces=5,
    )
    assert len(acl_rows) == 1
    assert acl_rows[0]["Snapshot_Traces"][0]["disposition"].startswith("DENIED")
    assert acl_rows[0]["Reference_Traces"][0]["disposition"] == "ACCEPTED"

    healthy_base = _snap(live, "healthy", "baseline_path", manifest)
    healthy_prop = _snap(live, "healthy", "proposed_path", manifest)
    # Absent from the result means "not reported changed" — never proof of
    # no change (the proof is the two direct check_intent results in Phase 2).
    assert (
        client.ask(
            "differentialReachability",
            healthy_prop,
            reference_snapshot=healthy_base,
            pathConstraints=path,
            headers=_icmp(),
            maxTraces=5,
        )
        == []
    )
