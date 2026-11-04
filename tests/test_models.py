"""Contract tests for the Phase 0 data models (no Batfish, no LLM)."""

from __future__ import annotations

import json

import pytest
from pydantic import TypeAdapter, ValidationError

from netops_lens.models import (
    AclDeny,
    AclPermit,
    AclRule,
    AddStaticRoute,
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    CandidateSubmission,
    ClaimType,
    EvidenceRecord,
    FileDiff,
    Finding,
    FlowComparison,
    FlowSpec,
    Intent,
    InvestigationResult,
    RemoveAclLine,
    RemoveStaticRoute,
    Report,
    SnapshotHealth,
    SnapshotRef,
    ToolCallLog,
    ToolResult,
    VerificationResult,
)


def _round_trip(model_cls, payload):
    """JSON round trip: input preserved, and dump -> parse is a fixpoint."""
    obj = model_cls.model_validate(payload)
    assert obj.model_dump(mode="json", exclude_unset=True) == json.loads(json.dumps(payload))
    assert model_cls.model_validate_json(obj.model_dump_json()) == obj
    return obj


def test_flow_spec_icmp_round_trip():
    payload = {
        "flow_id": "app-to-db-icmp",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.1",
        "protocol": "ICMP",
        "start_location": "@enter(r1[GigabitEthernet0/1])",
    }
    obj = _round_trip(FlowSpec, payload)
    assert obj.dst_port is None


def test_flow_spec_tcp_requires_port():
    base = {
        "flow_id": "f",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.1",
        "protocol": "TCP",
        "start_location": "loc",
    }
    with pytest.raises(ValidationError):
        FlowSpec.model_validate(base)
    with pytest.raises(ValidationError):
        FlowSpec.model_validate({**base, "protocol": "ICMP", "dst_port": 1433})
    ok = FlowSpec.model_validate({**base, "dst_port": 1433})
    assert ok.dst_port == 1433


def test_flow_spec_rejects_bad_ip_and_extra_keys():
    base = {
        "flow_id": "f",
        "src_ip": "not-an-ip",
        "dst_ip": "198.51.100.1",
        "protocol": "ICMP",
        "start_location": "loc",
    }
    with pytest.raises(ValidationError):
        FlowSpec.model_validate(base)
    with pytest.raises(ValidationError):
        FlowSpec.model_validate(
            {
                "flow_id": "f",
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.1",
                "protocol": "ICMP",
                "start_location": "loc",
                "unknown": 1,
            }
        )


def test_intent_unique_ids_and_round_trip():
    flow = {
        "flow_id": "app-to-db-icmp",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.1",
        "protocol": "ICMP",
        "start_location": "@enter(r1[GigabitEthernet0/1])",
    }
    _round_trip(
        Intent,
        {
            "version": 1,
            "description": "App tier must reach the DB host",
            "must_reach": [flow],
            "must_not_reach": [],
        },
    )
    with pytest.raises(ValidationError):
        Intent.model_validate({"version": 1, "must_reach": [flow], "must_not_reach": [flow]})


def test_snapshot_ref_and_health_round_trip():
    _round_trip(SnapshotRef, {"name": "baseline", "path": "lab/baseline"})
    _round_trip(
        SnapshotHealth,
        {
            "snapshot": "baseline",
            "status": "OK",
            "per_file_parse": [{"file": "r1.cfg", "status": "PASSED"}],
            "init_issues": [],
            "nodes": ["r1", "r2"],
            "reasons": [],
            "benign_warnings": [],
        },
    )
    with pytest.raises(ValidationError):
        SnapshotHealth.model_validate({"snapshot": "b", "status": "DEGRADED"})


def test_tool_result_and_evidence_record_round_trip():
    _round_trip(
        ToolResult,
        {
            "tool": "check_intent",
            "snapshots": ["proposed"],
            "flow_id": "app-to-db-icmp",
            "status": "ok",
            "summary": "UNREACHABLE",
            "details": {"disposition": "NO_ROUTE", "hops": ["r1"], "count": 2},
            "evidence_id": "ev-0001",
        },
    )
    _round_trip(
        EvidenceRecord,
        {
            "evidence_id": "ev-0001",
            "tool": "check_intent",
            "snapshots": ["proposed"],
            "flow_id": "app-to-db-icmp",
            "disposition": "UNREACHABLE",
            "details": {"nested": {"a": [1, 2, None]}},
            "created_order": 0,
        },
    )
    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(
            {
                "evidence_id": "bad-id",
                "tool": "t",
                "snapshots": ["s"],
                "created_order": 0,
            }
        )


def test_flow_comparison_finding_assessment_round_trip():
    comparison = {
        "flow_id": "app-to-db-icmp",
        "kind": "must_reach",
        "baseline_reach": "REACHABLE",
        "proposed_reach": "UNREACHABLE",
        "classification": "REGRESSION",
    }
    finding = {
        "finding_id": "f-0001",
        "claim_type": "REACHABILITY_CHANGED",
        "flow_id": "app-to-db-icmp",
        "statement": "app-to-db-icmp changed REACHABLE -> UNREACHABLE",
        "evidence_ids": ["ev-0001", "ev-0002"],
        "severity": "error",
    }
    _round_trip(FlowComparison, comparison)
    obj = _round_trip(Finding, finding)
    assert obj.claim_type is ClaimType.REACHABILITY_CHANGED
    _round_trip(
        AssessmentResult,
        {
            "verdict": "REGRESSION_DETECTED",
            "flow_comparisons": [comparison],
            "findings": [finding],
            "inconclusive_reasons": [],
            "health": [
                {"snapshot": "baseline", "status": "OK"},
                {"snapshot": "proposed", "status": "OK"},
            ],
        },
    )


def test_patch_operation_union_and_candidate_limits():
    route_op = {
        "op": "add_static_route",
        "node": "r1",
        "prefix": "198.51.100.0/24",
        "next_hop": "10.0.12.2",
    }
    acl_op = {
        "op": "remove_acl_line",
        "node": "r1",
        "acl": "DB-FILTER",
        "sequence_number": 10,
        "expected_rule": {
            "action": "deny",
            "src": "192.0.2.0/24",
            "dst": "198.51.100.0/24",
            "protocol": "tcp",
            "dst_port": 1433,
        },
    }
    submission = _round_trip(
        CandidateSubmission,
        {
            "rationale": "restore the deleted static route",
            "operations": [route_op],
            "target_flow_ids": ["app-to-db-icmp"],
        },
    )
    assert isinstance(submission.operations[0], AddStaticRoute)
    parsed = TypeAdapter(CandidateSubmission).validate_python(
        {"rationale": "x", "operations": [acl_op], "target_flow_ids": ["f"]}
    )
    assert isinstance(parsed.operations[0], RemoveAclLine)

    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate(
            {"rationale": "x", "operations": [], "target_flow_ids": ["f"]}
        )
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate(
            {
                "rationale": "x",
                "operations": [route_op] * 6,
                "target_flow_ids": ["f"],
            }
        )
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate(
            {
                "rationale": "x",
                "operations": [{"op": "free_text_fix", "text": "reboot"}],
                "target_flow_ids": ["f"],
            }
        )


def test_candidate_patch_requires_id_and_schema_excludes_it():
    payload = {
        "candidate_id": "c-01",
        "rationale": "r",
        "operations": [
            {
                "op": "add_static_route",
                "node": "r1",
                "prefix": "198.51.100.0/24",
                "next_hop": "10.0.12.2",
            }
        ],
        "target_flow_ids": ["app-to-db-icmp"],
    }
    _round_trip(CandidatePatch, payload)
    schema = CandidateSubmission.model_json_schema()
    assert "candidate_id" not in schema["properties"]
    assert "candidate_id" in CandidatePatch.model_json_schema()["properties"]
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate({**payload})


def test_verification_investigation_report_round_trip():
    verification = {
        "candidate_id": "c-01",
        "status": "VERIFIED",
        "reasons": [],
        "checks": [{"name": "candidate_health", "outcome": "pass"}],
        "candidate_snapshot": "runs/run-1/candidate-c-01",
    }
    _round_trip(VerificationResult, verification)
    investigation = {
        "narrative": "Missing static route on r1 (f-0001).",
        "candidates": [],
        "tool_activity": [
            {
                "tool": "trace_flow",
                "args": {"flow_id": "app-to-db-icmp"},
                "evidence_id": "ev-0003",
                "latency_ms": 12.5,
            }
        ],
    }
    obj = _round_trip(InvestigationResult, investigation)
    assert isinstance(obj.tool_activity[0], ToolCallLog)
    _round_trip(
        Report,
        {
            "assessment": {
                "verdict": "NO_REGRESSION_DETECTED",
                "flow_comparisons": [],
                "findings": [],
                "inconclusive_reasons": [],
                "health": [],
            },
            "investigation": investigation,
            "verifications": [verification],
            "human_decision": {"c-01": "APPROVED"},
            "evidence_index": {},
            "traces": [],
        },
    )


def _route_op(op="add_static_route"):
    return {
        "op": op,
        "node": "r1",
        "prefix": "198.51.100.0/24",
        "next_hop": "10.0.12.2",
    }


def _acl_op(op, sequence_number=10):
    return {
        "op": op,
        "node": "r1",
        "acl": "DB-FILTER",
        "sequence_number": sequence_number,
        "src": "192.0.2.0/24",
        "dst": "198.51.100.0/24",
        "protocol": "tcp",
        "dst_port": 1433,
    }


def test_patch_operation_discriminated_union_covers_all_ops():
    expected = {
        "add_static_route": AddStaticRoute,
        "remove_static_route": RemoveStaticRoute,
        "acl_permit": AclPermit,
        "acl_deny": AclDeny,
        "remove_acl_line": RemoveAclLine,
    }
    ops = [
        _route_op("add_static_route"),
        _route_op("remove_static_route"),
        _acl_op("acl_permit"),
        _acl_op("acl_deny"),
        {
            "op": "remove_acl_line",
            "node": "r1",
            "acl": "DB-FILTER",
            "sequence_number": 10,
            "expected_rule": {
                "action": "deny",
                "src": "192.0.2.0/24",
                "dst": "198.51.100.0/24",
                "protocol": "tcp",
                "dst_port": 1433,
            },
        },
    ]
    submission = CandidateSubmission.model_validate(
        {
            "rationale": "cover every op",
            "operations": ops,
            "target_flow_ids": ["app-to-db-authorized"],
        }
    )
    assert [type(op) for op in submission.operations] == list(expected.values())


def test_patch_operation_rejects_missing_or_unknown_discriminator():
    base = {"rationale": "x", "target_flow_ids": ["f"]}
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate(
            {**base, "operations": [{**_route_op(), "op": "reboot_router"}]}
        )
    op_without_tag = dict(_route_op())
    del op_without_tag["op"]
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate({**base, "operations": [op_without_tag]})


def test_patch_operation_schema_exposes_discriminator_mapping():
    items = CandidateSubmission.model_json_schema()["properties"]["operations"]["items"]
    assert items["discriminator"]["propertyName"] == "op"
    assert set(items["discriminator"]["mapping"]) == {
        "add_static_route",
        "remove_static_route",
        "acl_permit",
        "acl_deny",
        "remove_acl_line",
    }


def test_acl_rule_allows_broad_portless_entries():
    rule = AclRule.model_validate(
        {
            "action": "permit",
            "src": "192.0.2.0/24",
            "dst": "any",
            "protocol": "TCP",
        }
    )
    assert rule.dst_port is None
    assert rule.protocol == "tcp"
    assert rule.dst == "any"


def test_targeted_acl_ops_always_require_dst_port():
    for op in ("acl_permit", "acl_deny"):
        payload = _acl_op(op)
        del payload["dst_port"]
        with pytest.raises(ValidationError):
            CandidateSubmission.model_validate(
                {
                    "rationale": "x",
                    "operations": [payload],
                    "target_flow_ids": ["f"],
                }
            )


def test_network_and_acl_validation_rejects_malformed_values():
    with pytest.raises(ValidationError):
        AddStaticRoute.model_validate({**_route_op(), "prefix": "999.0.0.0/24"})
    with pytest.raises(ValidationError):
        AddStaticRoute.model_validate({**_route_op(), "prefix": "192.0.2.1/24"})
    with pytest.raises(ValidationError):
        AddStaticRoute.model_validate({**_route_op(), "next_hop": "not-an-ip"})
    with pytest.raises(ValidationError):
        AddStaticRoute.model_validate({**_route_op(), "prefix": "198.51.100.0/33"})
    with pytest.raises(ValidationError):
        AclPermit.model_validate({**_acl_op("acl_permit"), "src": "???-net"})
    with pytest.raises(ValidationError):
        AclPermit.model_validate({**_acl_op("acl_permit"), "protocol": "gre"})
    with pytest.raises(ValidationError):
        AclPermit.model_validate({**_acl_op("acl_permit"), "sequence_number": 0})
    with pytest.raises(ValidationError):
        AclPermit.model_validate({**_acl_op("acl_permit"), "dst_port": 0})
    with pytest.raises(ValidationError):
        AclPermit.model_validate({**_acl_op("acl_permit"), "dst_port": 65536})
    with pytest.raises(ValidationError):
        AclRule.model_validate(
            {
                "action": "bogus",
                "src": "any",
                "dst": "any",
                "protocol": "tcp",
            }
        )
    incomplete = _acl_op("acl_deny")
    del incomplete["node"]
    with pytest.raises(ValidationError):
        AclDeny.model_validate(incomplete)


def test_acl_endpoints_cover_plan_vocabulary():
    assert (
        AclRule.model_validate(
            {
                "action": "deny",
                "src": "192.0.2.0/24",
                "dst": "198.51.100.0/24",
                "protocol": "tcp",
                "dst_port": 22,
            }
        ).src
        == "192.0.2.0/24"
    )
    host_rule = AclRule.model_validate(
        {"action": "permit", "src": "host 192.0.2.10", "dst": "any", "protocol": "ip"}
    )
    assert host_rule.src == "host 192.0.2.10"


def test_id_patterns_reject_malformed_references():
    for bad in ("ev-0001!", "EV-0001", "evidence-1", "ev-", "f-01x"):
        with pytest.raises(ValidationError):
            ToolResult.model_validate(
                {
                    "tool": "t",
                    "snapshots": ["s"],
                    "status": "ok",
                    "evidence_id": bad,
                }
            )
    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(
            {
                "evidence_id": "ev-0001 ",
                "tool": "t",
                "snapshots": ["s"],
                "created_order": 0,
            }
        )
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "finding_id": "finding-1",
                "claim_type": "ROUTE_ABSENT",
                "statement": "s",
                "evidence_ids": ["ev-0001"],
                "severity": "error",
            }
        )
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "finding_id": "f-0001",
                "claim_type": "ROUTE_ABSENT",
                "statement": "s",
                "evidence_ids": ["nope"],
                "severity": "error",
            }
        )
    with pytest.raises(ValidationError):
        ToolCallLog.model_validate({"tool": "t", "evidence_id": "ev-?"})
    with pytest.raises(ValidationError):
        CandidatePatch.model_validate(
            {
                "candidate_id": "candidate-1",
                "rationale": "r",
                "operations": [_route_op()],
                "target_flow_ids": ["f"],
            }
        )


def test_target_flow_ids_reject_duplicates_and_blanks():
    base = {"rationale": "x", "operations": [_route_op()]}
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate({**base, "target_flow_ids": ["f", "f"]})
    with pytest.raises(ValidationError):
        CandidateSubmission.model_validate({**base, "target_flow_ids": ["  "]})


def test_snapshot_health_consistency_rules():
    with pytest.raises(ValidationError):
        SnapshotHealth.model_validate({"snapshot": "s", "status": "OK", "reasons": ["stale parse"]})
    with pytest.raises(ValidationError):
        SnapshotHealth.model_validate({"snapshot": "s", "status": "NOT_OK"})
    ok_with_warning = SnapshotHealth.model_validate(
        {
            "snapshot": "s",
            "status": "OK",
            "reasons": [],
            "benign_warnings": ["unsupported IGMP notice (allowlisted)"],
        }
    )
    assert ok_with_warning.benign_warnings == ("unsupported IGMP notice (allowlisted)",)
    not_ok = SnapshotHealth.model_validate(
        {"snapshot": "s", "status": "NOT_OK", "reasons": ["r1.cfg failed to parse"]}
    )
    assert not_ok.status == "NOT_OK"


def _application_result() -> ApplicationResult:
    return ApplicationResult(
        candidate_id="c-01",
        applied=True,
        changed_files=("configs/r1.cfg",),
        diff=(
            FileDiff(
                file="configs/r1.cfg",
                removed=("10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433",),
                added=("10 permit tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433",),
            ),
        ),
    )


def test_file_diff_and_application_result_round_trip():
    result = _application_result()
    restored = ApplicationResult.model_validate(json.loads(result.model_dump_json()))
    assert restored == result
    assert restored.diff[0].file == "configs/r1.cfg"


def test_application_result_is_frozen():
    result = _application_result()
    with pytest.raises(ValidationError):
        result.applied = False  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.changed_files += ("configs/r2.cfg",)  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.diff[0].removed += ("extra",)  # type: ignore[misc]


def test_application_result_uses_tuples_for_collections():
    result = ApplicationResult(candidate_id="c-02", applied=False, reasons=["boom"])
    assert result.changed_files == ()
    assert result.diff == ()
    assert isinstance(result.reasons, tuple)


def test_report_applications_defaults_to_empty():
    # Phase 4.3: Report carries per-candidate application results.
    assert "applications" in Report.model_fields
    report = Report(assessment=AssessmentResult(verdict="NO_REGRESSION_DETECTED"))
    assert report.applications == []
    assert report.model_dump()["applications"] == []


def test_candidate_patch_rejects_malformed_ids():
    base = {
        "rationale": "x",
        "operations": [_route_op()],
        "target_flow_ids": ["f"],
    }
    for bad_id in ("../evil", "c-", "candidate-1"):
        with pytest.raises(ValidationError):
            CandidatePatch.model_validate({**base, "candidate_id": bad_id})


def _verification_payload(**overrides):
    payload = {
        "candidate_id": "c-01",
        "status": "VERIFIED",
        "reasons": [],
        "checks": [
            {
                "name": "candidate_health",
                "outcome": "pass",
                "detail": "candidate snapshot 'cand' health OK",
                "evidence_ids": ["ev-0001"],
            },
            {
                "name": "intent:web",
                "outcome": "pass",
                "detail": "candidate REACHABLE satisfies must_reach for flow 'web'",
                "evidence_ids": ["ev-0002"],
            },
        ],
        "evidence_ids": ["ev-0001", "ev-0002"],
        "candidate_snapshot": "cand",
    }
    payload.update(overrides)
    return payload


def test_verification_check_construction_and_serialization():
    from netops_lens.models import VerificationCheck

    check = VerificationCheck(
        name="no_regression:web",
        outcome="fail",
        detail="regression for flow 'web'",
        evidence_ids=("ev-0002", "ev-0003"),
    )
    assert check.name == "no_regression:web"
    assert check.outcome == "fail"
    assert check.evidence_ids == ("ev-0002", "ev-0003")
    restored = VerificationCheck.model_validate(json.loads(check.model_dump_json()))
    assert restored == check


def test_verification_result_round_trip_and_explicit_ids():
    from netops_lens.models import VerificationResult

    restored = VerificationResult.model_validate(_verification_payload())
    assert restored.status == "VERIFIED"
    assert restored.candidate_snapshot == "cand"
    assert [c.name for c in restored.checks] == ["candidate_health", "intent:web"]
    assert restored.evidence_ids == ("ev-0001", "ev-0002")
    assert VerificationResult.model_validate(json.loads(restored.model_dump_json())) == restored


def test_verification_result_is_frozen_with_tuple_collections():
    from netops_lens.models import VerificationResult

    result = VerificationResult.model_validate(_verification_payload())
    assert isinstance(result.checks, tuple)
    assert isinstance(result.reasons, tuple)
    assert isinstance(result.evidence_ids, tuple)
    with pytest.raises(ValidationError):
        result.status = "REJECTED"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.checks[0].detail = "rewritten"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.checks.append(object())  # type: ignore[attr-defined]


def test_verification_result_preserves_snapshot_name_verbatim():
    # The model echoes the name it is given; verify.py guarantees that value
    # is the bare snapshot name (asserted end to end in test_verify.py).
    from netops_lens.models import VerificationResult

    result = VerificationResult.model_validate(_verification_payload())
    assert json.loads(result.model_dump_json())["candidate_snapshot"] == "cand"
