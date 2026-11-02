"""Deep-immutability guarantees for the Stage A assessment graph.

Every field reachable from ``AssessmentResult`` is frozen (pydantic
``frozen=True``) and every collection is a tuple, so no pipeline stage —
and no model output — can mutate a verdict, finding, or health record.
No Batfish, no LLM.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netops_lens.models import AssessmentResult


def _assessment() -> AssessmentResult:
    return AssessmentResult.model_validate(
        {
            "verdict": "REGRESSION_DETECTED",
            "flow_comparisons": [
                {
                    "flow_id": "app-to-db-icmp",
                    "kind": "must_reach",
                    "baseline_reach": "REACHABLE",
                    "proposed_reach": "UNREACHABLE",
                    "classification": "REGRESSION",
                }
            ],
            "findings": [
                {
                    "finding_id": "f-0001",
                    "claim_type": "REACHABILITY_CHANGED",
                    "flow_id": "app-to-db-icmp",
                    "statement": "app-to-db-icmp changed REACHABLE -> UNREACHABLE",
                    "evidence_ids": ["ev-0001", "ev-0002"],
                    "severity": "error",
                }
            ],
            "inconclusive_reasons": [],
            "health": [
                {"snapshot": "baseline", "status": "OK"},
                {
                    "snapshot": "proposed",
                    "status": "NOT_OK",
                    "reasons": ["r1.cfg failed to parse"],
                },
            ],
        }
    )


def test_verdict_assignment_fails():
    assessment = _assessment()
    with pytest.raises(ValidationError):
        assessment.verdict = "INCONCLUSIVE"  # type: ignore[misc]


def test_flow_comparisons_append_fails():
    assessment = _assessment()
    assert isinstance(assessment.flow_comparisons, tuple)
    with pytest.raises(AttributeError):
        assessment.flow_comparisons.append(object())  # type: ignore[attr-defined]


def test_nested_flow_comparison_mutation_fails():
    assessment = _assessment()
    with pytest.raises(ValidationError):
        assessment.flow_comparisons[0].classification = "UNKNOWN"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        assessment.flow_comparisons[0].flow_id = "other"  # type: ignore[misc]


def test_nested_finding_and_health_mutation_fails():
    assessment = _assessment()
    with pytest.raises(ValidationError):
        assessment.findings[0].statement = "rewritten"  # type: ignore[misc]
    assert isinstance(assessment.findings[0].evidence_ids, tuple)
    with pytest.raises(AttributeError):
        assessment.findings[0].evidence_ids.append("ev-9999")  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        assessment.health[0].status = "NOT_OK"  # type: ignore[misc]
    assert isinstance(assessment.health[1].reasons, tuple)
    with pytest.raises(AttributeError):
        assessment.health[1].reasons.append("extra")  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        assessment.inconclusive_reasons = ("late reason",)  # type: ignore[misc]


def test_serialization_preserves_complete_assessment():
    assessment = _assessment()
    rebuilt = AssessmentResult.model_validate_json(assessment.model_dump_json())
    assert rebuilt == assessment
    assert rebuilt.verdict == "REGRESSION_DETECTED"
    assert rebuilt.flow_comparisons[0].classification == "REGRESSION"
    assert rebuilt.findings[0].evidence_ids == ("ev-0001", "ev-0002")
    assert rebuilt.health[0].status == "OK"
    assert rebuilt.health[1].reasons == ("r1.cfg failed to parse",)
