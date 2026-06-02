from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from threatprism.cases.schemas import (
    Determination,
    Disposition,
    Finding,
    Severity,
    TriageReport,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.llm.batching import BatchItem, estimate_tokens, plan_batches
from threatprism.llm.failures import (
    BatchFailureReport,
    FailureType,
    ProviderAuthError,
    ProviderTimeout,
    TriageFailureReport,
    failure_from_validation_error,
)
from threatprism.llm.mock_analyst import MockAnalyst
from threatprism.llm.providers import (
    ClaudeTriageProvider,
    DeterministicDemoProvider,
    _extract_json,
    get_provider,
)
from threatprism.llm.runner import build_batch_narrative, safe_generate_report, validate_llm_report
from support_settings import local_auth_disabled_settings


_PAYLOAD = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8"))


def _a_case():
    service = CaseService(local_auth_disabled_settings())
    accepted = service.create_case(_PAYLOAD)
    return service.get_case(accepted.case_id)


def _report(case, *, summary="Reviewed.", evidence_ids=None):
    valid = [item.evidence_id for item in case.evidence]
    return TriageReport(
        case_id=case.case_id,
        summary=summary,
        determination=Determination.benign,
        severity=Severity.low,
        disposition=Disposition.monitor,
        confidence=0.5,
        findings=[Finding(title="t", summary="s", severity=Severity.low, evidence_ids=evidence_ids or valid)],
    )


class _FakeOk:
    provider_name = "fake_ok"

    def __init__(self, report):
        self._report = report

    def generate_report(self, case):
        return self._report


class _FakeRaise:
    provider_name = "fake_raise"

    def __init__(self, exc):
        self._exc = exc

    def generate_report(self, case):
        raise self._exc


class _FakeSchemaFail:
    provider_name = "fake_schema"

    def generate_report(self, case):
        return TriageReport.model_validate({"not": "a report"})  # raises ValidationError


# --- batching -------------------------------------------------------------

def test_batches_close_on_event_count() -> None:
    items = [BatchItem(f"c{i}", 10) for i in range(5)]
    plan = plan_batches(items, max_events=2, max_input_tokens=10_000)
    assert [len(b) for b in plan.batches] == [2, 2, 1]


def test_batches_close_on_token_budget() -> None:
    items = [BatchItem(f"c{i}", 40) for i in range(5)]
    plan = plan_batches(items, max_events=100, max_input_tokens=100)
    assert [len(b) for b in plan.batches] == [2, 2, 1]


def test_oversized_case_is_flagged_not_split() -> None:
    plan = plan_batches([BatchItem("big", 500), BatchItem("ok", 10)], max_events=10, max_input_tokens=100)
    assert plan.oversized == ["big"]
    assert plan.batches == [["ok"]]


def test_batch_order_is_preserved_not_resorted() -> None:
    plan = plan_batches([BatchItem("b", 10), BatchItem("a", 10)], max_events=10, max_input_tokens=10_000)
    assert plan.batches == [["b", "a"]]
    assert estimate_tokens("xxxx") >= 1


# --- failure reporting ----------------------------------------------------

def test_schema_failure_is_redacted_and_flagged() -> None:
    try:
        TriageReport.model_validate({"determination": "not-a-real-value"})
    except ValidationError as exc:
        failure = failure_from_validation_error(exc, case_id="c1", provider="anthropic_claude")
    assert failure.failure_type == FailureType.schema_validation_failure
    assert failure.pydantic_triggered is True
    assert failure.terminal_status == "needs_review"
    # No raw offending input value leaks into the failure record.
    assert "not-a-real-value" not in failure.model_dump_json()


def test_batch_failure_report_aggregates_by_type() -> None:
    fails = [
        TriageFailureReport(failure_type=FailureType.provider_timeout, stage="call", what="x", why="y"),
        TriageFailureReport(failure_type=FailureType.provider_timeout, stage="call", what="x", why="y"),
        TriageFailureReport(failure_type=FailureType.budget_exceeded, stage="batch", what="x", why="y"),
    ]
    report = BatchFailureReport.from_failures(fails, batch_id="b1")
    assert report.total == 3
    assert report.by_type == {"budget_exceeded": 1, "provider_timeout": 2}


# --- safe_generate_report seam -------------------------------------------

def test_safe_generate_report_happy_path_returns_report() -> None:
    case = _a_case()
    result = safe_generate_report(_FakeOk(_report(case)), case)
    assert isinstance(result, TriageReport)


def test_provider_call_failure_becomes_failure_report() -> None:
    case = _a_case()
    result = safe_generate_report(_FakeRaise(ProviderTimeout("deadline exceeded")), case)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_timeout
    assert result.terminal_status == "needs_review"


def test_schema_invalid_response_becomes_failure_report() -> None:
    case = _a_case()
    result = safe_generate_report(_FakeSchemaFail(), case)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.schema_validation_failure
    assert result.pydantic_triggered is True


def test_unsupported_evidence_becomes_guardrail_failure() -> None:
    case = _a_case()
    bad = _report(case, evidence_ids=["ev-does-not-exist"])
    result = safe_generate_report(_FakeOk(bad), case, validate_guardrails=True)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.evidence_grounding_failure
    assert result.terminal_status == "blocked_by_guardrail"


def test_overclaim_summary_becomes_output_policy_failure() -> None:
    case = _a_case()
    overclaim = _report(case, summary="This case is HIPAA compliant and HITRUST certified.")
    failure = validate_llm_report(overclaim, case, provider="anthropic_claude")
    assert failure is not None
    assert failure.failure_type == FailureType.output_policy_rejection


# --- Claude provider: fails closed when unconfigured (no network) ---------

def test_extract_json_strips_fences_and_prose() -> None:
    assert _extract_json('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert _extract_json('Here is the report:\n{"a": 1}\nDone.') == '{"a": 1}'
    assert _extract_json('{"a": {"b": 2}}') == '{"a": {"b": 2}}'
    # No JSON object present -> returned as-is so json.loads raises (unparseable).
    assert _extract_json("no json here") == "no json here"


def test_claude_provider_without_key_fails_closed() -> None:
    case = _a_case()
    provider = ClaudeTriageProvider(api_key="", model_id="claude-x")
    result = safe_generate_report(provider, case)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_auth_error


def test_get_provider_routes_demo_and_requires_settings_for_claude() -> None:
    assert isinstance(get_provider("deterministic_demo"), DeterministicDemoProvider)
    with pytest.raises(ValueError):
        get_provider("anthropic_claude")  # settings required
    settings = Settings(llm_provider="anthropic_claude", anthropic_api_key="sk-test")
    assert isinstance(get_provider("anthropic_claude", settings), ClaudeTriageProvider)


def test_validate_runtime_requires_key_for_real_provider() -> None:
    bad = local_auth_disabled_settings(llm_provider="anthropic_claude", anthropic_api_key="")
    with pytest.raises(ValueError):
        bad.validate_runtime()


# --- mock analyst (Evolution 2 grader) ------------------------------------

def test_mock_analyst_is_independent_and_fails_closed() -> None:
    case = _a_case()
    analyst = MockAnalyst(api_key="", model_id="gpt-x")
    # Independence: never the same provider path as the Claude triage brain.
    assert analyst.provider_name != ClaudeTriageProvider.provider_name
    with pytest.raises(ProviderAuthError):
        analyst.evaluate(case, _report(case))


def test_analyst_prompt_enumerates_all_required_enum_vocabularies() -> None:
    # A blind analyst has no ThreatPrism report to copy valid enum values from, so the
    # system prompt must itself state the closed vocabulary for EVERY required enum
    # field. Otherwise the model free-styles an out-of-enum value (notably
    # analyst_final_disposition) and grading fails schema validation -- exactly the
    # 2/8 blind-mode failures from the 2026-06-02 corrected A/B. Anchored runs masked
    # this because the report supplied valid enum values as an implicit example.
    from threatprism.llm.mock_analyst import _ANALYST_SYSTEM_PROMPT

    for value in (d.value for d in Determination):
        assert value in _ANALYST_SYSTEM_PROMPT, f"determination '{value}' missing from analyst prompt"
    for value in (s.value for s in Severity):
        assert value in _ANALYST_SYSTEM_PROMPT, f"severity '{value}' missing from analyst prompt"
    for value in (d.value for d in Disposition):
        assert value in _ANALYST_SYSTEM_PROMPT, f"disposition '{value}' missing from analyst prompt"


# --- batch narrative seam -------------------------------------------------

class _FakeNarrator:
    provider_name = "fake_narrator"

    def __init__(self, *, text=None, exc=None):
        self._text = text
        self._exc = exc

    def generate_narrative(self, context):
        if self._exc:
            raise self._exc
        return self._text


def test_batch_narrative_is_none_for_demo_provider() -> None:
    assert build_batch_narrative(DeterministicDemoProvider(), "ctx") is None


def test_batch_narrative_returns_validated_text() -> None:
    result = build_batch_narrative(_FakeNarrator(text="8 high-severity credential cases lead the batch."), "ctx")
    assert isinstance(result, str)
    assert "credential" in result


def test_batch_narrative_overclaim_becomes_output_policy_failure() -> None:
    result = build_batch_narrative(_FakeNarrator(text="This batch proves HIPAA compliance."), "ctx")
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.output_policy_rejection


def test_batch_narrative_provider_failure_becomes_failure_report() -> None:
    result = build_batch_narrative(_FakeNarrator(exc=ProviderTimeout("deadline")), "ctx")
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_timeout
