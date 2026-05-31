"""Structured, auditable failure reporting for real-LLM triage (spec 33 §4).

Every LLM triage failure produces a ``TriageFailureReport`` instead of a silent
pass. The taxonomy distinguishes *where* and *why* a failure happened so an
operator can answer: what failed, why, did Pydantic trigger it, and which
guardrail rejected the output. Failure records carry no raw payloads, secrets, or
PHI — only field paths, pattern names, and codes (same redaction discipline as
audit events).

This module is pure and deterministic: given the same provider behavior, the same
failure report is produced. The live provider raises the exceptions defined here;
the builders map exceptions / validation errors / guardrail issues to reports.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class FailureType(str, Enum):
    provider_unreachable = "provider_unreachable"
    provider_timeout = "provider_timeout"
    provider_rate_limited = "provider_rate_limited"
    provider_auth_error = "provider_auth_error"
    provider_response_unparseable = "provider_response_unparseable"
    schema_validation_failure = "schema_validation_failure"
    evidence_grounding_failure = "evidence_grounding_failure"
    output_policy_rejection = "output_policy_rejection"
    action_safety_rejection = "action_safety_rejection"
    prompt_quarantine = "prompt_quarantine"
    budget_exceeded = "budget_exceeded"


Stage = Literal["pre_model", "call", "parse", "guardrail", "batch"]

# Which stage each failure type belongs to, and the fail-closed status it forces.
_STAGE: dict[FailureType, Stage] = {
    FailureType.provider_unreachable: "call",
    FailureType.provider_timeout: "call",
    FailureType.provider_rate_limited: "call",
    FailureType.provider_auth_error: "call",
    FailureType.provider_response_unparseable: "parse",
    FailureType.schema_validation_failure: "parse",
    FailureType.evidence_grounding_failure: "guardrail",
    FailureType.output_policy_rejection: "guardrail",
    FailureType.action_safety_rejection: "guardrail",
    FailureType.prompt_quarantine: "pre_model",
    FailureType.budget_exceeded: "batch",
}


class TriageFailureReport(BaseModel):
    """A single fail-closed failure record. No raw payloads, secrets, or PHI."""

    failure_type: FailureType
    stage: Stage
    what: str
    why: str
    pydantic_triggered: bool = False
    pydantic_errors: list[str] = Field(default_factory=list)  # field paths only
    guardrail: str | None = None
    provider: str | None = None
    model_id: str | None = None
    model_revision: str | None = None
    attempt: int = 1
    case_id: str | None = None
    batch_id: str | None = None
    terminal_status: str = "needs_review"


class BatchFailureReport(BaseModel):
    """Aggregates per-case failures so an operator sees what failed at a glance."""

    batch_id: str | None = None
    total: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    failures: list[TriageFailureReport] = Field(default_factory=list)

    @classmethod
    def from_failures(cls, failures: list[TriageFailureReport], *, batch_id: str | None = None) -> "BatchFailureReport":
        by_type: dict[str, int] = {}
        for failure in failures:
            by_type[failure.failure_type.value] = by_type.get(failure.failure_type.value, 0) + 1
        return cls(
            batch_id=batch_id,
            total=len(failures),
            by_type=dict(sorted(by_type.items())),
            failures=failures,
        )


class LLMProviderError(Exception):
    """Base for provider-side (call/parse) failures the provider raises."""

    failure_type: FailureType = FailureType.provider_unreachable

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ProviderUnreachable(LLMProviderError):
    failure_type = FailureType.provider_unreachable


class ProviderTimeout(LLMProviderError):
    failure_type = FailureType.provider_timeout


class ProviderRateLimited(LLMProviderError):
    failure_type = FailureType.provider_rate_limited


class ProviderAuthError(LLMProviderError):
    failure_type = FailureType.provider_auth_error


class ProviderResponseUnparseable(LLMProviderError):
    failure_type = FailureType.provider_response_unparseable


_FAIL_CLOSED_STATUS: dict[FailureType, str] = {
    # Guardrail / quarantine rejections block the case outright.
    FailureType.evidence_grounding_failure: "blocked_by_guardrail",
    FailureType.output_policy_rejection: "blocked_by_guardrail",
    FailureType.action_safety_rejection: "blocked_by_guardrail",
    FailureType.prompt_quarantine: "blocked_by_guardrail",
}


def _terminal_status(failure_type: FailureType) -> str:
    # Guardrail failures block; transient/parse/budget failures need review.
    return _FAIL_CLOSED_STATUS.get(failure_type, "needs_review")


def _meta(case_id: str | None, batch_id: str | None, provider: str | None,
          model_id: str | None, model_revision: str | None, attempt: int) -> dict[str, object]:
    return {
        "case_id": case_id,
        "batch_id": batch_id,
        "provider": provider,
        "model_id": model_id,
        "model_revision": model_revision,
        "attempt": attempt,
    }


def failure_from_exception(
    exc: LLMProviderError,
    *,
    case_id: str | None = None,
    batch_id: str | None = None,
    provider: str | None = None,
    model_id: str | None = None,
    model_revision: str | None = None,
    attempt: int = 1,
) -> TriageFailureReport:
    ft = exc.failure_type
    return TriageFailureReport(
        failure_type=ft,
        stage=_STAGE[ft],
        what=f"LLM provider call failed ({ft.value}).",
        why=exc.message,
        terminal_status=_terminal_status(ft),
        **_meta(case_id, batch_id, provider, model_id, model_revision, attempt),
    )


def failure_from_validation_error(
    exc: ValidationError,
    *,
    case_id: str | None = None,
    batch_id: str | None = None,
    provider: str | None = None,
    model_id: str | None = None,
    model_revision: str | None = None,
    attempt: int = 1,
) -> TriageFailureReport:
    # Field paths + error type only — never the offending input value (no PHI/secret leak).
    paths = [
        f"{'.'.join(str(part) for part in err.get('loc', ()))}:{err.get('type', 'invalid')}"
        for err in exc.errors()
    ]
    ft = FailureType.schema_validation_failure
    return TriageFailureReport(
        failure_type=ft,
        stage=_STAGE[ft],
        what="LLM output did not match the TriageReport schema.",
        why=f"{len(paths)} field(s) failed Pydantic validation.",
        pydantic_triggered=True,
        pydantic_errors=sorted(paths),
        terminal_status=_terminal_status(ft),
        **_meta(case_id, batch_id, provider, model_id, model_revision, attempt),
    )


def failure_from_guardrail(
    failure_type: FailureType,
    guardrail: str,
    issues: list[str],
    *,
    case_id: str | None = None,
    batch_id: str | None = None,
    provider: str | None = None,
    model_id: str | None = None,
    model_revision: str | None = None,
    attempt: int = 1,
) -> TriageFailureReport:
    if failure_type not in {
        FailureType.evidence_grounding_failure,
        FailureType.output_policy_rejection,
        FailureType.action_safety_rejection,
        FailureType.prompt_quarantine,
    }:
        raise ValueError("failure_from_guardrail requires a guardrail failure type")
    return TriageFailureReport(
        failure_type=failure_type,
        stage=_STAGE[failure_type],
        what=f"LLM output rejected by guardrail: {guardrail}.",
        why="; ".join(issues)[:500] if issues else "guardrail rejected the report",
        guardrail=guardrail,
        terminal_status=_terminal_status(failure_type),
        **_meta(case_id, batch_id, provider, model_id, model_revision, attempt),
    )


def budget_exceeded_failure(
    *,
    case_id: str | None = None,
    batch_id: str | None = None,
    why: str = "case or batch exceeds the configured input token budget",
) -> TriageFailureReport:
    ft = FailureType.budget_exceeded
    return TriageFailureReport(
        failure_type=ft,
        stage=_STAGE[ft],
        what="Input exceeded the token budget and was not sent to the model.",
        why=why,
        case_id=case_id,
        batch_id=batch_id,
        terminal_status=_terminal_status(ft),
    )
