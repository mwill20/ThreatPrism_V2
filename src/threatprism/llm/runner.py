"""Untrusted-LLM-output validation seam (spec 33 §1, §4, §5).

``safe_generate_report`` wraps any ``TriageProvider`` so that:
- provider call failures (network/timeout/rate-limit/auth) become a
  ``TriageFailureReport`` instead of an exception,
- a malformed model response that fails Pydantic becomes a
  ``schema_validation_failure`` report,
- a structurally-valid report still passes the existing deterministic guardrails
  (output policy, evidence grounding, action safety) before it is trusted.

This is the enforcement of the hybrid-determinism rule: the LLM produces the
report, but a *deterministic* gate decides whether it is acceptable. The gate is
the same one ``run_triage`` already uses — reused here, not bypassed.
"""

from __future__ import annotations

from pydantic import ValidationError

from threatprism.cases.schemas import CaseRecord, TriageReport
from threatprism.guardrails.evidence import validate_report_evidence
from threatprism.guardrails.policy import enforce_action_safety, scan_output_policy
from threatprism.llm.failures import (
    FailureType,
    LLMProviderError,
    TriageFailureReport,
    failure_from_exception,
    failure_from_guardrail,
    failure_from_validation_error,
)


def build_batch_narrative(
    provider: object,
    context: str,
    *,
    max_chars: int = 4000,
) -> str | TriageFailureReport | None:
    """Generate the batch executive-summary narrative through a provider that
    supports it, validating the prose through the output policy before use.

    Returns ``None`` for providers without narrative support (e.g. the
    deterministic demo) so the narrative slot stays empty — never faked.
    """
    generate = getattr(provider, "generate_narrative", None)
    if generate is None:
        return None
    provider_name = getattr(provider, "provider_name", None)
    try:
        text = generate(context)
    except LLMProviderError as exc:
        return failure_from_exception(exc, provider=provider_name)
    issues = scan_output_policy({"narrative": text})
    if issues:
        return failure_from_guardrail(
            FailureType.output_policy_rejection, "output_policy", issues, provider=provider_name
        )
    return text[:max_chars]


def validate_llm_report(
    report: TriageReport,
    case: CaseRecord,
    *,
    provider: str | None = None,
    model_id: str | None = None,
    model_revision: str | None = None,
) -> TriageFailureReport | None:
    """Run the deterministic guardrails on LLM output. Returns a failure or None."""
    serialized = report.model_dump(mode="json")
    meta = {"case_id": case.case_id, "provider": provider, "model_id": model_id, "model_revision": model_revision}

    policy_issues = scan_output_policy(serialized)
    if policy_issues:
        return failure_from_guardrail(FailureType.output_policy_rejection, "output_policy", policy_issues, **meta)

    action_issues = enforce_action_safety(serialized)
    if action_issues:
        return failure_from_guardrail(FailureType.action_safety_rejection, "action_safety", action_issues, **meta)

    evidence_issues = validate_report_evidence(report, {item.evidence_id for item in case.evidence})
    if evidence_issues:
        return failure_from_guardrail(FailureType.evidence_grounding_failure, "evidence", evidence_issues, **meta)

    return None


def safe_generate_report(
    provider: object,
    case: CaseRecord,
    *,
    model_id: str | None = None,
    model_revision: str | None = None,
    attempt: int = 1,
    validate_guardrails: bool = True,
) -> TriageReport | TriageFailureReport:
    """Generate a report through a provider, converting every failure mode into a
    structured ``TriageFailureReport``. Never raises for known failure types.

    ``validate_guardrails=False`` handles only provider call/parse failures and
    leaves the deterministic guardrail validation to the caller (``run_triage``
    already runs that block, so it opts out to avoid double validation).
    """
    provider_name = getattr(provider, "provider_name", None)
    meta = {
        "case_id": case.case_id,
        "provider": provider_name,
        "model_id": model_id,
        "model_revision": model_revision,
        "attempt": attempt,
    }
    try:
        report = provider.generate_report(case)  # type: ignore[attr-defined]
    except LLMProviderError as exc:
        return failure_from_exception(exc, **meta)
    except ValidationError as exc:
        from threatprism.llm.failure_log import offending_value_sanitizer

        return failure_from_validation_error(exc, sanitizer=offending_value_sanitizer(), **meta)

    if not validate_guardrails:
        return report
    failure = validate_llm_report(
        report, case, provider=provider_name, model_id=model_id, model_revision=model_revision
    )
    return failure or report
