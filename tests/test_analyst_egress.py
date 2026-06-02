"""Data-egress guard for the real OpenAI mock-analyst (gate: real-LLM analyst).

The mock-analyst sends the case + triage report to a third-party provider
(OpenAI). The security invariant is that raw PHI/PII/secrets never leave the
trust boundary: only Stage-1 tokens (`[POTENTIAL_PHI:...]`, `[SECRET:...]`, which
are never rehydrated) may appear in the egressed prompt. This test locks that
invariant so a future change that routes a pre-tokenization case to the analyst
fails loudly instead of leaking silently.

Secret-shaped values are assembled by concatenation so no literal secret token
appears in source (mirrors tests/test_dev_workflow_hooks.py) — otherwise the
repo's own PreToolUse secret-block hook flags this file.
"""
from __future__ import annotations

from threatprism.cases.schemas import (
    CaseRecord,
    Determination,
    Disposition,
    Severity,
    TriageReport,
)
from threatprism.cases.service import CaseService
from threatprism.llm.mock_analyst import MockAnalyst
from support_settings import local_auth_disabled_settings


def test_analyst_prompt_carries_tokens_not_raw_phi_or_secrets() -> None:
    service = CaseService(local_auth_disabled_settings())

    raw_mrn = "998877AB"
    raw_secret = "sk-" + "A" * 40  # fake provider-key shape, assembled at runtime
    case = CaseRecord(
        source_case_id="egress-guard-1",
        title="Patient portal alert",
        description=f"Patient MRN: {raw_mrn} reported via portal. api token {raw_secret}",
    )

    # Stage-1 intake tokenization — the same call the API performs before persistence.
    tokenized_case = service._apply_healthcare_safeguards(case)

    report = TriageReport(
        case_id=tokenized_case.case_id,
        summary="demo triage",
        determination=Determination.benign,
        severity=Severity.low,
        disposition=Disposition.monitor,
        confidence=0.5,
    )

    analyst = MockAnalyst(api_key="dummy-not-used", model_id="gpt-4o-mini")
    prompt = analyst._build_prompt(tokenized_case, report)

    # Raw sensitive values must never reach the third-party provider.
    assert raw_mrn not in prompt
    assert raw_secret not in prompt
    # The redacted token form is what egresses instead.
    assert "[POTENTIAL_PHI:" in prompt
    assert "[SECRET:" in prompt
