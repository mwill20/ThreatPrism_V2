from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatprism.cases.service import CaseService
from threatprism.llm.failures import FailureType, TriageFailureReport
from threatprism.llm.governance import (
    APPROVED_MODELS,
    CostModel,
    SpendLedger,
    UsageRecord,
    build_llm_call_audit,
    enforce_spend_cap,
    metered_generate,
    would_exceed_budget,
)
from threatprism.cases.schemas import (
    Determination,
    Disposition,
    Finding,
    Severity,
    TriageReport,
)
from support_settings import local_auth_disabled_settings


_PAYLOAD = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8"))


def _a_case():
    service = CaseService(local_auth_disabled_settings())
    accepted = service.create_case(_PAYLOAD)
    return service.get_case(accepted.case_id)


def _report(case):
    return TriageReport(
        case_id=case.case_id,
        summary="Reviewed.",
        determination=Determination.benign,
        severity=Severity.low,
        disposition=Disposition.monitor,
        confidence=0.5,
        findings=[Finding(title="t", summary="s", severity=Severity.low,
                          evidence_ids=[i.evidence_id for i in case.evidence])],
    )


class _FakeMetered:
    provider_name = "fake_metered"

    def __init__(self, report, usage):
        self._report = report
        self.last_usage = usage
        self.called = False

    def generate_report(self, case):
        self.called = True
        return self._report


# --- cost + ledger --------------------------------------------------------

def test_cost_model_prices_tokens() -> None:
    cm = CostModel(input_price_per_mtok=3.0, output_price_per_mtok=15.0)
    assert cm.estimate(1_000_000, 0) == 3.0
    assert cm.estimate(0, 1_000_000) == 15.0


def test_ledger_accumulates() -> None:
    ledger = SpendLedger()
    ledger.add(UsageRecord(model_id="m", input_tokens=100, output_tokens=50, estimated_cost_usd=0.01))
    ledger.add(UsageRecord(model_id="m", input_tokens=200, output_tokens=100, estimated_cost_usd=0.02))
    assert ledger.total_tokens == 450
    assert ledger.total_cost_usd == 0.03


# --- spend cap ------------------------------------------------------------

def test_budget_exceeded_by_tokens_and_cost() -> None:
    ledger = SpendLedger()
    assert would_exceed_budget(ledger, projected_tokens=200, projected_cost_usd=0.0,
                               max_total_tokens=100, max_cost_usd=0.0) is True
    assert would_exceed_budget(ledger, projected_tokens=0, projected_cost_usd=10.0,
                               max_total_tokens=0, max_cost_usd=5.0) is True
    assert would_exceed_budget(ledger, projected_tokens=10, projected_cost_usd=1.0,
                               max_total_tokens=1000, max_cost_usd=5.0) is False


def test_enforce_spend_cap_returns_budget_failure() -> None:
    failure = enforce_spend_cap(SpendLedger(), projected_tokens=10_000, projected_cost_usd=0.0,
                                max_total_tokens=100, max_cost_usd=0.0, case_id="c1")
    assert isinstance(failure, TriageFailureReport)
    assert failure.failure_type == FailureType.budget_exceeded
    assert enforce_spend_cap(SpendLedger(), projected_tokens=1, projected_cost_usd=0.0,
                             max_total_tokens=1000, max_cost_usd=0.0) is None


# --- per-call audit -------------------------------------------------------

def test_call_audit_hashes_and_omits_raw_content() -> None:
    usage = UsageRecord(model_id="claude-sonnet-4-5", input_tokens=120, output_tokens=60)
    event = build_llm_call_audit(case_id="c1", usage=usage,
                                 prompt="RAW_SECRET_PROMPT_theshire", response="RAW_SECRET_RESPONSE")
    blob = json.dumps(event.model_dump(mode="json"))
    assert "RAW_SECRET_PROMPT" not in blob
    assert "RAW_SECRET_RESPONSE" not in blob
    assert "prompt_sha256" in blob and "input_tokens" in blob


# --- metered generation ---------------------------------------------------

def test_metered_generate_records_priced_usage() -> None:
    case = _a_case()
    usage = UsageRecord(model_id="claude-sonnet-4-5", input_tokens=1000, output_tokens=500)
    provider = _FakeMetered(_report(case), usage)
    ledger = SpendLedger()
    result = metered_generate(provider, case, ledger,
                              cost_model=CostModel(input_price_per_mtok=3.0, output_price_per_mtok=15.0),
                              max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(result, TriageReport)
    assert len(ledger.records) == 1
    # 1000/1e6*3 + 500/1e6*15 = 0.003 + 0.0075 = 0.0105
    assert ledger.records[0].estimated_cost_usd == 0.0105


def test_metered_generate_blocks_on_cap_without_calling_provider() -> None:
    case = _a_case()
    provider = _FakeMetered(_report(case), UsageRecord(model_id="m"))
    ledger = SpendLedger()
    result = metered_generate(provider, case, ledger, cost_model=CostModel(),
                              max_total_tokens=1, max_cost_usd=0.0)  # impossibly low token cap
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.budget_exceeded
    assert provider.called is False  # never spent


# --- approved-model governance -------------------------------------------

def test_approved_models_enforced_in_validate_runtime() -> None:
    ok = local_auth_disabled_settings(llm_provider="anthropic_claude", anthropic_api_key="sk-x",
                                      llm_model_id="claude-sonnet-4-5")
    ok.validate_runtime()  # approved model + default cap > 0

    bad_model = local_auth_disabled_settings(llm_provider="anthropic_claude", anthropic_api_key="sk-x",
                                             llm_model_id="totally-unapproved-model")
    with pytest.raises(ValueError):
        bad_model.validate_runtime()

    no_cap = local_auth_disabled_settings(llm_provider="anthropic_claude", anthropic_api_key="sk-x",
                                          llm_model_id="claude-sonnet-4-5",
                                          llm_max_cost_usd_per_run=0.0, llm_max_total_tokens_per_run=0)
    with pytest.raises(ValueError):
        no_cap.validate_runtime()


def test_default_model_is_approved() -> None:
    assert "claude-sonnet-4-5" in APPROVED_MODELS


# --- end-to-end wiring through run_triage ---------------------------------

class _FakeMeteredProvider:
    provider_name = "fake_metered_provider"

    def __init__(self, report, usage):
        self._report = report
        self.last_usage = usage
        self.last_prompt = "RAW_PROMPT_CONTENT_xyz"
        self.last_response = "RAW_RESPONSE_CONTENT_xyz"

    def generate_report(self, case):
        return self._report


def test_run_triage_meters_and_audits_a_real_like_call() -> None:
    service = CaseService(local_auth_disabled_settings())
    accepted = service.create_case(_PAYLOAD)
    case = service.get_case(accepted.case_id)
    service.provider = _FakeMeteredProvider(
        _report(case), UsageRecord(model_id="claude-sonnet-4-5", input_tokens=1000, output_tokens=500)
    )

    service.run_triage(case.case_id)

    # Spend ledger metered the call, and /metrics surfaces it.
    assert service._spend_ledger.total_tokens == 1500
    usage = service.get_operational_metrics().llm_usage
    assert usage.call_count == 1
    assert usage.total_tokens == 1500
    assert usage.input_tokens == 1000 and usage.output_tokens == 500
    # A sanitized llm_call audit event was recorded with hashes, not raw content.
    updated = service.get_case(case.case_id)
    llm_audits = [e for e in updated.audit_trail if e.event_type == "llm_call"]
    assert len(llm_audits) == 1
    assert "prompt_sha256" in llm_audits[0].metadata
    assert llm_audits[0].metadata["input_tokens"] == 1000
    blob = json.dumps([e.model_dump(mode="json") for e in updated.audit_trail])
    assert "RAW_PROMPT_CONTENT" not in blob and "RAW_RESPONSE_CONTENT" not in blob
