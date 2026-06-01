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
    metered_evaluate,
    metered_generate,
    metered_narrative,
    would_exceed_budget,
)
from threatprism.llm.providers import DeterministicDemoProvider
from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
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


# --- metered batch narrative ----------------------------------------------

class _FakeNarrator:
    provider_name = "fake_narrator"

    def __init__(self, *, text=None, usage=None, exc=None):
        self._text = text
        self.last_usage = usage
        self._exc = exc

    def generate_narrative(self, context):
        if self._exc:
            raise self._exc
        return self._text


def test_metered_narrative_returns_text_and_meters_usage() -> None:
    ledger = SpendLedger()
    prov = _FakeNarrator(text="High-severity OTRF credential cases lead the batch.",
                         usage=UsageRecord(model_id="claude-sonnet-4-5", input_tokens=300, output_tokens=120))
    out = metered_narrative(prov, "ctx", ledger, cost_model=CostModel(3.0, 15.0),
                            max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(out, str) and "OTRF" in out
    assert len(ledger.records) == 1 and ledger.records[0].call_kind == "narrative"
    assert ledger.records[0].estimated_cost_usd > 0


def test_metered_narrative_is_none_for_demo_provider() -> None:
    assert metered_narrative(DeterministicDemoProvider(), "ctx", SpendLedger(),
                             cost_model=CostModel(), max_total_tokens=1000, max_cost_usd=0.0) is None


def test_metered_narrative_skips_when_cap_would_be_exceeded() -> None:
    prov = _FakeNarrator(text="x", usage=UsageRecord(model_id="m"))
    out = metered_narrative(prov, "ctx", SpendLedger(), cost_model=CostModel(),
                            max_total_tokens=1, max_cost_usd=0.0)  # impossibly low token cap
    assert out is None
    assert len(SpendLedger().records) == 0


def test_metered_narrative_drops_overclaim_via_output_policy() -> None:
    prov = _FakeNarrator(text="This batch proves HIPAA compliance.", usage=UsageRecord(model_id="m"))
    out = metered_narrative(prov, "ctx", SpendLedger(), cost_model=CostModel(),
                            max_total_tokens=10_000, max_cost_usd=100.0)
    assert out is None  # output policy rejects -> no narrative


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


# --- spec 35: meter failed-after-call cost ---------------------------------

class _FailAfterCall:
    """Models the real provider's contract: resets last_usage per attempt, sets it
    only after a (simulated) API response, then fails downstream."""

    provider_name = "fail_after_call"

    def __init__(self, usage, mode: str):
        self._usage = usage
        self._mode = mode  # "unparseable" | "schema"
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""

    def generate_report(self, case):
        self.last_usage = None  # reset per attempt
        self.last_prompt = "PROMPT"
        self.last_response = "RESPONSE"
        self.last_usage = self._usage  # API responded — tokens spent
        if self._mode == "unparseable":
            from threatprism.llm.failures import ProviderResponseUnparseable
            raise ProviderResponseUnparseable("model response was not valid JSON")
        TriageReport.model_validate({})  # raises ValidationError -> schema failure


def test_failed_after_call_unparseable_is_metered_and_audited() -> None:
    case = _a_case()
    usage = UsageRecord(model_id="claude-sonnet-4-5", input_tokens=800, output_tokens=200)
    provider = _FailAfterCall(usage, "unparseable")
    ledger = SpendLedger()
    audits: list = []
    result = metered_generate(provider, case, ledger, cost_model=CostModel(3.0, 15.0),
                              max_total_tokens=10_000_000, max_cost_usd=100.0, audit_events=audits)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_response_unparseable
    # The spent tokens are now ledgered (previously dropped -> undercount).
    assert len(ledger.records) == 1
    assert ledger.records[0].failure_type == "provider_response_unparseable"
    assert ledger.records[0].estimated_cost_usd == 0.0054  # 800/1e6*3 + 200/1e6*15
    # A sanitized llm_call audit fired for the failed-after-call, hashes not raw.
    assert len(audits) == 1
    assert audits[0].metadata["failure_type"] == "provider_response_unparseable"
    assert "prompt_sha256" in audits[0].metadata
    assert "PROMPT" not in json.dumps(audits[0].model_dump(mode="json"))


def test_failed_after_call_schema_is_metered() -> None:
    case = _a_case()
    usage = UsageRecord(model_id="claude-sonnet-4-5", input_tokens=500, output_tokens=100)
    ledger = SpendLedger()
    result = metered_generate(_FailAfterCall(usage, "schema"), case, ledger,
                              cost_model=CostModel(3.0, 15.0),
                              max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.schema_validation_failure
    assert len(ledger.records) == 1
    assert ledger.records[0].failure_type == "schema_validation_failure"


class _PreCallFail:
    """Resets last_usage and fails before any API response (no tokens spent)."""

    provider_name = "pre_call_fail"

    def __init__(self):
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""

    def generate_report(self, case):
        self.last_usage = None  # reset; no response arrives
        from threatprism.llm.failures import ProviderUnreachable
        raise ProviderUnreachable("network down")


def test_pre_call_failure_is_not_metered() -> None:
    case = _a_case()
    ledger = SpendLedger()
    result = metered_generate(_PreCallFail(), case, ledger, cost_model=CostModel(3.0, 15.0),
                              max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_unreachable
    assert len(ledger.records) == 0  # no round-trip -> nothing billed


class _SucceedThenPreCallFail:
    """First attempt responds + succeeds (usage set); second attempt fails pre-call
    after resetting. Proves the reset prevents re-ledgering the stale record."""

    provider_name = "succeed_then_fail"

    def __init__(self, report, usage):
        self._report = report
        self._usage = usage
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""
        self.attempts = 0

    def generate_report(self, case):
        self.attempts += 1
        self.last_usage = None  # reset per attempt
        if self.attempts == 1:
            self.last_usage = self._usage  # responded
            return self._report
        from threatprism.llm.failures import ProviderAuthError
        raise ProviderAuthError("key rotated mid-run")  # pre-call, no usage


def test_last_usage_reset_prevents_double_count() -> None:
    case = _a_case()
    usage = UsageRecord(model_id="claude-sonnet-4-5", input_tokens=100, output_tokens=50)
    provider = _SucceedThenPreCallFail(_report(case), usage)
    ledger = SpendLedger()
    cm = CostModel(3.0, 15.0)
    r1 = metered_generate(provider, case, ledger, cost_model=cm, max_total_tokens=10_000_000, max_cost_usd=100.0)
    r2 = metered_generate(provider, case, ledger, cost_model=cm, max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(r1, TriageReport)
    assert isinstance(r2, TriageFailureReport) and r2.failure_type == FailureType.provider_auth_error
    # Only the successful attempt is billed; attempt 2 did not re-ledger stale usage.
    assert len(ledger.records) == 1


def test_metered_narrative_meters_failed_after_call() -> None:
    # Output policy rejects the prose, but the call already cost tokens.
    prov = _FakeNarrator(text="This batch proves HIPAA compliance.",
                         usage=UsageRecord(model_id="m", input_tokens=200, output_tokens=80))
    ledger = SpendLedger()
    out = metered_narrative(prov, "ctx", ledger, cost_model=CostModel(3.0, 15.0),
                            max_total_tokens=10_000, max_cost_usd=100.0)
    assert out is None  # policy rejected
    assert len(ledger.records) == 1  # but the spend was metered
    assert ledger.records[0].failure_type == "output_policy_rejection"
    assert ledger.records[0].call_kind == "narrative"


class _RunTriageFailAfterCall:
    provider_name = "fail_after_call_e2e"

    def __init__(self, usage):
        self._usage = usage
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""

    def generate_report(self, case):
        self.last_usage = None
        self.last_prompt = "p"
        self.last_response = "r"
        self.last_usage = self._usage
        from threatprism.llm.failures import ProviderResponseUnparseable
        raise ProviderResponseUnparseable("bad json")


def test_run_triage_surfaces_failed_call_in_metrics_and_audit() -> None:
    service = CaseService(local_auth_disabled_settings())
    accepted = service.create_case(_PAYLOAD)
    case = service.get_case(accepted.case_id)
    service.provider = _RunTriageFailAfterCall(
        UsageRecord(model_id="claude-sonnet-4-5", input_tokens=900, output_tokens=300)
    )

    service.run_triage(case.case_id)

    usage = service.get_operational_metrics().llm_usage
    assert usage.call_count == 1
    assert usage.failed_call_count == 1
    assert usage.total_tokens == 1200
    # The sanitized llm_call audit landed on the case despite the failure.
    updated = service.get_case(case.case_id)
    llm_audits = [e for e in updated.audit_trail if e.event_type == "llm_call"]
    assert len(llm_audits) == 1
    assert llm_audits[0].metadata["failure_type"] == "provider_response_unparseable"


# --- spec 36: governed independent-analyst spend (metered_evaluate) ---------

def _feedback(determination=Determination.benign, severity=Severity.low):
    return AnalystFeedbackCreate(
        analyst_id="x", analyst_determination=determination, analyst_severity=severity,
        analyst_confidence=0.5, analyst_final_disposition=Disposition.monitor,
    )


class _MeteredAnalyst:
    provider_name = "fake_analyst"
    model_id = "gpt-4o-mini"

    def __init__(self, feedback, usage):
        self._feedback = feedback
        self._usage = usage
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""
        self.called = False

    def evaluate(self, case, report):
        self.called = True
        self.last_usage = None  # reset per attempt
        self.last_prompt = "ANALYST_PROMPT"
        self.last_response = "ANALYST_RESPONSE"
        self.last_usage = self._usage  # API responded
        return self._feedback


def test_metered_evaluate_meters_analyst_usage_and_audits() -> None:
    case = _a_case()
    report = _report(case)
    usage = UsageRecord(model_id="gpt-4o-mini", call_kind="analyst", input_tokens=400, output_tokens=80)
    analyst = _MeteredAnalyst(_feedback(), usage)
    ledger = SpendLedger()
    audits: list = []
    result = metered_evaluate(analyst, case, report, ledger, cost_model=CostModel(0.15, 0.60),
                              max_total_tokens=10_000_000, max_cost_usd=100.0, audit_events=audits)
    assert isinstance(result, AnalystFeedbackCreate)
    assert len(ledger.records) == 1 and ledger.records[0].call_kind == "analyst"
    assert ledger.records[0].estimated_cost_usd == 0.000108  # 400*0.15/1e6 + 80*0.60/1e6
    assert len(audits) == 1 and "prompt_sha256" in audits[0].metadata
    assert "ANALYST_PROMPT" not in json.dumps(audits[0].model_dump(mode="json"))


def test_metered_evaluate_pre_call_failure_is_not_metered() -> None:
    case = _a_case()
    report = _report(case)

    class _Raise:
        provider_name = "raise_analyst"
        model_id = "gpt-4o-mini"
        last_usage = None

        def evaluate(self, case, report):
            self.last_usage = None
            from threatprism.llm.failures import ProviderUnreachable
            raise ProviderUnreachable("analyst down")

    ledger = SpendLedger()
    result = metered_evaluate(_Raise(), case, report, ledger, cost_model=CostModel(0.15, 0.60),
                              max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_unreachable
    assert len(ledger.records) == 0


def test_metered_evaluate_failed_after_call_is_metered() -> None:
    case = _a_case()
    report = _report(case)
    usage = UsageRecord(model_id="gpt-4o-mini", call_kind="analyst", input_tokens=300, output_tokens=50)

    class _FailAfter:
        provider_name = "fail_after_analyst"
        model_id = "gpt-4o-mini"

        def __init__(self, usage):
            self._usage = usage
            self.last_usage = None
            self.last_prompt = ""
            self.last_response = ""

        def evaluate(self, case, report):
            self.last_usage = None
            self.last_usage = self._usage  # responded
            from threatprism.llm.failures import ProviderResponseUnparseable
            raise ProviderResponseUnparseable("not json")

    ledger = SpendLedger()
    result = metered_evaluate(_FailAfter(usage), case, report, ledger, cost_model=CostModel(0.15, 0.60),
                              max_total_tokens=10_000_000, max_cost_usd=100.0)
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.provider_response_unparseable
    assert len(ledger.records) == 1 and ledger.records[0].failure_type == "provider_response_unparseable"


def test_metered_evaluate_blocks_on_cap_without_calling_analyst() -> None:
    case = _a_case()
    report = _report(case)
    analyst = _MeteredAnalyst(_feedback(), UsageRecord(model_id="gpt-4o-mini"))
    ledger = SpendLedger()
    result = metered_evaluate(analyst, case, report, ledger, cost_model=CostModel(),
                              max_total_tokens=1, max_cost_usd=0.0)  # impossibly low token cap
    assert isinstance(result, TriageFailureReport)
    assert result.failure_type == FailureType.budget_exceeded
    assert analyst.called is False
    assert len(ledger.records) == 0
