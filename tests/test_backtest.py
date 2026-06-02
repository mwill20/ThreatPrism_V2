from __future__ import annotations

import json

from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
    Determination,
    Disposition,
    Severity,
)
from threatprism.cases.service import CaseService
from threatprism.demo.backtest import BacktestReport, HeuristicDemoAnalyst, run_backtest
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder
from threatprism.llm.failures import ProviderTimeout
from support_settings import local_auth_disabled_settings


_FORBIDDEN = ("theshire", "cloudapp", "WORKSTATION5", "S-1-5-21")


def _seeded_service() -> CaseService:
    service = CaseService(local_auth_disabled_settings())
    DemoSeeder(service).seed([CuratedDatasetSource()])
    return service


class _AgreeAnalyst:
    provider_name = "agree"

    def evaluate(self, case, report):
        return AnalystFeedbackCreate(
            analyst_id="a",
            analyst_determination=report.determination,
            analyst_severity=report.severity,
            analyst_confidence=0.6,
            analyst_final_disposition=report.disposition,
        )


class _ClearAllAnalyst:
    provider_name = "clear_all"

    def evaluate(self, case, report):
        return AnalystFeedbackCreate(
            analyst_id="c",
            analyst_determination=Determination.benign,
            analyst_severity=Severity.low,
            analyst_confidence=0.6,
            analyst_final_disposition=Disposition.monitor,
        )


class _RaiseAnalyst:
    provider_name = "raise"

    def evaluate(self, case, report):
        raise ProviderTimeout("analyst unreachable")


class _BadDispositionAnalyst:
    """Emits an out-of-enum disposition -> ValidationError -> schema_validation_failure."""

    provider_name = "bad_disposition"

    def __init__(self):
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""

    def evaluate(self, case, report):
        return AnalystFeedbackCreate.model_validate(
            {
                "analyst_id": "bad",
                "analyst_determination": "suspicious",
                "analyst_severity": "medium",
                "analyst_confidence": 0.5,
                "analyst_final_disposition": "investigate-further",  # not in the enum
            }
        )


def test_backtest_records_failures_in_tamper_evident_log(tmp_path) -> None:
    # Owner requirement: grading failures must be inspectable AND immutable, not
    # counted-and-discarded. Each out-of-vocabulary output becomes an appended,
    # hash-chained record carrying the (sanitized) offending value.
    from threatprism.llm.failure_log import FailureLog

    path = tmp_path / "failures.jsonl"
    log = FailureLog(path)
    report = run_backtest(_seeded_service(), _BadDispositionAnalyst(), failure_log=log)

    assert report.grading_failures == 31
    assert report.grading_failure_types.get("schema_validation_failure") == 31

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 31          # every failure recorded, none discarded
    assert log.verify() is True      # tamper-evident chain intact

    blob = path.read_text(encoding="utf-8")
    assert "analyst_final_disposition" in blob  # WHICH field
    assert "investigate-further" in blob        # WHAT the model emitted


def test_full_agreement_when_analyst_mirrors_threatprism() -> None:
    report = run_backtest(_seeded_service(), _AgreeAnalyst())

    assert report.graded_total == 31  # 32 seeded, 1 blocked has no report
    assert report.agreement_rate == 1.0
    assert report.determination_mismatches == 0
    assert report.threatprism_flagged_analyst_cleared == []


def test_clearing_all_flags_every_non_benign_case() -> None:
    report = run_backtest(_seeded_service(), _ClearAllAnalyst())

    # The 8 suspicious OTRF cases are exactly the flagged-then-cleared set.
    assert len(report.threatprism_flagged_analyst_cleared) == 8
    assert report.determination_mismatches == 8
    assert report.agreement_rate < 1.0


def test_grading_failures_are_counted_not_swallowed() -> None:
    report = run_backtest(_seeded_service(), _RaiseAnalyst())

    assert report.graded_total == 0
    assert report.grading_failures == 31


def test_heuristic_demo_analyst_produces_deterministic_divergence() -> None:
    report = run_backtest(_seeded_service(), HeuristicDemoAnalyst())

    assert report.graded_total == 31
    assert report.agreement_rate == 0.871
    # Odd-indexed OTRF cases are cleared by the heuristic analyst.
    flagged = {r.source_case_id for r in report.threatprism_flagged_analyst_cleared}
    assert flagged == {
        "fixture-otrf_soc_telemetry_0001",
        "fixture-otrf_soc_telemetry_0003",
        "fixture-otrf_soc_telemetry_0005",
        "fixture-otrf_soc_telemetry_0007",
    }


def test_report_is_serializable_and_leaks_nothing() -> None:
    report = run_backtest(_seeded_service(), HeuristicDemoAnalyst())

    blob = report.model_dump_json()
    json.loads(blob)
    assert isinstance(report, BacktestReport)
    for token in _FORBIDDEN:
        assert token not in blob


# --- spec 36: governed analyst spend surfaced in the backtest --------------

class _MeteredAgreeAnalyst:
    provider_name = "metered_agree"
    model_id = "gpt-4o-mini"

    def __init__(self):
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""

    def evaluate(self, case, report):
        from threatprism.llm.governance import UsageRecord
        self.last_usage = None
        self.last_prompt = "P"
        self.last_response = "R"
        self.last_usage = UsageRecord(model_id="gpt-4o-mini", call_kind="analyst",
                                      input_tokens=100, output_tokens=20)
        return AnalystFeedbackCreate(
            analyst_id="a", analyst_determination=report.determination,
            analyst_severity=report.severity, analyst_confidence=0.6,
            analyst_final_disposition=report.disposition,
        )


def test_backtest_surfaces_governed_analyst_spend() -> None:
    from threatprism.llm.governance import CostModel
    report = run_backtest(_seeded_service(), _MeteredAgreeAnalyst(),
                          cost_model=CostModel(0.15, 0.60), max_total_tokens=10_000_000, max_cost_usd=100.0)
    # One metered analyst call per graded case.
    assert report.analyst_llm_usage["call_count"] == 31
    assert report.analyst_llm_usage["total_tokens"] == 31 * 120
    assert report.analyst_llm_usage["estimated_cost_usd"] > 0
    # The triage side is the deterministic demo here → zero triage spend.
    assert report.triage_llm_usage["call_count"] == 0


def test_heuristic_analyst_has_zero_analyst_spend() -> None:
    report = run_backtest(_seeded_service(), HeuristicDemoAnalyst())
    assert report.analyst_llm_usage["call_count"] == 0
    assert report.analyst_llm_usage["estimated_cost_usd"] == 0.0


# --- cost-minimal smoke runs: seed limit (--limit) -------------------------

def test_seed_limit_caps_seeded_and_triaged_cases() -> None:
    service = CaseService(local_auth_disabled_settings())
    result = DemoSeeder(service).seed([CuratedDatasetSource()], limit=2)
    # Triage runs per seeded case, so capping the seed caps the (paid) triage calls.
    assert len(result.seeded) == 2
    assert len(service.list_cases()) == 2


def test_backtest_over_seed_limited_service_grades_at_most_limit() -> None:
    service = CaseService(local_auth_disabled_settings())
    DemoSeeder(service).seed([CuratedDatasetSource()], limit=3)
    report = run_backtest(service, HeuristicDemoAnalyst())
    assert report.graded_total <= 3


def test_confidence_deltas_are_captured() -> None:
    # Blind A/B ruled out anchoring; determination buckets are too coarse to show
    # disagreement. Confidence deltas surface the soft divergence the buckets hide.
    report = run_backtest(_seeded_service(), HeuristicDemoAnalyst())
    summary = report.confidence_delta_summary
    assert {"mean_abs_delta", "max_abs_delta", "count_over_threshold"} <= set(summary)
    assert summary["max_abs_delta"] > 0.0  # heuristic analyst (0.6) differs from triage confidence
    assert report.results
    assert all(r.confidence_delta >= 0.0 for r in report.results)


def test_no_report_cases_are_counted_with_reason() -> None:
    # The curated corpus includes a case that produces no gradeable report (blocked).
    # The backtest must surface WHY (the 27-vs-31 gap from the live run), not silently
    # skip it. Reason = the case's triage_status.
    report = run_backtest(_seeded_service(), HeuristicDemoAnalyst())
    assert report.no_report_total >= 1
    assert sum(report.no_report_reasons.values()) == report.no_report_total
    assert report.no_report_reasons  # categorized by triage_status, not silent


def test_grading_failure_types_are_recorded_not_silent() -> None:
    # Found live 2026-06-01: failures were counted but their category was discarded,
    # so the report couldn't say WHY gradings failed. Now each failure_type is kept.
    report = run_backtest(_seeded_service(), _RaiseAnalyst())
    assert report.grading_failures == 31
    assert sum(report.grading_failure_types.values()) == 31
    assert report.grading_failure_types  # category recorded, not silent
