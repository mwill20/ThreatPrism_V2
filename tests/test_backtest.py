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
