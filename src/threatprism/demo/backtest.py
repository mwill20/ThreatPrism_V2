"""Evolution 2 backtest harness (spec 33 / PRODUCT_VALUE_AND_ROADMAP §5).

Grades a batch of already-triaged cases against an independent analyst verdict and
reports where ThreatPrism and the analyst diverged — the tuning signal. It reuses
the existing feedback loop: ``analyst.evaluate(case, report) -> AnalystFeedbackCreate``
-> ``service.submit_feedback`` -> ``DisagreementRecord``.

Provider-agnostic and deterministic in the demo path: the analyst is a pluggable
grader. The real Evolution 2 uses the OpenAI ``MockAnalyst`` (independent of the
Claude triage brain); this module ships a deterministic ``HeuristicDemoAnalyst`` so
the harness is runnable and tested with no keys. Swap in the real grader at the gate.

The headline output is ``threatprism_flagged_analyst_cleared``: the cases
ThreatPrism called non-benign where the analyst cleared them — exactly the
"analyst worked it longer and disagreed" set that drives tuning.
"""

from __future__ import annotations

import argparse
import re
from typing import Protocol

from pydantic import BaseModel, Field

from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
    CaseRecord,
    Determination,
    Disposition,
    Severity,
    TriageReport,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder
from threatprism.llm.failures import LLMProviderError


class AnalystGrader(Protocol):
    provider_name: str

    def evaluate(self, case: CaseRecord, report: TriageReport) -> AnalystFeedbackCreate:
        ...


class BacktestCaseResult(BaseModel):
    source_case_id: str
    case_id: str
    threatprism_determination: str
    threatprism_severity: str
    analyst_determination: str
    analyst_severity: str
    determination_mismatch: bool
    severity_mismatch: bool
    threatprism_flagged_analyst_cleared: bool


class BacktestReport(BaseModel):
    graded_total: int = 0
    grading_failures: int = 0
    agreement_rate: float = 1.0  # 1 - determination_mismatch / graded
    determination_mismatches: int = 0
    severity_mismatches: int = 0
    by_threatprism_determination: dict[str, int] = Field(default_factory=dict)
    threatprism_flagged_analyst_cleared: list[BacktestCaseResult] = Field(default_factory=list)
    results: list[BacktestCaseResult] = Field(default_factory=list)


def run_backtest(service: CaseService, analyst: AnalystGrader) -> BacktestReport:
    results: list[BacktestCaseResult] = []
    grading_failures = 0
    by_det: dict[str, int] = {}

    for item in service.list_case_read_models().items:
        report = service.get_report(item.case_id)
        if report is None:
            continue  # blocked / no report — nothing to grade
        case = service.get_case(item.case_id)
        if case is None:
            continue
        try:
            feedback = analyst.evaluate(case, report)
        except LLMProviderError:
            grading_failures += 1
            continue

        response = service.submit_feedback(item.case_id, feedback)
        disagreement = response.disagreement
        tp_det = report.determination.value
        an_det = feedback.analyst_determination.value
        by_det[tp_det] = by_det.get(tp_det, 0) + 1
        results.append(
            BacktestCaseResult(
                source_case_id=item.source_case_id,
                case_id=item.case_id,
                threatprism_determination=tp_det,
                threatprism_severity=report.severity.value,
                analyst_determination=an_det,
                analyst_severity=feedback.analyst_severity.value,
                determination_mismatch=disagreement.determination_mismatch,
                severity_mismatch=disagreement.severity_mismatch,
                threatprism_flagged_analyst_cleared=(tp_det != "benign" and an_det == "benign"),
            )
        )

    graded = len(results)
    det_mismatches = sum(r.determination_mismatch for r in results)
    flagged_cleared = [r for r in results if r.threatprism_flagged_analyst_cleared]
    return BacktestReport(
        graded_total=graded,
        grading_failures=grading_failures,
        agreement_rate=round(1 - det_mismatches / graded, 3) if graded else 1.0,
        determination_mismatches=det_mismatches,
        severity_mismatches=sum(r.severity_mismatch for r in results),
        by_threatprism_determination=dict(sorted(by_det.items())),
        threatprism_flagged_analyst_cleared=flagged_cleared,
        results=results,
    )


class HeuristicDemoAnalyst:
    """Deterministic stand-in analyst for the no-keys demo path.

    Mirrors ThreatPrism's verdict EXCEPT it "clears" (downgrades to benign) the
    odd-indexed non-benign cases — simulating an analyst who investigated longer
    and disagreed. Produces a stable, meaningful divergence set with no model.
    """

    provider_name = "heuristic_demo_analyst"

    def evaluate(self, case: CaseRecord, report: TriageReport) -> AnalystFeedbackCreate:
        match = re.search(r"(\d+)$", case.source_case_id)
        index = int(match.group(1)) if match else 0
        determination = report.determination
        severity = report.severity
        disposition = report.disposition
        cleared = determination != Determination.benign and index % 2 == 1
        if cleared:
            determination, severity, disposition = Determination.benign, Severity.low, Disposition.monitor
        return AnalystFeedbackCreate(
            analyst_id=self.provider_name,
            analyst_determination=determination,
            analyst_severity=severity,
            analyst_confidence=0.6,
            analyst_final_disposition=disposition,
            false_positive=cleared,
        )


def _demo_settings() -> Settings:
    return Settings(
        env="demo",
        database_url="sqlite:///:memory:",
        api_auth_mode="none",
        auth_required=False,
        local_dev_ack=True,
        llm_provider="deterministic_demo",
        allow_real_actions=False,
    )


def _render_human(report: BacktestReport) -> str:
    lines = [
        "ThreatPrism - Evolution 2 Backtest (deterministic demo analyst)",
        "=" * 62,
        f"Graded {report.graded_total} cases (grading failures: {report.grading_failures}).",
        f"Determination agreement rate: {report.agreement_rate}",
        f"Determination mismatches: {report.determination_mismatches}  "
        f"Severity mismatches: {report.severity_mismatches}",
        f"ThreatPrism verdicts: {report.by_threatprism_determination}",
        "",
        "Where ThreatPrism flagged but the analyst cleared (tuning signal):",
    ]
    for r in report.threatprism_flagged_analyst_cleared:
        lines.append(
            f"  - {r.source_case_id:<34} TP={r.threatprism_determination}/{r.threatprism_severity}"
            f"  analyst={r.analyst_determination}/{r.analyst_severity}"
        )
    if not report.threatprism_flagged_analyst_cleared:
        lines.append("  (none)")
    lines.append("")
    lines.append("Note: the demo analyst is a deterministic stand-in. Real divergence requires the")
    lines.append("OpenAI mock-analyst at the gate (docs/runbooks/OPEN_REAL_LLM_GATE.md).")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Evolution 2 backtest over the curated SOC dataset")
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use settings from the environment/.env (real Claude triage provider) "
        "instead of the in-memory deterministic demo.",
    )
    args = parser.parse_args()

    if args.live:
        from dataclasses import replace
        from threatprism.config import load_local_dotenv

        load_local_dotenv()
        settings = replace(Settings.from_env(), database_url="sqlite:///:memory:")
    else:
        settings = _demo_settings()
    settings.validate_runtime()
    service = CaseService(settings)
    DemoSeeder(service).seed([CuratedDatasetSource()])

    if args.live:
        # Independent OpenAI grader (Evolution 2). Falls closed if unconfigured.
        from threatprism.llm.mock_analyst import build_mock_analyst

        analyst: AnalystGrader = build_mock_analyst(settings)
    else:
        analyst = HeuristicDemoAnalyst()
    report = run_backtest(service, analyst)

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(_render_human(report))
        print()
        print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
