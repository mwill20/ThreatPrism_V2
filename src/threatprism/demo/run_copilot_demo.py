"""Evolution 3 — single-event live co-pilot cadence (headless driver).

Walks ONE case through the full analyst loop at single-event cadence:

    create_case -> run_triage (real provider under --live, deterministic otherwise)
      -> self-assign (assign_case)  -> analyst submits feedback  -> disagreement record

This is the headless analogue of the dashboard co-pilot panel, so the live owner-run is
repeatable, cost-capped (one case), and regression-tested. The analyst's verdict is an
explicit input (``AnalystVerdict``), NOT an LLM — it demonstrates the loop mechanics and
the tuning signal (disagreement -> manager review), it does not claim human judgment.
Reusing the Evolution-2 OpenAI ``MockAnalyst`` here would wrongly conflate the
independent second-opinion grader with the analyst working the case.

    PYTHONPATH=src python -m threatprism.demo.run_copilot_demo            # deterministic
    PYTHONPATH=src python -m threatprism.demo.run_copilot_demo --live     # real triage (paid)
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from threatprism.cases.schemas import (
    AnalystFeedbackCreate,
    Determination,
    Disposition,
    Severity,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder

_ANALYST_IDENTITY = "copilot_analyst"


@dataclass
class AnalystVerdict:
    """The human analyst's verdict. Any field left None mirrors the triage report
    (agreement); set a field to simulate the analyst reaching a different conclusion."""

    determination: str | None = None
    severity: str | None = None
    disposition: str | None = None
    confidence: float | None = None


class CopilotDemoResult(BaseModel):
    case_id: str
    source_case_id: str
    owner: str
    triage_determination: str
    triage_severity: str
    triage_confidence: float
    triage_disposition: str
    analyst_determination: str
    analyst_severity: str
    analyst_confidence: float
    analyst_disposition: str
    determination_mismatch: bool
    severity_mismatch: bool
    disposition_mismatch: bool
    confidence_delta: float
    manager_review_required: bool
    disagreement_reasons: list[str] = Field(default_factory=list)
    llm_usage: dict[str, Any] = Field(default_factory=dict)


def run_copilot_demo(
    service: CaseService,
    *,
    analyst_identity: str = _ANALYST_IDENTITY,
    analyst: AnalystVerdict | None = None,
) -> CopilotDemoResult | None:
    """Run one case through the single-event co-pilot loop. Returns None if no case
    could be seeded/triaged (e.g., the lone fixture was guardrail-blocked)."""
    DemoSeeder(service).seed([CuratedDatasetSource()], limit=1)
    items = service.list_case_read_models().items
    if not items:
        return None
    item = items[0]
    report = service.get_report(item.case_id)
    if report is None:
        return None

    # Evolution 3: the analyst self-assigns the case (ownership + audit).
    service.assign_case(item.case_id, actor_identity=analyst_identity, actor_role="analyst")

    # The analyst's verdict: mirror the report unless the caller overrides a field.
    verdict = analyst or AnalystVerdict()
    feedback = AnalystFeedbackCreate(
        analyst_id=analyst_identity,  # attribution is the authenticated caller
        analyst_determination=Determination(verdict.determination) if verdict.determination else report.determination,
        analyst_severity=Severity(verdict.severity) if verdict.severity else report.severity,
        analyst_confidence=verdict.confidence if verdict.confidence is not None else report.confidence,
        analyst_final_disposition=Disposition(verdict.disposition) if verdict.disposition else report.disposition,
    )
    response = service.submit_feedback(item.case_id, feedback)
    d = response.disagreement

    return CopilotDemoResult(
        case_id=item.case_id,
        source_case_id=item.source_case_id,
        owner=analyst_identity,
        triage_determination=report.determination.value,
        triage_severity=report.severity.value,
        triage_confidence=report.confidence,
        triage_disposition=report.disposition.value,
        analyst_determination=feedback.analyst_determination.value,
        analyst_severity=feedback.analyst_severity.value,
        analyst_confidence=feedback.analyst_confidence,
        analyst_disposition=feedback.analyst_final_disposition.value,
        determination_mismatch=d.determination_mismatch,
        severity_mismatch=d.severity_mismatch,
        disposition_mismatch=d.disposition_mismatch,
        confidence_delta=d.confidence_delta,
        manager_review_required=d.manager_review_required,
        disagreement_reasons=list(d.reasons),
        llm_usage=service.get_operational_metrics().llm_usage.model_dump(),
    )


def _render_human(result: CopilotDemoResult) -> str:
    lines = [
        f"Case {result.source_case_id} ({result.case_id})  owner={result.owner}",
        f"  ThreatPrism: {result.triage_determination}/{result.triage_severity}"
        f"  conf={result.triage_confidence}  disposition={result.triage_disposition}",
        f"  Analyst:     {result.analyst_determination}/{result.analyst_severity}"
        f"  conf={result.analyst_confidence}  disposition={result.analyst_disposition}",
        f"  Disagreement: determination={result.determination_mismatch}"
        f" severity={result.severity_mismatch} disposition={result.disposition_mismatch}"
        f" conf_delta={result.confidence_delta} -> manager_review={result.manager_review_required}",
    ]
    if result.disagreement_reasons:
        for reason in result.disagreement_reasons:
            lines.append(f"    - {reason}")
    usage = result.llm_usage or {}
    if usage.get("call_count"):
        lines.append(
            f"  LLM spend (this run): {usage.get('call_count')} calls, "
            f"{usage.get('total_tokens')} tok, ${usage.get('estimated_cost_usd')}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evolution 3 single-event co-pilot cadence demo.")
    parser.add_argument("--live", action="store_true", help="Use the real provider from .env (paid).")
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    parser.add_argument("--analyst-determination", choices=[d.value for d in Determination], default=None)
    parser.add_argument("--analyst-severity", choices=[s.value for s in Severity], default=None)
    parser.add_argument("--analyst-disposition", choices=[d.value for d in Disposition], default=None)
    parser.add_argument("--analyst-confidence", type=float, default=None)
    args = parser.parse_args()

    if args.live:
        from dataclasses import replace
        from threatprism.config import load_local_dotenv

        load_local_dotenv()
        settings = replace(Settings.from_env(), database_url="sqlite:///:memory:")
    else:
        settings = Settings(env="test", database_url="sqlite:///:memory:", auth_required=False, local_dev_ack=True)
    settings.validate_runtime()

    verdict = AnalystVerdict(
        determination=args.analyst_determination,
        severity=args.analyst_severity,
        disposition=args.analyst_disposition,
        confidence=args.analyst_confidence,
    )
    result = run_copilot_demo(CaseService(settings), analyst=verdict)
    if result is None:
        print("No case could be seeded/triaged (the lone fixture may have been guardrail-blocked).")
        return 1

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(_render_human(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
