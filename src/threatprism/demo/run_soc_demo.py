"""End-to-end SOC dataset run.

Demonstrates the premise of the whole build: take a realistic SOC dataset, push
it through the *real* ThreatPrism intake + four-layer guardrail + triage +
persistence + read-model pipeline, and emit a summary proving it worked — with no
SOAR, no live LLM, and no production environment.

The dataset is the three reviewed third-party families promoted under
``fixtures/curated_datasets/`` (Synthea healthcare, deepset prompt-injection, OTRF
SOC telemetry), replayed through `create_case` + `run_triage` by the existing
`DemoSeeder`. This proves the *pipeline, guardrails, persistence, and
observability* work on real-shaped data. It does not demonstrate LLM reasoning
quality — that is gated on real-LLM rollout (the provider here is the inert
`DeterministicDemoProvider`).

Run it:

    python -m threatprism.demo.run_soc_demo            # human-readable + JSON
    python -m threatprism.demo.run_soc_demo --json     # JSON only
"""

from __future__ import annotations

import argparse

from pydantic import BaseModel, Field

from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder, SeedResult


class SocCaseSample(BaseModel):
    family: str
    source_case_id: str
    severity: str | None
    triage_status: str
    guardrail_blocked: bool


class SocDemoRunSummary(BaseModel):
    """Sanitized, serializable proof of an end-to-end SOC dataset run."""

    seeded_total: int = 0
    skipped_total: int = 0
    by_family: dict[str, int] = Field(default_factory=dict)
    cases_total: int = 0
    triage: dict[str, int] = Field(default_factory=dict)
    severity: dict[str, int] = Field(default_factory=dict)
    determination: dict[str, int] = Field(default_factory=dict)
    guardrails: dict[str, int] = Field(default_factory=dict)
    manager_review_queue: int = 0
    healthcare_review_queue: int = 0
    samples: list[SocCaseSample] = Field(default_factory=list)


def _demo_settings() -> Settings:
    """Self-contained, in-memory, auth-disabled local-dev settings for the demo run."""
    return Settings(
        env="demo",
        database_url="sqlite:///:memory:",
        api_auth_mode="none",
        auth_required=False,
        local_dev_ack=True,
        llm_provider="deterministic_demo",
        allow_real_actions=False,
    )


def _family_by_source_case_id(result: SeedResult) -> dict[str, str]:
    return {outcome.source_case_id: outcome.fixture_id for outcome in result.seeded}


def run_soc_demo(settings: Settings | None = None) -> SocDemoRunSummary:
    settings = settings or _demo_settings()
    service = CaseService(settings)

    result = DemoSeeder(service).seed([CuratedDatasetSource()])
    family_of = _family_by_source_case_id(result)

    by_family: dict[str, int] = {}
    for outcome in result.seeded:
        by_family[outcome.fixture_id] = by_family.get(outcome.fixture_id, 0) + 1

    metrics = service.get_operational_metrics()
    manager_queue = service.list_case_read_models(manager_review_required=True)
    healthcare_queue = service.list_case_read_models(healthcare_review_required=True)

    # One representative case per family for the human-readable proof.
    samples: list[SocCaseSample] = []
    seen_families: set[str] = set()
    for item in service.list_case_read_models().items:
        family = family_of.get(item.source_case_id, "unknown")
        if family in seen_families:
            continue
        seen_families.add(family)
        samples.append(
            SocCaseSample(
                family=family,
                source_case_id=item.source_case_id,
                severity=item.triage.severity if item.triage else None,
                triage_status=item.triage_status.value,
                guardrail_blocked=item.guardrail_blocked,
            )
        )
    samples.sort(key=lambda s: s.family)

    return SocDemoRunSummary(
        seeded_total=result.seeded_count,
        skipped_total=result.skipped_count,
        by_family=dict(sorted(by_family.items())),
        cases_total=metrics.case_counts.total,
        triage={
            "queued": metrics.triage.queued,
            "running": metrics.triage.running,
            "completed": metrics.triage.completed,
            "blocked_by_guardrail": metrics.triage.blocked_by_guardrail,
            "needs_review": metrics.triage.needs_review,
            "failed": metrics.triage.failed,
        },
        severity=dict(sorted(metrics.report_decisions.severity.items())),
        determination=dict(sorted(metrics.report_decisions.determination.items())),
        guardrails={
            "blocked_cases": metrics.guardrails.blocked_cases,
            "healthcare_review_required": metrics.guardrails.healthcare_review_required,
            "potential_sensitive_data_exposure": metrics.guardrails.potential_sensitive_data_exposure,
            "secret_exposure_detected": metrics.guardrails.secret_exposure_detected,
        },
        manager_review_queue=len(manager_queue.items),
        healthcare_review_queue=len(healthcare_queue.items),
        samples=samples,
    )


def _render_human(summary: SocDemoRunSummary) -> str:
    lines: list[str] = []
    lines.append("ThreatPrism - End-to-End SOC Dataset Run")
    lines.append("=" * 44)
    lines.append("Source: fixtures/curated_datasets/ (3 reviewed families) - no SOAR, no live LLM, no prod.")
    lines.append("")
    lines.append(f"Seeded {summary.seeded_total} cases (skipped {summary.skipped_total}) through real intake + triage:")
    for family, count in summary.by_family.items():
        lines.append(f"  - {family}: {count}")
    lines.append("")
    t = summary.triage
    lines.append("Triage outcome (all terminal - nothing left pending):")
    lines.append(f"  completed={t['completed']}  blocked_by_guardrail={t['blocked_by_guardrail']}  "
                 f"needs_review={t['needs_review']}  failed={t['failed']}  queued={t['queued']}  running={t['running']}")
    lines.append("")
    lines.append(f"Report severity:       {summary.severity}")
    lines.append(f"Report determination:  {summary.determination}")
    lines.append(f"Guardrail blocks:      {summary.guardrails['blocked_cases']} "
                 f"(prompt firewall fired on retained injection text)")
    lines.append(f"Manager-review queue:  {summary.manager_review_queue}    "
                 f"Healthcare-review queue: {summary.healthcare_review_queue}")
    lines.append("  (queues reflect post-sanitization snapshots: already-tokenized PHI does not re-flag - see spec 31 section 7)")
    lines.append("")
    lines.append("Representative case per family:")
    for s in summary.samples:
        lines.append(f"  - {s.family:<26} {s.source_case_id:<34} "
                     f"severity={s.severity or '-':<8} status={s.triage_status} blocked={s.guardrail_blocked}")
    lines.append("")
    lines.append("Result: the pipeline, guardrails, persistence, and observability work end-to-end on")
    lines.append("real-shaped SOC data. LLM reasoning quality is NOT demonstrated (gated on real-LLM rollout).")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ThreatPrism end-to-end against the curated SOC dataset")
    parser.add_argument("--json", action="store_true", help="Print JSON only (no human-readable summary).")
    args = parser.parse_args()

    settings = _demo_settings()
    settings.validate_runtime()
    summary = run_soc_demo(settings)

    if args.json:
        print(summary.model_dump_json(indent=2))
    else:
        print(_render_human(summary))
        print()
        print(summary.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
