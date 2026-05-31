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
import json
from typing import Any

from pydantic import BaseModel, Field

from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder, SeedResult


# Auditor ordering: most critical first.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_key(severity: str | None) -> int:
    return _SEVERITY_RANK.get(severity or "", 99)


class SocCaseSample(BaseModel):
    family: str
    source_case_id: str
    severity: str | None
    triage_status: str
    guardrail_blocked: bool


class ExecSummaryItem(BaseModel):
    """One ranked case in the batch executive summary, with provenance/traceability."""

    rank: int
    severity: str | None = None
    determination: str | None = None
    disposition: str | None = None
    confidence: float | None = None
    source_case_id: str
    case_id: str
    family: str
    triage_status: str
    evidence_ids: list[str] = Field(default_factory=list)  # traceability
    source_payload_hash: str | None = None  # provenance


class BatchExecutiveSummary(BaseModel):
    """Auditor-facing batch summary: most critical first, with provenance/traceability.

    ``narrative`` is the LLM-generated executive prose slot. It is ``None`` here
    because the inert deterministic provider produces no synthesis — a real
    (gated) `TriageProvider` fills it. The ranking, severity counts, and per-case
    provenance below are deterministic and complete on their own, so this object
    is a usable audit artifact today even with the narrative empty.
    """

    narrative: str | None = None
    narrative_status: str = "pending_real_llm_provider"
    total_cases: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    items: list[ExecSummaryItem] = Field(default_factory=list)
    blocked_notes: list[str] = Field(default_factory=list)


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
    executive_summary: BatchExecutiveSummary = Field(default_factory=BatchExecutiveSummary)
    sample_reports: list[dict[str, Any]] = Field(default_factory=list)


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


def _build_executive_summary(service: CaseService, family_of: dict[str, str]) -> BatchExecutiveSummary:
    items: list[ExecSummaryItem] = []
    blocked_notes: list[str] = []
    by_severity: dict[str, int] = {}

    for read_item in service.list_case_read_models().items:
        family = family_of.get(read_item.source_case_id, "unknown")
        report = service.get_report(read_item.case_id)
        if report is None:
            blocked_notes.append(
                f"{read_item.source_case_id} ({family}) status={read_item.triage_status.value} "
                f"- no report; guardrail blocked before triage generation."
            )
            continue
        report_d = report.model_dump(mode="json")
        case = service.get_case(read_item.case_id)
        provenance = case.model_dump(mode="json").get("source_payload_hash") if case else None
        evidence_ids = sorted(
            {eid for finding in report_d.get("findings", []) for eid in finding.get("evidence_ids", [])}
        )
        severity = report_d.get("severity")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        items.append(
            ExecSummaryItem(
                rank=0,
                severity=severity,
                determination=report_d.get("determination"),
                disposition=report_d.get("disposition"),
                confidence=report_d.get("confidence"),
                source_case_id=read_item.source_case_id,
                case_id=read_item.case_id,
                family=family,
                triage_status=read_item.triage_status.value,
                evidence_ids=evidence_ids,
                source_payload_hash=provenance,
            )
        )

    items.sort(key=lambda it: (_sev_key(it.severity), it.source_case_id))
    for rank, item in enumerate(items, start=1):
        item.rank = rank

    return BatchExecutiveSummary(
        total_cases=len(items),
        by_severity=dict(sorted(by_severity.items())),
        items=items,
        blocked_notes=sorted(blocked_notes),
    )


def _collect_sample_reports(service: CaseService, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for read_item in service.list_case_read_models().items:
        report = service.get_report(read_item.case_id)
        if report is None:
            continue
        out.append({"source_case_id": read_item.source_case_id, "report": report.model_dump(mode="json")})
        if len(out) >= limit:
            break
    return out


def run_soc_demo(settings: Settings | None = None, *, sample_report_count: int = 0) -> SocDemoRunSummary:
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
        executive_summary=_build_executive_summary(service, family_of),
        sample_reports=_collect_sample_reports(service, sample_report_count) if sample_report_count else [],
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
    es = summary.executive_summary
    lines.append("Executive Summary (batch) - most critical first:")
    lines.append(f"  narrative: [{es.narrative_status}] (LLM-generated prose is gated on a real provider)")
    lines.append(f"  by_severity: {es.by_severity}")
    for it in es.items[:10]:
        lines.append(
            f"   #{it.rank:<2} {(it.severity or '-'):<8} {(it.determination or '-'):<10} "
            f"{it.source_case_id:<34} evidence={','.join(it.evidence_ids) or '-':<28} "
            f"prov={(it.source_payload_hash or '-')[:18]}"
        )
    if len(es.items) > 10:
        lines.append(f"   ... and {len(es.items) - 10} more (full list in JSON)")
    for note in es.blocked_notes:
        lines.append(f"   [blocked] {note}")
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
    parser.add_argument(
        "--show-reports",
        type=int,
        default=0,
        metavar="N",
        help="Also print full triage reports for the first N completed cases.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use settings from the environment/.env (e.g. the real Claude provider) "
        "instead of the in-memory deterministic demo.",
    )
    args = parser.parse_args()

    if args.live:
        from dataclasses import replace
        from threatprism.config import load_local_dotenv

        load_local_dotenv()
        # Real provider/keys from .env, but a clean in-memory DB each run.
        settings = replace(Settings.from_env(), database_url="sqlite:///:memory:")
    else:
        settings = _demo_settings()
    settings.validate_runtime()
    summary = run_soc_demo(settings, sample_report_count=args.show_reports)

    if args.json:
        print(summary.model_dump_json(indent=2))
        return 0

    print(_render_human(summary))
    if args.show_reports:
        print()
        print(f"--- Full triage reports (first {args.show_reports} completed cases) ---")
        for sr in summary.sample_reports:
            print(f"\n## {sr['source_case_id']}")
            print(json.dumps(sr["report"], indent=1))
    print()
    print(summary.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
