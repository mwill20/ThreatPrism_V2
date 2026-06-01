"""Evolution 1 — Batched-benign auto-close delta (PRODUCT_VALUE_AND_ROADMAP §5).

The headline SOC-migration use case: a SOAR auto-closes the high-volume "probably
benign" alert stream to save analyst time. Every auto-close is a bet, and the
dangerous case is the one it closes *wrong* (a false negative). ThreatPrism's value
is triaging that volume and surfacing the case the cheap rule would have wrongly
closed.

This computes the **delta** between a naive SOAR auto-close rule and ThreatPrism's
triage verdict. The auto-close rule is deliberately **independent** of ThreatPrism
(it keys on the *inbound* alert severity the SOAR sees pre-triage) — otherwise the
comparison is circular. The headline number is `catches`: cases the SOAR would
auto-close that ThreatPrism flagged as non-benign.

Provider-agnostic: deterministic with the demo provider (structural demonstration
on the curated corpus); the real auto-close rate + catch count come from a real
`TriageProvider` over a benign feed under `--live`. No fabricated volume numbers.
"""

from __future__ import annotations

import argparse

from pydantic import BaseModel, Field

from threatprism.cases.schemas import CaseRecord, Determination, Severity, TriageReport
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder

# A naive SOAR catch-all auto-closes anything the *source* did not mark high/critical.
_HIGH_INBOUND_SEVERITIES = {"high", "critical", "severe", "sev1", "sev2"}


def soar_would_auto_close(case: CaseRecord) -> bool:
    """The independent pre-triage rule: auto-close unless an inbound alert is
    high/critical. Uses only what the SOAR sees before ThreatPrism triages."""
    inbound = {(alert.severity or "").strip().lower() for alert in case.alerts}
    return not (inbound & _HIGH_INBOUND_SEVERITIES)


def threatprism_flagged(report: TriageReport) -> bool:
    """ThreatPrism considers the case worth a human: non-benign determination or
    high/critical triage severity."""
    return report.determination != Determination.benign or report.severity in {
        Severity.high,
        Severity.critical,
    }


def _inbound_severity(case: CaseRecord) -> str:
    sevs = [(a.severity or "").strip().lower() for a in case.alerts if (a.severity or "").strip()]
    return ",".join(sorted(set(sevs))) if sevs else "none"


class AutoCloseCaseResult(BaseModel):
    source_case_id: str
    case_id: str
    inbound_severity: str
    soar_would_auto_close: bool
    threatprism_determination: str
    threatprism_severity: str
    threatprism_flagged: bool
    is_catch: bool  # SOAR would auto-close, ThreatPrism flagged -> a saved false negative


class AutoCloseDeltaReport(BaseModel):
    total: int = 0
    auto_close_count: int = 0
    auto_close_rate: float = 0.0  # share of cases the SOAR rule would auto-close
    residual_review_count: int = 0  # cases the SOAR escalates to a human anyway
    catches: int = 0  # auto-close ∩ ThreatPrism-flagged (the saves)
    safe_auto_close_count: int = 0  # auto-close ∩ ThreatPrism-benign (agreement)
    soar_escalated_tp_cleared: int = 0  # SOAR escalated, ThreatPrism says benign (FP relief)
    catch_cases: list[AutoCloseCaseResult] = Field(default_factory=list)
    results: list[AutoCloseCaseResult] = Field(default_factory=list)


def run_auto_close_delta(service: CaseService) -> AutoCloseDeltaReport:
    results: list[AutoCloseCaseResult] = []
    for item in service.list_case_read_models().items:
        report = service.get_report(item.case_id)
        if report is None:
            continue  # blocked / no report — not part of the auto-close volume
        case = service.get_case(item.case_id)
        if case is None:
            continue
        auto_close = soar_would_auto_close(case)
        flagged = threatprism_flagged(report)
        results.append(
            AutoCloseCaseResult(
                source_case_id=item.source_case_id,
                case_id=item.case_id,
                inbound_severity=_inbound_severity(case),
                soar_would_auto_close=auto_close,
                threatprism_determination=report.determination.value,
                threatprism_severity=report.severity.value,
                threatprism_flagged=flagged,
                is_catch=auto_close and flagged,
            )
        )

    total = len(results)
    auto_close = [r for r in results if r.soar_would_auto_close]
    catch_cases = [r for r in results if r.is_catch]
    return AutoCloseDeltaReport(
        total=total,
        auto_close_count=len(auto_close),
        auto_close_rate=round(len(auto_close) / total, 3) if total else 0.0,
        residual_review_count=total - len(auto_close),
        catches=len(catch_cases),
        safe_auto_close_count=sum(1 for r in auto_close if not r.threatprism_flagged),
        soar_escalated_tp_cleared=sum(
            1 for r in results if not r.soar_would_auto_close and not r.threatprism_flagged
        ),
        catch_cases=catch_cases,
        results=results,
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


def _render_human(report: AutoCloseDeltaReport) -> str:
    lines = [
        "ThreatPrism - Evolution 1 Auto-Close Delta (vs a naive SOAR auto-close rule)",
        "=" * 76,
        f"Triaged cases:               {report.total}",
        f"SOAR would auto-close:       {report.auto_close_count} ({report.auto_close_rate:.0%} volume reduction)",
        f"  ...ThreatPrism cleared:    {report.safe_auto_close_count} (agreement - safe to auto-close)",
        f"  ...ThreatPrism FLAGGED:    {report.catches} (the catch - auto-close would have missed these)",
        f"SOAR escalated to a human:   {report.residual_review_count}",
        f"  ...ThreatPrism cleared:    {report.soar_escalated_tp_cleared} (false-positive relief)",
        "",
        "Cases the SOAR would auto-close but ThreatPrism flagged (the value):",
    ]
    for r in report.catch_cases:
        lines.append(
            f"  - {r.source_case_id:<36} inbound={r.inbound_severity:<10} "
            f"TP={r.threatprism_determination}/{r.threatprism_severity}"
        )
    if not report.catch_cases:
        lines.append("  (none in this corpus under this provider)")
    lines.append("")
    lines.append("Note: deterministic demo provider shows the machinery on the curated corpus.")
    lines.append("Real auto-close rate + catch count require a real TriageProvider over a benign")
    lines.append("feed under --live (docs/runbooks/OPEN_REAL_LLM_GATE.md). No volume is fabricated.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Evolution 1 auto-close delta over the curated SOC dataset"
    )
    parser.add_argument("--json", action="store_true", help="Print JSON only.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use settings from the environment/.env (real triage provider) instead of "
        "the in-memory deterministic demo.",
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

    report = run_auto_close_delta(service)
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(_render_human(report))
        print()
        print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
