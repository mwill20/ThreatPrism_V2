"""Spec 37: the adversarial/ambiguous dataset must be divergence-capable and must
surface disagreements into the manager-review queue — proven deterministically
(no live provider)."""
from __future__ import annotations

from threatprism.cases.service import CaseService
from threatprism.demo.backtest import HeuristicDemoAnalyst, run_backtest
from threatprism.demo.seeding import AdversarialCuratedSource, DemoSeeder
from support_settings import local_auth_disabled_settings


def _adversarial_service() -> CaseService:
    service = CaseService(local_auth_disabled_settings())
    DemoSeeder(service).seed([AdversarialCuratedSource()])
    return service


def test_adversarial_set_loads_eight_synthetic_cases() -> None:
    seeds = AdversarialCuratedSource().list_demo_fixtures()
    assert len(seeds) == 8
    assert all(s.source_case_id.startswith("adv-ambiguous-") for s in seeds)


def test_adversarial_set_is_divergence_capable() -> None:
    # The whole point of spec 37: a clear-cut corpus gives 100% agreement and proves
    # nothing. This set must be capable of producing disagreement deterministically.
    report = run_backtest(_adversarial_service(), HeuristicDemoAnalyst())
    assert report.graded_total >= 1
    assert report.determination_mismatches >= 1
    assert len(report.threatprism_flagged_analyst_cleared) >= 1
    assert report.agreement_rate < 1.0


def test_adversarial_disagreement_surfaces_in_manager_review_queue() -> None:
    service = _adversarial_service()
    run_backtest(service, HeuristicDemoAnalyst())  # submits analyst feedback -> disagreements
    queue = [item for item in service.list_case_read_models().items if item.manager_review_required]
    assert queue, "expected at least one disagreement in the manager-review queue"
