"""Evolution 3 — single-event live co-pilot cadence (headless driver).

One case through the full analyst loop: create -> real/demo triage -> self-assign ->
analyst feedback -> disagreement record. The "analyst" verdict is an explicit input
(parameterized), not an LLM — this demonstrates the loop mechanics, it does not claim
human judgment. Deterministic by default; `--live` swaps in the real provider.
"""
from __future__ import annotations

import json

from threatprism.cases.service import CaseService
from threatprism.demo.run_copilot_demo import AnalystVerdict, run_copilot_demo
from support_settings import local_auth_disabled_settings


_FORBIDDEN = ("theshire", "cloudapp", "WORKSTATION5", "S-1-5-21")


def test_copilot_demo_runs_full_single_event_loop() -> None:
    result = run_copilot_demo(CaseService(local_auth_disabled_settings()))

    assert result.case_id
    assert result.owner == "copilot_analyst"          # the caller self-assigned
    assert result.triage_determination                # a triage verdict was produced
    # Default analyst mirrors the report -> agreement, no manager review forced.
    assert result.determination_mismatch is False
    assert result.severity_mismatch is False


def test_copilot_demo_detects_disagreement_when_analyst_diverges() -> None:
    baseline = run_copilot_demo(CaseService(local_auth_disabled_settings()))
    # Force the analyst to a determination that differs from the triage verdict.
    other = "malicious" if baseline.triage_determination != "malicious" else "benign"
    result = run_copilot_demo(
        CaseService(local_auth_disabled_settings()),
        analyst=AnalystVerdict(determination=other),
    )

    assert result.analyst_determination == other
    assert result.determination_mismatch is True
    assert result.disagreement_reasons  # the disagreement was explained, not silent


def test_copilot_demo_result_leaks_nothing(tmp_path) -> None:
    result = run_copilot_demo(CaseService(local_auth_disabled_settings()))
    blob = json.dumps(result.model_dump(mode="json"))
    for forbidden in _FORBIDDEN:
        assert forbidden not in blob
