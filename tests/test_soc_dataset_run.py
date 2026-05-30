from __future__ import annotations

import json

from threatprism.demo.run_soc_demo import run_soc_demo
from support_settings import local_auth_disabled_settings


# Raw identifiers that must never appear in the end-to-end summary output.
_FORBIDDEN = ("theshire", "cloudapp", "WORKSTATION5", "S-1-5-21", "pgustavo")


def test_soc_dataset_run_is_end_to_end_and_terminal() -> None:
    summary = run_soc_demo(local_auth_disabled_settings())

    # All three curated families seeded through the real intake path.
    assert summary.seeded_total == 32
    assert summary.skipped_total == 0
    assert summary.by_family == {
        "synthea_healthcare": 12,
        "deepset_prompt_injection": 12,
        "otrf_soc_telemetry": 8,
    }
    assert summary.cases_total == 32


def test_every_case_reaches_a_terminal_triage_status() -> None:
    summary = run_soc_demo(local_auth_disabled_settings())
    t = summary.triage

    # Nothing left pending — the synchronous seed path runs triage inline.
    assert t["queued"] == 0
    assert t["running"] == 0
    assert t["completed"] + t["blocked_by_guardrail"] + t["needs_review"] + t["failed"] == 32


def test_prompt_firewall_fires_on_dataset_content() -> None:
    # The deepset family retains un-redacted injection text, so at least one
    # case must be blocked by the guardrail pipeline end-to-end. This is the
    # proof that the firewall actually runs on real dataset content.
    summary = run_soc_demo(local_auth_disabled_settings())

    assert summary.triage["blocked_by_guardrail"] >= 1
    assert summary.guardrails["blocked_cases"] >= 1
    # Cases with a report (completed) account for the full severity distribution.
    assert sum(summary.severity.values()) == summary.triage["completed"]


def test_summary_is_serializable_and_leaks_nothing() -> None:
    summary = run_soc_demo(local_auth_disabled_settings())

    blob = summary.model_dump_json()
    json.loads(blob)  # round-trips
    for token in _FORBIDDEN:
        assert token not in blob, f"summary leaked raw identifier: {token}"
