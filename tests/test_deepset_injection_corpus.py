"""Slice 6: deepset/prompt-injections corpus behaviour and no-leak proof.

The committed deepset fixtures deliberately retain un-redacted injection text so
the *runtime* prompt firewall is exercised on replay. These tests assert three
things on the real intake + triage path:

1. The committed corpus loads through the license/safety gate (12 fixtures).
2. Each deterministic-firewall bucket behaves as the fixture predicts:
   - quarantine -> triage blocked before the provider runs;
   - none (semantic bypass, RR-L1) -> reaches the inert provider, triage still
     completes because the demo provider follows no embedded instructions.
3. The provable no-leak property: the stored CASE keeps the injection text (it
   is the evidence under review), but that text never appears in the generated
   triage report or the audit trail.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from threatprism.cases.schemas import CaseStatus, TriageStatus
from threatprism.cases.service import CaseService
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder, SeedCase
from support_settings import local_auth_disabled_settings


DEEPSET_FIXTURE = Path("fixtures/curated_datasets/deepset_prompt_injection.jsonl")
DEEPSET_FIXTURE_ID = "deepset_prompt_injection"


def _load_deepset_records() -> dict[str, dict[str, Any]]:
    """Map source_case_id -> bucket / residual-risk / injection excerpt."""
    records: dict[str, dict[str, Any]] = {}
    for raw_line in DEEPSET_FIXTURE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        rec = json.loads(line)
        source_case_id = rec["payload"]["source_case_id"]
        expected = rec["expected_result"]
        records[source_case_id] = {
            "bucket": expected["deterministic_firewall_action"],
            "recognized": expected["deterministic_firewall_recognized"],
            "residual_risk": expected["residual_risk"],
            "excerpt": rec["payload"]["evidence"][0]["excerpt"],
        }
    return records


def _collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for entry in value.values() for s in _collect_strings(entry)]
    if isinstance(value, list):
        return [s for entry in value for s in _collect_strings(entry)]
    return []


def _haystack(value: Any) -> str:
    # Join leaf strings with a separator that cannot occur in fixture text, so a
    # substring search cannot straddle two unrelated fields.
    return "\x00".join(_collect_strings(value))


def _service() -> CaseService:
    return CaseService(local_auth_disabled_settings())


def _deepset_seeds() -> list[SeedCase]:
    return [
        seed
        for seed in CuratedDatasetSource().list_demo_fixtures()
        if seed.fixture_id == DEEPSET_FIXTURE_ID
    ]


def _seed_deepset(service: CaseService) -> dict[str, str]:
    """Seed only the deepset family through real intake; return source_case_id -> case_id."""
    seeds = _deepset_seeds()

    class _DeepsetOnlySource:
        name = "deepset_only"

        def list_demo_fixtures(self) -> list[SeedCase]:
            return seeds

    result = DemoSeeder(service).seed([_DeepsetOnlySource()])
    return {outcome.source_case_id: outcome.case_id for outcome in result.seeded}


def test_deepset_corpus_loads_through_license_gate() -> None:
    seeds = _deepset_seeds()

    assert len(seeds) == 12
    assert len({seed.source_case_id for seed in seeds}) == 12


def test_deepset_bucket_distribution_matches_committed_corpus() -> None:
    records = _load_deepset_records()

    buckets = Counter(rec["bucket"] for rec in records.values())
    assert dict(buckets) == {"quarantine": 1, "redact": 5, "none": 6}

    # RR-L1 is recorded exactly on the rows the deterministic firewall misses.
    rr_rows = {sid for sid, rec in records.items() if rec["residual_risk"] == "RR-L1"}
    none_rows = {sid for sid, rec in records.items() if rec["bucket"] == "none"}
    assert rr_rows == none_rows
    assert all(rec["recognized"] is False for sid, rec in records.items() if sid in none_rows)


def test_quarantine_fixture_blocks_triage_before_provider() -> None:
    records = _load_deepset_records()
    service = _service()
    case_ids = _seed_deepset(service)

    quarantine_ids = [sid for sid, rec in records.items() if rec["bucket"] == "quarantine"]
    assert quarantine_ids, "corpus must carry the one real quarantine row"
    for sid in quarantine_ids:
        case = service.get_case(case_ids[sid])
        assert case is not None
        assert case.triage_status == TriageStatus.blocked_by_guardrail
        assert case.status == CaseStatus.needs_analyst_review
        assert case.triage_report is None
        assert any(
            event.event_type == "triage_blocked_by_prompt_firewall"
            for event in case.audit_trail
        )


def test_semantic_bypass_rows_reach_provider_and_complete_triage() -> None:
    # RR-L1: the deterministic firewall does not recognize these injections, so
    # they pass the firewall, reach the inert provider, and triage completes --
    # the demo provider follows no embedded instructions. This is the honest
    # demonstration of what the deterministic layer alone cannot catch.
    records = _load_deepset_records()
    service = _service()
    case_ids = _seed_deepset(service)

    none_ids = [sid for sid, rec in records.items() if rec["bucket"] == "none"]
    assert none_ids
    for sid in none_ids:
        case = service.get_case(case_ids[sid])
        assert case is not None
        assert case.triage_status == TriageStatus.completed
        assert case.triage_report is not None


def test_injection_text_never_leaks_into_report_or_audit() -> None:
    # Stored case legitimately retains the injection text (it is the evidence
    # under review); the report and audit trail must never echo it. This holds
    # even for semantic-bypass rows that reach the provider because the
    # DeterministicDemoProvider builds reports from evidence summaries/IDs, not
    # from excerpts or raw event content.
    records = _load_deepset_records()
    service = _service()
    case_ids = _seed_deepset(service)

    for sid, rec in records.items():
        excerpt = rec["excerpt"]
        case = service.get_case(case_ids[sid])
        assert case is not None

        # Positive control: the injection text survives into the stored case.
        assert any(evidence.excerpt == excerpt for evidence in case.evidence)

        report = service.get_report(case_ids[sid])
        if report is not None:
            assert excerpt not in _haystack(report.model_dump(mode="json"))

        audit_blob = _haystack([event.model_dump(mode="json") for event in case.audit_trail])
        assert excerpt not in audit_blob
