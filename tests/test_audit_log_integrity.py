"""Tamper-evident mirror of the case audit trail (OT-1 / rest of OT-8).

The case `audit_trail` lives in a rewritable SQLite blob. This mirrors every persisted
AuditEvent into an append-only, hash-chained log so authorization decisions, guardrail
blocks, rehydration, and role-view accesses are forensically tamper-evident. Wired at
`SQLiteRepository.save_case` (the single chokepoint), deduped by `audit_event_id` so the
many save_case calls per case never double-log an event.
"""
from __future__ import annotations

import json
from pathlib import Path

from threatprism.cases.service import CaseService
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder
from threatprism.persistence.hash_chain import HashChainedLog
from support_settings import local_auth_disabled_settings


def _run_seed_flow(settings) -> CaseService:
    service = CaseService(settings)
    DemoSeeder(service).seed([CuratedDatasetSource()])
    return service


def test_case_flow_writes_verifiable_audit_chain(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_trail.jsonl"
    _run_seed_flow(local_auth_disabled_settings(audit_log_path=str(log_path)))

    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0                       # audit events were mirrored
    assert HashChainedLog(log_path).verify() is True  # tamper-evident chain intact


def test_audit_mirror_dedups_across_many_save_case_calls(tmp_path: Path) -> None:
    # Seeding triggers multiple save_case calls per case (create -> triage -> ...), each
    # re-persisting the full growing audit_trail. The mirror must log each event ONCE.
    log_path = tmp_path / "audit_trail.jsonl"
    _run_seed_flow(local_auth_disabled_settings(audit_log_path=str(log_path)))

    ids = [
        json.loads(line)["payload"]["audit_event_id"]
        for line in log_path.read_text(encoding="utf-8").strip().splitlines()
    ]
    assert ids, "expected mirrored audit events"
    assert len(ids) == len(set(ids)), "audit events must not be double-logged"


def test_audit_mirror_disabled_by_default(tmp_path: Path) -> None:
    # Default (empty path) keeps the demo/test posture: no audit sink, no file writes.
    service = _run_seed_flow(local_auth_disabled_settings())
    assert service.repository.audit_log is None
