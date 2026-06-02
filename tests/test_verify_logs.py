"""Operator verify/inspect/export for the tamper-evident integrity logs.

An append-only hash chain is only useful if an operator can actually run verify(),
see what's in it, and export an integrity report (the export half of OT-8). These
functions back `python -m threatprism.persistence.verify_logs`.
"""
from __future__ import annotations

import json
from pathlib import Path

from threatprism.persistence.hash_chain import HashChainedLog
from threatprism.persistence.verify_logs import (
    all_valid,
    export_reports,
    verify_log,
)


def test_verify_log_reports_valid_chain_count_and_summary(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = HashChainedLog(path)
    log.append_payload({"failure_type": "schema_validation_failure"})
    log.append_payload({"failure_type": "schema_validation_failure"})
    log.append_payload({"failure_type": "provider_timeout"})

    report = verify_log("failure_log", str(path), "failure_type")

    assert report.exists is True
    assert report.chain_valid is True
    assert report.record_count == 3
    assert report.summary == {"provider_timeout": 1, "schema_validation_failure": 2}


def test_verify_log_detects_tamper(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = HashChainedLog(path)
    log.append_payload({"failure_type": "x"})
    log.append_payload({"failure_type": "y"})

    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["payload"]["failure_type"] = "tampered"
    lines[0] = json.dumps(obj, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify_log("failure_log", str(path), "failure_type").chain_valid is False


def test_verify_log_missing_path_is_trivially_valid(tmp_path: Path) -> None:
    report = verify_log("audit_log", str(tmp_path / "absent.jsonl"), "event_type")
    assert report.exists is False
    assert report.record_count == 0
    assert report.chain_valid is True  # nothing to tamper with


def test_export_writes_integrity_report(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedLog(path)
    log.append_payload({"event_type": "authorization_decision"})
    log.append_payload({"event_type": "triage_blocked_by_guardrail"})

    report = verify_log("audit_log", str(path), "event_type")
    dest = tmp_path / "integrity_report.json"
    export_reports([report], str(dest))

    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["all_valid"] is True
    assert data["logs"][0]["name"] == "audit_log"
    assert data["logs"][0]["record_count"] == 2
    assert data["logs"][0]["chain_valid"] is True
    assert data["logs"][0]["summary"] == {
        "authorization_decision": 1,
        "triage_blocked_by_guardrail": 1,
    }


def test_all_valid_is_false_when_any_log_fails(tmp_path: Path) -> None:
    good = HashChainedLog(tmp_path / "good.jsonl")
    good.append_payload({"event_type": "ok"})
    bad_path = tmp_path / "bad.jsonl"
    bad = HashChainedLog(bad_path)
    bad.append_payload({"event_type": "first"})
    bad.append_payload({"event_type": "second"})
    lines = bad_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["payload"]["event_type"] = "tampered"
    lines[0] = json.dumps(obj, sort_keys=True)
    bad_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reports = [
        verify_log("good", str(tmp_path / "good.jsonl"), "event_type"),
        verify_log("bad", str(bad_path), "event_type"),
    ]
    assert all_valid(reports) is False
