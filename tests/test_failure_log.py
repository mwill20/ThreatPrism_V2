"""Tamper-evident, append-only failure log (owner requirement 2026-06-02).

Every LLM/analyst validation failure must be inspectable AND immutable: the sink is
an append-only JSONL hash chain (each record hashes the previous record's hash + its
own canonical payload), so any later edit or deletion is detectable via verify().
"""
from __future__ import annotations

import json
from pathlib import Path

from threatprism.llm.failure_log import GENESIS_HASH, FailureLog
from threatprism.llm.failures import FailureType, TriageFailureReport


def _report(why: str) -> TriageFailureReport:
    return TriageFailureReport(
        failure_type=FailureType.schema_validation_failure,
        stage="parse",
        what="LLM output did not match the schema.",
        why=why,
    )


def test_append_chains_records_and_verifies(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = FailureLog(path)
    r1 = log.append(_report("first"))
    r2 = log.append(_report("second"))

    assert r1["prev_hash"] == GENESIS_HASH
    assert r2["prev_hash"] == r1["record_hash"]  # the chain links record N to N-1
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert log.verify() is True


def test_verify_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = FailureLog(path)
    log.append(_report("first"))
    log.append(_report("second"))

    # Edit the first record's payload after the fact -> the chain must no longer verify.
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["payload"]["why"] = "edited after the fact"
    lines[0] = json.dumps(obj, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert log.verify() is False


def test_verify_detects_deletion(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = FailureLog(path)
    log.append(_report("first"))
    log.append(_report("second"))
    log.append(_report("third"))

    # Drop the middle record -> the surviving link is broken.
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")

    assert log.verify() is False


def test_append_is_additive_preserving_prior_lines(tmp_path: Path) -> None:
    path = tmp_path / "failures.jsonl"
    log = FailureLog(path)
    log.append(_report("first"))
    first_line = path.read_text(encoding="utf-8").splitlines()[0]

    log.append(_report("second"))
    after = path.read_text(encoding="utf-8").splitlines()

    assert after[0] == first_line  # append never rewrites an existing line
    assert len(after) == 2
