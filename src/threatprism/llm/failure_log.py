"""Tamper-evident, append-only failure log for LLM/analyst validation failures.

Owner requirement (2026-06-02): when a model emits output outside our closed
vocabulary (or any other fail-closed condition), we must be able to see *what*
failed and *why*, immutably — for debugging, tuning, feedback, and forensics.

Design: an append-only JSONL hash chain. Each line is
``{"payload": <sanitized TriageFailureReport>, "prev_hash": <hex>, "record_hash": <hex>}``
where ``record_hash = sha256(prev_hash + canonical(payload))`` and the first record's
``prev_hash`` is ``GENESIS_HASH``. Any later edit or deletion breaks the chain and is
caught by ``verify()`` — that is the "immutable" guarantee (tamper-evident, not merely
append-by-convention).

Safety: this sink stores only what is already in a ``TriageFailureReport`` — field
paths, codes, and SANITIZED offending values (PHI/secrets tokenized upstream before
they reach the report). It never receives a raw payload. Lives under the gitignored
``data/`` tree.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from threatprism.llm.failures import TriageFailureReport

GENESIS_HASH = "0" * 64


def offending_value_sanitizer() -> Callable[[str], str]:
    """Sanitizer for offending output values before they enter the log.

    Runs the existing healthcare/secret safeguard so PHI/PII/secret-shaped content is
    tokenized (`[POTENTIAL_PHI:...]`, `[SECRET:...]`) — the same Stage-1 discipline as
    the rest of the system. Lazy import avoids a module cycle (healthcare imports are
    heavy and unrelated to the pure failure taxonomy).
    """
    from threatprism.guardrails.healthcare import safeguard_text

    return lambda text: safeguard_text(text).value


def build_failure_log(settings: object) -> FailureLog | None:
    """Construct the failure sink from settings; None disables logging (empty path)."""
    path = getattr(settings, "failure_log_path", "") or ""
    return FailureLog(Path(path)) if path else None


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _record_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


@dataclass
class FailureLog:
    """Append-only, hash-chained sink for ``TriageFailureReport`` records."""

    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                last = json.loads(line).get("record_hash", last)
        return last

    def append(self, report: TriageFailureReport) -> dict:
        """Append one failure record, linking it to the prior record's hash."""
        payload = report.model_dump(mode="json")
        prev_hash = self._last_hash()
        record = {
            "payload": payload,
            "prev_hash": prev_hash,
            "record_hash": _record_hash(prev_hash, payload),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> bool:
        """Recompute the chain; return False on any edit, deletion, or reorder."""
        if not self.path.exists():
            return True
        prev_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("prev_hash") != prev_hash:
                    return False
                if record.get("record_hash") != _record_hash(prev_hash, record.get("payload", {})):
                    return False
                prev_hash = record["record_hash"]
        return True
