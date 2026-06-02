"""Tamper-evident, append-only failure log for LLM/analyst validation failures.

Owner requirement (2026-06-02): when a model emits output outside our closed
vocabulary (or any other fail-closed condition), we must be able to see *what*
failed and *why*, immutably — for debugging, tuning, feedback, and forensics.

Design: a thin ``TriageFailureReport`` adapter over the shared, generic
``HashChainedLog`` (`persistence/hash_chain.py`) — one append-only JSONL hash chain
whose ``verify()`` catches any later edit, deletion, or reorder. That is the
"immutable" guarantee (tamper-evident, not merely append-by-convention).

Safety: this sink stores only what is already in a ``TriageFailureReport`` — field
paths, codes, and SANITIZED offending values (PHI/secrets tokenized upstream before
they reach the report). It never receives a raw payload. Lives under the gitignored
``data/`` tree.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from threatprism.llm.failures import TriageFailureReport
from threatprism.persistence.hash_chain import GENESIS_HASH, HashChainedLog

__all__ = ["GENESIS_HASH", "FailureLog", "build_failure_log", "offending_value_sanitizer"]


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


@dataclass
class FailureLog:
    """Append-only, hash-chained sink for ``TriageFailureReport`` records."""

    path: Path
    _log: HashChainedLog = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._log = HashChainedLog(self.path)

    def append(self, report: TriageFailureReport) -> dict:
        """Append one failure record, linking it to the prior record's hash."""
        return self._log.append_payload(report.model_dump(mode="json"))

    def verify(self) -> bool:
        """Recompute the chain; return False on any edit, deletion, or reorder."""
        return self._log.verify()
