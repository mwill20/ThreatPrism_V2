"""Deterministic batch planning for real-LLM triage (spec 33 §3).

Batches close on a dual trigger: ``BATCH_MAX_EVENTS`` events OR
``BATCH_MAX_INPUT_TOKENS`` tokens, whichever is hit first. Boundaries are
deterministic (the caller supplies items in a stable order), a single case is
never split across batches, and a case that alone exceeds the token budget is
flagged ``oversized`` (it becomes a ``budget_exceeded`` failure upstream rather
than being sent).

Pure and deterministic — no network, no model. Token counts are supplied by the
caller (from the provider tokenizer or the conservative heuristic below) and are
measured on already-tokenized, prompt-firewalled text, never raw PHI.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Conservative chars-per-token heuristic for the no-tokenizer path. Biased to
# overcount so the real provider context window is never exceeded.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return max(1, (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)


@dataclass(frozen=True)
class BatchItem:
    case_id: str
    tokens: int


@dataclass
class BatchPlan:
    batches: list[list[str]] = field(default_factory=list)  # case_ids per batch
    oversized: list[str] = field(default_factory=list)      # single case > token budget

    @property
    def batch_count(self) -> int:
        return len(self.batches)


def plan_batches(
    items: list[BatchItem],
    *,
    max_events: int,
    max_input_tokens: int,
) -> BatchPlan:
    """Group items into deterministic batches by the dual trigger.

    ``items`` MUST already be in the caller's stable order (e.g. severity-rank
    then source_case_id). This function never reorders them.
    """
    if max_events <= 0:
        raise ValueError("max_events must be greater than zero")
    if max_input_tokens <= 0:
        raise ValueError("max_input_tokens must be greater than zero")

    plan = BatchPlan()
    current: list[str] = []
    current_tokens = 0

    for item in items:
        if item.tokens > max_input_tokens:
            # A single case cannot fit — never send it; flag for upstream failure.
            plan.oversized.append(item.case_id)
            continue
        would_exceed_events = len(current) >= max_events
        would_exceed_tokens = current and (current_tokens + item.tokens) > max_input_tokens
        if would_exceed_events or would_exceed_tokens:
            plan.batches.append(current)
            current = []
            current_tokens = 0
        current.append(item.case_id)
        current_tokens += item.tokens

    if current:
        plan.batches.append(current)
    return plan
