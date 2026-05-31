"""Real-LLM governance controls (AI_GOVERNANCE_ASSESSMENT.md gaps 1-4).

Deterministic, testable without keys. These are the controls a metered LLM needs
*before* it is turned on:

1. Spend cap  — pre-call ceiling on tokens + cost; exhaustion fails closed
   (`budget_exceeded`). (OWASP LLM10 Unbounded Consumption.)
2. Usage/cost accounting — a `UsageRecord` per call, accumulated in a `SpendLedger`.
   (NIST AI 600-1 MEASURE.)
3. Sanitized per-call audit — `build_llm_call_audit` records model id+revision,
   token counts, and a hash of prompt+response — never raw content. (EU AI Act.)
4. Approved-model allowlist — `APPROVED_MODELS`, an in-code frozenset enforced in
   `validate_runtime()`. (ISO/IEC 42001 governance.)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from threatprism.cases.schemas import AuditEvent, CaseRecord, TriageReport
from threatprism.llm.batching import estimate_tokens
from threatprism.llm.failures import TriageFailureReport, budget_exceeded_failure
from threatprism.llm.runner import safe_generate_report


# Code-authoritative allowlist of approved triage model ids (anti-tamper: config
# cannot select a model the code did not approve). Extend deliberately, in review.
APPROVED_MODELS = frozenset(
    {
        "claude-sonnet-4-5",
        "claude-opus-4-1",
        "claude-haiku-4-5",
    }
)


class UsageRecord(BaseModel):
    model_id: str
    model_revision: str | None = None
    call_kind: str = "triage"  # triage | narrative | analyst
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass(frozen=True)
class CostModel:
    """USD price per 1M tokens. Provider/model specific — configure per deployment."""

    input_price_per_mtok: float = 0.0
    output_price_per_mtok: float = 0.0

    def estimate(self, input_tokens: int, output_tokens: int) -> float:
        cost = (input_tokens / 1_000_000) * self.input_price_per_mtok
        cost += (output_tokens / 1_000_000) * self.output_price_per_mtok
        return round(cost, 6)


@dataclass
class SpendLedger:
    records: list[UsageRecord] = field(default_factory=list)

    def add(self, record: UsageRecord) -> None:
        self.records.append(record)

    @property
    def total_tokens(self) -> int:
        return sum(r.input_tokens + r.output_tokens for r in self.records)

    @property
    def total_cost_usd(self) -> float:
        return round(sum(r.estimated_cost_usd for r in self.records), 6)


def would_exceed_budget(
    ledger: SpendLedger,
    *,
    projected_tokens: int,
    projected_cost_usd: float,
    max_total_tokens: int,
    max_cost_usd: float,
) -> bool:
    if max_total_tokens > 0 and ledger.total_tokens + projected_tokens > max_total_tokens:
        return True
    if max_cost_usd > 0 and ledger.total_cost_usd + projected_cost_usd > max_cost_usd:
        return True
    return False


def enforce_spend_cap(
    ledger: SpendLedger,
    *,
    projected_tokens: int,
    projected_cost_usd: float,
    max_total_tokens: int,
    max_cost_usd: float,
    case_id: str | None = None,
    batch_id: str | None = None,
) -> TriageFailureReport | None:
    """Return a fail-closed `budget_exceeded` failure if the next call would breach
    the cap, else None (the call may proceed)."""
    if would_exceed_budget(
        ledger,
        projected_tokens=projected_tokens,
        projected_cost_usd=projected_cost_usd,
        max_total_tokens=max_total_tokens,
        max_cost_usd=max_cost_usd,
    ):
        return budget_exceeded_failure(
            case_id=case_id,
            batch_id=batch_id,
            why=(
                f"spend cap would be exceeded "
                f"(used {ledger.total_tokens} tok / ${ledger.total_cost_usd}; "
                f"projected +{projected_tokens} tok / +${projected_cost_usd}; "
                f"caps {max_total_tokens} tok / ${max_cost_usd})"
            ),
        )
    return None


def _hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_llm_call_audit(
    *,
    case_id: str,
    usage: UsageRecord,
    prompt: str,
    response: str,
) -> AuditEvent:
    """Sanitized per-call audit. Records counts + content HASHES, never raw text."""
    return AuditEvent(
        case_id=case_id,
        event_type="llm_call",
        summary="LLM call recorded (model, token usage, and content hashes).",
        metadata={
            "model_id": usage.model_id,
            "model_revision": usage.model_revision,
            "call_kind": usage.call_kind,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "estimated_cost_usd": usage.estimated_cost_usd,
            "prompt_sha256": _hash(prompt),
            "response_sha256": _hash(response),
        },
    )


def _case_text(case: CaseRecord) -> str:
    return " ".join(
        [case.title, case.description] + [item.summary for item in case.evidence]
    )


def metered_generate(
    provider: object,
    case: CaseRecord,
    ledger: SpendLedger,
    *,
    cost_model: CostModel,
    max_total_tokens: int,
    max_cost_usd: float,
    model_id: str | None = None,
    model_revision: str | None = None,
    projected_output_tokens: int = 1024,
) -> TriageReport | TriageFailureReport:
    """Spend-cap-gated generation: checks the budget *before* spending, then records
    usage *after* a successful call (from the provider's optional ``last_usage``)."""
    projected_input = estimate_tokens(_case_text(case))
    projected_cost = cost_model.estimate(projected_input, projected_output_tokens)
    cap_failure = enforce_spend_cap(
        ledger,
        projected_tokens=projected_input + projected_output_tokens,
        projected_cost_usd=projected_cost,
        max_total_tokens=max_total_tokens,
        max_cost_usd=max_cost_usd,
        case_id=case.case_id,
    )
    if cap_failure is not None:
        return cap_failure

    result = safe_generate_report(provider, case, model_id=model_id, model_revision=model_revision)
    if isinstance(result, TriageReport):
        usage = getattr(provider, "last_usage", None)
        if isinstance(usage, UsageRecord):
            # Price the actual reported tokens, not the projection.
            priced = usage.model_copy(
                update={"estimated_cost_usd": cost_model.estimate(usage.input_tokens, usage.output_tokens)}
            )
            ledger.add(priced)
    return result
