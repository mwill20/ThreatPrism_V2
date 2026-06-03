"""RGOI retrieval-into-triage context builder (spec 38, half A).

Produces an approved-tier, sanitized, evidence-cited `TriageContextBundle` that is
*ready* to inject into a triage prompt.

**NOT WIRED:** nothing in the triage pipeline (`cases/service.py`, `run_triage`)
imports or calls this. Feeding retrieved cognition to the model is the indirect
prompt-injection surface (threat OT-L1) and is gated — see spec 38 §7. A regression test
(`tests/test_rgoi_triage_context.py::test_triage_pipeline_does_not_consume_rgoi_context`)
enforces the disconnection.

Defense-in-depth even though unwired: only `approved_knowledge` tier objects with
`review_status == approved` and `validation_state == valid` are eligible, governance
(tenant isolation, role/zone policy, quarantine exclusion, stale filtering) is reused
via the retrieval service, and every snippet is Stage-1 sanitized before it leaves here.
"""
from __future__ import annotations

from collections.abc import Callable

from threatprism.csi.schemas import (
    CognitiveTier,
    RetrievalContext,
    RetrievalZone,
    ReviewStatus,
    TriageContextBundle,
    TriageContextItem,
    ValidationState,
)
from threatprism.csi.service import CognitiveRetrievalService


def _default_sanitizer(text: str) -> str:
    from threatprism.guardrails.healthcare import safeguard_text

    return safeguard_text(text).value


def build_triage_context(
    service: CognitiveRetrievalService,
    context: RetrievalContext,
    *,
    query: str | None = None,
    max_items: int = 5,
    sanitizer: Callable[[str], str] | None = None,
) -> TriageContextBundle:
    """Build the approved-tier, sanitized, cited context bundle for a (would-be) prompt."""
    sanitize = sanitizer or _default_sanitizer
    # Reuse the governed retrieval (tenant isolation, role/zone policy, quarantine + stale
    # exclusion). Then hard-filter to human-approved knowledge only.
    response = service.search(context=context, query=query, include_stale=False, limit=max(max_items * 4, 20))

    items: list[TriageContextItem] = []
    for result in response.items:
        obj = result.object
        if obj.tier != CognitiveTier.approved_knowledge:
            continue
        if obj.review_status != ReviewStatus.approved:
            continue
        if obj.validation_state != ValidationState.valid:
            continue
        if obj.retrieval_zone == RetrievalZone.quarantine:
            continue
        items.append(
            TriageContextItem(
                object_id=obj.id,
                snippet=sanitize(obj.summary),
                evidence_ids=sorted({ref.evidence_id for ref in obj.evidence_refs}),
                trust_score=result.trust.overall,
                retrieval_zone=obj.retrieval_zone,
            )
        )
        if len(items) >= max_items:
            break

    return TriageContextBundle(
        tenant_id=context.tenant_id,
        purpose=context.purpose,
        items=items,
        notes=[
            "Approved-knowledge tier only; AI proposals and quarantined cognition are excluded.",
            "Snippets are Stage-1 sanitized.",
            "NOT consumed by run_triage — wiring into the model is gated (OT-L1, spec 38).",
        ],
    )
