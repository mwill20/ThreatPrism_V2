"""Dev-time adapter: deepset/prompt-injections -> ThreatPrism injection fixtures.

Unlike every other adapter, this one deliberately does NOT run the prompt
firewall over the source text (``apply_prompt_firewall=False``). Attacker-
controlled injection strings are kept intact in the committed fixture so the
*runtime* firewall has live content to detect on replay. This is the single
source-scoped exception approved in ``docs/DATASET.md`` (deepset/prompt-injections
review) and specified for a future semantic layer in
``docs/specs/32_SEMANTIC_PROMPT_INJECTION_LAYER.md``.

The deepset corpus is labelled (``label==1`` => injection). Against the six
deterministic firewall patterns, only a small fraction of real injection rows
match -- most are semantic bypasses (RR-L1 in the LLM threat model). This adapter
promotes a deterministic mix of both so the regression corpus proves the firewall
catches what it recognizes AND exposes what it misses (which is harmless today
only because the provider is the inert ``DeterministicDemoProvider``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from threatprism.guardrails.prompt_firewall import PROMPT_INJECTION_RULES

from tools.fixture_factory.adapters.shared import (
    case_payload,
    default_role_visibility,
    guardrail,
    source_metadata,
    stable_fixture_id,
)
from tools.fixture_factory.models import PromptInjectionEvalFixture
from tools.fixture_factory.sanitizers import sanitize_fixture_source
from tools.fixture_factory.validators import validate_fixture_safety


SOURCE_ID = "deepset_prompt_injections"
SOURCE_FAMILY = "deepset"
ADAPTER_NAME = "deepset_adapter"

# deepset/prompt-injections labels: 1 == injection attempt, 0 == benign request.
INJECTION_LABEL = 1

# Deterministic curated mix. The corpus only carries one row matching a
# quarantine pattern, so the cap is generous and bounded by availability. The
# "none" bucket is the honest RR-L1 demonstration: real injections the
# deterministic firewall does not recognize.
BUCKET_TARGETS = {"quarantine": 2, "redact": 5, "none": 6}


def _classify_firewall(text: str) -> str:
    """Return the strongest firewall action the deterministic rules would take."""
    actions = {action for _name, pattern, action in PROMPT_INJECTION_RULES if pattern.search(text)}
    if "quarantine" in actions:
        return "quarantine"
    if "redact" in actions:
        return "redact"
    return "none"


def _read_injection_rows(input_path: Path) -> list[tuple[Path, int, dict[str, Any]]]:
    files = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.parquet"))
    rows: list[tuple[Path, int, dict[str, Any]]] = []
    for source_file in files:
        records = pq.read_table(source_file).to_pylist()
        for record_index, record in enumerate(records):
            if record.get("label") == INJECTION_LABEL:
                rows.append((source_file, record_index, {"text": str(record.get("text", "")), "label": INJECTION_LABEL}))
    return rows


def convert(input_path: Path, limit: int) -> list[PromptInjectionEvalFixture]:
    if limit <= 0:
        raise ValueError("--limit must be greater than zero")
    rows = _read_injection_rows(input_path)
    input_root = input_path if input_path.is_dir() else input_path.parent

    selected: dict[str, int] = {bucket: 0 for bucket in BUCKET_TARGETS}
    fixtures: list[PromptInjectionEvalFixture] = []
    for source_file, record_index, row in rows:
        if len(fixtures) >= limit:
            break
        bucket = _classify_firewall(row["text"])
        if selected[bucket] >= BUCKET_TARGETS[bucket]:
            continue
        fixture = _build_fixture(len(fixtures), source_file, record_index, row, input_root, bucket)
        if fixture is None:
            continue
        fixtures.append(fixture)
        selected[bucket] += 1
    return fixtures


def _build_fixture(
    index: int,
    source_file: Path,
    record_index: int,
    row: dict[str, Any],
    input_root: Path,
    bucket: str,
) -> PromptInjectionEvalFixture | None:
    fixture_id = stable_fixture_id("deepset_prompt_injection", index)
    # apply_prompt_firewall=False: keep the injection text intact (see module docstring).
    sanitized = sanitize_fixture_source(row, case_id=fixture_id, apply_prompt_firewall=False)
    firewall_recognized = bucket != "none"
    payload = _build_payload(fixture_id, sanitized.value)
    fixture = PromptInjectionEvalFixture(
        fixture_id=fixture_id,
        source_family=SOURCE_FAMILY,
        source_reference=SOURCE_ID,
        source_metadata=source_metadata(
            input_root=input_root,
            source_file=source_file,
            record_index=record_index,
            source_id=SOURCE_ID,
            adapter=ADAPTER_NAME,
            sanitized_row=sanitized.value,
        ),
        payload=payload,
        expected_result={
            "prompt_injection_expected": True,
            "deterministic_firewall_recognized": firewall_recognized,
            "deterministic_firewall_action": bucket,
            "quarantine_expected": bucket == "quarantine",
            # RR-L1: rows the pattern firewall misses reach the (inert) provider;
            # they are caught only by downstream output guardrails and the
            # provider not following instructions. A real LLM would re-raise this.
            "residual_risk": "RR-L1" if not firewall_recognized else None,
        },
        expected_guardrails=[_expected_guardrail(bucket)],
        expected_role_visibility=default_role_visibility(),
        expected_evidence_ids=[f"ev_{fixture_id}_001"],
        notes=(
            "Third-party synthetic prompt-injection fixture (deepset/prompt-injections, "
            "Apache-2.0). Injection text is intentionally retained un-redacted so the "
            "runtime prompt firewall is exercised on replay; rows the deterministic "
            "firewall misses demonstrate RR-L1."
        ),
    )
    try:
        validate_fixture_safety(fixture)
    except ValueError:
        # A rare injection row contains text that trips the output-policy scan
        # (e.g. remediation or clinical verbs). Skip it -- the corpus does not
        # need that specific row to make its point.
        return None
    return fixture


def _expected_guardrail(bucket: str):
    if bucket == "quarantine":
        return guardrail(
            "prompt_firewall",
            "quarantine",
            "Injection text matches a quarantine pattern; runtime triage is halted before the provider runs.",
        )
    if bucket == "redact":
        return guardrail(
            "prompt_firewall",
            "redact",
            "Injection text matches a redact pattern; the matched span is removed from the model-facing copy.",
        )
    return guardrail(
        "prompt_firewall",
        "pass",
        "Semantic injection not matched by the deterministic patterns (RR-L1); "
        "depends on downstream output guardrails and an inert provider until a semantic layer lands.",
    )


def _build_payload(fixture_id: str, row: dict[str, Any]) -> dict[str, Any]:
    injection_text = str(row.get("text", ""))
    return case_payload(
        fixture_id=fixture_id,
        title="Synthetic prompt-injection defense review",
        description=(
            "Third-party synthetic prompt-injection sample submitted for guardrail review; "
            "the injection content is carried in evidence for runtime firewall replay."
        ),
        evidence_summary="Third-party synthetic prompt-injection source row requires guardrail review.",
        evidence_excerpt=injection_text[:300],
        normalized={"source_row": row, "fixture_type": "prompt_injection"},
        source_family=SOURCE_FAMILY,
        manager_review_required=True,
    )
