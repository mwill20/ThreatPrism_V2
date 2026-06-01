"""OpenAI-backed mock analyst (spec 33; Evolution 2 grader).

Produces an *independent* analyst verdict (`AnalystFeedbackCreate`) for a case +
ThreatPrism report, so the disagreement loop (`submit_feedback` ->
`DisagreementRecord`) can measure where ThreatPrism and a baseline analyst differ.

**Independence rule:** this MUST be a different provider/model path than the
Claude triage provider, or the comparison is circular. ``provider_name`` is
asserted distinct in tests.

Gated and not exercised in the build environment (no SDK, no key). The live Chat
Completions call is isolated in ``_call`` and MUST be verified against the pinned
``openai`` version before use. Unconfigured -> structured ``LLMProviderError`` so
batch backtests fail closed rather than silently fabricating an analyst verdict.
"""

from __future__ import annotations

import json

from threatprism.cases.schemas import AnalystFeedbackCreate, CaseRecord, TriageReport
from threatprism.llm.failures import (
    ProviderAuthError,
    ProviderResponseUnparseable,
    ProviderUnreachable,
)


_ANALYST_SYSTEM_PROMPT = (
    "You are an experienced SOC analyst independently triaging a case. You are NOT "
    "the tool that produced the attached report — judge the case on its own merits. "
    "Return ONLY a JSON object with keys: analyst_id, analyst_determination "
    "(benign|suspicious|malicious|critical), analyst_severity (low|medium|high|"
    "critical), analyst_confidence (0..1), analyst_final_disposition, analyst_notes. "
    "Do not claim compliance or that any real action was taken."
)


class MockAnalyst:
    """An independent baseline-analyst grader backed by OpenAI."""

    provider_name = "openai_mock_analyst"

    def __init__(self, *, api_key: str, model_id: str, analyst_id: str = "mock_analyst_openai", temperature: float = 0.2) -> None:
        self.api_key = api_key
        self.model_id = model_id
        self.analyst_id = analyst_id
        self.temperature = temperature
        self.last_usage: object | None = None  # set per call for the spend ledger
        self.last_prompt: str = ""              # hashed (never raw) in the call audit
        self.last_response: str = ""

    def evaluate(self, case: CaseRecord, report: TriageReport) -> AnalystFeedbackCreate:
        # Reset per attempt so a stale record is never re-ledgered and a pre-call
        # failure leaves last_usage None -> nothing billed (spec 35 contract).
        self.last_usage = None
        self.last_prompt = ""
        self.last_response = ""
        prompt = self._build_prompt(case, report)
        self.last_prompt = prompt
        raw = self._call(prompt)
        self.last_response = raw
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProviderResponseUnparseable(f"mock-analyst response was not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ProviderResponseUnparseable("mock-analyst response JSON was not an object")
        parsed.setdefault("analyst_id", self.analyst_id)
        # May raise pydantic ValidationError -> schema_validation_failure upstream.
        return AnalystFeedbackCreate.model_validate(parsed)

    def _build_prompt(self, case: CaseRecord, report: TriageReport) -> str:
        return json.dumps(
            {
                "case": case.model_dump(mode="json"),
                "threatprism_report": report.model_dump(mode="json"),
            },
            sort_keys=True,
        )

    def _call(self, prompt: str) -> str:
        if not self.api_key:
            raise ProviderAuthError("OPENAI_API_KEY is not configured.")
        try:
            from openai import OpenAI  # noqa: F401  (gated dependency; verify pinned version)
        except ImportError as exc:
            raise ProviderUnreachable(
                "openai SDK is not installed; install the gated real-LLM extras."
            ) from exc

        # VERIFY against the pinned openai version before live use.
        try:
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model_id,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": _ANALYST_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            # VERIFY usage attribute names against the pinned openai version
            # (Chat Completions: usage.prompt_tokens / usage.completion_tokens).
            usage_obj = getattr(response, "usage", None)
            if usage_obj is not None:
                from threatprism.llm.governance import UsageRecord

                self.last_usage = UsageRecord(
                    model_id=self.model_id,
                    call_kind="analyst",
                    input_tokens=getattr(usage_obj, "prompt_tokens", 0),
                    output_tokens=getattr(usage_obj, "completion_tokens", 0),
                )
            return response.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001 - re-classified to a structured failure
            from threatprism.llm.providers import _classify_anthropic_error

            # Reuse the name-substring classifier (timeout/ratelimit/auth/unreachable).
            raise _classify_anthropic_error(exc) from exc


def build_mock_analyst(settings: object) -> MockAnalyst:
    return MockAnalyst(
        api_key=getattr(settings, "openai_api_key", ""),
        model_id=getattr(settings, "mock_analyst_model_id", "gpt-4o-mini"),
    )
