"""Semantic prompt-injection detection layer (spec 32).

This is the *behavioral* backstop behind the deterministic regex firewall
(`prompt_firewall.py`): a transformer classifier scores inbound text for
injection intent and catches the paraphrase/encoding/language variants the six
regex rules miss (measured empirically against the committed deepset corpus).

Non-negotiable contract — **detector, not gate** (spec 32 §2):
- The classifier emits a probabilistic ``injection_score`` in ``[0, 1]``.
- A *deterministic* threshold maps that score to a ``SemanticAction``.
- The action may only ever ESCALATE. A low semantic score can never unblock a
  deterministic quarantine. In the pipeline this is enforced structurally: the
  semantic layer only ever *appends* sanitization records / audit events, so it
  cannot remove the deterministic quarantine record that drives the block.
- The downstream deterministic guardrails (output policy, evidence validation,
  action safety, inert provider) remain authoritative and unchanged.

Disabled by default (``SEMANTIC_FIREWALL_ENABLED=false``) so the demo/CI posture
is byte-for-byte unchanged until the gated real-LLM work runs it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from threatprism.config import Settings


class SemanticAction(str, Enum):
    """Deterministic translation of a probabilistic score. Ordered by severity:
    ``pass_ < review < quarantine``."""

    pass_ = "pass"
    review = "review"
    quarantine = "quarantine"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {
    SemanticAction.pass_: 0,
    SemanticAction.review: 1,
    SemanticAction.quarantine: 2,
}


@dataclass(frozen=True)
class SemanticDecision:
    action: SemanticAction
    score: float
    model_id: str
    model_revision: str | None


@runtime_checkable
class SemanticScorer(Protocol):
    """Returns a calibrated injection probability in ``[0, 1]`` for ``text``.

    Implementations MUST be deterministic for a fixed model revision in eval
    mode (asserted by a test) and MUST NOT perform network egress.
    """

    def score_text(self, text: str) -> float: ...


def decide_action(
    score: float,
    *,
    review_threshold: float,
    quarantine_threshold: float,
) -> SemanticAction:
    """Pure, deterministic band mapping (spec 32 §2).

    ``score >= quarantine_threshold`` -> quarantine (fail-safe: blocks triage).
    ``review_threshold <= score < quarantine_threshold`` -> review (non-blocking
    manager-review signal).
    ``score < review_threshold`` -> pass.
    """

    if score >= quarantine_threshold:
        return SemanticAction.quarantine
    if score >= review_threshold:
        return SemanticAction.review
    return SemanticAction.pass_


class SemanticFirewall:
    """Wraps a deterministic policy around a probabilistic scorer."""

    def __init__(
        self,
        scorer: SemanticScorer,
        *,
        review_threshold: float,
        quarantine_threshold: float,
        model_id: str,
        model_revision: str | None,
    ) -> None:
        self._scorer = scorer
        self._review_threshold = review_threshold
        self._quarantine_threshold = quarantine_threshold
        self._model_id = model_id
        self._model_revision = model_revision

    def classify(self, text: str) -> SemanticDecision:
        if text is None or not text.strip():
            return SemanticDecision(SemanticAction.pass_, 0.0, self._model_id, self._model_revision)
        score = self._scorer.score_text(text)
        action = decide_action(
            score,
            review_threshold=self._review_threshold,
            quarantine_threshold=self._quarantine_threshold,
        )
        return SemanticDecision(action, score, self._model_id, self._model_revision)


class PromptGuardScorer:
    """Local Prompt Guard 2 encoder classifier (spec 32 §3).

    Loads ``meta-llama/Llama-Prompt-Guard-2-86M`` (or the configured fallback)
    once, in eval mode, from local files only — **no runtime auto-download and
    no network egress**. The model weights are a build/deploy artifact, not an
    intake-time fetch (consistent with the no-auto-download dataset rule).

    NOTE (spec 32 §3, §5): the exact label schema and inference call shape MUST
    be verified against the installed ``transformers`` version and the pinned
    model revision at build time. The model is gated on Hugging Face (Llama
    Community License) and is not present in this environment, so this loader is
    exercised only by the owner's live ``skipif`` test, never in CI. Treat the
    label-index assumption below as *requires verification*, not verified code.
    """

    # Prompt Guard 2 is a binary classifier; the malicious/injection class is
    # the positive label. Verify the index against the loaded model's
    # ``config.id2label`` at build time before any live use.
    _MALICIOUS_LABEL_HINTS = ("malicious", "injection", "label_1", "1")

    def __init__(self, model_id: str, model_revision: str | None) -> None:
        # Heavy import is local to construction so importing this module stays
        # cheap and the deterministic policy can be tested without torch/the model.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_id, revision=model_revision, local_files_only=True
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_id, revision=model_revision, local_files_only=True
        )
        self._model.eval()
        self._malicious_index = self._resolve_malicious_index()

    def _resolve_malicious_index(self) -> int:
        id2label = getattr(self._model.config, "id2label", {}) or {}
        for index, label in id2label.items():
            if str(label).strip().lower() in self._MALICIOUS_LABEL_HINTS:
                return int(index)
        # Binary classifier fallback: positive class is index 1.
        return 1 if self._model.config.num_labels > 1 else 0

    def score_text(self, text: str) -> float:
        torch = self._torch
        inputs = self._tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            logits = self._model(**inputs).logits
        probabilities = torch.softmax(logits, dim=-1)[0]
        return float(probabilities[self._malicious_index].item())


def build_semantic_firewall(
    settings: Settings,
    *,
    scorer: SemanticScorer | None = None,
) -> SemanticFirewall | None:
    """Construct the firewall, or ``None`` when disabled.

    ``None`` means the pipeline runs exactly as before (disabled-by-default
    invariant, spec 32 §8.7). A ``scorer`` may be injected for tests so the
    policy/merge/wiring can be validated without loading the gated model.
    """

    if not settings.semantic_firewall_enabled:
        return None
    active_scorer = scorer or PromptGuardScorer(
        settings.semantic_firewall_model_id,
        settings.semantic_firewall_model_revision or None,
    )
    return SemanticFirewall(
        active_scorer,
        review_threshold=settings.semantic_firewall_review_threshold,
        quarantine_threshold=settings.semantic_firewall_quarantine_threshold,
        model_id=settings.semantic_firewall_model_id,
        model_revision=settings.semantic_firewall_model_revision or None,
    )
