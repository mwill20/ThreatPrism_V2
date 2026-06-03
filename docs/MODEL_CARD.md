# Model And Provider Card

**Default provider is deterministic** (`deterministic_demo`) so tests, CI, and demos run
offline with no keys. The **real-LLM gate is open** (owner-authorized 2026-06-01): under
explicit `--live` configuration, real models run and have been live-validated. No live
provider is ever used during standard validation.

## Providers

| Provider | Role | Status | Network | Keys |
|----------|------|--------|---------|------|
| `deterministic_demo` (`llm/providers.py`) | Triage (default) | Active default | None | None |
| `anthropic_claude` (`ClaudeTriageProvider`) | Triage (real) | **Gate open**, runs only under `--live` | Anthropic API | `ANTHROPIC_API_KEY` |
| OpenAI `MockAnalyst` (`llm/mock_analyst.py`) | Independent analyst (Evolution 2) | **Gate open**, runs only under `--live` | OpenAI API | `OPENAI_API_KEY` |
| `Llama-Prompt-Guard-2-86M` (`guardrails/semantic_firewall.py`) | Prompt-injection detector | Built, default-off, local-only (no egress) | None (local cache) | None |

Training or fine-tuning: **none** (no fine-tuning pipeline exists — gated).

## Live evaluation performed

The real providers have been exercised on synthetic data under governed spend caps
(whole investigation arc ~$0.49):

- Two-model backtest (real Claude triage vs. independent OpenAI analyst) on curated +
  adversarial sets; a true-**blind** analyst showed real determination divergence
  (anchoring shown material). See [LIVE_BACKTEST_FINDINGS.md](LIVE_BACKTEST_FINDINGS.md).
- Single-event live co-pilot run (Evolution 3): real Claude rated an injection fixture
  `suspicious/0.95` where the demo stub said `benign`.

Spend is metered with a fail-closed per-run cap; every real call emits a sanitized
`llm_call` audit (token counts + content **hashes**, never raw text).

## Safety boundary

Provider output (deterministic or real) is treated as **untrusted** and must pass:

- schema validation, output policy scanning, evidence-grounding checks, action-safety
  checks, and role-aware rendering/authorization before display;
- any validation failure becomes a structured `TriageFailureReport` (fail closed) and is
  recorded in the tamper-evident failure log.

CSI/RGOI treats AI-authored cognition as **non-authoritative**. As of 2026-06-03 a
governed, demo-only **write-back loop** exists (`csi/learning_loop.py`): the AI may
propose knowledge, but only a human may promote it (deterministic gate, reverse-deny,
Stage-1 tokenization, audited). Retrieval-into-triage (feeding cognition to the model) is
**built but not wired** and remains gated (OT-L1). No live RAG, no autonomous memory
writes, no trust mutation, no suppression publication.

## Future live providers

Wiring retrieval into the triage prompt, productionizing write-back (persistence, HTTP
write routes, multi-tenancy), fine-tuning, and external research providers (e.g., Exa.ai)
all remain gated and require re-opening the relevant threat-model treatments in
[spec 21](specs/21_THREAT_MODEL_TREATMENT_AND_RISK_REGISTER.md). None may bypass
tokenization, prompt-firewall checks, policy scanning, evidence grounding, action safety,
or role-view rendering.
