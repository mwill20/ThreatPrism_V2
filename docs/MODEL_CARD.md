# Model And Provider Card

ThreatPrism currently does not use a live, hosted, trained, or fine-tuned model.
The implemented provider is deterministic demo logic for local validation and
repeatable tests.

## Current Provider

| Field | Current Status |
|---|---|
| Provider | `deterministic_demo` |
| Location | `src/threatprism/llm/providers.py` |
| External network calls | None |
| API keys required | None |
| Training or fine-tuning | None |
| Live LLM evaluation | Not performed |
| Intended use | Deterministic local triage behavior for fake demos and tests |
| Out-of-scope use | Production analysis, live incident response, compliance determinations |

## Safety Boundary

Even though the current provider is deterministic, ThreatPrism treats provider
output as untrusted. Output must pass:

- schema validation
- output policy scanning
- evidence-grounding checks
- action-safety checks
- role-aware rendering and authorization checks before display

CSI/RGOI also treats AI-authored cognition as non-authoritative unless a human
approval path approves it. The current CSI/RGOI slice does not call a live
model, write memory, mutate trust, publish suppressions, or run RAG.

## Future Live Providers

Future live LLM provider work must be explicitly approved and must re-open the
relevant threat-model treatments. It must not bypass tokenization, prompt
firewall checks, policy scanning, evidence grounding, action safety, or
controlled role-view rendering.
