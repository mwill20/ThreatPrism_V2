# Curated Adversarial / Ambiguous Fixtures (spec 37)

Hand-authored, **fully synthetic** SOC cases engineered to be *triage-ambiguous* —
each is built so that two competent, independent analysts (or models) could
reasonably reach different determinations, severities, or dispositions. Their job
is to **exercise disagreement detection** (`DisagreementRecord` →
`/queues/manager-review`) in the Evolution 2 backtest, which a too-clear-cut corpus
does not.

- **"Adversarial" means triage-ambiguous content, not adversarial input to the
  guardrails.** Prompt-injection / guardrail-evasion is a separate concern handled
  by the prompt firewall + semantic firewall + the sanitized injection fixtures.
- **No real data.** All hosts, accounts, tickets, and addresses are synthetic; IPs
  use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  and domains use `.test`. `tools/check_demo_safety.py` must pass.
- **Onboarding gate:** entries are listed in `manifest.json` and pass the same
  review gate as `fixtures/curated/` (safety/content review, no raw source, no
  downloads). Each line documents its `ambiguity_axis` and `intended_disagreement`
  (metadata only — the reader uses just `payload`).

Run the backtest over this set:

```bash
PYTHONPATH=src python -m threatprism.demo.backtest --dataset adversarial --json                    # deterministic
PYTHONPATH=src python -m threatprism.demo.backtest --live --dataset adversarial --json             # gated, paid (anchored analyst)
PYTHONPATH=src python -m threatprism.demo.backtest --live --dataset adversarial --blind-analyst --json  # blind analyst (case only, no report)
```

See `docs/specs/37_ADVERSARIAL_EVAL_DATASET.md`.
