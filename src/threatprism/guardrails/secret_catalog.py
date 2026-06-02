"""Single source of truth for secret-shaped detection patterns (spec 34 §3).

Every secret-shaped regex in the repo is defined here exactly once. Consumers
reference entries by name so product runtime detectors and the standalone
dev-workflow hook stay in sync under one quarterly refresh
(docs/runbooks/PATTERN_REFRESH.md):

- `guardrails/healthcare.py` — Stage-1 intake tokenization (`provider_token_prefix`
  as `api_key`, `password_in_config` as `password`).
- `guardrails/tokenization.py` — Stage-2 `secret_like` token (`provider_token_prefix`).
- `guardrails/policy.py` — output-policy scan (`provider_token_prefix`).
- `tools/hooks/_common.py` — the PreToolUse secret-block hook uses the full set.

The product runtime intentionally references a narrow subset (it tokenizes
*inbound* SOAR telemetry, where over-tokenization would destroy legitimate
security data); the dev-workflow hook uses the full set (it guards what the
assistant *writes to disk*, where a broad net is correct). Same catalog, different
named subsets — driven by two different threat models.

This module imports nothing from `threatprism`, so the standalone hook can load it
by file path without installing the package.

A pattern NAME is what gets logged on a block or output-policy violation — never
the matched secret value.
"""
from __future__ import annotations

import re

# (name, regex). Defined as source strings so the catalog is trivially auditable
# and serializable; each consumer compiles what it needs.
SECRET_PATTERN_SOURCES: list[tuple[str, str]] = [
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ("stripe_secret_key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ("anthropic_openai_key", r"\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}"),
    ("generic_sk_key", r"\bsk-[A-Za-z0-9]{32,}\b"),
    # Product runtime secret shape: healthcare `api_key`, tokenization
    # `secret_like`, and the policy output scan all reference this one entry.
    (
        "provider_token_prefix",
        r"\b(?:sk-[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|AIza[0-9A-Za-z_-]{12,})\b",
    ),
    (
        "db_connection_string",
        r"(?i)\b(?:postgres|postgresql|mysql|mongodb)(?:\+\w+)?://[^\s:@/]+:[^\s:@/]+@\S+",
    ),
    ("password_in_config", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{6,}"),
    (
        "api_key_assignment",
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
    ),
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(source)) for name, source in SECRET_PATTERN_SOURCES
]

_BY_NAME: dict[str, re.Pattern[str]] = {name: pattern for name, pattern in SECRET_PATTERNS}


def pattern_for(name: str) -> re.Pattern[str]:
    """Return the compiled pattern for a named catalog entry."""
    return _BY_NAME[name]


def scan(text: str) -> list[str]:
    """Return the sorted unique names of secret patterns that match `text`."""
    if not text:
        return []
    return sorted({name for name, pattern in SECRET_PATTERNS if pattern.search(text)})


def redact(text: str, max_len: int = 160) -> str:
    """Mask any secret-shaped spans, then collapse newlines and truncate."""
    masked = text
    for _name, pattern in SECRET_PATTERNS:
        masked = pattern.sub("[REDACTED_SECRET]", masked)
    return masked.replace("\n", " ")[:max_len]
