from __future__ import annotations

import json
import re
from typing import Any

from threatprism.guardrails.secret_catalog import pattern_for


PROHIBITED_PATTERNS = [
    re.compile(r"\b(I|we)\b.*\b(disabled|isolated|blocked|deleted|revoked|remediated)\b", re.I),
    re.compile(r"\b(real action executed|containment completed|remediation completed)\b", re.I),
    re.compile(r"\b(confirmed|certain|guaranteed) that\b", re.I),
    pattern_for("provider_token_prefix"),  # leaked-secret shape (shared catalog, spec 34 §3)
    re.compile(r"\bHIPAA[- ]?(?:compliant|compliance|certified|certification)\b", re.I),
    re.compile(r"\bHITRUST[- ]?(?:compliant|compliance|certified|certification)\b", re.I),
    re.compile(r"\b(?:control(?: is)? satisfied|satisfies (?:a )?control|case satisfies.*control)\b", re.I),
    re.compile(r"\b(?:audit[- ]?ready|certification[- ]?ready)\b", re.I),
    re.compile(r"\bevidence proves compliance\b", re.I),
    re.compile(r"\b(?:diagnose|treat|treatment plan|clinical recommendation)\b", re.I),
]


def scan_output_policy(value: Any) -> list[str]:
    text = json.dumps(value, ensure_ascii=False, default=str)
    violations: list[str] = []
    for pattern in PROHIBITED_PATTERNS:
        if pattern.search(text):
            violations.append(f"Prohibited output pattern detected: {pattern.pattern}")
    return violations


def enforce_action_safety(value: Any) -> list[str]:
    text = json.dumps(value, ensure_ascii=False, default=str)
    issues: list[str] = []
    if re.search(r'"real_action_executed"\s*:\s*true', text, re.I):
        issues.append("Real action execution is not allowed in V2.")
    return issues
