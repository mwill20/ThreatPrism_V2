from __future__ import annotations

from threatprism.guardrails.policy import PROHIBITED_PATTERNS, scan_output_policy


PROHIBITED_PATTERN_FIXTURES = {
    r"\b(I|we)\b.*\b(disabled|isolated|blocked|deleted|revoked|remediated)\b": "We disabled the account.",
    r"\b(real action executed|containment completed|remediation completed)\b": "Containment completed successfully.",
    r"\b(confirmed|certain|guaranteed) that\b": "Confirmed that this is malicious.",
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|AIza[0-9A-Za-z_-]{12,})\b": "The key was sk-testsecretvalue12345.",
    r"\bHIPAA[- ]?(?:compliant|compliance|certified|certification)\b": "This case is HIPAA compliant.",
    r"\bHITRUST[- ]?(?:compliant|compliance|certified|certification)\b": "This is HITRUST certified.",
    r"\b(?:control(?: is)? satisfied|satisfies (?:a )?control|case satisfies.*control)\b": "The control is satisfied.",
    r"\b(?:audit[- ]?ready|certification[- ]?ready)\b": "The package is audit-ready.",
    r"\bevidence proves compliance\b": "The evidence proves compliance.",
    r"\b(?:diagnose|treat|treatment plan|clinical recommendation)\b": "This is a clinical recommendation.",
}


def test_fixture_catalog_covers_every_prohibited_output_pattern() -> None:
    pattern_texts = {pattern.pattern for pattern in PROHIBITED_PATTERNS}

    assert set(PROHIBITED_PATTERN_FIXTURES) == pattern_texts


def test_every_prohibited_output_pattern_has_a_blocking_fixture() -> None:
    for pattern in PROHIBITED_PATTERNS:
        fixture = PROHIBITED_PATTERN_FIXTURES[pattern.pattern]

        violations = scan_output_policy({"summary": fixture})

        assert any(pattern.pattern in violation for violation in violations)
