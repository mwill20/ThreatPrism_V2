from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from threatprism.cases.schemas import SanitizationRecord
from threatprism.guardrails.secret_catalog import pattern_for


SensitiveClass = Literal["potential_phi", "potential_pii", "secret"]


HEALTH_CONTEXT_TERMS = {
    "appointment",
    "billing",
    "care",
    "chart",
    "claim",
    "claims",
    "clinical",
    "diagnosis",
    "dob",
    "encounter",
    "health",
    "lab",
    "medical",
    "member",
    "mrn",
    "patient",
    "portal",
    "radiology",
    "visit",
}


@dataclass(frozen=True)
class SensitiveRule:
    sensitive_class: SensitiveClass
    detector: str
    pattern: re.Pattern[str]
    confidence: float
    requires_context: bool = False


@dataclass
class HealthcareTokenVault:
    case_id: str | None = None
    counters: dict[str, int] = field(default_factory=dict)
    mappings: dict[tuple[str, str, str], str] = field(default_factory=dict)
    records: list[SanitizationRecord] = field(default_factory=list)

    def token_for(
        self,
        raw_value: str,
        sensitive_class: SensitiveClass,
        detector: str,
        field_path: str,
    ) -> str:
        key = (sensitive_class, detector, raw_value)
        if key in self.mappings:
            return self.mappings[key]

        prefix = {
            "potential_phi": "phi",
            "potential_pii": "pii",
            "secret": "secret",
        }[sensitive_class]
        next_index = self.counters.get(prefix, 0) + 1
        self.counters[prefix] = next_index
        token = f"[{_class_label(sensitive_class)}:{detector.upper()}:{prefix}_{next_index:04d}]"
        self.mappings[key] = token
        self.records.append(
            SanitizationRecord(
                case_id=self.case_id,
                operation="tokenize",
                field_path=field_path,
                token=token,
                token_type=f"{sensitive_class}:{detector}",
                raw_value_hash=f"sha256:{_sha256(raw_value)}",
                rehydration_allowed=False,
                metadata={
                    "sensitive_class": sensitive_class,
                    "detector": detector,
                    "confidence": _confidence_for(sensitive_class, detector),
                    "role_rehydration_allowed": {
                        "ai": False,
                        "analyst": False,
                        "engineer": False,
                        "manager_grc": False,
                        "legal_privacy": False,
                        "audit_debug": False,
                    },
                },
            )
        )
        return token


@dataclass(frozen=True)
class HealthcareScanResult:
    value: Any
    records: list[SanitizationRecord]
    summary: dict[str, Any]


# Detector regexes come from the shared catalog (spec 34 §3); the detector NAMES
# (`api_key`, `password`) are kept because they label the emitted Stage-1 tokens
# (e.g. `[SECRET:API_KEY:secret_0001]`) and `_confidence_for`.
SECRET_RULES = [
    SensitiveRule("secret", "api_key", pattern_for("provider_token_prefix"), 0.98),
    SensitiveRule("secret", "password", pattern_for("password_in_config"), 0.95),
]

PHI_RULES = [
    SensitiveRule(
        "potential_phi",
        "mrn",
        re.compile(r"(?i)\b(?:mrn|medical record(?: number)?)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.95,
    ),
    SensitiveRule(
        "potential_phi",
        "patient_id",
        re.compile(r"(?i)\b(?:patient id|patient_id|patient identifier|patient number)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.92,
    ),
    SensitiveRule(
        "potential_phi",
        "encounter_id",
        re.compile(r"(?i)\b(?:encounter id|encounter_id|encounter)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.92,
    ),
    SensitiveRule(
        "potential_phi",
        "member_id",
        re.compile(r"(?i)\b(?:member id|member_id|health plan id|plan member)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.9,
    ),
    SensitiveRule(
        "potential_phi",
        "claim_id",
        re.compile(r"(?i)\b(?:claim id|claim_id|claims id)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.9,
    ),
    SensitiveRule(
        "potential_phi",
        "appointment_id",
        re.compile(r"(?i)\b(?:appointment id|appointment_id|appt id)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b"),
        0.88,
    ),
    SensitiveRule(
        "potential_phi",
        "dob",
        re.compile(r"(?i)\b(?:dob|date of birth)\s*[:#=-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
        0.95,
    ),
    SensitiveRule(
        "potential_phi",
        "clinical_file_path",
        re.compile(r"(?i)(?:[A-Z]:\\|/|(?:[^\s<>\"|?*]+[\\/])+)[^\s<>\"|?*]*(?:patient|mrn|encounter|clinical|chart|lab|radiology)[^\s<>\"|?*]*(?:[\\/][^\s<>\"|?*]+)*"),
        0.88,
    ),
]

CONTEXT_IDENTIFIER_RULES = [
    SensitiveRule(
        "potential_phi",
        "context_email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.82,
        requires_context=True,
    ),
    SensitiveRule(
        "potential_phi",
        "context_ip",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.78,
        requires_context=True,
    ),
    SensitiveRule(
        "potential_phi",
        "context_url",
        re.compile(r"https?://[^\s\"'<>]+", re.I),
        0.8,
        requires_context=True,
    ),
]

PII_RULES = [
    SensitiveRule(
        "potential_pii",
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        0.95,
    ),
    SensitiveRule(
        "potential_pii",
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
        0.78,
    ),
    SensitiveRule(
        "potential_pii",
        "street_address",
        re.compile(r"(?i)\b\d{2,6}\s+[A-Za-z0-9 .'-]+\s+(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd)\b"),
        0.72,
    ),
]


def safeguard_value(value: Any, case_id: str | None = None) -> HealthcareScanResult:
    vault = HealthcareTokenVault(case_id=case_id)
    health_context_present = _value_has_health_context(value)
    sanitized = _scan_value(value, vault, "", health_context_present)
    summary = summarize_records(vault.records)
    return HealthcareScanResult(value=sanitized, records=vault.records, summary=summary)


def safeguard_text(
    text: str,
    field_path: str = "",
    case_id: str | None = None,
) -> HealthcareScanResult:
    vault = HealthcareTokenVault(case_id=case_id)
    sanitized = _scan_text(text, vault, field_path, _has_health_context(text))
    summary = summarize_records(vault.records)
    return HealthcareScanResult(value=sanitized, records=vault.records, summary=summary)


def summarize_records(records: list[SanitizationRecord]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    detectors: dict[str, int] = {}
    field_paths: list[str] = []
    for record in records:
        sensitive_class = str(record.metadata.get("sensitive_class", record.token_type or "unknown"))
        detector = str(record.metadata.get("detector", "unknown"))
        counts[sensitive_class] = counts.get(sensitive_class, 0) + 1
        detectors[detector] = detectors.get(detector, 0) + 1
        field_paths.append(record.field_path)
    return {
        "token_count": len(records),
        "counts": counts,
        "detectors": detectors,
        "field_paths": sorted(set(field_paths)),
        "potential_sensitive_data_exposure": counts.get("potential_phi", 0) > 0,
        "privacy_legal_review_required": counts.get("potential_phi", 0) > 0,
        "secret_exposure_detected": counts.get("secret", 0) > 0,
    }


def _scan_value(value: Any, vault: HealthcareTokenVault, path: str, health_context_present: bool) -> Any:
    if isinstance(value, dict):
        return {
            key: _scan_value(entry, vault, f"{path}.{key}" if path else str(key), health_context_present)
            for key, entry in value.items()
        }
    if isinstance(value, list):
        return [
            _scan_value(entry, vault, f"{path}[{idx}]", health_context_present)
            for idx, entry in enumerate(value)
        ]
    if isinstance(value, str):
        return _scan_text(value, vault, path, health_context_present)
    return value


def _scan_text(
    text: str,
    vault: HealthcareTokenVault,
    field_path: str,
    health_context_present: bool,
) -> str:
    sanitized = text
    for rule in SECRET_RULES:
        sanitized = _apply_rule(sanitized, vault, field_path, rule)
    for rule in PHI_RULES:
        sanitized = _apply_rule(sanitized, vault, field_path, rule)
    if health_context_present:
        for rule in CONTEXT_IDENTIFIER_RULES:
            sanitized = _apply_rule(sanitized, vault, field_path, rule)
    for rule in PII_RULES:
        sanitized = _apply_rule(sanitized, vault, field_path, rule)
    return sanitized


def _apply_rule(
    text: str,
    vault: HealthcareTokenVault,
    field_path: str,
    rule: SensitiveRule,
) -> str:
    return rule.pattern.sub(
        lambda match: vault.token_for(match.group(0), rule.sensitive_class, rule.detector, field_path),
        text,
    )


def _has_health_context(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in HEALTH_CONTEXT_TERMS)


def _value_has_health_context(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_value_has_health_context(entry) for entry in value.values())
    if isinstance(value, list):
        return any(_value_has_health_context(entry) for entry in value)
    if isinstance(value, str):
        return _has_health_context(value)
    return False


def _class_label(sensitive_class: SensitiveClass) -> str:
    return {
        "potential_phi": "POTENTIAL_PHI",
        "potential_pii": "POTENTIAL_PII",
        "secret": "SECRET",
    }[sensitive_class]


def _confidence_for(sensitive_class: SensitiveClass, detector: str) -> float:
    for rule in [*SECRET_RULES, *PHI_RULES, *CONTEXT_IDENTIFIER_RULES, *PII_RULES]:
        if rule.sensitive_class == sensitive_class and rule.detector == detector:
            return rule.confidence
    return 0.5


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
