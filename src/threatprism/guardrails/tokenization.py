from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from threatprism.cases.schemas import SanitizationRecord
from threatprism.guardrails.secret_catalog import pattern_for


TOKEN_PATTERNS = [
    ("secret_like", pattern_for("provider_token_prefix")),
    ("url", re.compile(r"https?://[^\s\"'<>]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("file_hash", re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
]

REHYDRATABLE_TYPES = {"email", "ip", "url", "host", "domain", "user", "file_hash"}


@dataclass
class TokenVault:
    case_id: str | None = None
    mappings: dict[str, tuple[str, str]] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    records: list[SanitizationRecord] = field(default_factory=list)

    def token_for(self, raw_value: str, token_type: str, field_path: str, evidence_id: str | None = None) -> str:
        for token, (existing_raw, existing_type) in self.mappings.items():
            if existing_raw == raw_value and existing_type == token_type:
                return token

        next_index = self.counters.get(token_type, 0) + 1
        self.counters[token_type] = next_index
        token = f"tp_{token_type}_{next_index:03d}"
        self.mappings[token] = (raw_value, token_type)
        self.records.append(
            SanitizationRecord(
                case_id=self.case_id,
                evidence_id=evidence_id,
                operation="tokenize",
                field_path=field_path,
                token=token,
                token_type=token_type,
                raw_value_hash=f"sha256:{_sha256(raw_value)}",
                rehydration_allowed=token_type in REHYDRATABLE_TYPES,
            )
        )
        return token

    def display_value(self, token: str) -> str:
        raw_value, token_type = self.mappings[token]
        if token_type == "secret_like":
            return "[REDACTED_SECRET]"
        if token_type == "email":
            return raw_value
        if token_type == "ip":
            return raw_value
        if token_type == "url":
            return raw_value
        if token_type == "file_hash":
            return raw_value[:8] + "..." + raw_value[-6:]
        return raw_value


def tokenize_text(
    text: str,
    vault: TokenVault,
    field_path: str,
    evidence_id: str | None = None,
) -> str:
    tokenized = text
    for token_type, pattern in TOKEN_PATTERNS:
        tokenized = pattern.sub(
            lambda match: vault.token_for(match.group(0), token_type, field_path, evidence_id),
            tokenized,
        )
    return tokenized


def tokenize_value(
    value: Any,
    vault: TokenVault,
    path: str = "",
    evidence_id: str | None = None,
) -> Any:
    if isinstance(value, dict):
        return {
            key: tokenize_value(entry, vault, f"{path}.{key}" if path else key, evidence_id)
            for key, entry in value.items()
        }
    if isinstance(value, list):
        return [tokenize_value(entry, vault, f"{path}[{idx}]", evidence_id) for idx, entry in enumerate(value)]
    if isinstance(value, str):
        return tokenize_text(value, vault, path, evidence_id)
    return value


def rehydrate_text(text: str, vault: TokenVault) -> str:
    rehydrated = text
    for token in sorted(vault.mappings, key=len, reverse=True):
        rehydrated = rehydrated.replace(token, vault.display_value(token))
    return rehydrated


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
