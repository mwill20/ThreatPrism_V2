from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from threatprism.guardrails.healthcare import safeguard_value
from threatprism.guardrails.prompt_firewall import sanitize_value


TOKEN_VAULT_KEYS = {
    "token_vault",
    "token_vault_map",
    "token_vault_mapping",
    "token_vault_mappings",
    "vault_mapping",
    "vault_mappings",
}
RAW_BODY_KEYS = {
    "authorization",
    "cookie",
    "raw_authorization",
    "raw_body",
    "raw_payload",
    "raw_request",
    "set_cookie",
}

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?!(?:example|localhost)\b)(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
AUTH_HEADER_PATTERN = re.compile(r"(?i)\b(?:authorization|api[-_ ]?key|token)\s*[:=]\s*(?:bearer\s+)?[A-Za-z0-9._~+/=-]{8,}")
PASSWORD_PATTERN = re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{6,}")

DOCUMENTATION_IPS = ("192.0.2.10", "198.51.100.10", "203.0.113.10")
RESERVED_DOMAINS = ("example.org", "example.net", "example.com")


@dataclass(frozen=True)
class FixtureSanitizationResult:
    value: Any
    prompt_flags: list[str] = field(default_factory=list)
    prompt_quarantined: bool = False
    healthcare_summary: dict[str, Any] = field(default_factory=dict)
    replacements: dict[str, int] = field(default_factory=dict)
    removed_fields: list[str] = field(default_factory=list)


def sanitize_fixture_source(
    value: Any,
    *,
    case_id: str | None = None,
    apply_prompt_firewall: bool = True,
) -> FixtureSanitizationResult:
    stripped, removed_fields, replacements = _strip_forbidden_fields(value)
    if apply_prompt_firewall:
        prompt_result = sanitize_value(stripped)
        prompt_value, prompt_flags, prompt_quarantined = (
            prompt_result.value,
            prompt_result.flags,
            prompt_result.quarantined,
        )
    else:
        # Deliberate, source-scoped exception: the prompt firewall is NOT run over
        # the source text so attacker-controlled injection content survives intact
        # into the committed fixture. The point is to give the *runtime* firewall
        # live content to detect on replay (and to expose the rows it misses --
        # RR-L1). Credential stripping, healthcare safeguard, and infrastructure
        # normalization below still apply. Only approved third-party injection
        # corpora may use this path.
        prompt_value, prompt_flags, prompt_quarantined = stripped, [], False
    healthcare_result = safeguard_value(prompt_value, case_id=case_id)
    normalized, infra_counts = _normalize_infrastructure(healthcare_result.value)
    for key, count in infra_counts.items():
        replacements[key] = replacements.get(key, 0) + count
    return FixtureSanitizationResult(
        value=normalized,
        prompt_flags=prompt_flags,
        prompt_quarantined=prompt_quarantined,
        healthcare_summary=healthcare_result.summary,
        replacements={key: replacements[key] for key in sorted(replacements)},
        removed_fields=sorted(removed_fields),
    )


def _strip_forbidden_fields(value: Any, path: str = "") -> tuple[Any, list[str], dict[str, int]]:
    removed_fields: list[str] = []
    replacements: dict[str, int] = {}

    def walk(item: Any, item_path: str) -> Any:
        if isinstance(item, dict):
            cleaned: dict[str, Any] = {}
            for key, entry in item.items():
                key_text = str(key)
                key_lower = key_text.lower()
                child_path = f"{item_path}.{key_text}" if item_path else key_text
                if key_lower in TOKEN_VAULT_KEYS:
                    removed_fields.append(child_path)
                    replacements["token_vault_mapping_removed"] = replacements.get("token_vault_mapping_removed", 0) + 1
                    continue
                if key_lower in RAW_BODY_KEYS:
                    removed_fields.append(child_path)
                    replacements["raw_field_removed"] = replacements.get("raw_field_removed", 0) + 1
                    continue
                cleaned[key_text] = walk(entry, child_path)
            return cleaned
        if isinstance(item, list):
            return [walk(entry, f"{item_path}[{idx}]") for idx, entry in enumerate(item)]
        if isinstance(item, str):
            updated = AUTH_HEADER_PATTERN.sub("[REDACTED_CREDENTIAL]", item)
            updated = PASSWORD_PATTERN.sub("[REDACTED_CREDENTIAL]", updated)
            if updated != item:
                replacements["credential_redacted"] = replacements.get("credential_redacted", 0) + 1
            return updated
        return item

    return walk(value, path), removed_fields, replacements


def _normalize_infrastructure(value: Any) -> tuple[Any, dict[str, int]]:
    counts: dict[str, int] = {}

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: walk(entry) for key, entry in item.items()}
        if isinstance(item, list):
            return [walk(entry) for entry in item]
        if isinstance(item, str):
            updated = item
            updated_before_ip = updated
            updated = IP_PATTERN.sub(_replace_ip, updated)
            if updated != updated_before_ip:
                counts["ip_replaced"] = counts.get("ip_replaced", 0) + 1
            updated_before_domain = updated
            updated = _replace_domains(updated)
            if updated != updated_before_domain:
                counts["domain_replaced"] = counts.get("domain_replaced", 0) + 1
            updated_before_email = updated
            updated = EMAIL_PATTERN.sub("synthetic.user@example.org", updated)
            if updated != updated_before_email:
                counts["email_replaced"] = counts.get("email_replaced", 0) + 1
            return updated
        return item

    return walk(value), counts


def _replace_domains(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        start, end = match.span()
        previous_char = text[start - 1] if start > 0 else ""
        next_char = text[end] if end < len(text) else ""
        if previous_char == "@" or next_char == "@":
            return match.group(0)
        return _replace_domain(match)

    return DOMAIN_PATTERN.sub(replace, text)


def _replace_ip(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return DOCUMENTATION_IPS[0]
    if parsed in ipaddress.ip_network("192.0.2.0/24"):
        return value
    if parsed in ipaddress.ip_network("198.51.100.0/24"):
        return value
    if parsed in ipaddress.ip_network("203.0.113.0/24"):
        return value
    octets = [int(part) for part in value.split(".")]
    return DOCUMENTATION_IPS[sum(octets) % len(DOCUMENTATION_IPS)]


def _replace_domain(match: re.Match[str]) -> str:
    value = match.group(0)
    lowered = value.lower()
    if lowered.endswith((".example.com", ".example.net", ".example.org", ".example.invalid")):
        return value
    label_score = sum(ord(char) for char in lowered)
    return RESERVED_DOMAINS[label_score % len(RESERVED_DOMAINS)]
