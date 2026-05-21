from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


PROMPT_INJECTION_RULES = [
    ("ignore_previous", re.compile(r"ignore (all|any|previous|above) instructions", re.I), "quarantine"),
    ("system_prompt_request", re.compile(r"(system prompt|developer message|internal rules)", re.I), "quarantine"),
    ("role_override", re.compile(r"you are (an? )?(ai|assistant|chatgpt)|act as", re.I), "redact"),
    ("instruction_block", re.compile(r"(BEGIN|END) (SYSTEM|INSTRUCTION|PROMPT)", re.I), "redact"),
    ("tool_request", re.compile(r"(run|execute) (this )?(command|script)", re.I), "redact"),
    ("prompt_exfil", re.compile(r"(exfiltrate|leak).*(prompt|system)", re.I), "quarantine"),
]


@dataclass
class SanitizationResult:
    value: Any
    flags: list[str] = field(default_factory=list)
    sanitized_fields: list[str] = field(default_factory=list)
    quarantined: bool = False


def sanitize_text(text: str) -> tuple[str, list[str], bool]:
    sanitized = text
    flags: list[str] = []
    quarantined = False
    for name, pattern, action in PROMPT_INJECTION_RULES:
        if pattern.search(sanitized):
            flags.append(name)
            if action == "quarantine":
                quarantined = True
            sanitized = pattern.sub("[REDACTED_PROMPT_INJECTION]", sanitized)
    return sanitized, sorted(set(flags)), quarantined


def sanitize_value(value: Any, path: str = "") -> SanitizationResult:
    flags: list[str] = []
    fields: list[str] = []
    quarantined = False

    def walk(item: Any, item_path: str) -> Any:
        nonlocal quarantined
        if isinstance(item, dict):
            return {
                key: walk(entry, f"{item_path}.{key}" if item_path else key)
                for key, entry in item.items()
            }
        if isinstance(item, list):
            return [walk(entry, f"{item_path}[{idx}]") for idx, entry in enumerate(item)]
        if isinstance(item, str):
            sanitized_text, matched, local_quarantine = sanitize_text(item)
            if matched:
                flags.extend(matched)
                fields.append(item_path)
            if local_quarantine:
                quarantined = True
            return sanitized_text
        return item

    return SanitizationResult(
        value=walk(value, path),
        flags=sorted(set(flags)),
        sanitized_fields=fields,
        quarantined=quarantined,
    )
