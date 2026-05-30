"""Dev-time adapter: OTRF Security-Datasets -> ThreatPrism SOC-telemetry fixtures.

The OTRF/Security-Datasets corpus is **MIT-licensed lab telemetry** (Windows
Sysmon/Security event logs from simulated adversary techniques), not generated
synthetic data like Synthea. The raw events therefore carry realistic
identifiers -- lab hostnames (``WORKSTATION5.theshire.local``), collector hosts
(``wec.internal.cloudapp.net``), Windows SIDs (``S-1-5-21-...``), account names,
domains, and ports. Those identifier shapes are exactly what this project's
hard rule forbids in committed fixtures, so this adapter is deliberately
aggressive:

1. A fail-closed ``SAFE_FIELDS`` allowlist keeps only non-identifying analytical
   fields (EventID, Channel, SourceName, Category, Severity, Task, RuleName,
   Opcode, EventType, tags, and the EventTime/UtcTime timestamps). Every
   identifying field -- host, Hostname, UserID,
   AccountName, Domain, port, *Guid, ProcessID, ThreadID, RecordNumber,
   TargetObject (which embeds a SID in the registry path) -- is dropped before
   the row enters the sanitization pipeline.
2. ``Image`` is reduced to its **basename** (e.g. ``powershell.exe``), which
   structurally discards any ``C:\\Users\\<name>\\`` profile path.
3. SID and user-profile-path scrubbers run as defense-in-depth over the kept
   values, before the shared sanitizer (IP/domain/email/credential +
   healthcare + prompt firewall) runs as a second pass.

The committed derivative is a sanitized ThreatPrism-native SOC case payload; no
raw OTRF row is retained. The MIT license requires retaining the copyright
notice -- provenance/attribution is recorded in the manifest entry and
``docs/DATASET.md``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.fixture_factory.adapters.shared import (
    case_payload,
    default_role_visibility,
    guardrail,
    source_metadata,
    stable_fixture_id,
)
from tools.fixture_factory.models import SyntheticSOARCaseFixture
from tools.fixture_factory.sanitizers import sanitize_fixture_source
from tools.fixture_factory.validators import validate_fixture_safety


SOURCE_ID = "otrf_security_datasets"
SOURCE_FAMILY = "otrf"
ADAPTER_NAME = "otrf_adapter"

# Fail-closed allowlist: only non-identifying analytical fields survive. Anything
# not listed here (host, Hostname, UserID, AccountName, Domain, port, *Guid,
# TargetObject, RecordNumber, ...) is dropped before sanitization.
SAFE_FIELDS = frozenset(
    {
        "EventID",
        "Channel",
        "SourceName",
        "Category",
        "Severity",
        "Task",
        "RuleName",
        "Opcode",
        "EventType",
        "EventTypeOrignal",
        "tags",
        # Timestamps are not identifiers; retained for SOC timeline realism.
        "EventTime",
        "UtcTime",
    }
)

SID_PATTERN = re.compile(r"S-1-5(?:-\d+){1,}", re.I)
USER_PATH_PATTERN = re.compile(r"(?i)([A-Za-z]:\\Users\\)[^\\\"]+")
SAFE_PROCESS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,60}$")

# Filename keyword -> (MITRE technique id, human label) for case framing only.
_TECHNIQUE_HINTS = (
    ("lsass", "T1003.001", "LSASS memory credential access"),
    ("sam", "T1003.002", "SAM credential access"),
    ("mimikatz", "T1003", "OS credential dumping"),
    ("netrserver", "T1210", "remote service exploitation"),
    ("dll_hijack", "T1574.001", "DLL search-order hijack"),
    ("empire", "T1059.001", "PowerShell adversary tooling"),
)


def _technique_for(source_file: Path) -> tuple[str, str]:
    name = source_file.name.lower()
    for keyword, technique, label in _TECHNIQUE_HINTS:
        if keyword in name:
            return technique, label
    return "T1059", "command and scripting interpreter activity"


def _scrub_identifiers(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _scrub_identifiers(entry) for key, entry in value.items()}
    if isinstance(value, list):
        return [_scrub_identifiers(entry) for entry in value]
    if isinstance(value, str):
        scrubbed = SID_PATTERN.sub("[REDACTED_SID]", value)
        scrubbed = USER_PATH_PATTERN.sub(r"\1[REDACTED_USER]", scrubbed)
        return scrubbed
    return value


def _process_basename(image: Any) -> str | None:
    if not isinstance(image, str) or not image:
        return None
    basename = re.split(r"[\\/]", image)[-1].strip()
    if basename and SAFE_PROCESS_NAME.fullmatch(basename):
        return basename
    return None


def _project_safe(row: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {key: row[key] for key in row if key in SAFE_FIELDS}
    return _scrub_identifiers(projected)


def _read_event_rows(input_path: Path, limit: int) -> list[tuple[Path, int, dict[str, Any]]]:
    """Stream OTRF JSON-Lines files, deduped by EventID, without loading 43 MB whole."""
    if limit <= 0:
        raise ValueError("--limit must be greater than zero")
    files = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.json"))
    rows: list[tuple[Path, int, dict[str, Any]]] = []
    seen_event_ids: set[Any] = set()
    for source_file in files:
        with source_file.open("r", encoding="utf-8") as handle:
            for record_index, line in enumerate(handle):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                event_id = record.get("EventID")
                if event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event_id)
                rows.append((source_file, record_index, record))
                if len(rows) >= limit:
                    return rows
    return rows


def convert(input_path: Path, limit: int) -> list[SyntheticSOARCaseFixture]:
    rows = _read_event_rows(input_path, limit)
    input_root = input_path if input_path.is_dir() else input_path.parent
    fixtures: list[SyntheticSOARCaseFixture] = []
    for idx, (source_file, record_index, row) in enumerate(rows):
        fixture_id = stable_fixture_id("otrf_soc_telemetry", idx)
        technique, technique_label = _technique_for(source_file)
        sanitized = sanitize_fixture_source(_project_safe(row), case_id=fixture_id)
        # ProcessName is an already-safe basename (SID/user-path scrubbed, charset
        # validated). It is attached AFTER sanitization so the domain normalizer
        # does not mistake e.g. "powershell.exe" for a network domain.
        safe_event = dict(sanitized.value)
        process_name = _process_basename(row.get("Image"))
        if process_name:
            safe_event["ProcessName"] = process_name
        payload = _build_payload(fixture_id, safe_event, technique, technique_label)
        fixture = SyntheticSOARCaseFixture(
            fixture_id=fixture_id,
            source_family=SOURCE_FAMILY,
            source_reference=SOURCE_ID,
            source_metadata=source_metadata(
                input_root=input_root,
                source_file=source_file,
                record_index=record_index,
                source_id=SOURCE_ID,
                adapter=ADAPTER_NAME,
                sanitized_row=sanitized.value,
            ),
            payload=payload,
            expected_result={
                "review_required": True,
                "manager_review_required": True,
                "mitre_technique": technique,
            },
            expected_guardrails=[
                guardrail(
                    "healthcare_safeguard",
                    "pass",
                    "SOC telemetry carries no healthcare context after the SAFE_FIELDS projection.",
                ),
                guardrail(
                    "role_visibility",
                    "review_required",
                    "Manager, GRC, legal, and audit views receive safe summaries only.",
                ),
            ],
            expected_role_visibility=default_role_visibility(),
            expected_evidence_ids=[f"ev_{fixture_id}_001"],
            notes=(
                "SOC-telemetry fixture derived from MIT-licensed OTRF Security-Datasets lab "
                "events. Identifying fields (host, SID, account, domain, port) are dropped by a "
                "fail-closed SAFE_FIELDS allowlist; only non-identifying analytical fields survive."
            ),
        )
        validate_fixture_safety(fixture)
        fixtures.append(fixture)
    return fixtures


def _build_payload(
    fixture_id: str,
    row: dict[str, Any],
    technique: str,
    technique_label: str,
) -> dict[str, Any]:
    title = "Adversary technique telemetry review"
    description = (
        f"Sanitized SOC telemetry sample illustrating {technique_label} ({technique}); "
        "analyst and manager review required."
    )
    evidence_summary = "Reviewed OTRF lab event projected to non-identifying analytical fields."
    return case_payload(
        fixture_id=fixture_id,
        title=title,
        description=description,
        evidence_summary=evidence_summary,
        evidence_excerpt=json.dumps(row, sort_keys=True)[:300],
        normalized={"source_event": row, "fixture_type": "soc_telemetry"},
        source_family=SOURCE_FAMILY,
        manager_review_required=True,
        mitre_technique=technique,
    )
