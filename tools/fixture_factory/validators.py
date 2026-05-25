from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from threatprism.cases.schemas import CaseCreate
from threatprism.guardrails.policy import enforce_action_safety, scan_output_policy

from tools.fixture_factory import REPO_ROOT
from tools.fixture_factory.models import DataSourceRegistry, ThreatPrismSyntheticFixture
from tools.fixture_factory.sanitizers import RAW_BODY_KEYS, TOKEN_VAULT_KEYS


INPUT_ROOT = "external_datasets"
OUTPUT_ROOT = "fixtures/generated"
INPUT_SUFFIXES = {".csv", ".json", ".jsonl"}
OUTPUT_SUFFIXES = {".jsonl"}

SECRET_PATTERN = re.compile(r"\bsk-(?!test|fake|demo|example)[A-Za-z0-9_-]{12,}\b", re.I)
RAW_PATIENT_PATTERN = re.compile(r"(?i)\b(?:patient id|mrn|medical record|encounter id)\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b")
TOKEN_PATTERN = re.compile(r"\[(?:POTENTIAL_PHI|POTENTIAL_PII|SECRET):[A-Z0-9_]+:[a-z]+_\d{4}\]")


def load_registry(path: Path | None = None) -> DataSourceRegistry:
    registry_path = path or REPO_ROOT / "data_sources" / "registry.json"
    return DataSourceRegistry.model_validate_json(registry_path.read_text(encoding="utf-8"))


def resolve_input_path(candidate: str | Path, *, repo_root: Path = REPO_ROOT, must_exist: bool = True) -> Path:
    resolved = _resolve_under(candidate, allowed_root=INPUT_ROOT, repo_root=repo_root, suffixes=INPUT_SUFFIXES)
    if must_exist and not resolved.exists():
        raise ValueError(f"Input path does not exist: {_relative_display(resolved, repo_root)}")
    return resolved


def resolve_output_path(
    candidate: str | Path,
    *,
    repo_root: Path = REPO_ROOT,
    force: bool = False,
) -> Path:
    resolved = _resolve_under(candidate, allowed_root=OUTPUT_ROOT, repo_root=repo_root, suffixes=OUTPUT_SUFFIXES)
    if resolved.exists() and not force:
        raise ValueError("Output path exists; pass --force to overwrite")
    return resolved


def validate_fixture_safety(fixture: ThreatPrismSyntheticFixture) -> ThreatPrismSyntheticFixture:
    if not fixture.synthetic_only:
        raise ValueError("Generated fixtures must be synthetic_only=true")
    if fixture.raw_source_retained:
        raise ValueError("Generated fixtures must set raw_source_retained=false")
    CaseCreate.model_validate(fixture.payload)
    serialized = json.dumps(fixture.model_dump(mode="json"), sort_keys=True)
    lower_serialized = serialized.lower()
    for forbidden_key in sorted(TOKEN_VAULT_KEYS | RAW_BODY_KEYS):
        if f'"{forbidden_key}"' in lower_serialized:
            raise ValueError(f"Fixture contains forbidden raw field: {forbidden_key}")
    if "vault_mappings" in lower_serialized or "token_vault" in lower_serialized:
        raise ValueError("Fixture contains token vault mapping metadata")
    if SECRET_PATTERN.search(serialized):
        raise ValueError("Fixture contains a live-looking secret")
    without_tokens = TOKEN_PATTERN.sub("[TOKEN]", serialized)
    if RAW_PATIENT_PATTERN.search(without_tokens):
        raise ValueError("Fixture contains raw healthcare-context identifier text")
    policy_issues = scan_output_policy(fixture.model_dump(mode="json"))
    action_issues = enforce_action_safety(fixture.model_dump(mode="json"))
    if policy_issues or action_issues:
        raise ValueError(f"Fixture violates output policy: {policy_issues + action_issues}")
    return fixture


def fixture_to_sorted_json(fixture: ThreatPrismSyntheticFixture) -> str:
    validate_fixture_safety(fixture)
    return json.dumps(fixture.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def ensure_deterministic_order(fixtures: list[ThreatPrismSyntheticFixture]) -> list[ThreatPrismSyntheticFixture]:
    return sorted(fixtures, key=lambda fixture: fixture.fixture_id)


def _resolve_under(candidate: str | Path, *, allowed_root: str, repo_root: Path, suffixes: set[str]) -> Path:
    raw = str(candidate).strip().replace("\\", "/")
    if not raw:
        raise ValueError("Path is required")
    if "\x00" in raw:
        raise ValueError("Path contains a null byte")
    windows_path = PureWindowsPath(raw)
    posix_path = PurePosixPath(raw)
    if windows_path.is_absolute() or windows_path.drive or posix_path.is_absolute():
        raise ValueError("Absolute paths are not allowed")
    parts = [part for part in posix_path.parts if part not in {"", "."}]
    allowed_parts = [part for part in PurePosixPath(allowed_root).parts if part not in {"", "."}]
    if not parts or parts[: len(allowed_parts)] != allowed_parts:
        raise ValueError(f"Path must be under {allowed_root}/")
    if any(part == ".." for part in parts):
        raise ValueError("Path traversal is not allowed")
    if posix_path.suffix and posix_path.suffix.lower() not in suffixes:
        raise ValueError(f"Unsafe file extension: {posix_path.suffix}")
    resolved = (repo_root / Path(*parts)).resolve()
    approved_root = (repo_root / allowed_root).resolve()
    if approved_root != resolved and approved_root not in resolved.parents:
        raise ValueError(f"Path must resolve under {allowed_root}/")
    return resolved


def _relative_display(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()
