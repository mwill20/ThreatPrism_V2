from __future__ import annotations

import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from tools.fixture_factory import REPO_ROOT
from tools.fixture_factory.models import ThreatPrismSyntheticFixture
from tools.fixture_factory.validators import validate_fixture_safety


CURATED_ROOT = "fixtures/curated"
MANIFEST_PATH = f"{CURATED_ROOT}/manifest.json"
ALLOWED_LICENSE_REVIEW_STATUSES = {"not_third_party_local_fake"}
ALLOWED_SAFETY_REVIEW_STATUSES = {"approved_demo_safe"}
ALLOWED_CONTENT_REVIEW_STATUSES = {"approved_for_tests"}


def load_curated_manifest(*, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    manifest_path = (repo_root / MANIFEST_PATH).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_curated_manifest(manifest, repo_root=repo_root)
    return manifest


def load_curated_fixtures(*, repo_root: Path = REPO_ROOT) -> list[ThreatPrismSyntheticFixture]:
    manifest = load_curated_manifest(repo_root=repo_root)
    fixtures: list[ThreatPrismSyntheticFixture] = []
    for entry in manifest["fixtures"]:
        fixture_path = resolve_curated_fixture_path(entry["path"], repo_root=repo_root)
        for line_number, line in enumerate(fixture_path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                fixture = ThreatPrismSyntheticFixture.model_validate_json(stripped)
            except Exception as exc:  # noqa: BLE001
                raise ValueError(
                    f"Curated fixture {fixture_path.name}:{line_number} is not schema-valid: {exc}"
                ) from exc
            validate_fixture_safety(fixture)
            fixtures.append(fixture)
    return sorted(fixtures, key=lambda fixture: fixture.fixture_id)


def validate_curated_manifest(manifest: dict[str, Any], *, repo_root: Path = REPO_ROOT) -> None:
    if manifest.get("manifest_version") != "curated-fixtures/0.1":
        raise ValueError("Unsupported curated fixture manifest version")
    if manifest.get("generated_fixture_auto_scan") is not False:
        raise ValueError("Curated fixture manifest must keep generated fixture auto-scan disabled")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("Curated fixture manifest must list at least one fixture")

    seen_ids: set[str] = set()
    for entry in fixtures:
        if not isinstance(entry, dict):
            raise ValueError("Curated fixture manifest entries must be objects")
        fixture_id = str(entry.get("fixture_id", ""))
        if not fixture_id:
            raise ValueError("Curated fixture manifest entries require fixture_id")
        if fixture_id in seen_ids:
            raise ValueError(f"Duplicate curated fixture id: {fixture_id}")
        seen_ids.add(fixture_id)
        resolve_curated_fixture_path(str(entry.get("path", "")), repo_root=repo_root)
        if entry.get("license_review_status") not in ALLOWED_LICENSE_REVIEW_STATUSES:
            raise ValueError(f"Curated fixture {fixture_id} lacks an approved license review status")
        if entry.get("safety_review_status") not in ALLOWED_SAFETY_REVIEW_STATUSES:
            raise ValueError(f"Curated fixture {fixture_id} lacks an approved safety review status")
        if entry.get("content_review_status") not in ALLOWED_CONTENT_REVIEW_STATUSES:
            raise ValueError(f"Curated fixture {fixture_id} lacks an approved content review status")
        if entry.get("raw_source_committed") is not False:
            raise ValueError(f"Curated fixture {fixture_id} must not commit raw source material")
        if entry.get("auto_downloaded") is not False:
            raise ValueError(f"Curated fixture {fixture_id} must not come from an auto-download")


def resolve_curated_fixture_path(candidate: str | Path, *, repo_root: Path = REPO_ROOT) -> Path:
    raw = str(candidate).strip().replace("\\", "/")
    if not raw:
        raise ValueError("Curated fixture path is required")
    if "\x00" in raw:
        raise ValueError("Curated fixture path contains a null byte")
    windows_path = PureWindowsPath(raw)
    posix_path = PurePosixPath(raw)
    if windows_path.is_absolute() or windows_path.drive or posix_path.is_absolute():
        raise ValueError("Curated fixture paths must be relative")
    parts = [part for part in posix_path.parts if part not in {"", "."}]
    curated_parts = [part for part in PurePosixPath(CURATED_ROOT).parts if part not in {"", "."}]
    if not parts or parts[: len(curated_parts)] != curated_parts:
        raise ValueError(f"Curated fixture paths must be under {CURATED_ROOT}/")
    if any(part == ".." for part in parts):
        raise ValueError("Curated fixture path traversal is not allowed")
    if posix_path.suffix.lower() != ".jsonl":
        raise ValueError("Curated fixtures must use .jsonl files")
    resolved = (repo_root / Path(*parts)).resolve()
    approved_root = (repo_root / CURATED_ROOT).resolve()
    if approved_root != resolved and approved_root not in resolved.parents:
        raise ValueError(f"Curated fixture paths must resolve under {CURATED_ROOT}/")
    return resolved
