"""Dataset-backed demo seeder.

Replays hand-reviewed curated fixtures through the real ``POST /cases`` intake
path so a fresh demo database can be populated with safe, deterministic cases.

The seeder is runtime-owned on purpose: it reads committed fixture *data* under
``fixtures/curated/`` directly and never imports the dev-time fixture factory
under ``tools/``. The architectural rule is one-directional -- dev tooling may
import the running app, but the running app must not depend on dev tooling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Protocol, Sequence, runtime_checkable

from pydantic import BaseModel, Field

from threatprism.cases.schemas import CaseCreate
from threatprism.cases.service import CaseService


CURATED_RELATIVE_ROOT = "fixtures/curated"
MANIFEST_FILENAME = "manifest.json"
DEMO_REVIEW_USE = "demo_review"
_SAFE_SAFETY_REVIEW = "approved_demo_safe"
_SAFE_CONTENT_REVIEW = "approved_for_tests"


class CuratedFixtureLoadError(RuntimeError):
    """Raised when a curated fixture fails safety, path, or schema validation."""


class SeedCase(BaseModel):
    """A single demo case derived from a curated fixture, ready for intake."""

    fixture_id: str
    source_case_id: str
    payload: dict[str, Any]


class SeedOutcome(BaseModel):
    fixture_id: str
    source_case_id: str
    status: Literal["seeded", "skipped_existing"]
    case_id: str | None = None


class SeedResult(BaseModel):
    seeded: list[SeedOutcome] = Field(default_factory=list)
    skipped: list[SeedOutcome] = Field(default_factory=list)

    @property
    def seeded_count(self) -> int:
        return len(self.seeded)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


@runtime_checkable
class FixtureSource(Protocol):
    """Extension seam for future demo data sources (e.g., a dataset ingest path).

    Implementations return fully-formed :class:`SeedCase` objects whose payloads
    have already passed any source-specific safety review. The seeder treats the
    returned payloads as trusted-to-replay but still runs them through the live
    guardrail pipeline at intake.
    """

    name: str

    def list_demo_fixtures(self) -> list[SeedCase]:
        ...


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


class CuratedFixtureSource:
    """Loads demo-review-approved fixtures from ``fixtures/curated/``."""

    name = "curated"

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self._repo_root = (repo_root or _default_repo_root()).resolve()
        self._curated_root = (self._repo_root / CURATED_RELATIVE_ROOT).resolve()

    def list_demo_fixtures(self) -> list[SeedCase]:
        manifest = self._load_manifest()
        seeds: list[SeedCase] = []
        for entry in manifest.get("fixtures", []):
            if not self._is_demo_seedable(entry):
                continue
            fixture_path = self._resolve_curated_path(str(entry.get("path", "")))
            seeds.extend(self._read_seed_cases(str(entry["fixture_id"]), fixture_path))
        seeds.sort(key=lambda seed: (seed.fixture_id, seed.source_case_id))
        return seeds

    def _load_manifest(self) -> dict[str, Any]:
        manifest_path = self._curated_root / MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise CuratedFixtureLoadError(f"Curated manifest not found at {CURATED_RELATIVE_ROOT}/{MANIFEST_FILENAME}.")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise CuratedFixtureLoadError("Curated manifest must be a JSON object.")
        return manifest

    @staticmethod
    def _is_demo_seedable(entry: dict[str, Any]) -> bool:
        allowed_uses = entry.get("allowed_uses", [])
        if not isinstance(allowed_uses, list) or DEMO_REVIEW_USE not in allowed_uses:
            return False
        if entry.get("safety_review_status") != _SAFE_SAFETY_REVIEW:
            return False
        if entry.get("content_review_status") != _SAFE_CONTENT_REVIEW:
            return False
        if entry.get("raw_source_committed") is True or entry.get("auto_downloaded") is True:
            return False
        return True

    def _resolve_curated_path(self, candidate: str) -> Path:
        normalized = candidate.replace("\\", "/")
        if not normalized:
            raise CuratedFixtureLoadError("Curated fixture entry is missing a path.")
        path = Path(normalized)
        if path.is_absolute() or path.drive or ".." in path.parts:
            raise CuratedFixtureLoadError(f"Unsafe curated fixture path rejected: {candidate}")
        if path.suffix.lower() != ".jsonl":
            raise CuratedFixtureLoadError(f"Curated fixtures must be .jsonl files: {candidate}")
        resolved = (self._repo_root / path).resolve()
        if not _is_within(resolved, self._curated_root):
            raise CuratedFixtureLoadError(f"Curated fixture path escapes {CURATED_RELATIVE_ROOT}: {candidate}")
        if not resolved.is_file():
            raise CuratedFixtureLoadError(f"Curated fixture file not found: {candidate}")
        return resolved

    @staticmethod
    def _read_seed_cases(fixture_id: str, fixture_path: Path) -> list[SeedCase]:
        seeds: list[SeedCase] = []
        for line_number, raw_line in enumerate(fixture_path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CuratedFixtureLoadError(
                    f"Malformed JSON in {fixture_id} line {line_number}: {exc}"
                ) from exc
            payload = record.get("payload")
            if not isinstance(payload, dict):
                raise CuratedFixtureLoadError(f"Fixture {fixture_id} line {line_number} has no object payload.")
            # Validate against the live intake schema; raises if the payload drifts.
            case = CaseCreate.model_validate(payload)
            seeds.append(
                SeedCase(
                    fixture_id=fixture_id,
                    source_case_id=case.source_case_id,
                    payload=payload,
                )
            )
        return seeds


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


class DemoSeeder:
    """Replays fixtures from one or more sources through the real intake path."""

    def __init__(self, service: CaseService) -> None:
        self._service = service

    def seed(
        self,
        sources: Sequence[FixtureSource],
        *,
        skip_existing: bool = True,
        run_triage: bool = True,
    ) -> SeedResult:
        existing = {summary.source_case_id for summary in self._service.list_cases()}
        result = SeedResult()
        for source in sources:
            for seed_case in source.list_demo_fixtures():
                if skip_existing and seed_case.source_case_id in existing:
                    result.skipped.append(
                        SeedOutcome(
                            fixture_id=seed_case.fixture_id,
                            source_case_id=seed_case.source_case_id,
                            status="skipped_existing",
                        )
                    )
                    continue
                accepted = self._service.create_case(seed_case.payload)
                if run_triage:
                    self._service.run_triage(accepted.case_id)
                existing.add(seed_case.source_case_id)
                result.seeded.append(
                    SeedOutcome(
                        fixture_id=seed_case.fixture_id,
                        source_case_id=seed_case.source_case_id,
                        status="seeded",
                        case_id=accepted.case_id,
                    )
                )
        return result
