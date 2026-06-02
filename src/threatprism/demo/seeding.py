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
ADVERSARIAL_RELATIVE_ROOT = "fixtures/curated_adversarial"
DATASET_RELATIVE_ROOT = "fixtures/curated_datasets"
LOCAL_DATASET_RELATIVE_ROOT = "external_datasets"
DATASET_MANIFEST_VERSION = "curated-datasets/0.1"
MANIFEST_FILENAME = "manifest.json"
DEMO_REVIEW_USE = "demo_review"
_SAFE_SAFETY_REVIEW = "approved_demo_safe"
_SAFE_CONTENT_REVIEW = "approved_for_tests"

# Authoritative allowlist of accepted license-review statuses for committed
# third-party derivatives. This lives in code -- not in the manifest -- so a
# tampered manifest cannot self-certify a license it was never granted.
#   - approved_third_party_apache2_synthetic: Synthea (healthcare), deepset
#     (prompt injection). Apache-2.0, generated-synthetic source material.
#   - approved_third_party_mit_lab_telemetry: OTRF Security-Datasets (SOC
#     telemetry). MIT-licensed lab event logs; identifying fields are dropped by
#     a fail-closed SAFE_FIELDS projection before the committed derivative.
DATASET_ALLOWED_LICENSE_REVIEW = frozenset(
    {
        "approved_third_party_apache2_synthetic",
        "approved_third_party_mit_lab_telemetry",
    }
)


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


class AdversarialCuratedSource(CuratedFixtureSource):
    """Hand-authored, fully synthetic triage-AMBIGUOUS SOC cases (spec 37).

    Same review/path-safety/manifest contract as the curated source, but rooted at
    ``fixtures/curated_adversarial/`` so it does not disturb the default curated set.
    These cases are engineered to produce reasonable disagreement, exercising the
    backtest's `DisagreementRecord` → manager-review path.
    """

    name = "adversarial"

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self._repo_root = (repo_root or _default_repo_root()).resolve()
        self._curated_root = (self._repo_root / ADVERSARIAL_RELATIVE_ROOT).resolve()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


class CuratedDatasetSource:
    """Loads demo-review-approved derivatives of reviewed third-party synthetic datasets.

    This is a parallel contract to :class:`CuratedFixtureSource`. It reads
    ``fixtures/curated_datasets/`` and additionally requires an approved
    third-party ``license_review_status`` (see ``DATASET_ALLOWED_LICENSE_REVIEW``).
    The hand-authored curated contract deliberately rejects third-party licenses,
    so committed synthetic derivatives onboard here instead.
    """

    name = "curated_datasets"

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self._repo_root = (repo_root or _default_repo_root()).resolve()
        self._dataset_root = (self._repo_root / DATASET_RELATIVE_ROOT).resolve()

    def list_demo_fixtures(self) -> list[SeedCase]:
        manifest = self._load_manifest()
        seeds: list[SeedCase] = []
        for entry in manifest.get("fixtures", []):
            if not self._is_dataset_seedable(entry):
                continue
            fixture_path = self._resolve_dataset_path(str(entry.get("path", "")))
            seeds.extend(
                CuratedFixtureSource._read_seed_cases(str(entry["fixture_id"]), fixture_path)
            )
        seeds.sort(key=lambda seed: (seed.fixture_id, seed.source_case_id))
        return seeds

    def _load_manifest(self) -> dict[str, Any]:
        manifest_path = self._dataset_root / MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise CuratedFixtureLoadError(
                f"Dataset manifest not found at {DATASET_RELATIVE_ROOT}/{MANIFEST_FILENAME}."
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise CuratedFixtureLoadError("Dataset manifest must be a JSON object.")
        if manifest.get("manifest_version") != DATASET_MANIFEST_VERSION:
            raise CuratedFixtureLoadError(
                f"Dataset manifest must declare manifest_version {DATASET_MANIFEST_VERSION!r}."
            )
        return manifest

    @staticmethod
    def _is_dataset_seedable(entry: dict[str, Any]) -> bool:
        if not CuratedFixtureSource._is_demo_seedable(entry):
            return False
        return entry.get("license_review_status") in DATASET_ALLOWED_LICENSE_REVIEW

    def _resolve_dataset_path(self, candidate: str) -> Path:
        normalized = candidate.replace("\\", "/")
        if not normalized:
            raise CuratedFixtureLoadError("Dataset fixture entry is missing a path.")
        path = Path(normalized)
        if path.is_absolute() or path.drive or ".." in path.parts:
            raise CuratedFixtureLoadError(f"Unsafe dataset fixture path rejected: {candidate}")
        if path.suffix.lower() != ".jsonl":
            raise CuratedFixtureLoadError(f"Dataset fixtures must be .jsonl files: {candidate}")
        resolved = (self._repo_root / path).resolve()
        if not _is_within(resolved, self._dataset_root):
            raise CuratedFixtureLoadError(
                f"Dataset fixture path escapes {DATASET_RELATIVE_ROOT}: {candidate}"
            )
        if not resolved.is_file():
            raise CuratedFixtureLoadError(f"Dataset fixture file not found: {candidate}")
        return resolved


class LocalDatasetSource:
    """Replays uncommitted, gitignored ``.jsonl`` staging files under ``external_datasets/``.

    This is the local developer loop. A reviewed projection produced by the
    dev-time fixture factory can be dropped under ``external_datasets/`` and
    replayed through the real intake path **without committing or promoting it**
    (``external_datasets/**`` is gitignored). It is intentionally OFF by default:
    it is never part of the startup seed hook, never part of ``--source all``,
    and must be selected explicitly with ``--source local``. It only ever reads
    -- it writes and commits nothing.

    Unlike the curated/dataset sources there is no manifest and no license gate
    here: this is unreviewed local-only data, which is exactly why it must never
    activate implicitly and is refused in production environments by the CLI.
    """

    name = "local"

    def __init__(self, *, repo_root: Path | None = None, limit: int | None = None) -> None:
        self._repo_root = (repo_root or _default_repo_root()).resolve()
        self._local_root = (self._repo_root / LOCAL_DATASET_RELATIVE_ROOT).resolve()
        if limit is not None and limit <= 0:
            raise CuratedFixtureLoadError("Local dataset limit must be greater than zero.")
        self._limit = limit

    def list_demo_fixtures(self) -> list[SeedCase]:
        if not self._local_root.is_dir():
            return []
        seeds: list[SeedCase] = []
        for fixture_path in sorted(self._local_root.rglob("*.jsonl")):
            resolved = fixture_path.resolve()
            # Defense-in-depth against symlinks resolving outside the sandbox.
            if not resolved.is_file() or not _is_within(resolved, self._local_root):
                continue
            relative = resolved.relative_to(self._local_root).with_suffix("")
            fixture_id = "local/" + str(relative).replace("\\", "/")
            seeds.extend(CuratedFixtureSource._read_seed_cases(fixture_id, resolved))
        seeds.sort(key=lambda seed: (seed.fixture_id, seed.source_case_id))
        if self._limit is not None:
            seeds = seeds[: self._limit]
        return seeds


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
        limit: int | None = None,
    ) -> SeedResult:
        """Replay fixtures through real intake + triage. ``limit`` caps the number
        of NEW cases seeded — and therefore the number of (paid, in live mode)
        triage calls — enabling a cost-minimal smoke run."""
        if limit is not None and limit <= 0:
            raise ValueError("seed limit must be greater than zero.")
        existing = {summary.source_case_id for summary in self._service.list_cases()}
        result = SeedResult()
        for source in sources:
            for seed_case in source.list_demo_fixtures():
                if limit is not None and len(result.seeded) >= limit:
                    return result
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
