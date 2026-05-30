from __future__ import annotations

import argparse

from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import (
    CuratedDatasetSource,
    CuratedFixtureSource,
    DemoSeeder,
    FixtureSource,
    LocalDatasetSource,
)


def _build_sources(source_name: str, *, limit: int | None = None) -> list[FixtureSource]:
    if source_name == "curated":
        return [CuratedFixtureSource()]
    if source_name == "curated_datasets":
        return [CuratedDatasetSource()]
    if source_name == "local":
        return [LocalDatasetSource(limit=limit)]
    # "all" deliberately excludes the uncommitted local source so reviewed,
    # committed data is the only thing that ever seeds without an explicit opt-in.
    if source_name == "all":
        return [CuratedFixtureSource(), CuratedDatasetSource()]
    raise SystemExit(f"Unknown demo seed source: {source_name}")


def _ensure_source_allowed(source_name: str, env: str) -> None:
    """Refuse the uncommitted local source in production-like environments."""
    if source_name == "local" and env.strip().lower() in {"prod", "production"}:
        raise SystemExit(
            "Local dataset seeding (--source local) is refused in production environments."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the ThreatPrism demo database from curated fixtures")
    parser.add_argument(
        "--source",
        default="curated",
        choices=["curated", "curated_datasets", "local", "all"],
        help="Fixture source to seed from (default: curated). 'local' replays "
        "uncommitted .jsonl staging under external_datasets/ and is never on by default.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="With --source local only: replay at most N staged fixtures.",
    )
    parser.add_argument(
        "--skip-existing",
        dest="skip_existing",
        action="store_true",
        default=True,
        help="Skip fixtures whose source_case_id already exists (default).",
    )
    parser.add_argument(
        "--no-skip-existing",
        dest="skip_existing",
        action="store_false",
        help="Seed even if a matching source_case_id already exists.",
    )
    args = parser.parse_args()

    if args.limit is not None and args.source != "local":
        raise SystemExit("--limit is only supported with --source local.")

    settings = Settings.from_env()
    settings.validate_runtime()
    _ensure_source_allowed(args.source, settings.env)

    service = CaseService(settings)
    seeder = DemoSeeder(service)
    result = seeder.seed(_build_sources(args.source, limit=args.limit), skip_existing=args.skip_existing)

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
