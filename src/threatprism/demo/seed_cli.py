from __future__ import annotations

import argparse

from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.demo.seeding import CuratedFixtureSource, DemoSeeder, FixtureSource


def _build_sources(source_name: str) -> list[FixtureSource]:
    if source_name == "curated":
        return [CuratedFixtureSource()]
    raise SystemExit(f"Unknown demo seed source: {source_name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the ThreatPrism demo database from curated fixtures")
    parser.add_argument(
        "--source",
        default="curated",
        choices=["curated"],
        help="Fixture source to seed from (default: curated).",
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

    settings = Settings.from_env()
    settings.validate_runtime()

    service = CaseService(settings)
    seeder = DemoSeeder(service)
    result = seeder.seed(_build_sources(args.source), skip_existing=args.skip_existing)

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
