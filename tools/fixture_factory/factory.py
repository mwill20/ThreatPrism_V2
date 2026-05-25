from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.fixture_factory.adapters import get_adapter
from tools.fixture_factory import REPO_ROOT
from tools.fixture_factory.validators import (
    ensure_deterministic_order,
    fixture_to_sorted_json,
    load_registry,
    resolve_input_path,
    resolve_output_path,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic sanitized ThreatPrism-native synthetic fixtures."
    )
    parser.add_argument("--source", required=True, help="Registered source id or local adapter alias.")
    parser.add_argument("--input", required=True, help="Local reviewed input path under external_datasets/.")
    parser.add_argument("--output", required=True, help="JSONL output path under fixtures/generated/.")
    parser.add_argument("--limit", required=True, type=int, help="Maximum number of source records to convert.")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing generated fixture file.")
    return parser


def main(argv: list[str] | None = None, *, repo_root: Path = REPO_ROOT) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.limit <= 0:
            raise ValueError("--limit must be greater than zero")
        registry = load_registry()
        registered_ids = {source.source_id for source in registry.sources}
        if args.source not in registered_ids and args.source not in {"synthea", "otrf", "pint", "giskard"}:
            raise ValueError(f"Unknown source id: {args.source}")
        input_path = resolve_input_path(args.input, repo_root=repo_root)
        output_path = resolve_output_path(args.output, repo_root=repo_root, force=args.force)
        adapter = get_adapter(args.source)
        fixtures = ensure_deterministic_order(adapter(input_path, args.limit))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output = "\n".join(fixture_to_sorted_json(fixture) for fixture in fixtures)
        if output:
            output += "\n"
        output_path.write_text(output, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"fixture_factory error: {exc}", file=sys.stderr)
        return 2
    fixture_ids = ", ".join(fixture.fixture_id for fixture in fixtures)
    try:
        relative_output = output_path.relative_to(repo_root).as_posix()
    except ValueError:
        relative_output = output_path.name
    print(f"generated={len(fixtures)} output={relative_output} fixture_ids={fixture_ids}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
