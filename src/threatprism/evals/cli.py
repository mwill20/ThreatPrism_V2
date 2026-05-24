from __future__ import annotations

import argparse

from threatprism.evals.runner import run_eval_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ThreatPrism dry-run eval harness")
    parser.add_argument("--fixtures", default=None, help="Fixture file or directory under tests/evals")
    parser.add_argument("--output", default=None, help="Output directory under .eval_runs")
    args = parser.parse_args()

    summary = run_eval_suite(args.fixtures, args.output)
    print(summary.model_dump_json(indent=2))
    return 0 if summary.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

