"""Operator verify / inspect / export for the tamper-evident integrity logs.

An append-only hash chain is only useful if an operator can run its integrity check,
see what it contains, and export an integrity report. This backs:

    python -m threatprism.persistence.verify_logs            # verify both, human output
    python -m threatprism.persistence.verify_logs --json     # machine-readable
    python -m threatprism.persistence.verify_logs --export integrity_report.json

Exit code is non-zero if any configured, existing log fails its hash-chain check, so
the command can gate CI / validation.

The logs already hold only sanitized payloads (failure reports with sanitized offending
values; audit events that are redacted by invariant), so verification and the integrity
report carry no raw PHI/secrets — this tool reads, never rehydrates.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from threatprism.config import Settings
from threatprism.persistence.hash_chain import HashChainedLog

# Each integrity log + the payload field used to summarize it.
_LOGS = (
    ("failure_log", "failure_log_path", "failure_type"),
    ("audit_log", "audit_log_path", "event_type"),
)


@dataclass
class LogReport:
    name: str
    path: str
    exists: bool
    record_count: int
    chain_valid: bool
    summary: dict[str, int] = field(default_factory=dict)


def _summarize(path: Path, category_field: str) -> tuple[int, dict[str, int]]:
    count = 0
    by_category: dict[str, int] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            count += 1
            category = json.loads(line).get("payload", {}).get(category_field)
            if category is not None:
                key = str(category)
                by_category[key] = by_category.get(key, 0) + 1
    return count, dict(sorted(by_category.items()))


def verify_log(name: str, path: str, category_field: str) -> LogReport:
    """Verify one log's hash chain and summarize its records by ``category_field``."""
    file_path = Path(path)
    if not file_path.exists():
        # An absent log is trivially valid (nothing to tamper with).
        return LogReport(name=name, path=path, exists=False, record_count=0, chain_valid=True)
    count, summary = _summarize(file_path, category_field)
    return LogReport(
        name=name,
        path=path,
        exists=True,
        record_count=count,
        chain_valid=HashChainedLog(file_path).verify(),
        summary=summary,
    )


def build_reports(settings: Settings) -> list[LogReport]:
    """Verify every configured integrity log (skips logs with an empty path)."""
    reports: list[LogReport] = []
    for name, path_attr, category_field in _LOGS:
        path = getattr(settings, path_attr, "") or ""
        if not path:
            continue
        reports.append(verify_log(name, path, category_field))
    return reports


def all_valid(reports: list[LogReport]) -> bool:
    return all(report.chain_valid for report in reports)


def export_reports(reports: list[LogReport], dest_path: str) -> None:
    """Write a redaction-safe integrity report (status + counts + summaries) to JSON."""
    payload = {
        "all_valid": all_valid(reports),
        "logs": [asdict(report) for report in reports],
    }
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _render_human(reports: list[LogReport]) -> str:
    if not reports:
        return "No integrity logs are configured (FAILURE_LOG_PATH / AUDIT_LOG_PATH empty)."
    lines = []
    for report in reports:
        status = "OK" if report.chain_valid else "TAMPERED"
        presence = "" if report.exists else " (not yet created)"
        lines.append(f"[{status}] {report.name}: {report.record_count} records{presence} -> {report.path}")
        for category, n in report.summary.items():
            lines.append(f"    {category}: {n}")
    lines.append("")
    lines.append("ALL LOGS VALID" if all_valid(reports) else "INTEGRITY CHECK FAILED")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify/inspect/export the tamper-evident integrity logs.")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    parser.add_argument("--export", metavar="PATH", default=None, help="Write the integrity report to PATH (JSON).")
    args = parser.parse_args()

    reports = build_reports(Settings.from_env())
    if args.export:
        export_reports(reports, args.export)
    if args.json:
        print(json.dumps({"all_valid": all_valid(reports), "logs": [asdict(r) for r in reports]}, indent=2, sort_keys=True))
    else:
        print(_render_human(reports))
    return 0 if all_valid(reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
