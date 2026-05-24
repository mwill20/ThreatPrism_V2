from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


LIVE_CREDENTIAL_ENV_VARS = {
    "OPENAI_API_KEY",
    "LOCAL_LLM_BASE_URL",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "ABUSEIPDB_API_KEY",
}

REQUIRED_GITIGNORE_ENTRIES = {
    ".env",
    ".eval_runs/",
    ".pytest_tmp*/",
    "pytest-cache-files-*/",
    "data/",
    "*.db",
}

GENERATED_TRACKED_PREFIXES = (
    ".eval_runs/",
    ".pytest_tmp",
    "data/",
    "pytest-cache-files-",
)

GENERATED_TRACKED_SUFFIXES = (
    ".db",
    ".db-journal",
    ".pyc",
    ".pyo",
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z_]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("OpenAI-style live key", re.compile(r"\bsk-(?!test|fake|demo|example)[0-9A-Za-z_-]{20,}\b", re.IGNORECASE)),
)

EVAL_ARTIFACT_FORBIDDEN_STRINGS = {
    "PAT-44321",
    "jane.patient@example.invalid",
    "demo.user@example.invalid",
    "203.0.113.42",
    "sk-testsecretvalue12345",
    "demo-manager-key",
    "not-a-real-demo-key",
    "raw_payload",
    "vault_mappings",
}

SKIP_DIRS = {
    ".git",
    ".venv",
    ".eval_runs",
    ".pytest_cache",
    "__pycache__",
    "data",
}


@dataclass(frozen=True)
class SafetyFinding:
    check: str
    path: str
    message: str


def run_checks(
    root: Path,
    *,
    include_untracked: bool = False,
    scan_eval_artifacts: bool = False,
) -> list[SafetyFinding]:
    root = root.resolve()
    findings: list[SafetyFinding] = []
    tracked_files = _git_files(root, include_untracked=False)
    scan_files = _git_files(root, include_untracked=include_untracked)

    findings.extend(_check_runtime_environment())
    findings.extend(_check_runtime_guard(root))
    findings.extend(_check_env_example(root))
    findings.extend(_check_gitignore(root))
    findings.extend(_check_generated_artifacts_not_tracked(tracked_files))
    findings.extend(_check_secret_patterns(root, scan_files))
    if scan_eval_artifacts:
        findings.extend(_check_eval_artifacts(root))
    return findings


def _check_runtime_environment() -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    if _is_truthy(os.getenv("ALLOW_REAL_ACTIONS")):
        findings.append(
            SafetyFinding(
                "runtime-env",
                "environment",
                "ALLOW_REAL_ACTIONS is enabled. ThreatPrism V2 validation must run with real actions disabled.",
            )
        )

    active_env = os.getenv("THREATPRISM_ENV", "").strip().lower()
    active_auth = os.getenv("API_AUTH_MODE", "").strip().lower()
    if active_env in {"prod", "production"} and active_auth in {"none", "demo_key"}:
        findings.append(
            SafetyFinding(
                "runtime-env",
                "environment",
                "Production-like environment is configured with disabled or demo authentication.",
            )
        )

    for env_var in sorted(LIVE_CREDENTIAL_ENV_VARS):
        if os.getenv(env_var):
            findings.append(
                SafetyFinding(
                    "live-credential-env",
                    "environment",
                    f"{env_var} is set. Safe validation must not run with live provider credentials in the environment.",
                )
            )
    return findings


def _check_runtime_guard(root: Path) -> list[SafetyFinding]:
    sys.path.insert(0, str(root / "src"))
    try:
        from threatprism.config import Settings
    except Exception as exc:  # noqa: BLE001
        return [
            SafetyFinding(
                "runtime-guard",
                "src/threatprism/config.py",
                f"Could not import Settings for runtime guard check: {exc.__class__.__name__}",
            )
        ]

    findings: list[SafetyFinding] = []
    for auth_mode in ("none", "demo_key"):
        try:
            Settings(env="production", api_auth_mode=auth_mode, allow_real_actions=False).validate_runtime()
        except ValueError:
            continue
        findings.append(
            SafetyFinding(
                "runtime-guard",
                "src/threatprism/config.py",
                f"Production environment did not reject API_AUTH_MODE={auth_mode}.",
            )
        )
    return findings


def _check_env_example(root: Path) -> list[SafetyFinding]:
    env_path = root / ".env.example"
    if not env_path.exists():
        return [SafetyFinding("env-template", ".env.example", ".env.example is missing.")]

    env_values = _parse_env_file(env_path)
    findings: list[SafetyFinding] = []
    if env_values.get("ALLOW_REAL_ACTIONS", "").strip().lower() != "false":
        findings.append(
            SafetyFinding("env-template", ".env.example", "ALLOW_REAL_ACTIONS must be false in the template.")
        )
    if env_values.get("LLM_PROVIDER", "").strip() != "deterministic_demo":
        findings.append(
            SafetyFinding("env-template", ".env.example", "LLM_PROVIDER must default to deterministic_demo.")
        )
    for env_var in sorted(LIVE_CREDENTIAL_ENV_VARS):
        if env_values.get(env_var, "").strip():
            findings.append(
                SafetyFinding("env-template", ".env.example", f"{env_var} must be empty in .env.example.")
            )
    demo_keys = env_values.get("DEMO_API_KEYS", "")
    if demo_keys and "demo-" not in demo_keys:
        findings.append(
            SafetyFinding("env-template", ".env.example", "DEMO_API_KEYS must contain fake demo credentials only.")
        )
    return findings


def _check_gitignore(root: Path) -> list[SafetyFinding]:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return [SafetyFinding("artifact-hygiene", ".gitignore", ".gitignore is missing.")]
    content = gitignore.read_text(encoding="utf-8")
    findings = []
    for entry in sorted(REQUIRED_GITIGNORE_ENTRIES):
        if entry not in content:
            findings.append(
                SafetyFinding("artifact-hygiene", ".gitignore", f"Missing required ignored artifact pattern: {entry}")
            )
    return findings


def _check_generated_artifacts_not_tracked(tracked_files: list[Path]) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    for path in tracked_files:
        normalized = path.as_posix()
        if normalized.startswith(GENERATED_TRACKED_PREFIXES) or normalized.endswith(GENERATED_TRACKED_SUFFIXES):
            findings.append(
                SafetyFinding(
                    "tracked-artifact",
                    normalized,
                    "Generated runtime, cache, database, or bytecode artifact is tracked.",
                )
            )
    return findings


def _check_secret_patterns(root: Path, files: list[Path]) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    for relative_path in files:
        if _should_skip(relative_path):
            continue
        path = root / relative_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    SafetyFinding(
                        "secret-scan",
                        relative_path.as_posix(),
                        f"Potential {label} found in repository content.",
                    )
                )
    return findings


def _check_eval_artifacts(root: Path) -> list[SafetyFinding]:
    eval_dir = root / ".eval_runs"
    if not eval_dir.exists():
        return []
    findings: list[SafetyFinding] = []
    for path in eval_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative_path = path.relative_to(root).as_posix()
        for forbidden in sorted(EVAL_ARTIFACT_FORBIDDEN_STRINGS):
            if forbidden in text:
                findings.append(
                    SafetyFinding(
                        "eval-artifact-sanitize",
                        relative_path,
                        f"Eval artifact contains forbidden raw value or metadata marker: {forbidden}",
                    )
                )
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    SafetyFinding(
                        "eval-artifact-sanitize",
                        relative_path,
                        f"Eval artifact contains potential {label}.",
                    )
                )
    return findings


def _git_files(root: Path, *, include_untracked: bool) -> list[Path]:
    args = ["git", "ls-files"]
    if include_untracked:
        args.extend(["--cached", "--others", "--exclude-standard"])
    try:
        completed = subprocess.run(args, cwd=root, check=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return _walk_files(root)
    return [Path(line) for line in completed.stdout.splitlines() if line.strip()]


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if _should_skip(relative):
            continue
        if path.is_file():
            files.append(relative)
    return files


def _should_skip(relative_path: Path) -> bool:
    return bool(relative_path.parts and relative_path.parts[0] in SKIP_DIRS)


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ThreatPrism fake-data safety checks.")
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Scan untracked non-ignored files as well as tracked files.",
    )
    parser.add_argument(
        "--scan-eval-artifacts",
        action="store_true",
        help="Scan generated .eval_runs artifacts for forbidden raw values.",
    )
    args = parser.parse_args()

    findings = run_checks(
        Path(args.root),
        include_untracked=args.include_untracked,
        scan_eval_artifacts=args.scan_eval_artifacts,
    )
    if findings:
        print("ThreatPrism demo safety check failed:")
        for finding in findings:
            print(f"- [{finding.check}] {finding.path}: {finding.message}")
        return 1
    print("ThreatPrism demo safety check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
