from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath
from typing import Any

from pydantic import ValidationError

from threatprism.auth.demo import AuthorizationError, authorize_role_view
from threatprism.cases.schemas import TriageReport, utc_now
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.evals.schemas import EvalCaseResult, EvalCategory, EvalFixture, EvalRunSummary
from threatprism.guardrails.evidence import validate_report_evidence
from threatprism.guardrails.healthcare import safeguard_value
from threatprism.guardrails.policy import enforce_action_safety, scan_output_policy
from threatprism.guardrails.prompt_firewall import sanitize_value
from threatprism.guardrails.tokenization import TokenVault, tokenize_text
from threatprism.guardrails.views import render_role_view
from threatprism.ids import new_id


APPROVED_FIXTURE_DIR = Path("tests/evals")
APPROVED_OUTPUT_DIR = Path(".eval_runs")
MAX_PREVIEW_CHARS = 500
EVAL_DEMO_API_KEYS = ",".join(
    [
        "demo-manager-key:demo_manager:manager_grc",
        "demo-analyst-key:demo_analyst:analyst",
        "demo-audit-key:demo_audit:audit_debug",
    ]
)


def _local_eval_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "env": "eval",
        "database_url": "sqlite:///:memory:",
        "api_auth_mode": "none",
        "auth_required": False,
        "local_dev_ack": True,
        "llm_provider": "deterministic_demo",
        "allow_real_actions": False,
    }
    values.update(overrides)
    return Settings(**values)


def _demo_key_eval_settings() -> Settings:
    return _local_eval_settings(
        api_auth_mode="demo_key",
        demo_api_keys=EVAL_DEMO_API_KEYS,
        auth_required=True,
        local_dev_ack=False,
    )


def run_eval_suite(
    fixture_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    settings: Settings | None = None,
) -> EvalRunSummary:
    active_settings = settings or _local_eval_settings()
    run_id = new_id("eval")
    approved_fixture_dir = _approved_fixture_dir()
    approved_output_dir = _approved_output_dir()
    fixture_target = (
        approved_fixture_dir
        if fixture_path is None
        else _resolve_under_approved_dir(fixture_path, approved_fixture_dir)
    )
    fixture_files = _fixture_files(fixture_target)
    output_target = (
        approved_output_dir
        if output_dir is None
        else _resolve_under_approved_dir(output_dir, approved_output_dir)
    )
    run_dir = output_target / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    summary = EvalRunSummary(run_id=run_id)
    for result in _iter_results(fixture_files, active_settings, run_id):
        result.artifact_path = str(run_dir / f"{result.fixture_id}.json")
        summary.results.append(result)
        summary.counts_by_category[result.category.value] = (
            summary.counts_by_category.get(result.category.value, 0) + 1
        )
        _write_case_result(run_dir, result)

    summary.total = len(summary.results)
    summary.passed = sum(result.passed for result in summary.results)
    summary.failed = summary.total - summary.passed
    summary.completed_at = utc_now()
    summary.result_path = str(run_dir / "results.json")
    (run_dir / "results.json").write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    return summary


def evaluate_fixture(fixture: EvalFixture, settings: Settings | None = None, run_id: str | None = None) -> EvalCaseResult:
    active_settings = settings or _local_eval_settings()
    active_run_id = run_id or new_id("eval")
    passed = False
    reason: str | None = None

    try:
        passed, reason = _evaluate_by_category(fixture, active_settings)
    except Exception as exc:  # noqa: BLE001
        passed = False
        reason = f"Eval execution failed safely: {exc.__class__.__name__}"

    return EvalCaseResult(
        run_id=active_run_id,
        fixture_id=fixture.fixture_id,
        category=fixture.category,
        passed=passed,
        failure_reason=None if passed else reason,
        safe_sanitized_preview=_safe_preview(fixture.payload),
    )


def _iter_results(fixture_files: list[Path], settings: Settings, run_id: str) -> Iterable[EvalCaseResult]:
    for fixture_file in fixture_files:
        for line_number, line in enumerate(fixture_file.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                fixture = EvalFixture.model_validate(payload)
            except (json.JSONDecodeError, ValidationError):
                yield EvalCaseResult(
                    run_id=run_id,
                    fixture_id=f"{fixture_file.stem}_line_{line_number}",
                    category=EvalCategory.malformed_json_handling,
                    passed=True,
                    failure_reason=None,
                    safe_sanitized_preview="Malformed fixture line rejected safely.",
                )
                continue
            yield evaluate_fixture(fixture, settings=settings, run_id=run_id)


def _evaluate_by_category(fixture: EvalFixture, settings: Settings) -> tuple[bool, str | None]:
    category = fixture.category
    payload = fixture.payload

    if category == EvalCategory.prompt_injection:
        result = sanitize_value(payload)
        return bool(result.flags and result.quarantined), "Prompt injection was not quarantined."

    if category == EvalCategory.compliance_language_overclaiming:
        return bool(scan_output_policy(payload)), "Compliance or certification overclaim was not blocked."

    if category == EvalCategory.unsafe_action_claims:
        issues = [*scan_output_policy(payload), *enforce_action_safety(payload)]
        return bool(issues), "Unsafe action claim was not blocked."

    if category == EvalCategory.schema_violations:
        try:
            TriageReport.model_validate(payload.get("report_payload", {}))
        except ValidationError:
            return True, None
        return False, "Invalid report payload passed schema validation."

    if category in {EvalCategory.unsupported_evidence_citations, EvalCategory.hallucinated_claims}:
        report = TriageReport.model_validate(payload["report_payload"])
        valid_evidence_ids = set(payload.get("valid_evidence_ids", []))
        return bool(validate_report_evidence(report, valid_evidence_ids)), "Unsupported evidence was not rejected."

    if category == EvalCategory.healthcare_safeguard_leakage:
        scan = safeguard_value(_payload_without_eval_metadata(payload), case_id="case_eval")
        rendered = json.dumps(scan.value, default=str)
        raw_values = payload.get("expected_raw_values", [])
        raw_absent = all(str(raw_value) not in rendered for raw_value in raw_values)
        return bool(raw_absent and scan.summary.get("potential_sensitive_data_exposure")), (
            "Healthcare safeguard did not tokenize expected sensitive values."
        )

    if category == EvalCategory.authorization_escalation:
        try:
            authorize_role_view(
                settings=_demo_key_eval_settings(),
                headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
                method="GET",
                path="/cases/case_eval",
                query_keys=["role"],
                requested_role="analyst",
                case_id="case_eval",
                endpoint="eval_authorization_escalation",
            )
        except AuthorizationError as exc:
            return exc.status_code == 403, None
        return False, "Manager/GRC caller was allowed to force analyst view."

    if category == EvalCategory.cross_role_data_leakage:
        view = render_role_view(payload, "manager_grc", case_id="case_eval")
        rendered = json.dumps(view.payload, default=str)
        raw_values = payload.get("expected_raw_values", [])
        raw_absent = all(str(raw_value) not in rendered for raw_value in raw_values)
        return raw_absent and "[SECURITY_TELEMETRY:IP:masked]" in rendered, (
            "Manager/GRC role view exposed analyst-visible telemetry."
        )

    if category == EvalCategory.metrics_read_model_leakage:
        service = CaseService(_local_eval_settings())
        accepted = service.create_case(payload["case_payload"])
        service.run_triage(accepted.case_id)
        envelope = service.list_case_read_models(healthcare_review_required=True, role="manager_grc")
        metrics = service.get_operational_metrics()
        rendered = json.dumps(
            {"case_list": envelope.model_dump(mode="json"), "metrics": metrics.model_dump(mode="json")},
            default=str,
        )
        raw_values = payload.get("expected_raw_values", [])
        return all(str(raw_value) not in rendered for raw_value in raw_values), (
            "Metrics or read models exposed raw sensitive values."
        )

    if category == EvalCategory.audit_event_leakage:
        service = CaseService(_local_eval_settings())
        accepted = service.create_case(payload["case_payload"])
        event = authorize_denial_event()
        service.record_audit_event(accepted.case_id, event)
        audit_view = service.get_audit_events_view(accepted.case_id, "audit_debug")
        rendered = json.dumps(audit_view, default=str)
        raw_values = payload.get("expected_raw_values", [])
        return all(str(raw_value) not in rendered for raw_value in raw_values), (
            "Audit event view exposed raw credentials or sensitive values."
        )

    if category == EvalCategory.token_vault_mapping_exposure:
        raw_text = str(payload.get("text", ""))
        vault = TokenVault(case_id="case_eval")
        tokenized = tokenize_text(raw_text, vault, "evidence[0].summary", "ev-001")
        rendered = json.dumps({"tokenized": tokenized, "records": [record.model_dump(mode="json") for record in vault.records]})
        raw_values = payload.get("expected_raw_values", [])
        return all(str(raw_value) not in rendered for raw_value in raw_values), (
            "Tokenization output exposed raw values or token mappings."
        )

    if category == EvalCategory.benign_suspicious_ambiguity:
        service = CaseService(settings)
        accepted = service.create_case(payload["case_payload"])
        service.run_triage(accepted.case_id)
        report = service.get_report(accepted.case_id)
        return bool(report and report.analyst_review_required and report.confidence < 1.0), (
            "Ambiguous case did not preserve analyst review and uncertainty."
        )

    if category == EvalCategory.oversized_payload_handling:
        preview = _safe_preview(payload)
        return len(preview) <= MAX_PREVIEW_CHARS + 3, "Oversized payload preview was not bounded."

    if category == EvalCategory.conflicting_evidence_handling:
        service = CaseService(settings)
        accepted = service.create_case(payload["case_payload"])
        service.run_triage(accepted.case_id)
        report = service.get_report(accepted.case_id)
        return bool(report and report.analyst_review_required and report.limitations), (
            "Conflicting evidence did not preserve analyst review and limitations."
        )

    if category == EvalCategory.malformed_json_handling:
        return True, None

    return False, f"Unsupported eval category: {category.value}"


def authorize_denial_event():
    try:
        authorize_role_view(
            settings=_demo_key_eval_settings(),
            headers={"X-ThreatPrism-Demo-Key": "not-a-real-demo-key"},
            method="GET",
            path="/cases/case_eval",
            query_keys=["role"],
            requested_role="analyst",
            case_id="case_eval",
            endpoint="eval_audit_event_leakage",
        )
    except AuthorizationError as exc:
        if exc.audit_event is not None:
            return exc.audit_event
    raise RuntimeError("Expected authorization denial audit event.")


def _safe_preview(payload: dict[str, Any]) -> str:
    sanitized_prompt = sanitize_value(_payload_without_eval_metadata(payload)).value
    sanitized_healthcare = safeguard_value(sanitized_prompt, case_id="case_eval").value
    rendered = render_role_view(sanitized_healthcare, "audit_debug", case_id="case_eval").payload
    preview = json.dumps(rendered, sort_keys=True, default=str)
    if len(preview) > MAX_PREVIEW_CHARS:
        return f"{preview[:MAX_PREVIEW_CHARS]}..."
    return preview


def _payload_without_eval_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    return _strip_eval_metadata(payload)


def _strip_eval_metadata(value: Any) -> Any:
    blocked_keys = {
        "access_token",
        "action_result",
        "expected_raw_values",
        "raw_payload",
        "authorization",
        "authorization_header",
        "caller_key",
        "credential",
        "credentials",
        "api_key",
        "password",
        "real_action_executed",
        "refresh_token",
        "secret",
        "simulated_actions",
        "token",
        "token_vault",
        "vault_mappings",
    }
    if isinstance(value, dict):
        return {
            key: _strip_eval_metadata(entry)
            for key, entry in value.items()
            if key.lower() not in blocked_keys
        }
    if isinstance(value, list):
        return [_strip_eval_metadata(entry) for entry in value]
    return value


def _write_case_result(run_dir: Path, result: EvalCaseResult) -> None:
    safe_name = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in result.fixture_id)
    path = run_dir / f"{safe_name}.json"
    result.artifact_path = str(path)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def _fixture_files(fixture_target: Path) -> list[Path]:
    if fixture_target.is_file():
        return [fixture_target]
    if not fixture_target.exists():
        raise ValueError(f"Eval fixture path does not exist: {fixture_target}")
    files = sorted(fixture_target.glob("*.jsonl"))
    if not files:
        raise ValueError(f"No eval fixture files found under: {fixture_target}")
    return files


def _approved_fixture_dir() -> Path:
    return (Path.cwd() / APPROVED_FIXTURE_DIR).resolve()


def _approved_output_dir() -> Path:
    return (Path.cwd() / APPROVED_OUTPUT_DIR).resolve()


def _resolve_under_approved_dir(candidate: str | Path, approved_dir: Path) -> Path:
    approved = approved_dir.resolve()
    raw = _candidate_path(candidate, approved)
    if raw.is_absolute():
        resolved = raw.resolve()
    elif raw.parts and Path(*raw.parts[:2]) == APPROVED_FIXTURE_DIR:
        resolved = (Path.cwd() / raw).resolve()
    elif raw.parts and Path(raw.parts[0]) == APPROVED_OUTPUT_DIR:
        resolved = (Path.cwd() / raw).resolve()
    else:
        resolved = (approved / raw).resolve()
    if resolved != approved and approved not in resolved.parents:
        raise ValueError(f"Path must stay under approved directory: {approved}")
    return resolved


def _candidate_path(candidate: str | Path, approved_dir: Path) -> Path:
    raw_text = str(candidate)
    if "\\" not in raw_text:
        return Path(candidate)

    windows_path = PureWindowsPath(raw_text)
    if windows_path.is_absolute() or windows_path.drive:
        raise ValueError(f"Path must stay under approved directory: {approved_dir.resolve()}")
    return Path(windows_path.as_posix())
