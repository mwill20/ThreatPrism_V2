from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


ScenarioPersona = Literal["analyst", "manager_grc", "legal_privacy", "audit_debug", "engineer"]
ScenarioBody = Literal["none", "payload", "feedback"]


class DemoScenarioStep(BaseModel):
    step_id: str
    method: Literal["GET", "POST"]
    path: str
    purpose: str
    expected_status: int
    body: ScenarioBody = "none"
    auth: str = "scenario"
    expected_json_paths: list[str] = Field(default_factory=list)
    expected_substrings: list[str] = Field(default_factory=list)
    forbidden_substrings: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def require_local_api_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("Demo scenario paths must be local API paths.")
        if "http://" in value or "https://" in value:
            raise ValueError("Demo scenarios must not call external URLs.")
        return value


class DemoScenario(BaseModel):
    scenario_id: str
    title: str
    persona: ScenarioPersona
    auth_key: str
    payload_path: str
    feedback: dict[str, Any] | None = None
    steps: list[DemoScenarioStep] = Field(default_factory=list, min_length=1)

    @field_validator("payload_path")
    @classmethod
    def require_example_payload(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Demo scenario payload paths must stay inside the repository.")
        if path.parts[:1] != ("examples",):
            raise ValueError("Demo scenario payloads must live under examples/.")
        if path.suffix.lower() != ".json":
            raise ValueError("Demo scenario payloads must be JSON files.")
        return value.replace("\\", "/")

    @field_validator("auth_key")
    @classmethod
    def require_demo_key(cls, value: str) -> str:
        if not value.startswith("demo-") or not value.endswith("-key"):
            raise ValueError("Demo scenarios must use fake demo API keys.")
        return value


class ApiContractRoute(BaseModel):
    method: Literal["GET", "POST"]
    path: str
    response_model: str | None = None
    status_codes: list[int] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def require_contract_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("API contract paths must be local API paths.")
        return value


class DemoScenarioPack(BaseModel):
    schema_version: Literal["demo-scenario-pack/0.1"]
    safety_rules: dict[str, Any]
    api_contract: list[ApiContractRoute]
    scenarios: list[DemoScenario] = Field(default_factory=list, min_length=1)


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_demo_scenario_pack(root: Path | None = None) -> DemoScenarioPack:
    repo_root = root or _default_repo_root()
    pack_path = repo_root / "examples" / "demo_scenarios" / "demo_scenario_pack.json"
    return DemoScenarioPack.model_validate_json(pack_path.read_text(encoding="utf-8"))
