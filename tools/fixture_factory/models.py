from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from threatprism.cases.schemas import CaseCreate


SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_/-]{1,80}$")
FIXTURE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,96}$")


class DataSourceRegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    name: str
    url: str
    category: str
    intended_use: str
    license_review_required: Literal[True] = True
    allowed_for_auto_download: Literal[False] = False
    raw_data_committed: Literal[False] = False
    notes: str

    @field_validator("source_id")
    @classmethod
    def source_id_is_safe(cls, value: str) -> str:
        if not SOURCE_ID_PATTERN.fullmatch(value):
            raise ValueError("source_id must be lowercase and path-safe")
        return value


class DataSourceRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[DataSourceRegistryEntry] = Field(..., min_length=1)

    @model_validator(mode="after")
    def source_ids_are_unique(self) -> "DataSourceRegistry":
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source_id values must be unique")
        return self


class FixtureSourceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    source_file: str
    record_index: int = Field(..., ge=0)
    license_review_required: Literal[True] = True
    raw_source_committed: Literal[False] = False
    source_payload_hash: str
    adapter: str

    @field_validator("source_file")
    @classmethod
    def source_file_is_relative(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("source_file must be a safe relative path")
        return normalized


class ExpectedGuardrailOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    guardrail: str
    expected: Literal["pass", "redact", "tokenize", "quarantine", "review_required", "block"]
    reason: str
    fields: list[str] = Field(default_factory=list)


class ExpectedRoleVisibility(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["ai", "analyst", "engineer", "manager_grc", "legal_privacy", "audit_debug"]
    raw_sensitive_values_visible: Literal[False] = False
    tokenized_values_visible: bool = True
    summary: str


class ThreatPrismSyntheticFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str
    source_family: str
    scenario_type: str
    source_reference: str
    source_metadata: FixtureSourceMetadata
    synthetic_only: Literal[True] = True
    raw_source_retained: Literal[False] = False
    payload: dict[str, Any]
    expected_result: dict[str, Any] = Field(default_factory=dict)
    expected_guardrails: list[ExpectedGuardrailOutcome] = Field(default_factory=list)
    expected_role_visibility: dict[str, ExpectedRoleVisibility] = Field(default_factory=dict)
    expected_evidence_ids: list[str] = Field(default_factory=list)
    notes: str = "Sanitized ThreatPrism-native fixture generated from reviewed source material."

    @field_validator("fixture_id")
    @classmethod
    def fixture_id_is_safe(cls, value: str) -> str:
        if not FIXTURE_ID_PATTERN.fullmatch(value):
            raise ValueError("fixture_id must be lowercase, deterministic, and path-safe")
        return value

    @field_validator("source_family", "source_reference", "scenario_type")
    @classmethod
    def labels_are_safe(cls, value: str) -> str:
        if not SOURCE_ID_PATTERN.fullmatch(value):
            raise ValueError("fixture labels must be lowercase and path-safe")
        return value

    @model_validator(mode="after")
    def payload_is_threatprism_case(self) -> "ThreatPrismSyntheticFixture":
        CaseCreate.model_validate(self.payload)
        return self


class SyntheticSOARCaseFixture(ThreatPrismSyntheticFixture):
    scenario_type: Literal["soc_case"] = "soc_case"


class PromptInjectionEvalFixture(ThreatPrismSyntheticFixture):
    scenario_type: Literal["prompt_injection"] = "prompt_injection"


class HealthcareExposureFixture(ThreatPrismSyntheticFixture):
    scenario_type: Literal["healthcare_exposure"] = "healthcare_exposure"


class EvidenceGroundingFixture(ThreatPrismSyntheticFixture):
    scenario_type: Literal["evidence_conflict"] = "evidence_conflict"
