from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from threatprism.cases.schemas import CaseCreate, Evidence, Event, OrganizationContext, Source


class GenericSoarAdapter:
    source_name = Source.generic_soar
    accepted_sources = {"generic_soar", "generic", None}

    def can_handle(self, payload: dict[str, Any]) -> bool:
        return payload.get("source", "generic_soar") in self.accepted_sources

    def normalize(self, payload: dict[str, Any]) -> CaseCreate:
        normalized = dict(payload)
        normalized["source"] = self.source_name
        normalized.setdefault("organization_context", OrganizationContext().model_dump(mode="json"))
        normalized.setdefault("alerts", [])
        normalized.setdefault("events", [])
        normalized.setdefault("entities", [])
        normalized.setdefault("iocs", [])
        normalized.setdefault("evidence", [])

        if not normalized["evidence"]:
            normalized["evidence"] = [
                Evidence(
                    evidence_id="ev-001",
                    evidence_type="case_summary",
                    summary=normalized.get("description") or normalized.get("title") or "Generic SOAR case",
                    source_uri=f"demo://soar/{normalized.get('source_case_id', 'unknown')}",
                    excerpt=normalized.get("description"),
                ).model_dump(mode="json")
            ]

        if not normalized["events"] and normalized.get("description"):
            normalized["events"] = [
                Event(
                    event_id="evt-001",
                    event_type="soar_case",
                    source="generic_soar",
                    description=normalized["description"],
                    raw_reference=f"demo://soar/{normalized.get('source_case_id', 'unknown')}",
                ).model_dump(mode="json")
            ]

        try:
            return CaseCreate.model_validate(normalized)
        except ValidationError:
            raise


class SentinelSoarAdapter(GenericSoarAdapter):
    source_name = Source.sentinel
    accepted_sources = {"sentinel", "microsoft_sentinel"}


class DefenderXdrSoarAdapter(GenericSoarAdapter):
    source_name = Source.defender_xdr
    accepted_sources = {"defender_xdr", "microsoft_defender_xdr", "defender"}


class LogicAppsSoarAdapter(GenericSoarAdapter):
    source_name = Source.logic_apps
    accepted_sources = {"logic_apps", "microsoft_logic_apps", "logic_app"}


class SwimlaneMockSoarAdapter(GenericSoarAdapter):
    source_name = Source.swimlane_mock
    accepted_sources = {"swimlane_mock", "swimlane"}


def normalize_soar_payload(payload: dict[str, Any]) -> CaseCreate:
    adapters = [
        GenericSoarAdapter(),
        SentinelSoarAdapter(),
        DefenderXdrSoarAdapter(),
        LogicAppsSoarAdapter(),
        SwimlaneMockSoarAdapter(),
    ]
    for adapter in adapters:
        if adapter.can_handle(payload):
            return adapter.normalize(payload)
    raise ValueError("No SOAR adapter could normalize this payload.")
