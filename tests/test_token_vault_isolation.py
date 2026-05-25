from __future__ import annotations

import json
import re
import sqlite3

from threatprism.cases.service import CaseService
from threatprism.config import Settings


TOKEN_MAPPING_KEY = re.compile(r'"tp_[a-z_]+_\d{3}"\s*:')


def test_token_vault_mappings_are_not_serialized_to_case_or_report_blobs() -> None:
    service = CaseService(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            llm_provider="deterministic_demo",
            allow_real_actions=False,
        )
    )

    accepted = service.create_case(
        {
            "source": "generic_soar",
            "source_case_id": "SOAR-DEMO-TOKEN-VAULT-001",
            "title": "Demo token vault isolation case",
            "description": "Synthetic login from analyst.demo@example.invalid at 203.0.113.42.",
            "events": [
                {
                    "event_type": "auth",
                    "description": "Synthetic authentication event.",
                    "normalized": {
                        "source_ip": "203.0.113.42",
                        "actor": "analyst.demo@example.invalid",
                        "url": "https://security.example.invalid/case/001",
                    },
                }
            ],
            "evidence": [
                {
                    "evidence_id": "ev-token-vault-001",
                    "evidence_type": "log",
                    "summary": "Synthetic authentication event references 203.0.113.42.",
                }
            ],
        }
    )
    service.run_triage(accepted.case_id)

    assert service.repository._memory_conn is not None
    serialized_payloads = _sqlite_payload_json(service.repository._memory_conn)
    serialized_payloads.extend(
        [
            json.dumps(service.get_case(accepted.case_id).model_dump(mode="json"), sort_keys=True),
            json.dumps(service.get_report(accepted.case_id).model_dump(mode="json"), sort_keys=True),
            json.dumps(service.list_case_read_models(role="analyst").model_dump(mode="json"), sort_keys=True),
            json.dumps(service.get_audit_events_view(accepted.case_id, "audit_debug"), sort_keys=True),
        ]
    )

    for payload in serialized_payloads:
        assert "TokenVault" not in payload
        assert '"mappings"' not in payload
        assert not TOKEN_MAPPING_KEY.search(payload), payload


def _sqlite_payload_json(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        SELECT payload_json FROM cases
        UNION ALL
        SELECT payload_json FROM triage_reports
        UNION ALL
        SELECT payload_json FROM analyst_feedback
        UNION ALL
        SELECT payload_json FROM disagreement_records
        """
    ).fetchall()
    return [str(row[0]) for row in rows]
