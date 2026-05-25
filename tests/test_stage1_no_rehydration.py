from __future__ import annotations

from threatprism.guardrails.healthcare import safeguard_value


STAGE1_ROLES = {"ai", "analyst", "engineer", "manager_grc", "legal_privacy", "audit_debug"}


def test_stage1_healthcare_tokens_are_never_marked_rehydratable() -> None:
    scan = safeguard_value(
        {
            "title": "Synthetic patient portal alert",
            "description": (
                "Patient portal alert for patient id PAT-DEMO-9001, "
                "MRN MRN-DEMO-1001, DOB 01/02/1970, SSN 123-45-6789, "
                "phone 555-010-1000, email patient.demo@example.invalid, "
                "source IP 198.51.100.24, password: fake-demo-secret"
            ),
            "evidence": [
                {
                    "summary": (
                        "Encounter ENC-DEMO-2001 and claim id CLM-DEMO-3001 "
                        "were included in a synthetic security alert."
                    )
                }
            ],
        },
        case_id="case_stage1_no_rehydrate",
    )

    assert scan.records
    detected = {record.metadata.get("detector") for record in scan.records}
    assert {"patient_id", "mrn", "dob", "ssn", "phone", "context_email", "context_ip", "password"} <= detected

    for record in scan.records:
        assert record.operation == "tokenize"
        assert record.rehydration_allowed is False
        role_policy = record.metadata.get("role_rehydration_allowed")
        assert isinstance(role_policy, dict)
        assert STAGE1_ROLES <= set(role_policy)
        assert not any(role_policy[role] for role in STAGE1_ROLES)
