from __future__ import annotations

from threatprism.cases.schemas import Evidence, GrcControl


def map_grc_controls(evidence: list[Evidence]) -> list[GrcControl]:
    text = " ".join([item.summary + " " + (item.excerpt or "") for item in evidence]).lower()
    controls: list[GrcControl] = []

    if any(term in text for term in ["sign-in", "signin", "account", "credential", "identity", "mailbox"]):
        controls.append(
            GrcControl(
                category="Identity and access management",
                rationale="Evidence includes identity or account activity that requires access review.",
                evidence_ids=[item.evidence_id for item in evidence],
                confidence=0.72,
            )
        )
    if any(term in text for term in ["soar", "automation", "closed", "alert"]):
        controls.append(
            GrcControl(
                category="Security monitoring",
                rationale="Evidence supports review of monitoring and automation quality.",
                evidence_ids=[item.evidence_id for item in evidence],
                confidence=0.68,
            )
        )
    if any(term in text for term in ["escalate", "incident", "triage", "malicious", "suspicious"]):
        controls.append(
            GrcControl(
                category="Incident response",
                rationale="The case requires evidence-linked incident response review.",
                evidence_ids=[item.evidence_id for item in evidence],
                confidence=0.65,
            )
        )

    return controls or [
        GrcControl(
            category="Risk management",
            rationale="Evidence is organized for review, but no narrower control category was confidently identified.",
            evidence_ids=[item.evidence_id for item in evidence],
            confidence=0.5,
        )
    ]
