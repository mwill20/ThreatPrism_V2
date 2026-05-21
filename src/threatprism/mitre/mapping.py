from __future__ import annotations

from threatprism.cases.schemas import Evidence, MitreMapping


def map_mitre(evidence: list[Evidence]) -> list[MitreMapping]:
    text = " ".join([item.summary + " " + (item.excerpt or "") for item in evidence]).lower()
    evidence_ids = [item.evidence_id for item in evidence]
    mappings: list[MitreMapping] = []

    if any(term in text for term in ["sign-in", "signin", "credential", "account", "mailbox"]):
        mappings.append(
            MitreMapping(
                tactic="Initial Access",
                technique="Valid Accounts",
                technique_id="T1078",
                confidence=0.66,
                evidence_ids=evidence_ids,
            )
        )
    if any(term in text for term in ["powershell", "script", "command"]):
        mappings.append(
            MitreMapping(
                tactic="Execution",
                technique="Command and Scripting Interpreter",
                technique_id="T1059",
                confidence=0.62,
                evidence_ids=evidence_ids,
            )
        )
    return mappings
