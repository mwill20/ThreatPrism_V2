# 07 Microsoft Integration

## Goal

ThreatPrism must remain provider-agnostic while making Microsoft security stack integration a first-class path.

## Target Integrations

- Microsoft Sentinel incidents.
- Microsoft Defender XDR incidents.
- Microsoft Defender for Endpoint alerts.
- Microsoft Graph Security API.
- Microsoft Entra ID sign-in and audit logs.
- Azure Monitor / Log Analytics / KQL exports.
- Logic Apps / Power Automate webhook flows.

## Design Constraint

Microsoft-specific adapters must not leak Microsoft-only assumptions into the core case model. They should map source payloads into common fields and preserve source-specific metadata separately.

## Sentinel Incident Mapping

Recommended mapping:

| Source Field | ThreatPrism Field |
| --- | --- |
| Incident ID | `source_case_id` |
| Title | `title` |
| Description | `description` |
| Severity | `source_metadata.severity` |
| Status | `source_metadata.status` |
| Created time | `created_at` |
| Last modified time | `updated_at` |
| Alerts | `alerts` |
| Entities | `entities` |
| Tactics | `mitre_mappings.tactic` |
| Techniques | `mitre_mappings.technique_id` |

## Defender XDR Mapping

Recommended mapping:

| Source Field | ThreatPrism Field |
| --- | --- |
| Incident ID or alert ID | `source_case_id` |
| Incident name | `title` |
| Detection source | `alerts.source` |
| Classification | `source_metadata.classification` |
| Determination | `source_metadata.determination` |
| Evidence | `evidence` |
| User evidence | `entities` |
| Device evidence | `entities` |
| URL/IP/file evidence | `iocs` |

## Entra ID Logs

Identity events should normalize into:

- `events` for sign-in and audit events.
- `entities` for users, apps, service principals, devices, and IP addresses.
- `iocs` for IPs, domains, URLs, and suspicious user agents where appropriate.
- `evidence` for source log references and excerpts.

## Azure Monitor / Log Analytics / KQL Exports

ThreatPrism should accept exported rows as demo or batch input in a later phase.

The adapter should preserve:

- Query name or export name.
- Workspace identifier only when demo-safe or redacted.
- Row index.
- Source timestamp.
- Source table.

## Logic Apps / Power Automate

Logic Apps and Power Automate should be treated as webhook transport paths.

Required behavior:

- Accept a JSON body posted by workflow automation.
- Return a quick tracking response.
- Avoid requiring workflow secrets in demo mode.
- Document a sample workflow payload.

## Microsoft-Friendly, Provider-Agnostic Output

ThreatPrism report output should include fields Microsoft tools can consume later:

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "source": "sentinel",
  "source_case_id": "INC-100245",
  "triage": {
    "determination": "suspicious",
    "severity": "high",
    "disposition": "escalate",
    "confidence": 0.84
  },
  "links": {
    "triage_report": "/cases/case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX/triage-report"
  },
  "analyst_review_required": true
}
```

## Authentication

Authentication is out of scope for the spec pack implementation, but future Microsoft integrations should use:

- Environment variables for local demo settings.
- Managed identity where deployed in Azure.
- Least-privilege app registration where API access is required.
- No hardcoded tokens.

## Demo Restrictions

- Demo payloads must be fake.
- Live Sentinel, Defender, Graph, Entra, or Log Analytics credentials are not required for demos.
- Docs must not include real tenant IDs, workplace names, user names, or customer data.
