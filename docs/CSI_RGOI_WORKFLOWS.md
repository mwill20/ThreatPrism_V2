# CSI/RGOI Workflows

These workflows use fake demo data only. They describe how the read-only
CSI/RGOI foundation supports analysts, managers, legal/privacy reviewers,
auditors, and engineers without making AI authoritative.

## Analyst Workflow

1. Analyst opens a case and reviews the current triage report.
2. Analyst queries `GET /csi/objects?tenant_id=tenant_demo_alpha&query=identity`.
3. ThreatPrism returns evidence-linked cognitive objects and explains active
   retrieval controls.
4. Analyst compares the AI-proposed interpretation with the human-approved
   interpretation.
5. Analyst uses `GET /csi/lineage/{object_id}` to reconstruct how the
   interpretation traces back to immutable evidence.
6. Analyst makes the final decision through the existing analyst feedback
   workflow. CSI/RGOI does not publish the decision automatically.

## Manager/GRC Workflow

1. Manager uses a manager/GRC demo credential.
2. Manager queries manager-safe knowledge objects through
   `GET /csi/objects?tenant_id=tenant_demo_alpha&purpose=manager_review`.
3. Retrieval policy blocks SOC-operational objects that are not in the
   manager-safe zone.
4. Manager sees approved summaries only, with evidence references and
   governance notes.
5. Any compliance or control language remains advisory and human-reviewed.

## Legal/Privacy Workflow

1. Legal/privacy reviewer uses a legal/privacy demo credential.
2. Reviewer queries for privacy-relevant cognition through the legal/privacy
   purpose.
3. ThreatPrism applies retrieval-zone policy and healthcare safeguard scanning
   before returning objects.
4. Reviewer can inspect exposure metadata and audit/debug-scoped objects when
   policy permits.
5. The workflow does not expose raw PHI, real PII, secrets, or token vault
   mappings.

## Audit/Debug Workflow

1. Auditor or engineer uses an authorized audit/debug or engineer role.
2. Reviewer calls `GET /csi/replay/{object_id}`.
3. ThreatPrism returns immutable evidence IDs, visible lineage object IDs, a
   deterministic input hash, and limitations.
4. The replay response reconstructs governed inputs only. It does not rerun an
   LLM and does not mutate evidence, trust, or knowledge.

## Engineering Workflow

1. Engineer inspects `GET /csi/observability` for visible object counts,
   stale cognition counts, AI non-authoritative counts, and active controls.
2. Engineer uses `GET /csi/divergence` to verify AI-vs-human disagreement is
   visible for regression testing.
3. Engineer runs `tests/test_csi_rgoi.py` or the full validation wrapper.
4. Any future write-back, RAG, live LLM, non-demo data, or production tenancy
   work must reopen the threat model treatment register first.
