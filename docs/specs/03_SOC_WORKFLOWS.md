# 03 SOC Workflows

## Workflow Overview

ThreatPrism supports this SOC workflow:

1. Alert intake.
2. Evidence normalization.
3. Entity extraction.
4. IOC extraction.
5. IOC enrichment.
6. MITRE mapping.
7. Timeline generation.
8. Hypothesis generation.
9. Severity recommendation.
10. Disposition recommendation.
11. Control mapping.
12. Analyst approval.
13. Report generation.
14. Analyst feedback capture.
15. Management and engineering metrics.

## Case States

Recommended case states:

- `received`
- `normalized`
- `queued_for_triage`
- `triage_running`
- `triage_completed`
- `needs_analyst_review`
- `analyst_feedback_submitted`
- `closed`
- `failed`

State transitions must be recorded in the audit trail.

## Evolution 1: Batch Triage Over SOAR-Automated Cases

### Goal

Review cases already closed or suppressed by SOAR automation.

### Flow

1. Operator imports a batch of SOAR-automated cases.
2. ThreatPrism normalizes each case.
3. Triage jobs run in batch mode.
4. Reports identify suspicious or high-risk cases that automation may have missed.
5. SOC analyst reviews high-risk disagreements.
6. SOC manager reviews automation quality metrics.

### Outputs

- Automation validation summary.
- Cases where ThreatPrism disagreed with SOAR closure.
- High-risk cases that need analyst review.
- Evidence-linked triage reports.
- Detection engineering notes.

## Evolution 2: Batch Review Of Human Analyst Determinations

### Goal

Compare ThreatPrism assessments to human analyst determinations.

### Flow

1. Operator imports cases previously handled by analysts.
2. ThreatPrism runs triage using available evidence.
3. Analyst decisions are submitted or imported as feedback.
4. ThreatPrism records disagreement fields.
5. Managers and detection engineers review patterns.

### Disagreement Dimensions

- Determination mismatch.
- Severity mismatch.
- Confidence gap.
- Disposition mismatch.
- Missed IOC.
- Missed MITRE mapping.
- Missed escalation.
- False positive.
- False negative.

### Outputs

- Analyst decision QA report.
- Case-level disagreement record.
- Aggregate disagreement metrics.
- Training and process-improvement candidates.
- Detection engineering backlog items.

## Evolution 3: Parallel Per-Event SOAR Triage

### Goal

Run ThreatPrism in parallel with SOAR handling without delaying incident response.

### Flow

1. SOAR posts a case payload to ThreatPrism.
2. ThreatPrism validates the envelope and stores the raw payload hash.
3. ThreatPrism returns immediately with `case_id`, `tracking_id`, and `triage_status`.
4. Triage runs asynchronously.
5. Analyst continues working in the SOAR.
6. ThreatPrism exposes the report via API and can optionally post a callback in future versions.
7. Analyst submits feedback.

### Required Response Pattern

```json
{
  "case_id": "case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX",
  "tracking_id": "triage_01JZ7NQ2VBE3D9HB4C2M9P3VMF",
  "triage_status": "queued",
  "message": "Case accepted. Triage will run asynchronously.",
  "report_url": "/cases/case_01JZ7NPZHV7Y7Y9D2PF3A2V3NX/triage-report"
}
```

## Analyst Review Workflow

1. Analyst opens a completed triage report.
2. Analyst reviews summary, evidence, timeline, IOCs, MITRE mappings, GRC mappings, limitations, and simulated actions.
3. Analyst chooses final determination, severity, disposition, and confidence.
4. Analyst records notes and missed elements.
5. ThreatPrism calculates disagreement metrics.
6. Manager review is flagged when policy requires it.

## Manager Review Triggers

`manager_review_required` should be set or recommended when:

- ThreatPrism severity is `high` or `critical` and analyst closes the case.
- ThreatPrism determination is `malicious` or `critical` and analyst marks `benign`.
- Analyst identifies a false negative.
- ThreatPrism recommends escalation and analyst closes without escalation.
- The case includes high-impact identity, endpoint, or data-exposure indicators.

## Metrics

Dashboard-ready metrics should include:

- Case volume by source.
- Triage completion rate.
- Guardrail block rate.
- Determination disagreement rate.
- Severity disagreement rate.
- False-positive and false-negative counts.
- Average time to acknowledge.
- Average time to close.
- Missed IOC count.
- Missed MITRE mapping count.
- Cases requiring manager review.
- SOAR automation quality indicators.
