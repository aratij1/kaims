alert_id: DW-1010
alert_name: Schema Drift Detected
service: customer-ingestion
severity: critical
alert_type: schema_change
source_system: internal
source_ref: DW-1010
dependencies: Not explicitly documented.
deployment: Not explicitly documented.
execution_plan: Regenerate ingestion schemas

# Schema Drift Detected (DW-1010)

Service: customer-ingestion
Severity: CRITICAL
Alert type: schema_change

## Summary
Schema drift was detected between source and warehouse ingestion mapping.

## Symptoms
- New fields not mapped
- Transformation errors
- Downstream type mismatches

## Root Cause
- Source schema modification
- New columns added

## Impact
- Service: customer-ingestion Severity: CRITICAL Alert type: schema_change

## Dependencies
- Not explicitly documented.

## Deployment Context
- Not explicitly documented.

## Execution Plan
- Regenerate ingestion schemas

## Investigation Timeline
1. Compare source and target schema
2. Review recent source changes
3. Check ingestion mapping versions

## Remediation
- Update ingestion mappings
- Regenerate schemas
- Validate transformations

## Prevention
- Review the incident pattern and update the runbook or automation as needed.

## SOP Notes
- This document was derived from RAG_doc.docx and is intended for retrieval, SOPs, and runbook-driven operations.
