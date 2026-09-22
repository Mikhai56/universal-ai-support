# Integration and security audit

Date: 2026-09-22

## Scope
Reviewed the SupportPilot main code used as the base for integration/production-supportpilot and the lead-processing-agent productionize/lead-pipeline branch.

## Findings
- No obvious malware indicators were found in the inspected source: no eval, shell execution, subprocess execution, suspicious download commands, or embedded credentials.
- Secrets are read from environment variables; .env and local database files are ignored by Git.
- The lead-processing branch uses PostgreSQL, UUID lead IDs, explicit workflow states, BotID, Slack approval, and Resend. Several connectors (CRM, tech-stack analysis, and knowledge-base) are placeholders and were not copied as if they were complete integrations.
- The two projects use different runtimes (Python and Next.js/TypeScript), so directly mixing their framework files would create a fragile deployment. The safe integration path is to keep SupportPilot as the primary service and add the useful lead state model behind its existing API.
- The new lead pipeline stores only validated contact fields and redacts card/CVV-like data before persistence.

## Integration implemented
- Added lead_pipeline.py with PostgreSQL/SQLite support.
- Added persistent lead states: NEW, RESEARCHING, QUALIFIED, PENDING_APPROVAL, SENT, REJECTED, FAILED.
- Added authenticated operator endpoints for listing and updating leads.
- Added public POST /api/leads intake with basic validation.
- Added unit tests for lead creation, state updates, and email validation.

## Remaining production checks
- Run the full test suite and CI.
- Add rate limiting/authentication for public lead intake if it will be exposed beyond the app UI.
- Add real research/CRM/KB integrations only after their credentials and contracts are defined.
- Review PostgreSQL TLS configuration before production; the source branch currently allows rejectUnauthorized=false for its own PG client.
- Do not merge to main until CI and security checks pass.
