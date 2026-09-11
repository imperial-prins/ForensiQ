# 00 — Open Questions and Decisions

**Status:** implementation-backed

This document records decisions that affect the current ForensiQ build. Open questions are deliberately separated from shipped behavior.

## Resolved

| Topic | Decision |
|---|---|
| Email sources | RFC822/`.eml` and Gmail are adapters to one `NormalizedEmail` contract. |
| Gmail demo | `GMAIL_MODE=mock` is the safe default and is visibly labeled `DEMO MAILBOX`. |
| Gmail access | Live mode uses server-side Google OAuth with the read-only Gmail scope. Passwords are never collected. |
| Analysis authority | Risk score and signals are deterministic. AI can explain evidence but cannot set the score. |
| User safety | Recommendations are advisory. ForensiQ never deletes, replies, forwards, or modifies Gmail messages. |
| Correlation | Cases are related through shared sender, sender domain, URL/domain/IP, ASN, or attachment hash. |
| Storage | SQLite and local evidence files remain the MVP persistence layer. No new queue or service is required. |
| External lookups | Intelligence and GeoIP are passive adapters. ForensiQ does not fetch URLs from email content. |

## Deliberately open after the MVP

- Multi-user authentication and authorization.
- Durable encrypted token storage backed by a managed secret store.
- Gmail history/watch push notifications and incremental mailbox sync.
- Retention automation that deletes expired evidence after an explicit policy decision.
- Campaign analyst review workflow and analyst-authored labels.
- Production-scale job execution and PostgreSQL migration.

## Non-decisions

A missing live Google credential is **not** treated as a successful Gmail connection. The application stays in mock mode or reports `GMAIL_NOT_CONFIGURED` in live mode.
