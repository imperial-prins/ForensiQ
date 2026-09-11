# 17 — Privacy and Data Handling

**Status:** implementation-backed MVP policy

## Boundaries

| Layer | Data | Handling |
|---|---|---|
| Local observation | headers, body extraction, attachments metadata, routing | parsed locally and stored in the case report/evidence file for this local demo |
| External intelligence | normalized IOC queries | sent only to explicitly configured passive adapters; results are labeled external |
| AI processing | bounded structured evidence and body snippet | sent only when Gemini credentials are configured; fallback is deterministic |
| OAuth | Google access/refresh tokens | backend-only process-local store; never returned to React or logs |

No Gmail password is requested. HTML is not rendered in the preview. Extracted URLs are never visited. Logging code records exception types/provider status rather than message bodies or tokens.

## Retention

The local MVP keeps SQLite reports and `evidence/{case_id}/original.eml` until an operator removes them. `RETENTION_DAYS=30` documents the intended default, but automatic deletion is intentionally deferred until a durable retention job is designed and verified.

## User-visible disclosure

The UI states when mock mailbox or mock intelligence is active, distinguishes local observation from external processing, and states that AI is advisory. A case is not presented as proof of attacker identity; GeoIP is infrastructure geography.
