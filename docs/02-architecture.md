# 02 — Architecture

**Status:** implementation-backed

## System shape

```text
EMLSource ───────┐
                 ├─> NormalizedEmail ─> canonical analysis pipeline ─> Case/SQLite
MockGmailSource ─┤                                      │
GmailSource ────┘                                      ├─> Protection mode
                                                       └─> Investigator mode
```

## Backend modules

- `backend/models/email.py` — provider-neutral `NormalizedEmail` dataclass.
- `backend/services/email_parser.py` — RFC822/MIME parsing, auth extraction, attachment metadata, normalization.
- `backend/services/email_sources.py` — `EmailSource` protocol, mock mailbox, Gmail REST adapter, Gmail raw MIME decoding.
- `backend/services/gmail.py` — environment settings, signed OAuth state, process-local server-side connection store, token refresh boundary.
- `backend/services/pipeline.py` — the only analysis pipeline. It runs IOC extraction, intelligence, GeoIP, timeline, contradiction signals, risk, graph, and AI explanation.
- `backend/services/contradictions.py` — deterministic sender/identity/infrastructure contradiction analysis.
- `backend/services/explainability.py` — user verdict copy and safe-action recommendations.
- `backend/services/correlation.py` — cross-case shared-indicator relationships and clusters.
- `backend/database/db.py` — SQLite persistence and source-identity lookup.
- `backend/api/endpoints.py` — upload, case, dashboard, Gmail, and correlation routes.

## Trust boundaries

1. Email body and headers are attacker-controlled data.
2. Local observations are distinct from external intelligence results.
3. AI receives a structured evidence envelope, not instructions from the email.
4. Gmail tokens are held by the backend connection store and are never serialized into reports or frontend responses.
5. The frontend receives bounded case previews; raw HTML is not rendered in the email preview.

## Deliberate simplicity

This is a FastAPI/React modular monolith with SQLite. There are no microservices, queues, mailbox-wide default downloads, or Gmail mutation operations. External adapters are synchronous and bounded for the local MVP.
