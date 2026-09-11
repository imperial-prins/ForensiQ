# 04 — API Contract

**Status:** implementation-backed

Base path: `/api/v1`. Error responses use `{ "detail": { "error": { "code", "message", "details" } } }`.

## Core analysis and cases

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | API liveness |
| `GET` | `/dashboard` | Counts and case summaries |
| `POST` | `/analyze` | Multipart `.eml` or `raw_email` form; creates an EML case |
| `GET` | `/cases` | Paginated case summaries |
| `GET` | `/cases/{case_id}` | Bounded user/investigator case report |
| `GET` | `/cases/{case_id}/status` | Completion state |
| `GET` | `/cases/{case_id}/verdict` | Deterministic risk assessment |
| `GET` | `/cases/{case_id}/evidence` | Evidence hash/integrity status |
| `GET` | `/cases/{case_id}/timeline` | Routing hops |
| `GET` | `/cases/{case_id}/graph` | Nodes and edges |
| `GET` | `/cases/{case_id}/related` | Related cases/clusters |
| `GET` | `/correlation/clusters` | All current cross-case clusters |
| `GET` | `/history` | Recent summaries |

## Gmail

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/gmail/connect` | Connect mock mode or return a live OAuth URL |
| `GET` | `/gmail/oauth/callback` | Verify state, exchange code, retrieve the authenticated profile, store tokens server-side, redirect to the frontend |
| `GET` | `/gmail/status` | Connection/configuration metadata; never tokens |
| `GET` | `/gmail/messages?limit=10\|25\|50` | Recent/relevant message metadata |
| `POST` | `/gmail/messages/{message_id}/analyze` | Analyze one message, reusing an existing source identity |
| `POST` | `/gmail/scan` | Analyze a bounded number of recent messages |
| `POST` | `/gmail/disconnect` | Clear the server-side local connection |

`/gmail/status` exposes provider, connection status, authenticated account email, display name, connected time, and last sync time; it never exposes tokens. `/gmail/messages` returns recent message ID, thread ID, sender, subject, date, and snippet. Scan response includes `analyzed_count`, `reused_count`, `failed_count`, bounded error identities, and case summaries. Gmail errors distinguish disabled configuration, OAuth reauthentication, malformed message, provider unavailable, and rate limit conditions.

## Security contract

- Live mode requires `GMAIL_MODE=live` and all server-side Google OAuth settings.
- The frontend never receives access or refresh tokens.
- Gmail scope is read-only.
- No route mutates Gmail messages.
- URL values from a message are data, not request targets.
