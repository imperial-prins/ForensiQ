# 12 — MVP Scope and Prioritization

**Status:** implementation-backed

## Shipped in this build

- Provider-neutral `NormalizedEmail` and `EmailSource` boundary.
- RFC822 upload and legacy parser compatibility.
- Mock Gmail mailbox with eight synthetic scenarios.
- Live Gmail OAuth URL/callback boundary and read-only REST adapter.
- Recent listing, selected analysis, bounded scans, duplicate reuse, disconnect, and failure handling.
- Deterministic forensic pipeline, risk, contradiction analysis, user explanations, safe actions, graph, timeline, intelligence, GeoIP, AI fallback, and SQLite cases.
- Protection mode and investigator mode in one React app.
- Cross-case shared-indicator relationships and clusters.
- Prompt-injection citation validation, CORS allowlist, upload bounds, and evidence integrity.

## Deferred intentionally

Multi-user auth/RBAC, push synchronization, durable encrypted token storage, background workers, sandbox execution, automatic mailbox actions, managed retention deletion, PostgreSQL, Kubernetes, and production campaign response workflows.

## MVP completion rule

A capability is considered shipped only when it is exercised by tests or the live demo. Documentation labels configured-live provider behavior separately from offline/demo behavior.
