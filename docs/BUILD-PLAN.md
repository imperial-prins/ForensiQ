# ForensiQ Build Plan

This is the implementation plan derived from the repository audit. It is intentionally short and will be removed or folded into the final documentation when the build is complete.

## Existing baseline

- FastAPI modular monolith in `backend/`.
- React/Vite/Tailwind SPA in `frontend/`.
- `backend/services/pipeline.py` already combines parsing, IOC extraction, intelligence, GeoIP, timeline, risk, graph, and AI fallback.
- SQLite stores the complete case report as JSON; evidence is preserved under `evidence/{case_id}/original.eml`.
- `.eml` upload, raw email paste, investigator tabs, deterministic scoring, mock intelligence, and evidence integrity already work.
- Existing tests and frontend build are green.

## Implementation slices

1. **Provider-neutral email model**
   - Add `NormalizedEmail` and `EmailSource` contracts.
   - Make `.eml` parsing produce the same normalized object used by Gmail.
   - Preserve the legacy parser dictionary and `analyze_email()` compatibility.

2. **Gmail sources**
   - Add a server-side OAuth configuration/state/token boundary.
   - Add a mock mailbox with realistic synthetic messages.
   - Add a live Gmail REST adapter using read-only scope and Gmail MIME `raw` decoding.
   - Add connect/status/messages/analyze/scan/disconnect routes.

3. **Single analysis pipeline**
   - Route both EML and Gmail messages through `analyze_normalized_email()`.
   - Persist source metadata and deduplicate by provider message identity.

4. **Explainability and correlation**
   - Add deterministic contradiction signals and evidence-linked user explanations.
   - Add conservative safe-action recommendations.
   - Add cross-case shared-indicator correlation and related-case endpoints.

5. **Dual-mode UI**
   - Make the default surface a mailbox-oriented protection dashboard.
   - Keep the existing deep evidence views behind `Investigate deeper`.
   - Clearly label mock Gmail and mock intelligence.

6. **Hardening and verification**
   - Add provider, OAuth, MIME, duplicate, correlation, prompt-injection, privacy, and failure-path tests.
   - Run pytest, Ruff, frontend lint/build, gitleaks, live backend/frontend checks, and an HTTP demo journey.

## Non-goals

No mailbox-wide default download, Gmail mutation actions, password collection, new microservices, new message queue, direct requests to email URLs, or fabricated live-provider status.
