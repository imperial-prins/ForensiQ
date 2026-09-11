# ForensiQ — AI-Powered Email Security & Investigation

ForensiQ helps people decide whether an email is safe before they interact with it, while giving security analysts a deeper evidence view. Gmail and `.eml` messages share one pipeline:

```text
Gmail / .eml → NormalizedEmail → forensics → intelligence → correlation
            → deterministic risk → user explanation → safe action
            → optional investigator console
```

## What is working

- Provider-neutral `NormalizedEmail` and `EmailSource` abstraction.
- RFC822 `.eml` upload and mock Gmail mailbox through the same analysis engine.
- Live Gmail OAuth/API adapter using server-side read-only credentials when configured.
- SPF/DKIM/DMARC extraction, Received routing, IOC/attachment extraction, passive intelligence, GeoIP, graph, timeline, evidence hash, and SQLite cases.
- Deterministic risk score and evidence-linked `SAFE` / `SUSPICIOUS` / `DANGEROUS` explanation.
- Conservative safe-action recommendations; no automatic Gmail mutation.
- Trust contradiction signals and cross-email related-case clusters.
- Protection mode for normal users and investigator mode for analysts.
- AI analyst with structured evidence, citation validation, prompt-injection boundary, and deterministic fallback.

## Quick start

From the repository root:

```bash
# Backend
.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000

# In another terminal
npm --prefix frontend run dev -- --host 0.0.0.0 --port 3000
```

Open:

- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- API docs: http://localhost:8000/docs
- Versioned health: http://localhost:8000/api/v1/health

The default `.env.example` configuration uses `GMAIL_MODE=mock`, so no Google credential is needed for the demo. Copy it to `.env` only when changing settings. For real-account evaluation, follow `docs/20-google-cloud-oauth.md`, set `GMAIL_MODE=live`, and never commit real credentials.

## Demo flow

1. Open the frontend.
2. Click **Connect Gmail**.
3. Confirm the visible **DEMO MAILBOX** label.
4. Select **Scan recent emails** or analyze a suspicious message.
5. Read the verdict, plain-language reasons, and conservative actions.
6. Use **Investigate deeper** to inspect authentication, IOCs, intelligence, GeoIP, routing, graph, evidence, AI citations, and related emails.
7. Upload `data/samples/sample_phishing.eml` and verify that it produces the same kind of case with source `EML`.

### Malicious campaign showcase

For a complete first-round demonstration, open **CRITICAL: Microsoft 365 session expires - verify immediately**. This is a clearly labeled synthetic/inert campaign message designed to populate every Investigator tab: Overview, Authentication, Indicators, Intelligence, GeoIP, Timeline, Graph, Evidence, and Related emails. The walkthrough and exact fixture files are documented in [`docs/21-demo-malicious-campaign.md`](docs/21-demo-malicious-campaign.md).

## Configuration

Important variables are documented in `.env.example`:

```dotenv
GMAIL_ENABLED=true
GMAIL_MODE=mock
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/gmail/oauth/callback
FRONTEND_URL=http://localhost:3000
GMAIL_OAUTH_STATE_SECRET=
INTEL_MODE=mock
GEOIP_MODE=mock
```

For live Gmail, set `GMAIL_MODE=live` and server-side Google OAuth credentials. The application uses `gmail.readonly`; it never asks for a Gmail password, returns OAuth tokens to React, or mutates messages. If credentials are missing, live connect fails honestly with `GMAIL_NOT_CONFIGURED`. The OAuth callback validates state, retrieves the authenticated Gmail profile address, stores the local connection, and redirects to `FRONTEND_URL/?gmail=connected`.

## Verification

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check backend tests
npm --prefix frontend run lint
npm --prefix frontend run build
gitleaks detect --no-git --verbose
```

## Repository guide

- `backend/services/pipeline.py` — canonical analysis pipeline.
- `backend/services/email_sources.py` — EML/Gmail/mock source adapters.
- `backend/services/gmail.py` — OAuth and server-side connection boundary.
- `backend/services/contradictions.py`, `explainability.py`, `correlation.py` — product intelligence layers.
- `frontend/src/App.jsx` — protection/investigator application flow.
- `docs/14-gmail-integration.md` through `docs/19-product-differentiation.md` — current product documentation.
- `data/samples/` — synthetic messages only.

## Explicit limitations

This is a local single-user MVP. Live OAuth tokens are process-local, retention deletion is documented but not scheduled, and multi-user auth, push sync, sandboxing, production queues, and managed database deployment are intentionally deferred.
