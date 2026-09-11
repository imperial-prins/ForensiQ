# 13 — Test Plan

**Status:** implementation-backed

## Automated coverage

The repository currently runs 29 tests covering:

- legacy parser compatibility and malformed/structured inputs;
- normalized EML contract and one-pipeline execution;
- mock mailbox size, MIME decoding, and source metadata;
- authentication, IOC extraction, risk caps, intelligence, and safe actions;
- contradiction evidence and cross-case relationships;
- Gmail connect/status/list/analyze/scan/duplicate/case retrieval;
- signed OAuth state, missing live configuration, revoked access, read-only request shape, malformed raw MIME;
- prompt-injection citation filtering and AI fallback boundaries;
- upload size/missing input, evidence integrity, graph access, and API health.

Run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check backend tests
cd frontend && npm run lint && npm run build
```

## Manual live journey

1. Start backend and frontend.
2. Open the frontend and confirm `Gmail not connected`.
3. Click Connect Gmail; confirm `DEMO / MOCK MAILBOX`.
4. List messages, analyze a credential-phishing message, inspect `Why?` and safe actions.
5. Open `Investigate deeper`; inspect authentication, IOCs, intelligence, GeoIP, timeline, graph, evidence, and related cases.
6. Run a 10-message scan and confirm duplicate reuse on a second scan.
7. Upload `data/samples/sample_phishing.eml` and confirm it appears as an EML case.
8. Verify `/api/v1/health`, `/docs`, frontend HTTP response, and gitleaks.

## Known testing boundary

There is no real Google account in the repository, so live OAuth/Gmail API calls require operator-provided credentials and are verified with adapter tests rather than fabricated integration success.
