# Implementation Status

## Verified product path

`Gmail mock or .eml → NormalizedEmail → canonical analysis pipeline → SQLite case → Protection mode / Investigator mode`

## Delivered

- Normalized provider contract and source adapters.
- Mock Gmail with eight synthetic scenarios and clear demo labeling.
- Live OAuth/API adapter, read-only scope, signed state, token refresh boundary, provider error handling, and no fake live status.
- Deterministic forensics, IOC extraction, authentication, intelligence, GeoIP, timeline, graph, risk, evidence hash, contradiction analysis, safe actions, and user explanation.
- Cross-case correlation and related-case endpoints.
- Evidence-bounded AI fallback/validation and prompt-injection tests.
- Mailbox-oriented React UI with progressive disclosure and investigator tabs.
- Updated configuration and product documentation.

## Current verification

- Backend tests: see `pytest`; current suite covers 29 paths.
- Ruff: clean.
- Frontend Oxlint: clean.
- Frontend Vite production build: clean.
- Mock Gmail: verified through API tests and live demo journey.
- Real Gmail OAuth: code path implemented; credentials are intentionally not present in the repository.

## Deferred honestly

Multi-user auth, durable encrypted token storage, push sync, automatic retention deletion, background jobs, sandboxing, managed database deployment, and Gmail mutation actions.
