# 01 — Software Requirements Specification

**Status:** implementation-backed MVP

## Product objective

ForensiQ helps an ordinary Gmail user decide whether an email is safe before interacting with it, while preserving a deep forensic view for security analysts. The product loop is:

`Gmail or .eml → normalize → forensic analysis → intelligence → correlation → deterministic risk → explanation → safe user action → optional investigation`

## Functional requirements

1. The system SHALL accept an RFC822 `.eml` upload or a message obtained through an EmailSource adapter.
2. Both sources SHALL become `NormalizedEmail` before entering the core pipeline.
3. The pipeline SHALL preserve headers, body text/HTML, authentication results, received headers, attachment metadata, IOCs, intelligence, GeoIP, graph, timeline, risk, AI explanation, and provenance.
4. The Gmail adapter SHALL support read-only OAuth, recent-message listing, selected-message analysis, limited scans, disconnect, revoked-access handling, and duplicate detection.
5. Mock Gmail SHALL expose synthetic safe, suspicious, and dangerous messages through the same pipeline.
6. Every report SHALL expose a deterministic numeric score and a user verdict: `SAFE`, `SUSPICIOUS`, or `DANGEROUS`.
7. Every material signal SHALL retain a description and evidence IDs.
8. User mode SHALL present plain-language reasons and conservative recommended actions before technical detail.
9. Investigator mode SHALL expose authentication, sender identity, Reply-To, Return-Path, IOCs, intelligence, GeoIP, routing, graph, evidence, AI analysis, and related cases.
10. Cross-case correlation SHALL show shared indicators, common infrastructure, recipients where available, confidence, and linked cases.
11. Email body content SHALL be treated as untrusted data at the AI boundary; invalid AI citations SHALL be discarded.
12. No automatic mailbox mutation SHALL be performed.

## Non-functional requirements

- Offline/mock operation must work without provider credentials.
- No access or refresh token may be returned to React.
- Logs must not contain full email bodies or OAuth secrets.
- URL text extracted from email content must not be fetched as a request target.
- Uploads are bounded at 25 MiB and unsafe filenames are rejected.
- Malformed messages and unavailable providers must produce bounded errors, not process crashes.
- The API is versioned under `/api/v1`.

## Current acceptance state

The current repository implements the requirements above for the local single-user MVP. Live Gmail requires Google OAuth configuration in `.env`; the repository never contains those credentials.
