# 05 — Risk Engine Specification

**Status:** implementation-backed, engine version `1.0`

## Authority

`backend/services/risk_engine.py` is the sole numeric authority. The frontend and AI explanation display its result; neither may recalculate or override it.

## Signal categories and caps

| Category | Cap |
|---|---:|
| Authentication | 30 |
| Sender | 25 |
| Intelligence | 35 |
| Content | 10 |
| URL | 25 |
| Attachment | 25 |
| Routing | 15 |
| Meta | 5 |

Score = the sum of each category total after its cap, limited to 100.

## Current signals

SPF/DKIM/DMARC fail or softfail, Reply-To mismatch, Return-Path mismatch, urgency language, IP-in-URL, suspicious TLD, malicious intelligence result, executable attachment, missing Received headers, identity contradiction, and multi-category agreement.

`IDENTITY_CONTRADICTION` is deterministic and carries evidence IDs, severity, confidence, explanation, and an 18-point sender contribution. It correlates claims and observed relationships; it does not claim that the concept itself is unprecedented.

## Bands

- `0–24`: `LOW` → user `SAFE`
- `25–49`: `MEDIUM` → user `SUSPICIOUS`
- `50–74`: `HIGH` → user `SUSPICIOUS`
- `75–100`: `CRITICAL` → user `DANGEROUS`

Confidence is based on successful intelligence queries, defaults to `0.5` without queries, and is explicitly `0.0` when all returned intelligence is mock data. This expresses provider confidence, not a probability that a human is malicious.
