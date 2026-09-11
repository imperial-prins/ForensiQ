# 18 — Cross-Email Correlation

**Status:** implementation-backed

After cases are persisted, `correlate_cases()` compares normalized indicators without re-running email analysis. It considers:

- exact sender and sender domain;
- URL, domain, IP, and extracted email indicators;
- GeoIP ASN when available;
- attachment SHA-256.

A relationship records the case IDs, shared indicators, common infrastructure, confidence, and provenance. Connected relationships form a `Potential related email cluster` with message count, affected recipients where present, common infrastructure, and linked cases.

Correlation is evidence-based and cautious: shared indicators create a review lead, not automatic attribution or a claim that messages came from the same actor. The investigator view exposes the cluster under `Related emails`; APIs are `/cases/{case_id}/related` and `/correlation/clusters`.
