# 16 — Investigator Mode

**Status:** implementation-backed

Investigator mode opens the same persisted case rather than re-running or duplicating analysis. It exposes:

- deterministic score, level, confidence, engine version, and signal breakdown;
- From, To, Reply-To, Return-Path, Message-ID, and authentication results;
- SPF, DKIM, DMARC, trust contradiction explanation, and evidence IDs;
- IPs, domains, URLs, email indicators, attachment hashes, and sources;
- passive intelligence and observed infrastructure GeoIP/ASN;
- Received-header routing timeline and anomalies;
- selectable relationship graph with node provenance;
- evidence hash and processing provenance;
- AI explanation with validated citations;
- related email clusters and shared infrastructure.

Technical detail is intentionally behind `Investigate deeper` in the normal-user flow. The investigator console is read-only with respect to Gmail.
