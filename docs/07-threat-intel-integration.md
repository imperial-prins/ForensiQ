# 07 — Threat Intelligence Integration

**Status:** implementation-backed

## Provider boundary

`backend/services/intelligence.py` exposes normalized results from mock, VirusTotal, and AbuseIPDB adapters. `backend/services/geolocation.py` provides mock or passive ip-api GeoIP results. All results carry provider, status, query type/value, risk tag, summary, and provenance.

## Modes

- `INTEL_MODE=mock` — deterministic offline responses for synthetic indicators.
- `INTEL_MODE=live` — only credentialed adapters are queried; unavailable credentials remain unavailable.
- `GEOIP_MODE=mock` — deterministic offline location records.
- `GEOIP_MODE=live` — bounded passive lookup to the configured GeoIP service.

## Safety

The system never performs `requests.get()` on a URL extracted from a message. URL intelligence is represented as data and may be queried only through an explicitly configured provider adapter. Provider failures lower confidence and do not become a clean result.

## Provenance in UI

Local observation, external intelligence, and AI interpretation are shown as separate processing layers in the investigator view and privacy banner.
