# 09 — Forensic Timeline Specification

**Status:** implementation-backed

`parse_received_headers()` reverses the Received-header order into a chronological hop display, bounded to 20 headers. Each hop can include from/by server, source IP, protocol, queue ID, recipient, timestamp, confidence, raw header, and anomalies.

Current anomaly detection includes missing timestamp and timestamp reversal. Missing Received headers produce an explicit routing signal and an empty timeline rather than a fabricated path.

The user view does not show this detail by default. Investigator mode exposes the timeline and clearly labels it as observed mail-routing evidence.
