# 06 — AI Analyst Specification

**Status:** implementation-backed

## Boundary

The AI analyst receives a structured evidence envelope containing bounded metadata, authentication, Received headers, extracted IOCs, provider results, GeoIP, timeline, risk signals, attachment metadata, and a 500-character body snippet. Email content is explicitly labeled untrusted data and never becomes an instruction.

## Authority rules

- The deterministic risk score is authoritative.
- AI output must be JSON and is validated before storage.
- Classification is constrained to known classes.
- Suspicious indicators without an evidence ID in the supplied envelope are discarded.
- Confidence, text, and lists are bounded.
- The fallback explanation is used when the key is unavailable, the provider fails, or output is malformed.
- AI cannot claim a provider match, location, action, score, or attribution that is not present in evidence.

## User explanation

The deterministic explanation layer maps evidence to:

`evidence → technical interpretation → plain-language reason → conservative action`.

The AI may improve the analyst narrative, but `user_explanation` and `safe_actions` remain deterministic and are the first surface for ordinary users.

## Prompt-injection test

A body containing instructions such as “ignore previous instructions” remains only in the body snippet. The structured evidence validator removes fabricated citations and the system prompt states that email data is not instructions.
