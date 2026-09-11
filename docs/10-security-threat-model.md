# 10 — Security Threat Model

**Status:** implementation-backed

## Assets

Gmail OAuth access/refresh tokens, local evidence files, email bodies and headers, case reports, intelligence credentials, and the integrity hash.

## Threats and controls

| Threat | Control |
|---|---|
| Password collection | No Gmail password field; Google OAuth only. |
| Token exposure | Tokens remain in backend process memory; status and reports omit them. |
| OAuth CSRF | Signed, time-bounded state value is verified at callback. |
| Revoked/expired access | Gmail 401/403 becomes `GMAIL_REAUTH_REQUIRED`; refresh is server-side. |
| Prompt injection | Email is untrusted data; structured evidence and citation validation constrain AI. |
| XSS in HTML mail | HTML is not rendered in the read-only preview; case detail strips body HTML. |
| SSRF | Extracted URLs are never used as request targets. |
| Upload abuse | 25 MiB bound, unsafe filename rejection, MIME metadata-only attachment handling. |
| Credential leakage in logs | Provider errors log only exception types in the existing adapters; raw bodies/tokens are not logged. |
| Gmail mutation | No delete/reply/forward/modify API scope or route exists. |
| Fake provider status | Live mode without credentials returns `GMAIL_NOT_CONFIGURED`; mock mode is visibly labeled. |
| Duplicate processing | Source type/message/account identity lookup reuses an existing case. |

## Residual risks

This is a local single-user MVP. OAuth tokens are process-local rather than encrypted in a durable secret store, SQLite is not multi-tenant, and retention automation is documented but not yet scheduled. These are not hidden behind production claims.
