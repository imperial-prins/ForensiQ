# 14 — Gmail Integration

**Status:** implementation-backed; live Google OAuth is ready for credentialed evaluation

## Configuration

```dotenv
GMAIL_ENABLED=true
GMAIL_MODE=live
GOOGLE_CLIENT_ID=[REDACTED]
GOOGLE_CLIENT_SECRET=[REDACTED]
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/gmail/oauth/callback
FRONTEND_URL=http://localhost:3000
GMAIL_OAUTH_STATE_SECRET=[REDACTED]
```

`mock` remains the default when no live credentials are available and is explicitly labeled **DEMO MAILBOX**. `live` requires all Google settings; otherwise connect returns `GMAIL_NOT_CONFIGURED` instead of pretending to be connected. Google Cloud setup and Testing-mode requirements are in `docs/20-google-cloud-oauth.md`.

## Live flow

1. `POST /api/v1/gmail/connect` returns a Google authorization URL with the read-only `gmail.readonly` scope and signed state.
2. Google redirects to the exact backend callback: `http://localhost:8000/api/v1/gmail/oauth/callback`.
3. The backend verifies state, exchanges the code server-side, and calls Gmail `/users/me/profile`.
4. The authenticated `emailAddress` from Gmail becomes the connected account identity; no address is taken from user input.
5. The backend stores account metadata and access/refresh tokens in the process-local connection store, then redirects to `FRONTEND_URL/?gmail=connected`.
6. The frontend reads `/api/v1/gmail/status`, displays the account address, and fetches recent Inbox metadata.
7. Gmail raw MIME is fetched only when a message is opened/analyzed or included in a bounded scan.

## Shared message path

```text
Gmail API → GmailSource → NormalizedEmail → analyze_normalized_email → persisted case
```

Gmail message summaries include sender, subject, date, snippet, message ID, and thread ID. URL-safe base64 MIME is decoded and normalized before entering the same analysis pipeline used by `.eml` uploads; there is no Gmail-specific analysis pipeline.

## Lifecycle and errors

- `Refresh Mail` fetches the current recent-message list again and updates `last_sync_at`.
- `Disconnect` removes the process-local account/token reference.
- Near-expiry access tokens use the stored refresh token when available.
- Revoked/expired access returns a safe reconnect message rather than a stack trace.
- OAuth cancellation, denied permission, state failure, provider failure, and malformed messages have bounded UI messages.
- No Gmail mutation endpoint exists.

## Security and limitations

- Gmail passwords are never requested.
- Client secrets and OAuth tokens are backend-only.
- OAuth state is signed and age-validated.
- Email content is not written to application logs.
- Gmail message IDs are validated before message retrieval.
- For this local single-user MVP, account metadata and tokens are process-local; restarting the backend requires reconnecting. Encrypted persistent multi-user storage and background sync are deferred.

## Mock scenarios

Safe newsletter, basic phishing, credential phishing, financial fraud, malicious attachment, sender impersonation, Reply-To mismatch, and suspicious infrastructure are available through `MockGmailSource`; they remain synthetic and are never presented as a real account.
