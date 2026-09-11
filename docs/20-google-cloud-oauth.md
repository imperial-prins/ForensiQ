# Google Cloud setup for real Gmail OAuth

ForensiQ uses the server-side Google OAuth authorization-code flow and requests only the read-only Gmail scope:

`https://www.googleapis.com/auth/gmail.readonly`

## Configure Google Cloud

1. Open **Google Cloud Console**: <https://console.cloud.google.com/>.
2. **Create or select a project**.
3. Open **APIs & Services → Library**, search for **Gmail API**, and click **Enable**.
4. Open **APIs & Services → OAuth consent screen**.
   - Choose the appropriate user type for the project.
   - Enter the application name and required support/developer contact details.
   - Add the Gmail read-only scope if Google asks for scopes.
   - If the app is in **Testing** mode, add every evaluator's Google address under **Test users**. Testing-mode consent and refresh authorization can be limited to the listed test users.
5. Open **APIs & Services → Credentials → Create credentials → OAuth client ID**.
6. Choose **Application type: Web application**.
7. Under **Authorized redirect URIs**, add this exact URI:

   `http://localhost:8000/api/v1/gmail/oauth/callback`

   The URI must match `GOOGLE_REDIRECT_URI` exactly, including scheme, host, port, path, and trailing-slash behavior. If the backend is intentionally run on another host/port, register that exact replacement and set the environment variable to the same value.
8. Create the client, then copy the **Client ID** and **Client secret**.

## Configure ForensiQ locally

From the repository root:

```bash
cp .env.example .env
```

Edit `.env` and set the server-side values:

```dotenv
GMAIL_ENABLED=true
GMAIL_MODE=live
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/gmail/oauth/callback
FRONTEND_URL=http://localhost:3000
GMAIL_OAUTH_STATE_SECRET=use-a-long-random-local-secret
```

Do not put these values in React or commit `.env`. The client secret, access token, and refresh token remain on the backend. ForensiQ never asks for a Gmail password.

Start the application in two terminals:

```bash
.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
npm --prefix frontend run dev -- --host 0.0.0.0 --port 3000
```

Open <http://localhost:3000>, choose **Connect Gmail**, complete Google's consent screen, and return through the backend callback. The callback validates OAuth state, exchanges the code, reads the authenticated Gmail profile, stores the account/token in the local process, and redirects to the frontend. The frontend then displays the returned Gmail address and fetches recent messages.

## Google-side development notes

- A redirect URI mismatch is usually caused by using `127.0.0.1` in one place and `localhost` in another. Use the exact URI above for the default demo.
- An OAuth app in **Testing** status requires evaluator accounts to be listed as test users. The evaluator may also see Google's unverified-app warning; continue only if the project owner and scope are trusted.
- Re-authorize after changing OAuth consent-screen scopes or client configuration.
- If access is revoked or the refresh token expires, ForensiQ shows a reconnect message; it does not request a Gmail password or fall back to credentials pasted into the app.

## MVP limitation

For this local single-user evaluation build, the connected account and OAuth tokens are stored process-locally. Restarting the backend clears the connection and requires reconnecting. Persistent encrypted multi-user token storage is intentionally deferred.
