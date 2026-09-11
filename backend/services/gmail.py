from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import requests

from backend.services.email_sources import (
    GmailAuthError,
    GmailProviderError,
    GmailSource,
    MockGmailSource,
)

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_STATE_SECRET = secrets.token_bytes(32)


@dataclass(frozen=True, slots=True)
class GmailSettings:
    enabled: bool
    mode: str
    client_id: str
    client_secret: str
    redirect_uri: str
    state_secret: str
    frontend_url: str = "http://localhost:3000"

    @classmethod
    def from_env(cls) -> GmailSettings:
        mode = os.getenv("GMAIL_MODE", "mock").strip().lower() or "mock"
        enabled = os.getenv("GMAIL_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
        return cls(
            enabled=enabled,
            mode=mode,
            client_id=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/gmail/oauth/callback").strip(),
            state_secret=os.getenv("GMAIL_OAUTH_STATE_SECRET", "").strip(),
            frontend_url=os.getenv("FRONTEND_URL", "http://localhost:3000").strip().rstrip("/"),
        )

    @property
    def live_configured(self) -> bool:
        return self.enabled and self.mode == "live" and all((self.client_id, self.client_secret, self.redirect_uri))


@dataclass(slots=True)
class GmailConnection:
    mode: str
    account_id: str
    account_email: str
    display_name: str = "Connected Gmail"
    provider: str = "gmail"
    status: str = "connected"
    connected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_sync_at: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: float = 0.0


class GmailConnectionStore:
    """Process-local token boundary for the single-user local deployment."""

    def __init__(self) -> None:
        self._connection: GmailConnection | None = None

    def connect_mock(self) -> GmailConnection:
        self._connection = GmailConnection(
            "mock",
            "demo-account",
            "demo@codeflux.local",
            display_name="DEMO / MOCK MAILBOX",
        )
        return self._connection

    def connect_live(self, payload: dict[str, Any]) -> GmailConnection:
        account_email = str(payload.get("email") or payload.get("emailAddress") or "").strip()
        if not account_email:
            raise GmailProviderError("Gmail profile did not return an email address")
        account_id = str(payload.get("user_id") or account_email)
        self._connection = GmailConnection(
            "live",
            account_id,
            account_email,
            display_name=str(payload.get("display_name") or payload.get("name") or account_email),
            access_token=str(payload["access_token"]),
            refresh_token=str(payload.get("refresh_token") or "") or None,
            expires_at=time.time() + float(payload.get("expires_in", 3600)),
        )
        return self._connection

    def get(self) -> GmailConnection | None:
        return self._connection

    def disconnect(self) -> None:
        self._connection = None

    def mark_sync(self) -> None:
        if self._connection:
            self._connection.last_sync_at = datetime.now(timezone.utc).isoformat()


connection_store = GmailConnectionStore()


def _secret(settings: GmailSettings) -> bytes:
    return (settings.state_secret.encode() if settings.state_secret else _STATE_SECRET)


def create_oauth_state(settings: GmailSettings) -> str:
    payload = f"{int(time.time())}:{secrets.token_urlsafe(18)}".encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(_secret(settings), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def validate_oauth_state(state: str, settings: GmailSettings, max_age_seconds: int = 600) -> bool:
    try:
        encoded, signature = state.split(".", 1)
        expected = hmac.new(_secret(settings), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = encoded + "=" * (-len(encoded) % 4)
        timestamp = int(base64.urlsafe_b64decode(padded.encode()).decode().split(":", 1)[0])
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error):
        return False
    return 0 <= time.time() - timestamp <= max_age_seconds


def authorization_url(settings: GmailSettings) -> str:
    state = create_oauth_state(settings)
    query = urlencode({
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri,
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "scope": GMAIL_READONLY_SCOPE,
        "state": state,
    })
    return f"https://accounts.google.com/o/oauth2/v2/auth?{query}"


def exchange_code(code: str, settings: GmailSettings) -> dict[str, Any]:
    if not code or not settings.live_configured:
        raise GmailProviderError("Gmail OAuth is not configured")
    try:
        response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "redirect_uri": settings.redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        raise GmailProviderError("Google OAuth is unavailable") from exc
    if response.status_code >= 400:
        raise GmailProviderError("Google OAuth could not exchange the authorization code")
    try:
        payload = response.json()
    except ValueError as exc:
        raise GmailProviderError("Google OAuth returned malformed JSON") from exc
    if not payload.get("access_token"):
        raise GmailProviderError("Google OAuth did not return an access token")
    return payload


def fetch_profile(access_token: str) -> dict[str, Any]:
    try:
        response = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
    except requests.RequestException as exc:
        raise GmailProviderError("Gmail profile is unavailable") from exc
    if response.status_code in {401, 403}:
        raise GmailAuthError("Gmail access was rejected")
    if response.status_code >= 400:
        raise GmailProviderError("Gmail profile could not be read")
    try:
        payload = response.json()
    except ValueError as exc:
        raise GmailProviderError("Gmail profile returned malformed JSON") from exc
    if not isinstance(payload, dict) or not str(payload.get("emailAddress", "")).strip():
        raise GmailProviderError("Gmail profile did not return an email address")
    return payload


def get_source() -> MockGmailSource | GmailSource:
    settings = GmailSettings.from_env()
    if not settings.enabled:
        raise GmailProviderError("Gmail integration is disabled")
    connection = connection_store.get()
    if not connection:
        raise GmailProviderError("Connect a Gmail account first")
    if connection.mode == "mock":
        return MockGmailSource(connection.account_id)
    if not connection.access_token:
        raise GmailAuthError("Gmail access token is missing; reconnect the account")
    if connection.expires_at and connection.expires_at <= time.time() + 30 and connection.refresh_token:
        _refresh_connection(connection, settings)
    return GmailSource(connection.access_token, connection.account_id, connection.account_email)


def _refresh_connection(connection: GmailConnection, settings: GmailSettings) -> None:
    try:
        response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "refresh_token": connection.refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        raise GmailAuthError("Gmail token refresh is unavailable") from exc
    if response.status_code >= 400:
        raise GmailAuthError("Gmail access expired; reconnect the account")
    try:
        payload = response.json()
    except ValueError as exc:
        raise GmailAuthError("Gmail token refresh returned malformed JSON") from exc
    if not payload.get("access_token"):
        raise GmailAuthError("Gmail token refresh did not return an access token")
    connection.access_token = str(payload.get("access_token", ""))
    connection.expires_at = time.time() + float(payload.get("expires_in", 3600))
