from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.email_sources import GmailSource, decode_gmail_raw_message
from backend.services.gmail import (
    GMAIL_READONLY_SCOPE,
    GmailSettings,
    authorization_url,
    connection_store,
    create_oauth_state,
    fetch_profile,
    get_source,
    validate_oauth_state,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_oauth_state_is_signed_and_expires(monkeypatch):
    settings = GmailSettings(True, "live", "client", "secret", "http://localhost/callback", "test-secret")
    state = create_oauth_state(settings)

    assert validate_oauth_state(state, settings)
    assert not validate_oauth_state(f"{state}tampered", settings)
    assert not validate_oauth_state(state, GmailSettings(True, "live", "client", "secret", "http://localhost/callback", "wrong"))


def test_authorization_url_requests_readonly_scope_and_signed_state():
    settings = GmailSettings(True, "live", "client-id", "secret", "http://localhost/callback", "test-secret")

    parsed = parse_qs(urlparse(authorization_url(settings)).query)

    assert parsed["scope"] == [GMAIL_READONLY_SCOPE]
    assert parsed["access_type"] == ["offline"]
    assert validate_oauth_state(parsed["state"][0], settings)


def test_oauth_callback_success_stores_profile_email_and_redirects(monkeypatch):
    monkeypatch.setenv("GMAIL_ENABLED", "true")
    monkeypatch.setenv("GMAIL_MODE", "live")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/gmail/oauth/callback")
    monkeypatch.setenv("FRONTEND_URL", "http://localhost:3000")
    settings = GmailSettings.from_env()
    state = create_oauth_state(settings)
    connection_store.disconnect()
    monkeypatch.setattr(
        "backend.api.endpoints.exchange_code",
        lambda code, configured: {"access_token": "server-only-access", "refresh_token": "server-only-refresh", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "backend.api.endpoints.fetch_profile",
        lambda access_token: {"emailAddress": "real-user@gmail.com", "historyId": "123"},
    )

    with TestClient(app, follow_redirects=False) as client:
        response = client.get("/api/v1/gmail/oauth/callback", params={"code": "one-time-code", "state": state})
        status = client.get("/api/v1/gmail/status")

    assert response.status_code == 303
    assert response.headers["location"] == "http://localhost:3000/?gmail=connected"
    assert "server-only" not in response.text
    assert status.json()["email_address"] == "real-user@gmail.com"
    assert status.json()["status"] == "connected"
    connection_store.disconnect()


def test_oauth_callback_failure_redirects_without_exposing_provider_details(monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", "http://localhost:3000")

    with TestClient(app, follow_redirects=False) as client:
        response = client.get("/api/v1/gmail/oauth/callback", params={"error": "access_denied"})

    assert response.status_code == 303
    location = parse_qs(urlparse(response.headers["location"]).query)
    assert location["gmail"] == ["error"]
    assert location["gmail_error"] == ["GMAIL_OAUTH_DENIED"]


def test_gmail_profile_retrieval_uses_authenticated_google_response(monkeypatch):
    monkeypatch.setattr(
        "backend.services.gmail.requests.get",
        lambda *args, **kwargs: FakeResponse(200, {"emailAddress": "authenticated@gmail.com", "historyId": "456"}),
    )

    profile = fetch_profile("server-only-access")

    assert profile["emailAddress"] == "authenticated@gmail.com"


def test_expired_access_token_uses_refresh_token(monkeypatch):
    monkeypatch.setenv("GMAIL_ENABLED", "true")
    monkeypatch.setenv("GMAIL_MODE", "live")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost/callback")
    connection_store.connect_live({"access_token": "expired-access", "refresh_token": "refresh-token", "expires_in": -1, "email": "user@example.com"})
    refresh_calls = []

    def fake_post(url, **kwargs):
        refresh_calls.append((url, kwargs))
        return FakeResponse(200, {"access_token": "refreshed-access", "expires_in": 3600})

    monkeypatch.setattr("backend.services.gmail.requests.post", fake_post)

    source = get_source()

    assert isinstance(source, GmailSource)
    assert source.access_token == "refreshed-access"
    assert refresh_calls[0][1]["data"]["refresh_token"] == "refresh-token"
    connection_store.disconnect()


def test_live_connect_does_not_fake_connection_without_credentials(monkeypatch):
    monkeypatch.setenv("GMAIL_MODE", "live")
    monkeypatch.setenv("GMAIL_ENABLED", "true")
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
    connection_store.disconnect()

    with TestClient(app) as client:
        response = client.post("/api/v1/gmail/connect")

    assert response.status_code == 503
    assert response.json()["detail"]["error"]["code"] == "GMAIL_NOT_CONFIGURED"
    monkeypatch.setenv("GMAIL_MODE", "mock")


def test_revoked_live_access_is_reported_as_reauthentication(monkeypatch):
    monkeypatch.setenv("GMAIL_MODE", "live")
    monkeypatch.setenv("GMAIL_ENABLED", "true")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost/callback")
    connection_store.connect_live({"access_token": "server-only-token", "email": "user@example.com"})
    monkeypatch.setattr("backend.services.email_sources.requests.request", lambda *args, **kwargs: FakeResponse(401, {}))

    with TestClient(app) as client:
        response = client.get("/api/v1/gmail/messages")

    assert response.status_code == 401
    assert response.json()["detail"]["error"]["code"] == "GMAIL_REAUTH_REQUIRED"
    connection_store.disconnect()
    monkeypatch.setenv("GMAIL_MODE", "mock")


def test_live_adapter_uses_readonly_gmail_request(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse(200, {"messages": []})

    monkeypatch.setattr("backend.services.email_sources.requests.request", fake_request)
    source = GmailSource("server-only-token", "account", "user@example.com")

    assert source.list_messages(10) == []
    assert calls[0][0] == "GET"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer server-only-token"
    assert calls[0][2]["params"]["labelIds"] == "INBOX"
    assert "gmail.readonly" not in calls[0][2]["params"]


def test_malformed_gmail_raw_payload_is_rejected():
    with pytest.raises(ValueError):
        decode_gmail_raw_message("not valid base64 ***")
