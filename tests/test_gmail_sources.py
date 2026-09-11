import base64
from pathlib import Path

from backend.services.email_sources import (
    GmailSource,
    MockGmailSource,
    decode_gmail_raw_message,
)


def test_gmail_raw_mime_decoding_is_urlsafe_and_provider_neutral():
    raw = Path("data/samples/sample_legitimate.eml").read_bytes()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    decoded = decode_gmail_raw_message(encoded)

    assert decoded == raw


def test_malformed_gmail_payload_is_rejected():
    try:
        decode_gmail_raw_message("!!!!")
    except ValueError as exc:
        assert "malformed" in str(exc)
    else:
        raise AssertionError("malformed Gmail payload was accepted")


def test_mock_gmail_source_returns_realistic_mailbox_and_normalized_messages():
    source = MockGmailSource()
    messages = source.list_messages(limit=50)

    assert len(messages) >= 8
    assert all(message["source_type"] == "GMAIL_MOCK" for message in messages)
    assert {message["risk_hint"] for message in messages} >= {"SAFE", "SUSPICIOUS", "DANGEROUS"}

    normalized = source.get_message(messages[0]["message_id"])
    assert normalized.source_type == "GMAIL_MOCK"
    assert normalized.source_message_id == messages[0]["message_id"]
    assert normalized.text or normalized.html


def test_live_gmail_source_retrieves_metadata_and_normalizes_raw_message(monkeypatch):
    raw = Path("data/samples/sample_legitimate.eml").read_bytes()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    class FakeResponse:
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    def fake_request(method, url, **kwargs):
        if url.endswith("/messages"):
            return FakeResponse({"messages": [{"id": "gmail-message-1", "threadId": "gmail-thread-1"}]})
        if kwargs["params"].get("format") == "metadata":
            return FakeResponse({
                "threadId": "gmail-thread-1",
                "snippet": "A real mailbox preview",
                "payload": {"headers": [
                    {"name": "From", "value": "sender@example.com"},
                    {"name": "To", "value": "recipient@example.com"},
                    {"name": "Subject", "value": "Mailbox subject"},
                    {"name": "Date", "value": "Sat, 12 Sep 2026 10:00:00 +0000"},
                ]},
            })
        return FakeResponse({"threadId": "gmail-thread-1", "raw": encoded, "labelIds": ["INBOX"]})

    monkeypatch.setattr("backend.services.email_sources.requests.request", fake_request)
    source = GmailSource("server-only-access", "account-id", "real-user@gmail.com")

    summaries = source.list_messages(limit=1)
    normalized = source.get_message("gmail-message-1")

    assert summaries[0]["message_id"] == "gmail-message-1"
    assert summaries[0]["thread_id"] == "gmail-thread-1"
    assert summaries[0]["subject"] == "Mailbox subject"
    assert normalized.source_type == "GMAIL"
    assert normalized.source_message_id == "gmail-message-1"
    assert normalized.source_metadata["gmail_thread_id"] == "gmail-thread-1"
