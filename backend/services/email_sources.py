from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import requests

from backend.models.email import NormalizedEmail
from backend.services.email_parser import normalize_raw_email


class EmailSource(Protocol):
    source_type: str

    def list_messages(self, limit: int = 10) -> list[dict[str, Any]]: ...

    def get_message(self, message_id: str) -> NormalizedEmail: ...


def decode_gmail_raw_message(raw: str) -> bytes:
    """Decode Gmail's URL-safe base64 RFC822 payload without accepting junk."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Gmail response did not contain a raw MIME message")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        if not decoded:
            raise ValueError("Gmail raw MIME payload is empty")
        return decoded
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Gmail raw MIME payload is malformed") from exc


@dataclass(frozen=True, slots=True)
class MockMailboxMessage:
    message_id: str
    fixture: str | None
    raw: bytes | None
    risk_hint: str
    label: str


_ROOT = Path(__file__).resolve().parents[2]
_SAMPLE_DIR = _ROOT / "data" / "samples"


def _mail(text: str) -> bytes:
    return text.strip().encode("utf-8")


MOCK_MAILBOX: tuple[MockMailboxMessage, ...] = (
    MockMailboxMessage("mock-safe-newsletter", "sample_legitimate.eml", None, "SAFE", "Weekly payroll summary"),
    MockMailboxMessage(
        "mock-forensiq-credential-campaign",
        "forensiq_demo_credential_campaign.eml",
        None,
        "DANGEROUS",
        "CRITICAL: Microsoft 365 session expires - verify immediately",
    ),
    MockMailboxMessage(
        "mock-forensiq-sharepoint-campaign",
        "forensiq_demo_sharepoint_campaign.eml",
        None,
        "DANGEROUS",
        "A SharePoint document was shared with you",
    ),
    MockMailboxMessage(
        "mock-forensiq-voicemail-campaign",
        "forensiq_demo_voicemail_campaign.eml",
        None,
        "DANGEROUS",
        "New secure voicemail notification",
    ),
    MockMailboxMessage("mock-basic-phishing", "sample_basic_phishing.eml", None, "SUSPICIOUS", "Urgent account verification required"),
    MockMailboxMessage("mock-credential-phishing", "sample_phishing.eml", None, "DANGEROUS", "Mandatory email portal verification"),
    MockMailboxMessage(
        "mock-financial-fraud",
        None,
        _mail("""
From: accounts-payable@vendor-invoice.top
To: analyst@company.example
Subject: Urgent wire transfer request
Date: Fri, 11 Sep 2026 15:00:00 +0000
Message-ID: <mock-financial-fraud@vendor-invoice.top>
Reply-To: executive-request@protonmail.example
Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail
Received: from relay.vendor-invoice.top [203.0.113.44] by mx.company.example; Fri, 11 Sep 2026 15:00:02 +0000
Content-Type: text/plain; charset="UTF-8"

Please transfer the outstanding invoice amount today to avoid service interruption. Do not call the office; this is confidential.
"""),
        "DANGEROUS",
        "Urgent wire transfer request",
    ),
    MockMailboxMessage(
        "mock-malicious-attachment",
        None,
        _mail("""
From: shipping@delivery-notice.top
To: analyst@company.example
Subject: Delivery invoice attached
Date: Fri, 11 Sep 2026 16:00:00 +0000
Message-ID: <mock-malicious-attachment@delivery-notice.top>
Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="demo-boundary"

--demo-boundary
Content-Type: text/plain; charset="UTF-8"

Open the attached invoice immediately to release your package.
--demo-boundary
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--demo-boundary--
"""),
        "DANGEROUS",
        "Delivery invoice attached",
    ),
    MockMailboxMessage(
        "mock-sender-impersonation",
        None,
        _mail("""
From: Microsoft Security <security@microsoft-account-alert.top>
To: analyst@company.example
Subject: Microsoft account security alert
Date: Fri, 11 Sep 2026 17:00:00 +0000
Message-ID: <mock-sender-impersonation@microsoft-account-alert.top>
Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail
Received: from unfamiliar-host.example [198.51.100.42] by mx.company.example; Fri, 11 Sep 2026 17:00:02 +0000
Content-Type: text/plain; charset="UTF-8"

Microsoft detected unusual activity. Verify your Microsoft account now at http://login.microsoft-account-alert.top/verify.
"""),
        "DANGEROUS",
        "Microsoft account security alert",
    ),
    MockMailboxMessage("mock-reply-mismatch", "sample_reply_to_mismatch.eml", None, "SUSPICIOUS", "Service notification"),
    MockMailboxMessage("mock-suspicious-infrastructure", "sample_suspicious_infrastructure.eml", None, "SUSPICIOUS", "Delivery update"),
)


class EMLSource:
    """Adapter for one RFC822 upload; it never performs analysis itself."""

    source_type = "EML"

    def __init__(
        self,
        raw_bytes: bytes | str | None = None,
        source_message_id: str | None = None,
        account_id: str | None = None,
    ) -> None:
        self.raw_bytes = raw_bytes
        self.source_message_id = source_message_id
        self.account_id = account_id

    def normalize(
        self,
        raw_bytes: bytes | str | None = None,
        *,
        source_message_id: str | None = None,
        source_metadata: dict[str, Any] | None = None,
    ) -> NormalizedEmail:
        payload = raw_bytes if raw_bytes is not None else self.raw_bytes
        if payload is None:
            raise ValueError("EML source has no RFC822 payload")
        return normalize_raw_email(
            payload,
            source_type=self.source_type,
            source_message_id=source_message_id or self.source_message_id,
            account_id=self.account_id,
            source_metadata=source_metadata,
        )

    def list_messages(self, limit: int = 1) -> list[dict[str, Any]]:
        if self.raw_bytes is None or limit < 1:
            return []
        normalized = self.normalize()
        return [{
            "message_id": normalized.source_message_id,
            "source_type": self.source_type,
            "account_id": self.account_id,
            "subject": normalized.subject,
            "sender": normalized.from_address,
            "recipient": normalized.to,
            "date": normalized.date,
            "snippet": normalized.text[:240],
            "demo": False,
        }]

    def get_message(self, message_id: str | None = None) -> NormalizedEmail:
        normalized = self.normalize(source_message_id=message_id or self.source_message_id)
        if message_id and normalized.source_message_id != message_id:
            raise KeyError(message_id)
        return normalized


class MockGmailSource:
    source_type = "GMAIL_MOCK"

    def __init__(self, account_id: str = "demo-account") -> None:
        self.account_id = account_id
        self._messages = {message.message_id: message for message in MOCK_MAILBOX}

    def list_messages(self, limit: int = 10) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 50))
        summaries = []
        for message in MOCK_MAILBOX[:bounded_limit]:
            normalized = normalize_raw_email(
                self._raw(message),
                source_type=self.source_type,
                source_message_id=message.message_id,
                account_id=self.account_id,
            )
            summaries.append({
                "message_id": message.message_id,
                "source_type": self.source_type,
                "account_id": self.account_id,
                "subject": normalized.subject or message.label,
                "sender": normalized.from_address or "(unknown sender)",
                "recipient": normalized.to,
                "date": normalized.date,
                "snippet": normalized.text[:240] or message.label,
                "risk_hint": message.risk_hint,
                "demo": True,
            })
        return summaries

    def get_message(self, message_id: str) -> NormalizedEmail:
        message = self._messages.get(message_id)
        if message is None:
            raise KeyError(message_id)
        return normalize_raw_email(
            self._raw(message),
            source_type=self.source_type,
            source_message_id=message.message_id,
            account_id=self.account_id,
            source_metadata={"demo": True, "risk_hint": message.risk_hint, "label": message.label},
        )

    def _raw(self, message: MockMailboxMessage) -> bytes:
        if message.raw is not None:
            return message.raw
        if not message.fixture:
            raise ValueError(f"Mock fixture missing for {message.message_id}")
        return (_SAMPLE_DIR / message.fixture).read_bytes()


class GmailProviderError(RuntimeError):
    """A safe, user-facing error from the live Gmail API boundary."""


class GmailAuthError(GmailProviderError):
    pass


class GmailSource:
    source_type = "GMAIL"
    base_url = "https://gmail.googleapis.com/gmail/v1/users/me"

    def __init__(self, access_token: str, account_id: str, account_email: str | None = None) -> None:
        self.access_token = access_token
        self.account_id = account_id
        self.account_email = account_email or "Connected Gmail account"

    def list_messages(self, limit: int = 10) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 50))
        data = self._request(
            "GET",
            f"{self.base_url}/messages",
            params={"maxResults": bounded_limit, "labelIds": "INBOX", "q": "newer_than:30d"},
        )
        messages = []
        for item in data.get("messages", [])[:bounded_limit]:
            message_id = str(item.get("id", "")).strip()
            if not message_id:
                continue
            metadata = self._request(
                "GET",
                f"{self.base_url}/messages/{message_id}",
                params={"format": "metadata", "metadataHeaders": "From,To,Subject,Date"},
            )
            headers = {
                header.get("name", "").lower(): header.get("value", "")
                for header in metadata.get("payload", {}).get("headers", [])
            }
            messages.append({
                "message_id": message_id,
                "thread_id": str(metadata.get("threadId", "")),
                "source_type": self.source_type,
                "account_id": self.account_id,
                "subject": headers.get("subject", "(no subject)"),
                "sender": headers.get("from", "(unknown sender)"),
                "recipient": headers.get("to", ""),
                "date": headers.get("date", ""),
                "snippet": str(metadata.get("snippet", ""))[:240],
                "demo": False,
            })
        return messages

    def get_message(self, message_id: str) -> NormalizedEmail:
        if not message_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", message_id):
            raise ValueError("Invalid Gmail message id")
        data = self._request("GET", f"{self.base_url}/messages/{message_id}", params={"format": "raw"})
        raw_bytes = decode_gmail_raw_message(str(data.get("raw", "")))
        return normalize_raw_email(
            raw_bytes,
            source_type=self.source_type,
            source_message_id=message_id,
            account_id=self.account_id,
            source_metadata={"gmail_thread_id": data.get("threadId"), "label_ids": data.get("labelIds", [])},
        )

    def _request(self, method: str, url: str, *, params: dict[str, Any]) -> dict[str, Any]:
        try:
            response = requests.request(
                method,
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.access_token}"},
                timeout=10,
            )
        except requests.RequestException as exc:
            raise GmailProviderError("Gmail API is unavailable") from exc
        if response.status_code in {401, 403}:
            raise GmailAuthError("Gmail access is no longer valid; reconnect the account")
        if response.status_code == 429:
            raise GmailProviderError("Gmail rate limit reached; try again shortly")
        if response.status_code >= 400:
            raise GmailProviderError("Gmail returned an error while reading the mailbox")
        try:
            payload = response.json()
        except ValueError as exc:
            raise GmailProviderError("Gmail returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise GmailProviderError("Gmail returned an unexpected response")
        return payload


