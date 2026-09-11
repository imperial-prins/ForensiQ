from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class NormalizedEmail:
    """Provider-neutral email contract consumed by the analysis pipeline."""

    source_type: str
    source_message_id: str
    account_id: str | None
    from_address: str
    to: str
    cc: str
    reply_to: str
    return_path: str
    subject: str
    message_id: str
    date: str
    text: str
    html: str
    attachments: list[dict[str, Any]] = field(default_factory=list)
    received_headers: list[str] = field(default_factory=list)
    mail_servers: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)
    auth_results_header: str = ""
    all_headers: dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = field(default=b"", repr=False)
    source_metadata: dict[str, Any] = field(default_factory=dict)

    def to_analysis_dict(self) -> dict[str, Any]:
        """Return the legacy parser shape used by existing analysis services."""
        return {
            "metadata": {
                "from": self.from_address,
                "to": self.to,
                "cc": self.cc,
                "subject": self.subject,
                "date": self.date,
                "reply_to": self.reply_to,
                "return_path": self.return_path,
                "message_id": self.message_id,
                "received_headers": list(self.received_headers),
                "mail_servers": list(self.mail_servers),
                "source_ips": list(self.source_ips),
                "auth_results_header": self.auth_results_header,
                "source_type": self.source_type,
                "source_message_id": self.source_message_id,
                "account_id": self.account_id,
                "source_metadata": dict(self.source_metadata),
            },
            "auth": dict(self.auth),
            "body_text": self.text,
            "body_html": self.html,
            "attachments": [dict(attachment) for attachment in self.attachments],
            "all_headers": dict(self.all_headers),
            "normalized_email": self.public_dict(),
        }

    def public_dict(self) -> dict[str, Any]:
        """Serialize metadata without exposing raw bytes or credentials."""
        return {
            "source_type": self.source_type,
            "source_message_id": self.source_message_id,
            "account_id": self.account_id,
            "from": self.from_address,
            "to": self.to,
            "cc": self.cc,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date,
            "text": self.text,
            "html": self.html,
            "attachments": [dict(attachment) for attachment in self.attachments],
            "received_headers": list(self.received_headers),
            "mail_servers": list(self.mail_servers),
            "source_ips": list(self.source_ips),
            "auth": dict(self.auth),
            "source_metadata": dict(self.source_metadata),
        }
