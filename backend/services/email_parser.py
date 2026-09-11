from __future__ import annotations

import email
import hashlib
import ipaddress
import re
from email import policy
from email.message import Message
from pathlib import PurePath
from typing import Any

from bs4 import BeautifulSoup

from backend.models.email import NormalizedEmail

MAX_MIME_DEPTH = 20
MAX_ATTACHMENTS = 50
MAX_BODY_CHARS = 1_000_000
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BY_SERVER_REGEX = re.compile(r"\bby\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)


def _header_map(msg: Message) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    for key, value in msg.items():
        text = str(value)
        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(text)
            else:
                headers[key] = [headers[key], text]
        else:
            headers[key] = text
    return headers


def _safe_filename(filename: str | None) -> str:
    candidate = (filename or "unnamed_attachment").replace("\\", "/")
    return PurePath(candidate).name or "unnamed_attachment"


def _source_ips(received_headers: list[str]) -> list[str]:
    result: list[str] = []
    for candidate in IP_REGEX.findall("\n".join(received_headers)):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in result:
            result.append(candidate)
    return result


def _mail_servers(received_headers: list[str]) -> list[str]:
    result: list[str] = []
    for header in received_headers:
        match = BY_SERVER_REGEX.search(header)
        if match and match.group(1) not in result:
            result.append(match.group(1))
    return result


def normalize_raw_email(
    raw_email_content: str | bytes,
    *,
    source_type: str = "EML",
    source_message_id: str | None = None,
    account_id: str | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> NormalizedEmail:
    """Parse any RFC822 message into the single provider-neutral email contract."""
    raw_bytes = raw_email_content.encode("utf-8", errors="replace") if isinstance(raw_email_content, str) else bytes(raw_email_content)
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    headers = _header_map(msg)

    from_address = str(msg.get("From", ""))
    to = str(msg.get("To", ""))
    cc = str(msg.get("Cc", ""))
    subject = str(msg.get("Subject", ""))
    date = str(msg.get("Date", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    message_id = str(msg.get("Message-ID", ""))
    auth_results_header = str(msg.get("Authentication-Results", ""))
    received_headers = [str(item) for item in (msg.get_all("Received", []) or [])]
    spf_status, dkim_status, dmarc_status = extract_auth_status(msg, auth_results_header)

    body_text = ""
    body_html = ""
    attachments: list[dict[str, Any]] = []
    if msg.is_multipart():
        for part in msg.walk():
            if len(list(part.walk())) > MAX_MIME_DEPTH:
                continue
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition and len(attachments) < MAX_ATTACHMENTS:
                filename = _safe_filename(part.get_filename())
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "is_executable": filename.lower().endswith((
                        ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".iso", ".zip", ".rar", ".js"
                    )),
                })
            elif content_type == "text/plain" and "attachment" not in disposition:
                body_text += str(part.get_content())
            elif content_type == "text/html" and "attachment" not in disposition:
                body_html += str(part.get_content())
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_text = str(msg.get_content())
        elif content_type == "text/html":
            body_html = str(msg.get_content())

    if not body_text and body_html:
        body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ")
    body_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", body_text)[:MAX_BODY_CHARS]
    body_html = body_html[:MAX_BODY_CHARS]

    effective_source_id = source_message_id or message_id or f"local-{hashlib.sha256(raw_bytes).hexdigest()[:16]}"
    return NormalizedEmail(
        source_type=source_type,
        source_message_id=effective_source_id,
        account_id=account_id,
        from_address=from_address,
        to=to,
        cc=cc,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        message_id=message_id,
        date=date,
        text=body_text,
        html=body_html,
        attachments=attachments,
        received_headers=received_headers,
        mail_servers=_mail_servers(received_headers),
        source_ips=_source_ips(received_headers),
        auth={"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status, "raw_header": auth_results_header},
        auth_results_header=auth_results_header,
        all_headers=headers,
        raw_bytes=raw_bytes,
        source_metadata=source_metadata or {},
    )


def parse_raw_email(raw_email_content: str | bytes) -> dict[str, Any]:
    """Backward-compatible parser facade for the existing analysis services."""
    return normalize_raw_email(raw_email_content).to_analysis_dict()


def extract_auth_status(msg: Message, auth_header: str) -> tuple[str, str, str]:
    statuses = {"spf": "UNKNOWN", "dkim": "UNKNOWN", "dmarc": "UNKNOWN"}
    combined = auth_header.lower()
    received_spf = str(msg.get("Received-SPF", "")).lower()
    if received_spf:
        if "softfail" in received_spf:
            statuses["spf"] = "SOFTFAIL"
        elif "fail" in received_spf:
            statuses["spf"] = "FAIL"
        elif "pass" in received_spf:
            statuses["spf"] = "PASS"
    if statuses["spf"] == "UNKNOWN" and combined:
        if "spf=softfail" in combined:
            statuses["spf"] = "SOFTFAIL"
        elif "spf=fail" in combined:
            statuses["spf"] = "FAIL"
        elif "spf=pass" in combined:
            statuses["spf"] = "PASS"
    if combined:
        if "dkim=fail" in combined:
            statuses["dkim"] = "FAIL"
        elif "dkim=pass" in combined:
            statuses["dkim"] = "PASS"
        if "dmarc=fail" in combined:
            statuses["dmarc"] = "FAIL"
        elif "dmarc=pass" in combined:
            statuses["dmarc"] = "PASS"
    if statuses["dkim"] == "UNKNOWN" and msg.get("DKIM-Signature"):
        statuses["dkim"] = "PASS"
    return statuses["spf"], statuses["dkim"], statuses["dmarc"]
