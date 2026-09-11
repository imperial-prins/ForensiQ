from __future__ import annotations

from email.utils import parseaddr
from typing import Any

from backend.services.risk_engine import DetectionSignal

ORG_DOMAINS = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "google": ("google.com", "googlemail.com"),
    "apple": ("apple.com", "icloud.com"),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.co.uk"),
    "docusign": ("docusign.com",),
}


def address_domain(value: str) -> str:
    address = parseaddr(value or "")[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def _ioc_ids(iocs: dict[str, Any], values: set[str]) -> list[str]:
    return [
        item["ioc_id"]
        for item in iocs.get("items", [])
        if item.get("normalized_value", item.get("value", "")).lower() in values
        or item.get("value", "").lower() in values
    ]


def detect_trust_contradictions(
    parsed: dict[str, Any],
    iocs: dict[str, Any],
    existing_signals: list[DetectionSignal] | tuple[DetectionSignal, ...] = (),
) -> list[dict[str, Any]]:
    """Correlate identity claims without asking an LLM to decide trust."""
    metadata = parsed.get("metadata", {})
    from_domain = address_domain(metadata.get("from", ""))
    reply_domain = address_domain(metadata.get("reply_to", ""))
    return_domain = address_domain(metadata.get("return_path", ""))
    content = f"{metadata.get('subject', '')} {parsed.get('body_text', '')}".lower()
    link_domains = {
        item.get("normalized_value", "").lower()
        for item in iocs.get("items", [])
        if item.get("type") == "DOMAIN"
    }
    evidence_ids: list[str] = []
    reasons: list[str] = []

    if reply_domain and from_domain and reply_domain != from_domain:
        reasons.append("The visible sender and reply destination use different domains.")
        evidence_ids.extend(signal.signal_id for signal in existing_signals if signal.signal_id == "REPLY_TO_MISMATCH")
    if return_domain and from_domain and return_domain != from_domain:
        reasons.append("The return path does not match the visible sender domain.")
        evidence_ids.extend(signal.signal_id for signal in existing_signals if signal.signal_id == "RETURN_PATH_MISMATCH")

    failed_auth = [signal.signal_id for signal in existing_signals if signal.category == "AUTHENTICATION"]
    if failed_auth:
        evidence_ids.extend(failed_auth)
        reasons.append("Sender authentication has one or more failed checks.")

    claimed_org: str | None = None
    for organization in ORG_DOMAINS:
        if organization in content:
            claimed_org = organization
            break
    if claimed_org:
        allowed_domains = ORG_DOMAINS[claimed_org]
        sender_matches = any(from_domain == domain or from_domain.endswith(f".{domain}") for domain in allowed_domains)
        link_matches = any(domain == allowed or domain.endswith(f".{allowed}") for domain in link_domains for allowed in allowed_domains)
        if not sender_matches:
            reasons.append(f"The message claims to represent {claimed_org.title()}, but the sender domain is {from_domain or 'missing'}.")
        if link_domains and not link_matches:
            reasons.append("The message's links do not use the claimed organization's domain.")

    if link_domains and from_domain and any(domain != from_domain for domain in link_domains):
        reasons.append("A link domain differs from the visible sender domain.")
        evidence_ids.extend(_ioc_ids(iocs, link_domains))

    if not reasons:
        return []
    evidence_ids = list(dict.fromkeys(evidence_ids))
    return [{
        "type": "IDENTITY_CONTRADICTION",
        "severity": "HIGH" if len(reasons) >= 2 else "MEDIUM",
        "evidence_ids": evidence_ids or ["IDENTITY_CONTRADICTION"],
        "explanation": " ".join(reasons),
        "confidence": round(min(0.99, 0.68 + (0.08 * min(len(reasons), 4))), 2),
        "risk_contribution": 18,
        "provenance": "DERIVED",
        "claimed_organization": claimed_org,
    }]


def contradiction_signals(contradictions: list[dict[str, Any]]) -> list[DetectionSignal]:
    return [
        DetectionSignal(
            "IDENTITY_CONTRADICTION",
            "IDENTITY_CONTRADICTION",
            "SENDER",
            float(item["risk_contribution"]),
            item["explanation"],
            tuple(item["evidence_ids"]),
        )
        for item in contradictions
    ]
