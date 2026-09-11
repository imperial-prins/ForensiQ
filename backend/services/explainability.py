from __future__ import annotations

from typing import Any

VERDICT_BY_LEVEL = {
    "LOW": "SAFE",
    "MEDIUM": "SUSPICIOUS",
    "HIGH": "SUSPICIOUS",
    "CRITICAL": "DANGEROUS",
}

SIGNAL_COPY = {
    "SPF_FAIL": (
        "Sender authentication failed",
        "The sending server was not authorized by the sender domain.",
    ),
    "DKIM_FAIL": (
        "Message signature failed",
        "The message could not be verified as signed by the claimed sender.",
    ),
    "DMARC_FAIL": (
        "Sender identity could not be verified",
        "The visible sender identity did not pass the domain's anti-spoofing policy.",
    ),
    "REPLY_TO_MISMATCH": (
        "Reply destination is different",
        "Replies would go to a different domain than the address shown in the From field.",
    ),
    "RETURN_PATH_MISMATCH": (
        "Return path is different",
        "The mail delivery path does not match the visible sender domain.",
    ),
    "IDENTITY_CONTRADICTION": (
        "Sender identity does not line up",
        "The sender, authentication, organization claim, or link infrastructure conflicts.",
    ),
    "URGENCY_KEYWORDS": (
        "The message creates pressure",
        "Urgent deadlines and account threats are common ways to make people act before checking.",
    ),
    "IP_IN_URL": (
        "A link points directly to an IP address",
        "Legitimate services usually use a recognizable domain rather than a raw IP in a login link.",
    ),
    "SUSPICIOUS_TLD": (
        "A link uses a high-abuse domain ending",
        "The domain ending is frequently used in disposable or deceptive campaigns.",
    ),
    "MALICIOUS_IP": (
        "Infrastructure was flagged by threat intelligence",
        "The extracted IP address matched the configured intelligence result.",
    ),
    "MALICIOUS_DOMAIN": (
        "A domain was flagged by threat intelligence",
        "The extracted domain matched the configured intelligence result.",
    ),
    "DANGEROUS_ATTACHMENT": (
        "The message includes a risky attachment",
        "The attachment type can execute code or contain a packaged payload.",
    ),
    "NO_RECEIVED_HEADERS": (
        "The routing trail is incomplete",
        "There were no Received headers to verify the path through mail servers.",
    ),
    "MULTIPLE_SUSPICIOUS_SIGNALS": (
        "Several different warning signs agree",
        "The evidence spans multiple parts of the message instead of relying on one clue.",
    ),
}


def recommend_safe_actions(parsed: dict[str, Any], risk_level: str) -> list[dict[str, Any]]:
    content = f"{parsed.get('metadata', {}).get('subject', '')} {parsed.get('body_text', '')}".lower()
    attachments = parsed.get("attachments", [])
    actions: list[dict[str, Any]] = []

    def add(action: str, reason: str) -> None:
        if action not in {item["action"] for item in actions}:
            actions.append({"action": action, "reason": reason, "automated": False})

    if risk_level in {"HIGH", "CRITICAL"} or any(keyword in content for keyword in ("verify", "login", "password", "credential")):
        add("Do not click links in this message.", "The analysis found phishing or identity-risk indicators.")
        add("Do not enter your password or security code from this message.", "A message can imitate a trusted service while sending credentials elsewhere.")
        add("Report the message as phishing, then delete or quarantine it.", "Reporting helps protect the mailbox and preserves the message for review.")
    if any(keyword in content for keyword in ("wire transfer", "transfer", "invoice", "payment", "bank", "gift card")):
        add("Do not transfer money or change payment details from this message.", "Financial requests should be verified through a known, independent channel.")
        add("Verify the request using a phone number or website you already trust.", "Do not use contact details supplied by the suspicious message.")
    if any(attachment.get("is_executable") for attachment in attachments):
        add("Do not open the attachment.", "Executable or packaged files can install malware.")
        add("Quarantine or delete the attachment and run endpoint security scanning.", "This limits the chance of accidental execution.")
    if not actions:
        add("No unsafe action is indicated by the current evidence.", "The deterministic checks did not find a material warning sign.")
        add("Still verify unexpected requests through a trusted channel.", "A low score is not proof that every message is genuine.")
    return actions


def build_user_explanation(parsed: dict[str, Any], risk: dict[str, Any]) -> dict[str, Any]:
    level = str(risk.get("level", "LOW"))
    signals = risk.get("signals", [])
    reasons = []
    for signal in sorted(signals, key=lambda item: float(item.get("weight", 0)), reverse=True):
        signal_id = str(signal.get("signal_id", ""))
        title, explanation = SIGNAL_COPY.get(
            signal_id,
            (str(signal.get("description", "Security signal")), str(signal.get("description", "Verified analysis signal."))),
        )
        reasons.append({
            "title": title,
            "explanation": explanation,
            "technical": signal.get("description", ""),
            "severity": "HIGH" if float(signal.get("weight", 0)) >= 15 else "MEDIUM",
            "evidence_ids": signal.get("evidence_ids") or [signal_id],
            "signal_id": signal_id,
        })
    verdict = VERDICT_BY_LEVEL.get(level, "SUSPICIOUS")
    return {
        "verdict": verdict,
        "headline": {
            "SAFE": "This email looks safe based on the available evidence.",
            "SUSPICIOUS": "This email has warning signs worth checking before you interact with it.",
            "DANGEROUS": "This email is dangerous. Treat it as a likely attack.",
        }[verdict],
        "why": reasons[:6],
        "what_to_do": recommend_safe_actions(parsed, level),
        "technical_disclosure": {
            "risk_level": level,
            "risk_score": risk.get("score", 0),
            "authentication": parsed.get("auth", {}),
            "progressive_disclosure": True,
        },
        "provenance": "DETERMINISTIC_ANALYSIS",
    }
