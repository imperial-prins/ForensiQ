from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from backend.models.email import NormalizedEmail
from backend.services.ai_analyst import analyze_with_ai, build_structured_evidence
from backend.services.contradictions import (
    contradiction_signals,
    detect_trust_contradictions,
)
from backend.services.email_parser import normalize_raw_email
from backend.services.email_sources import EMLSource
from backend.services.explainability import build_user_explanation
from backend.services.forensic import generate_routing_graph_dot, parse_received_headers
from backend.services.intelligence import enrich_geo, enrich_iocs
from backend.services.ioc_extractor import extract_iocs
from backend.services.risk_engine import DetectionSignal, RiskAssessment, calculate_risk


def _domain(address: str) -> str:
    parsed = parseaddr(address)[1]
    return parsed.rsplit("@", 1)[-1].lower() if "@" in parsed else ""


def build_signals(
    parsed: dict[str, Any],
    iocs: dict[str, Any],
    intel: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    auth = parsed.get("auth", {})
    for status, weight in (("spf", 15), ("dkim", 15), ("dmarc", 10)):
        if auth.get(status) == "FAIL":
            signals.append(DetectionSignal(f"{status.upper()}_FAIL", f"{status.upper()}_FAIL", "AUTHENTICATION", weight, f"{status.upper()} authentication failed"))
        elif auth.get(status) == "SOFTFAIL":
            signals.append(DetectionSignal(f"{status.upper()}_SOFTFAIL", f"{status.upper()}_SOFTFAIL", "AUTHENTICATION", 8, f"{status.upper()} authentication softfailed"))

    metadata = parsed.get("metadata", {})
    from_domain = _domain(metadata.get("from", ""))
    reply_domain = _domain(metadata.get("reply_to", ""))
    return_domain = _domain(metadata.get("return_path", ""))
    if reply_domain and reply_domain != from_domain:
        signals.append(DetectionSignal("REPLY_TO_MISMATCH", "REPLY_TO_MISMATCH", "SENDER", 12, "Reply-To domain differs from From domain"))
    if return_domain and return_domain != from_domain:
        signals.append(DetectionSignal("RETURN_PATH_MISMATCH", "RETURN_PATH_MISMATCH", "SENDER", 8, "Return-Path domain differs from From domain"))

    content = f"{metadata.get('subject', '')} {parsed.get('body_text', '')}".lower()
    if any(keyword in content for keyword in ("urgent", "verify immediately", "account suspended", "within 24 hours", "security warning", "transfer today")):
        signals.append(DetectionSignal("URGENCY_KEYWORDS", "URGENCY_KEYWORDS", "CONTENT", 8, "Urgency or phishing keywords detected"))
    for item in iocs.get("items", []):
        if item["type"] == "URL" and re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", item["value"]):
            signals.append(DetectionSignal("IP_IN_URL", "IP_IN_URL", "URL", 15, "URL uses a raw IP address", (item["ioc_id"],)))
        if item["type"] == "DOMAIN" and item["value"].endswith((".xyz", ".top", ".click", ".zip")):
            signals.append(DetectionSignal("SUSPICIOUS_TLD", "SUSPICIOUS_TLD", "URL", 10, "Domain uses a high-abuse TLD", (item["ioc_id"],)))
    for item in intel:
        if item["risk_tag"] == "MALICIOUS":
            signal_id = f"MALICIOUS_{item['query_type']}"
            if not any(signal.signal_id == signal_id for signal in signals):
                signals.append(DetectionSignal(signal_id, signal_id, "INTELLIGENCE", 20, f"Threat intelligence marked {item['query_value']} malicious", (item["ioc_id"],)))
    for attachment in parsed.get("attachments", []):
        if attachment.get("is_executable"):
            signals.append(DetectionSignal("DANGEROUS_ATTACHMENT", "DANGEROUS_ATTACHMENT", "ATTACHMENT", 20, "Executable or archive attachment present"))
    if not timeline:
        signals.append(DetectionSignal("NO_RECEIVED_HEADERS", "NO_RECEIVED_HEADERS", "ROUTING", 8, "No Received headers were available"))

    contradictions = detect_trust_contradictions(parsed, iocs, signals)
    signals.extend(contradiction_signals(contradictions))
    if len({signal.category for signal in signals}) >= 3:
        signals.append(DetectionSignal("MULTIPLE_SUSPICIOUS_SIGNALS", "MULTIPLE_SUSPICIOUS_SIGNALS", "META", 5, "Signals span at least three categories"))
    return signals


def analyze_email(
    raw_email: str | bytes,
    *,
    source_type: str = "EML",
    source_message_id: str | None = None,
    account_id: str | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility entry point for raw RFC822 input."""
    if source_type == "EML":
        normalized = EMLSource(account_id=account_id).normalize(
            raw_email,
            source_message_id=source_message_id,
            source_metadata=source_metadata,
        )
    else:
        normalized = normalize_raw_email(
            raw_email,
            source_type=source_type,
            source_message_id=source_message_id,
            account_id=account_id,
            source_metadata=source_metadata,
        )
    return analyze_normalized_email(normalized)


def analyze_normalized_email(normalized: NormalizedEmail) -> dict[str, Any]:
    """The one core analysis pipeline shared by EML and Gmail providers."""
    evidence_bytes = normalized.raw_bytes
    parsed = normalized.to_analysis_dict()
    iocs = extract_iocs(parsed)
    intel = enrich_iocs(iocs["items"])
    geo = enrich_geo(iocs["ips"])
    timeline = parse_received_headers(parsed["metadata"]["received_headers"])
    signals = build_signals(parsed, iocs, intel, timeline)
    risk: RiskAssessment = calculate_risk(
        signals,
        expected_intelligence_queries=len(intel),
        successful_intelligence_queries=sum(result["status"] in {"SUCCESS", "CACHED"} for result in intel),
        mock_intelligence=bool(intel) and all(result["provider"] == "MOCK" for result in intel),
    )
    case_id = str(uuid.uuid4())
    case_number = f"CASE-{case_id.replace('-', '').upper()[:8]}"
    graph = build_graph(parsed, iocs, intel, geo, timeline)
    structured_evidence = build_structured_evidence(parsed, iocs, intel, geo, timeline, risk)
    ai_explanation = analyze_with_ai(
        structured_evidence,
        deterministic_explanation(parsed, iocs, risk),
    )
    risk_payload = {
        "score": risk.score,
        "level": risk.level,
        "confidence": risk.confidence,
        "engine_version": risk.engine_version,
        "signals": [_signal_payload(signal) for signal in risk.signals],
    }
    user_explanation = build_user_explanation(parsed, risk_payload)
    return {
        "id": case_id,
        "case_id": case_id,
        "case_number": case_number,
        "status": "COMPLETE",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source_type": normalized.source_type,
        "source_message_id": normalized.source_message_id,
        "account_id": normalized.account_id,
        "source_metadata": normalized.source_metadata,
        "subject": parsed["metadata"].get("subject", ""),
        "sender": parsed["metadata"].get("from", ""),
        "recipient": parsed["metadata"].get("to", ""),
        "original_evidence_hash": f"sha256:{hashlib.sha256(evidence_bytes).hexdigest()}",
        "risk_score": risk.score,
        "risk_level": risk.level,
        "confidence": risk.confidence,
        "risk_engine_version": risk.engine_version,
        "parsed": parsed,
        "metadata": parsed["metadata"],
        "auth": parsed["auth"],
        "iocs": iocs,
        "intel_results": intel,
        "geoip": geo,
        "geoip_list": geo,
        "forensic_timeline": timeline,
        "risk_assessment": risk_payload,
        "contradictions": detect_trust_contradictions(parsed, iocs, signals),
        "ai_explanation": ai_explanation,
        "ai_analysis": ai_explanation,
        "ai_evidence": structured_evidence,
        "user_explanation": user_explanation,
        "safe_actions": user_explanation["what_to_do"],
        "routing_graph_dot": generate_routing_graph_dot(timeline, iocs),
        "graph": graph,
    }


def _signal_payload(signal: DetectionSignal) -> dict[str, Any]:
    return {
        "signal_id": signal.signal_id,
        "signal_type": signal.signal_type,
        "category": signal.category,
        "weight": signal.weight,
        "description": signal.description,
        "evidence_ids": list(signal.evidence_ids),
    }


def deterministic_explanation(parsed: dict[str, Any], iocs: dict[str, Any], risk: RiskAssessment) -> dict[str, Any]:
    indicators = [
        {
            "indicator": signal.description,
            "evidence_id": signal.evidence_ids[0] if signal.evidence_ids else signal.signal_id,
            "severity": "HIGH" if signal.weight >= 15 else "MEDIUM",
        }
        for signal in risk.signals
    ]
    return {
        "classification": "PHISHING" if risk.level in {"HIGH", "CRITICAL"} else "BENIGN",
        "confidence": risk.confidence,
        "confidence_statement": "Deterministic offline analysis; external intelligence confidence is unavailable in mock mode.",
        "summary": f"The message scored {risk.score}/100 ({risk.level}) based on verified parser and heuristic findings.",
        "suspicious_indicators": indicators,
        "analyst_reasoning": "The AI fallback explains only signals produced by the deterministic analysis pipeline.",
        "attack_technique": "Credential harvesting via deceptive email content" if indicators else "No supported attack technique identified",
        "recommended_actions": ["Review authentication failures and block malicious indicators before interacting with the message."],
        "limitations": ["Threat intelligence and geolocation are using clearly labeled offline mock adapters."],
        "provenance": "DERIVED",
        "is_fallback": True,
    }


def build_graph(
    parsed: dict[str, Any],
    iocs: dict[str, Any],
    intel: list[dict[str, Any]],
    geo: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    metadata = parsed.get("metadata", {})
    nodes = [{"id": "email", "type": "EMAIL", "label": metadata.get("subject", "Email"), "provenance": "OBSERVED"}]
    edges = []
    sender = metadata.get("from", "Unknown sender")
    nodes.append({"id": "sender", "type": "SENDER", "label": sender, "provenance": "OBSERVED"})
    edges.append({"id": "edge-sender", "source": "email", "target": "sender", "type": "SENT_BY"})
    for node_id, node_type, value, edge_type in (
        ("reply-to", "REPLY_TO", metadata.get("reply_to", ""), "REPLIES_TO"),
        ("return-path", "RETURN_PATH", metadata.get("return_path", ""), "BOUNCES_TO"),
    ):
        if value:
            nodes.append({"id": node_id, "type": node_type, "label": value, "provenance": "OBSERVED"})
            edges.append({"id": f"edge-{node_id}", "source": "email", "target": node_id, "type": edge_type})
    domain_ids: dict[str, str] = {}
    for item in iocs.get("items", []):
        node_id = item["ioc_id"]
        risk_tags = [result["risk_tag"] for result in intel if result["ioc_id"] == node_id]
        nodes.append({"id": node_id, "type": item["type"], "label": item["normalized_value"], "risk_tag": max(risk_tags, default="UNKNOWN"), "evidence_id": node_id, "provenance": "OBSERVED"})
        edge_type = "ROUTED_VIA" if item["type"] == "IP" and item["source"] == "RECEIVED_HEADER" else "CONTAINS"
        edges.append({"id": f"edge-{node_id}", "source": "email", "target": node_id, "type": edge_type, "evidence_id": node_id})
        if item["type"] == "DOMAIN":
            domain_ids[item["normalized_value"]] = node_id
    for item in iocs.get("items", []):
        if item["type"] == "DOMAIN" and item["normalized_value"] == _domain(sender):
            edges.append({"id": f"edge-uses-{item['ioc_id']}", "source": "sender", "target": item["ioc_id"], "type": "USES"})
        if item["type"] == "URL":
            hostname = (urlparse(item["value"]).hostname or "").lower()
            if hostname in domain_ids:
                edges.append({"id": f"edge-resolves-{item['ioc_id']}", "source": item["ioc_id"], "target": domain_ids[hostname], "type": "RESOLVES_TO"})
    for index, hop in enumerate(timeline, start=1):
        mail_id = f"mail-server-{index}"
        nodes.append({"id": mail_id, "type": "MAIL_SERVER", "label": hop["by_server"], "provenance": "OBSERVED"})
        edges.append({"id": f"edge-hop-{index}", "source": "email", "target": mail_id, "type": "ROUTED_VIA", "evidence_id": f"hop-{index}"})
    geo_by_ip = {result["ip"]: result for result in geo}
    for item in iocs.get("items", []):
        if item["type"] != "IP" or item["value"] not in geo_by_ip:
            continue
        result = geo_by_ip[item["value"]]
        location_id = f"geo-{item['ioc_id']}"
        nodes.append({"id": location_id, "type": "GEOLOCATION", "label": f"{result.get('city') or 'Unknown'}, {result.get('country') or 'Unknown'}", "metadata": result, "provenance": "EXTERNAL_INTELLIGENCE"})
        edges.append({"id": f"edge-geo-{item['ioc_id']}", "source": item["ioc_id"], "target": location_id, "type": "GEOLOCATED_AS"})
        if result.get("asn"):
            asn_id = f"asn-{item['ioc_id']}"
            nodes.append({"id": asn_id, "type": "ASN", "label": result["asn"], "metadata": {"isp": result.get("isp"), "org": result.get("org")}, "provenance": "EXTERNAL_INTELLIGENCE"})
            edges.append({"id": f"edge-asn-{item['ioc_id']}", "source": item["ioc_id"], "target": asn_id, "type": "BELONGS_TO"})
    return {"nodes": nodes, "edges": edges}
