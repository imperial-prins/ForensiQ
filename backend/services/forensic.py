import re
from datetime import timezone
from email.utils import parsedate_to_datetime
from itertools import pairwise
from typing import Any

import graphviz

BY_SERVER_REGEX = re.compile(r"\bby\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)
FROM_SERVER_REGEX = re.compile(r"\bfrom\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)
IP_IN_RECEIVED = re.compile(r"(?:\[|\()((?:\d{1,3}\.){3}\d{1,3})(?:\]|\))")
PROTOCOL_REGEX = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)
QUEUE_ID_REGEX = re.compile(r"\bid\s+(\S+)", re.IGNORECASE)
RECIPIENT_REGEX = re.compile(r"\bfor\s+<([^>]+)>", re.IGNORECASE)
TIMESTAMP_REGEX = re.compile(r";\s*(.+)$", re.DOTALL)


def _timestamp(value: str) -> str | None:
    try:
        parsed = parsedate_to_datetime(value.strip())
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def parse_received_headers(received_headers: list[str]) -> list[dict[str, Any]]:
    hops = []
    for index, header in enumerate(list(reversed(received_headers))[:20], start=1):
        from_match = FROM_SERVER_REGEX.search(header)
        by_match = BY_SERVER_REGEX.search(header)
        ip_match = IP_IN_RECEIVED.search(header)
        protocol_match = PROTOCOL_REGEX.search(header)
        queue_match = QUEUE_ID_REGEX.search(header)
        recipient_match = RECIPIENT_REGEX.search(header)
        timestamp_match = TIMESTAMP_REGEX.search(header)
        timestamp = _timestamp(timestamp_match.group(1)) if timestamp_match else None
        hops.append({
            "hop_number": index,
            "from_server": from_match.group(1) if from_match else "Origin/Client",
            "from_server_confidence": "PARSED" if from_match else "UNKNOWN",
            "from_ip": ip_match.group(1) if ip_match else None,
            "from_ip_confidence": "OBSERVED" if ip_match else "UNKNOWN",
            "by_server": by_match.group(1) if by_match else f"Server-{index}",
            "by_server_confidence": "PARSED" if by_match else "UNKNOWN",
            "ip": ip_match.group(1) if ip_match else None,
            "ip_confidence": "OBSERVED" if ip_match else "UNKNOWN",
            "protocol": protocol_match.group(1) if protocol_match else None,
            "queue_id": queue_match.group(1).rstrip(";") if queue_match else None,
            "for_recipient": recipient_match.group(1) if recipient_match else None,
            "timestamp": timestamp,
            "timestamp_confidence": "PARSED" if timestamp else "UNKNOWN",
            "delay_seconds": 0,
            "auth_status": "CHECKED",
            "raw_header": header,
            "anomalies": [] if timestamp else ["MISSING_TIMESTAMP"],
        })
    for previous, current in pairwise(hops):
        if previous["timestamp"] and current["timestamp"] and current["timestamp"] < previous["timestamp"]:
            current["anomalies"].append("TIMESTAMP_REVERSAL")
    return hops


def generate_routing_graph_dot(hops: list[dict[str, Any]], iocs: dict[str, Any]) -> str:
    dot = graphviz.Digraph(comment="Email Infrastructure & Routing Graph")
    dot.attr(rankdir="LR", bgcolor="#0f172a", fontcolor="#f8fafc", fontname="Helvetica")
    dot.attr("node", shape="rectangle", style="filled,rounded", fontcolor="#ffffff", fontname="Helvetica", fillcolor="#1e293b", color="#334155")
    dot.attr("edge", color="#64748b", fontcolor="#94a3b8", fontname="Helvetica")
    previous = None
    for hop in hops:
        node_id = f"hop_{hop['hop_number']}"
        dot.node(node_id, f"Hop {hop['hop_number']}\\nFrom: {hop['from_server']}\\nBy: {hop['by_server']}\\nIP: {hop.get('ip') or 'N/A'}", fillcolor="#ef4444" if hop["anomalies"] else "#1d4ed8")
        if previous:
            dot.edge(previous, node_id, label="relayed to")
        previous = node_id
    for index, domain in enumerate(iocs.get("domains", [])[:10]):
        dot.node(f"domain_{index}", f"Domain\\n{domain}", shape="ellipse", fillcolor="#475569")
    return dot.source
