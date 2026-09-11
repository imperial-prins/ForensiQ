from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from backend.services.contradictions import address_domain


def _case_indicators(case: dict[str, Any]) -> dict[tuple[str, str], str]:
    indicators: dict[tuple[str, str], str] = {}
    sender = str(case.get("sender", ""))
    if sender:
        indicators[("SENDER", sender.lower())] = sender
        domain = address_domain(sender)
        if domain:
            indicators[("SENDER_DOMAIN", domain)] = domain
    for item in case.get("iocs", {}).get("items", []):
        kind = str(item.get("type", "IOC"))
        value = str(item.get("normalized_value", item.get("value", ""))).lower()
        if value:
            indicators[(kind, value)] = str(item.get("value", value))
    for result in case.get("geoip", case.get("geoip_list", [])):
        ip = str(result.get("ip", "")).lower()
        asn = str(result.get("asn", "")).lower()
        if ip and asn:
            indicators[("ASN", asn)] = str(result.get("asn"))
    for attachment in case.get("parsed", {}).get("attachments", []):
        digest = str(attachment.get("sha256", "")).lower()
        if digest:
            indicators[("ATTACHMENT_HASH", digest)] = digest
    return indicators


def _confidence(shared: list[dict[str, Any]]) -> float:
    kinds = {item["type"] for item in shared}
    value = 0.58 + min(0.3, max(0, len(kinds) - 1) * 0.12)
    return round(min(0.95, value), 2)


def correlate_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Find explainable shared-indicator relationships between persisted cases."""
    indexed = {str(case.get("case_id", case.get("id"))): _case_indicators(case) for case in cases}
    relationships: list[dict[str, Any]] = []
    parent = {case_id: case_id for case_id in indexed}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for left_id, right_id in combinations(indexed, 2):
        left = indexed[left_id]
        right = indexed[right_id]
        shared: list[dict[str, Any]] = []
        for key in sorted(set(left) & set(right)):
            kind, normalized = key
            shared.append({"type": kind, "value": left[key], "normalized_value": normalized})
        if not shared:
            continue
        union(left_id, right_id)
        relationships.append({
            "case_ids": [left_id, right_id],
            "shared_indicators": shared,
            "common_infrastructure": [item for item in shared if item["type"] in {"IP", "DOMAIN", "SENDER_DOMAIN", "ASN"}],
            "confidence": _confidence(shared),
            "provenance": "CROSS_CASE_CORRELATION",
        })

    groups: dict[str, list[str]] = defaultdict(list)
    for case_id in indexed:
        groups[find(case_id)].append(case_id)
    clusters: list[dict[str, Any]] = []
    for index, member_ids in enumerate(groups.values(), start=1):
        if len(member_ids) < 2:
            continue
        member_set = set(member_ids)
        group_relationships = [
            relation for relation in relationships
            if member_set.intersection(relation["case_ids"]) == set(relation["case_ids"])
        ]
        shared_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for relation in group_relationships:
            for item in relation["shared_indicators"]:
                shared_by_key[(item["type"], item["normalized_value"])] = item
        recipients = sorted({
            str(case.get("recipient", ""))
            for case in cases
            if str(case.get("case_id", case.get("id"))) in member_set and case.get("recipient")
        })
        clusters.append({
            "cluster_id": f"cluster-{index:04d}",
            "label": "Potential related email cluster",
            "case_ids": sorted(member_ids),
            "message_count": len(member_ids),
            "shared_indicators": list(shared_by_key.values()),
            "common_infrastructure": [
                item for item in shared_by_key.values()
                if item["type"] in {"IP", "DOMAIN", "SENDER_DOMAIN", "ASN"}
            ],
            "affected_recipients": recipients,
            "confidence": max((relation["confidence"] for relation in group_relationships), default=0.0),
            "relationships": group_relationships,
            "provenance": "CROSS_CASE_CORRELATION",
        })
    return {"clusters": clusters, "relationships": relationships, "case_count": len(cases)}
