from collections.abc import Iterable
from dataclasses import dataclass

ENGINE_VERSION = "1.0"

CATEGORY_CAPS = {
    "AUTHENTICATION": 30,
    "SENDER": 25,
    "INTELLIGENCE": 35,
    "CONTENT": 10,
    "URL": 25,
    "ATTACHMENT": 25,
    "ROUTING": 15,
    "META": 5,
}


@dataclass(frozen=True)
class DetectionSignal:
    signal_id: str
    signal_type: str
    category: str
    weight: float
    description: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: str
    confidence: float
    signals: tuple[DetectionSignal, ...]
    engine_version: str = ENGINE_VERSION


def risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def calculate_confidence(expected_queries: int, successful_queries: int) -> float:
    if expected_queries == 0:
        return 0.5
    return round(max(0, min(successful_queries, expected_queries)) / expected_queries, 2)


def calculate_risk(
    signals: Iterable[DetectionSignal],
    *,
    expected_intelligence_queries: int = 0,
    successful_intelligence_queries: int = 0,
    mock_intelligence: bool = False,
) -> RiskAssessment:
    signal_list = tuple(signals)
    category_totals: dict[str, float] = {}
    for signal in signal_list:
        category_totals[signal.category] = category_totals.get(signal.category, 0) + signal.weight

    capped_total = sum(
        min(CATEGORY_CAPS.get(category, 0), total)
        for category, total in category_totals.items()
    )
    score = round(min(100, capped_total), 2)
    confidence = calculate_confidence(
        expected_intelligence_queries, successful_intelligence_queries
    )
    if mock_intelligence and expected_intelligence_queries:
        confidence = 0.0

    return RiskAssessment(
        score=score,
        level=risk_level(score),
        confidence=confidence,
        signals=signal_list,
    )