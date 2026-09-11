"""Compatibility facade for callers of the pre-CodeFlux analysis module.

The product has one canonical scoring and AI path in ``services.pipeline`` and
``services.ai_analyst``. These wrappers preserve old imports without creating a
second risk engine.
"""

from __future__ import annotations

from typing import Any

from backend.services.forensic import parse_received_headers
from backend.services.pipeline import build_signals, deterministic_explanation
from backend.services.risk_engine import RiskAssessment, calculate_risk


def calculate_heuristic_risk(parsed_email: dict[str, Any], iocs: dict[str, Any]) -> tuple[float, str, list[str]]:
    timeline = parse_received_headers(parsed_email.get("metadata", {}).get("received_headers", []))
    signals = build_signals(parsed_email, iocs, [], timeline)
    assessment = calculate_risk(signals)
    return assessment.score, assessment.level, [signal.description for signal in assessment.signals]


def analyze_with_ai(
    parsed_email: dict[str, Any],
    iocs: dict[str, Any],
    risk_score: float,
    risk_factors: list[str],
) -> dict[str, Any]:
    """Return a safe deterministic explanation for legacy callers.

    New callers should use ``pipeline.analyze_normalized_email``. ``risk_score``
    and ``risk_factors`` are retained only for signature compatibility; the
    canonical report is still generated from the deterministic signals.
    """
    timeline = parse_received_headers(parsed_email.get("metadata", {}).get("received_headers", []))
    signals = build_signals(parsed_email, iocs, [], timeline)
    assessment = RiskAssessment(
        score=risk_score,
        level=calculate_risk(signals).level,
        confidence=0.5,
        signals=tuple(signals),
    )
    return deterministic_explanation(parsed_email, iocs, assessment)
