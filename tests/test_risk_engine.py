from backend.services.risk_engine import DetectionSignal, calculate_risk


def signal(signal_id: str, category: str, weight: float) -> DetectionSignal:
    return DetectionSignal(signal_id, signal_id, category, weight, signal_id)


def test_category_caps_and_severity_follow_specification():
    assessment = calculate_risk(
        [
            signal("SPF_FAIL", "AUTHENTICATION", 15),
            signal("DKIM_FAIL", "AUTHENTICATION", 15),
            signal("DMARC_FAIL", "AUTHENTICATION", 10),
            signal("MALICIOUS_IP", "INTELLIGENCE", 20),
        ]
    )

    assert assessment.score == 50
    assert assessment.level == "HIGH"


def test_confidence_is_independent_from_risk_and_mock_override():
    assessment = calculate_risk(
        [signal("SPF_FAIL", "AUTHENTICATION", 15)],
        expected_intelligence_queries=6,
        successful_intelligence_queries=4,
    )
    mock_assessment = calculate_risk(
        [], expected_intelligence_queries=6, successful_intelligence_queries=6, mock_intelligence=True
    )

    assert assessment.score == 15
    assert assessment.confidence == 0.67
    assert mock_assessment.confidence == 0.0