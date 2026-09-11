from pathlib import Path

import pytest

from backend.services.pipeline import analyze_email

SCENARIOS = {
    "sample_legitimate.eml": set(),
    "sample_basic_phishing.eml": {"URGENCY_KEYWORDS", "SUSPICIOUS_TLD"},
    "sample_auth_failure.eml": {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"},
    "sample_reply_to_mismatch.eml": {"REPLY_TO_MISMATCH"},
    "sample_suspicious_url.eml": {"IP_IN_URL"},
    "sample_suspicious_infrastructure.eml": {"MALICIOUS_IP"},
}


@pytest.mark.parametrize("filename, expected_signals", SCENARIOS.items())
def test_synthetic_scenario_has_explainable_findings(filename, expected_signals):
    report = analyze_email(Path("data/samples", filename).read_bytes())
    signal_ids = {signal["signal_id"] for signal in report["risk_assessment"]["signals"]}

    assert report["status"] == "COMPLETE"
    assert expected_signals <= signal_ids
    assert report["ai_analysis"]["provenance"] in {"DERIVED", "AI_INTERPRETATION"}
    assert report["ai_analysis"]["is_fallback"] is True
