from pathlib import Path

from backend.services.correlation import correlate_cases
from backend.services.email_parser import normalize_raw_email
from backend.services.pipeline import analyze_normalized_email

SAMPLES = Path("data/samples")


def _report(filename: str, message_id: str) -> dict:
    normalized = normalize_raw_email(
        (SAMPLES / filename).read_bytes(),
        source_type="GMAIL_MOCK",
        source_message_id=message_id,
        account_id="demo-account",
    )
    return analyze_normalized_email(normalized)


def test_contradiction_engine_links_identity_evidence_and_safe_actions():
    report = _report("sample_phishing.eml", "gmail-phishing")

    contradiction = [
        signal for signal in report["risk_assessment"]["signals"]
        if signal["signal_id"] == "IDENTITY_CONTRADICTION"
    ]
    assert contradiction
    assert contradiction[0]["evidence_ids"]
    assert report["user_explanation"]["why"]
    assert report["safe_actions"]
    assert any("Do not click" in action["action"] for action in report["safe_actions"])


def test_cross_email_correlation_returns_shared_indicator_relationship():
    first = _report("sample_phishing.eml", "gmail-a")
    second = _report("sample_suspicious_infrastructure.eml", "gmail-b")

    correlation = correlate_cases([first, second])

    assert correlation["clusters"]
    relationship = correlation["clusters"][0]["relationships"][0]
    assert set(relationship["case_ids"]) == {first["case_id"], second["case_id"]}
    assert relationship["shared_indicators"]
    assert relationship["confidence"] > 0
