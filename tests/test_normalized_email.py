from pathlib import Path

from backend.services.email_parser import normalize_raw_email
from backend.services.email_sources import EMLSource
from backend.services.pipeline import analyze_normalized_email

SAMPLE = Path("data/samples/sample_phishing.eml").read_bytes()


def test_eml_normalizes_to_provider_neutral_contract():
    email = normalize_raw_email(
        SAMPLE,
        source_type="EML",
        source_message_id="local-1",
        account_id="local-account",
    )

    assert email.source_type == "EML"
    assert email.source_message_id == "local-1"
    assert email.account_id == "local-account"
    assert email.from_address == "IT Support Desk <support@secure-update-portal.xyz>"
    assert email.reply_to == "phisher-collect@harvest-credentials.top"
    assert email.received_headers
    assert email.source_ips == ["185.220.101.5", "192.168.1.50"]
    assert email.attachments == []
    adapter_email = EMLSource(SAMPLE, source_message_id="local-1").get_message()
    assert adapter_email.source_type == "EML"
    assert adapter_email.source_message_id == "local-1"


def test_normalized_email_uses_the_existing_analysis_pipeline():
    normalized = normalize_raw_email(SAMPLE, source_type="EML", source_message_id="local-2")
    report = analyze_normalized_email(normalized)

    assert report["source_type"] == "EML"
    assert report["parsed"]["metadata"]["message_id"]
    assert report["risk_assessment"]["signals"]
    assert report["user_explanation"]["verdict"] in {"SAFE", "SUSPICIOUS", "DANGEROUS"}
    valid_evidence = {
        item["ioc_id"] for item in report["iocs"]["items"]
    } | {item["signal_id"] for item in report["risk_assessment"]["signals"]}
    assert all(
        evidence_id in valid_evidence
        for reason in report["user_explanation"]["why"]
        for evidence_id in reason["evidence_ids"]
    )