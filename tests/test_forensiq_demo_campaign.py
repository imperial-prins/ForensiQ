from backend.services.correlation import correlate_cases
from backend.services.email_sources import MockGmailSource
from backend.services.pipeline import analyze_normalized_email

PRIMARY_ID = "mock-forensiq-credential-campaign"
COMPANION_IDS = (
    "mock-forensiq-sharepoint-campaign",
    "mock-forensiq-voicemail-campaign",
)


def _report(source: MockGmailSource, message_id: str) -> dict:
    return analyze_normalized_email(source.get_message(message_id))


def test_demo_campaign_populates_every_investigator_evidence_surface():
    source = MockGmailSource()
    report = _report(source, PRIMARY_ID)

    assert report["risk_level"] in {"HIGH", "CRITICAL"}
    assert report["auth"] == {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL", "raw_header": report["auth"]["raw_header"]}
    assert {item["type"] for item in report["iocs"]["items"]} >= {"IP", "DOMAIN", "URL", "EMAIL"}
    assert any(item["risk_tag"] == "MALICIOUS" for item in report["intel_results"])
    assert any(item["ip"] == "185.220.101.5" and item["city"] == "Frankfurt" for item in report["geoip"])
    assert len(report["forensic_timeline"]) >= 2
    assert report["parsed"]["attachments"]
    assert any(item["is_executable"] for item in report["parsed"]["attachments"])
    assert report["graph"]["nodes"]
    assert report["graph"]["edges"]
    assert report["original_evidence_hash"].startswith("sha256:")
    assert report["user_explanation"]["why"]
    assert report["safe_actions"]


def test_demo_campaign_creates_related_email_cluster():
    source = MockGmailSource()
    reports = [_report(source, message_id) for message_id in (PRIMARY_ID, *COMPANION_IDS)]

    correlation = correlate_cases(reports)

    cluster = next(cluster for cluster in correlation["clusters"] if reports[0]["case_id"] in cluster["case_ids"])
    assert set(cluster["case_ids"]) == {report["case_id"] for report in reports}
    assert cluster["message_count"] == 3
    assert cluster["confidence"] > 0
    assert {item["type"] for item in cluster["shared_indicators"]} & {"IP", "DOMAIN", "SENDER_DOMAIN"}
