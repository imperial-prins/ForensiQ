from backend.services.intelligence import IntelHub, MockThreatIntelProvider


def test_mock_provider_is_deterministic_and_explicit():
    result = MockThreatIntelProvider().lookup("IP", "185.220.101.5")

    assert result.provider == "MOCK"
    assert result.status == "SUCCESS"
    assert result.risk_tag == "MALICIOUS"


def test_live_mode_without_credentials_degrades_to_mock(monkeypatch):
    monkeypatch.setenv("INTEL_MODE", "live")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    hub = IntelHub()

    assert hub.is_mock is True