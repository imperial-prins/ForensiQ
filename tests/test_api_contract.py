from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app


def test_sample_upload_returns_case_and_integrity_resources():
    sample = Path("data/samples/sample_phishing.eml").read_bytes()

    with TestClient(app) as client:
        response = client.post("/api/v1/analyze", files={"file": ("sample.eml", sample, "message/rfc822")})
        assert response.status_code == 201
        case_id = response.json()["case_id"]

        assert client.get(f"/api/v1/cases/{case_id}").status_code == 200
        assert client.get(f"/api/v1/cases/{case_id}/evidence").json()["integrity_status"] == "VALID"
        assert client.get(f"/api/v1/cases/{case_id}/graph").json()["nodes"]


def test_analyze_rejects_missing_and_oversized_input():
    with TestClient(app) as client:
        missing = client.post("/api/v1/analyze")
        oversized = client.post("/api/v1/analyze", files={"file": ("large.eml", b"x" * (25 * 1024 * 1024 + 1), "message/rfc822")})

    assert missing.status_code == 400
    assert missing.json()["detail"]["error"]["code"] == "NO_EMAIL_PROVIDED"
    assert oversized.status_code == 413