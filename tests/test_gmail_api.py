from fastapi.testclient import TestClient

from backend.main import app


def test_mock_gmail_connect_status_messages_and_scan_share_case_pipeline():
    with TestClient(app) as client:
        connect = client.post("/api/v1/gmail/connect")
        assert connect.status_code == 200
        assert connect.json()["mode"] == "mock"
        assert connect.json()["demo"] is True

        status = client.get("/api/v1/gmail/status")
        assert status.status_code == 200
        assert status.json()["connected"] is True
        assert status.json()["display_name"] == "DEMO / MOCK MAILBOX"

        messages = client.get("/api/v1/gmail/messages", params={"limit": 10})
        assert messages.status_code == 200
        message = messages.json()["messages"][0]

        analyzed = client.post(f"/api/v1/gmail/messages/{message['message_id']}/analyze")
        assert analyzed.status_code in {200, 201}
        case_id = analyzed.json()["case_id"]

        duplicate = client.post(f"/api/v1/gmail/messages/{message['message_id']}/analyze")
        assert duplicate.status_code == 200
        assert duplicate.json()["case_id"] == case_id

        scan = client.post("/api/v1/gmail/scan", json={"limit": 10})
        assert scan.status_code == 200
        assert scan.json()["analyzed_count"] + scan.json()["reused_count"] >= 1
        assert scan.json()["cases"]

        detail = client.get(f"/api/v1/cases/{case_id}")
        assert detail.status_code == 200
        assert detail.json()["case"]["source_type"] == "GMAIL_MOCK"
        assert detail.json()["case"]["user_explanation"]
        assert detail.json()["case"]["safe_actions"]
