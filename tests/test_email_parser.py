import os

from backend.services.email_parser import parse_raw_email

SAMPLE_EML_PATH = "data/samples/sample_phishing.eml"

def test_parse_sample_email():
    assert os.path.exists(SAMPLE_EML_PATH)
    with open(SAMPLE_EML_PATH, "r", encoding="utf-8") as f:
        raw_content = f.read()
        
    parsed = parse_raw_email(raw_content)
    
    assert "metadata" in parsed
    assert "From" in parsed["metadata"]["from"] or "support@secure-update-portal.xyz" in parsed["metadata"]["from"]
    assert "URGENT" in parsed["metadata"]["subject"]
    
    assert parsed["auth"]["spf"] == "FAIL"
    assert parsed["auth"]["dkim"] == "FAIL"
    assert parsed["auth"]["dmarc"] == "FAIL"
    
    assert len(parsed["metadata"]["received_headers"]) == 2
    assert "Critical IT Security Warning" in parsed["body_text"]
