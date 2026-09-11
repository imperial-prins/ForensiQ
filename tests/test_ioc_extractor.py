from backend.services.email_parser import parse_raw_email
from backend.services.ioc_extractor import extract_iocs

SAMPLE_EML_PATH = "data/samples/sample_phishing.eml"

def test_extract_iocs():
    with open(SAMPLE_EML_PATH, "r", encoding="utf-8") as f:
        raw_content = f.read()
        
    parsed = parse_raw_email(raw_content)
    iocs = extract_iocs(parsed)
    
    assert "185.220.101.5" in iocs["ips"]
    assert "login-verify-portal.top" in iocs["domains"] or "secure-update-portal.xyz" in iocs["domains"]
    assert any("185.220.101.5" in u for u in iocs["urls"])
