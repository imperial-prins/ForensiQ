import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

# Regex Patterns
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b')

# Reserved/private IP filter
def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_id: str
    type: str
    value: str
    normalized_value: str
    source: str
    extraction_location: str
    is_public: bool | None = None

# Safe common system domain filter
IGNORED_DOMAINS = {
    "schemas.xmlsoap.org", "w3.org", "schemas.microsoft.com", "schema.org",
    "google.com", "microsoft.com", "apple.com", "ns.adobe.com"
}

def extract_iocs(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts IPs, Domains, URLs, and Attachment metadata from parsed email content.
    """
    text_content = parsed_email.get("body_text", "")
    html_content = parsed_email.get("body_html", "")
    received_headers = parsed_email.get("metadata", {}).get("received_headers", [])
    
    combined_text = text_content + "\n" + "\n".join(received_headers)
    
    extracted: list[ExtractedIOC] = []

    # 1. Extract URLs from HTML tags and plain text
    urls: set[str] = set()
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href.startswith(("http://", "https://", "www.")):
                urls.add(href)
                
    for match in URL_REGEX.findall(text_content):
        urls.add(match.strip())
        
    clean_urls = sorted(urls)
    
    # 2. Extract Domains from URLs and text
    domains: set[str] = set()
    for u in clean_urls:
        parsed_url = urlparse(u if u.startswith("http") else "http://" + u)
        if parsed_url.hostname:
            domains.add(parsed_url.hostname.lower())
            
    for match in DOMAIN_REGEX.findall(combined_text):
        match_lower = match.lower()
        if match_lower not in IGNORED_DOMAINS and not match_lower.endswith(".png") and not match_lower.endswith(".jpg"):
            domains.add(match_lower)
            
    # 3. Extract IP addresses
    raw_ips = IP_REGEX.findall(combined_text)
    public_ips: set[str] = set()
    for ip in raw_ips:
        if is_public_ip(ip):
            public_ips.add(ip)

    for index, ip in enumerate(sorted(public_ips), start=1):
        extracted.append(ExtractedIOC(f"ioc-{index:04d}", "IP", ip, ip, "RECEIVED_HEADER", "Received/header", True))
    for domain in sorted(domains):
        extracted.append(ExtractedIOC(f"ioc-{len(extracted) + 1:04d}", "DOMAIN", domain, domain, "BODY_TEXT", "body/header text"))
    for url in clean_urls:
        normalized = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        extracted.append(ExtractedIOC(f"ioc-{len(extracted) + 1:04d}", "URL", url, normalized, "BODY_HTML", "body link"))

    for address in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", combined_text):
        extracted.append(ExtractedIOC(f"ioc-{len(extracted) + 1:04d}", "EMAIL", address, address.lower(), "HEADER", "email header"))
            
    attachments = parsed_email.get("attachments", [])
    
    return {
        "ips": sorted(public_ips),
        "domains": sorted(domains),
        "urls": sorted(clean_urls),
        "attachments": attachments,
        "items": [asdict(item) for item in extracted],
    }
