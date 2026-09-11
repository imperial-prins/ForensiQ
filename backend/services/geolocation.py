import logging
import os
from typing import Any

import requests

logger = logging.getLogger("geolocation")

class IPGeoProvider:
    """
    IP Intelligence Provider abstraction.
    Uses free ip-api.com API with clean fallback defaults.
    """
    def __init__(self, api_url: str | None = None):
        self.api_url = api_url or os.getenv("IP_GEO_API_URL", "http://ip-api.com/json/")
        
    def lookup_ip(self, ip: str) -> dict[str, Any]:
        url = f"{self.api_url.rstrip('/')}/{ip}"
        try:
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    asn_raw = data.get("as", "")
                    asn_code = asn_raw.split(" ")[0] if asn_raw else "ASN-Unknown"
                    return {
                        "ip": ip,
                        "country": data.get("country", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "asn": asn_code,
                        "org": data.get("org", data.get("isp", "Unknown")),
                        "latitude": float(data.get("lat", 0.0)),
                        "longitude": float(data.get("lon", 0.0)),
                        "risk_tag": "SUSPICIOUS" if "Hosting" in data.get("isp", "") or "VPN" in data.get("org", "") else "INFORMATIONAL"
                    }
        except Exception as e:  # noqa: BLE001
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            
        # Fallback default values
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Private/Local ISP",
            "asn": "AS-UNKNOWN",
            "org": "Unknown Infrastructure",
            "latitude": 0.0,
            "longitude": 0.0,
            "risk_tag": "UNKNOWN"
        }

    def batch_lookup(self, ip_list: list[str]) -> list[dict[str, Any]]:
        results = []
        for ip in ip_list[:10]:  # Limit top 10 IPs for fast hackathon response
            results.append(self.lookup_ip(ip))
        return results
