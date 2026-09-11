import base64
import ipaddress
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IntelResult:
    provider: str
    status: str
    query_type: str
    query_value: str
    risk_tag: str
    result_summary: str
    raw_response: dict[str, Any] | None
    cached: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "query_type": self.query_type,
            "query_value": self.query_value,
            "risk_tag": self.risk_tag,
            "result_summary": self.result_summary,
            "raw_response": self.raw_response,
            "cached": self.cached,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }


class ThreatIntelProvider(Protocol):
    name: str
    supported_ioc_types: tuple[str, ...]

    def lookup(self, ioc_type: str, value: str) -> IntelResult:
        ...


class MockThreatIntelProvider:
    name = "MOCK"
    supported_ioc_types = ("IP", "DOMAIN", "URL", "HASH_SHA256", "HASH_MD5", "HASH_SHA1")

    def lookup(self, ioc_type: str, value: str) -> IntelResult:
        lowered = value.lower()
        if (ioc_type == "IP" and lowered.startswith("185.220.")) or lowered.endswith((".xyz", ".top", ".click")):
            return IntelResult(self.name, "SUCCESS", ioc_type, value, "MALICIOUS", "Deterministic mock rule matched", {"mock": True})
        return IntelResult(self.name, "SUCCESS", ioc_type, value, "UNKNOWN", "No mock reputation match", {"mock": True})


class HTTPThreatIntelProvider:
    name = "HTTP"
    supported_ioc_types: tuple[str, ...] = ()
    timeout_seconds = 5.0

    def __init__(self, api_key: str, base_url: str) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _request(self, path: str, headers: dict[str, str], params: dict[str, str] | None = None) -> IntelResult | dict[str, Any]:
        try:
            response = requests.get(
                f"{self.base_url}/{path.lstrip('/')}",
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
            if response.status_code == 429:
                return IntelResult(self.name, "RATE_LIMITED", "", "", "UNKNOWN", "Provider rate limit reached", None)
            if response.status_code >= 500:
                return IntelResult(self.name, "UNAVAILABLE", "", "", "UNKNOWN", "Provider unavailable", None)
            if response.status_code != 200:
                return IntelResult(self.name, "ERROR", "", "", "UNKNOWN", f"Provider returned HTTP {response.status_code}", None)
            payload = response.json()
            if not isinstance(payload, dict):
                return IntelResult(self.name, "ERROR", "", "", "UNKNOWN", "Provider returned an invalid response", None)
            return payload
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Threat intelligence provider %s failed: %s", self.name, type(exc).__name__)
            return IntelResult(self.name, "UNAVAILABLE", "", "", "UNKNOWN", "Provider request failed", None)

    def _failure(self, ioc_type: str, value: str, result: IntelResult) -> IntelResult:
        return IntelResult(self.name, result.status, ioc_type, value, "UNKNOWN", result.result_summary, result.raw_response)


class VirusTotalProvider(HTTPThreatIntelProvider):
    name = "VIRUSTOTAL"
    supported_ioc_types = ("IP", "DOMAIN", "URL", "HASH_SHA256")

    def __init__(self, api_key: str) -> None:
        super().__init__(api_key, os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"))

    def lookup(self, ioc_type: str, value: str) -> IntelResult:
        paths = {
            "IP": f"ip_addresses/{quote(value, safe='')}",
            "DOMAIN": f"domains/{quote(value, safe='')}",
            "URL": f"urls/{base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')}",
            "HASH_SHA256": f"files/{quote(value, safe='')}",
        }
        path = paths.get(ioc_type, "").strip()
        if not path:
            return IntelResult(self.name, "ERROR", ioc_type, value, "UNKNOWN", "Unsupported IOC type", None)
        result = self._request(path, {"x-apikey": self.api_key})
        if isinstance(result, IntelResult):
            return self._failure(ioc_type, value, result)
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        risk_tag = "MALICIOUS" if malicious >= 3 else "SUSPICIOUS" if suspicious >= 2 else "CLEAN" if malicious == 0 and suspicious == 0 else "UNKNOWN"
        return IntelResult(self.name, "SUCCESS", ioc_type, value, risk_tag, f"VirusTotal: {malicious} malicious, {suspicious} suspicious", result)


class AbuseIPDBProvider(HTTPThreatIntelProvider):
    name = "ABUSEIPDB"
    supported_ioc_types = ("IP",)

    def __init__(self, api_key: str) -> None:
        super().__init__(api_key, os.getenv("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2"))

    def lookup(self, ioc_type: str, value: str) -> IntelResult:
        result = self._request("check", {"Key": self.api_key, "Accept": "application/json"}, {"ipAddress": value, "maxAgeInDays": "90"})
        if isinstance(result, IntelResult):
            return self._failure(ioc_type, value, result)
        score = int(result.get("data", {}).get("abuseConfidenceScore", 0) or 0)
        risk_tag = "MALICIOUS" if score >= 75 else "SUSPICIOUS" if score >= 25 else "CLEAN"
        return IntelResult(self.name, "SUCCESS", ioc_type, value, risk_tag, f"Abuse confidence score: {score}", result)


class AlienVaultOTXProvider(HTTPThreatIntelProvider):
    name = "ALIENVAULT_OTX"
    supported_ioc_types = ("IP", "DOMAIN", "URL", "HASH_SHA256", "HASH_MD5", "HASH_SHA1")

    def __init__(self, api_key: str) -> None:
        super().__init__(api_key, os.getenv("OTX_BASE_URL", "https://otx.alienvault.com/api/v1"))

    def lookup(self, ioc_type: str, value: str) -> IntelResult:
        type_paths = {"IP": "indicators/IPv4", "DOMAIN": "indicators/domain", "URL": "indicators/url", "HASH_SHA256": "indicators/file", "HASH_MD5": "indicators/file", "HASH_SHA1": "indicators/file"}
        if ioc_type not in type_paths:
            return IntelResult(self.name, "ERROR", ioc_type, value, "UNKNOWN", "Unsupported IOC type", None)
        result = self._request(f"{type_paths[ioc_type]}/{quote(value, safe='')}/general", {"X-OTX-API-KEY": self.api_key})
        if isinstance(result, IntelResult):
            return self._failure(ioc_type, value, result)
        pulse_count = int(result.get("pulse_info", {}).get("count", 0) or 0)
        risk_tag = "MALICIOUS" if pulse_count >= 3 else "SUSPICIOUS" if pulse_count >= 1 else "CLEAN"
        return IntelResult(self.name, "SUCCESS", ioc_type, value, risk_tag, f"OTX pulses: {pulse_count}", result)


class IntelHub:
    def __init__(self) -> None:
        mode = os.getenv("INTEL_MODE", "mock").lower()
        self.providers: list[ThreatIntelProvider] = []
        if mode == "live":
            virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
            abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
            otx_key = os.getenv("OTX_API_KEY", "").strip()
            if virustotal_key:
                self.providers.append(VirusTotalProvider(virustotal_key))
            if abuseipdb_key:
                self.providers.append(AbuseIPDBProvider(abuseipdb_key))
            if otx_key:
                self.providers.append(AlienVaultOTXProvider(otx_key))
        if not self.providers:
            self.providers.append(MockThreatIntelProvider())

    @property
    def is_mock(self) -> bool:
        return all(provider.name == "MOCK" for provider in self.providers)

    def lookup(self, ioc_type: str, value: str) -> list[IntelResult]:
        return [provider.lookup(ioc_type, value) for provider in self.providers if ioc_type in provider.supported_ioc_types]


def enrich_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hub = IntelHub()
    results = []
    for item in iocs:
        for result in hub.lookup(item["type"], item["value"]):
            results.append(result.as_dict() | {"ioc_id": item["ioc_id"]})
    return results


def enrich_geo(ips: list[str]) -> list[dict[str, Any]]:
    mode = os.getenv("GEOIP_MODE", os.getenv("INTEL_MODE", "mock")).lower()
    results = []
    for ip in ips[:10]:
        if mode == "live":
            results.append(_live_geo(ip))
        else:
            results.append(_mock_geo(ip))
    return results


def _mock_geo(ip: str) -> dict[str, Any]:
    if ip == "185.220.101.5":
        return {"ip": ip, "country": "Germany", "country_code": "DE", "city": "Frankfurt", "isp": "Mock Hosting", "asn": "AS-MOCK", "org": "Mock Infrastructure", "latitude": 50.1109, "longitude": 8.6821, "provider": "MOCK", "status": "SUCCESS", "source_confidence": "Observed infrastructure geography"}
    return {"ip": ip, "country": None, "country_code": None, "city": None, "isp": None, "asn": None, "org": None, "latitude": None, "longitude": None, "provider": "MOCK", "status": "SUCCESS", "source_confidence": "Observed infrastructure geography"}


def _live_geo(ip: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return {"ip": ip, "provider": "IP_API", "status": "UNAVAILABLE", "source_confidence": "Private or non-global IP"}
        response = requests.get(
            f"{os.getenv('IP_GEO_API_URL', 'https://ip-api.com/json').rstrip('/')}/{quote(ip, safe='')}",
            params={"fields": "status,message,country,countryCode,city,isp,as,org,lat,lon,query"},
            timeout=3.0,
        )
        payload = response.json()
        if response.status_code != 200 or payload.get("status") != "success":
            return {"ip": ip, "provider": "IP_API", "status": "UNAVAILABLE", "source_confidence": "Observed infrastructure geography"}
        return {"ip": ip, "country": payload.get("country"), "country_code": payload.get("countryCode"), "city": payload.get("city"), "isp": payload.get("isp"), "asn": str(payload.get("as", "")).split(" ")[0], "org": payload.get("org"), "latitude": payload.get("lat"), "longitude": payload.get("lon"), "provider": "IP_API", "status": "SUCCESS", "source_confidence": "Observed infrastructure geography"}
    except (ValueError, requests.RequestException, TypeError):
        return {"ip": ip, "provider": "IP_API", "status": "UNAVAILABLE", "source_confidence": "Observed infrastructure geography"}
