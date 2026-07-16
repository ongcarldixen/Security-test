import logging
from typing import List

import requests

from ioc_scraper.models import IOC, IOCType
from ioc_scraper.sources.base import IOCSource

logger = logging.getLogger(__name__)

API_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_TYPE_MAP = {
    "ip:port": IOCType.IPV4,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5_hash": IOCType.MD5,
    "sha1_hash": IOCType.SHA1,
    "sha256_hash": IOCType.SHA256,
}


class ThreatFoxSource(IOCSource):
    """Recent IOCs from abuse.ch ThreatFox, mapped to malware families."""

    name = "threatfox"

    def __init__(self, days: int = 3, timeout: int = 15, session: requests.Session | None = None):
        self.days = days
        self.timeout = timeout
        self.session = session or requests.Session()

    def collect(self) -> List[IOC]:
        try:
            response = self.session.post(
                API_ENDPOINT, json={"query": "get_iocs", "days": self.days}, timeout=self.timeout
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("ThreatFox collection failed: %s", exc)
            return []

        if payload.get("query_status") != "ok":
            return []

        iocs: List[IOC] = []
        for entry in payload.get("data", []):
            ioc_type = _TYPE_MAP.get(entry.get("ioc_type"))
            value = entry.get("ioc")
            if not ioc_type or not value:
                continue
            if ioc_type is IOCType.IPV4 and ":" in value:
                value = value.split(":", 1)[0]
            tags = [t for t in (entry.get("malware_printable"), entry.get("threat_type")) if t]
            confidence = entry.get("confidence_level")
            iocs.append(
                IOC(
                    type=ioc_type,
                    value=value,
                    source=self.name,
                    tags=tags,
                    confidence=int(confidence) if confidence is not None else 70,
                )
            )
        return iocs
