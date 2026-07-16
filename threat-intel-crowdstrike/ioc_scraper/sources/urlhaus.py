import ipaddress
import logging
from typing import List

import requests

from ioc_scraper.models import IOC, IOCType
from ioc_scraper.sources.base import IOCSource

logger = logging.getLogger(__name__)

RECENT_URLS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausSource(IOCSource):
    """Recently reported malware-distribution URLs from abuse.ch URLhaus."""

    name = "urlhaus"

    def __init__(self, limit: int = 100, timeout: int = 15, session: requests.Session | None = None):
        self.limit = limit
        self.timeout = timeout
        self.session = session or requests.Session()

    def collect(self) -> List[IOC]:
        try:
            response = self.session.get(RECENT_URLS_ENDPOINT, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("URLhaus collection failed: %s", exc)
            return []

        if payload.get("query_status") != "ok":
            return []

        iocs: List[IOC] = []
        for entry in payload.get("urls", [])[: self.limit]:
            url = entry.get("url")
            if not url:
                continue
            tags = entry.get("tags") or []
            threat = entry.get("threat")
            if threat:
                tags = [*tags, threat]
            iocs.append(
                IOC(
                    type=IOCType.URL,
                    value=url,
                    source=self.name,
                    tags=tags,
                    confidence=75,
                )
            )
            host = entry.get("host")
            if host:
                host_type = IOCType.IPV4
                try:
                    ipaddress.IPv4Address(host)
                except ValueError:
                    host_type = IOCType.DOMAIN
                iocs.append(
                    IOC(
                        type=host_type,
                        value=host,
                        source=self.name,
                        tags=tags,
                        confidence=60,
                    )
                )
        return iocs
