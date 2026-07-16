import logging
from typing import List

import requests
from bs4 import BeautifulSoup

from ioc_scraper.extractors import extract_iocs
from ioc_scraper.models import IOC
from ioc_scraper.sources.base import IOCSource

logger = logging.getLogger(__name__)


class WebPageSource(IOCSource):
    """Fetches arbitrary threat-report/blog URLs and regex-extracts IOCs
    from the rendered text. Use for pages that don't expose a feed API.
    """

    name = "web_scraper"

    def __init__(self, urls: List[str], timeout: int = 15, session: requests.Session | None = None):
        self.urls = urls
        self.timeout = timeout
        self.session = session or requests.Session()

    def collect(self) -> List[IOC]:
        iocs: List[IOC] = []
        for url in self.urls:
            iocs.extend(self._collect_one(url))
        return iocs

    def _collect_one(self, url: str) -> List[IOC]:
        try:
            response = self.session.get(url, timeout=self.timeout, headers={"User-Agent": "threat-intel-scraper/1.0"})
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Failed to fetch %s: %s", url, exc)
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        return extract_iocs(text, source=f"{self.name}:{url}")
