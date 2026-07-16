from abc import ABC, abstractmethod
from typing import List

from ioc_scraper.models import IOC


class IOCSource(ABC):
    """A feed or page that yields IOCs when collected."""

    name: str = "unknown"

    @abstractmethod
    def collect(self) -> List[IOC]:
        raise NotImplementedError
