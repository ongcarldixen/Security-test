from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class IOC:
    type: IOCType
    value: str
    source: str
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: List[str] = field(default_factory=list)
    confidence: int = 50

    def key(self) -> str:
        """Stable identity used for dedup and lookups, independent of source."""
        return f"{self.type.value}:{self.value.lower()}"

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "first_seen": self.first_seen,
            "tags": self.tags,
            "confidence": self.confidence,
        }
