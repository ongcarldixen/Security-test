"""Environment-driven configuration for the scraper and CrowdStrike client."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class CrowdStrikeConfig:
    client_id: str
    client_secret: str
    base_url: str

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


def load_crowdstrike_config() -> CrowdStrikeConfig:
    return CrowdStrikeConfig(
        client_id=os.getenv("CROWDSTRIKE_CLIENT_ID", ""),
        client_secret=os.getenv("CROWDSTRIKE_CLIENT_SECRET", ""),
        base_url=os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"),
    )


ABUSE_CH_CONTACT = os.getenv("ABUSE_CH_CONTACT", "")
