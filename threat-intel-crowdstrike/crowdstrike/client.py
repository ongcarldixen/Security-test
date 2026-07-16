"""Thin wrapper around the falconpy Custom IOC and Falcon Intel Indicator APIs.

Two different CrowdStrike surfaces are involved here and they are not the
same thing:

* Custom IOC Management (`falconpy.IOC`) - indicators *you* have uploaded to
  your own tenant so Falcon sensors detect/block on them.
* Falcon Intel (`falconpy.Intel`) - CrowdStrike's own curated threat intel,
  used here read-only to see whether they already track an indicator you
  scraped, independent of whether you've uploaded it yourself.
"""
import logging
from typing import Iterable, List, Optional

from falconpy import IOC as FalconCustomIOC
from falconpy import Intel as FalconIntel

from config import CrowdStrikeConfig
from ioc_scraper.models import IOC, IOCType

logger = logging.getLogger(__name__)

# Custom IOC Management API type values (POST /iocs/entities/indicators/v1).
_TO_CUSTOM_IOC_TYPE = {
    IOCType.IPV4: "ipv4",
    IOCType.DOMAIN: "domain",
    IOCType.MD5: "md5",
    IOCType.SHA1: "sha1",
    IOCType.SHA256: "sha256",
}
# Custom IOC Management has no concept of "url" or "email" indicators.
UPLOADABLE_TYPES = set(_TO_CUSTOM_IOC_TYPE)

# Falcon Intel indicator API type values differ from the Custom IOC ones.
_TO_INTEL_TYPE = {
    IOCType.IPV4: "ip_address",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "hash_md5",
    IOCType.SHA1: "hash_sha1",
    IOCType.SHA256: "hash_sha256",
    IOCType.EMAIL: "email_address",
}


def _escape_fql(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class CrowdStrikeClient:
    """Authenticated access to the Custom IOC and Intel Indicator APIs."""

    def __init__(self, config: CrowdStrikeConfig):
        if not config.is_configured:
            raise ValueError("CrowdStrike client_id/client_secret are not configured")
        auth_kwargs = dict(
            client_id=config.client_id,
            client_secret=config.client_secret,
            base_url=config.base_url,
        )
        self.ioc_api = FalconCustomIOC(**auth_kwargs)
        self.intel_api = FalconIntel(**auth_kwargs)

    # -- Custom IOC management (indicators applied in your tenant) --------

    def find_existing_custom_ioc(self, ioc: IOC) -> Optional[dict]:
        """Return the existing custom IOC entity if this value is already applied, else None."""
        custom_type = _TO_CUSTOM_IOC_TYPE.get(ioc.type)
        if not custom_type:
            return None
        fql = f"type:'{custom_type}'+value:'{_escape_fql(ioc.value)}'"
        response = self.ioc_api.indicator_search(filter=fql, limit=1)
        ids = response.get("body", {}).get("resources", [])
        if not ids:
            return None
        details = self.ioc_api.indicator_get(ids=ids)
        resources = details.get("body", {}).get("resources", [])
        return resources[0] if resources else None

    def create_custom_iocs(
        self,
        iocs: Iterable[IOC],
        *,
        action: str = "detect",
        severity: str = "medium",
        platforms: Optional[List[str]] = None,
        comment: str = "",
    ) -> dict:
        """Upload IOCs as custom indicators. Non-uploadable types (url, email) are skipped."""
        indicators = []
        for ioc in iocs:
            custom_type = _TO_CUSTOM_IOC_TYPE.get(ioc.type)
            if not custom_type:
                logger.debug("Skipping non-uploadable IOC type=%s value=%s", ioc.type, ioc.value)
                continue
            indicators.append(
                {
                    "type": custom_type,
                    "value": ioc.value,
                    "action": action,
                    "severity": severity,
                    "platforms": platforms or ["linux", "mac", "windows"],
                    "source": (ioc.source or "threat-intel-scraper")[:200],
                    "tags": ioc.tags,
                    "applied_globally": True,
                }
            )
        if not indicators:
            return {"body": {"resources": []}}
        return self.ioc_api.indicator_create(comment=comment, indicators=indicators)

    # -- Falcon Intel (CrowdStrike's own threat intel, read-only) ---------

    def lookup_intel_indicator(self, ioc: IOC) -> Optional[dict]:
        """Check whether CrowdStrike's own threat intel already tracks this indicator."""
        intel_type = _TO_INTEL_TYPE.get(ioc.type)
        if not intel_type:
            return None
        fql = f"type:'{intel_type}'+indicator:'{_escape_fql(ioc.value)}'"
        response = self.intel_api.query_indicator_entities(filter=fql, limit=1, include_relations=False)
        resources = response.get("body", {}).get("resources", [])
        return resources[0] if resources else None
