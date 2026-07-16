"""Cross-checks scraped IOCs against a CrowdStrike Falcon tenant.

For every scraped indicator we answer two questions:
  1. Is it already applied as a custom IOC in this tenant? (avoid duplicates)
  2. Does CrowdStrike's own Intel already know about it, and how confident
     are they it's malicious? (independent validation of the scrape)
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional

from crowdstrike.client import CrowdStrikeClient
from ioc_scraper.models import IOC


class IOCStatus(str, Enum):
    ALREADY_APPLIED = "already_applied"
    KNOWN_MALICIOUS = "known_malicious"
    UNCONFIRMED_NEW = "unconfirmed_new"


@dataclass
class CheckedIOC:
    ioc: IOC
    status: IOCStatus
    crowdstrike_intel_confidence: Optional[str] = None
    crowdstrike_labels: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            **self.ioc.to_dict(),
            "status": self.status.value,
            "crowdstrike_intel_confidence": self.crowdstrike_intel_confidence,
            "crowdstrike_labels": self.crowdstrike_labels,
        }


@dataclass
class CheckReport:
    checked: List[CheckedIOC] = field(default_factory=list)

    def by_status(self, status: IOCStatus) -> List[CheckedIOC]:
        return [c for c in self.checked if c.status == status]

    def summary(self) -> dict:
        return {status.value: len(self.by_status(status)) for status in IOCStatus}


class CrowdStrikeChecker:
    def __init__(self, client: CrowdStrikeClient):
        self.client = client

    def cross_check(self, iocs: Iterable[IOC]) -> CheckReport:
        report = CheckReport()
        for ioc in iocs:
            existing = self.client.find_existing_custom_ioc(ioc)
            if existing:
                report.checked.append(CheckedIOC(ioc=ioc, status=IOCStatus.ALREADY_APPLIED))
                continue

            intel_hit = self.client.lookup_intel_indicator(ioc)
            if intel_hit:
                labels = [lbl.get("name") for lbl in intel_hit.get("labels", []) if lbl.get("name")]
                report.checked.append(
                    CheckedIOC(
                        ioc=ioc,
                        status=IOCStatus.KNOWN_MALICIOUS,
                        crowdstrike_intel_confidence=intel_hit.get("malicious_confidence"),
                        crowdstrike_labels=labels,
                    )
                )
                continue

            report.checked.append(CheckedIOC(ioc=ioc, status=IOCStatus.UNCONFIRMED_NEW))
        return report

    def sync_new_iocs(
        self,
        report: CheckReport,
        *,
        include_unconfirmed: bool = False,
        dry_run: bool = True,
        **create_kwargs,
    ) -> dict:
        """Push not-yet-applied IOCs to CrowdStrike as custom indicators.

        Defaults to known-malicious-only and dry_run=True: writing new
        detection rules into a live tenant is a real, hard-to-reverse
        action, so both safety rails require an explicit opt-in to bypass.
        """
        candidates = report.by_status(IOCStatus.KNOWN_MALICIOUS)
        if include_unconfirmed:
            candidates = candidates + report.by_status(IOCStatus.UNCONFIRMED_NEW)
        target_iocs = [c.ioc for c in candidates]

        if dry_run:
            return {"dry_run": True, "would_create": [i.to_dict() for i in target_iocs]}
        return self.client.create_custom_iocs(target_iocs, **create_kwargs)
