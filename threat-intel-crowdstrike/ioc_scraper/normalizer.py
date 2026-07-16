from typing import Iterable, List

from ioc_scraper.models import IOC


def dedupe(iocs: Iterable[IOC]) -> List[IOC]:
    """Collapse IOCs seen from multiple sources into one entry per (type, value).

    Keeps the first occurrence but merges tags/sources so provenance from
    every feed that reported the indicator is preserved.
    """
    merged: dict[str, IOC] = {}
    for ioc in iocs:
        key = ioc.key()
        if key not in merged:
            merged[key] = ioc
            continue
        existing = merged[key]
        for tag in ioc.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)
        if ioc.source not in existing.source.split(","):
            existing.source = f"{existing.source},{ioc.source}"
        existing.confidence = max(existing.confidence, ioc.confidence)
    return list(merged.values())
