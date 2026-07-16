from ioc_scraper.models import IOC, IOCType
from ioc_scraper.normalizer import dedupe


def test_dedupe_merges_sources_and_tags():
    iocs = [
        IOC(type=IOCType.DOMAIN, value="evil.com", source="urlhaus", tags=["botnet"], confidence=60),
        IOC(type=IOCType.DOMAIN, value="EVIL.COM", source="threatfox", tags=["c2"], confidence=80),
    ]
    result = dedupe(iocs)
    assert len(result) == 1
    merged = result[0]
    assert merged.confidence == 80
    assert set(merged.tags) == {"botnet", "c2"}
    assert "urlhaus" in merged.source and "threatfox" in merged.source


def test_dedupe_keeps_distinct_types_separate():
    iocs = [
        IOC(type=IOCType.DOMAIN, value="1.2.3.4.example.com", source="a"),
        IOC(type=IOCType.URL, value="http://1.2.3.4.example.com", source="a"),
    ]
    result = dedupe(iocs)
    assert len(result) == 2
