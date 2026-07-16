from unittest.mock import MagicMock

from ioc_scraper.models import IOCType
from ioc_scraper.sources.threatfox import ThreatFoxSource
from ioc_scraper.sources.urlhaus import URLhausSource
from ioc_scraper.sources.web_scraper import WebPageSource


def _mock_session(json_body, status_ok=True):
    session = MagicMock()
    response = MagicMock()
    response.json.return_value = json_body
    response.raise_for_status.return_value = None
    session.get.return_value = response
    session.post.return_value = response
    return session


def test_urlhaus_parses_url_and_host():
    payload = {
        "query_status": "ok",
        "urls": [
            {"url": "http://evil.com/payload.exe", "host": "evil.com", "tags": ["exe"], "threat": "malware_download"},
            {"url": "http://1.2.3.4/x", "host": "1.2.3.4", "tags": [], "threat": None},
        ],
    }
    source = URLhausSource(session=_mock_session(payload))
    iocs = source.collect()

    by_type = {(i.type, i.value) for i in iocs}
    assert (IOCType.URL, "http://evil.com/payload.exe") in by_type
    assert (IOCType.DOMAIN, "evil.com") in by_type
    assert (IOCType.IPV4, "1.2.3.4") in by_type


def test_urlhaus_returns_empty_on_bad_status():
    source = URLhausSource(session=_mock_session({"query_status": "no_results"}))
    assert source.collect() == []


def test_threatfox_maps_types_and_strips_port():
    payload = {
        "query_status": "ok",
        "data": [
            {"ioc_type": "ip:port", "ioc": "5.6.7.8:443", "malware_printable": "Cobalt Strike", "confidence_level": 90},
            {"ioc_type": "sha256_hash", "ioc": "a" * 64, "threat_type": "payload"},
        ],
    }
    source = ThreatFoxSource(session=_mock_session(payload))
    iocs = source.collect()

    ip_ioc = next(i for i in iocs if i.type == IOCType.IPV4)
    assert ip_ioc.value == "5.6.7.8"
    assert ip_ioc.confidence == 90

    hash_ioc = next(i for i in iocs if i.type == IOCType.SHA256)
    assert hash_ioc.value == "a" * 64


def test_web_scraper_extracts_from_page_text():
    session = MagicMock()
    response = MagicMock()
    response.text = "<html><body>Bad domain: evil-report.example and ip 203.0.113.9</body></html>"
    response.raise_for_status.return_value = None
    session.get.return_value = response

    source = WebPageSource(urls=["https://blog.example/report"], session=session)
    iocs = source.collect()

    values = {i.value for i in iocs}
    assert "203.0.113.9" in values
    assert "evil-report.example" in values
