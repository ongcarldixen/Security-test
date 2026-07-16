from ioc_scraper.extractors import extract_iocs, refang
from ioc_scraper.models import IOCType


def test_refang_defanged_url_and_ip():
    text = "Beacon to hxxp://evil[.]com and 8[.]8[.]8[.]8"
    result = refang(text)
    assert "http://evil.com" in result
    assert "8.8.8.8" in result


def test_extracts_all_known_types():
    text = """
    Malware phoned home to http://bad-domain.example.co and 203.0.113.5,
    dropped a file with sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    and md5 5d41402abc4b2a76b9719d911017c592, contacting attacker@bad-domain.example.co.
    """
    iocs = extract_iocs(text, source="unittest")
    types_found = {i.type for i in iocs}
    assert IOCType.URL in types_found
    assert IOCType.IPV4 in types_found
    assert IOCType.SHA256 in types_found
    assert IOCType.MD5 in types_found
    assert IOCType.EMAIL in types_found
    assert IOCType.DOMAIN in types_found


def test_filters_private_ips():
    text = "internal hosts 10.0.0.5, 192.168.1.1, 127.0.0.1 and external 203.0.113.7"
    iocs = extract_iocs(text, source="unittest")
    ips = {i.value for i in iocs if i.type == IOCType.IPV4}
    assert ips == {"203.0.113.7"}


def test_hash_lengths_do_not_collide():
    text = "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract_iocs(text, source="unittest")
    hash_values = {(i.type, i.value) for i in iocs if i.type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)}
    assert hash_values == {
        (IOCType.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }
