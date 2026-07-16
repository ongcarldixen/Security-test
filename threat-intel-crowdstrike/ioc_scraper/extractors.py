"""Regex-based IOC extraction from free-form text (blog posts, reports, pastes).

Threat intel writeups routinely "defang" indicators (hxxp, [.], (.)) to keep
them from becoming clickable/live. We refang before matching so those are
still picked up.
"""
import re
from typing import List

from ioc_scraper.models import IOC, IOCType

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,24})\b",
    re.IGNORECASE,
)
_URL = re.compile(r"\bhttps?://[^\s\"'<>\]\)]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Reserved / non-routable ranges and placeholder domains that show up
# constantly as noise (RFC1918, loopback, documentation examples).
_PRIVATE_IP_PREFIXES = ("10.", "127.", "169.254.", "192.168.")
_DOMAIN_DENYLIST = {
    "example.com",
    "example.org",
    "example.net",
    "localhost.com",
    "yourdomain.com",
    "domain.com",
}


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(_PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    return False


def refang(text: str) -> str:
    text = re.sub(r"hxxps?://", lambda m: m.group(0).replace("hxxp", "http"), text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = text.replace("[:]", ":").replace("[at]", "@").replace("(at)", "@")
    return text


def extract_iocs(text: str, source: str) -> List[IOC]:
    """Pull every recognizable IOC out of a text blob.

    Hash regexes are length-based, so longer patterns are matched before
    shorter ones and consumed values are excluded from the next pass to
    avoid a sha256 also showing up as a stray md5-length substring match.
    """
    text = refang(text)
    found: List[IOC] = []
    seen_values = set()

    for pattern, ioc_type in ((_SHA256, IOCType.SHA256), (_SHA1, IOCType.SHA1), (_MD5, IOCType.MD5)):
        for match in pattern.finditer(text):
            value = match.group(0).lower()
            if value in seen_values:
                continue
            seen_values.add(value)
            found.append(IOC(type=ioc_type, value=value, source=source))

    for match in _URL.finditer(text):
        value = match.group(0).rstrip(".,;:")
        if value in seen_values:
            continue
        seen_values.add(value)
        found.append(IOC(type=IOCType.URL, value=value, source=source))

    for match in _EMAIL.finditer(text):
        value = match.group(0).lower()
        if value in seen_values:
            continue
        seen_values.add(value)
        found.append(IOC(type=IOCType.EMAIL, value=value, source=source))

    for match in _IPV4.finditer(text):
        value = match.group(0)
        if value in seen_values or _is_private_ipv4(value):
            continue
        seen_values.add(value)
        found.append(IOC(type=IOCType.IPV4, value=value, source=source))

    for match in _DOMAIN.finditer(text):
        value = match.group(0).lower()
        if value in seen_values or value in _DOMAIN_DENYLIST:
            continue
        if _IPV4.fullmatch(value):
            continue
        seen_values.add(value)
        found.append(IOC(type=IOCType.DOMAIN, value=value, source=source))

    return found
