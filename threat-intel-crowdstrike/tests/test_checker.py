from unittest.mock import MagicMock

from crowdstrike.checker import CrowdStrikeChecker, IOCStatus
from ioc_scraper.models import IOC, IOCType


def make_client(existing_values=(), intel_hits=None):
    intel_hits = intel_hits or {}
    client = MagicMock()

    def find_existing(ioc):
        return {"id": "abc"} if ioc.value in existing_values else None

    def lookup_intel(ioc):
        return intel_hits.get(ioc.value)

    client.find_existing_custom_ioc.side_effect = find_existing
    client.lookup_intel_indicator.side_effect = lookup_intel
    return client


def test_already_applied_short_circuits_intel_lookup():
    client = make_client(existing_values={"evil.com"})
    checker = CrowdStrikeChecker(client)
    report = checker.cross_check([IOC(type=IOCType.DOMAIN, value="evil.com", source="test")])

    assert report.checked[0].status == IOCStatus.ALREADY_APPLIED
    client.lookup_intel_indicator.assert_not_called()


def test_known_malicious_captures_confidence_and_labels():
    client = make_client(
        intel_hits={
            "evil.com": {
                "malicious_confidence": "high",
                "labels": [{"name": "MaliciousConfidence/High"}, {"name": "Malware/Emotet"}],
            }
        }
    )
    checker = CrowdStrikeChecker(client)
    report = checker.cross_check([IOC(type=IOCType.DOMAIN, value="evil.com", source="test")])

    checked = report.checked[0]
    assert checked.status == IOCStatus.KNOWN_MALICIOUS
    assert checked.crowdstrike_intel_confidence == "high"
    assert "Malware/Emotet" in checked.crowdstrike_labels


def test_unconfirmed_when_no_hits():
    client = make_client()
    checker = CrowdStrikeChecker(client)
    report = checker.cross_check([IOC(type=IOCType.DOMAIN, value="unknown.example", source="test")])
    assert report.checked[0].status == IOCStatus.UNCONFIRMED_NEW


def test_sync_defaults_to_dry_run_and_known_malicious_only():
    client = make_client(intel_hits={"bad.com": {"malicious_confidence": "high", "labels": []}})
    checker = CrowdStrikeChecker(client)
    report = checker.cross_check(
        [
            IOC(type=IOCType.DOMAIN, value="bad.com", source="test"),
            IOC(type=IOCType.DOMAIN, value="unknown.example", source="test"),
        ]
    )

    result = checker.sync_new_iocs(report)

    assert result["dry_run"] is True
    values = {i["value"] for i in result["would_create"]}
    assert values == {"bad.com"}
    client.create_custom_iocs.assert_not_called()


def test_sync_live_calls_client_create():
    client = make_client(intel_hits={"bad.com": {"malicious_confidence": "high", "labels": []}})
    checker = CrowdStrikeChecker(client)
    report = checker.cross_check([IOC(type=IOCType.DOMAIN, value="bad.com", source="test")])

    checker.sync_new_iocs(report, dry_run=False)

    client.create_custom_iocs.assert_called_once()
    (created_iocs,), _kwargs = client.create_custom_iocs.call_args
    assert [i.value for i in created_iocs] == ["bad.com"]
