from unittest.mock import MagicMock, patch

from config import CrowdStrikeConfig
from crowdstrike.client import CrowdStrikeClient
from ioc_scraper.models import IOC, IOCType


def make_client():
    config = CrowdStrikeConfig(client_id="id", client_secret="secret", base_url="https://api.crowdstrike.com")
    with patch("crowdstrike.client.FalconCustomIOC") as MockIOC, patch("crowdstrike.client.FalconIntel") as MockIntel:
        client = CrowdStrikeClient(config)
        return client, MockIOC.return_value, MockIntel.return_value


def test_rejects_unconfigured_credentials():
    config = CrowdStrikeConfig(client_id="", client_secret="", base_url="https://api.crowdstrike.com")
    try:
        CrowdStrikeClient(config)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_find_existing_custom_ioc_builds_fql_and_resolves():
    client, ioc_api, _intel_api = make_client()
    ioc_api.indicator_search.return_value = {"body": {"resources": ["id-1"]}}
    ioc_api.indicator_get.return_value = {"body": {"resources": [{"id": "id-1", "value": "evil.com"}]}}

    result = client.find_existing_custom_ioc(IOC(type=IOCType.DOMAIN, value="evil.com", source="test"))

    assert result == {"id": "id-1", "value": "evil.com"}
    ioc_api.indicator_search.assert_called_once_with(filter="type:'domain'+value:'evil.com'", limit=1)
    ioc_api.indicator_get.assert_called_once_with(ids=["id-1"])


def test_find_existing_custom_ioc_returns_none_when_absent():
    client, ioc_api, _intel_api = make_client()
    ioc_api.indicator_search.return_value = {"body": {"resources": []}}

    result = client.find_existing_custom_ioc(IOC(type=IOCType.DOMAIN, value="new.com", source="test"))

    assert result is None
    ioc_api.indicator_get.assert_not_called()


def test_lookup_intel_indicator_maps_type_and_escapes_value():
    client, _ioc_api, intel_api = make_client()
    intel_api.query_indicator_entities.return_value = {"body": {"resources": [{"indicator": "1.2.3.4"}]}}

    result = client.lookup_intel_indicator(IOC(type=IOCType.IPV4, value="1.2.3.4", source="test"))

    assert result == {"indicator": "1.2.3.4"}
    intel_api.query_indicator_entities.assert_called_once_with(
        filter="type:'ip_address'+indicator:'1.2.3.4'", limit=1, include_relations=False
    )


def test_create_custom_iocs_skips_non_uploadable_types():
    client, ioc_api, _intel_api = make_client()
    ioc_api.indicator_create.return_value = {"body": {"resources": []}}

    iocs = [
        IOC(type=IOCType.URL, value="http://evil.com/x", source="test"),
        IOC(type=IOCType.DOMAIN, value="evil.com", source="test"),
    ]
    client.create_custom_iocs(iocs)

    _args, kwargs = ioc_api.indicator_create.call_args
    submitted = kwargs["indicators"]
    assert len(submitted) == 1
    assert submitted[0]["type"] == "domain"
    assert submitted[0]["value"] == "evil.com"


def test_create_custom_iocs_noop_when_nothing_uploadable():
    client, ioc_api, _intel_api = make_client()
    client.create_custom_iocs([IOC(type=IOCType.EMAIL, value="a@b.com", source="test")])
    ioc_api.indicator_create.assert_not_called()
