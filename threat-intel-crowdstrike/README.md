# threat-intel-crowdstrike

Scrapes IOCs (indicators of compromise) from open threat-intel feeds and
web pages, then cross-checks each one against a CrowdStrike Falcon tenant:

1. **Scrape** — pull IOCs from abuse.ch URLhaus / ThreatFox, and/or
   regex-extract them from arbitrary report/blog URLs (handles defanged
   values like `hxxp://evil[.]com`).
2. **Check** — for every IOC, ask CrowdStrike two questions:
   - *Already applied?* Is it already uploaded as a Custom IOC in this
     tenant (Custom IOC Management API)?
   - *Known malicious?* Does CrowdStrike's own Falcon Intel already track
     it, and at what confidence (Intel Indicator API, read-only)?
3. **Sync** *(optional, opt-in)* — upload IOCs CrowdStrike confirms as
   malicious (or, if you ask for it, unconfirmed ones too) as new Custom
   IOCs so Falcon sensors detect/prevent on them.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # or requirements.txt for runtime-only
cp .env.example .env                  # fill in CrowdStrike API credentials
```

Create a CrowdStrike API client at
`Falcon console -> Support and resources -> API clients and keys` with scopes:
- **IOC Management**: Read, Write
- **Indicators (Falcon Intelligence)**: Read

## Usage

```bash
# 1. Scrape IOCs from OSINT feeds (add --web-urls for arbitrary report pages)
python main.py scrape --sources urlhaus,threatfox -o reports/iocs.json

# 2. Cross-check them against your CrowdStrike tenant
python main.py check reports/iocs.json -o reports/check_report.json

# 3. Preview what would be uploaded (dry-run is the default, nothing is written)
python main.py sync reports/check_report.json

# 4. Actually upload the known-malicious ones as Custom IOCs
python main.py sync reports/check_report.json --live --yes

# Or do 1+2 in one shot:
python main.py all --sources urlhaus,threatfox
```

`sync` only ever touches indicators CrowdStrike Intel already confirms as
malicious unless you pass `--include-unconfirmed`, and it never writes to
your tenant unless you pass both `--live` and `--yes` — pushing detection
rules into a production security tool is a real, hard-to-reverse action,
so that has to be explicit.

## Project layout

```
ioc_scraper/
  extractors.py      regex IOC extraction + defang handling
  normalizer.py       cross-source dedup
  models.py           IOC dataclass / IOCType enum
  sources/
    urlhaus.py         abuse.ch URLhaus feed
    threatfox.py        abuse.ch ThreatFox feed
    web_scraper.py       generic page -> IOC extraction
crowdstrike/
  client.py            falconpy wrapper (Custom IOC + Intel APIs)
  checker.py           cross-check + sync orchestration
main.py                CLI (scrape / check / sync / all)
tests/                 pytest suite, network calls mocked
```

## Tests

```bash
pytest -q
```

All tests mock `requests` and `falconpy` — no network access or real
CrowdStrike credentials are needed to run the suite.
