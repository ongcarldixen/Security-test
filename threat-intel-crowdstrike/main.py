#!/usr/bin/env python3
"""CLI for scraping IOCs from OSINT feeds and cross-checking them against
a CrowdStrike Falcon tenant.

    python main.py scrape --sources urlhaus,threatfox -o reports/iocs.json
    python main.py check reports/iocs.json -o reports/check_report.json
    python main.py sync reports/check_report.json --live --yes
    python main.py all --sources urlhaus,threatfox
"""
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List

from tabulate import tabulate

from config import load_crowdstrike_config
from crowdstrike.checker import CheckedIOC, CheckReport, CrowdStrikeChecker, IOCStatus
from crowdstrike.client import CrowdStrikeClient
from ioc_scraper.models import IOC, IOCType
from ioc_scraper.normalizer import dedupe
from ioc_scraper.sources.base import IOCSource
from ioc_scraper.sources.threatfox import ThreatFoxSource
from ioc_scraper.sources.urlhaus import URLhausSource
from ioc_scraper.sources.web_scraper import WebPageSource

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("threat-intel-cli")

SOURCE_REGISTRY = {
    "urlhaus": lambda: URLhausSource(),
    "threatfox": lambda: ThreatFoxSource(),
}


def build_sources(names: List[str], web_urls: List[str]) -> List[IOCSource]:
    sources: List[IOCSource] = []
    for name in names:
        factory = SOURCE_REGISTRY.get(name)
        if not factory:
            raise SystemExit(f"Unknown source: {name}. Available: {', '.join(SOURCE_REGISTRY)}, web")
        sources.append(factory())
    if web_urls:
        sources.append(WebPageSource(urls=web_urls))
    return sources


def cmd_scrape(args: argparse.Namespace) -> List[IOC]:
    names = [s.strip() for s in args.sources.split(",") if s.strip()]
    web_urls = [u.strip() for u in (args.web_urls or []) if u.strip()]
    sources = build_sources(names, web_urls)

    all_iocs: List[IOC] = []
    for source in sources:
        logger.info("Collecting from %s", source.name)
        collected = source.collect()
        logger.info("  -> %d IOC(s)", len(collected))
        all_iocs.extend(collected)

    iocs = dedupe(all_iocs)
    logger.info("Total after dedupe: %d IOC(s)", len(iocs))

    if args.output:
        save_iocs(iocs, args.output)
        logger.info("Wrote %s", args.output)

    print(tabulate(_ioc_rows(iocs)[: args.print_limit], headers="keys", tablefmt="simple"))
    if len(iocs) > args.print_limit:
        print(f"... and {len(iocs) - args.print_limit} more (see output file)")
    return iocs


def cmd_check(args: argparse.Namespace) -> CheckReport:
    iocs = load_iocs(args.input)
    logger.info("Loaded %d IOC(s) from %s", len(iocs), args.input)

    cs_config = load_crowdstrike_config()
    client = CrowdStrikeClient(cs_config)
    checker = CrowdStrikeChecker(client)

    report = checker.cross_check(iocs)
    logger.info("Cross-check summary: %s", report.summary())

    if args.output:
        save_report(report, args.output)
        logger.info("Wrote %s", args.output)

    print(tabulate(_report_rows(report), headers="keys", tablefmt="simple"))
    print()
    print(tabulate(report.summary().items(), headers=["status", "count"], tablefmt="simple"))
    return report


def cmd_sync(args: argparse.Namespace) -> dict:
    report = load_report(args.input)
    cs_config = load_crowdstrike_config()
    client = CrowdStrikeClient(cs_config)
    checker = CrowdStrikeChecker(client)

    dry_run = not args.live
    if args.live and not args.yes:
        raise SystemExit("--live requires --yes to confirm you want to write IOCs into CrowdStrike")

    result = checker.sync_new_iocs(
        report,
        include_unconfirmed=args.include_unconfirmed,
        dry_run=dry_run,
        action=args.action,
        severity=args.severity,
        comment="Uploaded by threat-intel-crowdstrike scraper",
    )

    if dry_run:
        would_create = result.get("would_create", [])
        logger.info("[dry-run] Would create %d custom IOC(s). Re-run with --live --yes to apply.", len(would_create))
        print(tabulate(would_create, headers="keys", tablefmt="simple"))
    else:
        logger.info("Sync response: %s", result.get("body", {}).get("meta", {}))
    return result


def cmd_all(args: argparse.Namespace) -> None:
    iocs = cmd_scrape(args)
    args.input = args.output or "reports/iocs.json"
    if not args.output:
        save_iocs(iocs, args.input)
    args.output = args.check_output
    report = cmd_check(args)

    if args.sync:
        args.input = args.check_output
        args.live = False
        args.yes = False
        args.include_unconfirmed = args.include_unconfirmed
        args.action = args.action
        args.severity = args.severity
        cmd_sync(args)
    else:
        _ = report


# -- (de)serialization helpers --------------------------------------------

def _ioc_rows(iocs: List[IOC]) -> List[dict]:
    return [{"type": i.type.value, "value": i.value, "source": i.source, "confidence": i.confidence} for i in iocs]


def _report_rows(report: CheckReport) -> List[dict]:
    return [
        {
            "type": c.ioc.type.value,
            "value": c.ioc.value,
            "status": c.status.value,
            "cs_confidence": c.crowdstrike_intel_confidence or "",
            "cs_labels": ", ".join(c.crowdstrike_labels[:3]),
        }
        for c in report.checked
    ]


def save_iocs(iocs: List[IOC], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps([i.to_dict() for i in iocs], indent=2))


def load_iocs(path: str) -> List[IOC]:
    data = json.loads(Path(path).read_text())
    return [
        IOC(
            type=IOCType(d["type"]),
            value=d["value"],
            source=d["source"],
            first_seen=d.get("first_seen", ""),
            tags=d.get("tags", []),
            confidence=d.get("confidence", 50),
        )
        for d in data
    ]


def save_report(report: CheckReport, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps([c.to_dict() for c in report.checked], indent=2))


def load_report(path: str) -> CheckReport:
    data = json.loads(Path(path).read_text())
    checked = [
        CheckedIOC(
            ioc=IOC(
                type=IOCType(d["type"]),
                value=d["value"],
                source=d["source"],
                first_seen=d.get("first_seen", ""),
                tags=d.get("tags", []),
                confidence=d.get("confidence", 50),
            ),
            status=IOCStatus(d["status"]),
            crowdstrike_intel_confidence=d.get("crowdstrike_intel_confidence"),
            crowdstrike_labels=d.get("crowdstrike_labels", []),
        )
        for d in data
    ]
    return CheckReport(checked=checked)


# -- argparse wiring --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    scrape_p = sub.add_parser("scrape", help="Collect IOCs from configured sources")
    scrape_p.add_argument("--sources", default="urlhaus,threatfox", help="Comma-separated source names")
    scrape_p.add_argument("--web-urls", nargs="*", help="Extra report/blog URLs to scrape for IOCs")
    scrape_p.add_argument("-o", "--output", default="reports/iocs.json")
    scrape_p.add_argument("--print-limit", type=int, default=25)
    scrape_p.set_defaults(func=cmd_scrape)

    check_p = sub.add_parser("check", help="Cross-check IOCs against CrowdStrike")
    check_p.add_argument("input", help="Path to a JSON file produced by 'scrape'")
    check_p.add_argument("-o", "--output", default="reports/check_report.json")
    check_p.set_defaults(func=cmd_check)

    sync_p = sub.add_parser("sync", help="Upload confirmed-new IOCs to CrowdStrike as custom indicators")
    sync_p.add_argument("input", help="Path to a JSON file produced by 'check'")
    sync_p.add_argument("--include-unconfirmed", action="store_true",
                         help="Also upload IOCs CrowdStrike Intel has no record of (default: only known-malicious)")
    sync_p.add_argument("--action", default="detect", choices=["detect", "prevent", "allow"])
    sync_p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    sync_p.add_argument("--live", action="store_true", help="Actually write to CrowdStrike (default: dry-run)")
    sync_p.add_argument("--yes", action="store_true", help="Required alongside --live to confirm")
    sync_p.set_defaults(func=cmd_sync)

    all_p = sub.add_parser("all", help="scrape -> check -> (dry-run) sync in one shot")
    all_p.add_argument("--sources", default="urlhaus,threatfox")
    all_p.add_argument("--web-urls", nargs="*")
    all_p.add_argument("-o", "--output", default="reports/iocs.json")
    all_p.add_argument("--check-output", default="reports/check_report.json")
    all_p.add_argument("--print-limit", type=int, default=25)
    all_p.add_argument("--sync", action="store_true", help="Also run a dry-run sync preview at the end")
    all_p.add_argument("--include-unconfirmed", action="store_true")
    all_p.add_argument("--action", default="detect", choices=["detect", "prevent", "allow"])
    all_p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    all_p.set_defaults(func=cmd_all)

    return parser


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ValueError as exc:
        logger.error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
