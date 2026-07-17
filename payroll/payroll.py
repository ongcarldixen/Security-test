#!/usr/bin/env python3
"""Payroll automation.

Workflow:
  1. python payroll.py init                       -> creates employees.csv + rules.json
  2. (fill in employees.csv)
  3. python payroll.py learn --entries examples_entries.csv --totals examples_totals.csv
     -> infers hourly rate / overtime multiplier per employee from worked examples
        and saves them into rules.json
  4. python payroll.py compute --entries time_entries.csv --out report.csv
     -> computes payroll automatically using the learned rules.
     -> if an active employee on the roster has no punches this period, or has
        no learned rate yet, it is called out instead of guessed.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RULES_PATH = BASE_DIR / "rules.json"
EMPLOYEES_PATH = BASE_DIR / "employees.csv"

DEFAULT_RULES = {
    "currency": "USD",
    "default": {
        "hourly_rate": None,
        "overtime": {
            "daily_threshold_hours": 8.0,
            "weekly_threshold_hours": 40.0,
            "multiplier": 1.5
        },
        "unpaid_break_minutes": 0
    },
    "employees": {}
}

TIME_FORMATS = ("%H:%M", "%I:%M%p", "%I:%M %p")


def parse_time(date_str, time_str):
    time_str = time_str.strip()
    for fmt in TIME_FORMATS:
        try:
            t = datetime.strptime(time_str, fmt)
            d = datetime.strptime(date_str.strip(), "%Y-%m-%d")
            return d.replace(hour=t.hour, minute=t.minute)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized time '{time_str}' (use 24h HH:MM or hh:mmAM/PM)")


def load_rules():
    if RULES_PATH.exists():
        with open(RULES_PATH) as f:
            return json.load(f)
    return json.loads(json.dumps(DEFAULT_RULES))


def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=2)
        f.write("\n")


def load_employees():
    employees = {}
    if EMPLOYEES_PATH.exists():
        with open(EMPLOYEES_PATH, newline="") as f:
            for row in csv.DictReader(f):
                employees[row["employee_id"].strip()] = {
                    "name": row["name"].strip(),
                    "active": row.get("active", "yes").strip().lower() != "no",
                }
    return employees


def read_punches(path):
    """Return {employee_id: [(date, time_in, time_out, break_minutes)]}."""
    punches = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            eid = row["employee_id"].strip()
            date = row["date"].strip()
            time_in = parse_time(date, row["time_in"])
            time_out = parse_time(date, row["time_out"])
            if time_out <= time_in:
                time_out += timedelta(days=1)  # overnight shift
            break_minutes = float(row.get("break_minutes") or 0)
            punches.setdefault(eid, []).append((date, time_in, time_out, break_minutes))
    return punches


def day_hours(time_in, time_out, break_minutes):
    worked = (time_out - time_in).total_seconds() / 3600.0
    worked -= break_minutes / 60.0
    return max(worked, 0.0)


def split_regular_overtime(daily_hours_list, weekly_threshold, daily_threshold):
    """Split a period's daily hours into (regular, overtime).

    Applies both a daily and a weekly threshold and takes whichever produces
    more overtime. This is a default assumption (common US daily/weekly OT
    rules) -- edit rules.json's overtime thresholds if your policy differs.
    """
    total = sum(daily_hours_list)
    daily_ot = sum(max(h - daily_threshold, 0.0) for h in daily_hours_list)
    daily_reg = total - daily_ot
    weekly_ot = max(total - weekly_threshold, 0.0)
    weekly_reg = total - weekly_ot
    if daily_ot >= weekly_ot:
        return daily_reg, daily_ot
    return weekly_reg, weekly_ot


def rules_for(rules, eid):
    merged = json.loads(json.dumps(rules["default"]))
    override = rules["employees"].get(eid, {})
    for k, v in override.items():
        if k == "overtime":
            merged["overtime"].update(v)
        else:
            merged[k] = v
    return merged


def employee_period_hours(punches_for_employee, rules_for_employee):
    ot_rules = rules_for_employee["overtime"]
    break_default = rules_for_employee.get("unpaid_break_minutes", 0)
    by_day = {}
    for date, time_in, time_out, break_minutes in punches_for_employee:
        bm = break_minutes if break_minutes else break_default
        by_day[date] = by_day.get(date, 0.0) + day_hours(time_in, time_out, bm)
    daily_hours_list = [by_day[d] for d in sorted(by_day)]
    return split_regular_overtime(
        daily_hours_list,
        ot_rules["weekly_threshold_hours"],
        ot_rules["daily_threshold_hours"],
    )


def cmd_init(args):
    if not EMPLOYEES_PATH.exists():
        with open(EMPLOYEES_PATH, "w", newline="") as f:
            f.write("employee_id,name,active\n")
    if not RULES_PATH.exists():
        save_rules(json.loads(json.dumps(DEFAULT_RULES)))
    print(f"Initialized {EMPLOYEES_PATH} and {RULES_PATH}")


def solve_rate_and_multiplier(examples):
    """examples: list of (regular_hours, overtime_hours, expected_pay).

    Solves pay = x*regular + y*overtime for x (hourly rate) and
    y (rate*multiplier) via least squares, stdlib only.
    """
    sr2 = so2 = sro = spr = spo = 0.0
    for reg, ot, pay in examples:
        sr2 += reg * reg
        so2 += ot * ot
        sro += reg * ot
        spr += pay * reg
        spo += pay * ot
    det = sr2 * so2 - sro * sro
    if abs(det) < 1e-9:
        if len(examples) == 1 and examples[0][1] == 0:
            reg, _, pay = examples[0]
            return (pay / reg, None) if reg else (None, None)
        return None, None
    x = (spr * so2 - spo * sro) / det
    y = (sr2 * spo - sro * spr) / det
    return x, (y / x if x else None)


def cmd_learn(args):
    rules = load_rules()
    employees = load_employees()
    punches = read_punches(args.entries)

    totals = {}
    with open(args.totals, newline="") as f:
        for row in csv.DictReader(f):
            totals.setdefault(row["employee_id"].strip(), []).append(
                float(row["expected_gross_pay"])
            )

    print("Inferred pay rules (review before trusting):\n")
    for eid, entries in punches.items():
        if eid not in totals:
            continue
        r = rules_for(rules, eid)
        regular, overtime = employee_period_hours(entries, r)
        pay = totals[eid][0]
        rate, mult = solve_rate_and_multiplier([(regular, overtime, pay)])
        name = employees.get(eid, {}).get("name", eid)
        if rate is None:
            print(f"  {name} ({eid}): cannot solve uniquely from this single example "
                  f"-- provide a second example with different overtime hours, or state "
                  f"the rate/multiplier directly.")
            continue
        rules["employees"].setdefault(eid, {})
        rules["employees"][eid]["hourly_rate"] = round(rate, 4)
        note = ""
        if mult is not None:
            rules["employees"][eid].setdefault("overtime", {})["multiplier"] = round(mult, 3)
        else:
            note = (f" (no overtime in this example -- kept default "
                    f"{r['overtime']['multiplier']}x multiplier, please confirm)")
        print(f"  {name} ({eid}): rate=${rate:.2f}/hr  reg={regular:.2f}h  "
              f"ot={overtime:.2f}h{note}")

    save_rules(rules)
    print(f"\nSaved to {RULES_PATH}")


def cmd_compute(args):
    rules = load_rules()
    employees = load_employees()
    punches = read_punches(args.entries)

    missing = [eid for eid, info in employees.items()
               if info["active"] and eid not in punches]
    unrated = []
    report_rows = []
    for eid, entries in punches.items():
        r = rules_for(rules, eid)
        if r.get("hourly_rate") is None:
            unrated.append(eid)
            continue
        regular, overtime = employee_period_hours(entries, r)
        rate = r["hourly_rate"]
        mult = r["overtime"]["multiplier"]
        gross = regular * rate + overtime * mult * rate
        name = employees.get(eid, {}).get("name", eid)
        report_rows.append({
            "employee_id": eid,
            "name": name,
            "regular_hours": round(regular, 2),
            "overtime_hours": round(overtime, 2),
            "hourly_rate": rate,
            "gross_pay": round(gross, 2),
        })

    if args.out:
        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "employee_id", "name", "regular_hours", "overtime_hours",
                "hourly_rate", "gross_pay",
            ])
            writer.writeheader()
            writer.writerows(report_rows)

    for row in report_rows:
        print(f"{row['name']:<20} reg={row['regular_hours']:>6}h  "
              f"ot={row['overtime_hours']:>5}h  rate=${row['hourly_rate']:.2f}  "
              f"gross=${row['gross_pay']:.2f}")

    if unrated:
        print("\nNo learned pay rate for these employees (skipped) -- "
              "run `learn` first or set rules.json manually:")
        for eid in unrated:
            print(f"  - {eid} ({employees.get(eid, {}).get('name', 'unknown')})")

    if missing:
        print("\nNo time entries found this period for:")
        for eid in missing:
            print(f"  - {eid} ({employees[eid]['name']})")
        print("Please confirm: did they not work, or were entries not submitted yet?")

    return 1 if (missing or unrated) else 0


def main():
    parser = argparse.ArgumentParser(description="Payroll automation")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create starter employees.csv and rules.json")
    p_init.set_defaults(func=cmd_init)

    p_learn = sub.add_parser("learn", help="Infer pay rate/overtime rules from worked examples")
    p_learn.add_argument("--entries", required=True, help="CSV of example punches")
    p_learn.add_argument("--totals", required=True, help="CSV of employee_id,expected_gross_pay")
    p_learn.set_defaults(func=cmd_learn)

    p_compute = sub.add_parser("compute", help="Compute payroll for a period from time punches")
    p_compute.add_argument("--entries", required=True, help="CSV of time punches")
    p_compute.add_argument("--out", help="Write report CSV to this path")
    p_compute.set_defaults(func=cmd_compute)

    args = parser.parse_args()
    rc = args.func(args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
