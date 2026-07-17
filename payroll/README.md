# Payroll automation

CSV-based time tracking -> payroll calculator. It "learns" each employee's
hourly rate and overtime multiplier from worked examples you provide, then
computes payroll automatically from raw time in/out punches on later runs.
It never guesses pay for an employee it has no rate for, and it never
silently pays ₱0 for an employee with no punches this period -- both cases
are called out so you can be asked instead. Currency defaults to PHP
(Philippine peso, `rules.json`'s top-level `currency` field).

## Files

- `employees.csv` - roster (`employee_id,name,active`)
- `rules.json` - learned pay rules (hourly rate, overtime threshold/multiplier
  per employee, plus a `default` used until an employee has their own).
  Starts empty (`hourly_rate: null`) until you run `learn`.
- `examples_entries_template.csv` / `examples_totals_template.csv` - shape of
  the input used for the one-time `learn` step.
- `time_entries_template.csv` - shape of the input used for every regular
  `compute` run.

## One-time: teach it your pay rules

Give an example pay period's punches, plus the gross pay you expect it to
produce, for at least one employee:

```
python payroll.py learn --entries examples_entries.csv --totals examples_totals.csv
```

`examples_entries.csv` columns: `employee_id,date,time_in,time_out,break_minutes`
`examples_totals.csv` columns: `employee_id,expected_gross_pay`

It solves for hourly rate (and overtime multiplier, if the example includes
overtime hours) and saves them into `rules.json`. If an example has no
overtime, the multiplier can't be solved from it alone and keeps the default
(1.5x) until you provide an example that does include overtime, or edit
`rules.json` by hand. Review the printed rates before trusting them.

Overtime *thresholds* (default: over 8h/day or 40h/week) aren't inferred --
edit `rules.json`'s `overtime.daily_threshold_hours` /
`weekly_threshold_hours` per employee if your policy differs.

## Every pay period

```
python payroll.py compute --entries time_entries.csv --out report.csv
```

Prints and writes a per-employee breakdown (regular hours, overtime hours,
rate, gross pay). Two things are flagged instead of guessed:

- **Employee has no learned rate** -- run `learn` for them, or add them to
  `rules.json` manually.
- **Active employee has zero punches this period** -- confirm whether they
  didn't work or the entries just weren't submitted yet.

## Setup

```
python payroll.py init
```

Creates `employees.csv` and `rules.json` if they don't already exist.
