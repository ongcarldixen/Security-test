<?php
/**
 * Payroll automation.
 *
 * Workflow:
 *   1. php payroll.php init
 *        -> creates employees.csv + rules.json
 *   2. (fill in employees.csv)
 *   3. php payroll.php learn --entries examples_entries.csv --totals examples_totals.csv
 *        -> infers hourly rate / overtime multiplier per employee from worked
 *           examples and saves them into rules.json
 *   4. php payroll.php compute --entries time_entries.csv --out report.csv
 *        -> computes payroll automatically using the learned rules.
 *        -> if an active employee on the roster has no punches this period,
 *           or has no learned rate yet, it is called out instead of guessed.
 */

const RULES_PATH = __DIR__ . '/rules.json';
const EMPLOYEES_PATH = __DIR__ . '/employees.csv';

const DEFAULT_RULES = [
    'currency' => 'USD',
    'default' => [
        'hourly_rate' => null,
        'overtime' => [
            'daily_threshold_hours' => 8.0,
            'weekly_threshold_hours' => 40.0,
            'multiplier' => 1.5,
        ],
        'unpaid_break_minutes' => 0,
    ],
    'employees' => new stdClass(),
];

function parse_time(string $dateStr, string $timeStr): DateTime
{
    $timeStr = trim($timeStr);
    $formats = ['H:i', 'g:iA', 'g:i A'];
    foreach ($formats as $fmt) {
        $t = DateTime::createFromFormat($fmt, $timeStr);
        if ($t !== false) {
            $d = DateTime::createFromFormat('Y-m-d', trim($dateStr));
            if ($d === false) {
                throw new RuntimeException("Unrecognized date '$dateStr' (use YYYY-MM-DD)");
            }
            $d->setTime((int) $t->format('H'), (int) $t->format('i'));
            return $d;
        }
    }
    throw new RuntimeException("Unrecognized time '$timeStr' (use 24h HH:MM or hh:mmAM/PM)");
}

function load_rules(): array
{
    if (file_exists(RULES_PATH)) {
        return json_decode(file_get_contents(RULES_PATH), true);
    }
    return json_decode(json_encode(DEFAULT_RULES), true);
}

function save_rules(array $rules): void
{
    if (empty($rules['employees'])) {
        $rules['employees'] = new stdClass();
    }
    file_put_contents(RULES_PATH, json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
}

function load_employees(): array
{
    $employees = [];
    if (file_exists(EMPLOYEES_PATH)) {
        $fh = fopen(EMPLOYEES_PATH, 'r');
        $header = fgetcsv($fh);
        while (($row = fgetcsv($fh)) !== false) {
            $rec = array_combine($header, $row);
            $active = strtolower(trim($rec['active'] ?? 'yes')) !== 'no';
            $employees[trim($rec['employee_id'])] = [
                'name' => trim($rec['name']),
                'active' => $active,
            ];
        }
        fclose($fh);
    }
    return $employees;
}

/** Returns [employee_id => [[date, DateTime timeIn, DateTime timeOut, float breakMinutes], ...]] */
function read_punches(string $path): array
{
    $punches = [];
    $fh = fopen($path, 'r');
    $header = fgetcsv($fh);
    while (($row = fgetcsv($fh)) !== false) {
        $rec = array_combine($header, $row);
        $eid = trim($rec['employee_id']);
        $date = trim($rec['date']);
        $timeIn = parse_time($date, $rec['time_in']);
        $timeOut = parse_time($date, $rec['time_out']);
        if ($timeOut <= $timeIn) {
            $timeOut->modify('+1 day'); // overnight shift
        }
        $breakMinutes = isset($rec['break_minutes']) && $rec['break_minutes'] !== ''
            ? (float) $rec['break_minutes'] : 0.0;
        $punches[$eid][] = [$date, $timeIn, $timeOut, $breakMinutes];
    }
    fclose($fh);
    return $punches;
}

function day_hours(DateTime $timeIn, DateTime $timeOut, float $breakMinutes): float
{
    $worked = ($timeOut->getTimestamp() - $timeIn->getTimestamp()) / 3600.0;
    $worked -= $breakMinutes / 60.0;
    return max($worked, 0.0);
}

/**
 * Split a period's daily hours into [regular, overtime].
 *
 * Applies both a daily and a weekly threshold and takes whichever produces
 * more overtime. This is a default assumption (common US daily/weekly OT
 * rules) -- edit rules.json's overtime thresholds if your policy differs.
 */
function split_regular_overtime(array $dailyHoursList, float $weeklyThreshold, float $dailyThreshold): array
{
    $total = array_sum($dailyHoursList);
    $dailyOt = array_sum(array_map(fn($h) => max($h - $dailyThreshold, 0.0), $dailyHoursList));
    $dailyReg = $total - $dailyOt;
    $weeklyOt = max($total - $weeklyThreshold, 0.0);
    $weeklyReg = $total - $weeklyOt;
    if ($dailyOt >= $weeklyOt) {
        return [$dailyReg, $dailyOt];
    }
    return [$weeklyReg, $weeklyOt];
}

function rules_for(array $rules, string $eid): array
{
    $merged = json_decode(json_encode($rules['default']), true);
    $override = $rules['employees'][$eid] ?? [];
    foreach ($override as $k => $v) {
        if ($k === 'overtime') {
            $merged['overtime'] = array_merge($merged['overtime'], $v);
        } else {
            $merged[$k] = $v;
        }
    }
    return $merged;
}

function employee_period_hours(array $punchesForEmployee, array $rulesForEmployee): array
{
    $otRules = $rulesForEmployee['overtime'];
    $breakDefault = $rulesForEmployee['unpaid_break_minutes'] ?? 0;
    $byDay = [];
    foreach ($punchesForEmployee as [$date, $timeIn, $timeOut, $breakMinutes]) {
        $bm = $breakMinutes ?: $breakDefault;
        $byDay[$date] = ($byDay[$date] ?? 0.0) + day_hours($timeIn, $timeOut, $bm);
    }
    ksort($byDay);
    return split_regular_overtime(array_values($byDay), $otRules['weekly_threshold_hours'], $otRules['daily_threshold_hours']);
}

/**
 * examples: list of [regular_hours, overtime_hours, expected_pay]
 * Solves pay = x*regular + y*overtime for x (hourly rate) and
 * y (rate*multiplier) via least squares.
 * Returns [rate, multiplier|null] or [null, null] if unsolvable.
 */
function solve_rate_and_multiplier(array $examples): array
{
    $sr2 = $so2 = $sro = $spr = $spo = 0.0;
    foreach ($examples as [$reg, $ot, $pay]) {
        $sr2 += $reg * $reg;
        $so2 += $ot * $ot;
        $sro += $reg * $ot;
        $spr += $pay * $reg;
        $spo += $pay * $ot;
    }
    $det = $sr2 * $so2 - $sro * $sro;
    if (abs($det) < 1e-9) {
        if (count($examples) === 1 && $examples[0][1] == 0) {
            [$reg, , $pay] = $examples[0];
            return $reg ? [$pay / $reg, null] : [null, null];
        }
        return [null, null];
    }
    $x = ($spr * $so2 - $spo * $sro) / $det;
    $y = ($sr2 * $spo - $sro * $spr) / $det;
    return [$x, $x ? $y / $x : null];
}

function get_opt(array $argv, string $name): ?string
{
    $idx = array_search($name, $argv, true);
    return ($idx !== false && isset($argv[$idx + 1])) ? $argv[$idx + 1] : null;
}

function cmd_init(): void
{
    if (!file_exists(EMPLOYEES_PATH)) {
        file_put_contents(EMPLOYEES_PATH, "employee_id,name,active\n");
    }
    if (!file_exists(RULES_PATH)) {
        save_rules(json_decode(json_encode(DEFAULT_RULES), true));
    }
    echo "Initialized " . EMPLOYEES_PATH . " and " . RULES_PATH . "\n";
}

function cmd_learn(array $argv): int
{
    $entriesPath = get_opt($argv, '--entries');
    $totalsPath = get_opt($argv, '--totals');
    if (!$entriesPath || !$totalsPath) {
        fwrite(STDERR, "learn requires --entries <csv> --totals <csv>\n");
        return 1;
    }

    $rules = load_rules();
    $employees = load_employees();
    $punches = read_punches($entriesPath);

    $totals = [];
    $fh = fopen($totalsPath, 'r');
    $header = fgetcsv($fh);
    while (($row = fgetcsv($fh)) !== false) {
        $rec = array_combine($header, $row);
        $eid = trim($rec['employee_id']);
        $totals[$eid][] = (float) $rec['expected_gross_pay'];
    }
    fclose($fh);

    echo "Inferred pay rules (review before trusting):\n\n";
    foreach ($punches as $eid => $entries) {
        if (!isset($totals[$eid])) {
            continue;
        }
        $r = rules_for($rules, $eid);
        [$regular, $overtime] = employee_period_hours($entries, $r);
        $pay = $totals[$eid][0];
        [$rate, $mult] = solve_rate_and_multiplier([[$regular, $overtime, $pay]]);
        $name = $employees[$eid]['name'] ?? $eid;

        if ($rate === null) {
            echo "  $name ($eid): cannot solve uniquely from this single example -- "
                . "provide a second example with different overtime hours, or state "
                . "the rate/multiplier directly.\n";
            continue;
        }

        $rules['employees'][$eid] = $rules['employees'][$eid] ?? [];
        $rules['employees'][$eid]['hourly_rate'] = round($rate, 4);
        $note = '';
        if ($mult !== null) {
            $rules['employees'][$eid]['overtime'] = ($rules['employees'][$eid]['overtime'] ?? []);
            $rules['employees'][$eid]['overtime']['multiplier'] = round($mult, 3);
        } else {
            $note = sprintf(" (no overtime in this example -- kept default %sx multiplier, please confirm)",
                $r['overtime']['multiplier']);
        }
        printf("  %s (%s): rate=\$%.2f/hr  reg=%.2fh  ot=%.2fh%s\n", $name, $eid, $rate, $regular, $overtime, $note);
    }

    save_rules($rules);
    echo "\nSaved to " . RULES_PATH . "\n";
    return 0;
}

function cmd_compute(array $argv): int
{
    $entriesPath = get_opt($argv, '--entries');
    $outPath = get_opt($argv, '--out');
    if (!$entriesPath) {
        fwrite(STDERR, "compute requires --entries <csv>\n");
        return 1;
    }

    $rules = load_rules();
    $employees = load_employees();
    $punches = read_punches($entriesPath);

    $missing = [];
    foreach ($employees as $eid => $info) {
        if ($info['active'] && !isset($punches[$eid])) {
            $missing[] = $eid;
        }
    }

    $unrated = [];
    $reportRows = [];
    foreach ($punches as $eid => $entries) {
        $r = rules_for($rules, $eid);
        if ($r['hourly_rate'] === null) {
            $unrated[] = $eid;
            continue;
        }
        [$regular, $overtime] = employee_period_hours($entries, $r);
        $rate = $r['hourly_rate'];
        $mult = $r['overtime']['multiplier'];
        $gross = $regular * $rate + $overtime * $mult * $rate;
        $name = $employees[$eid]['name'] ?? $eid;
        $reportRows[] = [
            'employee_id' => $eid,
            'name' => $name,
            'regular_hours' => round($regular, 2),
            'overtime_hours' => round($overtime, 2),
            'hourly_rate' => $rate,
            'gross_pay' => round($gross, 2),
        ];
    }

    if ($outPath) {
        $fh = fopen($outPath, 'w');
        fputcsv($fh, ['employee_id', 'name', 'regular_hours', 'overtime_hours', 'hourly_rate', 'gross_pay']);
        foreach ($reportRows as $row) {
            fputcsv($fh, array_values($row));
        }
        fclose($fh);
    }

    foreach ($reportRows as $row) {
        printf("%-20s reg=%6.2fh  ot=%5.2fh  rate=\$%.2f  gross=\$%.2f\n",
            $row['name'], $row['regular_hours'], $row['overtime_hours'], $row['hourly_rate'], $row['gross_pay']);
    }

    if ($unrated) {
        echo "\nNo learned pay rate for these employees (skipped) -- "
            . "run `learn` first or set rules.json manually:\n";
        foreach ($unrated as $eid) {
            echo "  - $eid (" . ($employees[$eid]['name'] ?? 'unknown') . ")\n";
        }
    }

    if ($missing) {
        echo "\nNo time entries found this period for:\n";
        foreach ($missing as $eid) {
            echo "  - $eid (" . $employees[$eid]['name'] . ")\n";
        }
        echo "Please confirm: did they not work, or were entries not submitted yet?\n";
    }

    return ($missing || $unrated) ? 1 : 0;
}

function main(array $argv): int
{
    $command = $argv[1] ?? null;
    $rest = array_slice($argv, 1);
    switch ($command) {
        case 'init':
            cmd_init();
            return 0;
        case 'learn':
            return cmd_learn($rest);
        case 'compute':
            return cmd_compute($rest);
        default:
            fwrite(STDERR, "Usage: php payroll.php <init|learn|compute> [options]\n");
            return 1;
    }
}

exit(main($argv));
