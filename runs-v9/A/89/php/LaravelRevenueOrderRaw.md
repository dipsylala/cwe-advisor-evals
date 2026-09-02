## Verdict
Confirmed. `RevenueRepository::forAccount()` passes the `$sort` parameter directly into `orderByRaw()` at line 12, and `$sort` originates from unvalidated user input (`$request['sort']`) in `RevenueController::index()`. `orderByRaw()` inserts its argument into the SQL statement verbatim, with no parameter binding, so an attacker-controlled `sort` value is concatenated straight into the `ORDER BY` clause. This allows arbitrary SQL injection (e.g. stacked clauses, subqueries, boolean/time-based blind extraction) via the `sort` request field.

## Source
`$request['sort']` in `RevenueController::index()` (line 11, defaulting to `'created_at desc'` only when absent) flows unmodified as the `$sort` argument into `RevenueRepository::forAccount()` (line 13), which passes it straight to `orderByRaw($sort)` (line 12) — the sink.

## Fix
```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    /**
     * Whitelist of sortable columns exposed to callers. Keys are the
     * external "sort" values callers may request; values are the actual
     * column names used in the query.
     */
    private const SORTABLE_COLUMNS = [
        'created_at' => 'created_at',
        'amount' => 'amount',
        'account_id' => 'account_id',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        [$column, $direction] = $this->parseSort($sort);

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderBy($column, $direction)
            ->get()
            ->all();
    }

    private function parseSort(string $sort): array
    {
        [$field, $dir] = array_pad(explode(' ', trim($sort), 2), 2, 'asc');

        $column = self::SORTABLE_COLUMNS[$field] ?? 'created_at';
        $direction = strtolower($dir) === 'desc' ? 'desc' : 'asc';

        return [$column, $direction];
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
```

The controller (`RevenueController.php`) needs no change — it can continue to pass the raw `sort` request value through, because validation now happens at the point where the value reaches SQL construction, in the repository.

Key changes:
- Replaced `orderByRaw($sort)` with `orderBy($column, $direction)`, using Laravel's query builder, which safely quotes/escapes identifiers instead of interpolating a raw string.
- Split the incoming `sort` string into a `field` and an optional `dir` token, then resolved `field` through a strict whitelist (`SORTABLE_COLUMNS`) mapping only known-safe column names — any unrecognized value falls back to a safe default (`created_at`) rather than being used verbatim.
- Constrained `direction` to exactly `asc` or `desc` via an explicit equality check, rather than passing the user-supplied token through.
- Left the existing `whereRaw(... ?, [...])` call untouched since it already uses a bound parameter and is not part of this finding.

## Explanation
`whereRaw()` in the original code is safe because the day count is passed through a `?` placeholder and bound, so the query builder handles escaping. `orderByRaw()` has no equivalent binding mechanism for column/direction names — it accepts a literal SQL fragment and appends it directly to the query string. Passing user input there is equivalent to string-concatenating a `WHERE` clause: an attacker can supply a `sort` value such as `1) UNION SELECT ... --` or a subquery/`CASE` expression to alter the query, extract other accounts' revenue data, or trigger errors/time delays for blind exfiltration, all without needing to break out of a quoted string since `orderByRaw` performs no quoting at all.

Column and sort-direction names cannot be parameterized with placeholders in SQL (placeholders bind values, not identifiers), so the correct defense is an allowlist: map every externally-supplied sort key to a fixed, known-safe column name and restrict direction to a closed set of literal values (`asc`/`desc`) determined in code, never taken verbatim from the request. Using `orderBy($column, $direction)` after this validation lets the query builder handle identifier quoting for the resolved column, and guarantees the direction can only ever be one of two hardcoded strings. Any `sort` input that doesn't match a whitelisted column degrades gracefully to a default order rather than being rejected outright or passed through, preserving existing behavior for legitimate values while eliminating the injection vector.
