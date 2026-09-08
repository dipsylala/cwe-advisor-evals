## Verdict
Confirmed. `RevenueRepository::forAccount()` passes the request-controlled `$sort` string straight into `orderByRaw($sort)`. Laravel's query builder parameterizes `where`/`whereRaw` bindings, but `orderByRaw()` has no binding mechanism for column names or sort direction — its argument is concatenated directly into the `ORDER BY` clause of the generated SQL. An attacker who controls the `sort` request parameter can inject arbitrary SQL (e.g. subqueries, `UNION`-based extraction via error/boolean/time-based techniques, or stacked expressions), independent of the `account_id` binding being safe.

## Source
`RevenueController::index()` reads `sort` directly from the inbound request array (`$request['sort'] ?? 'created_at desc'`) with no validation, and passes it unchanged into `RevenueRepository::forAccount()`, which forwards it to `orderByRaw($sort)` at `RevenueRepository.php:12`. The `account_id` and `range` parameters are also attacker-controlled but are already handled safely: `account_id` goes through a bound `where()` clause, and `range` is mapped through `daysForRange()` to one of two fixed integers before being bound into `whereRaw`. `sort` is the only value that reaches SQL text unvalidated.

## Fix
Replace the raw sort sink with `orderBy()` fed from a server-side allowlist that maps accepted sort tokens to real column names and directions, so no attacker-supplied text ever reaches the query as SQL. `orderByRaw()` is removed entirely; unrecognized input falls back to the existing default order instead of being passed through.

### File: RevenueRepository.php
```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    /**
     * Allowlist of sortable columns. Only these keys (matched case-insensitively
     * against the "column direction" request token) may reach the ORDER BY clause.
     */
    private const SORTABLE_COLUMNS = [
        'created_at' => 'created_at',
        'amount' => 'amount',
    ];

    private const DEFAULT_COLUMN = 'created_at';
    private const DEFAULT_DIRECTION = 'desc';

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

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }

    /**
     * Maps a "column direction" request token to a known-safe column and
     * direction. Any column not in the allowlist, or any malformed token,
     * falls back to the default order rather than being used as-is.
     *
     * @return array{0: string, 1: string}
     */
    private function parseSort(string $sort): array
    {
        $parts = preg_split('/\s+/', trim($sort), 2) ?: [];
        $requestedColumn = strtolower($parts[0] ?? '');
        $requestedDirection = strtolower($parts[1] ?? '');

        $column = self::SORTABLE_COLUMNS[$requestedColumn] ?? self::DEFAULT_COLUMN;
        $direction = $requestedDirection === 'asc' ? 'asc' : self::DEFAULT_DIRECTION;

        return [$column, $direction];
    }
}
```

## Explanation
`orderBy($column, $direction)` uses Laravel's query grammar to validate and quote the column identifier and to constrain direction to `asc`/`desc` internally — it is not a raw string sink, so nothing attacker-controlled reaches SQL text. The allowlist (`SORTABLE_COLUMNS`) is the actual security boundary: only `created_at` and `amount` can be selected as sort columns, and direction is reduced to a strict `asc`/anything-else→`desc` check rather than being echoed. This is a legitimate use of an allowlist because the application, not an external format, defines the finite set of valid sort columns — unlike a general-purpose input-shape allowlist, it isn't rejecting otherwise-valid data, only closing the sink.

This does not weaken existing behavior: the default token `'created_at desc'` still maps to `created_at`/`desc`, matching the prior default. `account_id`'s binding and `range`'s mapping to 31/365 days are untouched. Any `sort` value outside the allowlist (including SQL metacharacters, extra clauses, or unknown columns) now silently falls back to the default order instead of being rejected with an error or passed into the query, which avoids introducing a new error-oracle side channel while eliminating the injection.

A prescribed test that would have passed against the original vulnerable code — e.g. asserting no exception is thrown, or that results are returned — proves nothing, since `orderByRaw()` happily executes injected SQL and returns rows. The meaningful verification is structural: assert that `forAccount()` never invokes `orderByRaw()`/`DB::raw()` and that supplying a `sort` value containing SQL syntax (e.g. `created_at; DROP TABLE revenue_events; --` or a subquery) produces the same query shape as the default (`ORDER BY created_at desc`), while supplying `'amount asc'` produces `ORDER BY amount asc`.
