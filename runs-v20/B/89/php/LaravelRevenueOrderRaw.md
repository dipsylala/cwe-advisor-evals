## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

- Location: `RevenueRepository.php`, line 12 (`orderByRaw($sort)`).
- Source: `$request['sort']` in `RevenueController::index()` (defaults to `'created_at desc'` if absent, but otherwise passed through from the request unvalidated).
- Sink: `orderByRaw($sort)` in `RevenueRepository::forAccount()`.

## Source

`RevenueController::index()` reads `$sort = $request['sort'] ?? 'created_at desc';` directly from the incoming request array and passes it, unvalidated, to `RevenueRepository::forAccount($accountId, $range, $sort)`.

`forAccount()` then passes `$sort` straight into `->orderByRaw($sort)` with no bindings and no validation. `orderByRaw()` inserts its argument verbatim into the generated SQL's `ORDER BY` clause, so an attacker-controlled `sort` value (e.g. `created_at; DROP TABLE revenue_events;--` or a boolean/UNION-based subquery) is executed as raw SQL. This is a distinct, unrelated sink from the same method's `whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [...])` call, which is already safely parameterized via a `?` placeholder and bindings array, and from `where('account_id', '=', $accountId)`, which Eloquent binds automatically - neither of those needed a change.

An `ORDER BY` column/direction is an identifier/keyword position, not a bindable value, so this cannot be fixed with a placeholder; it requires allowlist validation of the column and direction, per the loaded CWE-89 guidance (root `cwe/89/INDEX.md` and `cwe/89/php/INDEX.md`), which states the canonical allowlisted value must be substituted for the raw input at the sink, not merely validated and then passed through.

## Fix

### File: RevenueRepository.php
```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const SORTABLE_COLUMNS = ['created_at'];
    private const SORT_DIRECTIONS = ['asc', 'desc'];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($this->safeSort($sort))
            ->get()
            ->all();
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }

    private function safeSort(string $sort): string
    {
        [$column, $direction] = array_pad(explode(' ', trim($sort), 2), 2, 'desc');

        $column = in_array(strtolower($column), self::SORTABLE_COLUMNS, true)
            ? strtolower($column)
            : self::SORTABLE_COLUMNS[0];

        $direction = in_array(strtolower($direction), self::SORT_DIRECTIONS, true)
            ? strtolower($direction)
            : 'desc';

        return "{$column} {$direction}";
    }
}
```

## Explanation

`forAccount()` no longer hands the raw, request-controlled `$sort` string to `orderByRaw()`. It first passes it through a new private `safeSort()` helper that splits the string into a column and a direction, checks each against a fixed, server-defined allowlist (`SORTABLE_COLUMNS`, `SORT_DIRECTIONS`), and returns a freshly built string composed only of the matched allowlist literals - never the caller's original substrings. `orderByRaw()` then receives only this trusted, reconstructed value. Because an `ORDER BY` column/direction is a SQL identifier/keyword position rather than a bindable value, a placeholder cannot be used here; the allowlist substitution is the correct primary defence per the loaded guidance, and it eliminates the injection because no attacker-supplied byte reaches the generated SQL. `SORTABLE_COLUMNS` currently lists only `created_at`, the one column this file's code shows is queried against; if the application intends additional sortable columns (e.g. an amount/total field), they should be added to this allowlist explicitly rather than the check being loosened to accept arbitrary identifiers - schema details for `revenue_events` beyond `account_id` and `created_at` are not visible in the provided call chain.

## Behaviour changes

- An unrecognized or malformed `sort` value (anything other than `created_at`/`created_at asc`/`created_at desc`, case-insensitively) now silently falls back to `created_at desc` instead of being passed to the database (where it would previously either error or, if it happened to be valid SQL, execute attacker-chosen logic). This is the intended effect of the allowlist fix, matching the existing method's own default-on-missing-input pattern (`$range` and `$sort` already default when absent in the controller).
- Sorting on any column other than `created_at` (e.g. a hypothetical amount/total column) is no longer possible even if it was previously reachable via a valid raw string - narrowed deliberately to the one column shown in the visible code; broadening it requires adding the real column name to `SORTABLE_COLUMNS`.
- No changes to `RevenueController.php`, to the `account_id` `where()` clause, to the parameterized `whereRaw()` date-range clause, or to the method's return type/shape.

Verification: `php -l` was run against the fixed file in a scratch copy outside the repository - "No syntax errors detected". `array_pad`, `explode`, `in_array`, and `strtolower` are PHP standard-library functions requiring no new dependency; `DB::table()->where()->whereRaw()->orderByRaw()->get()->all()` is the same Laravel Eloquent query-builder chain already present in the original file, unchanged in signature.
