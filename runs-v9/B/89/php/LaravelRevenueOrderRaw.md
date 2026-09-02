## Verdict

- **CWE-89** - Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **Location**: `RevenueRepository.php`, line 12, `orderByRaw($sort)`
- **Verdict**: exploitable
- **Confidence**: high

## Source

`RevenueController::index()` reads `$sort` directly from the incoming request array, with only a static default and no validation:

```
$sort = $request['sort'] ?? 'created_at desc';
```

It passes `$sort` unchanged into `RevenueRepository::forAccount($accountId, $range, $sort)`, which forwards it straight into `orderByRaw($sort)` at line 12. `orderByRaw()` is a Laravel raw sink - its argument is concatenated into the query's `ORDER BY` clause verbatim, and here it receives the full attacker-controlled string with no bindings and no allowlist check, so an attacker can inject arbitrary SQL (e.g. a subquery or stacked expression) via the `sort` request parameter.

The other two parameters on the same call are not exploitable:
- `$accountId` reaches `->where('account_id', '=', $accountId)`, which Eloquent/Query Builder binds as a parameter - safe.
- `$range` only reaches `daysForRange()`, which uses a strict `===` comparison against the literal `'year'` and returns one of two fixed integers (365 or 31) - `$range` itself never reaches the query, so this path is not exploitable.

## Fix

Vulnerable code (`RevenueRepository.php`):

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    public function forAccount(string $accountId, string $range, string $sort): array
    {
        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($sort) // VULNERABLE: unvalidated request value concatenated into ORDER BY
            ->get()
            ->all();
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
```

Fixed code:

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const ALLOWED_SORTS = [
        'created_at desc' => ['created_at', 'desc'],
        'created_at asc'  => ['created_at', 'asc'],
        'total desc'      => ['total', 'desc'],
        'total asc'       => ['total', 'asc'],
    ];

    private const DEFAULT_SORT = 'created_at desc';

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        [$sortColumn, $sortDirection] = self::ALLOWED_SORTS[$sort]
            ?? self::ALLOWED_SORTS[self::DEFAULT_SORT];

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderBy($sortColumn, $sortDirection)
            ->get()
            ->all();
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
```

## Explanation

`orderByRaw()` cannot bind its argument the way `whereRaw()` binds values - an `ORDER BY` clause is structure (column and direction), not a value, so there is nothing to parameterize. The fix treats `$sort` as a key into a fixed, server-controlled allowlist (`ALLOWED_SORTS`) rather than as input to sanitize: the raw request string is looked up in the map, and only the map's own canonical `[column, direction]` pair - never the caller-supplied string - reaches the query, via the safe `orderBy($column, $direction)` builder method. An unrecognized `sort` value falls back to the same default the controller previously used (`'created_at desc'`), so the endpoint keeps working for any input instead of erroring, while no attacker-controlled string ever reaches SQL text. `$accountId` and `$range` were already handled safely and are unchanged.

## Behaviour changes

- **Unrecognized `sort` values now silently fall back to the default order (`created_at desc`) instead of being executed as raw SQL.** Previously, any string reaching `orderByRaw()` unchanged would either run as-is (if valid SQL) or throw a database error (if malformed). Falling back to a safe default is the intended effect of the allowlist fix, but it does mean a caller who previously relied on some other raw `ORDER BY` expression working will now silently get the default order instead of an error - flag this if any legitimate caller depended on an undocumented sort string.
- **`orderByRaw($sort)` replaced with `orderBy($sortColumn, $sortDirection)`.** This changes how the ORDER BY is built (bound structure via allowlist vs. raw string) but produces the same clause shape (`ORDER BY <column> <direction>`) for every currently-supported sort value, so output ordering for legitimate inputs is unchanged.
- No change to `$accountId` or `$range` handling, to the query's `WHERE`/`whereRaw` clauses, to the method signature, or to the return value/shape (`->get()->all()`).
