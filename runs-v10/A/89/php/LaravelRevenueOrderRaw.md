## Verdict

Real SQL injection vulnerability. The `$sort` parameter from the HTTP request flows directly into `orderByRaw()` without parameterization or validation, enabling arbitrary SQL execution.

## Source

`RevenueController::index()` receives `$sort` from the request array (line 11, defaulting to `'created_at desc'`), which is passed to `RevenueRepository::forAccount()`. At line 12 of RevenueRepository.php, this untrusted value reaches the sink: `->orderByRaw($sort)`.

## Fix

Replace `orderByRaw($sort)` with validated parameterized sorting in RevenueRepository.php:

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Parse sort parameter into column and direction
        $parts = explode(' ', trim($sort), 2);
        $column = $parts[0] ?? 'created_at';
        $direction = strtoupper($parts[1] ?? 'ASC');

        // Whitelist allowed columns
        $allowedColumns = ['created_at', 'account_id', 'amount'];
        if (!in_array($column, $allowedColumns, true)) {
            $column = 'created_at';
        }

        // Validate direction
        $direction = in_array($direction, ['ASC', 'DESC'], true) ? $direction : 'ASC';

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
}
```

## Explanation

`orderByRaw()` executes its argument as raw SQL without escaping. An attacker controlling `$sort` could inject commands like `created_at desc; DROP TABLE revenue_events; --`.

The fix prevents injection by:
1. **Parsing** the sort parameter to extract column and direction components
2. **Whitelisting columns** against allowed fields, rejecting any unknown column names
3. **Validating direction** to only `ASC` or `DESC`, rejecting other values
4. **Using `orderBy()`** instead of `orderByRaw()`, which properly escapes identifiers through Eloquent's query builder

This preserves legitimate sort functionality while eliminating the SQL injection surface.
