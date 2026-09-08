## Verdict

SQL injection via unsanitized sort parameter passed to `orderByRaw()`.

## Source

User input flows from `$request['sort']` in RevenueController (line 11) to `RevenueRepository::forAccount($sort)` (line 13), then directly into `orderByRaw($sort)` at line 12 of RevenueRepository, where it is treated as raw SQL.

## Fix

### File: RevenueRepository.php

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const ALLOWED_SORT_COLUMNS = ['created_at', 'amount', 'account_id'];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        [$column, $direction] = $this->validateSortParameter($sort);

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderBy($column, $direction)
            ->get()
            ->all();
    }

    private function validateSortParameter(string $sort): array
    {
        $parts = explode(' ', trim($sort), 2);
        $column = $parts[0];
        $direction = strtolower($parts[1] ?? 'asc');

        if (!in_array($column, self::ALLOWED_SORT_COLUMNS, true)) {
            throw new \InvalidArgumentException("Invalid sort column: {$column}");
        }

        if (!in_array($direction, ['asc', 'desc'], true)) {
            throw new \InvalidArgumentException("Invalid sort direction: {$direction}");
        }

        return [$column, $direction];
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
```

## Explanation

The fix validates the `$sort` parameter against a fixed allowlist of permitted columns (`ALLOWED_SORT_COLUMNS`) and validates the direction against only `'asc'` or `'desc'`. It parses the sort parameter to extract the column and direction, validates both independently, and then uses Laravel's safe `orderBy($column, $direction)` method which properly handles the identifiers without raw SQL execution.

This prevents SQL injection because:
1. Only columns in the allowlist can be used, rejecting any malicious SQL
2. Direction is strictly limited to valid values
3. `orderBy()` safely handles the identifiers rather than treating them as raw SQL
4. The allowlist approach follows CWE-89 PHP guidance: "Treat a dynamic identifier as a key into a server-side map of permitted names"
