## Verdict
SQL injection vulnerability confirmed. User-controlled input from `$request['sort']` flows unsanitized through the controller to `orderByRaw()`, permitting arbitrary SQL execution.

## Source
The `$sort` parameter originates in `RevenueController::index()` from `$request['sort']` (line 11) and is passed directly to `RevenueRepository::forAccount()` (line 13), which uses it in `orderByRaw($sort)` (line 12 of RevenueRepository.php) without validation.

## Fix
```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const ALLOWED_COLUMNS = ['id', 'account_id', 'created_at', 'amount'];
    
    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter format: "column asc|desc"
        if (!preg_match('/^([a-z_]+)\s+(asc|desc)$/i', trim($sort), $matches)) {
            throw new \InvalidArgumentException('Invalid sort parameter');
        }
        
        $column = strtolower($matches[1]);
        $direction = strtoupper($matches[2]);
        
        // Whitelist column names
        if (!in_array($column, self::ALLOWED_COLUMNS, true)) {
            throw new \InvalidArgumentException('Sort column not allowed');
        }
        
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
The original code passes `$sort` directly to `orderByRaw()`, which executes it as raw SQL. An attacker could inject clauses like `id; DROP TABLE revenue_events; --` to execute arbitrary commands.

The fix:
1. **Validates format**: The regex requires `"column asc|desc"` pattern, rejecting injected SQL syntax.
2. **Whitelists columns**: Only allows sorting by explicitly permitted columns (`ALLOWED_COLUMNS`), preventing references to schema-altering operations or sensitive data.
3. **Uses parameterized API**: `orderBy($column, $direction)` with separate parameters replaces `orderByRaw()`, ensuring Laravel constructs the SQL safely.
4. **Throws exceptions**: Invalid sorts are rejected at call time rather than silently failing or being logged, making injection attempts visible.
