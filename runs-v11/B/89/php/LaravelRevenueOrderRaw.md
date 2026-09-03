## Verdict

Exploitable. The `$sort` parameter flows from user input (via HTTP request in `RevenueController::index()`) directly to the `orderByRaw()` sink without validation.

## Source

`$request['sort']` in `RevenueController::index()` (line 11, defaults to `'created_at desc'`) flows to the `$sort` parameter of `RevenueRepository::forAccount()`.

## Fix

**Vulnerable code:**
```php
final class RevenueRepository
{
    public function forAccount(string $accountId, string $range, string $sort): array
    {
        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($sort)  // SQL injection: $sort is unvalidated
            ->get()
            ->all();
    }
    // ...
}
```

**Fixed code:**
```php
final class RevenueRepository
{
    private const ALLOWED_SORTS = [
        'created_at asc',
        'created_at desc',
        'total asc',
        'total desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter against allowlist
        if (!in_array($sort, self::ALLOWED_SORTS, true)) {
            throw new InvalidArgumentException("Invalid sort parameter");
        }

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($sort)
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

SQL injection occurs when untrusted input is incorporated into SQL queries without proper validation. The `orderByRaw()` method is a raw SQL sink that executes its argument directly; ORDER BY clauses cannot use parameter binding because they reference structural elements (column names and sort directions) rather than data values. The fix applies allowlist validation: define a fixed set of permitted sort values (in this case, the legitimate combinations of allowed columns and directions), validate the input parameter against this list with strict type checking, and reject any value not in the allowlist by throwing an exception. This prevents an attacker from injecting malicious SQL syntax through the sort parameter (e.g., `"created_at desc; DROP TABLE revenue_events;--"`).

## Behaviour changes

None. For valid input present in the allowlist, the fixed code produces identical output to the original. For invalid input, the original would pass it through to SQL execution (vulnerable); the fixed code throws an `InvalidArgumentException` instead (safe). The exception is appropriate for out-of-contract input and signals to calling code that the sort parameter requires validation at the API boundary.
