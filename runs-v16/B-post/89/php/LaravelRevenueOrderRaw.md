## Verdict

Exploitable. The `$sort` parameter flows directly from user-controlled request input in RevenueController to the `orderByRaw()` sink in RevenueRepository without validation, allowing SQL injection.

## Source

RevenueController.php line 11: `$sort = $request['sort'] ?? 'created_at desc'` — untrusted user input from the request array, passed to the repository method on line 13.

## Fix

**Vulnerable code:**
```php
public function forAccount(string $accountId, string $range, string $sort): array
{
    return DB::table('revenue_events')
        ->where('account_id', '=', $accountId)
        ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
        ->orderByRaw($sort)  // SQL injection: $sort comes from user input without validation
        ->get()
        ->all();
}
```

**Fixed code:**
```php
final class RevenueRepository
{
    private const ALLOWED_COLUMNS = ['created_at', 'amount', 'total'];
    private const ALLOWED_DIRECTIONS = ['asc', 'desc'];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        [$column, $direction] = $this->parseSortParameter($sort);

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderBy($column, $direction)
            ->get()
            ->all();
    }

    private function parseSortParameter(string $sort): array
    {
        $parts = explode(' ', trim($sort), 2);
        $column = $parts[0] ?? null;
        $direction = strtolower($parts[1] ?? 'asc');

        if (!in_array($column, self::ALLOWED_COLUMNS, true)) {
            throw new InvalidArgumentException(sprintf('Invalid sort column: %s', $column));
        }

        if (!in_array($direction, self::ALLOWED_DIRECTIONS, true)) {
            throw new InvalidArgumentException(sprintf('Invalid sort direction: %s', $direction));
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

The vulnerability arises because `orderByRaw()` executes untrusted SQL without parameterization. SQL column names and directions cannot be bound as parameters—they are structural elements of the query—so raw SQL combined with user input enables SQL injection. The fix implements allowlist validation: the sort parameter is split into column and direction components, each validated against a whitelist of permitted values defined in class constants. Invalid input throws an `InvalidArgumentException` before reaching the database layer. The validated, now-trusted values are passed to Laravel's `orderBy()` method, which internally constructs safe SQL. This approach follows the principle of treating dynamic identifiers as a key into a server-side map rather than as input to be sanitized and reused.

## Behaviour changes

None. The fix uses the same query builder methods on the same table, returns the same result shape, throws exceptions only on invalid input that would have produced a SQL error anyway, and maintains compatibility with the existing method signature and return type. The allowlist of columns and directions can be expanded to include any columns callers need access to, making this a zero-regression fix—valid requests execute identically to before; only SQL injection attempts are now blocked.
