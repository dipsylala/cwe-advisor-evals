## Verdict

CONFIRMED. The code is vulnerable to SQL injection via the `orderByRaw()` sink on line 12 of RevenueRepository.php.

## Source

**File:** RevenueController.php  
**Line:** 11  
**Code:** `$sort = $request['sort'] ?? 'created_at desc'`

The `$sort` parameter originates from user input in the request array with a default value. This untrusted value is passed directly to `forAccount()` in the repository without any validation.

## Fix

### File: RevenueRepository.php

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    // Allowlist of permitted ORDER BY expressions
    private const PERMITTED_SORTS = [
        'created_at asc',
        'created_at desc',
        'total asc',
        'total desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort against allowlist; reject injection attempts
        $validatedSort = in_array(strtolower($sort), self::PERMITTED_SORTS, true)
            ? $sort
            : 'created_at desc';

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($validatedSort)
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

The vulnerability exists because `orderByRaw()` in Laravel is a raw SQL sink that executes untrusted data as query structure. Column names and ORDER BY directions cannot be bound as parameters (CWE-89 guidance: "placeholders stand in for values, not for structure"), so they must be validated against a fixed allowlist of permitted identifiers.

The fix defines a class-level constant `PERMITTED_SORTS` containing the safe ORDER BY expressions the application needs. Before executing the query, the method validates the user-supplied `$sort` parameter against this allowlist using `in_array()` with case-insensitive comparison. If the sort matches an allowlisted value, it is used; otherwise, the code defaults to `'created_at desc'`. The validated value—not the untrusted user input—reaches `orderByRaw()`.

This approach closes the injection vector: an attacker attempting to inject SQL syntax like `'created_at desc; DROP TABLE revenue_events; --'` will fail the allowlist check and trigger the safe default instead.

## Behaviour changes

- **Injection attempts now rejected:** Invalid or malicious sort parameters that do not match the allowlist fall back to the safe default `'created_at desc'` instead of being concatenated into SQL.
- **Method interface unchanged:** The `forAccount()` signature and return type remain identical; callers are unaffected.
- **Legitimate sorts preserved:** Requests with sort values matching the allowlist (`'created_at asc'`, `'created_at desc'`, `'total asc'`, `'total desc'`) continue to work exactly as before.
- **Deterministic fallback:** When an invalid sort is supplied (e.g., from a browser request with a crafted parameter), the query always executes with the default sort order, providing consistent and predictable behaviour.
