## Verdict

Exploitable. The `$sort` parameter flows from untrusted user input in `RevenueController.index()` directly to `orderByRaw()` in `RevenueRepository.forAccount()` without validation. Since identifiers like ORDER BY clauses cannot be parameterized, the unvalidated input is directly interpolated into the SQL query, allowing an attacker to inject arbitrary SQL (e.g., `created_at desc; DROP TABLE revenue_events; --`).

## Source

User input: `$request['sort']` in `RevenueController.index()` line 11, which defaults to `'created_at desc'` but accepts any caller-supplied string and passes it to `RevenueRepository.forAccount()` at line 13.

## Fix

### File: RevenueRepository.php

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    /**
     * Permitted ORDER BY values for forAccount queries.
     * Identifiers cannot be parameterized and must be validated against a whitelist.
     */
    private const ALLOWED_SORTS = [
        'created_at asc',
        'created_at desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter against allowlist to prevent SQL injection
        if (!in_array($sort, self::ALLOWED_SORTS, true)) {
            throw new \InvalidArgumentException("Invalid sort parameter: {$sort}");
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

The fix closes the SQL injection vulnerability by implementing allowlist-based validation of the `$sort` parameter before it reaches the `orderByRaw()` sink. ORDER BY identifiers cannot be parameterized in SQL, so they must be validated against a fixed set of permitted values. The `ALLOWED_SORTS` constant defines the only sort orders permitted for revenue queries (`created_at asc` and `created_at desc`). Before using the sort parameter, the code checks that it matches one of these allowed values using strict equality (`in_array(..., true)`). If an attacker attempts to inject SQL through the `sort` parameter, it will fail the validation check and an `InvalidArgumentException` will be thrown instead of executing the malicious query. This approach follows Laravel's guidance for handling dynamic identifiers: treat them as keys into a server-controlled map, not as input to validate and then pass through.

## Behaviour changes

The function now throws `InvalidArgumentException` when called with a sort value not in the allowlist, rather than silently executing arbitrary SQL. This is a necessary breaking change: attackers previously had unrestricted ability to inject SQL, and legitimate callers should only be using the defined sort options. The default sort parameter in `RevenueController.index()` (`'created_at desc'`) remains supported and will not trigger the exception. Any legitimate use cases requiring additional sort fields can be added to `ALLOWED_SORTS`, but require explicit enumeration rather than arbitrary user input.
