## Verdict

**Exploitable.** User-supplied `$sort` parameter flows from `RevenueController` line 11 directly into `orderByRaw()` at `RevenueRepository` line 12 without validation or parameterization. The `orderByRaw()` method executes raw SQL, allowing an attacker to inject arbitrary SQL through the ORDER BY clause—for example, `created_at desc; DROP TABLE revenue_events; --`.

## Source

`RevenueController.php` line 11: `$sort = $request['sort'] ?? 'created_at desc'`

The `$sort` variable is populated from untrusted request data and passed directly to the repository's `forAccount()` method on line 13.

## Fix

**RevenueRepository.php:**

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const ALLOWED_SORTS = [
        'created_at asc',
        'created_at desc',
        'id asc',
        'id desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter against allowlist
        $validSort = $this->validateSort($sort);

        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($validSort)
            ->get()
            ->all();
    }

    private function validateSort(string $sort): string
    {
        // Treat sort as a key into a server-controlled map of permitted values
        if (!in_array($sort, self::ALLOWED_SORTS, true)) {
            // Reject invalid input; do not use the original tainted value
            throw new \InvalidArgumentException(sprintf('Invalid sort parameter: %s', $sort));
        }
        // Use the allowlist value, not the original input
        return $sort;
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
```

## Explanation

The vulnerability occurs because `$sort` is passed directly to `orderByRaw()`, which executes it as raw SQL. Since ORDER BY clauses contain structural query elements (column name and direction) that cannot be bound as parameters, they require allowlist validation.

The fix:

1. Defines `ALLOWED_SORTS` as a constant holding only the permitted sort options that the application needs (`created_at asc`, `created_at desc`, `id asc`, `id desc`).
2. Adds a `validateSort()` method that checks whether the input matches an allowlist entry using strict comparison (`in_array(..., true)`).
3. Rejects invalid input by throwing an exception rather than passing the tainted value downstream.
4. Uses the validated value from the allowlist in the `orderByRaw()` call.

This pattern treats the dynamic sort parameter as a key into a server-controlled map (the allowlist) rather than as input to validate and then reuse. An attacker cannot inject SQL through this parameter because the value must match one of the predetermined safe options exactly.

## Behaviour changes

**Before:** The application accepted any string as a sort parameter, including SQL injection payloads like `created_at desc; DROP TABLE revenue_events; --`.

**After:** The application rejects any sort value not in the `ALLOWED_SORTS` constant and throws an `InvalidArgumentException`. Only the predefined sort directions (`created_at asc`, `created_at desc`, `id asc`, `id desc`) are accepted. If a client sends an unexpected sort value, the request fails rather than silently executing injected SQL.

This is a breaking change only if the application previously accepted sort values outside the allowlist; if the application is designed to support only a fixed set of sort options (which is typical), this change aligns implementation with design and has no impact on legitimate clients.
