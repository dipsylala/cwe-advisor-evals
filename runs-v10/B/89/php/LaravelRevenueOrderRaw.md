## Verdict

**Exploitable SQL Injection confirmed.** The `$sort` parameter from the HTTP request (RevenueController.php:11) is passed unsanitized to `orderByRaw()` at RevenueRepository.php:12, allowing an attacker to inject arbitrary SQL commands.

## Source

**Source:** RevenueController.php:11
```
$sort = $request['sort'] ?? 'created_at desc';
```
User-controlled input from the request is assigned to `$sort` without validation.

**Sink:** RevenueRepository.php:12
```
->orderByRaw($sort)
```
The parameter flows directly into raw SQL execution.

## Fix

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const PERMITTED_SORTS = [
        'created_at asc',
        'created_at desc',
        'total asc',
        'total desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter against allowlist of complete sort expressions
        if (!in_array($sort, self::PERMITTED_SORTS, true)) {
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

ORDER BY expressions cannot be parameterized—they specify query structure rather than data values. Per CWE-89 PHP guidance, SQL identifiers must be validated against an explicit allowlist of permitted values. The fix defines `PERMITTED_SORTS` as a class constant containing only legitimate, complete sort expressions, then validates the incoming `$sort` using strict comparison (`in_array()` with the `true` flag). Only validated values are passed to `orderByRaw()`. This prevents injection while preserving the dynamic sort behaviour within a pre-approved set. The default value `'created_at desc'` from the controller passes validation.

## Behaviour changes

- Sort parameter is now restricted to the allowlist: `created_at asc`, `created_at desc`, `total asc`, `total desc`.
- Any sort value not in the allowlist raises `InvalidArgumentException`; the controller must handle this exception or ensure valid input.
- Default behaviour unchanged for valid requests matching the allowlist.
