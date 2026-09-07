## Verdict

SQL injection vulnerability in `orderByRaw()` clause due to unsanitized user input directly interpolated into a raw SQL query.

## Source

The vulnerability originates in `RevenueController.php` where user-supplied `$sort` parameter from `$request['sort']` is passed without validation to `RevenueRepository::forAccount()`. The `$sort` parameter flows directly into line 12 of `RevenueRepository.php` where it is used in `orderByRaw($sort)`, allowing an attacker to inject arbitrary SQL commands.

## Fix

Replace `orderByRaw()` with a whitelist-validated approach using Laravel's parameterized `orderBy()` method:

```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const ALLOWED_SORTS = [
        'created_at asc',
        'created_at desc',
        'amount asc',
        'amount desc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        $sortLower = strtolower($sort);
        
        if (!in_array($sortLower, self::ALLOWED_SORTS, true)) {
            $sort = 'created_at desc'; // Safe default
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

The fix introduces an allowlist of safe sort expressions in `ALLOWED_SORTS` constant. Before using the `$sort` parameter in the raw SQL clause, it is validated against this whitelist. If the user-supplied value does not match an allowed sort expression, a safe default (`created_at desc`) is used instead.

This approach:
- Blocks all SQL injection attempts by restricting input to a predefined set of safe column names and sort directions
- Maintains the intended functionality by allowing the most common sort combinations
- Uses case-insensitive comparison to handle user input variations
- Provides a sensible fallback default when invalid input is provided

The whitelist should be expanded or adjusted based on the actual columns and sort orders needed by the application, but crucially, only developer-controlled strings should appear in the constant.
