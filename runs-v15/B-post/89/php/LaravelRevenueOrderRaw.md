## Verdict
exploitable

## Source
RevenueController.php line 11: `$sort = $request['sort'] ?? 'created_at desc'`

## Fix

**Vulnerable code (RevenueRepository.php, line 12):**
```php
->orderByRaw($sort)
```

**Fixed code (RevenueRepository.php):**
```php
<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    private const PERMITTED_SORTS = [
        'created_at desc' => 'created_at desc',
        'created_at asc' => 'created_at asc',
        'revenue desc' => 'revenue desc',
        'revenue asc' => 'revenue asc',
    ];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate sort parameter against allowlist; default to safe value if invalid
        $validatedSort = self::PERMITTED_SORTS[$sort] ?? 'created_at desc';

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
The vulnerability occurs because `orderByRaw($sort)` concatenates untrusted user input directly into the SQL query without parameterization. In Laravel, `orderByRaw()` does not support parameter binding for the entire raw clause—ORDER BY expressions cannot be parameterized—so identifiers and expressions must be validated against an allowlist of permitted values. The fix introduces a `PERMITTED_SORTS` constant containing only the safe sort expressions the application should accept. When the user-supplied `$sort` parameter arrives, it is validated against this allowlist. If it matches, the mapped value from the allowlist is used; if not, a safe default is applied. This ensures that even if an attacker supplies a malicious sort expression like `'created_at desc; DROP TABLE users;--'`, the allowlist check rejects it and substitutes the default, preventing SQL injection.

## Behaviour changes
none
