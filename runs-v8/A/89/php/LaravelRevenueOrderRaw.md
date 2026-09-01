## Verdict
True Positive

## Source
The vulnerability is in `RevenueRepository.php` at line 12. The `orderByRaw($sort)` method accepts the `$sort` parameter directly from user input via `RevenueController` line 11, where `$sort` is read from the request array with a default value of `'created_at desc'`. This parameter is then passed unsanitized to `orderByRaw()`, which executes it as raw SQL without parameter binding.

## Fix
Replace the unsafe `orderByRaw()` with a whitelist-validated approach:

```php
final class RevenueRepository
{
    private const ALLOWED_SORT_COLUMNS = [
        'created_at',
        'amount',
        'account_id',
    ];

    private const ALLOWED_DIRECTIONS = ['asc', 'desc'];

    public function forAccount(string $accountId, string $range, string $sort): array
    {
        // Validate and parse the sort parameter
        $sortParts = explode(' ', trim($sort), 2);
        $column = $sortParts[0] ?? 'created_at';
        $direction = strtolower($sortParts[1] ?? 'desc');

        // Validate against whitelist
        if (!in_array($column, self::ALLOWED_SORT_COLUMNS, true)) {
            $column = 'created_at';
        }
        if (!in_array($direction, self::ALLOWED_DIRECTIONS, true)) {
            $direction = 'desc';
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
The vulnerability arises because `orderByRaw()` executes its argument as raw SQL without any parameter binding or escaping. An attacker controlling the `$sort` parameter can inject arbitrary SQL—for example, `"created_at desc; DROP TABLE revenue_events;--"` would execute the DROP command.

The fix validates the sort parameter by:
1. Parsing the input to extract the column name and direction separately
2. Checking both against whitelists of allowed columns and directions
3. Using `orderBy($column, $direction)` instead of `orderByRaw()`, which safely binds the column and direction without executing user input as SQL

If the sort parameter does not match the whitelist, it defaults to the safe default `created_at` descending order, preventing injection while maintaining a predictable fallback behavior.
