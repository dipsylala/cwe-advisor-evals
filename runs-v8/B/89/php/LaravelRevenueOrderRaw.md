## Verdict

Exploitable. The `$sort` parameter on line 12 flows from user input directly into the `orderByRaw()` sink without validation, allowing SQL injection in the ORDER BY clause.

## Source

The `$sort` parameter (line 7) is user-controlled input passed to the method with no type narrowing beyond the string type hint.

## Fix

Replace the vulnerable `orderByRaw($sort)` with an allowlist-validated approach:

**Vulnerable code:**
```php
public function forAccount(string $accountId, string $range, string $sort): array
{
    return DB::table('revenue_events')
        ->where('account_id', '=', $accountId)
        ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
        ->orderByRaw($sort)  // SQL injection: $sort is unsanitized
        ->get()
        ->all();
}
```

**Fixed code:**
```php
public function forAccount(string $accountId, string $range, string $sort): array
{
    // Allowlist of permitted sort expressions mapped from caller input
    $allowedSorts = [
        'created_at_desc' => 'created_at DESC',
        'created_at_asc' => 'created_at ASC',
        'account_id_desc' => 'account_id DESC',
        'account_id_asc' => 'account_id ASC',
    ];
    
    // Validate and retrieve the permitted expression
    if (!isset($allowedSorts[$sort])) {
        throw new \InvalidArgumentException("Invalid sort parameter: {$sort}");
    }
    
    return DB::table('revenue_events')
        ->where('account_id', '=', $accountId)
        ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
        ->orderByRaw($allowedSorts[$sort])  // Now using validated value from allowlist
        ->get()
        ->all();
}
```

## Explanation

SQL identifiers like column names and ORDER BY directions cannot be bound as parameters. The PHP guidance prescribes treating dynamic identifiers as keys into a server-side map of permitted names—the value reaching the query should be from the allowlist map, never the caller's input. The fix defines an allowlist mapping caller-friendly sort keys (e.g., `'created_at_desc'`) to vetted SQL expressions. When `$sort` is received, it is validated against the allowlist keys. If valid, the corresponding safe SQL expression is retrieved and passed to `orderByRaw()`. If invalid, an `InvalidArgumentException` is thrown, rejecting the malicious input. This ensures only pre-approved sort expressions can enter the query.

## Behaviour changes

The method now rejects invalid sort parameters by throwing `InvalidArgumentException` rather than silently accepting them. Callers must use one of the allowlist keys (`'created_at_desc'`, `'created_at_asc'`, `'account_id_desc'`, `'account_id_asc'`) instead of arbitrary SQL strings. The method's return type and structure remain unchanged. Testing with injection payloads (e.g., `'created_at; DROP TABLE revenue_events; --'`) will now raise an exception instead of executing malicious SQL.
