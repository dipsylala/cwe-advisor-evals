## Verdict

Exploitable.

## Source

`$region` at line 15: `$request->query('region', '')` - attacker-controlled user input from query parameters, with no default constraint applied.

## Fix

**Vulnerable code (line 17-24):**
```php
$sql = "SELECT product_id, SUM(amount) AS total
        FROM sales
        WHERE region = '" . $region . "'
        GROUP BY product_id
        ORDER BY total DESC";

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
$rows = DB::select($sql);
```

**Fixed code:**
```php
$rows = DB::table('sales')
    ->select('product_id', DB::raw('SUM(amount) AS total'))
    ->where('region', '=', $region)
    ->groupBy('product_id')
    ->orderByDesc('total')
    ->get();
```

## Explanation

The fix replaces string concatenation with Laravel's fluent query builder. The `where('region', '=', $region)` clause uses parameterized query binding internally - Laravel's query builder always treats the third argument to `where()` as a value to be bound, never as part of the query structure. The `DB::raw()` call for the aggregate function preserves the `SUM(amount) AS total` expression in the SELECT, which cannot be parameterized. This eliminates the SQL injection vulnerability by ensuring `$region` is transmitted to the database as a parameter value, not as part of the query text.

## Behaviour changes

None. The fixed code produces the same result set. `DB::table('sales')->...->get()` returns a collection of objects matching the original rows, and Laravel's query builder handles aggregation identically to the raw SQL. The only substantive change is that `$region` is now a bound parameter, which closes the injection vulnerability without altering the query's semantics or output.
