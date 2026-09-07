## Verdict

Exploitable. The untrusted user input from `$_GET['sku']` flows directly into an SQL query string via string concatenation, allowing attackers to inject arbitrary SQL clauses such as `' OR '1'='1` to bypass query logic or access unauthorized data.

## Source

Line 20: `$sku = $_GET['sku'] ?? ''` — untrusted user-supplied query parameter.

Data flows to line 5 where it is concatenated into the SQL query string, then to line 8 where the unsanitized query is executed via `PDO::query()`.

## Fix

**Vulnerable code (line 5-8):**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = '" . $sku . "'";

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
$stmt = $db->query($sql);
```

**Fixed code:**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = ?";

$stmt = $db->prepare($sql);

if ($stmt === false) {
    return null;
}

if (!$stmt->execute([$sku])) {
    return null;
}
```

## Explanation

The fix replaces string concatenation with a prepared statement using PDO's `prepare()` and `execute()` methods. The placeholder `?` marks the parameter position in the query; the untrusted `$sku` value is passed to `execute()` as a bound parameter, which is transmitted to the database server as data, never as executable SQL. This separates query structure from data and prevents an attacker-controlled value from altering the query logic. Error handling is preserved: `prepare()` returns `false` on failure (caught in the first check), and `execute()` returns `false` on parameter binding or execution failure (caught in the second check). The remainder of the function — the fetch, the return contract, and the calling code — remains unchanged.

## Behaviour changes

**Error handling:** Two additional error checks added.
- `if ($stmt === false)` checks whether `prepare()` succeeded. This mirrors the original pattern from lines 10-12 (`if ($stmt === false)`), so it preserves the existing error semantics.
- `if (!$stmt->execute([...]))` checks whether parameter binding and query execution succeeded. The original code passed the burden of error detection to the caller (via `if ($stmt === false)` on line 10), but with `prepare()`, the query is not executed until `execute()` is called, so the check must occur at that point. This is a necessary change to detect execution failures in this new structure; it does not alter the return value (still `null` on error).

**Sink contract:** The sink (`$db->prepare()` followed by `$stmt->execute()`) produces the same `PDOStatement` object that the original `$db->query()` call produced, so `fetch()`, the return value, and the response encoding remain identical. No silent behaviour changes.

