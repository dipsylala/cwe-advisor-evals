## Verdict

Confirmed SQL Injection via string concatenation into a PDO query.

## Source

Untrusted `$sku` parameter from `$_GET['sku']` (line 20 of the vulnerable code) flows directly into the SQL query via string concatenation without parameterization.

## Fix

Replace string concatenation with PDO prepared statements using bound parameters.

**Vulnerable code (line 5-8):**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = '" . $sku . "'";
$stmt = $db->query($sql);
```

**Fixed code:**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = ?";
$stmt = $db->prepare($sql);
$stmt->execute([$sku]);
```

## Explanation

The vulnerability occurs at line 5 where the `$sku` variable is concatenated directly into the SQL query string. An attacker can inject SQL metacharacters—for example, passing `sku=' OR '1'='1` would bypass the WHERE clause, or `sku='; DROP TABLE products; --` would execute arbitrary SQL commands.

The fix uses PDO prepared statements, which separate query structure from data. The `prepare()` method pre-compiles the SQL with a placeholder (`?`), and `execute()` binds the user input as a parameter value. The database driver then ensures the value is treated as data only, not executable SQL, regardless of its content. This is the primary defence against SQL injection in PHP and is the mechanism recommended by both the general CWE-89 guidance and PHP-specific CWE-89 guidance.

## Behaviour changes

- **Query execution method:** Changed from `query()` to `prepare()` followed by `execute()`.
- **Return type:** `prepare()` returns a prepared statement object, which is the same type that `query()` returns on success, so the subsequent `fetch()` call at line 14 works identically.
- **Error handling:** `prepare()` may return `false` on error in some configurations, matching the existing `$stmt === false` check at line 10. No change to error-handling logic is required.
- **Parameter binding:** The user input is now bound as a data value through `execute()` rather than interpolated into the query string. The database guarantees it will never be interpreted as SQL structure.
