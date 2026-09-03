## Verdict

SQL injection vulnerability confirmed. The `$sku` parameter from `$_GET` is concatenated directly into the SQL query string on line 5, then executed unparameterized on line 8. An attacker can supply `' OR '1'='1` or similar payloads to alter the query logic.

## Source

**Line 5:** Query string is built via concatenation with unsanitized user input.
```
$sql = "SELECT id, name, price, stock FROM products WHERE sku = '" . $sku . "'";
```

**Line 20:** The `$sku` variable originates from user input.
```
$sku = $_GET['sku'] ?? '';
```

**Line 8:** The unparameterized query is executed.
```
$stmt = $db->query($sql);
```

The data flow is: `$_GET['sku']` → `$sku` → string concatenation → `$sql` → `$db->query()`.

## Fix

Replace the query construction and execution with a prepared statement using placeholders:

```php
function findProductBySku(PDO $db, string $sku): ?array
{
    $stmt = $db->prepare("SELECT id, name, price, stock FROM products WHERE sku = ?");
    $stmt->execute([$sku]);

    if ($stmt === false) {
        return null;
    }

    $product = $stmt->fetch(PDO::FETCH_ASSOC);
    return $product !== false ? $product : null;
}
```

The key changes:
1. Use `PDO::prepare()` with a `?` placeholder instead of concatenating the parameter into the query string.
2. Pass user input separately to `execute()`, not into the SQL text.
3. PDO handles escaping and prevents the parameter from being interpreted as SQL syntax.

## Explanation

Prepared statements are the standard defense against SQL injection in PHP because they cleanly separate query structure from user data. The database driver receives the SQL template and the parameters as separate inputs, guaranteeing that user-supplied values cannot alter the query's intended meaning.

String concatenation leaves no way for the driver to distinguish between SQL syntax and data; any special characters in `$sku` (such as quotes, semicolons, or SQL keywords) are treated as part of the query structure. A payload like `' UNION SELECT password FROM users WHERE '1'='1` would execute successfully if passed this way.

PDO's `prepare()` and `execute()` enforce this separation: the template is parsed and validated before parameters are bound, and parameters are always treated as literal values, never as executable SQL. This is why parameterized queries are the recommended fix across all OWASP and vendor security guidance for SQL injection.
