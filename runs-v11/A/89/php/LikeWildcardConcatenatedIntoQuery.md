## Verdict
SQL injection vulnerability confirmed. User-controlled input is concatenated directly into the SQL query string without parameterization.

## Source
Line 5 constructs the SQL query by concatenating the `$term` parameter directly into the query string:
```php
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
```

Although `PDO::prepare()` is called, the dangerous string concatenation happens before the query reaches the prepare method. The `$term` variable is embedded into the SQL literal, not passed as a bound parameter.

## Fix
Use parameterized queries with placeholders and bind the user input to execute:

```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
    $stmt->execute(["%{$term}%"]);
    return $stmt->fetchAll();
}
```

Alternatively, using named placeholders:

```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE :pattern");
    $stmt->execute([':pattern' => "%{$term}%"]);
    return $stmt->fetchAll();
}
```

## Explanation
The vulnerability occurs because string concatenation happens before the query is passed to `prepare()`. PDO's prepared statements only protect against injection when user input is passed through bound parameters to `execute()`, not when it is concatenated into the query string itself.

The fix applies the LIKE wildcard pattern (`%`) safely by binding the complete search pattern (including wildcards) as a single parameter. This ensures the entire value, including any special SQL characters, is treated as literal data rather than executable SQL code. An attacker cannot break out of the string or inject additional SQL logic through the `$term` parameter.
