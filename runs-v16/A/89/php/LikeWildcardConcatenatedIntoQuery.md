## Verdict

Confirmed SQL injection vulnerability. The `$term` parameter is concatenated into the SQL query string before preparation, bypassing parameterization protection.

## Source

Line 5 constructs a query with direct string concatenation:

```php
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
```

The `$term` variable is concatenated into the query before `prepare()` receives it. An attacker can close the quoted string and inject SQL operators:

```php
searchProducts($pdo, "x' OR '1'='1");
// Produces: SELECT id, name FROM products WHERE name LIKE '%x' OR '1'='1%'
```

## Fix

Use parameterized queries with bound parameters. Move the wildcard characters into the parameter value:

```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
    $stmt->execute(['%' . $term . '%']);
    return $stmt->fetchAll();
}
```

## Explanation

PDO's `prepare()` only protects against injection if the query structure itself is fixed before binding. By concatenating `$term` into the query string before `prepare()`, the fix was never applied. The corrected code separates concerns: the query structure is hardcoded with a `?` placeholder, and the user input—now including the `%` wildcards—is passed separately to `execute()` as a bound parameter. PDO handles the escaping, preventing any SQL metacharacters in `$term` from altering the query structure.
