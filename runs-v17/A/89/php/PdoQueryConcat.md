## Verdict

VULNERABLE. Line 5 constructs an SQL query through string concatenation of unsanitized user input (`$_GET['sku']`), which is then executed via `$db->query()`. An attacker can inject SQL commands by passing special characters such as `'` or `OR` clauses.

## Source

User-supplied input flows from `$_GET['sku']` into the `$sku` parameter of `findProductBySku()`, is concatenated directly into the SQL query string without escaping or parameterization, and reaches the taint sink `$db->query($sql)` on line 8.

## Fix

### File: PdoQueryConcat.php

```php
<?php

function findProductBySku(PDO $db, string $sku): ?array
{
    $sql = "SELECT id, name, price, stock FROM products WHERE sku = ?";

    $stmt = $db->prepare($sql);

    if ($stmt === false) {
        return null;
    }

    if (!$stmt->execute([$sku])) {
        return null;
    }

    $product = $stmt->fetch(PDO::FETCH_ASSOC);
    return $product !== false ? $product : null;
}

$db = new PDO('mysql:host=localhost;dbname=app_db;charset=utf8mb4', 'app_user', 'app_pass');

$sku = $_GET['sku'] ?? '';
$product = findProductBySku($db, $sku);

if ($product === null) {
    http_response_code(404);
    echo json_encode(['error' => 'product not found']);
} else {
    echo json_encode($product);
}
```

## Explanation

The vulnerability arises from passing an unsanitized, user-controlled string directly into an SQL query. SQL injection exploits this by injecting metacharacters and SQL syntax into the query, allowing the attacker to bypass intended query logic, extract unauthorized data, or modify the database.

The fix replaces string concatenation with parameterized queries using PDO's prepared statement mechanism. Line 5 now uses a `?` placeholder instead of embedding the `$sku` variable. The `prepare()` method on line 7 compiles the SQL template without any variable data. The `execute()` method on line 13 passes the parameter values separately, ensuring the database engine treats `$sku` as data only, not executable SQL. This separation of query structure from data is the standard defence against SQL injection across all database APIs.

