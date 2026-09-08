## Verdict

Confirmed SQL injection vulnerability via string concatenation of user input into a SQL query passed to PDO::query().

## Source

Line 5 concatenates the unsanitized `$sku` parameter directly into the SQL string. Line 8 executes the concatenated query with `$db->query()`, which is the taint sink. The `$sku` value originates from `$_GET['sku']` on line 20, user-controlled input.

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

The vulnerability occurred because the SQL query was built by string concatenation with unsanitized user input. An attacker supplying `sku = ' OR '1'='1` would alter the query logic and extract all rows.

The fix uses PDO prepared statements with parameterized queries:

1. Replace the concatenated placeholder with a `?` positional marker in the SQL string.
2. Call `$db->prepare($sql)` to prepare the statement separately from the parameters.
3. Call `$stmt->execute([$sku])` to pass the user input as a bound parameter, ensuring it is treated as data, not SQL syntax.
4. Add error handling on `execute()` to catch binding failures.

Prepared statements are the primary defense against SQL injection in PHP. The parameter binding ensures special SQL characters in `$sku` are properly escaped and interpreted as data values, not executable SQL code.
