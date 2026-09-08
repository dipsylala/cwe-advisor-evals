## Verdict

The vulnerability is exploitable. An attacker can inject arbitrary SQL through the `sku` GET parameter by providing values like `' OR '1'='1` or `'; DROP TABLE products; --`, which will be concatenated directly into the query string.

## Source

User input enters via `$_GET['sku']` (line 20 of the vulnerable file) and is passed as the `$sku` parameter to `findProductBySku()` without any prior validation.

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

The fix replaces string concatenation with a prepared statement using a placeholder (`?`). Instead of building the SQL by concatenating the untrusted `$sku` directly into the query string, the SQL query is now prepared with a placeholder, and the `$sku` value is bound separately via `execute()`. This ensures that the value is always treated as data, not executable SQL code, preventing injection attacks. The placeholder mechanism is handled natively by PDO at the protocol level, making the fix secure regardless of the value's content.

The error handling was also improved: `prepare()` can fail and now returns `false`, which is checked. The result of `execute()` is also validated to catch execution errors.

## Behaviour changes

- **Query execution model**: Changed from direct query execution via `query()` to prepared statement execution via `prepare()` and `execute()`. The query now reaches the database server in two stages: structure first, then data binding. The result set behaviour and fetch semantics remain identical.
- **Error handling**: Added validation of `prepare()` return value (which can be false) and validation of `execute()` return value (which can be false on error). The original code only checked the `query()` result.
- **Performance**: Prepared statements may be slightly reused by the database server across multiple calls with different parameters, but in this single-invocation context there is no performance change.
