## Verdict

Confirmed. `findProductBySku()` builds the SQL statement by directly concatenating the untrusted `$sku` value (sourced from `$_GET['sku']`) into the query string, then executes it with `PDO::query()`. An attacker-controlled `sku` value such as `' OR '1'='1` or a UNION-based payload is interpreted as SQL syntax rather than as data, allowing data exfiltration or logic bypass.

## Source

`$_GET['sku']` (line 20) flows unmodified into `findProductBySku($db, $sku)` (line 21), where it is concatenated into `$sql` (line 5) and passed to `$db->query($sql)` (line 8, the reported sink).

## Fix

### File: PdoQueryConcat.php

```php
<?php

function findProductBySku(PDO $db, string $sku): ?array
{
    $sql = "SELECT id, name, price, stock FROM products WHERE sku = :sku";

    $stmt = $db->prepare($sql);
    $stmt->bindValue(':sku', $sku, PDO::PARAM_STR);
    $stmt->execute();

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

The fix replaces string concatenation and `PDO::query()` with a parameterized query built via `PDO::prepare()`. The `:sku` placeholder is bound with `PDOStatement::bindValue()` and `PDO::PARAM_STR`, so the value is transmitted to the database as data rather than being spliced into the SQL text. This means special characters in `$sku` (quotes, `OR`, `UNION`, comment sequences, etc.) can no longer alter the query's structure, regardless of their content, closing the injection path while preserving the original behavior for legitimate SKU lookups.
