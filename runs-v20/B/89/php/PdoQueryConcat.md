## Verdict

exploitable

- cwe_id: CWE-89
- location: PdoQueryConcat.php, line 8 (sink: `$db->query($sql)`)
- confidence: high

## Source

`$_GET['sku']` (line 20) is read with no validation or sanitization, assigned to `$sku`, and passed directly into `findProductBySku()`.

## Fix

### File: PdoQueryConcat.php

```php
<?php

function findProductBySku(PDO $db, string $sku): ?array
{
    $sql = "SELECT id, name, price, stock FROM products WHERE sku = :sku";

    $stmt = $db->prepare($sql);
    if ($stmt === false) {
        return null;
    }

    if (!$stmt->execute(['sku' => $sku])) {
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

The sink built its SQL by directly concatenating the untrusted `$sku` value into a single-quoted string literal, so a value such as `' OR '1'='1` or a value containing `'; DROP TABLE products; --` changes the query's logic or structure. The fix replaces `$db->query($sql)` with a prepared statement: `$sql` now contains a named placeholder (`:sku`) instead of the literal value, `$db->prepare()` compiles the query with that placeholder as its structure, and `$stmt->execute(['sku' => $sku])` binds `$sku` as a data value for that placeholder. PDO sends the value separately from the query text, so it can never be interpreted as SQL syntax regardless of its contents, closing the injection without needing any escaping or input filtering.

## Behaviour changes

- `PDO::query()` was replaced with `PDO::prepare()` + `PDOStatement::execute()`. `query()` performs prepare-and-execute in one call and returns `false` on any failure (connection error, syntax error, etc.); the fix preserves the same externally-observed failure behaviour by checking both steps explicitly and returning `null` from `findProductBySku()` on failure in either case, exactly as the original did when `$stmt === false`.
- The successful-path return value is unchanged: `$stmt->fetch(PDO::FETCH_ASSOC)` is called identically, and the `$product !== false ? $product : null` mapping is untouched.
- No change was made to the `PDO::ATTR_EMULATE_PREPARES` setting or the DSN. The knowledge base notes that emulated prepares make the connection charset security-relevant, but the DSN here already sets `charset=utf8mb4` explicitly, so that condition is already satisfied and disabling emulation is not required to close this finding; leaving it out keeps the fix scoped to the reported sink.
- No other logic, argument, or output was added or removed.

## Verification

Ran `php -l` (PHP 8.5.8 CLI) against the fixed file in a scratch copy outside the case directory: `No syntax errors detected`. Every name introduced by the fix (`PDO::prepare()`, `PDOStatement::execute()` with an associative parameter array, named placeholder `:sku`) is a standard PDO API used per the PHP manual and matches the language-specific knowledge base guidance (`cwe/89/php/INDEX.md`), which names `prepare()` plus `bindValue()`/`execute([...])` as the fix pattern.
