## Verdict

**Confirmed SQL Injection (CWE-89).** The vulnerability is real and directly exploitable. User input from `$_GET['sku']` flows unparameterized into an SQL query executed by PDO, allowing attackers to inject arbitrary SQL clauses.

## Source

User input enters at line 20 (`$_GET['sku']`), flows as parameter `$sku` into `findProductBySku()` at line 21, and is concatenated directly into the SQL string at line 5 without parameterization. The concatenated query reaches the sink `$db->query($sql)` at line 8.

**Attack scenario:** Input like `' OR '1'='1` or `'; DROP TABLE products; --` will be concatenated into the query string, allowing the attacker to manipulate the WHERE clause or execute additional commands.

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

The fix replaces string concatenation with a prepared statement. Line 5 now uses a `?` placeholder instead of directly embedding `$sku` into the SQL string. The query template is sent to `PDO::prepare()` (line 8), which returns a PDOStatement. The user input is then bound as a parameter via `execute()` (lines 13-15) rather than being concatenated into the query string.

Prepared statements ensure that user input is always treated as data, never as executable SQL structure. The database driver parses the query template and the parameter binding separately, so attacker-controlled characters in `$sku` cannot alter the query's structure. Error handling is preserved: failures from `prepare()` and `execute()` are both checked before proceeding to fetch results.

## Behaviour changes

1. **Query execution model**: Changed from direct query execution (`query()`) to prepared statement execution (`prepare()` then `execute()`). The database receives the same logical query with the same result, but via parameterized binding instead of string concatenation.

2. **Error handling distribution**: The original code checks only if `query()` fails. The fixed code explicitly checks if both `prepare()` and `execute()` fail, catching errors at both stages.

3. **Security posture**: User input is now parameterized and cannot alter query structure, eliminating the SQL injection vulnerability.

4. **Performance**: Prepared statements allow driver-level and server-level caching and optimization. There is no functional difference from the caller's perspective; the API contract (returns `?array` or `null`) remains unchanged.

5. **Query logging**: Some database logging/auditing tools may display the prepared statement template with placeholders rather than the fully-bound query, which is typically the desired logging behaviour for security.
