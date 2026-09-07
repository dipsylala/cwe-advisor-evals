## Verdict

SQL injection confirmed. The `$sku` parameter from user input is concatenated directly into the SQL query without escaping or parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

Line 5 constructs the query via string concatenation:
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = '" . $sku . "'";
```

Line 8 executes the unsanitized query:
```php
$stmt = $db->query($sql);
```

An attacker can supply a `sku` parameter like `' OR '1'='1` to bypass authentication or extract data.

## Fix

Use prepared statements with parameterized queries:

```php
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
```

Alternatively, use named placeholders for clarity:

```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = :sku";
$stmt = $db->prepare($sql);

if ($stmt === false) {
    return null;
}

if (!$stmt->execute([':sku' => $sku])) {
    return null;
}
```

## Explanation

Prepared statements separate the SQL structure from user-supplied data. The database driver treats the parameter as a literal value, never as executable SQL. This prevents injection regardless of the input content—even strings containing quotes, semicolons, or SQL keywords are safe.

PDO's `prepare()` method returns a statement object. The `execute()` method then binds user input to placeholders (`?` for positional or `:name` for named). The database handles escaping internally using the connection's character set, making it both secure and performant.
