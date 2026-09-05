## Verdict

Vulnerable. User input from `$_GET['sku']` flows through string concatenation directly into the SQL query passed to `PDO::query()`, permitting SQL injection.

## Source

`$_GET['sku']` on line 20, passed to the `findProductBySku()` function as the `$sku` parameter and concatenated into the SQL string on line 5.

## Fix

Replace string concatenation with a prepared statement and bind the parameter separately:

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

## Explanation

The vulnerability is eliminated by switching from `PDO::query()` with concatenated input to `PDO::prepare()` and `PDO::execute()` with bound parameters. Prepared statements ensure that `$sku` is treated as data, never as executable SQL code, regardless of its content. The placeholder `?` marks where the bound parameter goes; `execute()` receives the data in an array. Error handling is preserved: `prepare()` returns false on error, and `execute()` returns false if the query fails.

## Behaviour changes

- `prepare()` returns a PDOStatement or false; error checking on line 10 remains valid.
- `execute()` is added on line 10 to run the prepared statement with the bound parameter; error handling added.
- Query execution now happens in two steps (prepare, then execute) rather than one, but functionality is identical from the caller's perspective.
