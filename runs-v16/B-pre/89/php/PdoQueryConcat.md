## Verdict

exploitable

## Source

`$_GET['sku']` at line 20 flows to the `findProductBySku()` function parameter without validation or escaping.

## Fix

**Vulnerable code (line 5-8):**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = '" . $sku . "'";

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
$stmt = $db->query($sql);
```

**Fixed code:**
```php
$sql = "SELECT id, name, price, stock FROM products WHERE sku = ?";

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
$stmt = $db->prepare($sql);
$stmt->execute([$sku]);
```

## Explanation

The vulnerability stems from concatenating untrusted user input directly into an SQL query string. By constructing `WHERE sku = '" . $sku . "'"`, an attacker can inject SQL code: passing `' OR '1'='1` as the sku parameter produces `WHERE sku = '' OR '1'='1'`, which bypasses the WHERE clause and retrieves all products. The fix replaces string concatenation with PDO prepared statements: `prepare()` sends the query structure to the database server separately from the data, and `execute()` binds the untrusted `$sku` value as a parameter. The database treats the parameter value as literal data, not executable SQL, which prevents injection regardless of special characters the attacker supplies.

## Behaviour changes

none
