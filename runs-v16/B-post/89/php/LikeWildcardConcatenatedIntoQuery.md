## Verdict

Exploitable. The `$term` parameter is concatenated directly into the SQL query string within a `prepare()` call, creating a SQL injection vulnerability even though `execute()` is called on the prepared statement. The wildcard values `%` are concatenated with the untrusted input before parameterization, so the attacker can inject SQL by manipulating the term parameter.

## Source

Function parameter `$term` (string) passed to `searchProducts()` from an external caller. The value originates from untrusted input and is directly concatenated into the SQL query string without parameterization.

## Fix

**Vulnerable code:**
```php
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
$stmt->execute();
```

**Fixed code:**
```php
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
$stmt->execute(['%' . $term . '%']);
```

## Explanation

The vulnerability lies in concatenating the `$term` parameter directly into the SQL string during the `prepare()` call. Although `PDO::prepare()` is used, the query string is already constructed with the untrusted value embedded in it, so the `execute()` call has no opportunity to treat it as data rather than code. The fix moves the `LIKE` wildcard construction (`'%' . $term . '%'`) into the parameter binding, where it is passed as a bound parameter value to `execute()`. PDO now handles the entire search string (wildcards and all) as a data value, preventing SQL injection. The wildcard pattern is preserved—it still searches for products with names containing the term—but the injection vector is closed.

## Behaviour changes

None. The fixed code preserves the original functionality: it returns the same result set (products matching the search term) using the same SQL semantics. The `fetchAll()` return value and calling context remain identical. The only change is the protection mechanism—the search pattern is now passed as a bound parameter instead of being concatenated into the query string.
