## Verdict

exploitable

## Source

The `$term` parameter in the `searchProducts()` function is user-supplied untrusted input.

## Fix

**Vulnerable code:**
```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
    $stmt->execute();
    return $stmt->fetchAll();
}
```

**Fixed code:**
```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
    $stmt->execute(['%' . $term . '%']);
    return $stmt->fetchAll();
}
```

## Explanation

The vulnerability is that the user-supplied `$term` is concatenated directly into the SQL query string before the statement is prepared. An attacker can inject SQL operators—for example, passing `%' OR '1'='1` to bypass the LIKE clause entirely. Although `prepare()` is called, it receives a fully-constructed query with the untrusted data already embedded.

The fix moves the LIKE wildcards out of the query string and into the parameter binding. The query structure is now fixed (`LIKE ?`), and the entire search term including wildcard characters is bound separately via `execute()`. This ensures the database driver treats the value as data, not as executable query syntax. Even if an attacker supplies special characters or SQL keywords, they will be safely escaped by the driver.

## Behaviour changes

None. The `execute()` method returns the same boolean result; `fetchAll()` retrieves results identically. The data passed to the database is the same (`%` + `$term` + `%`), but it is now properly parameterized instead of concatenated into query text.
