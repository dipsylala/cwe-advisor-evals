## Verdict

Exploitable. The `$term` parameter is directly concatenated into the SQL query string on line 5 before `prepare()` is called. Although `prepare()` and `execute()` are invoked, they are not used correctly for parameterization—the unsafe query string is already formed at the time of `prepare()`.

## Source

The `$term` parameter (line 3) receives user-supplied search text from the function caller.

## Fix

**Vulnerable code:**
```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
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

The original code concatenates `$term` directly into the query string before calling `prepare()`. The correct use of prepared statements requires that the query string contain only static SQL and placeholders, with untrusted data passed separately as bound parameters.

The fix moves the wildcard padding (`%`) and the user-supplied `$term` into the parameter array passed to `execute()`. The `?` placeholder in the query string is replaced with the bound value `'%' . $term . '%'`, ensuring that the entire pattern—wildcards and user input alike—is treated as data, not as executable SQL.

## Behaviour changes

None. The query logic, result set, and return type remain identical. The fix preserves the same search functionality while eliminating the injection vulnerability.
