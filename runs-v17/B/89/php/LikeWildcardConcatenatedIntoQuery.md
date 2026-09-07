## Verdict

Exploitable. The `$term` parameter is concatenated directly into the SQL string before the string is passed to `PDO::prepare()`. Although `prepare()` is called, the concatenation occurs in the query string itself, not as a bound parameter, so malicious input reaches the SQL parser as executable code rather than as data.

## Source

The `$term` parameter (line 3) receives untrusted input from the caller with no validation. It is a string type without constraint.

## Sink

`PDO::prepare()` at line 5 receives a SQL string that has already been concatenated with the untrusted `$term` value via the expression `"SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'"`. The concatenation happens before parameterization, so the injection occurs at query construction time.

## Fix

### File: ProductSearch.php

```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
    $stmt->execute(["%{$term}%"]);
    return $stmt->fetchAll();
}
```

## Explanation

The fix moves the wildcard concatenation from the SQL string into the parameter binding. Instead of concatenating `"%` and `%"` around `$term` before passing the entire string to `prepare()`, the SQL string now contains a single `?` placeholder for the LIKE value. The wildcarded string `"%{$term}%"` is then passed as a bound parameter in the `execute()` call. PDO treats this parameter as data, not as SQL code, so any special characters in `$term` (including single quotes, SQL comments, or boolean operators) are escaped by the database driver and cannot alter the query structure.

## Behaviour changes

None. The query executes the same SELECT statement with the same semantics. `$stmt->fetchAll()` returns an associative array of matching rows, identical to the original behavior. The only change is that malicious input can no longer modify the query logic.
