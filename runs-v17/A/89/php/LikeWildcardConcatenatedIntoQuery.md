## Verdict
CONFIRMED

## Source
File: ProductSearch.php, line 5 (prepare statement construction)

The `searchProducts` function constructs a SQL LIKE query by concatenating the user-supplied `$term` directly into the SQL string:
```
"SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'"
```

While `prepare()` is called, the string concatenation happens before the prepare, so the dangerous value reaches the SQL parser as part of the query syntax, not as a parameter value. An attacker can inject SQL syntax by supplying a `$term` like `%' OR '1'='1` to modify the query logic.

## Fix

### File: ProductSearch.php

```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");

    $stmt->execute(['%' . $term . '%']);
    return $stmt->fetchAll();
}
```

## Explanation
The fix separates the query structure from the data:

1. **Use a parameterized placeholder**: Replace the concatenated string with `?` in the LIKE clause. This tells PDO where a parameter value belongs.

2. **Pass wildcards in the parameter value**: The `execute()` method receives an array where the wildcard characters are concatenated with `$term`. Since this entire string is now a parameter value, not part of the SQL syntax, PDO applies parameter escaping rules and the LIKE metacharacters in the value cannot modify the query logic.

3. **Result**: A `$term` value like `%' OR '1'='1` is treated as a literal substring to match, not as SQL syntax to execute. The query executes safely regardless of the input.

PDO's parameter binding ensures that the value arrives at the database as data, not syntax.
