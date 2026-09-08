## Verdict

Confirmed. `$term` is concatenated directly into the SQL string used to build a `LIKE` pattern, then executed with no bound parameters. An attacker-controlled `$term` (e.g. containing `%' OR '1'='1`) breaks out of the intended `LIKE` clause and alters the query's logic.

## Source

`$term`, the `string $term` parameter to `searchProducts()`, is untrusted input (a caller-supplied search term originating from user input further up the call chain).

## Fix

### File: ProductSearch.php

```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE :term");
    $stmt->bindValue(':term', '%' . $term . '%', PDO::PARAM_STR);

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    $stmt->execute();
    return $stmt->fetchAll();
}
```

## Explanation

The original code built the SQL text itself with string concatenation: `"... LIKE '%" . $term . "%'"`. Calling `PDO::prepare()` on that string does not make it safe, because the `%` wildcards and the surrounding quotes are already baked into the query text before the database ever sees a parameter — `$term` is part of the SQL, not a bound value. Any quote, `%`, `_`, or SQL syntax inside `$term` is interpreted as SQL rather than as literal search text.

The fix moves `$term` out of the SQL string entirely. The query now contains a single placeholder, `:term`, and the `%` wildcards are appended to `$term` in PHP before being passed to `bindValue()`. PDO sends the placeholder and the bound value to the database separately from the query plan, so the driver always treats the bound value as literal data — no combination of quotes, wildcards, or SQL keywords in `$term` can change the query's structure. The `LIKE` semantics (substring match) are unchanged: the bound value still contains the same `%term%` pattern, only the wildcards are now assembled outside the SQL text instead of inside it.
