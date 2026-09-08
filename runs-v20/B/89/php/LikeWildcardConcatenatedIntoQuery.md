## Verdict

exploitable

- cwe_id: CWE-89
- location: ProductSearch.php, line 8 (sink: `$stmt->execute()`; root cause on line 5)
- confidence: high

## Source

`$term`, the `string $term` parameter of `searchProducts(PDO $pdo, string $term)`. It is passed directly into the function with no prior validation or encoding and is attacker-controlled (a search-box value from the caller).

## Fix

### File: ProductSearch.php

```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE :term");

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    $stmt->execute([':term' => '%' . $term . '%']);
    return $stmt->fetchAll();
}
```

## Explanation

The original query built its SQL text by concatenating `$term` straight into the `LIKE` clause (`"... LIKE '%" . $term . "%'"`) before calling `prepare()`, so `prepare()` had nothing left to parameterize - the wildcard-wrapped value was baked into the query string and `$stmt->execute()` at line 8 ran it as-is, letting a value such as `%' OR '1'='1` break out of the intended clause and alter the query logic. The fix moves the entire wildcarded value out of the SQL text and into a bound parameter: the query now contains only the static placeholder `:term`, and the `%...%` wrapping is done in PHP and passed to `execute()` as the parameter's value. PDO sends the placeholder and the value to the database separately, so the driver always treats `$term` as literal data for the `LIKE` comparison, never as SQL syntax, regardless of what characters (including `%`, `_`, or quotes) it contains.

## Behaviour changes

none - the fixed query returns the same rows as the original for any given `$term` (rows whose `name` contains `$term` as a substring, using SQL `LIKE` semantics), preserves `fetchAll()`'s return value and shape, and neither version checks the return value of `prepare()` or `execute()`. The only difference is that `%` and `_` characters occurring inside `$term` are now passed to the database as literal parameter data rather than as characters already embedded in the query string; since PDO binds the wildcard-wrapped value as a single string parameter (not as a separately-typed argument), the database still interprets any `%`/`_` within it as `LIKE` wildcard characters exactly as before, so search behavior for such input is unchanged.

## Verification

Ran `php -l` (PHP's built-in syntax linter) against the fixed file copied to a scratch location outside the repository - result: "No syntax errors detected". No PHP runtime with a live database was available to execute the query end-to-end, so behavior was verified by inspection against the PDO documentation: `PDOStatement::execute()` accepts an array mapping named placeholders (`:term`) to values, and `prepare()`/`execute()` with bound parameters is the pattern named as the primary defence in the loaded CWE-89 PHP guidance.

Assumptions: none - the CWE ID matched the description, the language was unambiguous from the `.php` extension, and the loaded PHP-specific guidance directly covers this exact case ("Bind `LIKE` wildcard values as a parameter too - concatenating `"%$search%"` into an otherwise-prepared query still injects the wildcard portion").
