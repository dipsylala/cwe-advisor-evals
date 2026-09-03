## Verdict

CONFIRMED - SQL Injection via concatenated LIKE pattern. The search term is concatenated directly into the query string before prepare() is called, allowing an attacker to inject SQL metacharacters. This is a first-order injection from the `$term` parameter to the sink at `execute()`.

## Source

User-controlled input: The `$term` parameter passed to `searchProducts()`.

Data path: `$term` (parameter) → concatenated into query string on line 5 → passed to `PDO::prepare()` → executed on line 8.

## Fix

```php
function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");
    $stmt->execute(['%' . $term . '%']);
    return $stmt->fetchAll();
}
```

The query placeholder (`?`) stands in for the complete LIKE pattern including wildcards. The `%` wildcards are concatenated around `$term` and passed as a single bound parameter to `execute()`, ensuring the entire pattern (including any quotes, semicolons, or SQL keywords in the search term) is treated as literal data, not query syntax.

## Explanation

The original code builds the full SQL query string by concatenating `$term` directly into the query before `prepare()` is called. This means the prepared statement is created with the user input already embedded in the SQL text, defeating the parameterization mechanism entirely. The fix separates the query structure from the data by using a placeholder in the query string and passing the actual search term (with wildcards) as a bound parameter to `execute()`. This ensures `$term` is always treated as data, not as executable SQL, and prevents injection through quote characters, SQL keywords, or metacharacters. The LIKE wildcards themselves (`%`) are part of the pattern but are specified by the application, not by user input.

## Behaviour changes

No behaviour change for legitimate input. Injection attempts such as `' OR '1'='1` in `$term` will now be treated as literal characters to search for in the product name, rather than being interpreted as SQL syntax. Query results remain identical for all valid search terms.
