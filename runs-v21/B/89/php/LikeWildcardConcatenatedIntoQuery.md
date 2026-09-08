## Verdict

CONFIRMED SQL Injection via LIKE wildcard concatenation. The user-supplied `$term` parameter is concatenated into the SQL query string before the prepared statement is created, bypassing parameterization.

## Source

**File:** ProductSearch.php, Line 5

**Code:**
```php
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");
```

**Source (input):** `$term` parameter - user-controlled string from the function argument
**Sink (execution):** `$stmt->execute()` on line 8

## Data Flow

1. Attacker controls the `$term` parameter passed to `searchProducts()`
2. Line 5: `$term` is concatenated directly into the SQL query string with wildcards, creating the full query: `"SELECT id, name FROM products WHERE name LIKE '%<TERM>%'"`
3. `prepare()` receives the already-assembled SQL string with embedded user input
4. Line 8: `execute()` runs the prepared statement with the concatenated user data

**Exploitable path:** An attacker can supply `$term = "%' OR '1'='1"` to create:
```sql
SELECT id, name FROM products WHERE name LIKE '%' OR '1'='1%'
```
This bypasses the intended search logic and returns all products.

## Fix

### File: ProductSearch.php

```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE ?");

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    $stmt->execute(['%' . $term . '%']);
    return $stmt->fetchAll();
}
```

## Explanation

The fix converts the concatenated query to a parameterized prepared statement. Instead of embedding `$term` and the wildcards into the SQL string before `prepare()`, a placeholder `?` is used in the query structure. The wildcard-wrapped value `'%' . $term . '%'` is passed as a bound parameter to `execute()`, where the PDO driver safely treats it as data, never as SQL syntax.

This ensures:
- The SQL query structure is fixed and known to the database at prepare time
- The search term is always treated as a literal string value, never as query logic
- Injection attempts like `' OR '1'='1` in `$term` are treated as literal search text, not SQL operators

The PHP guidance emphasizes that `LIKE` wildcard values must be bound as parameters too—concatenating `"%$search%"` into an otherwise-prepared query still permits injection of the wildcard portion itself, which this fix prevents.

## Behaviour changes

**Original behaviour (vulnerable):**
- SQL structure incorporates user input before prepare time
- Attacker can inject SQL operators and logic through `$term`
- Query outcome changes based on injection payload

**Fixed behaviour:**
- SQL structure is fixed at prepare time with a placeholder
- User input is always treated as literal search data
- Query outcome depends only on the string content of `$term`, not its syntax
- Search for terms containing special characters (e.g., `%`, `'`, `_`) works correctly because they are escaped by the driver when bound as data

**Functional equivalence:**
- The query still searches the `name` column using `LIKE` with wildcards
- Results are identical for non-malicious input
- No additional database calls or performance impact
