## Verdict
SQL Injection vulnerability confirmed. The search term is concatenated into the SQL query string before parameterization, allowing an attacker to inject arbitrary SQL.

## Source
```php
<?php

function searchProducts(PDO $pdo, string $term): array
{
    $stmt = $pdo->prepare("SELECT id, name FROM products WHERE name LIKE '%" . $term . "%'");

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    $stmt->execute();
    return $stmt->fetchAll();
}
```

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
The fix uses a positional parameter placeholder (`?`) in the query string and passes the parameterized term via the `execute()` method. The wildcard characters (`%`) remain in PHP code under developer control, while the user-supplied `$term` is properly escaped by PDO's parameter binding mechanism. This prevents SQL injection regardless of the term's content—quotes, semicolons, or SQL keywords cannot break the query structure.
