## Verdict

The data flow from `$_GET['username']` to `mysqli_query()` is exploitable. The username parameter is concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL syntax.

## Source

`$_GET['username']` at line 19 flows into the `$username` parameter at line 3, then into a string concatenation at line 5 that builds the query.

## Fix

Replace the string concatenation with a prepared statement using parameter binding:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $stmt = mysqli_prepare($db, "SELECT id, username, email FROM users WHERE username = ?");
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($result === false) {
        return null;
    }

    return mysqli_fetch_assoc($result) ?: null;
}
```

The `?` placeholder in the prepared statement marks where a parameter will be bound. The `"s"` type specifier in `bind_param()` indicates a string parameter. The username value is now passed separately through binding, not concatenated into the query.

## Explanation

The original code built a SQL string by concatenating `$username` directly: `"... WHERE username = '" . $username . "'"`. An attacker could supply `' OR '1'='1` to turn the query into `WHERE username = '' OR '1'='1`, matching all rows.

Prepared statements solve this by separating query structure from data. The placeholder `?` reserves a slot for a value, and `bind_param()` delivers that value to the server as data, never as SQL code. The server parses the query structure first, then substitutes the bound data safely into the parameter slot. No amount of special characters in the username can alter the query structure once the statement is prepared.

All three APIs used—`mysqli_prepare()`, `mysqli_stmt_bind_param()`, and `mysqli_stmt_execute()`—are built into PHP's standard MySQLi extension (no external dependencies). The result is retrieved with `mysqli_stmt_get_result()`, which returns the same `mysqli_result|false` contract as the original `mysqli_query()`, so error handling and result fetching remain unchanged.

## Behaviour changes

- Query execution model shifts from direct query to two-stage execution (prepare, then execute with bound parameters). This is the standard and recommended pattern for all parameterized queries in MySQLi.
- Prepared statements are parsed once and can be reused if the function is called multiple times; performance is improved for repeated calls.
- No changes to the function's signature, return type, or error handling contract. Callers see identical behaviour.
- The `mysqli_fetch_assoc()` call works unchanged with the result set from `mysqli_stmt_get_result()`.
