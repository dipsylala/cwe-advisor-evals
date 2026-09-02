## Verdict

Confirmed. `findUserByUsername()` builds a SQL query by directly concatenating the caller-supplied `$username` into a single-quoted string literal, then executes it with `mysqli_query()`. Any value containing a `'` (or other SQL metacharacters) breaks out of the intended literal and alters the query's structure. Since `$username` is populated from `$_GET['username']` with no filtering, this is directly exploitable for authentication bypass, data exfiltration (e.g. `UNION SELECT`), or blind boolean/time-based extraction of other rows.

## Source

`$_GET['username']` at line 19 (`$username = $_GET['username'] ?? '';`), passed unmodified into `findUserByUsername($db, $username)` at line 20, which flows into the `$query` string built at line 5.

## Fix

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = 'SELECT id, username, email FROM users WHERE username = ?';

    $stmt = mysqli_prepare($db, $query);
    if ($stmt === false) {
        return null;
    }

    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    if ($result === false) {
        mysqli_stmt_close($stmt);
        return null;
    }

    $row = mysqli_fetch_assoc($result) ?: null;
    mysqli_stmt_close($stmt);

    return $row;
}
```

## Explanation

The fix replaces string concatenation with a parameterized query using the `mysqli_stmt` prepared-statement API. `$query` now contains a fixed `?` placeholder instead of the interpolated value, so the SQL structure is fixed at prepare time and can no longer be altered by attacker input. `mysqli_stmt_bind_param($stmt, 's', $username)` binds `$username` as a typed string parameter; the MySQL client library sends it to the server separately from the query text, so the database treats it strictly as data, never as SQL syntax, regardless of what characters (quotes, semicolons, comment sequences, etc.) it contains. `mysqli_stmt_get_result()` recovers a normal result set so the rest of the function's control flow (`mysqli_fetch_assoc`, the `null`-on-no-row behavior) is preserved unchanged, and the statement handle is closed on both the success and early-return paths to avoid leaking it. This eliminates the injection vector entirely rather than attempting to escape or filter the input, which is the correct primary defense for this class of finding.
