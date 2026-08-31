## Verdict

- **CWE-89** - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **Location**: `MysqliQueryConcat.php`, line 8 (sink); line 5 (concatenation)
- **Verdict**: exploitable
- **Confidence**: high

## Source

`$_GET['username']` (line 19) flows unvalidated and unescaped into `findUserByUsername($db, $username)` (line 20), where the parameter `$username` is concatenated directly into the SQL text on line 5 and executed by `mysqli_query()` on line 8. No validation, escaping, or type coercion occurs anywhere on the path, so a value such as `' OR '1'='1` or a stacked/UNION payload reaches the query as raw SQL text.

## Fix

**Library recommendation**: none required - the fix uses MySQLi's built-in prepared statement API, already in use via `mysqli_query()`; no new dependency.

**Vulnerable code**:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";

    // SAST FINDING: CWE-89 reported here. Sink is the next statement.
    $result = mysqli_query($db, $query);

    if ($result === false) {
        return null;
    }

    return mysqli_fetch_assoc($result) ?: null;
}
```

**Fixed code**:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";

    $stmt = mysqli_prepare($db, $query);
    if ($stmt === false) {
        return null;
    }

    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($result === false) {
        return null;
    }

    return mysqli_fetch_assoc($result) ?: null;
}
```

## Explanation

The query text no longer contains the username; `?` is a placeholder bound separately with `mysqli_stmt_bind_param($stmt, "s", $username)`, which sends `$username` to the server as a data value in the `s` (string) slot rather than as part of the SQL statement. This makes it structurally impossible for quote characters, `OR` clauses, comment sequences, or stacked statements in the input to alter the query's logic, closing the injection regardless of what the value contains. `mysqli_stmt_get_result()` is used to keep the return shape identical to the original - a `mysqli_result` that `mysqli_fetch_assoc()` can consume the same way as before.

## Behaviour changes

- Added a failure check after `mysqli_prepare()` returning `null` on failure. The original had no separate prepare step; this preserves the same "return null on any DB-layer failure" contract the function already had for `mysqli_query()`, just extended to the new prepare stage - no observable behaviour change for callers.
- `mysqli_stmt_get_result()` requires the `mysqlnd` driver (the default and near-universal MySQLi driver on modern PHP installs). If the target environment uses the older `libmysql`-only build without `mysqlnd`, this call is unavailable and `mysqli_stmt_bind_result()` plus a manual fetch loop must be used instead to build the associative array.
- All other behaviour (return type, `null` on no-match or failure, associative array on success) is unchanged.
