## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))
- **Location**: `MysqliQueryConcat.php`, line 8 (sink); query built at line 5
- **Source**: `$_GET['username']` (line 19), passed unmodified into `findUserByUsername()`
- **Sink**: `mysqli_query($db, $query)` (line 8), where `$query` is built by direct string concatenation of the untrusted `$username` value at line 5

## Source

```php
$username = $_GET['username'] ?? '';
$user = findUserByUsername($db, $username);
```

`$username` comes straight from the query string with no validation or escaping, then flows unchanged into `findUserByUsername()`, where it is concatenated into the SQL string and executed. Nothing on this path constrains its contents, so a value such as `' OR '1'='1` or a stacked/UNION payload reaches `mysqli_query()` intact.

## Fix

Vulnerable code:

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

Fixed code:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $stmt = mysqli_prepare($db, "SELECT id, username, email FROM users WHERE username = ?");

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

No third-party library is involved; the fix uses PHP's built-in MySQLi extension prepared-statement API, so no dependency/version recommendation applies.

## Explanation

The query is rewritten as a prepared statement: the SQL text now contains a `?` placeholder instead of the interpolated username, and `$username` is bound as a typed parameter (`"s"` for string) via `mysqli_stmt_bind_param()` rather than concatenated into the query text. MySQLi sends the query structure and the parameter value to the server separately, so the bound value can never be reinterpreted as SQL syntax regardless of its contents, which closes the injection. `mysqli_stmt_get_result()` is used to obtain a result set with the same shape (`mysqli_result`) that `mysqli_fetch_assoc()` already expects, so the rest of the function's logic is unchanged.

## Behaviour changes

- Added a `$stmt === false` check after `mysqli_prepare()`, returning `null` on failure. The original had no equivalent step (there was nothing to prepare), but a prepared statement introduces a new call that can itself fail (e.g., malformed SQL, connection issue); returning `null` here mirrors the existing `$result === false` handling for query failure, so the function's external behaviour on a database-level failure is unchanged (still returns `null`).
- `mysqli_stmt_get_result()` requires the mysqlnd driver to be enabled (the default in most modern PHP builds, including PHP's official Docker images and most Linux distro packages). If the target environment uses the older non-mysqlnd MySQLi driver, `mysqli_stmt_get_result()` is unavailable and the fetch would need to use `mysqli_stmt_bind_result()` with output variables instead. Assumed mysqlnd is available, consistent with default PHP installations; flagging this as the one environment-dependent assumption in an otherwise drop-in fix.
- All other behaviour (return type, `null` on not-found or failure, associative array on success, no output on this path) is unchanged.
