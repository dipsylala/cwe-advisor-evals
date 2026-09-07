## Verdict

Exploitable

## Source

User input from `$_GET['username']` at line 19 of the case file, passed unsanitized as the `$username` parameter to `findUserByUsername()` at line 20.

## Fix

**Vulnerable code:**

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

**Fixed code:**

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

The original code builds the SQL query by concatenating the untrusted `$username` parameter directly into the query string. An attacker can supply payloads like `' OR '1'='1` to manipulate query logic and bypass authentication or access unauthorized data. The fix replaces string concatenation with a prepared statement, using `mysqli_prepare()` to create a parameterized query with a placeholder (`?`), then binding the username parameter separately via `mysqli_stmt_bind_param()` with type specifier `"s"` (string). This ensures the parameter is always treated as data, never as executable SQL code. The result set is retrieved via `mysqli_stmt_get_result()` and processed identically to the original code, preserving the function's contract and error handling.

## Behaviour changes

**Error handling addition:** An additional check for `mysqli_prepare()` failure is added at line 6-8. The original code would have silently passed a false value to `mysqli_query()`, which would also fail; the fixed code detects the error at the prepare stage and returns null immediately, providing clearer separation of concerns.

**No other behaviour changes** - the function's signature, return type, error responses, and result processing remain identical. The fix closes the injection vulnerability without altering the function's observable contract from the caller's perspective.
