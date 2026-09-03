## Verdict

Exploitable. SQL injection is confirmed via direct string concatenation of untrusted user input (`$_GET['username']`) into a SQL query executed by `mysqli_query()`.

## Source

**Source:** `$_GET['username']` → function parameter `$username` (line 3)

**Sink:** `mysqli_query($db, $query)` (line 8)

**Data Flow:**
1. Untrusted input from `$_GET['username']` is passed to `findUserByUsername()` at line 19
2. The `$username` parameter is directly concatenated into a SQL query string using string concatenation (line 5): `"SELECT id, username, email FROM users WHERE username = '" . $username . "'"`
3. The concatenated query is executed by `mysqli_query()` at line 8

**Attack Vector:**
An attacker can inject SQL operators by supplying input like `' OR '1'='1`, which transforms the query to: `SELECT id, username, email FROM users WHERE username = '' OR '1'='1'`, bypassing authentication logic and leaking all users.

## Fix

**Vulnerable Code:**
```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
    // Line 8: SQL injection vulnerability - concatenated query executed directly
    $result = mysqli_query($db, $query);

    if ($result === false) {
        return null;
    }

    return mysqli_fetch_assoc($result) ?: null;
}
```

**Fixed Code:**
```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";
    $stmt = mysqli_prepare($db, $query);

    if ($stmt === false) {
        return null;
    }

    mysqli_stmt_bind_param($stmt, "s", $username);
    $executeResult = mysqli_stmt_execute($stmt);

    if ($executeResult === false) {
        return null;
    }

    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_assoc($result) ?: null;
}
```

## Explanation

The fix replaces string concatenation with a parameterized query (prepared statement). The query now contains a placeholder (`?`) instead of the concatenated user input. The `mysqli_prepare()` function creates a prepared statement, `mysqli_stmt_bind_param("s", $username)` binds the user input as a separate parameter with type specifier `"s"` (string), and `mysqli_stmt_execute()` executes the query safely. The `mysqli_stmt_get_result()` call retrieves the result resource, which then works with `mysqli_fetch_assoc()` exactly as before. This ensures the user input is always treated as data, never as SQL code, eliminating the injection vector.

## Behaviour changes

**None.** The prepared statement approach preserves the original sink contract:

- **Returns:** Same return value (associative array or null) from `mysqli_fetch_assoc()`
- **Error handling:** Same error checks and null returns on failure
- **Query semantics:** Identical SQL query structure and result set
- **Function signature:** Unchanged

The fix only changes how the query is constructed (prepared statement instead of concatenation) and executed (through `mysqli_prepare()` and `mysqli_stmt_*` functions instead of `mysqli_query()`), without altering the observable behavior of the function.
