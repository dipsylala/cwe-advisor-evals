## Verdict

Confirmed SQL injection vulnerability. User input from `$_GET['username']` flows unsanitized into the SQL query at line 5 via string concatenation, then executed at line 8 via `mysqli_query()`. Attacker can inject arbitrary SQL operators to manipulate query logic.

## Source

Line 19 (outside the function): `$username = $_GET['username'] ?? '';`

Untrusted user input from query string parameter `username`, with empty string as fallback (still attacker-controlled).

## Fix

**Vulnerable code (line 5 and 8):**
```php
$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
$result = mysqli_query($db, $query);
```

**Fixed code:**
```php
$query = "SELECT id, username, email FROM users WHERE username = ?";
$stmt = mysqli_prepare($db, $query);
if ($stmt === false) {
    return null;
}
mysqli_stmt_bind_param($stmt, "s", $username);
if (!mysqli_stmt_execute($stmt)) {
    mysqli_stmt_close($stmt);
    return null;
}
$result = mysqli_stmt_get_result($stmt);
if ($result === false) {
    mysqli_stmt_close($stmt);
    return null;
}
$row = mysqli_fetch_assoc($result) ?: null;
mysqli_stmt_close($stmt);
return $row;
```

## Explanation

The fix replaces string concatenation with a prepared statement. The SQL query now contains a placeholder `?` for the username parameter instead of concatenating the value directly. The `mysqli_prepare()` function creates a prepared statement, `mysqli_stmt_bind_param()` binds the user-supplied `$username` with type `"s"` (string), and `mysqli_stmt_execute()` sends the query and parameter separately to the database server. The database engine treats the parameter as data, not query structure, preventing SQL injection. Error handling is preserved to maintain the original function's failure contract.

## Behaviour changes

- Query execution now uses prepared statements instead of string concatenation
- Parameter binding ensures user input is treated as literal string data
- Database server performs parsing and binding separately, preventing operator injection
- Error handling flow is unchanged: function returns `null` on prepare, bind, or execute failures
- Fetch logic unchanged: returns single row as associative array or `null` if not found
- Statement resources are properly cleaned up via `mysqli_stmt_close()`
