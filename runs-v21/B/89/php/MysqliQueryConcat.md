## Verdict

SQL Injection vulnerability confirmed. The query is constructed via string concatenation with unsanitized user input from `$_GET['username']`, allowing an attacker to inject arbitrary SQL.

## Source

Untrusted data: `$_GET['username']` (line 19) passed to `findUserByUsername()` parameter `$username`.

Data flow: User input → `$username` parameter → string concatenation in query string (line 5) → `mysqli_query()` sink (line 8).

## Fix

### File: MysqliQueryConcat.php

```php
<?php

function findUserByUsername(mysqli $db, string $username): ?array
{
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
    $user = mysqli_fetch_assoc($result) ?: null;
    mysqli_stmt_close($stmt);

    return $user;
}

$db = mysqli_connect('localhost', 'app_user', 'app_pass', 'app_db');

$username = $_GET['username'] ?? '';
$user = findUserByUsername($db, $username);

if ($user === null) {
    http_response_code(404);
    echo json_encode(['error' => 'user not found']);
} else {
    echo json_encode($user);
}
```

## Explanation

The fix replaces string concatenation with a prepared statement using MySQLi's procedural API. The query now uses a `?` placeholder (line 5) instead of embedding `$username` directly. The `mysqli_prepare()` function compiles the query structure on the server, separating it from the data. The `mysqli_stmt_bind_param()` call binds the `$username` parameter with type `"s"` (string), ensuring it is treated as data rather than executable SQL. The `mysqli_stmt_execute()` function safely executes the prepared statement with the bound values. `mysqli_stmt_get_result()` retrieves the result set, and `mysqli_stmt_close()` cleans up the statement resource.

This approach closes the SQL Injection vector by ensuring that user input can never alter the query's structure or logic. The parameter binding is applied at the protocol level, making it impossible for injected SQL syntax to be interpreted as query commands.

## Behaviour changes

**Preserved:** Query logic, return type, error handling flow, and JSON response format remain identical.

**Changed:** Query execution now uses prepared statements instead of concatenation. Error handling for statement preparation added (line 8 check). Resource cleanup added with `mysqli_stmt_close()` calls to prevent statement handle leaks.

**Returns:** Same as original—returns a single user record as an associative array or null.

**Discards:** None—all result data is preserved and returned.

**Arguments left implicit:** None added or changed—`mysqli_stmt_bind_param()` uses default behavior for the string type, `mysqli_stmt_execute()` uses default commit mode.

**Failure behaviour:** Added check for `mysqli_prepare()` returning false (rare, indicates malformed query or connection issue). `mysqli_stmt_execute()` failure now explicitly closes the statement before returning null. Original behavior of returning null on query failure is preserved.
