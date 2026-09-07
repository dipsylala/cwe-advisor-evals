## Verdict

**Confirmed exploitable.** The function concatenates untrusted user input directly into a SQL query passed to `mysqli_query()`. An attacker supplying `' OR '1'='1` as the username parameter executes arbitrary SQL.

## Source

`$_GET['username']` at line 19 flows unsanitized into the `findUserByUsername()` function parameter at line 20, then into string concatenation at line 5.

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
    mysqli_stmt_close($stmt);

    if ($result === false) {
        return null;
    }

    return mysqli_fetch_assoc($result) ?: null;
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

The fix replaces string concatenation with a MySQLi prepared statement. The query now uses `?` as a placeholder instead of embedding the username directly. The `mysqli_stmt_bind_param()` call binds the username as a string parameter (type `"s"`), ensuring the database driver treats it as data, not query structure. The placeholder is evaluated server-side after the query is parsed, so any SQL metacharacters in the username (quotes, dashes, semicolons) cannot alter the query logic. The error handling and return contract are preserved—the function still returns null on failure and a result array on success.

## Behaviour changes

None. The function signature, return type, and behavior remain identical. Query execution still returns the same result set or null on error. Error codes and diagnostic output are unchanged. The only change is that SQL injection is no longer possible.
