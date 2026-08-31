## Verdict

Confirmed. `findUserByUsername()` builds the SQL string by concatenating the caller-supplied `$username` directly into a single-quoted literal and passes it to `mysqli_query()`. Any attacker who controls `$username` can close the literal and inject arbitrary SQL.

## Source

`$_GET['username']` (line 19) flows unvalidated and unescaped into `$username`, is passed as an argument into `findUserByUsername()`, and is concatenated straight into `$query` at line 5.

## Fix

```php
<?php

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

The query text is now a static string containing a `?` placeholder instead of an interpolated value, so user input can never change the shape of the SQL statement. `mysqli_prepare()` compiles the statement once; `mysqli_stmt_bind_param($stmt, 's', $username)` binds `$username` as a string parameter, and the mysqli driver sends it to the server as data rather than as part of the SQL text, so quotes, backslashes, or SQL keywords in the input have no special meaning. `mysqli_stmt_get_result()` retrieves the result set from the executed statement in the same shape (`mysqli_fetch_assoc()`-compatible) that the rest of the function already expects, so the calling code and return contract are unchanged. `mysqli_stmt_close($stmt)` releases the prepared statement handle on every return path. To verify, submit a `username` value such as `' OR '1'='1` or `'; DROP TABLE users; --` and confirm the query returns no row (rather than the whole table or an error), and separately confirm a legitimate username still returns the matching user.
