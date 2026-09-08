## Verdict

Confirmed. `$username`, sourced from `$_GET['username']` (line 19), is concatenated directly into the SQL string on line 5 and passed to `mysqli_query()` on line 8 with no escaping or parameterization. A value such as `' OR '1'='1` or a stacked/UNION payload alters the query's logic or exfiltrates data from other tables.

## Source

`$_GET['username']` (line 19) flows unmodified into `findUserByUsername()`'s `$username` parameter, is string-concatenated into `$query` (line 5), and reaches the `mysqli_query()` sink (line 8).

## Fix

### File: MysqliQueryConcat.php
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

The fix replaces string concatenation with a parameterized query. `mysqli_prepare()` compiles the SQL with a `?` placeholder in place of the username; `mysqli_stmt_bind_param()` binds `$username` as a string (`'s'` type) rather than splicing it into the SQL text, so the database driver transmits the value as data and it can never be reinterpreted as SQL syntax regardless of quotes, comments, or keywords it contains. `mysqli_stmt_get_result()` retrieves the result set as a `mysqli_result`, so the existing `mysqli_fetch_assoc()` call and all downstream logic are unchanged. This requires the `mysqlnd` driver (the default PHP mysqli backend since PHP 5.4/7+); the rest of the function's control flow and the surrounding request handling are untouched.
