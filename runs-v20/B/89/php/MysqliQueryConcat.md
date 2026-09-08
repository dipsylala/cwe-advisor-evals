## Verdict

Confirmed. `findUserByUsername()` builds the SQL statement by concatenating `$username` directly into a single-quoted string literal, then executes it with `mysqli_query()`. The value is attacker-controlled and reaches the query with no parameterization or escaping, so a username such as `' OR '1'='1` or `' UNION SELECT ...--` changes the query's logic.

## Source

`$_GET['username']` (line 19), passed unmodified into `findUserByUsername($db, $username)` (line 20).

## Fix

### File: MysqliQueryConcat.php

```php
<?php

function findUserByUsername(mysqli $db, string $username): ?array
{
    $stmt = mysqli_prepare($db, 'SELECT id, username, email FROM users WHERE username = ?');

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

The query text is now a static string with a `?` placeholder in place of the concatenated value. `mysqli_prepare()` compiles that statement once; `mysqli_stmt_bind_param($stmt, 's', $username)` attaches `$username` as a typed parameter (`s` = string) rather than as text spliced into the SQL, so the database always treats it as a single data value and never as query syntax, regardless of what characters it contains. `mysqli_stmt_execute()` runs the bound statement, and `mysqli_stmt_get_result()` retrieves a result set with the same shape `mysqli_query()` produced, so the rest of the function - the false-check and `mysqli_fetch_assoc()` - is unchanged. `mysqli_prepare()` can itself return `false` (e.g. on a malformed statement or a lost connection), which the original code had no equivalent path for since `mysqli_query()` folded that failure mode into its own `false` return; the added check preserves the function's existing "return null on failure" contract for that case instead of calling `mysqli_stmt_bind_param()` on a non-object.

## Behaviour changes

None observable to callers. Return type, success payload (associative array of `id`, `username`, `email`), and the `null` result on no-match or failure are all unchanged. The only new internal path is `mysqli_prepare()` returning `false`, which is mapped to the same `null` return the function already produces for a failed query - no new exception, status code, or response shape is introduced.
