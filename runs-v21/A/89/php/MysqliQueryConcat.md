## Verdict
Confirmed CWE-89 SQL Injection. The `$username` parameter is concatenated directly into the SQL query without sanitization and then executed via `mysqli_query()`.

## Source
Line 5 constructs the query by concatenating the unsanitized `$username` parameter:
```php
$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
```
The `$username` parameter originates from user input (`$_GET['username']` at line 19) and flows directly into the SQL command without parameterization, allowing an attacker to inject arbitrary SQL.

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
The vulnerability is eliminated by using a prepared statement with parameterized query. Instead of concatenating the username directly into the query string, a placeholder `?` is used. The `mysqli_prepare()` function compiles the query, and `mysqli_stmt_bind_param()` binds the user input as a parameter with type `s` (string), ensuring the database treats it as data rather than executable SQL. `mysqli_stmt_execute()` safely executes the prepared statement. The result is retrieved with `mysqli_stmt_get_result()` and processed as before. This approach prevents SQL injection because user input cannot alter the query structure.
