## Verdict
CWE-89 SQL Injection confirmed at line 8. The query is built via string concatenation with unsanitized user input, then passed directly to `mysqli_query()`. An attacker controlling `$username` can inject SQL metacharacters to break out of the string literal and execute arbitrary SQL.

## Source
The vulnerability originates at line 19 where `$_GET['username']` is passed unsanitized to `findUserByUsername()`, travels through the parameter at line 3, is concatenated into the query at line 5, and reaches the sink at line 8 where `mysqli_query()` executes it.

## Fix
### File: MysqliQueryConcat.php
```php
<?php

function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";

    // Use prepared statement to prevent SQL injection
    $stmt = mysqli_prepare($db, $query);
    
    if ($stmt === false) {
        return null;
    }
    
    mysqli_bind_param($stmt, "s", $username);
    
    if (!mysqli_execute($stmt)) {
        mysqli_stmt_close($stmt);
        return null;
    }
    
    $result = mysqli_stmt_get_result($stmt);
    
    if ($result === false) {
        mysqli_stmt_close($stmt);
        return null;
    }
    
    $row = mysqli_fetch_assoc($result);
    mysqli_stmt_close($stmt);
    
    return $row ?: null;
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
The fix replaces string concatenation with a mysqli prepared statement. Instead of embedding the username directly in the query string at line 5, the revised code uses a `?` placeholder. The `mysqli_prepare()` call creates a prepared statement template, `mysqli_bind_param()` binds the `$username` parameter with type specifier `"s"` (string), and `mysqli_execute()` runs the statement with the parameter safely separated from the SQL syntax. This ensures the username is always treated as data, never as executable SQL code. The `mysqli_stmt_get_result()` retrieves the result set and `mysqli_stmt_close()` releases the statement resource.
