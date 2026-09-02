## Verdict
SQL injection vulnerability confirmed. User-controlled input from `$_GET['username']` is concatenated into an SQL query string and executed without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source
Line 5 constructs the query via string concatenation:
```php
$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
```

The `$username` parameter receives untrusted input from `$_GET['username']` (line 19) and flows directly into the query without sanitization or parameterization before execution at line 8.

## Fix
Replace the concatenated query with a prepared statement using bound parameters:

```php
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
```

## Explanation
Prepared statements with bound parameters separate the SQL structure from user-supplied data. The placeholder `?` marks where data belongs, and `mysqli_stmt_bind_param()` binds the `$username` value as a parameter (the `"s"` type specifier indicates a string) rather than concatenating it into the query. The database driver handles escaping at the protocol level, making injection impossible—any special characters in the username are treated as literal data, not SQL syntax.
