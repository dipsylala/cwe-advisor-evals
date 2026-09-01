## Verdict
Confirmed SQL Injection vulnerability via unsafe string concatenation.

## Source
Line 19: `$_GET['username']` provides untrusted user input without validation or escaping.

## Fix
Replace string concatenation with a prepared statement using parameterized queries:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";
    
    $stmt = mysqli_prepare($db, $query);
    if ($stmt === false) {
        return null;
    }
    
    mysqli_bind_param($stmt, "s", $username);
    
    if (!mysqli_execute($stmt)) {
        return null;
    }
    
    $result = mysqli_get_result($stmt);
    mysqli_stmt_close($stmt);
    
    if ($result === false) {
        return null;
    }
    
    return mysqli_fetch_assoc($result) ?: null;
}
```

## Explanation
The original code constructs SQL by concatenating the `$username` parameter directly into the query string. An attacker can inject SQL syntax by supplying input like `' OR '1'='1` to bypass authentication logic or extract unintended data.

Prepared statements separate SQL structure from user data. The `?` placeholder marks where the parameter belongs, and `mysqli_bind_param()` binds the user input as data only—not as SQL code. Even if the input contains SQL metacharacters like quotes or keywords, they are treated as literal string values, not executable SQL commands.

The fix uses the procedural MySQLi API with `mysqli_prepare()`, `mysqli_bind_param()`, and `mysqli_execute()` to safely parameterize the query. Alternatively, use the object-oriented MySQLi API or prepared statements with `sqlsrv`, PDO, or other database libraries that support the same mechanism.
