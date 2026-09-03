## Verdict

SQL injection via concatenated user input into query string. The `$username` parameter is directly interpolated into the SQL query without escaping or parameterization, enabling an attacker to inject arbitrary SQL.

## Source

Line 5 constructs the query by concatenating the untrusted `$username` variable:

```php
$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
```

The tainted value flows to the sink at line 8 (`mysqli_query`), where it is executed against the database.

## Fix

Replace string concatenation with a prepared statement and bound parameters:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";
    
    $stmt = $db->prepare($query);
    if ($stmt === false) {
        return null;
    }
    
    $stmt->bind_param("s", $username);
    if ($stmt->execute() === false) {
        return null;
    }
    
    $result = $stmt->get_result();
    if ($result === false) {
        return null;
    }
    
    return $result->fetch_assoc() ?: null;
}
```

Alternatively, use the procedural API:

```php
$stmt = mysqli_prepare($db, $query);
mysqli_stmt_bind_param($stmt, "s", $username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

## Explanation

Prepared statements separate SQL structure from user-supplied data. The `?` placeholder marks where data will be inserted, and `bind_param("s", $username)` binds the variable securely—the database driver handles escaping and ensures the value cannot alter the query structure.

The `"s"` type specifier indicates a string parameter. Other common types are `"i"` (integer), `"d"` (double), and `"b"` (blob).

This approach defends against SQL injection regardless of the input content, making it the standard secure pattern for database queries in PHP with MySQLi.
